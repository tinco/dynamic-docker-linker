package main

import (
	"errors"
	"fmt"
	dc "github.com/fsouza/go-dockerclient"
	"github.com/spf13/cobra"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/openshift/geard/cmd"
	"github.com/openshift/geard/containers"
	"github.com/openshift/geard/containers/systemd"
	"github.com/openshift/geard/docker"
	"github.com/openshift/geard/selinux"
	"github.com/openshift/geard/ssh"
	"github.com/openshift/geard/utils"
)


func linkNetworkNamespace(pid int) (string, error) {
	name := "netlink-" + strconv.Itoa(pid)
	path := fmt.Sprintf("/var/run/netns/%s", name)
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	if err := os.MkdirAll("/var/run/netns", 0755); err != nil {
		return name, err
	}
	if err := os.Symlink(nsPath, path); err != nil && !os.IsExist(err) {
		return name, err
	}
	return name, nil
}

func unlinkNetworkNamespace(pid int) error {
	name := "netlink-" + strconv.Itoa(pid)
	path := fmt.Sprintf("/var/run/netns/%s", name)
	return os.Remove(path)
}

func getHostIPFromNamespace(name string) (*net.IPAddr, error) {
	// Resolve the containers local IP
	cmd := exec.Command("ip", "netns", "exec", name, "hostname", "-I")
	cmd.Stderr = os.Stderr
	source, erro := cmd.Output()
	if erro != nil {
		log.Printf("gear: Could not read IP for container: %v", erro)
		return nil, erro
	}
	sourceAddr, errr := net.ResolveIPAddr("ip", strings.TrimSpace(string(source)))
	if errr != nil {
		log.Printf("gear: Host source IP %s does not resolve %v", sourceAddr, errr)
		return nil, errr
	}
	return sourceAddr, nil
}

type addressResolver struct {
	local   net.IP
	checked bool
}

func (resolver *addressResolver) ResolveIP(host string) (net.IP, error) {
	if host == "localhost" || host == "127.0.0.1" {
		if resolver.local != nil {
			return resolver.local, nil
		}
		if !resolver.checked {
			resolver.checked = true
			devices, err := net.Interfaces()
			if err != nil {
				return nil, err
			}
			for _, dev := range devices {
				if (dev.Flags&net.FlagUp != 0) && (dev.Flags&net.FlagLoopback == 0) {
					addrs, err := dev.Addrs()
					if err != nil {
						continue
					}
					for i := range addrs {
						if ip, ok := addrs[i].(*net.IPNet); ok {
							if ip.IP.To4() != nil {
								log.Printf("Using %v for %s", ip, host)
								resolver.local = ip.IP
								return resolver.local, nil
							}
						}
					}
				}
			}
		}
	}
	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

func updateNamespaceNetworkLinks(name string, sourceAddr *net.IPAddr, ports io.Reader) error {

	// Enable routing in the namespace
	output, err := exec.Command("ip", "netns", "exec", name, "sysctl", "-w", "net.ipv4.conf.all.route_localnet=1").Output()
	if err != nil {
		log.Printf("gear: Failed to enable localnet routing: %v", err)
		log.Printf("gear: error output: %v", output)
		return err
	}

	// Enable ip forwarding
	output, err = exec.Command("ip", "netns", "exec", name, "sysctl", "-w", "net.ipv4.ip_forward=1").Output()
	if err != nil {
		log.Printf("gear: Failed to enable ipv4 forwarding: %v", err)
		log.Printf("gear: error output: %v", output)
		return err
	}

	// Restore a set of rules to the table
	cmd := exec.Command("ip", "netns", "exec", name, "iptables-restore")
	stdin, errp := cmd.StdinPipe()
	if errp != nil {
		log.Printf("gear: Could not open pipe to iptables-restore: %v", errp)
		return errp
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		log.Printf("gear: Could not start iptables-restore: %v", errp)
		return err
	}

	/*

These would be the commands that they fabricate.

iptables -t nat -A PREROUTING -d ${local_ip}/32 -p tcp -m tcp --dport ${local_port} -j DNAT --to-destination ${remote_ip}:${remote_port}

iptables -t nat -A OUTPUT -d ${local_ip}/32 -p tcp -m tcp --dport ${local_port} -j DNAT --to-destination ${remote_ip}:${remote_port}

iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source ${container_ip}

So basically what GearD does is store the list of iptable rules, and restore them everytime something changes.

Ideally we'd have this command be stateless. So what we could do is first run iptables-save, load it into a datastructure, add our
new link to that datastructure, replacing any previous link on the same interface+port, and serializing that out to iptables-restore.

	*/


	fmt.Fprintf(stdin, "*nat\n")
	for {
		link := containers.NetworkLink{}
		// this Fscanf call reads a line, setting the fromHost FromPort ToPort and ToHost on the link structure.
		// if it encounters EOF, it will break out of the for loop
		// so we could go without the for loop, and just make this link structure from the link argument
		if _, err := fmt.Fscanf(ports, "%s\t%v\t%v\t%s\n", &link.FromHost, &link.FromPort, &link.ToPort, &link.ToHost); err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("gear: Could not read from network links file: %v", err)
			continue
		}
		// Apparently a link can be invalid.
		if err := link.Check(); err != nil {
			log.Printf("gear: Link in file is not valid: %v", err)
			continue
		}
		// What could link.Complete() be?
		if link.Complete() {
			// This is fancy, it checks whether the hosts are resolvable
			// Since we're going to link only local ip's (which might proxy to remote machines)
			// We might as well skip the whole hosts step and work only with ips
			srcIP, err := net.ResolveIPAddr("ip", link.FromHost)
			if err != nil {
				log.Printf("gear: Link source host does not resolve %v", err)
				continue
			}

			destIP, err := resolver.ResolveIP(link.ToHost)
			if err != nil {
				log.Printf("gear: Link destination host does not resolve %v", err)
				continue
			}

			log.Printf("Mapping %s(%s):%d -> %s:%d", sourceAddr.String(), srcIP.String(), link.FromPort, destIP.String(), link.ToPort)

			// It builds the data and then puts it into a template which gets output to stdin.
			// we need to get that template
			data := OutboundNetworkIptables{sourceAddr.String(), srcIP.IP.String(), link.FromPort, destIP.String(), link.ToPort}
			if err := OutboundNetworkIptablesTemplate.Execute(stdin, &data); err != nil {
				log.Printf("gear: Unable to write network link rules: %v", err)
				return err
			}
		}
	}
	fmt.Fprintf(stdin, "COMMIT\n")

	stdin.Close()
	if err := cmd.Wait(); err != nil {
		log.Printf("gear: iptables-restore did not successfully complete: %v", err)
		return err
	}
	return nil
}
