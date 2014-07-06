require 'fileutils'
require 'ipaddr'

def main
	cid = ARGV[1]
	#TODO geard for some reason finds the child process of the container for this
	pid = run("docker inspect --format '{{ .State.Pid }}' #{cid}")
	name = linkNamespace(pid)
	linker = Linker.new(name)

	#TODO read links from stdin and apply them
	links = []
	links.each do |link|
		linker.link(link)
	end

	unlinkNamespace(pid)
end

def linkNamespace(pid)
	name = "netlink-#{pid}"
	path = "/var/run/netns/#{name}"
	nsPath = "/proc/#{pid}/ns/net"

	Dir.mkdir("/var/run/netns", 0755)
	FileUtils.symlink(nsPath, path, :force => true)

	name
end

def unlinkNamespace(pid)
	name = "netlink-#{pid}"
	path = "/var/run/netns/#{name}"
	FileUtils.rm(path)
end

class Linker
	def initialize(namespace)
		@namespace = namespace
	end

	def link(localPort, destAddr, destPort)
		enable_routing()
		enable_ip_forwarding()

		table = get_iptables()
		info = [localPort, destAddr, destPort]
		run(netns_exec_command insert_rule_command(table, "PREROUTING", info))
		run(netns_exec_command insert_rule_command(table, "OUTPUT", info))

		unless table.detect {|l| l.include? "POSTROUTING ContainerSource"}
			containerAddr = getIp
			run(netns_exec_command "iptables -A #{postrouting containerAddr}")
		end
	end

	def netns_exec_command(command)
		"ip netns exec #{@namespace} #{command}"
	end

	def enable_routing()
		run netns_exec_command("sysctl -w net.ipv4.conf.all.route_localnet=1")
	end

	def enable_ip_forwarding()
		run netns_exec_command("sysctl -w net.ipv4.ip_forward=1")
	end

	def get_iptables()
		run(netns_exec_command("iptables -L -n --line-numbers")).split("\n")
	end

	def routing_argument(chain, info)
		localPort, destAddr, destPort = info
		# on the chain, when a request comes in at localAddr, on port localPort, it is jumped to destination destAddr:destPort
		route = "-d #{localAddr}/32 -p tcp -m tcp --dport #{localPort} -j DNAT --to-destination #{destAddr}:#{destPort}"
		comment = "-m comment --comment \"#{chain} LINK: #{localPort}->#{destAddr}:#{destPort}\""
		"#{route} #{comment}"
	end

	def postrouting(containerAddr)
		# after routing, we set the source ip address of outgoing packets to be containerAddr
		"POSTROUTING -o eth0 -j SNAT --to-source #{containerAddr} -m comment --comment \"POSTROUTING ContainerSource\""
	end

	def insert_rule_command(table, chain, info)
		localPort,_,_ = info
		if line = table.detect {|l| l.include? "#{chain} LINK: #{localPort}" }
			prefix = "-R #{chain} #{ line.to_i }"
		else
			prefix = "-A #{chain}"
		end
		
		"iptables #{prefix} #{routing_argument(chain, info)}"
	end

	def getIP
		host = run(netns_exec_command("hostname -I")).split(" ",2).first
		begin
			IPAddr.new(host)
		rescue
			IPAddr.new(Resolv.getaddress host)
		end
	end
end

## Helpers
class ExecError < StandardError
	attr_reader stdout
	attr_reader stderr
	attr_reader status

	def initialize(stdout, stderr, status)
		@stdout = stdout
		@stderr = stderr
		@status = status
	end

	def message
		msg = @stdout.read
		msg << "\n\n" if msg.length > 0
		msg << "Command failed: #{@stderr.read}\nStatus: #{@status.to_i}"
	end
end

def run(command)
	Open3.popen3(command) do |stdin,stdout,stderr,wait_thr|
		if wait_thr.value.success?
			return stdout.read
		else
			raise ExecError.new(stdout,stderr, wait_thr.value)
		end
	end
end

## entrypoint
main()
