#!/usr/bin/env ruby
require 'fileutils'
require 'ipaddr'
require 'json'

## TODO almost every line can throw an error in this file, they should be handled

def main
	cid = ARGV[0]
	pid = getPID(cid)
	name = linkNamespace(pid)
	linker = Linker.new(name)

	links = JSON.load(STDIN.read)

	links.each do |localPort, destination|
		linker.link(localPort, destination["address"], destination["port"])
	end

ensure
	begin
		unlinkNamespace(pid)
	rescue
	end
end

def getPID(cid)
	dpid = run("docker inspect --format '{{ .State.Pid }}' #{cid}")
	driver = run("docker inspect --format '{{ .ExecDriver }}' #{cid}")

	if driver.empty? || driver =~ /^lxc/
		raise "Unsupported driver: '#{driver}', look to geard/docker/docker.go to implement GetChildProcess"
	else
		dpid.strip
	end
end

def linkNamespace(pid)
	name = "netlink-#{pid}"
	path = "/var/run/netns/#{name}"
	nsPath = "/proc/#{pid}/ns/net"

	FileUtils.mkdir_p("/var/run/netns", :mode => 0755)
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

		#puts "IPTABLES: \n#{table.join("\n")}"

		info = [localPort, destAddr, destPort]
		run(netns_exec_command insert_rule_command(table, "PREROUTING", info))
		run(netns_exec_command insert_rule_command(table, "OUTPUT", info))

		unless table.detect {|l| l.include? "POSTROUTING ContainerSource"}
			containerAddr = getIP
			run(netns_exec_command "iptables -t nat -A #{postrouting containerAddr}")
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
		run(netns_exec_command("iptables -t nat -L -n --line-numbers")).split("\n")
	end

	def routing_argument(chain, info)
		localPort, destAddr, destPort = info
		localAddr = "127.0.0.1"
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
		
		"iptables -t nat #{prefix} #{routing_argument(chain, info)}"
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
	attr_reader :command
	attr_reader :stdout
	attr_reader :stderr
	attr_reader :status

	def initialize(command, stdout, stderr, status)
		@command = command
		@stdout = stdout
		@stderr = stderr
		@status = status
	end

	def message
		msg = @stdout || ""
		msg << "\n\n" if msg.length > 0
		msg << "Command '#{@command}' failed: #{@stderr}\nStatus: #{@status.to_i}"
	end
end

def run(command)
	# stdout, stderr pipes
	rout, wout = IO.pipe
	rerr, werr = IO.pipe

	pid = Process.spawn(command, :out => wout, :err => werr)
	_, status = Process.wait2(pid)

	# close write ends so we could read them
	wout.close
	werr.close

	stdout = rout.readlines.join("\n")
	stderr = rerr.readlines.join("\n")

	# dispose the read ends of the pipes
	rout.close
	rerr.close

	if status.success?
		stdout
	else
		raise ExecError.new(command,stdout,stderr,status.exitstatus)
	end
end

## entrypoint
main()
