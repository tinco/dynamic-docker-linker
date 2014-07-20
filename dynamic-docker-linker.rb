#!/usr/bin/env ruby
require 'fileutils'
require 'ipaddr'
require 'json'

## TODO almost every line can throw an error in this file, they should be handled

def main
	json = JSON.load(STDIN.read)
	links = json["links"] || {}
	links.each do |localPort, destination|
		link(localPort, destination["address"], destination["port"])
	end
end

def link(localPort, destAddr, destPort)
	table = get_iptables()

	#puts "IPTABLES: \n#{table.join("\n")}"

	info = [localPort, destAddr, destPort]
	run(insert_rule_command(table, "PREROUTING", info))
	run(insert_rule_command(table, "OUTPUT", info))

	unless table.detect {|l| l.include? "POSTROUTING ContainerSource"}
		containerAddr = getIP
		run("iptables -t nat -A #{postrouting containerAddr}")
	end
end

def get_iptables()
	run("iptables -t nat -L -n --line-numbers").split("\n")
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
	host = run("hostname -I").split(" ",2).first
	begin
		IPAddr.new(host)
	rescue
		IPAddr.new(Resolv.getaddress host)
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