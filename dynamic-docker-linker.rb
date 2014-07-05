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

class Host
	def initialize(namespace)
		@namespace = namespace
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

	def get_ip_table()
		result = run netns_exec_command("iptables-save")
		result
	end

	def link_template(localPort, destAddr, destPort)
		# on the prerouting chain, when a request comes in at localAddr, on port localPort, it is jumped to destination destAddr:destPort
		prerouting =  "-A PREROUTING -d #{localAddr}/32 -p tcp -m tcp --dport #{localPort} -j DNAT --to-destination #{destAddr}:#{destPort}"
		prerouting << " -m comment --comment \"PREROUTING LINK: #{localPort}->#{destAddr}:#{destPort}\""

		# on the output chain, do the same
		output =          "-A OUTPUT -d #{localAddr}/32 -p tcp -m tcp --dport #{localPort} -j DNAT --to-destination #{destAddr}:#{destPort}"
		output << " -m comment --comment \"OUTPUT LINK: #{localPort}->#{destAddr}:#{destPort}\""

		# after routing, we set the source ip address of outgoing packets to be containerAddr
		postrouting = "-A POSTROUTING -o eth0 -j SNAT --to-source #{containerAddr}"

		[prerouting, output, postrouting].join("\n")
	end

	def link(info)
		enable_routing()
		enable_ip_forwarding()
		get_ip_table()
	end
end
