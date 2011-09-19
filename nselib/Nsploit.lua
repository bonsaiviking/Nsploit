--- Nsploit functions
--- By: sussurro@happypacket.net
--@copyright See nmaps COPYING for licence

module(... or "Nsploit",package.seeall)

require "lxp/lom"
require "stdnse"

local xmlHeader = "<?xml version=\"1.0\" ?>"

function msfInit()
	local filepath = nil
	local socket = nil

	if not nmap.registry.Nsploit then
		nmap.registry.Nsploit = {}
	end
	
	if not nmap.registry.Nsploit["config"] then
		if os.getenv("NSPLOIT_HOME") then
			filepath = os.getenv("NSPLOIT_HOME") .. "/.Nsploit"
		elseif os.getenv("HOME") then
			filepath = os.getenv("HOME") .. "/.Nsploit"
		elseif os.getenv("USERPROFILE") then
			filepath = os.getenv("USERPROFILE") .. "\Nsploit"
		else
			return 0
		end

		local file = assert(io.open(filepath,"r"))
		local config  = file:read("*all")
		config = string.gsub(config,"\n","")
        
        	local parsed = lxp.lom.parse(config)
		config = parseConfig(parsed)
		nmap.registry.Nsploit["config"] = config
	
	end


	if nmap.registry.Nsploit["socket"] then
		socket = nmap.registry.Nsploit["socket"]
		 local try = nmap.new_try(function() 
					socket = msfConnect()
					stdnse.print_debug(1,"Saved socket busted")
					return socket
					 end)
		try(socket:send("\n"))
		nmap.registry.Nsploit["socket"] = socket
		return socket

	else
		socket = msfConnect()
		nmap.registry.Nsploit["socket"] = socket
		return socket
	end
	
end

function msfConnect(errcnt)

   local loginStr = nil
   local username = nmap.registry.Nsploit["config"]["username"]
   local password = nmap.registry.Nsploit["config"]["password"]
   local host = nmap.registry.Nsploit["config"]["host"]
   local port = nmap.registry.Nsploit["config"]["port"]
   local socket = nil

   loginStr  = genLogin(username,password)

   if nmap.registry.Nsploit["socket"] ~= nil then
	socket = nmap.registry.Nsploit["socket"]
	return socket
   end

   acquireMutex()
   socket = nmap.new_socket()
   stdnse.print_debug(1,"New Socket Created") 

   if not socket:connect(host,port) then 
   		stdnse.print_debug(1,"Connect Failed") 
   		nmap.registry.Nsploit["mutex"] = 0
		return nil
   end
   		stdnse.print_debug(1,"Connect Success") 
   stdnse.print_debug(1, "Sending: " .. loginStr )
   status, err =  socket:send(loginStr)
   if err ~= nil then
        if status == nil then
   		releaseMutex()
		 socket = msfConnect(1)
           	 return socket
	else
		if errcnt > 3 then
   			releaseMutex()
			return nil
		end
   		releaseMutex()
		socket = msfConnect(errcnt + 1)
		return socket
	end
   end
   status, line = socket:receive_buf("\n", false)
   if not status then
   	releaseMutex()
	return nil
   end
   stdnse.print_debug(1,"Login Line: " .. line )
   responseXML  = lxp.lom.parse(line)

   if isFault(responseXML) then 
   	releaseMutex()
	return nil
   end

   local loginResult  = parseResponse(responseXML)

   if loginResult["token"] then
	if not nmap.registry.Nsploit then
		nmap.registry.Nsploit = {}
	end	
	nmap.registry.Nsploit["token"] = loginResult["token"]
   	nmap.registry.Nsploit["mutex"] = 0
	return socket
   end
   
   releaseMutex()
   return nil

end

function exploit(socket,exploit,os,ip,opt )
	
	local options
	os = os:lower()
	if not os or not ip or not exploit then return "Exploit Failed" end
	if not nmap.registry.Nsploit["config"]["os"][os] then return "Bad Operating System" end
	if not nmap.registry.Nsploit["config"]["os"][os]["options"] then return "No Options Found" end

	stdnse.print_debug(1,"Exploit function for " .. exploit .. " got a socket of type  " .. type(socket))
	options = nmap.registry.Nsploit["config"]["os"][os]["options"]
	options["RHOST"] = ip
	if type(opt) == "table" then
		for k,v in pairs(opt) do
			options[k] = v
		end
	end

	if options["payload"]  ~= nil and string.match(options["payload"],"reverse") then
		if nmap.registry.Nsploit["LPORT"] then
			nmap.registry.Nsploit["LPORT"] = nmap.registry.Nsploit["LPORT"] + 1
			options["LPORT"] = nmap.registry.Nsploit["LPORT"]
		else
			nmap.registry.Nsploit["LPORT"] = 4444
			options["LPORT"] = nmap.registry.Nsploit["LPORT"]
		end
	end
	

	if socket == nil then
		socket = msfConnect()
	end
	stdnse.print_debug(1,"socket is of type " .. type(socket) .. " in " .. exploit)
	acquireMutex()
	socket:send(buildExploitXML(exploit,options))
   	status, line = socket:receive_buf("\n", false)
	releaseMutex()
	if status then
   		local responseXML  = lxp.lom.parse(line)
		if isFault(responseXML) then
			return "Exploit Failed"
		else
			return "Exploit Sent"
		end
		
	else
		return "Failed"
	end
	
end
function isResponse(t)
	if(type(t) == "table") then
		if(t["name"] == "methodResponse") then
			return true
		else
			return false
		end
	else
		return false
	end
end

function parseValue(t)
	if(type(t) ~= "table") then
		return {}
	end
	local value = t[1]
	ret = {}
	if(value["tag"] == "struct") then
		for i,v in ipairs(value) do
			if(v[2][1]["tag"] == "array") then
				ret[v[1][1]] = {}
				for n,e in ipairs(v[2][1][1]) do
					table.insert(ret[v[1][1]],e[1][1])
				end
			else
				ret[v[1][1]] = v[2][1][1]
			end
			
		end
	end

	return ret
end
function parseResponse(t)
	if(type(t) == "table") then
		if(t["tag"] == "methodResponse" and  not isFault(t)) then
			if(t[1]["tag"] == "params") then
				if(table.getn(t[1][1]) > 1) then 
					for i,v in ipairs(t[1][1]) do
						stdnse.print_debug(1,i .. ":")
						parseValue(v)
					end
				else
					return parseValue(t[1][1][1])
				end
			end
		else
			stdnse.print_debug(1,"parseResponse: No methodResponse tag")
			return false
		end
	else
		stdnse.print_debug(1,"parseResponse: object is not a table")
		return false
	end
end
function isFault(t)
	if(type(t) == "table") then
		if(t[1]["tag"] == "fault") then
			return true
		else
			return false
		end
	else
		return false
	end
end

function getFault(t)
	if(type(t) == "table") then
		print(table.show(t[2][1][1][1],"FAULT:"))
	else
		return {}
	end
end
function genLogin(username,password)
	local retstring
	retstring = "<?xml version=\"1.0\" ?><methodCall><methodName>auth.login</methodName><params>"
	retstring = retstring .. makeParam(username)
	retstring = retstring .. makeParam(password)
	retstring = retstring .. "</params></methodCall>\0\n"
	return (retstring)


end
function parseConfig(config)
	
	local retVal = {}
	local i,v

	for i,v in ipairs(config)  do
		if type(v[1]) == "table" then
			retVal[config[i]["tag"]] = parseConfig(v)
		else
			if v[1] then
				retVal[string.lower(config[i]["tag"])] = v[1]
			end
		end
	end

	return retVal
end

function buildExploitXML(exploit,options)

   	local xmlString = xmlHeader

   	xmlString = xmlString .. "<methodCall>"
	xmlString = xmlString .. makeTag("methodName","module.execute")
	xmlString = xmlString .. "<params>"
	xmlString = xmlString .. makeParam(nmap.registry.Nsploit["token"])
	xmlString = xmlString .. makeParam("exploit")
	xmlString = xmlString .. makeParam(exploit)
	xmlString = xmlString .. makeParam(options)
	xmlString = xmlString .. "</params>"
	xmlString = xmlString .. "</methodCall>\0"

	return xmlString

end

function makeTag(header,myvalue)
	retstring = "<" .. header .. ">" .. myvalue .. "</" .. header .. ">"
	return retstring
end

function makeParam(value)
	local tempString,node = "",nil
	
	if type(value) == "array"  or type(value) == "table" then
		for k,v in pairs(value) do
			node = makeTag("name",string.upper(k))
			node = node .. makeTag("value",makeTag("string",v))
			node = makeTag("member",node)
			tempString = tempString .. node
		end
		return makeTag("param",makeTag("value",makeTag("struct",tempString)))
		
	else
		return makeTag("param",makeTag("value",makeTag("string",value)))
	end
end
function hostMatch(os,check)
	if os == nil or check == nil then
		return false
	end

	if type(os) == "string" then
		if string.match(os,check) then
			return true
		else
			return false
		end
	end
	
	if type(os) == "table" then
		for k,v in pairs(os) do
                        if string.match(v,check) then
                                return true
                        end
                end
	end

	return false
end
function acquireMutex()
   if nmap.registry.Nsploit["mutex"] then
 	while nmap.registry.Nsploit["mutex"] == 1  do
		mysocket = nmap.new_socket()
		mysocket:set_timeout(1000)
		mysocket:connect("localhost",0)
   		stdnse.print_debug(1,"Waiting on Mutex") 
	end
   end
   stdnse.print_debug(1,"Got Mutex")
   nmap.registry.Nsploit["mutex"] = 1
end

function releaseMutex()
   stdnse.print_debug(1,"Giving Up Mutex")
  if nmap.registry.Nsploit["mutex"] then
	nmap.registry.Nsploit["mutex"] = 0
  end
end
