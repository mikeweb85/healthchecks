<%

'**
'* Set the node as ENABLED or DISABLED
'*
NodeEnable = true



'**
'* Get System Hostname
'*
dim dos, env
set shell= CreateObject ("WScript.Shell")
set enviro = shell.Environment ("PROCESS")
HostName = enviro("COMPUTERNAME")



'**
'* Header values
'*
HostHeader = Request.ServerVariables("SERVER_NAME")
Https = Request.ServerVariables("HTTPS")
RemoteAddress = Request.ServerVariables("REMOTE_ADDR")
xForwardedFor = Request.ServerVariables("HTTP_X_FORWARDED_FOR")
xForwardedProto = Request.ServerVariables("HTTP_X_FORWARDED_PROTO")



'**
'* Is this request HTTPS
'*
if (xForwardedProto = "https" or Https = "on") then
	isHttps = true
else
	isHttps = false
end if
%>
<p>Server Name: <%= HostName %></p>
<p>Host Name: <%= HostHeader %></p>
<p>Remote Address: <%= RemoteAddress %></p>
<p>X-Forwarded-For: <% if (xForwardedFor > "") then %><%= xForwardedFor %><% else %>Not Found<% end if %></p>
<p>X-Forwarded-Proto: <% if (xForwardedProto > "") then %><%= xForwardedProto %><% else %>Not Found<% end if %></p>
<p>HTTPS: <% if (isHttps = true) then %>TRUE<% else %>FALSE<% end if %></p>
<p>&nbsp;</p>
<p>Status: <% if (NodeEnable = true) then %>ENABLED<% else %>DISABLED<% end if %></p>