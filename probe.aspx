<%@ Page Language="C#" AutoEventWireup="true" EnableSessionState="False" Debug="false" %>
<%

bool NodeEnable;
bool isHttps;
string HostName;
string HostHeader;
string RemoteAddress;
string xForwardedFor;
string xForwardedProto;
string Https;



/**
 * Set the node as ENABLED or DISABLED
 */
NodeEnable = true;



/**
 * Get System Hostname
 */
HostName = System.Environment.MachineName.ToUpper();



/**
 * Header values
 */
HostHeader = Request["HTTP_HOST"];
Https = Request["HTTPS"];
RemoteAddress = Request["REMOTE_ADDR"];
xForwardedFor = Request["HTTP_X_FORWARDED_FOR"];
xForwardedProto = Request["HTTP_X_FORWARDED_PROTO"];



/**
 * Is this request HTTPS
 */
 if (xForwardedProto == "https" || Https == "on") {
	isHttps = true;
} else {
	isHttps = false;
}




%>
<p>Server Name: <%= HostName %></p>
<p>Host Name: <%= HostHeader %></p>
<p>Remote Address: <%= RemoteAddress %></p>
<p>X-Forwarded-For: <% if (xForwardedFor != null) { %><%= xForwardedFor %><% } else { %>Not Found<% } %></p>
<p>X-Forwarded-Proto: <% if (xForwardedProto != null) { %><%= xForwardedProto %><% } else { %>Not Found<% } %></p>
<p>HTTPS: <% if (isHttps == true) { %>TRUE<% } else { %>FALSE<% } %></p>
<p>&nbsp;</p>
<p>Status: <% if (NodeEnable == true) { %>ENABLED<% } else { %>DISABLED<% } %></p>