<cfscript>

// Debug Mode
DebugMode = (structKeyExists(url, "debug"));



// Get Request Header values
request = GetHttpRequestData(false);



// Get AdminAPI instance
try {
	instanceName = createObject("component", "cfide.adminapi.runtime").getInstanceName();
	
} catch (any e) {
	instanceName = "";
}

if (instanceName eq "") {
	try {
		instanceName =createObject("java", "jrunx.kernel.JRun").getServerName();
		
	} catch (any e) {}
}



// Set the node as ENABLED or DISABLED
NodeEnable = True;
if (structKeyExists(request.headers, "APPLICATION-DISABLE-LB") && StructFind(request.headers, "APPLICATION-DISABLE-LB") eq "true") {
	NodeEnable = False;
}



// Get System Hostname
InetAddress = CreateObject("java", "java.net.InetAddress");
LocalHost = InetAddress.getLocalHost();
ServerName = UCase(LocalHost.getHostName());
HostName = UCase(LocalHost.getHostName());



// Get Remote Address
if (structKeyExists(request.headers, "True-Client-IP")) {
	RemoteAddress = StructFind(request.headers, "True-Client-IP");
	
} else if (structKeyExists(request.headers, "X-Real-IP")) {
	RemoteAddress = StructFind(request.headers, "X-Real-IP");
	
} else if (structKeyExists(request.headers, "X-Forwarded-For")) {
	RemoteAddresses = ListToArray(StructFind(request.headers, "X-Forwarded-For"));
	RemoteAddress = RemoteAddresses[1];
	
} else {
	RemoteAddress = CGI.REMOTE_ADDR;
}



// Get HTTPS Status
Https = False;
if ( (structKeyExists(request.headers, "CF-Visitor") && FindNoCase('"scheme":"https"', StructFind(request.headers, "CF-Visitor")) neq 0) || 
	(structKeyExists(request.headers, "X-Forwarded-Proto") && StructFind(request.headers, "X-Forwarded-Proto") eq "https") || 
	(structKeyExists(request.headers, "BIGIPSSL") && StructFind(request.headers, "BIGIPSSL") eq "true") || 
	(CGI.HTTPS eq "on")) {
	Https = True;
}
</cfscript>
<h3>General Information</h3>
<p>Server Name: <cfoutput>#ServerName#</cfoutput></p>
<cfif IsDefined("instanceName") and instanceName neq "">
<p>CF Instance Name: <cfoutput>#instanceName#</cfoutput></p>
</cfif>
<p>Remote Address: <cfoutput>#RemoteAddress#</cfoutput></p>
<p>HTTPS: <cfif Https eq True>TRUE<cfelse>FALSE</cfif></p>
<cfif structKeyExists(request.headers, "X-Forwarded-For")>
<p>X-Forwarded-For: <cfoutput>#StructFind(request.headers, "X-Forwarded-For")#</cfoutput></p>
</cfif>
<cfif structKeyExists(request.headers, "X-Forwarded-Proto")>
<p>X-Forwarded-Proto: <cfoutput>#UCase(StructFind(request.headers, "X-Forwarded-Proto"))#</cfoutput></p>
</cfif>
<cfif structKeyExists(request.headers, "BIGIPSSL")>
<p>BIGIPSSL: <cfoutput>#UCase(StructFind(request.headers, "BIGIPSSL"))#</cfoutput></p>
</cfif>
<p>Status: <cfif NodeEnable eq True>ENABLED<cfelse>DISABLED</cfif></p>
<hr/>
<h3>Application Information</h3>
<p>Host Name: <cfoutput>#StructFind(request.headers, "Host")#</cfoutput></p>
<cfif structKeyExists(request.headers, "APPLICATION-NODE")>
<p>Application Node: <cfoutput>#UCase(StructFind(request.headers, "APPLICATION-NODE"))#</cfoutput></p>
</cfif>
<cfif structKeyExists(request.headers, "APPLICATION-ENV")>
<p>Application Environment: <cfoutput>#UCase(StructFind(request.headers, "APPLICATION-ENV"))#</cfoutput></p>
</cfif>
<cfif structKeyExists(request.headers, "APPLICATION-MAINTENANCE")>
<p>Maintenance Mode: <cfoutput>#UCase(StructFind(request.headers, "APPLICATION-MAINTENANCE"))#</cfoutput></p>
</cfif>
<cfif DebugMode eq True>
<hr/>
<h3>Request Headers</h3>
<cfdump var="#request.headers#" />
<hr/>
<h3>CGI Scope Variables</h3>
<cfdump var="#CGI#" />
</cfif>