<%@ Page Language="C#" AutoEventWireup="true" EnableSessionState="False" Debug="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%
Response.Cache.SetCacheability(HttpCacheability.ServerAndNoCache);


/** MODIFY THIS SECTION ONLY */
string BaseFilePath = Server.MapPath(".");
int ReplicationAllowMinutes = 3;
bool BiDirectional = true;
string[] ServerNames = {};

/** [END] MODIFY THIS SECTION ONLY */


string HostName = System.Environment.MachineName.ToString().ToUpper();
DateTime DTNOW = DateTime.Now;
string LocalWriteFilePath = BaseFilePath + "\\" + HostName + ".txt";
long LocalWriteFileSize = 0;
string LocalWriteError = "";
int SyncErrors = 0;

try {
	File.WriteAllText(LocalWriteFilePath, DTNOW.ToString());
	LocalWriteFileSize = new System.IO.FileInfo(LocalWriteFilePath).Length;
	
} catch (Exception e) {
	SyncErrors++;
	LocalWriteError = e.Message;
}
%>
<!DOCTYPE html>
<html>
<head>
	<title>PeerSync Monitor</title>
</head>
<body>
	<h2>PeerSync Monitoring on <%= HostName %></h2>
	
	<h3>Updating Local Server Text File</h3>
	<% if (LocalWriteError == "") { %>
	<strong>Success:</strong> File &ldquo;<em><%= LocalWriteFilePath %></em>&rdquo; modified, <%= LocalWriteFileSize %> bytes written.
	<% } else { %>
	<strong>Error:</strong> <%= LocalWriteError %>
	<% } %>
	
<% if (BiDirectional == true) { %>
	<br /><br />
	<h3>Checking PeerSync Bi-Directional Status<br /><small>Maximum time differential of <%= ReplicationAllowMinutes %> minute(s)</small></h3>
	<ul>
	<%
	string ServerNameFilePath;
	DateTime ServerNameLastMod;
	int? ServerNameDiffAllow;
	string ServerNameError;
	
	foreach (string ServerName in ServerNames) {
		ServerNameFilePath = BaseFilePath + "\\" + ServerName + ".txt";
		
		try {
			if (!File.Exists(ServerNameFilePath)) {
				throw new Exception("File &ldquo;<em>" + ServerNameFilePath + "</em>&rdquo; does not exist.");
			}
			
			ServerNameLastMod = File.GetLastWriteTime(ServerNameFilePath);
			ServerNameDiffAllow = DateTime.Compare(DTNOW, ServerNameLastMod.AddMinutes(ReplicationAllowMinutes));
			
			if (ServerNameDiffAllow > 0) {
				throw new Exception("File &ldquo;<em>" + ServerNameFilePath + "</em>&rdquo; was last modified at <em>" + ServerNameLastMod.ToString() + "</em>");
			}
			
			ServerNameError = "";
			
		} catch (Exception e) {
			SyncErrors++;
			ServerNameLastMod = DateTime.Now;
			ServerNameDiffAllow = null;
			ServerNameError = e.Message;
		}
	%>
		<li>
		<% if (ServerNameError == "") { %>
			<p><strong>Success:</strong> File &ldquo;<em><%= ServerNameFilePath %></em>&rdquo; was last modified at <em><%= ServerNameLastMod.ToString() %></em></p>
		<% } else { %>
			<p><strong>Error:</strong> <%= ServerNameError %></p>
		<% } %>
		</li>
	<% } %>
	</ul>
<% } %>

	<br /><br />
	<h3>PeerSync Overall Status</h3>
<% if (SyncErrors == 0) { %>
	<p><strong>Success:</strong> PeerSync running.</p>
<% } else { %>
	<p><strong>Error:</strong> PeerSync has <%= SyncErrors %> alert(s).</p>
<% } %>
</body>
</html>