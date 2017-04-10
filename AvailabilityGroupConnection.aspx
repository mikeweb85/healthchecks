<%@ Page Language="C#" AutoEventWireup="true" EnableSessionState="False" Debug="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Configuration" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%
Response.Cache.SetCacheability(HttpCacheability.ServerAndNoCache);



/**
 * Update the connection string to fit your need
 */
string ConnectionString = System.Configuration.ConfigurationManager.ConnectionStrings["AISPortalConnection"].ConnectionString;



/**
 * Do not modify below this line
 */
string error = "";
string ServerName = "";
DateTime DTNOW = DateTime.Now;
string HostName = System.Environment.MachineName.ToString().ToUpper();

try {
	SqlConnection con = new SqlConnection(ConnectionString);   
	SqlCommand cmd = new SqlCommand("SELECT @@SERVERNAME", con);

	con.Open();   

	SqlDataReader nwReader = cmd.ExecuteReader();

	while (nwReader.Read())
	{
		ServerName = nwReader[0].ToString();
	}

	nwReader.Close();
	con.Close();
	
} catch (Exception e) {
	error = e.Message;
}

%>
<!DOCTYPE html>
<html>
<head>
	<title>MSSQL Availability Group Connection Monitor</title>
</head>
<body>
	<h2>MSSQL Availability Group Connection Monitor</h2>
	<p><strong>Source Host:&nbsp;</strong><%= HostName %></p>
	<p><strong>Connection String:&nbsp;</strong><%= ConnectionString %></p>
	<br/>
	
	<h3>Connection Results</h3>
	<% if (error == "") { %>
	<p><strong>Connected Host:&nbsp;</strong><%= ServerName %></p>
	<% } else { %>
	<p><strong>Error:&nbsp;</strong><%= error %></p>
	<% } %>
	
	<p><strong>Status:&nbsp;</strong><% if (error == "") { %>Success<% } else { %>Fail<% } %></p>
</body>
</html>