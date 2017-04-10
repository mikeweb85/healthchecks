<cfscript>
if ( server.os.name.startsWith("Windows") ) {
	DS = "\";
} else {
	DS = "/";
}

param url.maxmail=10;
param url.do="status";
param url.verbose=1;

InetAddress = CreateObject("java", "java.net.InetAddress");
LocalHost = InetAddress.getLocalHost();
HostName = UCase(LocalHost.getHostName());

sFactory = CreateObject("java","coldfusion.server.ServiceFactory");
MailSpoolService = sFactory.mailSpoolService;

spoolEnable = MailSpoolService.getSettings().spoolenable;
spoolDir = REReplace(Replace(MailSpoolService.getSettings().spooldir, "{neo.rootdir}", Server.ColdFusion.rootdir), "[\\/]{1,}", DS, "ALL");
undeliverDir = REReplace(Replace(MailSpoolService.getSettings().undeliverdir, "{neo.rootdir}", Server.ColdFusion.rootdir), "[\\/]{1,}", DS, "ALL");

mailSpoolQuery = DirectoryList(spoolDir, false, "query", "asc");
undeliverMailSpoolQuery = DirectoryList(undeliverDir, false, "query", "asc");

mailOk = ( mailSpoolQuery.recordcount <= url.maxmail );

if ( UCase(url.do) == "RESTART" ) {
	if ( spoolEnable ) {
		MailSpoolService.stop();
		MailSpoolService.start();
		WriteOutput("ColdFusion Mail Spool Service restarted successfully.");
		
	} else {
		WriteOutput("ColdFusion Mail Spool not enabled.");
	}
	
	exit;
	
} else if (url.verbose != 1) {
	WriteOutput( (mailOk) ? "Status: OK" : "Status: FAIL" );
	exit;
}
</cfscript>

<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>[<cfoutput>#HostName#</cfoutput>] - ColdFusion Mail Spool Status</title>
</head>

<body>
	<h2>ColdFusion Mail Spool Status</h2>
	<p>Basic information about your ColdFusion outgoing mail status.</p>
	
	<br/>
	
	<h3>Server Stats</h3>
	<table border="0" cellspacing="2" cellpadding="2">
		<tbody>
			<tr>
				<th scope="row" style="width: 200px; text-align: right;">Host:</th>
				<td><cfoutput>#HostName#</cfoutput></td>
			</tr>
			<tr>
				<th scope="row" style="width: 200px; text-align: right;">Spool Enabled:</th>
				<td><cfoutput>#spoolEnable#</cfoutput></td>
			</tr>
			<tr>
				<th scope="row" style="width: 200px; text-align: right;">Mail Queue Max Length:</th>
				<td><cfoutput>#url.maxmail#</cfoutput></td>
			</tr>
			<tr>
				<th scope="row" style="width: 200px; text-align: right;">Mail Queue Length:</th>
				<td><cfoutput>#mailSpoolQuery.recordcount#</cfoutput></td>
			</tr>
			<tr>
				<th scope="row" style="width: 200px; text-align: right;">Undeliverable Mail Length:</th>
				<td><cfoutput>#undeliverMailSpoolQuery.recordcount#</cfoutput></td>
			</tr>
			<tr style="vertical-align: top;">
				<th scope="row" style="width: 200px; text-align: right;">Status:</th>
				<td>
					<cfif mailOk>OK<cfelse>FAIL</cfif><br/>
					<small><em>* Click <a href="?do=restart">here</a> to restart ColdFusion Mail Spool Service.</em></small>
				</td>
			</tr>
		</tbody>
	</table>
</body>
</html>
