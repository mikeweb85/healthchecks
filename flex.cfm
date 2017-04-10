<cfscript>
if (isDefined("FORM.host") && FORM.host neq "") {
	flexHost = FORM.host;
} else {
	flexHost = CGI.HTTP_HOST;
}

httpRequest = new http(url="#flexHost#/flex2gateway/", method="POST");

flexPostData = binaryDecode("00030000000100046e756c6c00022f31000000e00a00000001110a81134d666c65782e6d6573736167696e672e6d657373616765732e436f6d6d616e644d657373616765136f7065726174696f6e1b636f7272656c6174696f6e4964136d657373616765496411636c69656e7449641574696d65546f4c69766509626f64790f686561646572731764657374696e6174696f6e1374696d657374616d7004050601064942313733444531452d413244332d463532362d433336462d4336353445314146454132450104000a0b01010a05094453496406076e696c2544534d6573736167696e6756657273696f6e04010106010400", "hex");

httpRequest.addParam(type="header", name="Content-Type", value="application/x-amf");
httpRequest.addParam(type="body", value=flexPostData);
 
response = httpRequest.send().getPrefix();

flexStatus = ((val(response.statusCode) == 200) && (response.mimeType eq "application/x-amf") && isObject(response.fileContent));
</cfscript>

<h3>Flex2Gateway Status</h3>
<p>Flex Host: <cfoutput>#flexHost#</cfoutput>
<p>Status: <cfif flexStatus eq True>SUCCESS<cfelse>FAILURE</cfif></p>
<hr/>
<h3>Debugging Information</h3>
<cfdump var="#GetHttpRequestData()#" label="Request Scope" />
<p>&nbsp;</p>
<cfdump var="#response#" label="Flex Response" />