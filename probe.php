<?php

/**
 * Set the node as ENABLED or DISABLED
 */
$NodeEnable = true;



/**
 * Get System Hostname
 */
$HostName = trim( shell_exec("hostname") );



/**
 * Header values
 * @note Use $_SERVER in PHP FastCGI or getallheaders() with mod_php
 */
$headers = $_SERVER;
$HostHeader = isset($headers['HTTP_HOST']) ? $headers['HTTP_HOST'] : $headers['SERVER_NAME'];
$Https = isset($headers['HTTPS']) ? $headers['HTTPS'] : 'off';
$RemoteAddress = $headers['REMOTE_ADDR'];
$xForwardedFor = isset($headers['HTTP_X_FORWARDED_FOR']) ? $headers['HTTP_X_FORWARDED_FOR'] : null;
$xForwardedProto = isset($headers['HTTP_X_FORWARDED_PROTO']) ? $headers['HTTP_X_FORWARDED_PROTO'] : null;



/**
 * Is this request HTTPS
 */
if ($xForwardedProto == "https" || $Https == "on") {
	$isHttps = true;
} else {
	$isHttps = false;
}
?>
<p>Server Name: <?php print $HostName ?></p>
<p>Host Name: <?php print $HostHeader ?></p>
<p>Remote Address: <?php print $RemoteAddress ?></p>
<p>X-Forwarded-For: <?php if ($xForwardedFor != ""): ?><?php print $xForwardedFor ?><?php else: ?>Not Found<?php endif; ?></p>
<p>X-Forwarded-Proto: <?php if ($xForwardedProto != ""): ?><?php print $xForwardedProto ?><?php else: ?>Not Found<?php endif; ?></p>
<p>HTTPS: <?php if ($isHttps == true): ?>TRUE<?php else: ?>FALSE<?php endif; ?></p>
<p>&nbsp;</p>
<p>Status: <?php if ($NodeEnable == true): ?>ENABLED<?php else: ?>DISABLED<?php endif; ?></p>