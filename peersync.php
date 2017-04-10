<?php
/** DO NOT CACHE */
header("Expires: Mon, 26 Jul 1997 05:00:00 GMT");
header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT"); 
header("Cache-Control: no-store, no-cache, must-revalidate"); 
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");




/** MODIFY THIS SECTION ONLY */
$BaseFilePath = getcwd();
$ReplicationAllowMinutes = 3;
$BiDirectional = true;
$ServerNames = array();

/** [END] MODIFY THIS SECTION ONLY */



$HostName = strtoupper( shell_exec("hostname") );
$DTNOW = now();
$LocalWriteFilePath = $BaseFilePath . "\\" . $HostName . ".txt";
$LocalWriteFileSize = 0;
$LocalWriteError = "";
$SyncErrors = 0;

try {
	if (FALSE === ($LocalWriteFileSize = file_put_contents($LocalWriteFilePath, date("D, d M Y H:i:s", $DTNOW))) {
		throw new Exception("Unable to write to file `{$LocalWriteFilePath}`");
	}
	
} catch (Exception $e) {
	$SyncErrors++;
	$LocalWriteError = $e.getMessage();
}

?>
<!DOCTYPE html>
<html>
<head>
	<title>PeerSync Monitor</title>
</head>
<body>
	<h2>PeerSync Monitoring on <?php print $$HostName ?></h2>
	
	<h3>Updating Local Server Text File</h3>
	<?php if ($LocalWriteError == "") { ?>
	<strong>Success:</strong> File &ldquo;<em><?php print $LocalWriteFilePath ?></em>&rdquo; modified, <?php print $LocalWriteFileSize ?> bytes written.
	<?php } else { ?>
	<strong>Error:</strong> <?php print $LocalWriteError ?>
	<?php } ?>
	
<?php if ($BiDirectional === true) { ?>
	<br /><br />
	<h3>Checking PeerSync Bi-Directional Status<br /><small>Maximum time differential of <?php print $ReplicationAllowMinutes ?> minute(s)</small></h3>
	<ul>
	<?php
	$ServerNameFilePath;
	$ServerNameLastMod;
	$ServerNameDiffAllow;
	$ServerNameError;
	
	foreach (array_map('strtoupper', $ServerNames) as $ServerName) {
		$ServerNameFilePath = $BaseFilePath . "\\" . $ServerName . ".txt";
		
		try {
			if (!file_exists($ServerNameFilePath)) {
				throw new Exception("File &ldquo;<em>" . $ServerNameFilePath . "</em>&rdquo; does not exist.");
			}
			
			if (FALSE === ($ServerNameLastMod = filemtime($ServerNameFilePath))) {
				throw new Exception("Unable to access file `{$ServerNameFilePath}`");
			}
			
			$ServerNameDiffAllow = $DTNOW - strtotime("+{$ReplicationAllowMinutes} minutes", $DTNOW);
			
			if ($ServerNameDiffAllow > 0) {
				throw new Exception("File &ldquo;<em>" . $ServerNameFilePath . "</em>&rdquo; was last modified at <em>" . date("d/M/Y H:i:s", $ServerNameLastMod) . "</em>");
			}
			
			$ServerNameError = "";
			
		} catch (Exception $e) {
			$SyncErrors++;
			$ServerNameLastMod = null;
			$ServerNameDiffAllow = null;
			$ServerNameError = $e.getMessage();
		}
	?>
		<li>
		<?php if ($ServerNameError == "") { ?>
			<p><strong>Success:</strong> File &ldquo;<em><?php print $ServerNameFilePath ?></em>&rdquo; was last modified at <em><?php print date("d/M/Y H:i:s", $ServerNameLastMod); ?></em></p>
		<?php } else { ?>
			<p><strong>Error:</strong> <?php print $ServerNameError ?></p>
		<?php } ?>
		</li>
	<?php } ?>
	</ul>
<?php } ?>

	<br /><br />
	<h3>PeerSync Overall Status</h3>
<?php if ($SyncErrors == 0) { ?>
	<p><strong>Success:</strong> PeerSync running.</p>
<?php } else { ?>
	<p><strong>Error:</strong> PeerSync has <?php print $SyncErrors ?> alert(s).</p>
<?php } ?>
</body>
</html>