<?php
	// Set config by hand, via config/DB, or allow user 
	// to invoke the page with the command line. These variables
	// MUST be set before calling ServerStats.php!
	$_REQUEST["host"] = "255.255.255.255";
	$_REQUEST["port"] = 15779;
	$_REQUEST["locale"] = 22;
	$_REQUEST["version"] = 218;
	$_REQUEST["timeout"] = 5;

	// Execute the server stats page and store the results. This code doesn't change.
	ob_start();
	include( "ServerStats.php" );
	$result = ob_get_contents();
	ob_end_clean();

	// Breakup the output, this code doesn't change.
	$result = str_replace( PHP_EOL, "", $result );
	$parts = explode( "<br />", $result );

	// Check the result
	if( count( $parts[0] ) == 0 || $parts[0] != "Success" )
	{
		// TODO: When there is an error, you must output your error page,
		// or handle the error based on the data in 'parts'. Read the 
		// ServerStats.php file for various error messages to handle as well
		// as play with incorrect command lines (like older version, short 
		// timeout, etc... to test)
		print_r( $parts );
		die( "" );
	}

	// For this simple example, we output the data into a table.
	echo "<table border=\"1\">";
	for( $x = 0; $x < count( $parts ); ++$x )
	{
		$lines = explode( "|", $parts[$x] );
		if( count( $lines ) < 5 ) // empty line or success message
		{
			continue;
		}
		echo "<tr>";
		for( $y = 0; $y < count( $lines ); ++$y )
		{
			$line = $lines[$y];
			// TODO: translate names, change the text of headers, or skip the entire line, if needed based on value.
			echo "<td>" . $line . "</td>";
		}
		echo "</tr>";
	}
	echo "</table>";

	// For more advanced uses, you may store into a database instead (this page is private),
	// and then another public php page is added to load the stats from the DB.
?>