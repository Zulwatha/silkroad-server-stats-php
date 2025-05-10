<?php
	// Sends a buffer through a socket, ensuring the entire buffer is sent
	function socket_send_buffer( &$sock, $buffer, $length )
	{
		while($length > 0)
		{
			// Attempt to send data
			$sent = @socket_write( $sock, $buffer, $length );
			if( $sent === false )
			{
				return false; // Sending failed
			}
			if( $sent < $length )
			{
				// If not all data was sent, update buffer and remaining length
				$buffer = substr( $buffer, $sent );
				$length -= $sent;
			}
			else
			{
				return true; // All data sent successfully
			} 
		}
		return false; // Fallback failure
	} 

	// Receives a specific length of data from a socket
	function socket_recv_buffer( &$sock, $length )
	{
		$all_buffer = "";
		while( $length > 0 )
		{
			$buffer = "";
			// Receive exact number of bytes requested using MSG_WAITALL
			$count = @socket_recv( $sock, $buffer, $length, MSG_WAITALL );
			if( $count == 0 )
			{
				return false; // Connection closed or error
			}
			$all_buffer .= $buffer;
			$length -= $count;
		}
		return $all_buffer; // Return full received data
	}

	// Reads an unsigned 8-bit integer from the binary stream
	function unpack_uint8( &$stream )
	{
		$val = unpack( "C", $stream );
		$val = $val[1];
		$stream = substr( $stream, 1 ); // Advance stream
		return $val;
	}
	
	// Reads a signed 8-bit integer from the binary stream
	function unpack_int8( &$stream )
	{
		$val = unpack( "c", $stream );
		$val = $val[1];
		$stream = substr( $stream, 1 );
		return $val;
	}

	// Reads an unsigned 16-bit little-endian integer
	function unpack_uint16( &$stream )
	{
		$val = unpack( "v", $stream );
		$val = $val[1];
		$stream = substr( $stream, 2 );
		return $val;
	}

	// Reads an unsigned 32-bit little-endian integer
	function unpack_uint32( &$stream )
	{
		$val = unpack( "V", $stream );
		$val = $val[1];
		$stream = substr( $stream, 4 );
		return $val;
	}

	// Reads a 32-bit float value
	function unpack_float( &$stream )
	{
		$val = unpack( "f", $stream );
		$val = $val[1];
		$stream = substr( $stream, 4 );
		return $val;
	}

	// Reads a fixed-length ASCII string
	function unpack_ASCII( &$stream, $len )
	{
		$val = implode("", unpack( "a" . $len, $stream ));
		$stream = substr( $stream, $len );
		return $val;
	}
?>
