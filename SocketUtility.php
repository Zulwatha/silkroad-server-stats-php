<?php
	function socket_send_buffer( &$sock, $buffer, $length )
	{
		while($length > 0)
		{
			$sent = @socket_write( $sock, $buffer, $length );
			if( $sent === false )
			{
				return false; 
			}
			if( $sent < $length )
			{
				$buffer = substr( $buffer, $sent );
				$length -= $sent;
			}
			else
			{
				return true; 
			} 
		}
		return false; 
	} 

	function socket_recv_buffer( &$sock, $length )
	{
		$all_buffer = "";
		while( $length > 0 )
		{
			$buffer = "";
			$count = @socket_recv( $sock, $buffer, $length, MSG_WAITALL );
			if( $count == 0 )
			{
				return false;
			}
			$all_buffer .= $buffer;
			$length -= $count;
		}
		return $all_buffer;
	}

	function unpack_uint8( &$stream )
	{
		$val = unpack( "C", $stream );
		$val = $val[1];
		$stream = substr( $stream, 1 );
		return $val;
	}
	
	function unpack_int8( &$stream )
	{
		$val = unpack( "c", $stream );
		$val = $val[1];
		$stream = substr( $stream, 1 );
		return $val;
	}

	function unpack_uint16( &$stream )
	{
		$val = unpack( "v", $stream );
		$val = $val[1];
		$stream = substr( $stream, 2 );
		return $val;
	}

	function unpack_uint32( &$stream )
	{
		$val = unpack( "V", $stream );
		$val = $val[1];
		$stream = substr( $stream, 4 );
		return $val;
	}

	function unpack_float( &$stream )
	{
		$val = unpack( "f", $stream );
		$val = $val[1];
		$stream = substr( $stream, 4 );
		return $val;
	}

	function unpack_ASCII( &$stream, $len )
	{
		$val = implode("", unpack( "a" . $len, $stream ));
		$stream = substr( $stream, $len );
		return $val;
	}
?>