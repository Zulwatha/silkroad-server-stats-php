<?php
	header('Content-Type: text/html; charset=utf-8'); // to support output in unicode

	require( "SilkroadSecurity.php" );
	require( "SocketUtility.php" );
	require( "HexDump.php" );

	function Send( $socket, $buffer )
	{
		if( !socket_send_buffer( $socket, $buffer, strlen( $buffer ) ) )
		{
			@socket_close( $socket );
			echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Could not send data." );
			return false;
		}
		return true;
	}

	$param_host = $_REQUEST["host"];
	$param_port = $_REQUEST["port"];
	$param_locale = $_REQUEST["locale"];
	$param_version = $_REQUEST["version"];
	$param_timeout = $_REQUEST["timeout"];

	if( !isset( $param_host ) )
	{
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "No host set." );
		return;
	}

	if( !isset( $param_port ) )
	{
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "No port set." );
		return;
	}

	if( !isset( $param_locale ) )
	{
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "No locale set." );
		return;
	}

	if( !isset( $param_version ) )
	{
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "No version set." );
		return;
	}

	if( !isset( $param_timeout ) )
	{
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "No timeout set." );
		return;
	}

	$s = new SilkroadSecurity();

	$socket = @socket_create( AF_INET, SOCK_STREAM, 0 );
	if( $socket === false )
	{
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Could not create the socket." );
		return;
	}

	@socket_set_nonblock( $socket );
	@socket_connect( $socket, $param_host, $param_port );
	@socket_set_block( $socket );

	$r = array( $socket );
	$w = array( $socket );
	$e = array( $socket );

	if( false === @socket_select( $r, $w, $e, $param_timeout ) )
	{
		@socket_close( $socket );
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "A connection could not be established." );
		return;
	}
	if( count( $w ) != 1 || count( $e ) == 1 )
	{
		@socket_close( $socket );
		echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "A connection could not be established." );
		return;
	}

	$big_packet = false;
	$big_opcode = 0;
	$big_count = 0;
	$big_data = "";

	while( true )
	{
		$r = array( $socket );
		$w = NULL;
		$e = NULL;

		if( false === @socket_select( $r, $w, $e, $param_timeout ) )
		{
			@socket_close( $socket );
			echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "There was an error with the connection." );
			return;
		}

		if( count( $r ) != 1 )
		{
			@socket_close( $socket );
			echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "No more data was received on the socket." );
			return;
		}

		$response = socket_recv_buffer( $socket, 2 );
		if( $response == false )
		{
			@socket_close( $socket );
			echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Could not receive data." );
			return;
		}

		$header = "";

		$array = unpack( "vsize", $response );
		$response = "";

		$size = (int)$array["size"];
		if( bcand( $size, 0x8000 ) > 0 )
		{
			$expected_size = 0;
			
			$input_size = bcadd( 4, bcand( $size, 0x7FFF ) );
			$lVal = bcmod( $input_size, 8 );
			if( $lVal != 0 )
			{
				$expected_size = bcsub( bcadd( $input_size, 8 ), $lVal );
			}
			else
			{
				$expected_size = $input_size;
			}

			$enc_payload = socket_recv_buffer( $socket, $expected_size );

			$enc_payload_tmp = "";
			while( strlen( $enc_payload ) > 0 )
			{
				$val = unpack( "N", $enc_payload );
				$enc_payload = substr( $enc_payload, 4 );
				$enc_payload_tmp .= bcbytearray( hexdec( dechex( $val[1] ) ), 4 );
			}

			$dec_payload = mcrypt_ecb( MCRYPT_BLOWFISH, bcbytearray( $s->m_handshake_blowfish_key, 8 ), $enc_payload_tmp, MCRYPT_DECRYPT );

			$dec_payload_arr = array();
			while( strlen( $dec_payload ) > 0 )
			{
				$val = unpack( "N", $dec_payload );
				$dec_payload = substr( $dec_payload, 4 );
				$val = hexdec( dechex( $val[1] ) );

				$m = bcbytearray( $val , 4 );
				$m = unpack( "C*", $m );
				for( $x = 1; $x <= 4; ++$x )
				{
					array_push( $dec_payload_arr, $m[$x] );
				}
			}

			$payload = "";

			$dec_payload_arr = array_splice( $dec_payload_arr, 0, $input_size );
			for( $x = 0; $x < count( $dec_payload_arr ); ++$x )
			{
				$payload .= pack( "C", bchexdec( bcdechex( $dec_payload_arr[$x] ) ) );
			}

			$header = unpack( "vopcode/vsecurity", $payload );
			$header["size"] = bcsub( $input_size, 4 );
			$header["encrypted"] = true;

			if( $header["size"] > 0 )
			{
				$payload = substr( $payload, 4 );
				$header["payload"] = hexdump( $payload );
			}
			else
			{
				$payload = "";
			}
		}
		else
		{
			$header = socket_recv_buffer( $socket, 4 );
			$header = unpack( "vopcode/vsecurity", $header );
			$header["size"] = $size;
			$header["encrypted"] = false;

			if( $size > 0 )
			{
				$payload = socket_recv_buffer( $socket, $size );
				$header["payload"] = hexdump( $payload );
			}
		}

		// Debugging
		//print_r( $header );
		//print( PHP_EOL . "<br />". PHP_EOL );

		if( $header["opcode"] == 0x5000 )
		{
			$data = unpack( "Cflag", $payload );
			if( $data["flag"] == 0x0E )
			{
				$data = unpack( "Cflag/Vblowfishlow/Vblowfishhigh/Vseedcount/Vseedcrc/Vhandshakelow/Vhandshakehigh/Vg/Vp/VA", $payload );
				$packet_payload = $s->Handshake_E( $data );

				if( !Send( $socket, $packet_payload ) )
					return;
			}
			else if( $data["flag"] == 0x10 )
			{
				$data = unpack( "Cflag/Vhandshakelow/Vhandshakehigh", $payload );
				$packet_payload = $s->Handshake_10( $data );

				if( !Send( $socket, $packet_payload ) )
					return;

				$new_payload = pack( "va9C", 9, "SR_Client", 0 );
				$packet_payload = $s->format_packet( 0x2001, $new_payload, true );

				if( !Send( $socket, $packet_payload ) )
					return;
			}
			else
			{
				@socket_close( $socket );
				echo( "Unknown flag: " . dechex( $data["flag"] ) );
				return;
			}
		}
		else if( $header["opcode"] == 0x2001 )
		{
			$new_payload = pack( "Cva9V", $param_locale, 9, "SR_Client", $param_version );
			$packet_payload = $s->format_packet( 0x6100, $new_payload, true );

			if( !Send( $socket, $packet_payload ) )
				return;
		}
		else if( $header["opcode"] == 0x600D )
		{
			$type = unpack_uint8( $payload );
			if( $type == 1 ) // header
			{
				if( $big_packet == true )
				{
					@socket_close( $socket );
					echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Received an invalid 0x600d packet. Duplicate header." );
					return;
				}

				$big_count = unpack_uint16( $payload );
				$big_opcode = unpack_uint16( $payload );

				$big_packet = true;
			}
			else if( $type == 0 ) // data
			{
				if( !$big_packet )
				{
					@socket_close( $socket );
					echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Received an invalid 0x600d packet. Out of order data." );
					return;
				}

				$big_data .= $payload; // Append the data
				$payload = "";

				--$big_count; // One less packet chunk to process
				if( $big_count == 0 ) // The massive packet is complete now
				{
					$big_packet = false;
					if( $big_opcode == 0xA100 ) // 0x6100 response
					{
						$res = unpack_uint8( $big_data );

						if( $res == 1 ) // Success, now request server list
						{
							if( $param_locale == 18 ) // ISRO has this
							{
								$new_payload = "";
								$packet_payload = $s->format_packet( 0x6107, $new_payload, true );
	
								if( !Send( $socket, $packet_payload ) )
									return;
							}

							$new_payload = "";
							$packet_payload = $s->format_packet( 0x6101, $new_payload, true );

							if( !Send( $socket, $packet_payload ) )
								return;
						}
						else // Error, can be version, GatewayServer being down, etc...
						{
							print( "Error" . PHP_EOL . "<br />" . PHP_EOL );

							$res = unpack_uint8( $big_data );

							if( $res == 4 )
							{
								print( "The version packet was rejected because the GatewayServer is closed." . PHP_EOL . "<br />" . PHP_EOL );
							}
							else if( $res == 2 )
							{
								print( "The version packet was rejected because it is outdated." . PHP_EOL . "<br />" . PHP_EOL );

								$len = unpack_uint16( $big_data );
								$ip = unpack_ASCII( $big_data, $len );
								$port = unpack_uint16( $big_data );								
								$new_version = unpack_uint32( $big_data );

								print( "$ip|$port|$new_version" . PHP_EOL . "<br />" . PHP_EOL );

								$new_file = unpack_uint8( $big_data );
								while( $new_file == 1 )
								{
									$id = unpack_uint32( $big_data );
									$len = unpack_uint16( $big_data );
									$name = unpack_ASCII( $big_data, $len );
									$len = unpack_uint16( $big_data );
									$path = unpack_ASCII( $big_data, $len );
									$size = unpack_uint32( $big_data );
									$in_pk2 = unpack_uint8( $big_data );
									$new_file = unpack_uint8( $big_data );

									print( "$id|$name|$path|$size|$in_pk2" . PHP_EOL . "<br />" . PHP_EOL );
								}

								break;
							}
							else if( $res == 1 )
							{
								print( "The version packet was rejected because the version is too new." . PHP_EOL . "<br />" . PHP_EOL );
							}
							else if( $res == 5 )
							{
								print( "The version packet was rejected because the version is too old." . PHP_EOL . "<br />" . PHP_EOL );
							}
							else if( $res == 6 )
							{
								print( "The version packet was rejected because a manual patch is needed." . PHP_EOL . "<br />" . PHP_EOL );
							}
							else
							{
								print( "The version packet was rejected (Code: $res)." . PHP_EOL . "<br />" . PHP_EOL );
							}

							print( hexdump( $big_data ) );
							print( PHP_EOL . "<br />" );

							@socket_close( $socket );
							return;
						}
					}
					else if( $big_opcode == 0x2005 ) // server info, ignore
					{
					}
					else if( $big_opcode == 0x6005 ) // server info, ignore
					{
					}
					else
					{
						@socket_close( $socket );
						echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Unknown packet contained in 0x600d: 0x" . dechex( $big_opcode ) );
						return;
					}

					$big_opcode = 0;
					$big_data = "";
				}
			}
			else
			{
				@socket_close( $socket );
				echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Unknown type(" . $type . ") in 0x600d." );
				return;
			}
		}
		else if( $header["opcode"] == 0xA107 ) // ISRO
		{
			$count = unpack_uint8( $payload );
			for( $x = 0; $x < $count; ++$x )
			{
				$id = unpack_uint8( $payload );
				$len = unpack_uint16( $payload );
				$ip = unpack_ASCII( $payload, $len );
				$port = unpack_uint16( $payload );
				//echo( "id: $id ip: $ip port: $port<br />" );
			}
			//echo( "<br />" );
		}
		else if( $header["opcode"] == 0xA101 )
		{
			print( "Success" . PHP_EOL . "<br />" . PHP_EOL );

			$header = true;

			$new_server = unpack_uint8( $payload );
			while( $new_server == 1 )
			{
				$id = unpack_uint8( $payload );
				$len = unpack_uint16( $payload );
				$name = unpack_ASCII( $payload, $len );
				//echo( "id: $id name: $name<br />" );
				$new_server = unpack_uint8( $payload );
			}

			$new_server = unpack_uint8( $payload );
			while( $new_server == 1 )
			{
				$id = unpack_uint16( $payload );

				$len = unpack_uint16( $payload );

				if( $param_locale == 18 )
				{
					$c = chr( unpack_int8( $payload ) );
					if( $c == '1' )
					{
						$c = "USA";
					}
					else if( $c == '0' )
					{
						$c = "Korea";
					}

					$len--;
					$name = unpack_ASCII( $payload, $len );

					$ratio = unpack_float( $payload );
				}
				else
				{
					$name = unpack_ASCII( $payload, $len );
					$cur = unpack_uint16( $payload );
					$max = unpack_uint16( $payload );
				}

				$state = unpack_uint8( $payload );

				if( $param_locale == 4 || $param_locale == 23 ) // csro/vsro extra bytes
				{
					$extra1 = unpack_uint8( $payload );
					$extra2 = "";

					if( $extra1 == 1 )
					{
						$extra2 = unpack_uint8( $payload );
					}
				}

				if( $param_locale == 40 ) // russian
				{
					$name = mb_convert_encoding( $name, "utf-8", "Windows-1251" );
				}
				else if( $param_locale == 2 ) // korean
				{
					$name = mb_convert_encoding( $name, "utf-8", "EUC-KR" );
				}
				else if( $param_locale == 4 ) // chinese
				{
					$name = mb_convert_encoding( $name, "utf-8", "EUC-CN" );
				}
				else if( $param_locale == 12 ) // taiwanese
				{
					$name = mb_convert_encoding( $name, "utf-8", "BIG-5" );
				}
				else if( $param_locale == 15 ) // japanese
				{
					$name = mb_convert_encoding( $name, "utf-8", "EUC-JP" ); // not tested, might need to use something else
				}
				else // everything else that uses default windows codepage
				{
					$name = mb_convert_encoding( $name, "utf-8", "Windows-1252" );
				}

				if( $param_locale == 18 )
				{
					if( $header )
					{
						print( "Id|Country|Name|Ratio|State" . PHP_EOL . "<br />" . PHP_EOL );
					}
					print( "$id|$c|$name|$ratio|$state" . PHP_EOL . "<br />" . PHP_EOL );
				}
				else if( $param_locale == 4 || $param_locale == 23 )
				{
					if( $header )
					{
						print( "Id|Name|Cur|Max|State|Extra1|Extra2" . PHP_EOL . "<br />" . PHP_EOL );
					}
					print( "$id|$name|$cur|$max|$state|$extra1|$extra2" . PHP_EOL . "<br />" . PHP_EOL );
				}
				else
				{
					if( $header )
					{
						print( "Id|Name|Cur|Max|State" . PHP_EOL . "<br />" . PHP_EOL );
					}
					print( "$id|$name|$cur|$max|$state" . PHP_EOL . "<br />" . PHP_EOL );
				}

				$new_server = unpack_uint8( $payload );
				
				$header = false;
			}
			break;
		}
		else
		{
			@socket_close( $socket );
			echo( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Unknown opcode: 0x" . dechex( $header["opcode"] ) );
			return;
		}
	}

	@socket_close( $socket );
	return;
?>