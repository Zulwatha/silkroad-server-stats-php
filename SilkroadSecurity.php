<?php
	require( "bcmath.php" );
	require( "SecurityTable.php" );

	class SilkroadSecurity
	{
		public $m_initial_blowfish_key = 0;
		public $m_seed_count = 0;
		public $m_crc_seed = 0;
		public $m_handshake_blowfish_key = 0;
		public $m_value_g = 0;
		public $m_value_p = 0;
		public $m_value_A = 0;
		public $m_value_x = 0;
		public $m_value_B = 0;
		public $m_value_K = 0;
		public $m_count_byte_seeds = array( 0, 0, 0 );
		public $m_client_key = 0;
		public $m_challenge_key = 0;
		public $key_array = 0;

		function GenerateValue( &$val )
		{
			for( $i = 0; $i < 32; ++$i )
			{
				$val = bcor( bcand( bcxor( bcrightshift( bcxor( bcrightshift( bcxor( bcrightshift( bcxor( bcrightshift( bcxor( bcrightshift( $val, 2 ), $val ), 2 ), $val ), 1 ), $val ), 1 ), $val ), 1 ), $val ), 1 ), bcand( bcor( bcleftshift( bcand( $val, 1 ), 31 ), bcrightshift( $val, 1 ) ), 0xFFFFFFFE ) );
			}
			return $val;
		}

		function SetupCountByte( $seed )
		{
			if( $seed == 0 ) $seed = 0x9ABFB3B6;
			$mut = $seed;
			$mut1 = $this->GenerateValue( $mut );
            $mut2 = $this->GenerateValue( $mut );
            $mut3 = $this->GenerateValue( $mut );
            $this->GenerateValue( $mut );
			$byte1 = bcxor( bcand( $mut, 0xFF ), bcand( $mut3, 0xFF ) );
            $byte2 = bcxor( bcand( $mut1, 0xFF ), bcand( $mut2, 0xFF ) );
            if( $byte1 == 0 ) $byte1 = 1;
            if( $byte2 == 0 ) $byte2 = 1;
            $this->m_count_byte_seeds[0] = bcand( bcxor( $byte1, $byte2 ), 0xFF );
            $this->m_count_byte_seeds[1] = bcand( $byte2, 0xFF );
            $this->m_count_byte_seeds[2] = bcand( $byte1, 0xFF );
		}

		function G_pow_X_mod_P( $P, $X, $G )
		{
			$result = 1;
            $mult = $G;
			if( $X == 0 )
            {
                return 1;
            }
			while( $X != 0 )
            {
                if( bcand( $X, 1 ) > 0 )
                {
                    $result = bcmod( bcmul( $mult, $result ), $P );
                }
				$X = bcrightshift( $X, 1 );
                $mult = bcmod( bcmul( $mult, $mult ), $P );
            }
			return bcand( $result, 0xFFFFFFFF );
		}

		function KeyTransformValue( &$val, $key, $key_byte )
        {
			$s1 = bcand( bcrightshift( $val,  0 ), 0xFF );
			$s2 = bcand( bcrightshift( $val,  8 ), 0xFF );
			$s3 = bcand( bcrightshift( $val, 16 ), 0xFF );
			$s4 = bcand( bcrightshift( $val, 24 ), 0xFF );
			$s5 = bcand( bcrightshift( $val, 32 ), 0xFF );
			$s6 = bcand( bcrightshift( $val, 40 ), 0xFF );
			$s7 = bcand( bcrightshift( $val, 48 ), 0xFF );
			$s8 = bcand( bcrightshift( $val, 56 ), 0xFF );

			$s1 = bcxor( $s1, bcand( $s1 + bcand( bcrightshift( $key,  0 ), 0xFF ) + $key_byte, 0xFF ) );
			$s2 = bcxor( $s2, bcand( $s2 + bcand( bcrightshift( $key,  8 ), 0xFF ) + $key_byte, 0xFF ) );
			$s3 = bcxor( $s3, bcand( $s3 + bcand( bcrightshift( $key, 16 ), 0xFF ) + $key_byte, 0xFF ) );
			$s4 = bcxor( $s4, bcand( $s4 + bcand( bcrightshift( $key, 24 ), 0xFF ) + $key_byte, 0xFF ) );
			$s5 = bcxor( $s5, bcand( $s5 + bcand( bcrightshift( $key,  0 ), 0xFF ) + $key_byte, 0xFF ) );
			$s6 = bcxor( $s6, bcand( $s6 + bcand( bcrightshift( $key,  8 ), 0xFF ) + $key_byte, 0xFF ) );
			$s7 = bcxor( $s7, bcand( $s7 + bcand( bcrightshift( $key, 16 ), 0xFF ) + $key_byte, 0xFF ) );
			$s8 = bcxor( $s8, bcand( $s8 + bcand( bcrightshift( $key, 24 ), 0xFF ) + $key_byte, 0xFF ) );

			$val = $s1;
			$val = bcadd( $val, bcleftshift( $s2,  8 ) );
			$val = bcadd( $val, bcleftshift( $s3, 16 ) );
			$val = bcadd( $val, bcleftshift( $s4, 24 ) );
			$val = bcadd( $val, bcleftshift( $s5, 32 ) );
			$val = bcadd( $val, bcleftshift( $s6, 40 ) );
			$val = bcadd( $val, bcleftshift( $s7, 48 ) );
			$val = bcadd( $val, bcleftshift( $s8, 56 ) );
		}

		function GenerateCountByte( $update )
		{
			$result = bcand( bcmul( $this->m_count_byte_seeds[2], bcadd( bcnot( $this->m_count_byte_seeds[0] ), $this->m_count_byte_seeds[1] ) ), 0xFF );
            $result = bcand( bcxor( $result, bcrightshift( $result, 4 ) ), 0xFF );
            if( $update == true )
            {
                $this->m_count_byte_seeds[0] = $result;
            }
            return $result;
		}

		function GenerateCheckByte( $stream, $offset, $length )
		{
			global $global_security_table;
			
			$stream = unpack( "C*", $stream );
			$checksum = 0xFFFFFFFF;
			$moddedseed = bcleftshift( $this->m_crc_seed, 8 );
			for( $x = $offset; $x < $offset + $length; ++$x )
			{
				$checksum = bcxor( bcrightshift( $checksum, 8 ), $global_security_table[bcadd( $moddedseed, bcand( bcxor( $stream[$x + 1], $checksum ), 0xFF ) )] );
			}
			$val = bcand( $checksum, 0xFF );
			$val = bcadd( $val, bcand( bcrightshift( $checksum,  8 ), 0xFF ) );
			$val = bcadd( $val, bcand( bcrightshift( $checksum, 16 ), 0xFF ) );
			$val = bcadd( $val, bcand( bcrightshift( $checksum, 24 ), 0xFF ) );
			return bcand( $val, 0xFF );
		}

		function Handshake_10( $data )
		{
			$this->m_challenge_key = bcadd( hexdec( dechex( $data["handshakelow"] ) ), bcleftshift( hexdec( dechex( $data["handshakehigh"] ) ), 32 ) );

			$expected_challenge_key = bcadd( $this->m_value_A, bcleftshift( $this->m_value_B, 32 ) );

			$this->KeyTransformValue( $expected_challenge_key, $this->m_value_K, bcand( $this->m_value_A, 7 ) );
			$expected_challenge_key = mcrypt_ecb( MCRYPT_BLOWFISH, bcbytearray( $this->key_array, 8 ), swap( bcbytearray( $expected_challenge_key, 8 ), 8 ), MCRYPT_ENCRYPT );

			$arr = unpack( "Nl/Nh", $expected_challenge_key );
			$arr["l"] = hexdec( dechex( $arr["l"] ) );
			$arr["h"] = hexdec( dechex( $arr["h"] ) );

			$expected_challenge_key = bcadd( $arr["l"], bcleftshift( $arr["h"], 32 ) );

			if( bcdechex( $expected_challenge_key ) != bcdechex( $this->m_challenge_key ) )
			{
				die( "Error" . PHP_EOL . "<br />" . PHP_EOL . "Server signature error. " . bcdechex( $this->m_challenge_key ) . " vs " . bcdechex( $expected_challenge_key ) );
			}

			$this->KeyTransformValue( $this->m_handshake_blowfish_key, $this->m_value_K, 0x3 );

			$new_payload = ""; // Nothing for 0x9000
			return $this->format_packet( 0x9000, $new_payload, false );
		}

		function Handshake_E( $data )
		{
			$this->m_initial_blowfish_key = bcadd( $data["blowfishlow"], bcleftshift( $data["blowfishhigh"], 32 ) );
			$this->m_seed_count = bcadd( $data["seedcount"], 0 );
			$this->m_crc_seed = bcadd( $data["seedcrc"], 0 );
			$this->m_handshake_blowfish_key = bcadd( hexdec( dechex( $data["handshakelow"] ) ), bcleftshift( hexdec( dechex( $data["handshakehigh"] ) ), 32 ) );
			$this->m_value_g = bcadd( $data["g"], 0 );
			$this->m_value_p = bcadd( $data["p"], 0 );
			$this->m_value_A = bcadd( $data["A"], 0 );
			$this->SetupCountByte( $this->m_seed_count );
			$this->m_value_x = mt_rand( 0, 0x7FFFFFFF );

			$this->m_value_B = $this->G_pow_X_mod_P( $this->m_value_p, $this->m_value_x, $this->m_value_g );
			$this->m_value_K = $this->G_pow_X_mod_P( $this->m_value_p, $this->m_value_x, $this->m_value_A );

			$this->key_array = bcadd( $this->m_value_A, bcleftshift( $this->m_value_B, 32 ) );
			$this->KeyTransformValue( $this->key_array, $this->m_value_K, bcand( $this->m_value_K, 3 ) );

			$this->m_client_key = bcadd( $this->m_value_B, bcleftshift( $this->m_value_A, 32 ) );
			$this->KeyTransformValue( $this->m_client_key, $this->m_value_K, bcand( $this->m_value_B, 7 ) );

			$this->m_client_key = mcrypt_ecb( MCRYPT_BLOWFISH, bcbytearray( $this->key_array, 8 ), swap( bcbytearray( $this->m_client_key, 8 ), 8 ), MCRYPT_ENCRYPT );

			$arr = unpack( "Nl/Nh", $this->m_client_key );
			$arr["l"] = hexdec( dechex( $arr["l"] ) );
			$arr["h"] = hexdec( dechex( $arr["h"] ) );

			$this->m_client_key = bcadd( $arr["l"], bcleftshift( $arr["h"], 32 ) );

			// Build the 0x5000 response packet
			$new_payload = pack( "VVV", $this->m_value_B, $arr["l"], $arr["h"] );
			return $this->format_packet( 0x5000, $new_payload, false );
		}

		function format_packet( $opcode, $new_payload, $encrypted = false )
		{
			if( $encrypted == false )
			{
				$packet_payload = "";
				$packet_payload .= pack( "v", strlen( $new_payload ) );
				$packet_payload .= pack( "v", $opcode );
				$packet_payload .= pack( "C", $this->GenerateCountByte( false ) );
				$packet_payload .= pack( "C", 0 );
				$packet_payload .= $new_payload;

				$crc = $this->GenerateCheckByte( $packet_payload, 0, strlen( $packet_payload ) );

				$packet_payload = "";
				$packet_payload .= pack( "v", strlen( $new_payload ) );
				$packet_payload .= pack( "v", $opcode );
				$packet_payload .= pack( "C", $this->GenerateCountByte( true ) );
				$packet_payload .= pack( "C", $crc );
				$packet_payload .= $new_payload;
			}
			else
			{
				$len = bcor( 0x8000, strlen( $new_payload ) );

				$packet_payload = "";
				$packet_payload .= pack( "v", $len );
				$packet_payload .= pack( "v", $opcode );
				$packet_payload .= pack( "C", $this->GenerateCountByte( false ) );
				$packet_payload .= pack( "C", 0 );
				$packet_payload .= $new_payload;

				$crc = $this->GenerateCheckByte( $packet_payload, 0, strlen( $packet_payload ) );

				$packet_payload = "";
				$packet_payload .= pack( "v", $len );

				$packet_payload_tmp = "";
				$packet_payload_tmp .= pack( "v", $opcode );
				$packet_payload_tmp .= pack( "C", $this->GenerateCountByte( true ) );
				$packet_payload_tmp .= pack( "C", $crc );
				$packet_payload_tmp .= $new_payload;

				$packet_payload_tmp = pad( $packet_payload_tmp, strlen( $packet_payload_tmp ) );
				$packet_payload_tmp = swap( $packet_payload_tmp, strlen( $packet_payload_tmp ) );
				$packet_payload_tmp = mcrypt_ecb( MCRYPT_BLOWFISH, bcbytearray( $this->m_handshake_blowfish_key, 8 ), $packet_payload_tmp, MCRYPT_ENCRYPT );

				while( strlen( $packet_payload_tmp ) > 0 )
				{
					$val = unpack( "N", $packet_payload_tmp );
					$packet_payload_tmp = substr( $packet_payload_tmp, 4 );
					$packet_payload .= bcbytearray( hexdec( dechex( $val[1] ) ), 4 );
				}
			}

			return $packet_payload;
		}
	}

	function pad( $data, $count )
	{
		if( $count % 8 == 0 )
		{
			return $data;
		}
		$padlen = 8 - ( $count % 8 );
		for( $i = 0; $i < $padlen; $i++ )
		{
			$data .= chr( 0 );
		}
		return $data; 
	}

	function swap( $data, $count ) // taken from a php.net post
	{
		if( $count % 4 )
		{
			die( "Invalid count[$count] passed to swap." );
		}
		$res = "";
		for( $i = 0; $i < $count; $i += 4 )
		{
			list( , $val ) = unpack( 'N', substr( $data, $i, 4 ) );
			$res .= pack( 'V', $val ); 
		}
		return $res;
	}
?>