<?php

$sock = '/tmp/my_socket';
@unlink($sock);

$server = stream_socket_server('udg://'.$sock, $errno, $errstr, STREAM_SERVER_BIND);
if (!$server) die($errno.' '.$errstr."\n");
chmod($sock, 0777);

while(1) {
	$r = array($server);
	$n = stream_select($r, $w = array(), $e = array(), 5);
	if ($r) {
		$packet = stream_socket_recvfrom($server, 65535);
		parse_str($packet, $x);
		var_dump($x);
	}
}

