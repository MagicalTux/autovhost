<?php

$sock = '/tmp/my_socket';

$client = stream_socket_client('udg://'.$sock, $errno, $errstr, STREAM_SERVER_BIND);
if (!$client) die($errno.' '.$errstr."\n");

fwrite($client, "Hello world\n");

//stream_socket_sendto(

