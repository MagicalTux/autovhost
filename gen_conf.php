<?php

$config = array();
$config[] = array('Options', '-Indexes');
$config[] = array('php_value', 'SMTP "smtp.dtc.com"');
$config[] = array('php_value', 'display_errors 0');

output_config($config, '/www/x/xo/xonas.com_www.config');

function output_config(array $config, $file) {
	$f = pack('c', 0x01); // version
	foreach($config as $tmp) {
		$var = $tmp[0];
		$val = $tmp[1];
		$f .= pack('cc', 0x0, strlen($var)).$var; // type 0 = "variable, length coded on 1 byte
		$f .= pack('c', strlen($val)).$val;
	}
	$f .= pack('c', 0xff); // 0xff = end of file

	var_dump($file);
	file_put_contents($file, $f);
}

