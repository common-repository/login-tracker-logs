<?php
// TUTORIAL: http://stackoverflow.com/a/38607701/2377343

$user_ip= !empty($user_ip) ? $user_ip : '123.123.123.123';
spl_autoload_register('my_reg888'); function my_reg888($class){ include_once(str_replace(array('/','\\'), DIRECTORY_SEPARATOR, dirname(__file__)."/$class.php")) ;}
use GeoIp2\Database\Reader; 
//for country   (same for "city".. just everywhere change phrase "country" with "city")
	$reader = new Reader(dirname(__file__)."/GeoLite2-Country.mmdb");
	$record = $reader->country($user_ip);
	$reader->close();
$country_name =  $record->raw['country']['names']['en'];