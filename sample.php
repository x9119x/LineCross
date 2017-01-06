<?php
date_default_timezone_set('Asia/Tokyo');
include 'LineCross.php';
use x9119x\LineCross;
use x9119x\AuthInfo;

try{
$Line = new LineCross();
print_r($Line->LineService->getProfile());
}catch(x9119x\TalkException $e)
{
	echo $e->reason.PHP_EOL;
	exit;
}
