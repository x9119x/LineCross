<?php
date_default_timezone_set('Asia/Tokyo');
include 'LineCross.php';
$mail = 'YOUR_MAIL';
$password = 'YOUR_PASS';
if (file_exists(__DIR__ . '/auth.txt')) {
	$auth = file_get_contents(__DIR__ . '/auth.txt');
	try {
		$Line = new LineCross($auth);
	}
	catch(TalkException $e) {
		echo $e->reason . PHP_EOL;
		exit;
	}
} elseif (!empty($mail) && !empty($password)) {
	if (empty($cert)) {
		$cert = NULL;
	}
	try {
		$Line = new LineCross(NULL, $mail, $password, $cert);
	}
	catch(TalkException $e) {
		echo $e->reason . PHP_EOL;
		exit;
	}
} else {
	try {
		$Line = new LineCross();
	}
	catch(TalkException $e) {
		echo $e->reason . PHP_EOL;
		exit;
	}
}
print_r($Line->getProfile());
