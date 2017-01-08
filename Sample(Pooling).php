<?php
date_default_timezone_set('Asia/Tokyo');
include 'LineCross.php';
use x9119x\LineCross;
use x9119x\AuthInfo;

$Auth = new AuthInfo();
try{
$Line = new LineCross($Auth);
}catch(x9119x\TalkException $e)
{
	echo "\033[0;31m[ERROR]\033[0m".$e->reason . PHP_EOL;
	exit;
}

print_r($Line->LineService->getProfile());
$Pooling = new Pooling($Line);

while(true)
{
	$Ops = $Pooling->Fetch();
	echo 'a';
	if(empty($Ops))
		continue;
	foreach ($Pooling->Alloc($Ops) as $msg) {
		print_r($msg);
	}

}

class Pooling
{
	public $Line;
	public $OpType;
	public function __construct($Line) {
		$this->Line = $Line;
		$this->OpType = new x9119x\OpType();
	}

	public function Fetch()
	{
		try {
			$Ops = $this->Line->PollService->start(100);
		} catch (x9119x\TalkException $e) {
			echo "\033[0;31m[ERROR]\033[0m".$e->reason . PHP_EOL;
			exit;
		}catch(Thrift\Exception\TTransportException $e){
			echo $e->getMessage().PHP_EOL;
		}
		$msg = '';
		if(empty($Ops)){
			return;
		}
		return $Ops;

	}

	public function Alloc($Ops)
	{

		foreach ($Ops as $Op) {
			$this->Line->AuthInfo->Rev = max(intval($Op->revision), intval($this->Line->AuthInfo->Rev));

			switch ($Op->type) {
				case $this->OpType::RECEIVE_MESSAGE:
					$msg = $Op->message;
					yield $msg;
				break;
				
				default:
					break;
			}
		}
	}

}