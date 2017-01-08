<?php
namespace x9119x;
require_once __DIR__ . '/Thrift/ClassLoader/ThriftClassLoader.php';
require_once __DIR__ . '/Thrift/Exception/TException.php';
require_once __DIR__ . '/Thrift/x9119x/Types.php';
require __DIR__ . '/Thrift/x9119x/LineTalkService.php';
require __DIR__ . '/Thrift/x9119x/LinePollService.php';
require __DIR__ . '/Thrift/x9119x/LineService.php';
require __DIR__ . '/Thrift/x9119x/LineShopService.php';
@require __DIR__ . '/Thrift/Math/BigInteger.php';
@require __DIR__ . '/Thrift/Crypt/RSA.php';
use Thrift\ClassLoader\ThriftClassLoader;
$loader = new ThriftClassLoader();
$loader->registerNamespace('Thrift', __DIR__);
$loader->register();
use Thrift\Protocol\TCompactProtocol;
use Thrift\Transport\TBufferedTransport;
use Thrift\Transport\TSocket;
use Thrift\Transport\THttpClient;
use Thrift\Transport\TTransport;
use Thrift\Exception\TException;
Class AuthInfo {
    public $Mail;
    public $Pass;
    public $Cert;
    public $Token;
    public $Name;
    public $Rev;
    public function __construct($Token = NULL,$Mail = NULL, $Pass = NULL, $Cert = NULL,  $Name = "GOD", $Rev = NULL) {
        $this->Mail = $Mail;
        $this->Pass = $Pass;
        $this->Cert = $Cert;
        $this->Token = $Token;
        $this->Name = $Name;
        $this->Rev = $Rev;
    }
}
class Connection {
    public $transport;
    public $protocol;
    public $client;
}
class Connections {
    public $LineService;
    public $LinePollService;
    public $LineTalkService;
    public function __construct() {
        $this->LineService = new Connection();
        $this->LinePollService = new Connection();
        $this->LineTalkService = new Connection();
    }
}
class EndPoint {
    public $TalkService = '/api/v4/TalkService.do';
    public $Wait = '/Q';
    public $LineService = '/S4';
    public $PollService = '/P4';
}
class Host {
    public $Windows_1 = 'gd2.line.naver.jp';
    public $Android_1 = 'gf.line.naver.jp';
    public $Host;
    public function __construct() {
        $this->Host = $this->Windows_1;
    }
}
class AppType {
    public $Mac_UA = 'DESKTOP:MAC:10.10.2-YOSEMITE-x64(4.5.0)';
    public $Mac_APP = 'DESKTOPMAC 10.10.2-YOSEMITE-x64    MAC 4.5.0';
    public $UA;
    public $APP;
    public function __construct() {
        $this->UA = $this->Mac_UA;
        $this->APP = $this->Mac_APP;
    }
}
class ServiceInfo {
    public $Host;
    public $AppType;
    public $EndPoint;
    public function __construct() {
        $this->Host = new Host();
        $this->AppType = new AppType();
        $this->EndPoint = new EndPoint();
    }
}
class LineCross {
    public $Connections;
    public $AuthInfo;
    public $LineService;
    public $PollService;
    public $ServiceInfo;
    public function __construct($AuthInfo = NULL) {
        $this->Connections = new Connections();
        $this->ServiceInfo = new ServiceInfo();
        $this->AuthInfo = $AuthInfo;
        if (empty($AuthInfo)) {
            $this->AuthInfo = new AuthInfo();
            $this->LoginWithQR();
        } elseif (!empty($Mail)) {
            $this->LoginWhithMailPass();
        }
        $this->LineService = new Service($this->ServiceInfo, $this->AuthInfo, $this->Connections->LineService);
        $this->PollService = new Poll($this->ServiceInfo, $this->AuthInfo, $this->Connections->LinePollService);
    }

    public function LoginWithQR() {
        $this->Connections->LineTalkService->transport = new THttpClient($this->ServiceInfo->Host->Host, 443, $this->ServiceInfo->EndPoint->TalkService, 'https');
        $this->Connections->LineTalkService->transport->addHeaders(["User-Agent" => $this->ServiceInfo->AppType->UA, "X-Line-Application" => $this->ServiceInfo->AppType->APP, ]);
        $this->Connections->LineTalkService->protocol = new TCompactProtocol($this->Connections->LineTalkService->transport);
        $this->Connections->LineTalkService->client = new LineTalkServiceClient($this->Connections->LineTalkService->protocol);
        $msg = $this->Connections->LineTalkService->client->getAuthQrcode(true, $this->AuthInfo->Name);
        $qrcode = $msg->qrcode;
        $verifier = $msg->verifier;
        echo ("line://au/q/" . $verifier . PHP_EOL);
        $headers = ["User-Agent: {$this->ServiceInfo->AppType->UA}", "X-Line-Application: {$this->ServiceInfo->AppType->APP}", "X-Line-Access: " . $verifier];
        $ch = curl_init();
        $options = [CURLOPT_URL => 'https://' . $this->ServiceInfo->Host->Host . $this->ServiceInfo->EndPoint->Wait, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_CUSTOMREQUEST => 'GET', ];
        curl_setopt_array($ch, $options);
        $res = json_decode(curl_exec($ch), true);
        curl_close($ch);
        $verifier = $res['result']['verifier'];
        try {
            $msg = $this->Connections->LineTalkService->client->loginWithVerifierForCertificate($verifier);
        }
        catch(TalkException $e) {
            echo $e->reason . PHP_EOL;
            exit;
        }
        $this->AuthInfo->Token = $msg->authToken;
        echo 'authToken = ' .  $this->AuthInfo->Token . PHP_EOL;
        file_put_contents(__DIR__ . '/auth.txt',  $this->AuthInfo->Token);
    }
    public function LoginWhithMailPass() {
        $this->Connections->LineTalkService->transport = new THttpClient($this->ServiceInfo->Host->Host, 443, $this->ServiceInfo->EndPoint->TalkService, 'https');
        $this->Connections->LineTalkService->transport->addHeaders(["User-Agent" => $this->ServiceInfo->AppType->UA, "X-Line-Application" => $this->ServiceInfo->AppType->APP, ]);
        $this->Connections->LineTalkService->protocol = new TCompactProtocol($this->Connections->LineTalkService->transport);
        $this->Connections->LineTalkService->client = new LineTalkServiceClient($this->Connections->LineTalkService->protocol);
        $rsakey = $this->Connections->LineTalkService->client->getRSAKeyInfo(1);
        $msg = utf8_encode(chr(mb_strlen($rsakey->sessionKey)) . $rsakey->sessionKey . chr(mb_strlen($this->AuthInfo->Mail)) . $this->AuthInfo->Mail . chr(mb_strlen($this->AuthInfo->Pass)) . $this->AuthInfo->Pass);
        $crypted = $this->export_rsa($msg, $rsakey->nvalue, $rsakey->evalue);
        $result = $this->Connections->LineTalkService->client->loginWithIdentityCredentialForCertificate(1, $rsakey->keynm, $crypted, true, '127.0.0.1', $this->AuthInfo->Name, $this->AuthInfo->Cert);
        switch ($result->type) {
            case 3: //pin required
                echo 'type to your divice [' . $result->pinCode . ']' . PHP_EOL;
                $headers = array("X-Line-Access: {$result->verifier}");
                $ch = curl_init();
                $options = [CURLOPT_URL => 'https://' . $this->ServiceInfo->Host->Host . $this->ServiceInfo->EndPoint->Wait, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_CUSTOMREQUEST => 'GET', ];
                curl_setopt_array($ch, $options);
                $res = curl_exec($ch);
                curl_close($ch);
                $json_data = json_decode($res, true);
                $vr = $json_data["result"]["verifier"];
                $log_in = $this->Connections->LineTalkService->client->loginWithVerifierForCerificate($login->vr);
                echo ('authToken = ' . $log_in->authToken . PHP_EOL);
                file_put_contents(__DIR__ . '/auth.txt', $log_in->authToken);
                $this->AuthInfo->Token = $log_in->authToken;
        }
    }
    private function export_rsa($message, $n, $e) {
        $RSA = new \Crypt_RSA();
        $A = new \Math_BigInteger($n, 16);
        $B = new \Math_BigInteger($e, 16);
        $public_key = $RSA->_convertPublicKey($A, $B);
        $RSA->setPublicKey($public_key);
        $pubkey = openssl_get_publickey($public_key);
        $msg = openssl_public_encrypt($message, $crypted, $pubkey);
        $crypted = bin2hex($crypted);
        return $crypted;
    }
}
class Service {
    public $client;
    public function __construct($ServiceInfo, $AuthInfo, $Connection) {
        $Connection->transport = new THttpClient($ServiceInfo->Host->Host, 443, $ServiceInfo->EndPoint->LineService, 'https');
        $Connection->transport->addHeaders(["User-Agent" => $ServiceInfo->AppType->UA, 
            "X-Line-Application" => $ServiceInfo->AppType->APP,
            'X-Line-Access' => $AuthInfo->Token, ]);
        $Connection->protocol = new TCompactProtocol($Connection->transport);
        $Connection->client = new LineServiceClient($Connection->protocol);
        $this->client = $Connection->client;
        if(empty($AuthInfo->Rev)){
            $AuthInfo->Rev = $Connection->client->getLastOpRevision();
        }
    }
    public function getGroupIdsInvited() {
        return $this->client->getGroupIdsInvited();
    }
    public function getUserTicket() {
        return $this->client->getUserTicket();
    }
    public function findAndAddContactsByMid($mid) {
        return $this->client->findAndAddContactsByMid(0, $mid);
    }
    public function getProfile() {
        return $this->client->getProfile();
    }
    public function getCompactGroup($groupId) {
        return $this->client->getCompactGroup($groupId);
    }
    public function getAuthQrcode($keepLoggedIn, $systemName) {
        return $this->client->getAuthQrcode($keepLoggedIn, $systemName);
    }
    public function getContacts($Mids) {
        return $this->client->getContacts($Mids);
    }
    public function acceptGroupInvitation($groupId) {
        return $this->client->acceptGroupInvitation(0, $groupId);
    }
    public function leaveGroup($groupId) {
        return $this->client->leaveGroup(0, $groupId);
    }
    public function kickoutFromGroup($groupId, $contactIds) {
        return $this->client->kickoutFromGroup(0, $groupId, $contactIds);
    }
    public function getGroup($groupId) {
        return $this->client->getGroup($groupId);
    }
    public function cancelGroupInvitation($groupId, $contactIds) {
        return $this->client->cancelGroupInvitation(0, $groupId, $contactIds);
    }
    public function sendMessage($text, $id) {
        $message = new Message();
        $message->text = $text;
        $message->to = $id;
        return $this->client->sendMessage(0, $message);
    }
    public function updateGroup($group) {
        return $this->client->updateGroup(0, $group);
    }
    public function getFavoriteMids() {
        return $this->client->getFavoriteMids();
    }
    public function inviteIntoGroup($groupId, $contactIds) {
        return $this->client->inviteIntoGroup(0, $groupId, $contactIds);
    }
    public function createGroup($name, $contactIds) {
        return $this->client->createGroup(0, $name, $contactIds);
    }
    public function leaveRoom($roomId) {
        return $this->client->leaveRoom(0, $roomId);
    }
    public function updateProfile($profile) {
        return $this->client->updateProfile(0, $profile);
    }
    public function updateRegion($region) {
        return $this->client->updateRegion($region);
    }
    public function getLastReadMessageIds($chatId) {
        return $this->client->getLastReadMessageIds($chatId);
    }
    public function getMessageBoxWrapUp($mid) {
        return $this->client->getMessageBoxWrapUp($mid);
    }
    public function getMessageBoxCompactWrapUpList($start, $messageBoxCount) {
        return $this->client->getMessageBoxCompactWrapUpList($start, $messageBoxCount);
    }
    public function getSettings() {
        return $this->client->getSettings();
    }
    public function getServerTime() {
        return $this->client->getServerTime();
    }
    public function reissueGroupTicket($groupId) {
        return $this->client->reissueGroupTicket($groupId);
    }
    public function findGroupByTicket($ticketId) {
        return $this->client->findGroupByTicket($ticketId);
    }
    public function acceptGroupInvitationByTicket($groupId, $ticketId) {
        return $this->client->acceptGroupInvitationByTicket(0, $groupId, $ticketId);
    }
}
class Poll {
    public $client;
    public $AuthInfo;
    public function __construct($ServiceInfo, $AuthInfo, $Connection) {
        $this->AuthInfo = $AuthInfo;
        $Connection->transport = new THttpClient($ServiceInfo->Host->Host, 443, $ServiceInfo->EndPoint->PollService, 'https');
        $Connection->transport->addHeaders(array("User-Agent" => $ServiceInfo->AppType->UA, "X-Line-Application" => $ServiceInfo->AppType->APP, 'X-Line-Access' => $AuthInfo->Token,));
        $Connection->protocol = new TCompactProtocol($Connection->transport);
        $Connection->client = new LinePollServiceClient($Connection->protocol);
        $this->client = $Connection->client;
    }
    public function start($count = 1) {
        return $this->client->fetchOperations($this->AuthInfo->Rev, $count);
    }
}
