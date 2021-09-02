<?php
// +----------------------------------------------------------------------
// | Wahway E8372h-820 SMS 相关接口二次封装
// +----------------------------------------------------------------------
// | 硬件版本 CL4E8372HM
// | 软件版本 11.0.1.2(H197SP1C233)
// | WEB UI 版本 WEBUI 11.0.1.2(W13SP2C233)
// +----------------------------------------------------------------------
// | Copyright (c) 2021 http://233.imjs.work All rights reserved.
// +----------------------------------------------------------------------
// | Author: jshensh <admin@imjs.work>
// +----------------------------------------------------------------------

use CustomCurl\Client;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;
use phpseclib3\Crypt\AES;

Client::setConf('userAgent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36');
Client::setConf('customHeader', [
    'Connection: keep-alive',
    'Accept: */*',
    'X-Requested-With: XMLHttpRequest',
    'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8',
    '_ResponseSource: Broswer'
]);

class Wahway
{
    const SMS_TEXT_MODE_UCS2 = 0;
    const SMS_TEXT_MODE_7BIT = 1;
    const SMS_TEXT_MODE_8BIT = 2;

    private static $obj;

    private $baseUrl, 
            $password,
            $cookieJar = [],
            $token,
            $publicKey = null;

    private function __construct($baseUrl, $password)
    {
        $this->baseUrl  = $baseUrl;
        $this->password = $password;
        $this->login();
    }

    public function __destruct() {
        $this->logout();
    }

    /**
     * 实例化
     *
     * @access public
     *
     * @param string $baseUrl 上网卡后台访问地址，例如 http://192.168.8.1
     * @param string $password 登录密码
     *
     * @return $this
     */
    public static function init($baseUrl, $password)
    {
        if (!self::$obj) {
            self::$obj = new self($baseUrl, $password);
        }
        return self::$obj;
    }

    /**
     * XML 转数组
     *
     * @access private
     *
     * @param string $str XML
     *
     * @return array
     */
    private function xmlParse($str)
    {
        return json_decode(json_encode(simplexml_load_string($str)), 1);
    }

    /**
     * 数组转 XML
     *
     * @access private
     *
     * @param array $str XML
     *
     * @return string
     */
    private function xmlStringify($name, $obj) {
        $xmlstr;
        if (is_string($obj) || is_numeric($obj)) {
            $xmlstr = "<${name}>${obj}</${name}>";
        } else if (is_array($obj)) {
            $isIndexedArray = count(array_filter(array_keys($obj), 'is_string'));
            if (!$isIndexedArray) {
                foreach ($obj as $idx => $item) {
                    $xmlstr .= $this->xmlStringify($name, $item);
                }
            } else {
                $xmlstr .= "<${name}>";
                foreach ($obj as $propName => $propVal) {
                    $xmlstr .= $this->xmlStringify($propName, $propVal);
                }
                $xmlstr .= "</${name}>";
            }
        }
        return $xmlstr;
    }

    /**
     * Wahway 的 AES 解密
     *
     * @access private
     *
     * @param string $data 加密后的 HEX，Wahway 返回的 pwd 参数
     * @param string $nonce $this->getNonce()['nonce']
     * @param string $salt $this->getNonce()['salt']
     * @param string $iter Wahway 返回的 iter 参数
     * @param string $hash Wahway 返回的 hash 参数
     *
     * @return string
     */
    private function aesDecrypt($data, $nonce, $salt, $iter, $hash)
    {
        $saltedStr = hash_pbkdf2("sha256", $nonce, hex2bin($salt), (int) $iter);
        $aesKey = substr($saltedStr, 0, 32);
        $aesIv = substr($saltedStr, 32, 16);
        $hmacKey = substr($saltedStr, 48, 16);
        $hashData = hash_hmac("sha256", hex2bin($data), hex2bin($hmacKey));
        if ($hashData !== $hash) {
            throw new \Exception('UserPwd hash error');
        }

        $cipher = new AES('cbc');
        $cipher->setIV($aesIv);
        $cipher->setKey(hex2bin($aesKey));
        $data = $cipher->decrypt(hex2bin($data));

        return $data;
    }

    /**
     * Wahway 的 RSA 加密
     *
     * @access private
     *
     * @param string $data 需要加密的数据
     *
     * @return array
     */
    private function rsaEncrypt($data)
    {
        $data = base64_encode($data);
        $res = '';
        for ($i = 0; $i < ceil(strlen($data) / 214); $i++) {
            $res .= bin2hex($this->publicKey->encrypt(substr($data, $i * 214, 214)));
        }
        return $res;
    }

    /**
     * 生成一个通讯用的随机数（包含 nonce 和 salt）
     *
     * @access private
     *
     * @return array
     */
    private function getNonce()
    {
        $nonce = bin2hex(random_bytes(32));
        $salt = bin2hex(random_bytes(32));
        $data = "{$nonce}{$salt}";

        return [
            'nonce'       => $nonce,
            'salt'        => $salt,
            'encryptData' => $this->rsaEncrypt($data)
        ];
    }

    /**
     * /api/monitoring/status，主要用来获取一个 SESSION ID
     *
     * @access private
     *
     * @return true
     */
    private function monitoringStatus()
    {
        $curlObj0 = Client::init($this->baseUrl . '/api/monitoring/status')
            ->cookieJar($this->cookieJar)
            ->setHeader('Update-Cookie', 'UpdateCookie')
            ->set('referer', $this->baseUrl . '/html/index.html?noredirect')
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        return true;
    }

    /**
     * 从指定 Header 或者 /api/webserver/token 接口中获取一个 __RequestVerificationToken
     *
     * @access private
     *
     * @param string|null $header 前一次通讯返回的 HTTP Header
     *
     * @return string|false
     */
    private function freshToken($header = null)
    {
        if ($header) {
            if (preg_match('/__RequestVerificationToken: (.{32})/', $header, $tokenTmp)) {
                $this->token = $tokenTmp[1];
                return $this->token;
            }
            return false;
        }

        $curlObj0 = Client::init($this->baseUrl . '/api/webserver/token')
            ->cookieJar($this->cookieJar)
            ->set('referer', $this->baseUrl . '/html/index.html?noredirect')
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());

        if (!$data['token']) {
            return false;
        }

        $this->token = substr($data['token'], 32);
        return $this->token;
    }

    /**
     * 登录
     *
     * @access private
     *
     * @return true
     */
    private function login()
    {
        $this->monitoringStatus();

        $firstnonce = bin2hex(random_bytes(32));
        $token = $this->freshToken();

        $curlObj0 = Client::init($this->baseUrl . '/api/user/challenge_login', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $token)
            ->setHeader('Origin', $this->baseUrl)
            ->set('referer', $this->baseUrl . '/html/index.html?noredirect')
            ->set('postFields', '<?xml version="1.0" encoding="UTF-8"?><request><username>admin</username><firstnonce>' . $firstnonce . '</firstnonce><mode>1</mode></request>')
            ->set('postFieldsBuildQuery', false)
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());

        if (isset($data['code'])) {
            throw new \Exception("Login error {$data['code']}");
        }

        $saltPassword = hash_pbkdf2("sha256", $this->password, hex2bin($data['salt']), (int) $data['iterations']);
        $serverKey = hash_hmac("sha256", hex2bin($saltPassword), "Server Key");
        $authMsg = "{$firstnonce},{$data['servernonce']},{$data['servernonce']}";
        $ckey = hash_hmac("sha256", hex2bin($saltPassword), "Client Key");
        $skey = hash("sha256", hex2bin($ckey));
        $csig = hash_hmac("sha256", hex2bin($skey), $authMsg);
        $clientProof = bin2hex(hex2bin($ckey) ^ hex2bin($csig));

        $token = $this->freshToken($curlObj0->getHeader());

        $curlObj1 = Client::init($this->baseUrl . '/api/user/authentication_login', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $token)
            ->setHeader('Origin', $this->baseUrl)
            ->set('referer', $this->baseUrl . '/html/index.html?noredirect')
            ->set('postFields', '<?xml version="1.0" encoding="UTF-8"?><request><clientproof>' . $clientProof . '</clientproof><finalnonce>' . $data['servernonce'] . '</finalnonce></request>')
            ->set('postFieldsBuildQuery', false)
            ->exec();

        if (!$curlObj1->getStatus()) {
            throw new \Exception('Curl Error', $curlObj1->getCurlErrNo());
        }

        $this->freshToken($curlObj1->getHeader());

        $data = $this->xmlParse($curlObj1->getBody());
        $this->publicKey = PublicKeyLoader::load([
            'e' => new BigInteger($data['rsae'], 16),
            'n' => new BigInteger($data['rsan'], 16)
        ]);
        $this->publicKey = $this->publicKey->withMGFHash('sha1')->withHash('sha1');

        return true;
    }

    /**
     * 删除多条短信
     *
     * @access public
     *
     * @param string|array $indexArr 短信的 Index
     *
     * @return bool
     */
    public function smsDelete($indexArr)
    {
        if (!is_array($indexArr)) {
            $indexArr = [$indexArr];
        }

        $data = array_reduce($indexArr, function($carry, $item) {
            return "<Index>${item}</Index>";
        });

        $curlObj0 = Client::init($this->baseUrl . '/api/sms/delete-sms', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $this->token)
            ->setHeader('Origin', $this->baseUrl)
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->set('postFields', '<?xml version="1.0" encoding="UTF-8"?><request>' . $data . '</request>')
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        $this->freshToken($curlObj0->getHeader());

        return $data[0] === 'OK';
    }

    /**
     * 获取短信会话数量
     *
     * @access public
     *
     * @return integer
     */
    public function smsCountContact()
    {
        $curlObj0 = Client::init($this->baseUrl . '/api/sms/sms-count-contact')
            ->cookieJar($this->cookieJar)
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        if (!isset($data['count'])) {
            return false;
        }

        return (int) $data['count'];
    }

    /**
     * 获取短信会话列表
     *
     * @access public
     *
     * @param integer $page 页码
     *
     * @return array
     */
    public function smsListContact($page = 1)
    {
        $nonce = $this->getNonce();

        $curlObj0 = Client::init($this->baseUrl . '/api/sms/sms-list-contact', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $this->token)
            ->setHeader('Origin', $this->baseUrl)
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->set('postFields', '<?xml version: "1.0" encoding="UTF-8"?><request><pageindex>' . $page . '</pageindex><readcount>20</readcount><nonce>' . $nonce['encryptData'] . '</nonce></request>')
            ->set('postFieldsBuildQuery', false)
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        $this->freshToken($curlObj0->getHeader());

        $data = $this->aesDecrypt($data['pwd'], $nonce['nonce'], $nonce['salt'], $data['iter'], $data['hash']);
        $data = $this->xmlParse(substr($data, strpos($data, '<response>')));

        return $data;
    }

    /**
     * 获取指定号码下的短信数量
     *
     * @access public
     *
     * @param string $phone 对方号码
     *
     * @return integer
     */
    public function smsCountPhone($phone)
    {
        $curlObj0 = Client::init($this->baseUrl . '/api/sms/sms-count-contact', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $this->token)
            ->setHeader('Origin', $this->baseUrl)
            ->setHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8;enc')
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->set('postFields', $this->rsaEncrypt('<?xml version=\"1.0\" encoding=\"UTF-8\"?>' . $this->xmlStringify('request', ['phone' => $phone])))
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        $this->freshToken($curlObj0->getHeader());

        return (int) $data['count'];
    }

    /**
     * 获取指定号码下的短信列表
     *
     * @access public
     *
     * @param string $phone 对方号码
     * @param integer $page 页码
     *
     * @return array
     */
    public function smsListPhone($phone, $page = 1)
    {
        $nonce = $this->getNonce();

        $data = [
            'phone'     => htmlspecialchars($phone),
            'pageindex' => $page,
            'readcount' => 20,
            'nonce'     => $nonce['encryptData']
        ];

        $curlObj0 = Client::init($this->baseUrl . '/api/sms/sms-list-phone', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $this->token)
            ->setHeader('Origin', $this->baseUrl)
            ->setHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8;enc')
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->set('postFields', $this->rsaEncrypt('<?xml version=\"1.0\" encoding=\"UTF-8\"?>' . $this->xmlStringify('request', $data)))
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        $this->freshToken($curlObj0->getHeader());

        $data = $this->aesDecrypt($data['pwd'], $nonce['nonce'], $nonce['salt'], $data['iter'], $data['hash']);
        $data = $this->xmlParse(substr($data, strpos($data, '<response>')));

        return $data;
    }

    /**
     * 发送短信
     *
     * @access public
     *
     * @param string|array $phone 收方号码
     * @param string $content 短信内容
     *
     * @return bool
     */
    public function smsSend($phone = [], $content)
    {
        if (!is_array($phone)) {
            $phone = [$phone];
        }

        $data = [
            'Index'    => -1,
            'Phones'   => [
                'Phone' => $phone
            ],
            'Sca'      => '',
            'Content'  => $content,
            'Length'   => mb_strlen($content),
            'Reserved' => strlen($content) !== mb_strlen($content) ? self::SMS_TEXT_MODE_UCS2 : self::SMS_TEXT_MODE_7BIT,
            'Date'     => date('Y-m-d H:i:s')
        ];

        $curlObj0 = Client::init($this->baseUrl . '/api/sms/send-sms', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $this->token)
            ->setHeader('Origin', $this->baseUrl)
            ->setHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8;enc')
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->set('postFields', $this->rsaEncrypt('<?xml version=\"1.0\" encoding=\"UTF-8\"?>' . $this->xmlStringify('request', $data)))
            ->set('postFieldsBuildQuery', false)
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        $this->freshToken($curlObj0->getHeader());

        return $data[0] === 'OK';
    }

    /**
     * 登出
     *
     * @access public
     *
     * @return true
     */
    public function logout()
    {
        $curlObj0 = Client::init($this->baseUrl . '/api/user/logout', 'POST')
            ->cookieJar($this->cookieJar)
            ->setHeader('__RequestVerificationToken', $this->token)
            ->setHeader('Origin', $this->baseUrl)
            ->set('referer', $this->baseUrl . '/html/content.html')
            ->set('postFields', '<?xml version="1.0" encoding="UTF-8"?><request><Logout>1</Logout></request>')
            ->exec();

        if (!$curlObj0->getStatus()) {
            throw new \Exception('Curl Error', $curlObj0->getCurlErrNo());
        }

        $data = $this->xmlParse($curlObj0->getBody());
        $this->freshToken($curlObj0->getHeader());

        self::$obj = null;

        return true;
    }
}