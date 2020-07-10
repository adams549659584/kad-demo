<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Demo</title>
  <style type="text/css">
.log {
  width: 80%;
  margin: 0 auto;
  word-break:break-all;
  padding: 10px;
}
  </style>
</head>
<body>
<?php

function checkEmpty($value)
{
    if (!isset($value)) {
        return true;
    }
    if ($value === null) {
        return true;
    }
    if (trim($value) === '') {
        return true;
    }
    return false;
}

/**
 * 转换字符集编码
 * @param $data
 * @param $targetCharset
 * @return string
 */
function characet($data, $charset, $targetCharset)
{
    if (!empty($data)) {
        $fileType = $charset;
        if (strcasecmp($fileType, $targetCharset) != 0) {
            $data = mb_convert_encoding($data, $targetCharset, $fileType);
        }
    }
    return $data;
}

function getSignContent($params, $charset)
{
    ksort($params);
    $stringToBeSigned = "";
    $i = 0;
    foreach ($params as $k => $v) {
        if (false === checkEmpty($v) && "@" != substr($v, 0, 1)) {
            // 转换成目标字符集
            $v = characet($v, $charset, $charset);
            if ($i == 0) {
                $stringToBeSigned .= "$k" . "=" . "$v";
            } else {
                $stringToBeSigned .= "&" . "$k" . "=" . "$v";
            }
            $i++;
        }
    }
    unset($k, $v);
    return $stringToBeSigned;
}

function sign($data, $priKey, $signType = "RSA")
{
    $res = "-----BEGIN RSA PRIVATE KEY-----\n" .
    wordwrap($priKey, 64, "\n", true) .
        "\n-----END RSA PRIVATE KEY-----";

    ($res) or die('您使用的私钥格式错误，请检查RSA私钥配置');
    if ("RSA2" == $signType) {
        openssl_sign($data, $sign, $res, version_compare(PHP_VERSION, '5.4.0', '<') ? SHA256 : OPENSSL_ALGO_SHA256); //OPENSSL_ALGO_SHA256是php5.4.8以上版本才支持
    } else {
        openssl_sign($data, $sign, $res);
    }
    $sign = base64_encode($sign);
    return $sign;
}

function verify($data, $sign, $pubKey, $signType = 'RSA')
{
    $res = "-----BEGIN PUBLIC KEY-----\n" .
    wordwrap($pubKey, 64, "\n", true) .
        "\n-----END PUBLIC KEY-----";

    ($res) or die('RSA公钥错误。请检查公钥文件格式是否正确');
    //调用openssl内置方法验签，返回bool值
    $result = false;
    if ("RSA2" == $signType) {
        $result = (openssl_verify($data, base64_decode($sign), $res, OPENSSL_ALGO_SHA256) === 1);
    } else {
        $result = (openssl_verify($data, base64_decode($sign), $res) === 1);
    }
    return $result;
}

$inputCharset = 'utf8';
$signType = 'RSA2';

$waitForSignParams = array(
    'channel' => '999', // 来源渠道，Kad提供
    'openid' => 'kadtest', // 第三方用户唯一标识
    'timestamp' => '1591394766', // 时间戳，需自行替换为当前时间戳
    'mobile' => '13766666666', // 用户手机号
    'sign_type' => $signType, // 签名方式
);

$waitForSignStr = getSignContent($waitForSignParams, $inputCharset);
echo '<div class="log">waitForSignStr = ' . htmlspecialchars($waitForSignStr) . '</div>';

$privateKeyStr = file_get_contents('keys/prv.key');
echo '<div class="log">privateKeyStr = ' . htmlspecialchars($privateKeyStr) . '</div>';

$sign = sign($waitForSignStr, $privateKeyStr, $signType);
echo '<div class="log">sign = ' . htmlspecialchars($sign) . '</div>';

$publicKeyStr = file_get_contents('keys/pub.key');
echo '<div class="log">publicKeyStr = ' . htmlspecialchars($publicKeyStr) . '</div>';

$verifyRsa2Result = verify($waitForSignStr, $sign, $publicKeyStr, $signType);
echo '<div class="log">verifyRsa2Result = ' . htmlspecialchars($verifyRsa2Result) . '</div>';

$kadLoginURL = "https://tstm.360kad.com/Login/KadAuthReturn?" . $waitForSignStr . "&sign="
. urlencode($sign);
echo '<div class="log">kadLoginURL = <a href="' . htmlspecialchars($kadLoginURL) . '">' . htmlspecialchars($kadLoginURL) . '</a></div>';

?>
</body>
</html>

