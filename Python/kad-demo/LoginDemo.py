import os
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import decodebytes, encodebytes
from urllib.parse import quote


def getSignContent(waitForSignParams):
    signContent = ""
    for (k, v) in sorted(waitForSignParams.items()):
        value = v
        if not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False)
        signContent += ("&" + k + "=" + value)
    signContent = signContent[1:]
    return signContent


def fillPrivateKeyMarker(privateKey):
    return '-----BEGIN RSA PRIVATE KEY-----\n{0}\n-----END RSA PRIVATE KEY-----'.format(privateKey)


def fillPublicKeyMarker(publicKey):
    return '-----BEGIN PUBLIC KEY-----\n{0}\n-----END PUBLIC KEY-----'.format(publicKey)


def signWithRSA2(waitForSignStr, privateKey, charset):
    key = RSA.importKey(fillPrivateKeyMarker(privateKey))
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(SHA256.new(waitForSignStr.encode(charset)))
    sign = encodebytes(signature).decode(charset).replace('\n', '')
    return sign


def verify(waitForSignStr, sign, publicKey, charset):
    key = RSA.importKey(fillPublicKeyMarker(publicKey))
    signer = PKCS1_v1_5.new(key)
    digest = SHA256.new()
    digest.update(waitForSignStr.encode(charset))
    if signer.verify(digest, decodebytes(sign.encode(charset))):
        return True
    return False


# 可参考支付宝官方sdk https://github.com/alipay/alipay-sdk-python-all/blob/master/alipay/aop/api/util/SignatureUtils.py

inputCharset = 'utf8'

# 加签
waitForSignParams = {
    'channel': '999',  # 来源渠道，Kad提供
    'openid': 'kadtest',  # 第三方用户唯一标识
    'timestamp': '1591394766',  # 时间戳，需自行替换为当前时间戳
    'mobile': '13766666666',  # 用户手机号
    'sign_type': 'RSA2'  # 签名方式
}
waitForSignStr = getSignContent(waitForSignParams)
print('waitForSignStr = ', waitForSignStr)
print()

with open(os.path.join(os.getcwd(), 'keys/prv.key')) as file:
    privateKeyStr = file.read()
    print('privateKeyStr = ', privateKeyStr)
    print()

sign = signWithRSA2(waitForSignStr, privateKeyStr, inputCharset)
print('sign = ', sign)
print()

# 验签
with open(os.path.join(os.getcwd(), 'keys/pub.key')) as file:
    publicKeyStr = file.read()
    print('publicKeyStr = ', publicKeyStr)
    print()

verifyRsa2Result = verify(
    waitForSignStr, sign, publicKeyStr, inputCharset)
print('verifyRsa2Result = ', verifyRsa2Result)
print()

# kad 登录链接
kadLoginURL = 'https://tstm.360kad.com/Login/KadAuthReturn?{0}&sign={1}'.format(
    waitForSignStr, quote(sign))
print('kadLoginURL = ', kadLoginURL)
print()
