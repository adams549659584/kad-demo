const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function getSignContent(waitForSignParams) {
  return Object.keys(waitForSignParams)
    .sort()
    .map(key => {
      return `${key}=${waitForSignParams[key]}`;
    })
    .join('&');
}

function fillPrivateKeyMarker(privateKey) {
  return `-----BEGIN RSA PRIVATE KEY-----\n${privateKey}\n-----END RSA PRIVATE KEY-----`;
}

function fillPublicKeyMarker(publicKey) {
  return `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;
}

// 可参考支付宝官方sdk https://github.com/alipay/alipay-sdk-nodejs-all
const inputCharset = 'utf-8';
const signType = 'RSA2';
const signAlgorithm = 'RSA-SHA256';

// 加签
const waitForSignParams = {
  channel: 999, // 来源渠道，Kad提供
  openid: 'kadtest', // 第三方用户唯一标识
  timestamp: '1591394766', // 时间戳，需自行替换为当前时间戳
  mobile: '13766666666', // 用户手机号
  sign_type: signType, // 签名方式
};

const waitForSignStr = getSignContent(waitForSignParams);
console.log('waitForSignStr = ', waitForSignStr);
console.log('');

const privateKeyStr = fs.readFileSync(path.join(__dirname, './keys/prv.key'), inputCharset);
console.log('privateKeyStr = ' + privateKeyStr);
console.log('');

const sign = crypto.createSign(signAlgorithm).update(waitForSignStr, inputCharset).sign(fillPrivateKeyMarker(privateKeyStr), 'base64');
console.log('sign = ' + sign);
console.log('');

// 验签
const publicKeyStr = fs.readFileSync(path.join(__dirname, './keys/pub.key'), inputCharset);
console.log('publicKeyStr = ' + publicKeyStr);
console.log('');

const verifyRsa2Result = crypto.createVerify(signAlgorithm).update(waitForSignStr, inputCharset).verify(fillPublicKeyMarker(publicKeyStr), sign, 'base64');
console.log('verifyRsa2Result = ' + verifyRsa2Result);
console.log('');

// kad 登录链接
const kadLoginURL = `https://tstm.360kad.com/Login/KadAuthReturn?${waitForSignStr}&sign=${encodeURIComponent(sign)}`;
console.log('kadLoginURL = ' + kadLoginURL);
console.log('');
