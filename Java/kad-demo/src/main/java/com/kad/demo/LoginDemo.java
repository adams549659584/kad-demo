package com.kad.demo;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.util.Map;
import java.util.TreeMap;

import com.kad.util.RSAUtil;

import org.apache.commons.io.IOUtils;

public class LoginDemo {

  public static void main(String[] args) throws Exception {
    String inputCharset = "UTF-8";
    String signType = "RSA2";

    // 加签
    Map<String, String> waitForSignParams = new TreeMap<String, String>();
    waitForSignParams.put("channel", "999");// 来源渠道，Kad提供
    waitForSignParams.put("openid", "kadtest");// 第三方用户唯一标识
    waitForSignParams.put("timestamp", "1591394766");// 时间戳，需自行替换为当前时间戳
    waitForSignParams.put("mobile", "13766666666");// 用户手机号
    waitForSignParams.put("sign_type", signType);// 签名方式

    String waitForSignStr = RSAUtil.getSignContent(waitForSignParams);
    System.out.println("waitForSignStr = " + waitForSignStr);
    System.out.println();

    String privateKeyStr = IOUtils.toString(new FileInputStream(ClassLoader.getSystemResource("prv.key").getPath()),
        inputCharset);
    System.out.println("privateKeyStr = " + privateKeyStr);
    System.out.println();

    String sign = RSAUtil.sign(waitForSignStr, privateKeyStr, inputCharset);
    System.out.println("sign = " + sign);
    System.out.println();

    // 验签
    String publicKeyStr = IOUtils.toString(new FileInputStream(ClassLoader.getSystemResource("pub.key").getPath()),
        inputCharset);
    System.out.println("publicKeyStr = " + publicKeyStr);
    System.out.println();

    boolean verifyRsa2Result = RSAUtil.verify(waitForSignStr, publicKeyStr, sign, inputCharset);
    System.out.println("verifyRsa2Result = " + verifyRsa2Result);
    System.out.println();

    // kad 登录链接
    String kadLoginURL = "https://tstm.360kad.com/Login/KadAuthReturn?" + waitForSignStr + "&sign="
        + URLEncoder.encode(sign, inputCharset);
    System.out.println("kadLoginURL = " + kadLoginURL);
    System.out.println();
  }
}
