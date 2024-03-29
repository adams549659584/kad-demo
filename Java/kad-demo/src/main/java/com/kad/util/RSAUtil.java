package com.kad.util;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;

public class RSAUtil {

  /**
   * 加密算法RSA
   */
  private static final String KEY_ALGORITHM = "RSA";

  /**
   * 签名算法
   */
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

  /**
   * 获取公钥的key
   */
  private static final String PUBLIC_KEY = "RSAPublicKey";

  /**
   * 获取私钥的key
   */
  private static final String PRIVATE_KEY = "RSAPrivateKey";

  /**
   * RSA最大加密明文大小
   */
  private static final int MAX_ENCRYPT_BLOCK = 117;

  /**
   * RSA最大解密密文大小
   */
  private static final int MAX_DECRYPT_BLOCK = 256;

  /**
   * 获取需签名内容
   * 
   * @param sortedParams 参数
   * @return
   */
  public static String getSignContent(Map<String, String> sortedParams) {
    StringBuilder content = new StringBuilder();
    List<String> keys = new ArrayList<String>(sortedParams.keySet());
    Collections.sort(keys);
    int index = 0;
    for (String key : keys) {
      String value = sortedParams.get(key);
      if (StringUtils.areNotEmpty(key, value)) {
        content.append(index == 0 ? "" : "&").append(key).append("=").append(value);
        index++;
      }
    }
    return content.toString();
  }

  /**
   * @param keySize 生成的秘钥长度 一般为1024或2048
   * @return
   * @throws Exception
   */
  public static Map<String, Object> genKeyPair(int keySize) throws Exception {
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
    keyPairGen.initialize(keySize);
    KeyPair keyPair = keyPairGen.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    Map<String, Object> keyMap = new HashMap<String, Object>(2);
    keyMap.put(PUBLIC_KEY, publicKey);
    keyMap.put(PRIVATE_KEY, privateKey);

    System.out.println("publicKey：" + Base64.encodeBase64(publicKey.getEncoded()));
    System.out.println("privateKey：" + Base64.encodeBase64(privateKey.getEncoded()));

    return keyMap;
  }

  /**
   * 对数据进行签名
   *
   * @param data       数据
   * @param privateKey 私钥
   * @return 对数据生成的签名
   * @throws Exception
   */

  public static String sign(byte[] data, String privateKey) throws Exception {
    byte[] keyBytes = Base64.decodeBase64(privateKey);
    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
    Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
    signature.initSign(privateK);
    signature.update(data);
    String sign = Base64.encodeBase64String(signature.sign());
    return sign;
  }

  /**
   * 对数据进行签名
   * 
   * @param waitForSignContent 待签名数据
   * @param privateKey         私钥
   * @param charsetName        字符编码
   * @return 对数据生成的签名
   * @throws Exception
   */
  public static String sign(String waitForSignContent, String privateKey, String charsetName) throws Exception {
    return sign(waitForSignContent.getBytes(charsetName), privateKey);
  }

  /**
   * 验签
   *
   * @param data      签名之前的数据
   * @param publicKey 公钥
   * @param sign      签名之后的数据
   * @return 验签是否成功
   * @throws Exception
   */
  public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
    byte[] keyBytes = Base64.decodeBase64(publicKey);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    PublicKey publicK = keyFactory.generatePublic(keySpec);
    Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
    signature.initVerify(publicK);
    signature.update(data);
    return signature.verify(Base64.decodeBase64(sign));
  }

  /**
   * 验签
   *
   * @param data        签名之前的数据
   * @param publicKey   公钥
   * @param sign        签名之后的数据
   * @param charsetName 字符编码
   * @return 验签是否成功
   * @throws Exception
   */
  public static boolean verify(String data, String publicKey, String sign, String charsetName) throws Exception {
    return verify(data.getBytes(charsetName), publicKey, sign);
  }

  /**
   * 用私钥对数据进行解密
   *
   * @param encryptedData 使用公钥加密过的数据
   * @param privateKey    私钥
   * @return 解密后的数据
   * @throws Exception
   */
  public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
    byte[] keyBytes = Base64.decodeBase64(privateKey);
    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
    // Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
    Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, privateK);

    int inputLen = encryptedData.length;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int offSet = 0;
    byte[] cache;
    int i = 0;
    // 对数据分段解密
    while (inputLen - offSet > 0) {
      if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
        cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
      } else {
        cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
      }
      out.write(cache, 0, cache.length);
      i++;
      offSet = i * MAX_DECRYPT_BLOCK;
    }
    byte[] decryptedData = out.toByteArray();
    out.close();

    return decryptedData;
  }

  /**
   * 公钥解密
   *
   * @param encryptedData 使用私钥加密过的数据
   * @param publicKey     公钥
   * @return 解密后的数据
   * @throws Exception
   */
  public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
    byte[] keyBytes = Base64.decodeBase64(publicKey);
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    Key publicK = keyFactory.generatePublic(x509KeySpec);
    Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
    cipher.init(Cipher.DECRYPT_MODE, publicK);
    int inputLen = encryptedData.length;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int offSet = 0;
    byte[] cache;
    int i = 0;
    // 对数据分段解密
    while (inputLen - offSet > 0) {
      if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
        cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
      } else {
        cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
      }
      out.write(cache, 0, cache.length);
      i++;
      offSet = i * MAX_DECRYPT_BLOCK;
    }
    byte[] decryptedData = out.toByteArray();
    out.close();
    return decryptedData;
  }

  /**
   * 公钥加密
   *
   * @param data      需要加密的数据
   * @param publicKey 公钥
   * @return 使用公钥加密后的数据
   * @throws Exception
   */
  public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
    byte[] keyBytes = Base64.decodeBase64(publicKey);
    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    Key publicK = keyFactory.generatePublic(x509KeySpec);
    // 对数据加密
    Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
    cipher.init(Cipher.ENCRYPT_MODE, publicK);
    int inputLen = data.length;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int offSet = 0;
    byte[] cache;
    int i = 0;
    // 对数据分段加密
    while (inputLen - offSet > 0) {
      if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
        cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
      } else {
        cache = cipher.doFinal(data, offSet, inputLen - offSet);
      }
      out.write(cache, 0, cache.length);
      i++;
      offSet = i * MAX_ENCRYPT_BLOCK;
    }
    byte[] encryptedData = out.toByteArray();
    out.close();
    return encryptedData;
  }

  /**
   * 私钥加密
   *
   * @param data       待加密的数据
   * @param privateKey 私钥
   * @return 使用私钥加密后的数据
   * @throws Exception
   */
  public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
    byte[] keyBytes = Base64.decodeBase64(privateKey);
    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
    Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
    Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
    cipher.init(Cipher.ENCRYPT_MODE, privateK);
    int inputLen = data.length;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int offSet = 0;
    byte[] cache;
    int i = 0;
    // 对数据分段加密
    while (inputLen - offSet > 0) {
      if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
        cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
      } else {
        cache = cipher.doFinal(data, offSet, inputLen - offSet);
      }
      out.write(cache, 0, cache.length);
      i++;
      offSet = i * MAX_ENCRYPT_BLOCK;
    }
    byte[] encryptedData = out.toByteArray();
    out.close();
    return encryptedData;
  }

  /**
   * 获取私钥
   *
   * @param keyMap 生成的秘钥对
   * @return
   * @throws Exception
   */
  public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
    Key key = (Key) keyMap.get(PRIVATE_KEY);
    return Base64.encodeBase64String(key.getEncoded());
  }

  /**
   * 获取公钥
   *
   * @param keyMap 生成的秘钥对
   * @return
   * @throws Exception
   */
  public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
    Key key = (Key) keyMap.get(PUBLIC_KEY);
    return Base64.encodeBase64String(key.getEncoded());
  }
}