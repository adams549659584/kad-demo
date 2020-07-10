package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"sort"
	"strings"
)

func getSignContent(waitForSignParams map[string]string) string {
	var list []string
	m := make(map[string]int)
	for k := range waitForSignParams {
		if _, ok := m[k]; ok {
			continue
		}
		value := waitForSignParams[k]
		if value == "" {
			continue
		}
		list = append(list, fmt.Sprintf("%s=%s", k, value))
	}
	sort.Strings(list)
	return strings.Join(list, "&")
}

func fillPrivateKeyMarker(privateKey string) string {
	return fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----", privateKey)
}

func fillPublicKeyMarker(publicKey string) string {
	return fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", publicKey)
}

func signWithRSA2(waitForSignStr string, privateKeyStr string) string {
	waitForSignBytes := []byte(waitForSignStr)
	privateKeyBytes := []byte(fillPrivateKeyMarker(privateKeyStr))
	h := sha256.New()
	h.Write(waitForSignBytes)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		panic(errors.New("private key error"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ParsePKCS1PrivateKey err", err)
		panic(err)
	}
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sign)
}

func verify(waitForSignStr string, sign string, publicKeyStr string) bool {
	waitForSignBytes := []byte(waitForSignStr)
	publicKeyBytes := []byte(fillPrivateKeyMarker(publicKeyStr))
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		panic(errors.New("public key error"))
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	hashed := sha256.Sum256(waitForSignBytes)
	signData, _ := base64.StdEncoding.DecodeString(sign)
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData)
	if err != nil {
		panic(err)
	}
	return true
}

// LoginDemoRun 运行登录简单demo 异常处理等等需自行加上
func LoginDemoRun() {
	waitForSignParams := map[string]string{
		"channel":   "999",         // 来源渠道，Kad提供
		"openid":    "kadtest",     // 第三方用户唯一标识
		"timestamp": "1591394766",  // 时间戳，需自行替换为当前时间戳
		"mobile":    "13766666666", // 用户手机号
		"sign_type": "RSA2"}        // 签名方式

	waitForSignStr := getSignContent(waitForSignParams)
	fmt.Printf("waitForSignStr = %s", waitForSignStr)
	fmt.Println()
	fmt.Println()

	privateKeyBytes, readPrvKeyErr := ioutil.ReadFile("keys/prv.key")
	if readPrvKeyErr != nil {
		panic(readPrvKeyErr)
	}
	privateKeyStr := string(privateKeyBytes)
	fmt.Printf("privateKeyStr = %s", privateKeyStr)
	fmt.Println()
	fmt.Println()

	sign := signWithRSA2(waitForSignStr, privateKeyStr)
	fmt.Printf("sign = %s", sign)
	fmt.Println()
	fmt.Println()

	// 验签
	publicKeyBytes, readPubKeyErr := ioutil.ReadFile("keys/pub.key")
	if readPubKeyErr != nil {
		panic(readPubKeyErr)
	}
	publicKeyStr := string(publicKeyBytes)
	fmt.Printf("publicKeyStr = %s", publicKeyStr)
	fmt.Println()
	fmt.Println()

	verifyRsa2Result := verify(waitForSignStr, sign, publicKeyStr)
	fmt.Printf("verifyRsa2Result = %v", verifyRsa2Result)
	fmt.Println()
	fmt.Println()

	// kad 登录链接
	kadLoginURL := fmt.Sprintf("https://tstm.360kad.com/Login/KadAuthReturn?%s&sign=%s", waitForSignStr, url.QueryEscape(sign))
	fmt.Printf("kadLoginURL = %s", kadLoginURL)
	fmt.Println()
	fmt.Println()

	fmt.Println("Hello World")
}
