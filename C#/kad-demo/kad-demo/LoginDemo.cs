using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace kad_demo
{
    public class LoginDemo
    {
        public static void Run()
        {
            var inputCharset = "UTF-8";
            var signType = "RSA2";

            // 加签
            var waitForSignParams = new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                { "channel", "999" },// 来源渠道，Kad提供
                { "openid", "kadtest" },// 第三方用户唯一标识
                { "timestamp", "1591394766" },// 时间戳，需自行替换为当前时间戳
                { "mobile", "13766666666" },// 用户手机号
                { "sign_type", signType },// 签名方式
            };
            var waitForSignStr = string.Join("&", waitForSignParams.Where(x => !string.IsNullOrWhiteSpace(x.Value)).Select(x => string.Format("{0}={1}", x.Key, x.Value)));
            Console.WriteLine("waitForSignStr = " + waitForSignStr);
            Console.WriteLine();

            var privateKeyStr = Utils.GetKey("keys\\prv.key");
            Console.WriteLine("privateKeyStr = " + privateKeyStr);
            Console.WriteLine();

            // 为方便，直接用了阿里的sdk，可以自己实现rsa2加签
            var sign = Aop.Api.Util.AlipaySignature.RSASign(waitForSignStr, privateKeyStr, inputCharset, signType, false);
            Console.WriteLine("sign = " + sign);
            Console.WriteLine();

            // 验签
            var publicKeyStr = Utils.GetKey("keys\\pub.key");
            Console.WriteLine("publicKeyStr = " + publicKeyStr);
            Console.WriteLine();

            var verifyRsa2Result = Aop.Api.Util.AlipaySignature.RSACheckContent(waitForSignStr, sign, publicKeyStr, inputCharset, signType, false);
            Console.WriteLine("verifyRsa2Result = " + verifyRsa2Result);
            Console.WriteLine();

            // kad 登录链接
            var kadLoginURL = "https://tstm.360kad.com/Login/KadAuthReturn?" + waitForSignStr + "&sign="
                + HttpUtility.UrlEncode(sign);
            Console.WriteLine("kadLoginURL = " + kadLoginURL);
            Console.WriteLine();
        }
    }
}
