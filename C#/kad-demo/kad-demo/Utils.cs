using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace kad_demo
{
    public class Utils
    {
        public static string GetKey(string path)
        {
            string keyPath = Path.Combine(Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory).FullName, path);
            using (var reader = new System.IO.StreamReader(keyPath))
            {
                string key = reader.ReadToEnd();
                return key;
            }
        }
    }
}
