using System.Security.Cryptography;

namespace ADAuth
{
    public class AppConfig
    {
        public RSA rsa = RSA.Create();
        
        public Dictionary<string,string> authTargets;

        public int tokenExpireTimeInSecondes;

        public AppConfig (Dictionary<String,String> authTargets, int tokenExpireTimeInSecondes)
        {
            this.authTargets = authTargets;
            this.tokenExpireTimeInSecondes = tokenExpireTimeInSecondes > 0 ? tokenExpireTimeInSecondes : 300;
        }

        public string getRSAPublicKeyInBase64()
        {
            string result = $"-----BEGIN PUBLIC KEY-----{Environment.NewLine}#pubKey#{Environment.NewLine}-----END PUBLIC KEY-----";
            string publicKey = Convert.ToBase64String(this.rsa.ExportSubjectPublicKeyInfo());
            int lineSize = 64;
            for (int i = lineSize; i < publicKey.Length; i += lineSize + 2)
            {
                publicKey = publicKey.Insert(i, Environment.NewLine);
            }
            result = result.Replace("#pubKey#", publicKey);
            return result;
        }
    }

}
