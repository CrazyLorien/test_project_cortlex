using System;
using System.IO;
using System.Security.Cryptography;

namespace TestAuth.Helpers
{
    public class CryptoHelper
    {
        internal byte[] encrypt(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return encrypted;
        }

        internal string descrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream 
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }

        internal Tuple<byte[], byte[]> decryptKeysRSA2048(Tuple<string, string, string> keyValuePairDecrypted)
        {
            using (RSACryptoServiceProvider RsaKey = new RSACryptoServiceProvider())
            {
                RsaKey.FromXmlString(keyValuePairDecrypted.Item3);
                byte[] EncryptedDataKey = Convert.FromBase64String(keyValuePairDecrypted.Item1);
                byte[] EncryptedDataIv = Convert.FromBase64String(keyValuePairDecrypted.Item2);

                var DecryptedDataKey = RsaKey.Decrypt(EncryptedDataKey, false);
                var DecryptedDataiV = RsaKey.Decrypt(EncryptedDataIv, false);

                return new Tuple<byte[], byte[]>(DecryptedDataKey, DecryptedDataiV);
            }
        }

        internal Tuple<string, string, string> encryptKeysRSA2048(byte[] key, byte[] iV)
        {
            using (RSACryptoServiceProvider RsaKey = new RSACryptoServiceProvider())
            {

                string publickey = RsaKey.ToXmlString(false); //получим открытый ключ
                string privatekey = RsaKey.ToXmlString(true); //

                string EncryptedDataKey;
                string EncryptedDataIv;
                EncryptedDataKey = Convert.ToBase64String(RsaKey.Encrypt(key, false));
                EncryptedDataIv = Convert.ToBase64String(RsaKey.Encrypt(iV, false));

                return new Tuple<string, string, string>(EncryptedDataKey, EncryptedDataIv,privatekey);
            }
           
        }
    }
}

