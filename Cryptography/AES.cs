using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace IntellicCrypto
{
    /// <summary>
    /// Class for AES cryptography
    /// </summary>
    public class AES
    {
        public AES()
        {
        }

        /// <summary>
        /// Creates a new Aes key and IV and returns the bytes
        /// Defaulted to 128 bit size private key
        /// </summary>
        /// <returns></returns>
        public byte[] CreateAesKey()
        {
            //Key settings
            Aes key = Aes.Create();
            key.KeySize = 128;

            var aes = new List<byte>();
            foreach (var b in key.Key)
                aes.Add(b);
            foreach (var b in key.IV)
                aes.Add(b);

            return aes.ToArray();
        }

        /// <summary>
        /// Encrypts the plain data with given key and iv
        /// </summary>
        /// <param name="plainData"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plainData, byte[] key, byte[] iv)
        {
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                //Setup the encryption key settings
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.ANSIX923;

                // Create an encryptor to perform the stream transform.
                var cryptoTrans = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                //Encrypts the plain text
                var output = cryptoTrans.TransformFinalBlock(plainData, 0, plainData.Length);
                return output;
            }
        }

        /// <summary>
        /// Decrypts the encrypted data with given key and iv
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                //Setup the encryption key settings
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.ANSIX923;

                // Create an encryptor to perform the stream transform.
                var cryptoTrans = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                //Decrypts the encrypted file
                var output = cryptoTrans.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                return output;
            }   
        }
    }
}
