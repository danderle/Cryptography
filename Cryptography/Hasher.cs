using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;


namespace IntellicCrypto
{
    /// <summary>
    /// The Types of hashing methods available
    /// </summary>
    public enum HashMethod
    {
        SHA1        = 0,
        SHA256      = 1,
        SHA384      = 2,
        SHA512      = 3,
        SHA3_224    = 4,
        SHA3_256    = 5,
        SHA3_384    = 6,
        SHA3_512    = 7,
        CRC32       = 8,
    }

    /// <summary>
    /// Hasher class enables different hashing methods
    /// </summary>
    public class Hasher
    {
        #region Private Properties

        /// <summary>
        /// The hashing method
        /// </summary>
        private HashMethod mHashMethod;
        
        #endregion

        #region Constructor

        /// <summary>
        /// Overloaded Constructor
        /// </summary>
        /// <param name="hashMethod"></param>
        public Hasher(HashMethod hashMethod)
        {
            mHashMethod = hashMethod;
        }
        
        #endregion

        #region Public Methods

        /// <summary>
        /// Computes the hash determined by the hashing method
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] data)
        {
            switch (mHashMethod)
            {
                case HashMethod.SHA1:
                    return ComputeSHA1(data);
                case HashMethod.SHA256:
                    return ComputeSHA256(data);
                case HashMethod.SHA384:
                    return ComputeSHA384(data);
                case HashMethod.SHA512:
                    return ComputeSHA512(data);
                case HashMethod.SHA3_224:
                    return ComputeSHA3(data, 224);
                case HashMethod.SHA3_256:
                    return ComputeSHA3(data, 256);
                case HashMethod.SHA3_384:
                    return ComputeSHA3(data, 384);
                case HashMethod.SHA3_512:
                    return ComputeSHA3(data, 512);
                case HashMethod.CRC32:
                    return ComputeCRC32(data);
                default:
                    Debugger.Break();
                    return data;
            }
        }

        /// <summary>
        /// Gets the current hashing mehtod as a string
        /// </summary>
        /// <returns></returns>
        public string GetHashLabel()
        {
            switch (mHashMethod)
            {
                case HashMethod.SHA1:
                    return "SHA-1";
                case HashMethod.SHA256:
                    return "SHA-256";
                case HashMethod.SHA384:
                    return "SHA-384";
                case HashMethod.SHA512:
                    return "SHA-512";
                case HashMethod.SHA3_224:
                    return "SHA3-224";
                case HashMethod.SHA3_256:
                    return "SHA3-256";
                case HashMethod.SHA3_384:
                    return "SHA3-384";
                case HashMethod.SHA3_512:
                    return "SHA3-512";
                case HashMethod.CRC32:
                    return "CRC32";
                default:
                    //Something failed
                    Debugger.Break();
                    return "Failed";
            }
        }
        
        #endregion

        #region Private Methods

        /// <summary>
        /// Computes the SHA3 hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="bitLength"></param>
        /// <returns></returns>
        private byte[] ComputeSHA3(byte[] data, int bitLength)
        {
            var digest = new Sha3Digest(bitLength);
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        /// <summary>
        /// Computes the SHA512 hash
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] ComputeSHA512(byte[] data)
        {
            var sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
        }

        /// <summary>
        /// Computes the SHA384 hash
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] ComputeSHA384(byte[] data)
        {
            var sha384 = SHA384.Create();
            return sha384.ComputeHash(data);
        }

        /// <summary>
        /// Computes the sha 256 hash
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] ComputeSHA256(byte[] data)
        {
            var sha256 = SHA256.Create();
            return sha256.ComputeHash(data);
        }


        /// <summary>
        /// Computes the SHA1 hash
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] ComputeSHA1(byte[] data)
        {
            var sha1 = SHA1.Create();
            return sha1.ComputeHash(data);
        }

        /// <summary>
        /// Returns a hashed data as a byte array
        /// </summary>
        /// <param name="data">Data to be hashed</param>
        /// <returns></returns>
        private byte[] ComputeCRC32(byte[] data)
        {
            UInt32 hash = Crc32.Compute(data);
            var hashBytes = new byte[4];
            hashBytes[3] = (byte)hash;
            hashBytes[2] = (byte)(hash >> 8);
            hashBytes[1] = (byte)(hash >> 16);
            hashBytes[0] = (byte)(hash >> 24);

            return hashBytes;
        }

        #endregion
    }
}
