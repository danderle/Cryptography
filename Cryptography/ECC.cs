using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;

namespace IntellicCrypto
{
    /// <summary>
    /// Class for creating ECC Keys
    /// Also able to create signatures and verify them
    /// </summary>
    public class ECC
    {
        #region Constructor
        
        public ECC()
        {
        } 
        
        #endregion

        #region Public Methods

        /// <summary>
        /// Creates a Signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="curveName"></param>
        /// <returns></returns>
        public byte[] CreateSignature(byte[] data, byte[] privateKey, string curveName)
        {
            var ecp = TeleTrusTNamedCurves.GetByName(curveName);
            if (ecp == null)
            {
                ecp = NistNamedCurves.GetByName(curveName);
            }
            var domainParameters = new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed());
            var myPriKey = new ECPrivateKeyParameters(new BigInteger(1, privateKey), domainParameters);

            var dsa = new ECDsaSigner();
            dsa.Init(true, myPriKey);
            var signature = dsa.GenerateSignature(data);
            var sign = new List<byte>();
            foreach (var bigInt in signature)
            {
                foreach (var bite in bigInt.ToByteArrayUnsigned())
                {
                    sign.Add(bite);
                }
            }
            return sign.ToArray();
        }

        /// <summary>
        /// Verifies the signature
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="publicKey"></param>
        /// <param name="curveName"></param>
        /// <returns></returns>
        public bool VerifiySignature(byte[] data, byte[] signature, byte[] publicKey, string curveName)
        {
            var ecp = TeleTrusTNamedCurves.GetByName(curveName);
            if (ecp == null)
            {
                ecp = NistNamedCurves.GetByName(curveName);
            }
            var domainParameters = new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed());
            var publicKeyParam = CreatePublicKeyParam(domainParameters, publicKey);

            var dsa = new ECDsaSigner();
            dsa.Init(false, publicKeyParam);

            var r = new BigInteger(1, signature.Take(signature.Length / 2).ToArray());
            var s = new BigInteger(1, signature.Skip(signature.Length / 2).ToArray());

            var verified = dsa.VerifySignature(data, r, s);
            string verifedTextL = verified ? "Verified" : "not verified";

            using (StreamWriter writer = File.AppendText("Working.txt"))
            {
                writer.WriteLine("{0}: {1}", curveName, verifedTextL);
            }
            return verified;
        }

        /// <summary>
        /// Creates a random key pair from given curve name
        /// </summary>
        /// <param name="curveName"></param>
        /// <returns></returns>
        public List<byte[]> CreateRandomKeyPair(string curveName)
        {
            var keyPair = new List<byte[]>();
            var ecp = TeleTrusTNamedCurves.GetByName(curveName);
            if (ecp == null)
            {
                ecp = NistNamedCurves.GetByName(curveName);
            }
            AsymmetricCipherKeyPair kp = null;
            ECPublicKeyParameters publicKey = null;
            bool success = false;
            bool compress = false;
            while (!success)
            {
                IAsymmetricCipherKeyPairGenerator kpg = GeneratorUtilities.GetKeyPairGenerator("ECDSA");

                var parameters = new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed());
                var ecP = new ECKeyGenerationParameters(parameters, new SecureRandom());
                kpg.Init(ecP);
                kp = kpg.GenerateKeyPair();
                // The very old Problem... we need a certificate chain to
                // save a private key...
                publicKey = (ECPublicKeyParameters)kp.Public;

                if (!compress)
                {
                    //pubKey.setPointFormat("UNCOMPRESSED");
                    publicKey = SetPublicUncompressed(publicKey);
                }

                byte[] x = publicKey.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
                byte[] y = publicKey.Q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned();
                if (x.Length == y.Length)
                {
                    var b = publicKey.Q.GetEncoded();
                    var bs = Hex.ToHexString(b);
                    success = true;
                    BigInteger xb = new BigInteger(1, x);
                    BigInteger yb = new BigInteger(1, y);
                   
                    ECCurve curve = parameters.Curve;
                    ECPoint q = curve.DecodePoint(b);

                    ECPoint qb = curve.CreatePoint(xb, yb);
                    curve.ValidatePoint(xb, yb); var k = new ECPublicKeyParameters(q, parameters);
                }
            }
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)kp.Private;

            if (KeysVerified(privateKey, publicKey, curveName))
            {
                var privateBytes = privateKey.D.ToByteArrayUnsigned();
                var pubKey = Hex.ToHexString(publicKey.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned()) + Hex.ToHexString(publicKey.Q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned());
                var pubKeyBytes = publicKey.Q.GetEncoded();
                keyPair.Add(privateBytes);
                keyPair.Add(pubKeyBytes);
            }

            return keyPair;
        }

        /// <summary>
        /// Returns the ec parameters as a tuple list containing the name and OID
        /// </summary>
        /// <returns></returns>
        public List<string> GetECParameters()
        {
            var list = new List<string>();
            var names = TeleTrusTNamedCurves.Names;

            foreach (string name in names)
            {
                list.Add(name);
            }

            names = NistNamedCurves.Names;
            foreach (string name in names)
            {
                list.Add(name);
            }

            return list;
        }

        #endregion
       
        #region Private Methods

        /// <summary>
        /// Verifies a public and private key by creating and verifiying a signature
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="publicKey"></param>
        /// <param name="curveName"></param>
        /// <returns></returns>
        private bool KeysVerified(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey, string curveName)
        {
            byte[] M = Hex.Decode("1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD");
            ECDsaSigner dsa = new ECDsaSigner();
            dsa.Init(true, privateKey);
            var signature = dsa.GenerateSignature(M);
            dsa.Init(false, publicKey);

            return dsa.VerifySignature(M, signature[0], signature[1]);
        }


        /// <summary>
        /// Creates an uncompressed public key parameters
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private ECPublicKeyParameters SetPublicUncompressed(
            ECPublicKeyParameters key)
        {
            ECPoint p = key.Q.Normalize();
            return new ECPublicKeyParameters(
                key.AlgorithmName,
                p.Curve.CreatePoint(p.XCoord.ToBigInteger(), p.YCoord.ToBigInteger()),
                key.Parameters);
        }

        /// <summary>
        /// Creates the public key parameters
        /// </summary>
        /// <param name="domainParams"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private ECPublicKeyParameters CreatePublicKeyParam(ECDomainParameters domainParams, byte[] key)
        {
            ECCurve curve = domainParams.Curve;
            ECPoint q = curve.DecodePoint(key);
            return new ECPublicKeyParameters(q, domainParams);
        }

        #endregion

        


    }
}
