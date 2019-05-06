using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace PksSigner
{
    /// <summary>
    /// Signer that accesses private key store (PKS) and signs without exporting the private key explicitly
    /// </summary>
    internal class PksEcdsaSigner : ECDsaSigner
    {
        private PksEcPrivateKey _privateKey; // used for signing

        public override void Init(bool forSigning, ICipherParameters parameters)
        {
            SecureRandom providedRandom = null;

            if (forSigning)
            {
                if (parameters is ParametersWithRandom rParam)
                {
                    providedRandom = rParam.Random;
                    parameters = rParam.Parameters;
                }

                _privateKey = parameters as PksEcPrivateKey ?? 
                              throw new InvalidKeyException("EC private key required for signing");
            }
            else
            {
                key = parameters as ECPublicKeyParameters ??
                           throw new InvalidKeyException("EC public key required for verification");
            }

            random = InitSecureRandom(forSigning && !kCalculator.IsDeterministic, providedRandom);
        }

        public override BigInteger[] GenerateSignature(byte[] message)
        {
            var signer = new CertificateSigner.SignerWrapper();

            byte[] signature = signer.Sign(message, 
                _privateKey.CertificateCommonName,
                _privateKey.CertificateStoreName,
                _privateKey.CertificateStoreLocation);

            if(signature == null || signature.Length != 64)
                throw new Exception($"Invalid signature length, expected 64 but got: {signature?.Length}");

            /*
             * To prevent positive values from being misinterpreted as negative values,
             * you can add a zero-byte value to the end of the array.
             * END of the array since BigInteger interprets byte array as little-endian:
             *
             * The individual bytes in the value array should be in little-endian order,
             * from lowest-order byte to highest-order byte
             */

            BigInteger r = new BigInteger(1, signature, 0, 32);
            BigInteger s = new BigInteger(1, signature, 32, 32);

            return new[] { r, s };
        }
    }
}