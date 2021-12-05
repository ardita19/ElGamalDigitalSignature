using ElGamal.Structs;
using System;
using ElGamal.Extension;
using System.Security.Cryptography;
using System.Xml;

namespace ElGamal
{
    public class ElGamal : AsymmetricAlgorithm
    {
        private ElGamalKeyStruct keyStruct;
        public ElGamal()
        {
            keyStruct = new ElGamalKeyStruct();
            keyStruct.P = new BigInteger(0);
            keyStruct.G = new BigInteger(0);
            keyStruct.Y = new BigInteger(0);
            keyStruct.X = new BigInteger(0);
            KeySizeValue = 1024;
            LegalKeySizesValue = new KeySizes[] { new KeySizes(256, 1024, 8) };
        }
        /// <summary>
        /// This method contains .Net framework methods that are specially added for generation of pseudo-
        /// prime numbers and random bits
        /// </summary>
        /// <param name="nrOfBits"></param>
        private void CreateKeyPair(int nrOfBits)
        {
            Random randomGenerator = new Random();

            keyStruct.P = BigInteger.genPseudoPrime(nrOfBits,20, randomGenerator);

            keyStruct.X = new BigInteger();
            keyStruct.X.genRandomBits(nrOfBits - 1, randomGenerator);
            keyStruct.G = new BigInteger();
            keyStruct.G.genRandomBits(nrOfBits - 1, randomGenerator);

            keyStruct.Y = keyStruct.G.modPow(keyStruct.X, keyStruct.P);
        }
        private bool NeedToGenerateKey()
        {
            return keyStruct.P == 0 && keyStruct.G == 0 && keyStruct.Y == 0;
        }
        public void ImportParameters(ElGamalParameters parameters)
        {
            keyStruct.P = new BigInteger(parameters.P);
            keyStruct.G = new BigInteger(parameters.G);
            keyStruct.Y = new BigInteger(parameters.Y);
            if (parameters.X != null && parameters.X.Length > 0)
            {
                keyStruct.X = new BigInteger(parameters.X);
            }
            KeySizeValue = keyStruct.P.bitCount();
        }
        public ElGamalParameters ExportParameters(bool
            includePrivateParameter)
        {

            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            ElGamalParameters parameters = new ElGamalParameters();
            parameters.P = keyStruct.P.getBytes();
            parameters.G = keyStruct.G.getBytes();
            parameters.Y = keyStruct.Y.getBytes();

            if (includePrivateParameter)
            {
                parameters.X = keyStruct.X.getBytes();
            }
            else
            {
                parameters.X = new byte[1];
            }
            return parameters;
        }
        public byte[] Sign(byte[] hashCode)
        {
            if (NeedToGenerateKey()) 
            {
               CreateKeyPair(KeySizeValue);
            }

            return ElGamalSignature.CreateSignature(hashCode, keyStruct);

        }
        public bool VerifySignature(byte[] hashCode, byte[] signature)
        {
            if (NeedToGenerateKey()) 
            {
              CreateKeyPair(KeySizeValue);
            }
            return ElGamalSignature.VerifySignature(hashCode, signature, keyStruct);
        }
        public override string ToXmlString(bool includePrivate)
        {
            ElGamalParameters keys = ExportParameters(includePrivate);
            string result = "<ElGamalKeyValue><P>" + Convert.ToBase64String(keys.P) + "</P><G>"
                 + Convert.ToBase64String(keys.G) + "</G><Y>" + Convert.ToBase64String(keys.Y) + "</Y>";
            if (includePrivate)
            {
                result += "<X>" + Convert.ToBase64String(keys.X) + "</X>";
            }
            result += "</ElGamalKeyValue>";
            return result;
        }
        public override void FromXmlString(string pString)
        {
            ElGamalParameters xParams = new ElGamalParameters();
            XmlTextReader reader = new XmlTextReader(new System.IO.StringReader(pString));

            while (reader.Read())
            {
                if (true || reader.IsStartElement())
                {
                    switch (reader.Name)
                    {
                        case "P":
                            xParams.P =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                        case "G":
                            xParams.G =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                        case "Y":
                            xParams.Y =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                        case "X":
                            xParams.X =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                    }
                }
            }
            ImportParameters(xParams);
        }
    }
}

