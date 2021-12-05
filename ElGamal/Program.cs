using System;
using System.Text;

namespace ElGamal
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Ju lutem shkruani tekstin per nenshkrim digjital:");
            string plainTextAsString = Console.ReadLine();
            byte[] plaintextAsBytes = Encoding.Default.GetBytes(plainTextAsString);

            ElGamal elGamal = new ElGamal();
            elGamal.KeySize = 512;
            string xmlString = elGamal.ToXmlString(true);
            Console.WriteLine("\n{0}\n", xmlString);

            elGamal.FromXmlString(elGamal.ToXmlString(true));
            byte[] signature = elGamal.Sign(plaintextAsBytes);

            // signature forge
            byte[] eveSignature = new byte[signature.Length];
            for (int i = 0; i < signature.Length; i++) 
            {
                eveSignature[i] = 0xFF;
            }

            elGamal.FromXmlString(elGamal.ToXmlString(false));
            Console.WriteLine("Nenshkrimi i takon Bob-it: " + elGamal.VerifySignature(plaintextAsBytes, signature));


            //-----------------------------------------------
        }
    }
}
