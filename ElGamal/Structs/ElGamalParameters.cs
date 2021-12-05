using System;
using System.Collections.Generic;
using System.Text;

namespace ElGamal.Structs
{
    [Serializable]
    public struct ElGamalParameters
    {
        public byte[] P;
        public byte[] G;
        public byte[] Y;
        [NonSerialized] public byte[] X;
    }
}
