using System;
using System.Collections.Generic;

namespace NeoSmart.SecureStore
{
    sealed internal class Vault
    {
        public byte[] IV;
        public SortedDictionary<string, EncryptedBlob> Data;
    }
}
