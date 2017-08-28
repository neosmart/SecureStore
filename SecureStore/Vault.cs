using System;
using System.Collections.Generic;

namespace NeoSmart.SecureStore
{
    sealed internal class Vault
    {
        string VaultVersion = "1.0";
        public byte[] IV;
        public SortedDictionary<string, EncryptedBlob> Data;
    }
}
