using System;
using System.Collections.Generic;

namespace NeoSmart.SecureStore
{
    sealed internal class Vault
    {
        internal const int SCHEMAVERSION = 1;

        public int VaultVersion;
        public byte[] IV;
        public SortedDictionary<string, EncryptedBlob> Data;
    }
}
