using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace NeoSmart.SecureStore
{
    [Serializable]
    sealed internal class Vault
    {
        public byte[] IV;
        public SortedDictionary<string, EncryptedBlob> Data;
    }
}
