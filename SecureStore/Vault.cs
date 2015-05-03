using System;
using System.Collections.Concurrent;

namespace NeoSmart.SecureStore
{
    [Serializable]
    sealed internal class Vault
    {
        public byte[] IV;
        public ConcurrentDictionary<string, EncryptedBlob> Data;
    }
}
