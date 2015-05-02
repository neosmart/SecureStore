using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;

namespace SecureStore
{
    [Serializable]
    sealed internal class Vault
    {
        public byte[] IV;
        public ConcurrentDictionary<string, EncryptedBlob> Data;
    }
}
