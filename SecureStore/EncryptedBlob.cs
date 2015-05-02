using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureStore
{
    [Serializable]
    internal struct EncryptedBlob
    {
        public byte[] IV;
        public byte[] Payload;
    }
}
