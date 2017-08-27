using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NeoSmart.SecureStore
{
    [Serializable]
    internal struct EncryptedBlob
    {
        public byte[] IV;
        public byte[] Payload;
    }
}
