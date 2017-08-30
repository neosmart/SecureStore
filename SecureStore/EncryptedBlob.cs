using System;
using System.Collections.Generic;
using System.Text;

namespace NeoSmart.SecureStore
{
    [Serializable]
    internal struct EncryptedBlob
    {
        public byte[] IV;
        public byte[] Hmac;
        public byte[] Payload;
    }
}
