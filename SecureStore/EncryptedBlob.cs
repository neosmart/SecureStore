using System;
using Newtonsoft.Json;

namespace NeoSmart.SecureStore
{
    [Serializable]
    internal struct EncryptedBlob
    {
        [JsonProperty(PropertyName = "iv")]
        public byte[] IV;
        [JsonProperty(PropertyName = "hmac")]
        public byte[] Hmac;
        [JsonProperty(PropertyName = "payload")]
        public byte[] Payload;
    }
}
