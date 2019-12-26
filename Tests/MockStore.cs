using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Tests
{

    class MockStore
    {
        [JsonProperty(PropertyName = "secrets")]
        internal SortedDictionary<string, EncryptedBlob> Secrets { get; set; }
        [JsonProperty(PropertyName = "version")]
        internal int VaultVersion { get; set; }
        [JsonProperty(PropertyName = "iv")]
        internal byte[] IV { get; set; }

        internal class EncryptedBlob
        {
            [JsonProperty(PropertyName = "iv")]
            public byte[] IV;
            [JsonProperty(PropertyName = "hmac")]
            public byte[] Hmac;
            [JsonProperty(PropertyName = "payload")]
            public byte[] Payload;
        }
    }
}
