using System.Collections.Generic;
using System.Text;
using NeoSmart.SecureStore.Serializers;
using Newtonsoft.Json;

namespace NeoSmart.SecureStore.Versioning
{
    class VaultUpgrade_V1_V2 : IVaultUpgrade
    {
        public int FromVersion => 1;
        public int ToVersion => 2;

        public bool Upgrade(SecretsManager sman, Vault vault, string password)
        {
            // Convert JSON strings and byte arrays to plain values

            var jsonSettings = SecretsManager.DefaultJsonSettings;
            foreach (var key in new List<string>(sman.Keys))
            {
                sman.DefaultSerializer = new Utf8JsonSerializer();
                sman.TryGetValue(key, out byte[] bytes);

                try
                {
                    var s = Encoding.UTF8.GetString(bytes);
                    var o = JsonConvert.DeserializeObject(s, jsonSettings);

                    if (o is string stringValue)
                    {
                        sman.Set(key, stringValue);
                    }
                    else if (o is byte[] byteValue)
                    {
                        sman.Set(key, byteValue);
                    }
#if JSON_SERIALIZER
                    else
                    {
                        sman.Set(key, s);
                    }
#endif
                }
                catch
                {
                    throw new VaultVersionException($"Cannot upgrade secret {key}");
                }
            }

            sman.CreateSentinel();

            return true;
        }
    }
}
