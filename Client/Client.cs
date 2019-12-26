using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace NeoSmart.SecureStore.Client
{
    class Client
    {
        private SecretsManager _sman;

        public Client(SecretsManager sman)
        {
            _sman = sman;
        }

        public void Create()
        {
            //no-op
        }

        public void Update(string key, string value)
        {
            // Force validation to avoid loss of sensitive data
            if (_sman.TryGetBytes(key, out var buffer))
            {
            }
            // Manually attempt to handle a few particular types
            if (!value.StartsWith("0") && int.TryParse(value, out var intValue))
            {
                _sman.Set(key, intValue);
            }
            else if (bool.TryParse(value, out var boolValue))
            {
                _sman.Set(key, boolValue ? 1 : 0);
            }
            else
            {
                _sman.Set(key, value);
            }
        }

        public void Delete(string key)
        {
            if (!_sman.Delete(key))
            {
                throw new ExitCodeException(1, $"Key \"{key}\" not found in secrets store!");
            }
        }

        public void Decrypt(string key)
        {
            if (!_sman.TryGetValue(key, out string retrieved))
            {
                throw new ExitCodeException(1, $"Key \"{key}\" not found in secrets store!");
            }
            else
            {
                Console.WriteLine(retrieved);
            }
        }

        public void DecryptAll(DecryptFormat format)
        {
            //this is going to stdout out, don't bother securing the memory here
            var decrypted = new Dictionary<string, dynamic>();
            foreach (var k in _sman.Keys)
            {
                var v = _sman.Get(k);
                decrypted[k] = v;
            }

            switch (format)
            {
                case DecryptFormat.PlainText:
                    foreach (var k in decrypted.Keys)
                    {
                        Console.WriteLine($"{k}: { decrypted[k].ToString() }");
                    }
                    break;
                default:
                    var serializerOptions = JsonConvert.SerializeObject(decrypted, Formatting.Indented);
                    Console.WriteLine(serializerOptions);
                    break;
            }
        }
    }
}
