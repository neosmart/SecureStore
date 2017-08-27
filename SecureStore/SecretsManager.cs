using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

#if NETSTANDARD1_3
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
#endif

namespace NeoSmart.SecureStore
{
    sealed public class SecretsManager : IDisposable
    {
        private byte[] _key;
        private Vault _vault;

        private SecretsManager()
        {
        }

        public static SecretsManager NewStore()
        {
            var secretsManager = new SecretsManager();
            secretsManager.InitializeNewStore();
            return secretsManager;
        }

        public static SecretsManager LoadStore(string path)
        {
            var secretsManager = new SecretsManager();
            secretsManager.LoadSecretsFromFile(path);
            return secretsManager;
        }

        static private byte[] DerivePassword(string password, byte[] salt)
        {
#if NETSTANDARD1_3
            return KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA1, 10000, 32);
#elif NET20 || NET30 || NET35
            return new Rfc2898DeriveBytes(password, salt, 10000).GetBytes(32);
#else
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
            {
                return pbkdf2.GetBytes(32);
            }
#endif
        }

        //Load an encryption key from a file
        public void LoadKeyFromFile(string path)
        {
            _key = File.ReadAllBytes(path);
        }

        public void SaveKeyFile(string path)
        {
            File.WriteAllBytes(path, _key);
        }

        //Derive an encryption key from a password
        public void LoadKeyFromPassword(string password)
        {
            if (_vault == null)
            {
                throw new NoStoreLoadedException();
            }
            _key = DerivePassword(password, _vault.IV);
        }

        private void InitializeNewStore()
        {
            _vault = new Vault();
            _vault.IV = new byte[8];
            _vault.Data = new SortedDictionary<string, EncryptedBlob>();

            //Generate a new IV for password-based key derivation
#if NETSTANDARD1_3
            var rng = RandomNumberGenerator.Create();
#else
            var rng = new RNGCryptoServiceProvider();
#endif

            rng.GetBytes(_vault.IV);

#if !NET20 && !NET30 && !NET35
            rng.Dispose();
#endif
        }

        private void LoadSecretsFromFile(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            using (var jreader = new JsonTextReader(reader))
            {
                _vault = JsonSerializer.Create().Deserialize<Vault>(jreader);
            }
        }

        public string Retrieve(string name)
        {
            return Retrieve<string>(name);
        }

        public bool TryRetrieve<T>(string name, out T value)
        {
            if (_vault.Data.ContainsKey(name))
            {
                value = Retrieve<T>(name);
                return true;
            }
            value = default(T);
            return false;
        }

        public T Retrieve<T>(string name)
        {
            var decrypted = Decrypt(_vault.Data[name]);
            return JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(decrypted));
        }

        public void Set<T>(string name, T value)
        {
            _vault.Data[name] = Encrypt(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(value)));
        }

        public void SaveSecretsToFile(string path)
        {
            using (var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            using (var writer = new StreamWriter(stream, Encoding.UTF8))
            using (var jwriter = new JsonTextWriter(writer))
            {
                JsonSerializer.Create().Serialize(jwriter, _vault);
            }
        }
        
        private EncryptedBlob Encrypt(byte[] input)
        {
            EncryptedBlob blob;

            SymmetricAlgorithm aes;

#if NETSTANDARD1_3
        aes = Aes.Create();
#elif NET20 || NET30
        aes = Rijndael.Create();
#else
        aes = new AesCryptoServiceProvider();
#endif

            using (aes)
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = _key;
                aes.BlockSize = 128;
                aes.GenerateIV();

                blob.IV = aes.IV;

                using (var encryptor = aes.CreateEncryptor())
                {
                    blob.Payload = encryptor.TransformFinalBlock(input, 0, input.Length);
                }
            }

            return blob;
        }

        private byte[] Decrypt(EncryptedBlob blob)
        {
            SymmetricAlgorithm aes;

#if NETSTANDARD1_3
            aes = Aes.Create();
#elif NET20 || NET30
            aes = Rijndael.Create();
#else
            aes = new AesCryptoServiceProvider();
#endif

            using (aes)
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = _key;
                aes.BlockSize = 128;
                aes.IV = blob.IV;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(blob.Payload, 0, blob.Payload.Length);
                }
            }
        }

        public void Dispose()
        {
            //Overwrite key in memory before leaving
            if (_key != null)
            {
#if NETSTANDARD1_3
                var rng = RandomNumberGenerator.Create();
#else
                var rng = new RNGCryptoServiceProvider();
#endif
                rng.GetBytes(_key);
                _key = null;

#if !NET20 && !NET30 && !NET35
            rng.Dispose();
#endif
            }
        }
    }
}
