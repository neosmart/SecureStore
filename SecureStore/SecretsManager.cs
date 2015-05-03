using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;

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
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
            {
                return pbkdf2.GetBytes(32);
            }
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
            _vault.Data = new ConcurrentDictionary<string, EncryptedBlob>();

            //Generate a new IV for password-based key derivation
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(_vault.IV);
            }
        }

        private void LoadSecretsFromFile(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                _vault = Jil.JSON.Deserialize<Vault>(reader);
            }
        }

        public string Retrieve(string name)
        {
            return Retrieve<string>(name);
        }

        public T Retrieve<T>(string name)
        {
            var decrypted = Decrypt(_vault.Data[name]);
            return Jil.JSON.Deserialize<T>(Encoding.UTF8.GetString(decrypted));
        }

        public void Set<T>(string name, T value)
        {
            _vault.Data[name] = Encrypt(Encoding.UTF8.GetBytes(Jil.JSON.Serialize(value)));
        }

        public void SaveSecretsToFile(string path)
        {
            using (var stream = new FileStream(path, FileMode.Create))
            using (var writer = new StreamWriter(stream, Encoding.UTF8))
            {
                Jil.JSON.Serialize(_vault, writer);
            }
        }

        private byte[] Decrypt(EncryptedBlob blob)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = _key;
                aes.IV = blob.IV;

                using (var outputStream = new MemoryStream())
                using (var memstream = new MemoryStream(blob.Payload))
                {
                    using (var cryptostream = new CryptoStream(memstream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        cryptostream.CopyTo(outputStream);
                    }
                    return outputStream.ToArray();
                }
            }
        }

        private EncryptedBlob Encrypt(byte[] input)
        {
            EncryptedBlob blob;

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = _key;
                aes.GenerateIV();
                blob.IV = aes.IV;

                using (var memstream = new MemoryStream())
                {
                    using (var cryptostream = new CryptoStream(memstream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptostream.Write(input, 0, input.Length);
                    }
                    blob.Payload = memstream.ToArray();
                }
            }

            return blob;
        }

        public void Dispose()
        {
            //Overwrite key in memory before leaving
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(_key);
            }
        }
    }
}
