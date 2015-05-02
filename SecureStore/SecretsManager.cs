using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SecureStore
{
    sealed public class SecretsManager
    {
        private byte[] _key;
        private ConcurrentDictionary<string, EncryptedBlob> _secretsStore { get { return _vault.Data; } }
        private Vault _vault;
        private ThreadLocal<BinaryFormatter> _formatter = new ThreadLocal<BinaryFormatter>(() => new BinaryFormatter());
        private BinaryFormatter Formatter { get { return _formatter.Value; } }

        public void InitializeNewStore()
        {
            _vault = new Vault();
            _vault.IV = new byte[8];
            _vault.Data = new ConcurrentDictionary<string, EncryptedBlob>();
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(_vault.IV);
            }
        }

        static private byte[] DerivePassword(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        //Load an encryption key from a file
        public void LoadKeyFile(string path)
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

        public void LoadSecretsFromFile(string path)
        {
            var formatter = new BinaryFormatter();
            using (var serializedStream = File.OpenRead(path))
            {
                _vault = formatter.Deserialize<Vault>(serializedStream);
            }
        }

        public T RetrieveSecret<T>(string name)
        {
            var decrypted = Decrypt(_secretsStore[name]);
            return Formatter.Deserialize<T>(decrypted);
        }

        public void AddSecret<T>(string name, T value)
        {
            _secretsStore[name] = Encrypt(Formatter.Serialize(value));
        }

        public void SaveSecretsToFile(string path)
        {
            var formatter = new BinaryFormatter();
            using (var serializedStream = File.OpenWrite(path))
            {
                formatter.Serialize(serializedStream, _vault);
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
    }
}
