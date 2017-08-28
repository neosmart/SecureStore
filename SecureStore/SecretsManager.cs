using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using System.Security;
using System.Runtime.InteropServices;

#if NETSTANDARD1_3
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
#endif

namespace NeoSmart.SecureStore
{
    sealed public class SecretsManager : IDisposable
    {
        private const int KEYLENGTH = 256 / 8;
        private const int PBKDF2ROUNDS = 10000;

        private SecureBuffer _key;
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

        static private byte[] DerivePassword(SecureString password, byte[] salt)
        {
#if NETSTANDARD1_3
            return KeyDerivation.Pbkdf2(password.ToString(), salt, KeyDerivationPrf.HMACSHA1, PBKDF2ROUNDS, 32);
#elif NET20 || NET30 || NET35
            return new Rfc2898DeriveBytes(password.ToString(), salt, PBKDF2ROUNDS).GetBytes(32);
#else
            using (var pbkdf2 = new Rfc2898DeriveBytes(password.ToString(), salt, PBKDF2ROUNDS))
            {
                return pbkdf2.GetBytes(KEYLENGTH);
            }
#endif
        }

        //Load an encryption key from a file
        public void LoadKeyFromFile(string path)
        {
            if (_key != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            //We don't know how .NET buffers things in memory, so we write it ourselves for maximum security
            //avoid excess buffering where possible, even if slow
            using (var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                if (file.Length != KEYLENGTH)
                {
                    throw new InvalidKeyFileException();
                }

                _key = new SecureBuffer(KEYLENGTH);

                int start = 0;
                const int blockSize = 1024;
                for (var bytesRemaining = KEYLENGTH; bytesRemaining > 0;)
                {
                    int toRead = Math.Min(blockSize, bytesRemaining);
                    int read = file.Read(_key.Buffer, start, toRead);
                    start += read;
                    bytesRemaining -= read;
                }
            }
        }

        public void SaveKeyFile(string path)
        {
            //We don't know how .NET buffers things in memory, so we write it ourselves for maximum security
            //avoid excess buffering where possible, even if slow
            using (var file = File.Create(path, 1, FileOptions.WriteThrough))
            {
                int start = 0;
                const int blockSize = 1024;
                for (var bytesRemaining = _key.Buffer.Length; bytesRemaining > 0;)
                {
                    int toWrite = Math.Min(blockSize, bytesRemaining);
                    file.Write(_key.Buffer, start, toWrite);
                    start += toWrite;
                    bytesRemaining -= toWrite;
                }
            }
        }

        //Derive an encryption key from a password
        public void LoadKeyFromPassword(SecureString password)
        {
            if (_key != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            var insecure = DerivePassword(password, _vault.IV);
            _key = new SecureBuffer(insecure);
        }

        public void LoadKeyFromPassword(string password)
        {
            if (_vault == null)
            {
                throw new NoStoreLoadedException();
            }

            using (var ss = new SecureString())
            {
                ss.FromInsecure(password);
                var insecure = DerivePassword(ss, _vault.IV);
                _key = new SecureBuffer(insecure);
            }
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

        public T Retrieve<T>(string name)
        {
            var decrypted = Decrypt(_vault.Data[name]);
            return JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(decrypted));
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

        public void Set<T>(string name, T value)
        {
            _vault.Data[name] = Encrypt(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(value)));
        }

        public bool Delete(string name)
        {
            if (_vault.Data.ContainsKey(name))
            {
                _vault.Data.Remove(name);
                return true;
            }
            return false;
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
                aes.Key = _key.Buffer;
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
                aes.Key = _key.Buffer;
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
            if (_key != null)
            {
                _key.Dispose();
                _key = null;
            }
        }
    }
}
