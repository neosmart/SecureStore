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
        private const int KEYCOUNT = 2;
        private const int KEYLENGTH = 128 / 8;
        private const int PBKDF2ROUNDS = 10000;
        private const int IVSIZE = 8;

        private SecureBuffer _encryptionKey;
        private SecureBuffer _hmacKey;
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

        //Load an encryption key from a file
        public void LoadKeyFromFile(string path)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            //We don't know how .NET buffers things in memory, so we write it ourselves for maximum security
            //avoid excess buffering where possible, even if slow
            using (var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                if (file.Length != KEYLENGTH * KEYCOUNT)
                {
                    throw new InvalidKeyFileException();
                }

                _encryptionKey = new SecureBuffer(KEYLENGTH);
                _hmacKey = new SecureBuffer(KEYLENGTH);

                int bytesRead = file.Read(_encryptionKey.Buffer, 0, KEYLENGTH);
                if (bytesRead != KEYLENGTH)
                {
                    throw new IOException("Unable to read from key file!");
                }

                bytesRead = file.Read(_hmacKey.Buffer, 0, KEYLENGTH);
                if (bytesRead != KEYLENGTH)
                {
                    throw new IOException("Unable to read from key file!");
                }
            }
        }

        public void SaveKeyFile(string path)
        {
            //We don't know how .NET buffers things in memory, so we write it ourselves for maximum security
            //avoid excess buffering where possible, even if slow
            using (var file = File.Create(path, 1, FileOptions.WriteThrough))
            {
                file.Write(_encryptionKey.Buffer, 0, KEYLENGTH);
                file.Write(_hmacKey.Buffer, 0, KEYLENGTH);
            }
        }

        static private byte[] DerivePassword(SecureString password, byte[] salt)
        {
#if NETSTANDARD1_3
            return KeyDerivation.Pbkdf2(password.ToString(), salt, KeyDerivationPrf.HMACSHA1, PBKDF2ROUNDS, KEYLENGTH * KEYCOUNT);
#elif NET20 || NET30 || NET35
            return new Rfc2898DeriveBytes(password.ToString(), salt, PBKDF2ROUNDS).GetBytes(KEYLENGTH * KEYCOUNT);
#else
            using (var pbkdf2 = new Rfc2898DeriveBytes(password.ToString(), salt, PBKDF2ROUNDS))
            {
                return pbkdf2.GetBytes(KEYLENGTH * KEYCOUNT);
            }
#endif
        }

        private void SplitKey(byte[] insecure)
        {
            //While the consensus is that AES and HMAC are "sufficiently different" that reusing
            //the same key for Encrypt-then-MAC is probably safe, it's not something provable
            //and therefore (esp. since we can without too much additional burden) we should use two
            //separate keys.
            using (var temp = new SecureBuffer(insecure))
            {
                _encryptionKey = new SecureBuffer(KEYLENGTH);
                _hmacKey = new SecureBuffer(KEYLENGTH);

                Array.Copy(temp.Buffer, 0, _encryptionKey.Buffer, 0, KEYLENGTH);
                Array.Copy(temp.Buffer, KEYLENGTH, _hmacKey.Buffer, 0, KEYLENGTH);
            }
        }

        //Derive an encryption key from a password
        public void LoadKeyFromPassword(SecureString password)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            var insecure = DerivePassword(password, _vault.IV);
            SplitKey(insecure);
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
                SplitKey(insecure);
            }
        }

        private void InitializeNewStore()
        {
            _vault = new Vault();
            _vault.IV = new byte[IVSIZE];
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
            using (var decrypted = new SecureBuffer(Decrypt(_vault.Data[name])))
            {
                //the conversion from bytes to string involves some non-shredded memory
                return JsonConvert.DeserializeObject<T>(Encoding.UTF8.GetString(decrypted.Buffer));
            }
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
            //JsonConvert and the UTF8 conversion likely involve non-shredded memory
            var insecure = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(value));
            using (var secured = new SecureBuffer(insecure))
            {
                _vault.Data[name] = Encrypt(secured);
            }
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

        private EncryptedBlob Encrypt(SecureBuffer input)
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
                aes.Key = _encryptionKey.Buffer;
                aes.BlockSize = 128;
                aes.GenerateIV();

                blob.IV = aes.IV;

                using (var encryptor = aes.CreateEncryptor())
                {
                    blob.Payload = encryptor.TransformFinalBlock(input.Buffer, 0, input.Buffer.Length);
                }
            }

            blob.Hmac = Authenticate(blob.IV, blob.Payload);

            return blob;
        }

        private byte[] Authenticate(byte[] iv, byte[] encrypted)
        {
#if NETSTANDARD1_3
            var hmac = new System.Security.Cryptography.HMACSHA1(_hmacKey.Buffer);
            var composite = new byte[iv.Length + encrypted.Length];
            Array.Copy(iv, 0, composite, 0, iv.Length);
            Array.Copy(encrypted, 0, composite, iv.Length, encrypted.Length);
            var result = hmac.ComputeHash(composite);
#else
            var hmac = System.Security.Cryptography.HMACSHA1.Create();
            hmac.Key = _hmacKey.Buffer;

            hmac.TransformBlock(iv, 0, iv.Length, iv, 0);
            hmac.TransformFinalBlock(encrypted, 0, encrypted.Length);

            var result = hmac.Hash;
#endif

#if !NET20 && !NET30 && !NET35
            hmac.Dispose();
#endif

            return result;
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

            //first validate the HMAC
            var calculatedHmac = Authenticate(blob.IV, blob.Payload);

            if (calculatedHmac.Length != blob.Hmac.Length)
            {
                throw new TamperedCipherTextException();
            }

            //compare without early abort
            int mismatches = 0;
            for (int i = 0; i < calculatedHmac.Length; ++i)
            {
                calculatedHmac[i] = (byte)(calculatedHmac[i] ^ blob.Hmac[i]);
            }
            for (int i = 0; i < calculatedHmac.Length; ++i)
            {
                mismatches += calculatedHmac[i];
            }
            if (mismatches != 0)
            {
                throw new TamperedCipherTextException();
            }

            using (aes)
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = _encryptionKey.Buffer;
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
            if (_hmacKey != null)
            {
                _hmacKey.Dispose();
                _hmacKey = null;
            }
            if (_encryptionKey != null)
            {
                _encryptionKey.Dispose();
                _encryptionKey = null;
            }
        }
    }
}
