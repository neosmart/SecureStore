using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

#if ASYNC
using System.Threading.Tasks;
using NeoSmart.SecureStore.Versioning;
#endif

#if NETSTANDARD1_3
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
#endif

namespace NeoSmart.SecureStore
{
    sealed public class SecretsManager : IDisposable
    {
        /// <summary>
        /// Determines runtime behavior when older schema versions are loaded.
        ///
        /// (This will likely default to <see cref="Versioning.VaultVersionPolicy.Strict"/> at
        /// some point in the future close to version 1.0)
        /// </summary>
        public static Versioning.VaultVersionPolicy VaultVersionPolicy { get; set; } = Versioning.VaultVersionPolicy.Upgrade;

        public static Encoding DefaultEncoding { get; } = new UTF8Encoding(false);

        private const int KEYCOUNT = 2;
        private const int KEYLENGTH = 128 / 8;
        private const int PBKDF2ROUNDS = 10000;
        private const int IVSIZE = 8;

        private Vault _vault;
        private SecureBuffer? _encryptionKey;
        private SecureBuffer? _hmacKey;
        private bool _vaultUpgradePending = false;
        private bool _sentinelValidated = false;

        public delegate SecureBuffer SerializeFunc<T>(T value);
        public delegate T DeserializeFunc<T>(SecureBuffer serialized);
        public delegate bool TryDeserializeFunc<T>(SecureBuffer serialized, out T deserialized);
        public delegate void ByteReceiver(byte[] bytes);

#if !JSON_SERIALIZER
        public ISecretSerializer DefaultSerializer { get; set; } = null;
#else
        public ISecretSerializer DefaultSerializer { get; set; } = new Serializers.Utf8JsonSerializer();
#endif

        private SecretsManager()
        {
        }

        public static SecretsManager CreateStore()
        {
            var secretsManager = new SecretsManager();
            secretsManager.InitializeNewStore();
            return secretsManager;
        }

        public static SecretsManager LoadStore(string path)
        {
            var secretsManager = new SecretsManager();
            secretsManager.LoadSecretsFile(path);
            return secretsManager;
        }

        public static SecretsManager LoadStore(Stream stream)
        {
            var secretsManager = new SecretsManager();
            secretsManager.LoadSecretsStream(stream);
            return secretsManager;
        }

        // This is only used when creating a new vault, so it's OK to
        // create an RNG each time.
        private static void GenerateBytes(byte[] buffer)
        {
#if NETSTANDARD1_3
            using var rng = RandomNumberGenerator.Create();
#elif NET40 || NET45
            using var rng = new RNGCryptoServiceProvider();
#else
            var rng = new RNGCryptoServiceProvider();
#endif

            rng.GetBytes(buffer);
        }

        // Generate a new key for a new store
        public void GenerateKey()
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            _encryptionKey = new SecureBuffer(KEYLENGTH);
            GenerateBytes(_encryptionKey?.Buffer);
            _hmacKey = new SecureBuffer(KEYLENGTH);
            GenerateBytes(_hmacKey?.Buffer);
        }

        // Load an encryption key from a file
        public void LoadKeyFromFile(string path)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.None))
            {
                if (file.Length != KEYLENGTH * KEYCOUNT)
                {
                    throw new InvalidKeyFileException();
                }

                _encryptionKey = new SecureBuffer(KEYLENGTH);
                _hmacKey = new SecureBuffer(KEYLENGTH);

                foreach (var buffer in new[] { _encryptionKey?.Buffer, _hmacKey?.Buffer })
                {
                    int offset = 0;
                    int bytesRead = -1;
                    while (bytesRead != 0)
                    {
                        bytesRead = file.Read(buffer, offset, KEYLENGTH - offset);
                        offset += bytesRead;
                    }

                    if (offset != KEYLENGTH)
                    {
                        throw new IOException("Error reading key from file!");
                    }
                }
            }

            CheckUpgrade();
        }

#if ASYNC
        public async Task LoadKeyFromFileAsync(string path)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous))
            {
                if (file.Length != KEYLENGTH * KEYCOUNT)
                {
                    throw new InvalidKeyFileException();
                }

                _encryptionKey = new SecureBuffer(KEYLENGTH);
                _hmacKey = new SecureBuffer(KEYLENGTH);

                foreach (var buffer in new[] { _encryptionKey?.Buffer, _hmacKey?.Buffer })
                {
                    int offset = 0;
                    int bytesRead = -1;
                    while (bytesRead != 0)
                    {
                        bytesRead = await file.ReadAsync(buffer, offset, KEYLENGTH - offset);
                        offset += bytesRead;
                    }

                    if (offset != KEYLENGTH)
                    {
                        throw new IOException("Error reading key from file!");
                    }
                }
            }

            CheckUpgrade();
        }
#endif

        public void ExportKey(string path)
        {
            if (_encryptionKey?.Buffer == null || _hmacKey?.Buffer == null)
            {
                throw new NoKeyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                file.Write(_encryptionKey?.Buffer, 0, KEYLENGTH);
                file.Write(_hmacKey?.Buffer, 0, KEYLENGTH);
            }
        }

#if ASYNC
        public async Task ExportKeyAsync(string path)
        {
            if (_encryptionKey?.Buffer == null || _hmacKey?.Buffer == null)
            {
                throw new NoKeyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await file.WriteAsync(_encryptionKey?.Buffer, 0, KEYLENGTH);
                await file.WriteAsync(_hmacKey?.Buffer, 0, KEYLENGTH);
            }
        }
#endif

        public SecureBuffer ExportKey()
        {
            if (_encryptionKey?.Buffer == null || _hmacKey?.Buffer == null)
            {
                throw new NoKeyLoadedException();
            }

            var secure = new SecureBuffer(KEYLENGTH * 2);
            var buffers = new[] { _encryptionKey?.Buffer, _hmacKey?.Buffer };
            for (int i = 0; i < buffers.Length; ++i)
            {
                Array.Copy(buffers[i], 0, secure.Buffer, i * KEYLENGTH, KEYLENGTH);
            }

            return secure;
        }

        static private byte[] DerivePassword(string password, byte[] salt)
        {
#if NETSTANDARD1_3
            return KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA1, PBKDF2ROUNDS, KEYLENGTH * KEYCOUNT);
#elif NET20 || NET30 || NET35
            return new Rfc2898DeriveBytes(password, salt, PBKDF2ROUNDS).GetBytes(KEYLENGTH * KEYCOUNT);
#else
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PBKDF2ROUNDS))
            {
                return pbkdf2.GetBytes(KEYLENGTH * KEYCOUNT);
            }
#endif
        }

        private void SplitKey(byte[] insecure)
        {
            if (insecure.Length != KEYLENGTH * 2)
            {
                throw new ArgumentException("Key with incorrect length provided!");
            }

            // While the consensus is that AES and HMAC are "sufficiently different" that reusing
            // the same key for Encrypt-then-MAC is probably safe, it's not something provable
            // and therefore (esp. since we can without too much additional burden) we should use two
            // separate keys.
            using (var temp = new SecureBuffer(insecure))
            {
                _encryptionKey = new SecureBuffer(KEYLENGTH);
                _hmacKey = new SecureBuffer(KEYLENGTH);

                Array.Copy(temp.Buffer, 0, _encryptionKey?.Buffer, 0, KEYLENGTH);
                Array.Copy(temp.Buffer, KEYLENGTH, _hmacKey?.Buffer, 0, KEYLENGTH);

                // Before overwriting the key in memory
                CheckUpgrade();
            }
        }

        // Derive an encryption key from a password
        public void LoadKeyFromPassword(string password)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            var insecure = DerivePassword(password, _vault.IV);
            using (var sb = new SecureBuffer(insecure))
            {
                SplitKey(insecure);
            }
        }

        public void LoadKey(SecureBuffer key)
        {
            LoadKeyInsecure(key.Buffer);
        }

        [Obsolete("Prefer using LoadKey(SecureBuffer key) instead")]
        public void LoadKey(byte[] key)
        {
            LoadKeyInsecure(key);
        }

        private void LoadKeyInsecure(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            SplitKey(key);
        }


        private void InitializeNewStore()
        {
            // Generate a new IV for password-based key derivation
            var iv = new byte[IVSIZE];
            GenerateBytes(iv);

            _vault = new Vault(iv);
        }

        internal void CreateSentinel()
        {
            if (_vault.Sentinel is null)
            {
                var sentinel = new SecureBuffer(IVSIZE * 2);
                GenerateBytes(sentinel.Buffer);
                _vault.Sentinel = Encrypt(sentinel);
                _sentinelValidated = true;
            }
        }

        internal void ValidateSentinel()
        {
            if (!_sentinelValidated && !(_vault.Sentinel is null))
            {
                _ = Decrypt(_vault.Sentinel.Value);
                _sentinelValidated = true;
            }
        }

        private void LoadSecretsFile(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                LoadSecretsStream(stream);
            }
        }

        private void LoadSecretsStream(Stream stream)
        {
            using (var reader = new StreamReader(stream, DefaultEncoding))
            using (var jreader = new JsonTextReader(reader))
            {
                _vault = JsonSerializer.Create().Deserialize<VaultLoader>(jreader);
                if (_vault.VaultVersion > Vault.SCHEMAVERSION)
                {
                    throw Versioning.VaultVersionException.UnsupportedVersion();
                }
                if (_vault.VaultVersion != Vault.SCHEMAVERSION)
                {
                    _vaultUpgradePending = true;
                }
            }
        }

        private void CheckUpgrade()
        {
            if (_vaultUpgradePending && _vault != null && _encryptionKey != null)
            {
                var upgrade = new Versioning.VaultUpgrade();
                upgrade.Upgrade(this, _vault);
            }
        }

        public SecureBuffer GetBytes(string key)
        {
            return Decrypt(_vault.Data[key]);
        }

        public string Get(string key)
        {
            using (var decrypted = Decrypt(_vault.Data[key]))
            {
                return DefaultEncoding.GetString(decrypted.Buffer);
            }
        }

        public bool TryGetBytes(string key, out SecureBuffer buffer)
        {
            if (!_vault.Data.ContainsKey(key))
            {
                buffer = default;
                return false;
            }

            buffer = GetBytes(key);
            return true;
        }

#if ASYNC
        public bool TryGetBytes(string key, Action<byte[]> receiver)
#else
        public bool TryGetBytes(string key, ByteReceiver receiver)
#endif
        {
            if (!_vault.Data.ContainsKey(key))
            {
                return false;
            }

            using (var buffer = GetBytes(key))
            {
                receiver(buffer.Buffer);
            }

            return true;
        }

        public bool TryGetValue<T>(string key, out T value)
        {
            if (!_vault.Data.ContainsKey(key))
            {
                value = default;
                return false;
            }

            var decrypted = Decrypt(_vault.Data[key]);
            if (typeof(T) == typeof(SecureBuffer))
            {
                value = (T)(object)decrypted;
                return true;
            }

            if (typeof(T) == typeof(byte[]))
            {
                value = (T)(object)decrypted.Buffer;
                return true;
            }

            using (decrypted)
            {
                if (typeof(T) == typeof(string))
                {
                    var result = Get(key);
                    value = (T)(object)result;
                    return true;
                }

                if (DefaultSerializer == null)
                {
                    throw new Exception("DefaultSerializer must be assigned!");
                }

                value = DefaultSerializer.Deserialize<T>(decrypted);
                return true;
            }
        }

        public bool TryGetValue<T>(string key, TryDeserializeFunc<T> deserialize, out T value)
        {
            if (!TryGetBytes(key, out var buffer))
            {
                value = default;
                return false;
            }

            if (deserialize(buffer, out value))
            {
                return true;
            }

            value = default;
            return false;
        }

        public bool TryGetValue<T>(string key, DeserializeFunc<T> deserialize, out T value)
        {
            if (!TryGetBytes(key, out var encoded))
            {
                value = default;
                return false;
            }

            try
            {
                value = deserialize(encoded);
                return true;
            }
            catch
            {
                value = default;
                return false;
            }
        }

        public void Set(string key, SecureBuffer value)
        {
            ValidateSentinel();
            _vault.Data[key] = Encrypt(value);
        }

        public void Set<T>(string key, T value, SerializeFunc<T> serialize)
        {
            Set(key, serialize(value));
        }

        public void Set<T>(string key, T value)
        {
            if (typeof(T) == typeof(string))
            {
                // Strings must always be serialized as UTF-8 without a BOM
                var @string = (string)(object)value;
                var byteCount = DefaultEncoding.GetByteCount(@string);
                using (var secure = new SecureBuffer(byteCount))
                {
                    DefaultEncoding.GetBytes(@string, 0, byteCount, secure.Buffer, 0);
                    Set(key, secure);
                }
            }
            else if (typeof(T) == typeof(byte[]))
            {
                var bytes = (byte[])(object)value;
                using (var buffer = SecureBuffer.From(bytes))
                {
                    Set(key, buffer);
                }
            }
            else
            {
                if (DefaultSerializer == null)
                {
                    throw new Exception("DefaultSerializer must be assigned!");
                }

                using (var buffer = DefaultSerializer.Serialize(value))
                {
                    Set(key, buffer);
                }
            }
        }

        public bool Delete(string key)
        {
            if (_vault.Data.ContainsKey(key))
            {
                _vault.Data.Remove(key);
                return true;
            }
            return false;
        }

        public void SaveStore(string path)
        {
            CreateSentinel();

            using (var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
            using (var writer = new StreamWriter(stream, DefaultEncoding))
            using (var jwriter = new JsonTextWriter(writer))
            {
                jwriter.Formatting = Formatting.Indented;
                JsonSerializer.Create().Serialize(jwriter, _vault);
            }
        }

        public IEnumerable<string> Keys => _vault.Data.Keys;

        private EncryptedBlob Encrypt(SecureBuffer input)
        {
            EncryptedBlob blob;

#if NETSTANDARD1_3
            var aes = Aes.Create();
#elif NET20 || NET30
            var aes = Rijndael.Create();
#else
            var aes = new AesCryptoServiceProvider();
#endif

            using (aes)
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = _encryptionKey?.Buffer;
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
            var hmac = new HMACSHA1(_hmacKey?.Buffer);
            var composite = new byte[iv.Length + encrypted.Length];
            Array.Copy(iv, 0, composite, 0, iv.Length);
            Array.Copy(encrypted, 0, composite, iv.Length, encrypted.Length);
            var result = hmac.ComputeHash(composite);
#else
            var hmac = HMACSHA1.Create();
            hmac.Key = _hmacKey?.Buffer;

            hmac.TransformBlock(iv, 0, iv.Length, iv, 0);
            hmac.TransformFinalBlock(encrypted, 0, encrypted.Length);

            var result = hmac.Hash;
#endif

#if !NET20 && !NET30 && !NET35
            hmac.Dispose();
#endif

            return result;
        }

        private SecureBuffer Decrypt(EncryptedBlob blob)
        {
            SymmetricAlgorithm aes;

#if NETSTANDARD1_3
            aes = Aes.Create();
#elif NET20 || NET30
            aes = Rijndael.Create();
#else
            aes = new AesCryptoServiceProvider();
#endif

            // Validate the HMAC
            var calculatedHmac = Authenticate(blob.IV, blob.Payload);

            if (calculatedHmac.Length != blob.Hmac.Length)
            {
                throw new TamperedCipherTextException();
            }

            // Compare without early abort for timing attack resistance
            int mismatches = 0;
            for (int i = 0; i < calculatedHmac.Length; ++i)
            {
                mismatches += (byte)(calculatedHmac[i] ^ blob.Hmac[i]);
            }
            if (mismatches != 0)
            {
                throw new TamperedCipherTextException();
            }

            using (aes)
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = _encryptionKey?.Buffer;
                aes.BlockSize = 128;
                aes.IV = blob.IV;

                using (var decryptor = aes.CreateDecryptor())
                {
                    var unsecured = decryptor.TransformFinalBlock(blob.Payload, 0, blob.Payload.Length);
                    return new SecureBuffer(unsecured);
                }
            }
        }

        public void Dispose()
        {
            _hmacKey?.Dispose();
            _encryptionKey?.Dispose();
            _encryptionKey = null;
        }

#region Obsolete
        [Obsolete("Use SecretsManager.TryGetValue(..) instead.")]
        public bool TryRetrieve<T>(string key, out T value)
        {
            return TryGetValue<T>(key, out value);
        }

        [Obsolete("Use SecretsManager.Get(..) instead.")]
        public string Retrieve(string key)
        {
            if (!TryGetValue<string>(key, out var result))
            {
                throw new KeyNotFoundException();
            }

            return result;
        }
#endregion
    }
}
