using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NeoSmart.SecureStore.Versioning;
using Newtonsoft.Json;

namespace NeoSmart.SecureStore
{
    sealed public class SecretsManager : IDisposable
    {
        /// <summary>
        /// Determines runtime behavior when older schema versions are loaded.
        ///
        /// This defaults to <see cref="VaultVersionPolicy.Strict" /> in the library and is
        /// overridden to <see cref="VaultVersionPolicy.Upgrade"/> in the companion CLI app
        /// to allow for development/deployment-time upgrades across major vault versions (which may risk
        /// version downgrade attacks) but protects against them in-prod.
        /// </summary>
        public static VaultVersionPolicy VaultVersionPolicy { get; set; } = VaultVersionPolicy.Strict;

        internal static Encoding DefaultEncoding { get; } = new UTF8Encoding(false);

        private const int KEYCOUNT = 2;
        private const int KEYLENGTH = 128 / 8;
        private const int PBKDF2ROUNDS = 256000;
        private const int IVSIZE = 16;
        private const int MAX_KEY_SIZE = 2048;

        private Vault _vault = null!;
        private SecureBuffer? _encryptionKey;
        private SecureBuffer? _hmacKey;
        private bool _vaultUpgradePending = false;
        private bool _sentinelValidated = false;

        public delegate SecureBuffer SerializeFunc<T>(T value);
        public delegate T DeserializeFunc<T>(SecureBuffer serialized);
        public delegate bool TryDeserializeFunc<T>(SecureBuffer serialized, out T deserialized);

        /// <summary>
        /// The vault has been upgraded to a new schema version. Changes should be saved to disk.
        /// </summary>
        public bool StoreUpgraded { get; internal set; } = false;

#if !JSON_SERIALIZER
        public ISecretSerializer? DefaultSerializer { get; set; } = null;
#else
        public ISecretSerializer? DefaultSerializer { get; set; } = new Serializers.Utf8JsonSerializer();
#endif

        /// <summary>
        /// A <c>JsonSerializerSettings</c> instance that must be used (at least) for all deserialization
        /// calls as it addresses a known security issue in Newtonsoft.Json
        /// </summary>
        internal static JsonSerializerSettings DefaultJsonSettings => new JsonSerializerSettings()
        {
            // Guard against GHSA-5crp-9r3c-p9vr
            // See https://github.com/advisories/GHSA-5crp-9r3c-p9vr
            MaxDepth = 128,
        };

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

        internal static void GenerateBytes(byte[] buffer)
        {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
            RandomNumberGenerator.Fill(buffer);
#else
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);
#endif
        }

        // Generate a new key for a new store
        public void GenerateKey()
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            _encryptionKey = new SecureBuffer(KEYLENGTH);
            GenerateBytes(_encryptionKey.Value.Buffer);
            _hmacKey = new SecureBuffer(KEYLENGTH);
            GenerateBytes(_hmacKey.Value.Buffer);
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
                if (file.Length == KEYLENGTH * KEYCOUNT)
                {
                    LoadLegacyKeyFromStream(file);
                }
                else if (file.Length > KEYLENGTH * KEYCOUNT)
                {
                    LoadPemKeyFromStream(file);
                }
                else
                {
                    throw new InvalidKeyFileException();
                }
            }
        }

        public void LoadKeyFromStream(Stream stream)
        {
            using var mstream = new MemoryStream();

            var buffer = new byte[4096];
            int bytesRead = 0;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                mstream.Write(buffer, 0, bytesRead);
                if (mstream.Length > MAX_KEY_SIZE)
                {
                    throw new InvalidKeyFileException("Key from stream is too large!");
                }
            }

            mstream.Seek(0, SeekOrigin.Begin);

            if (mstream.Length == KEYLENGTH * KEYCOUNT)
            {
                LoadLegacyKeyFromStream(mstream);
            }
            else if (mstream.Length > KEYLENGTH * KEYCOUNT)
            {
                LoadPemKeyFromStream(mstream);
            }
            else
            {
                throw new InvalidKeyFileException();
            }
        }

        private void LoadPemKeyFromStream(Stream stream)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            var pemReader = new PemReader();
            var insecure = pemReader.Read(stream);
            SplitAndLoadKey(insecure);

            CheckUpgrade();
        }

        // Load an encryption key from a file
        private void LoadLegacyKeyFromStream(Stream stream)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            _encryptionKey = new SecureBuffer(KEYLENGTH);
            _hmacKey = new SecureBuffer(KEYLENGTH);

            foreach (var buffer in new[] { _encryptionKey.Value.Buffer, _hmacKey.Value.Buffer })
            {
                int offset = 0;
                int bytesRead = -1;
                while (bytesRead != 0)
                {
                    bytesRead = stream.Read(buffer, offset, KEYLENGTH - offset);
                    offset += bytesRead;
                }

                if (offset != KEYLENGTH)
                {
                    throw new IOException("Error reading key from file!");
                }
            }

            // Validate that we have exhausted the key source
            if (stream.ReadByte() != -1)
            {
                throw new InvalidKeyFileException("The key file is longer than expected!");
            }

            CheckUpgrade();
        }

        public async Task LoadKeyFromFileAsync(string path, CancellationToken cancel = default)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous))
            {
                if (file.Length == KEYLENGTH * KEYCOUNT)
                {
                    await LoadLegacyKeyFromStreamAsync(file, cancel);
                }
                else if (file.Length > KEYLENGTH * KEYCOUNT)
                {
                    await LoadPemKeyFromStreamAsync(file, cancel);
                }
                else
                {
                    throw new InvalidKeyFileException();
                }
            }
        }

        public async Task LoadKeyFromStreamAsync(Stream stream, CancellationToken cancel = default)
        {
            using var mstream = new MemoryStream();

            var buffer = new byte[4096];
            int bytesRead = 0;
            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancel)) != 0)
            {
                await mstream.WriteAsync(buffer, 0, bytesRead, cancel);
                if (mstream.Length > MAX_KEY_SIZE)
                {
                    throw new InvalidKeyFileException("Key from stream is too large!");
                }
            }

            mstream.Seek(0, SeekOrigin.Begin);

            if (mstream.Length == KEYLENGTH * KEYCOUNT)
            {
                await LoadLegacyKeyFromStreamAsync(mstream, cancel);
            }
            else if (mstream.Length > KEYLENGTH * KEYCOUNT)
            {
                await LoadPemKeyFromStreamAsync(mstream, cancel);
            }
            else
            {
                throw new InvalidKeyFileException();
            }
        }

        private async Task LoadPemKeyFromStreamAsync(Stream stream, CancellationToken cancel = default)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            var pemReader = new PemReader();
            var insecure = await pemReader.ReadAsync(stream, cancel);
            SplitAndLoadKey(insecure);

            CheckUpgrade();
        }

        private async Task LoadLegacyKeyFromStreamAsync(Stream stream, CancellationToken cancel = default)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            {
                _encryptionKey = new SecureBuffer(KEYLENGTH);
                _hmacKey = new SecureBuffer(KEYLENGTH);

                foreach (var buffer in new[] { _encryptionKey.Value.Buffer, _hmacKey.Value.Buffer })
                {
                    int offset = 0;
                    int bytesRead = -1;
                    while (bytesRead != 0)
                    {
                        bytesRead = await stream.ReadAsync(buffer, offset, KEYLENGTH - offset, cancel);
                        offset += bytesRead;
                    }

                    if (offset != KEYLENGTH)
                    {
                        throw new IOException("Error reading key from file!");
                    }
                }

                // Verify that the stream does not contain any more bytes
                if (stream.ReadByte() != -1)
                {
                    throw new InvalidKeyFileException("The key file is longer than expected");
                }
            }

            CheckUpgrade();
        }

        public void ExportKey(string path)
        {
            if (_encryptionKey?.Buffer == null || _hmacKey?.Buffer == null)
            {
                throw new NoKeyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            using (var mstream = new MemoryStream(KEYCOUNT * KEYLENGTH))
            {
                mstream.Write(_encryptionKey.Value.Buffer, 0, KEYLENGTH);
                mstream.Write(_hmacKey.Value.Buffer, 0, KEYLENGTH);

                var pemWriter = new PemWriter();
                pemWriter.Write(file, mstream.GetBuffer().AsMemory(0, KEYCOUNT * KEYLENGTH));
                file.Flush();
            }
        }

        public async Task ExportKeyAsync(string path, CancellationToken cancel = default)
        {
            if (_encryptionKey?.Buffer == null || _hmacKey?.Buffer == null)
            {
                throw new NoKeyLoadedException();
            }

            // We don't know how .NET buffers things in memory, so we write it ourselves for maximum security.
            // Avoid excess buffering where possible, even if it's slower.
            using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            using (var mstream = new MemoryStream(KEYCOUNT * KEYLENGTH))
            {
                await mstream.WriteAsync(_encryptionKey.Value.Buffer, 0, KEYLENGTH, cancel);
                await mstream.WriteAsync(_hmacKey.Value.Buffer, 0, KEYLENGTH, cancel);

                var pemWriter = new PemWriter();
                await pemWriter.WriteAsync(file, mstream.GetBuffer().AsMemory(0, KEYCOUNT * KEYLENGTH), cancel);
                await file.FlushAsync(cancel);
            }
        }

        public SecureBuffer ExportKey()
        {
            if (_encryptionKey?.Buffer == null || _hmacKey?.Buffer == null)
            {
                throw new NoKeyLoadedException();
            }

            var secure = new SecureBuffer(KEYLENGTH * 2);
            var buffers = new[] { _encryptionKey.Value.Buffer, _hmacKey.Value.Buffer };
            for (int i = 0; i < buffers.Length; ++i)
            {
                Array.Copy(buffers[i], 0, secure.Buffer, i * KEYLENGTH, KEYLENGTH);
            }

            return secure;
        }

        static internal byte[] DerivePassword(string password, byte[] salt, int rounds = PBKDF2ROUNDS)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, rounds))
            {
                return pbkdf2.GetBytes(KEYLENGTH * KEYCOUNT);
            }
        }

        internal void SplitAndLoadKey(byte[] insecure)
        {
            if (insecure.Length != KEYLENGTH * 2)
            {
                throw new ArgumentException("Key with incorrect length provided!");
            }

            // While the consensus is that AES and HMAC are "sufficiently different" that reusing
            // the same key for Encrypt-then-MAC is probably safe, it's not something provable
            // and therefore (esp. since we can without too much additional burden) we should use two
            // separate keys.
            _encryptionKey = new SecureBuffer(KEYLENGTH);
            _hmacKey = new SecureBuffer(KEYLENGTH);

            Array.Copy(insecure, 0, _encryptionKey.Value.Buffer, 0, KEYLENGTH);
            Array.Copy(insecure, KEYLENGTH, _hmacKey.Value.Buffer, 0, KEYLENGTH);
        }

        // Derive an encryption key from a password
        public void LoadKeyFromPassword(string password)
        {
            if (_encryptionKey != null)
            {
                throw new KeyAlreadyLoadedException();
            }

            var insecure = DerivePassword(password, _vault.IV);
            SplitAndLoadKey(insecure);

            CheckUpgrade(password);
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

            SplitAndLoadKey(key);
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

        public void ValidateSentinel()
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
                _vault = JsonSerializer.Create(DefaultJsonSettings).Deserialize<VaultLoader>(jreader)!;
                if (_vault.VaultVersion > Vault.SCHEMAVERSION)
                {
                    throw VaultVersionException.UnsupportedVersion();
                }
                if (_vault.VaultVersion != Vault.SCHEMAVERSION)
                {
                    _vaultUpgradePending = true;
                }
            }
        }

        private void CheckUpgrade(string? password = null)
        {
            if (_vaultUpgradePending && _vault is not null && _encryptionKey is not null)
            {
                if (VaultVersionPolicy == VaultVersionPolicy.Strict)
                {
                    throw new VaultVersionException($"Current {VaultVersionPolicy} forbids use of older vault versions! " +
                        $"Upgrade the vault (via the SecureStore cli or api) and then re-deploy the upgraded secrets file.");
                }
                var upgrade = new VaultUpgrade();
                upgrade.Upgrade(this, _vault, password);
                StoreUpgraded = true;
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

        public bool TryGetBytes(string key, Action<byte[]> receiver)
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

        public bool TryGetValue<T>(string key, out T? value)
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

        public bool TryGetValue<T>(string key, TryDeserializeFunc<T> deserialize, out T? value)
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

        public bool TryGetValue<T>(string key, DeserializeFunc<T> deserialize, out T? value)
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
                var @string = (string)(object)value!;
                var byteCount = DefaultEncoding.GetByteCount(@string);
                using (var secure = new SecureBuffer(byteCount))
                {
                    DefaultEncoding.GetBytes(@string, 0, @string.Length, secure.Buffer, 0);
                    Set(key, secure);
                }
            }
            else if (typeof(T) == typeof(byte[]))
            {
                var bytes = (byte[])(object)value!;
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
                JsonSerializer.Create(DefaultJsonSettings).Serialize(jwriter, _vault);
            }
        }

        public IEnumerable<string> Keys => _vault.Data.Keys;

        private EncryptedBlob Encrypt(SecureBuffer input)
        {
            EncryptedBlob blob;

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Key = _encryptionKey!.Value.Buffer;
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
            using var hmac = HMAC.Create("HMACSHA1")!;
            hmac.Key = _hmacKey!.Value.Buffer;

            hmac.TransformBlock(iv, 0, iv.Length, iv, 0);
            hmac.TransformFinalBlock(encrypted, 0, encrypted.Length);

            return hmac.Hash!;
        }

        internal SecureBuffer Decrypt(EncryptedBlob blob)
        {
            // Validate the HMAC
            var calculatedHmac = Authenticate(blob.IV, blob.Payload);

            if (calculatedHmac.Length != blob.Hmac.Length)
            {
                throw new TamperedCipherTextException();
            }

            // Compare without early abort for timing attack resistance
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
            if (!CryptographicOperations.FixedTimeEquals(calculatedHmac, blob.Hmac))
            {
                throw new TamperedCipherTextException();
            }
#else
            int mismatches = 0;
            for (int i = 0; i < calculatedHmac.Length; ++i)
            {
                mismatches += (byte)(calculatedHmac[i] ^ blob.Hmac[i]);
            }
            if (mismatches != 0)
            {
                throw new TamperedCipherTextException();
            }
#endif

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Key = _encryptionKey!.Value.Buffer;
            aes.BlockSize = 128;
            aes.IV = blob.IV;

            using (var decryptor = aes.CreateDecryptor())
            {
                var unsecured = decryptor.TransformFinalBlock(blob.Payload, 0, blob.Payload.Length);
                return new SecureBuffer(unsecured);
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
        public bool TryRetrieve<T>(string key, out T? value)
        {
            return TryGetValue<T>(key, out value);
        }

        [Obsolete("Use SecretsManager.Get(..) instead.")]
        public string? Retrieve(string key)
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
