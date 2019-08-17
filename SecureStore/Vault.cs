using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace NeoSmart.SecureStore
{
    sealed internal class Vault
    {
        /* Schema Changelog:
         * v1: Initial version, all values are stored as JSON-encoded
         * v2: Strings stored as UTF8, bytes stored as-is (unserialized), numbers stored as Big Endian
         */
        internal const int SCHEMAVERSION = 2;

        [JsonProperty(PropertyName = "version")]
        private int _vaultVersion;
        /// <summary>
        /// The schema version of the loaded vault instance.
        /// </summary>
        public int VaultVersion => _vaultVersion;

        [JsonProperty(PropertyName = "iv")]
        private byte[] _iv;
        /// <summary>
        /// The initialization vector used for password-based key derivation.
        /// </summary>
        public byte[] IV => _iv;

        [JsonProperty(PropertyName = "secrets")]
        private SortedDictionary<string, EncryptedBlob> _data;
        /// <summary>
        /// All secrets stored in this vault, sorted by name.
        /// </summary>
        public SortedDictionary<string, EncryptedBlob> Data => _data;

        /// <summary>
        /// This constructor is only intended for use by the serialization library.
        /// </summary>
        [Obsolete("Not intended to be used directly!", true)]
        public Vault()
        {
        }

        internal Vault(byte[] iv)
        {
            _iv = iv;
            _vaultVersion = SCHEMAVERSION;
            _data = new SortedDictionary<string, EncryptedBlob>(StringComparer.OrdinalIgnoreCase);
        }
    }
}
