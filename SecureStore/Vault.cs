using System;
using System.Collections.Generic;
using System.ComponentModel;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace NeoSmart.SecureStore
{
    internal class Vault
    {
        /* Schema Changelog:
         * v1: Initial version, all values are stored as JSON-encoded
         * v2: Strings stored as UTF8, bytes stored as-is (unserialized),
         *     and fields renamed more descriptively and camelCased per
         *     JSON conventions (VaultVersion -> version, Data -> secrets),
         *     and added an optional Sentinel field.
         */
        internal const int SCHEMAVERSION = 2;

        /// <summary>
        /// The schema version of the loaded vault instance.
        /// </summary>
        [JsonProperty(PropertyName = "version")]
        public int VaultVersion { get; set; }

        /// <summary>
        /// The initialization vector used for password-based key derivation.
        /// </summary>
        [JsonProperty(PropertyName = "iv")]
        public byte[] IV;

        /// <summary>
        /// We store a randomly-generated sentinel value in the store when it is first created.
        /// This has no impact on the security of the contents but does affect integrity: it lets
        /// us ensure that subsequent inserts are performed with the same key, preventing potential
        /// loss of data if a user fat-fingered the password and attempts to encrypt a key with an
        /// incorrect password or wrong keyfile.
        /// </summary>
        [JsonProperty(PropertyName = "sentinel")]
        public EncryptedBlob? Sentinel { get; set; }

        /// <summary>
        /// All secrets stored in this vault, sorted by name.
        /// </summary>
        [JsonProperty(PropertyName = "secrets")]
        public SortedDictionary<string, EncryptedBlob> Data { get; set; }

        internal Vault(byte[] iv)
        {
            IV = iv;
            VaultVersion = SCHEMAVERSION;
            Data = new SortedDictionary<string, EncryptedBlob>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// This constructor is only intended for use by the serialization library.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        protected Vault()
        {
        }
    }

    internal class VaultLoader : Vault
    {
        [Obsolete]
        [EditorBrowsable(EditorBrowsableState.Never)]
        [JsonProperty(PropertyName = "VaultVersion")]
        internal virtual int V1_VaultVersion
        {
            set => VaultVersion = value;
        }

        [Obsolete]
        [EditorBrowsable(EditorBrowsableState.Never)]
        [JsonProperty(PropertyName = "Data")]
        internal virtual SortedDictionary<string, EncryptedBlob> V1_Data
        {
            set => Data = value;
        }
    }
}
