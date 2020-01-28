using System.Collections.Generic;

namespace NeoSmart.SecureStore.Versioning
{
    class VaultUpgrade_V2_V3 : IVaultUpgrade
    {
        public int FromVersion => 2;
        public int ToVersion => 3;

        public bool Upgrade(SecretsManager sman, Vault vault, string password)
        {
            // Upgrade from 10,000 PBKDF2 rounds to 256,000 PBKDF2 rounds
            if (password is null)
            {
                return true;
            }

            // Load old key
            var oldKey = SecretsManager.DerivePassword(password, vault.IV, 10000);
            sman.SplitAndLoadKey(oldKey);

            var secrets = new Dictionary<string, SecureBuffer>(vault.Data.Count);
            foreach (var kv in vault.Data)
            {
                secrets.Add(kv.Key, sman.Decrypt(kv.Value));
            }

            // Load new key with explicit IV length
            vault.IV = new byte[16];
            SecretsManager.GenerateBytes(vault.IV);
            var newKey = SecretsManager.DerivePassword(password, vault.IV, 256000);
            sman.SplitAndLoadKey(newKey);

            // Update individual secrets
            foreach (var kv in secrets)
            {
                sman.Set(kv.Key, kv.Value);
                kv.Value.Dispose();
            }

            // Update sentinel to match new password
            vault.Sentinel = null;
            sman.CreateSentinel();

            return true;
        }
    }
}
