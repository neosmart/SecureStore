using System;
using System.Collections.Generic;

namespace NeoSmart.SecureStore.Versioning
{
    public enum VaultVersionPolicy
    {
        /// <summary>
        /// Vaults with a previous schema version will not be loaded and
        /// a runtime exception will be thrown.
        /// </summary>
        Strict,
        /// <summary>
        /// Vaults with older schema versions will be upgraded when loaded.
        /// </summary>
        Upgrade,
    }

    public class VaultVersionException : SecretsException
    {
        public VaultVersionException(string message)
            : base(message)
        {
        }

        internal static VaultVersionException UnsupportedVersion()
        {
            return new VaultVersionException(
                "An attempt was made to load a secrets file that cannot be read with this version of SecureStore.");
        }

        internal static VaultVersionException PolicyViolation()
        {
            return new VaultVersionException(
                "An attempt was made to load a secrets file in conflict with the specified schema version compatibility policy.");
        }

        /// <summary>
        /// This purposely does not take an internal exception or extra error info to avoid leaking sensitive data.
        /// </summary>
        /// <returns></returns>
        internal static VaultVersionException UpgradeException()
        {
            return new VaultVersionException(
                "An error occurred attempting to upgrade from a previous version of the secrets vault.");
        }
    }

    internal interface IVaultUpgrade
    {
        int FromVersion { get; }
        int ToVersion { get; }

        bool Upgrade(SecretsManager sman, Vault vault, string password);
    }

    internal class VaultUpgrade
    {
        readonly Dictionary<int, IVaultUpgrade> _upgradeMap = new Dictionary<int, IVaultUpgrade>();

        public VaultUpgrade()
        {
            _upgradeMap.Add(1, new VaultUpgrade_V1_V2());
            _upgradeMap.Add(2, new VaultUpgrade_V2_V3());
        }

        public void Upgrade(SecretsManager sman, Vault vault, string password)
        {
            while (vault.VaultVersion != Vault.SCHEMAVERSION)
            {
                if (_upgradeMap.TryGetValue(vault.VaultVersion, out var upgrade))
                {
                    try
                    {
                        if (!upgrade.Upgrade(sman, vault, password))
                        {
                            throw VaultVersionException.UpgradeException();
                        }
                    }
                    catch (VaultVersionException)
                    {
                        throw;
                    }
                    catch
                    {
                        // Intentionally does not take an inner exception to avoid leaking
                        // possibly sensitive data.
                        throw VaultVersionException.UpgradeException();
                    }
                    vault.VaultVersion = upgrade.ToVersion;
                    continue;
                }
                else
                {
                    throw VaultVersionException.UnsupportedVersion();
                }
            }
        }
    }
}
