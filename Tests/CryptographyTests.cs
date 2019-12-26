using Microsoft.VisualStudio.TestTools.UnitTesting;
using NeoSmart.SecureStore;
using Newtonsoft.Json;
using System;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Tests
{
    [TestClass]
    public class CryptographyTests
    {
        /// <summary>
        /// Verifies that two keys generated from the same password are not the same.
        /// </summary>
        [TestMethod]
        public void PasswordSalting()
        {
            const string password = "password";
            string keyPath1 = Path.GetTempFileName();
            string keyPath2 = Path.GetTempFileName();

            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromPassword(password);
                sman.ExportKey(keyPath1);
            }

            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromPassword(password);
                sman.ExportKey(keyPath2);
            }

            var key1 = File.ReadAllBytes(keyPath1);
            var key2 = File.ReadAllBytes(keyPath2);

            Assert.IsTrue(key1.Length == key2.Length);
            Assert.IsFalse(key1.SequenceEqual(key2));
        }

        /// <summary>
        /// Verify tampered data fails HMAC checks
        /// </summary>
        [TestMethod]
        public void CatchTamperedData()
        {
            const string password = "password";
            string storePath = Path.GetTempFileName();

            // Generate a valid store
            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromPassword(password);
                sman.Set("foo", "bar");
                sman.SaveStore(storePath);
            }

            // Load the store contents into memory
            var fileData = File.ReadAllText(storePath);
            // We don't have access to the internal encrypted bytes payloads are
            // deserialized to, but we can just access it directly.
            var deserialized = JsonConvert.DeserializeObject<MockStore>(fileData);

            var bytes = deserialized.Secrets["foo"].Payload;

            // Tamper with the data
            var prng = new Random();
            for (int i = 0; i < bytes.Length; ++i)
            {
                bytes[i] ^= (byte)prng.Next();
            }

            // Write the changes back
            deserialized.Secrets["foo"].Payload = bytes;
            fileData = JsonConvert.SerializeObject(deserialized);
            File.WriteAllText(storePath, fileData);

            // Verify that tampering is caught
            using (var sman = SecretsManager.LoadStore(storePath))
            {
                sman.LoadKeyFromPassword(password);
                Assert.ThrowsException<TamperedCipherTextException>(() => sman.Get("foo"), "Could not detect tampering with encrypted data!");
            }
        }

        /// <summary>
        /// Verify contents cannot be decrypted with a wrong key/password
        /// </summary>
        [TestMethod]
        public void EncryptionTest()
        {
            string storePath = Path.GetTempFileName();

            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromPassword("password1");
                sman.Set("foo", "bar");
                sman.SaveStore(storePath);
            }

            using (var sman = SecretsManager.LoadStore(storePath))
            {
                sman.LoadKeyFromPassword("password2");

                string retrieved = null;
                try
                {
                    retrieved = sman.Get("foo");
                }
                catch { }
                Assert.AreNotEqual("bar", retrieved, "Retrieved encrypted data with wrong password!");
            }
        }

        /// <summary>
        /// Verify that the RNG creates unique keys.
        /// </summary>
        [TestMethod]
        public void KeyDuplicationTest()
        {
            string path1 = Path.GetTempFileName();
            string path2 = Path.GetTempFileName();

            using (var sman = SecretsManager.CreateStore())
            {
                sman.GenerateKey();
                sman.ExportKey(path1);
            }

            using (var sman = SecretsManager.CreateStore())
            {
                sman.GenerateKey();
                sman.ExportKey(path2);
            }

            // Verify that keys are not the same
            var key1 = File.ReadAllBytes(path1);
            var key2 = File.ReadAllBytes(path2);

            Assert.IsTrue(key1.Length == key2.Length, "Generated key lengths differ!");
            Assert.IsTrue(key1.Length != 0, "A zero-length keyfile was created!");
            Assert.IsFalse(key1.SequenceEqual(key2));
        }
    }
}
