using Microsoft.VisualStudio.TestTools.UnitTesting;
using NeoSmart.SecureStore;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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

            //generate a valid store
            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromPassword(password);
                sman.Set("foo", "bar");
                sman.SaveSecretsToFile(storePath);
            }

            //load the store contents into memory
            var fileData = File.ReadAllText(storePath);
            var deserialized = JsonConvert.DeserializeObject<dynamic>(fileData);

            string base64 = deserialized.Data.foo.Payload;
            var bytes = Convert.FromBase64String(base64);

            //tamper with the data
            var prng = new Random();
            for (int i = 0; i < bytes.Length; ++i)
            {
                bytes[i] ^= (byte)prng.Next();
            }

            //write the changes back
            deserialized.Data.foo.Payload = Convert.ToBase64String(bytes);
            fileData = JsonConvert.SerializeObject(deserialized);
            File.WriteAllText(storePath, fileData);

            //test decryption
            using (var sman = SecretsManager.LoadStore(storePath))
            {
                sman.LoadKeyFromPassword(password);
                Assert.ThrowsException<TamperedCipherTextException>(() => sman.Retrieve("foo"), "Could not detect tampering with encrypted data!");
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
                sman.SaveSecretsToFile(storePath);
            }

            using (var sman = SecretsManager.LoadStore(storePath))
            {
                sman.LoadKeyFromPassword("password2");

                string retrieved = null;
                try
                {
                    retrieved = sman.Retrieve("foo");
                }
                catch { }
                Assert.AreNotEqual("bar", retrieved, "Retrieved encrypted data with wrong password!");
            }
        }
    }
}
