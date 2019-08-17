using Microsoft.VisualStudio.TestTools.UnitTesting;
using NeoSmart.SecureStore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Tests
{
    [TestClass]
    public class FunctionalityTests
    {
        static private Dictionary<string, string> SecureData = new Dictionary<string, string>()
        {
            { "foo1", "bar1" },
            { "foo2", "bar2" },
            { "foo3", "bar3" },
        };

        [TestMethod]
        public void CreateStore()
        {
            var storePath = Path.GetTempFileName();

            using (var sman = SecretsManager.CreateStore())
            {
                sman.GenerateKey();
                sman.SaveStore(storePath);
            }

            Assert.IsTrue(File.Exists(storePath));
            Assert.AreNotEqual(0, new FileInfo(storePath).Length, "Saved store is zero bytes!");
        }

        [TestMethod]
        public void ExportNewKey()
        {
            var keyPath = Path.GetTempFileName();

            using (var sman = SecretsManager.CreateStore())
            {
                sman.GenerateKey();
                sman.ExportKey(keyPath);
            }

            Assert.IsTrue(File.Exists(keyPath));
            Assert.AreNotEqual(0, new FileInfo(keyPath).Length, "Exported key is zero bytes!");
        }

        private void CreateTestStore(string storePath, string keyPath)
        {
            using (var sman = SecretsManager.CreateStore())
            {
                sman.GenerateKey();
                foreach (var key in SecureData.Keys)
                {
                    sman.Set(key, SecureData[key]);
                }
                sman.SaveStore(storePath);
                sman.ExportKey(keyPath);
            }
        }

        [TestMethod]
        public void StoreAndLoad()
        {
            var storePath = Path.GetTempFileName();
            var keyPath = Path.GetTempFileName();

            CreateTestStore(storePath, keyPath);

            using (var sman = SecretsManager.LoadStore(storePath))
            {
                sman.LoadKeyFromFile(keyPath);
                foreach (var key in SecureData.Keys)
                {
                    Assert.AreEqual(SecureData[key], sman.Get(key), $"Retrieved data for key \"{key}\" does not match stored value!");
                }
            }
        }


        [TestMethod]
        public void StoreAndLoadStream()
        {
            var storePath = Path.GetTempFileName();
            var keyPath = Path.GetTempFileName();

            CreateTestStore(storePath, keyPath);

            using (var stream = new FileStream(storePath, FileMode.Open, FileAccess.Read))
            {
                using (var sman = SecretsManager.LoadStore(stream))
                {
                    sman.LoadKeyFromFile(keyPath);
                    foreach (var key in SecureData.Keys)
                    {
                        Assert.AreEqual(SecureData[key], sman.Get(key), $"Retrieved data for key \"{key}\" does not match stored value!");
                    }
                }
            }
        }
    }
}
