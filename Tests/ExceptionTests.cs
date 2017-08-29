using Microsoft.VisualStudio.TestTools.UnitTesting;
using NeoSmart.SecureStore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;

namespace Tests
{
    [TestClass]
    public class ExceptionTests
    {
        [TestMethod]
        public void LoadMultipleKeys()
        {
            string exportedKeyPath = Path.GetTempFileName();

            using (var sman = SecretsManager.CreateStore())
            {
                sman.GenerateKey();

                //export to re-use later
                sman.ExportKey(exportedKeyPath);

                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.GenerateKey());
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.LoadKeyFromFile(exportedKeyPath));
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.LoadKeyFromPassword("password"));
            }

            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromPassword("password");
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.GenerateKey());
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.LoadKeyFromFile(exportedKeyPath));
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.LoadKeyFromPassword("password"));
            }

            using (var sman = SecretsManager.CreateStore())
            {
                sman.LoadKeyFromFile(exportedKeyPath);
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.GenerateKey());
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.LoadKeyFromFile(exportedKeyPath));
                Assert.ThrowsException<KeyAlreadyLoadedException>(() => sman.LoadKeyFromPassword("password"));
            }
        }
    }
}
