using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecureStore;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var secure = new SecretsManager();
            
            secure.InitializeNewStore();
            secure.LoadKeyFromPassword("test123");

            var testSuite = new Dictionary<string, object>
            {
                {"string", "hello"},
                {"int", 42},
                {"guid", Guid.NewGuid()}
            };

            //Test adding
            foreach (var secret in testSuite)
            {
                secure.AddSecret(secret.Key, secret.Value);
            }

            //Test exporting the key (also so we can test key <---> password compatibility later)
            secure.SaveKeyFile("keyfile.bin");

            //Test saving
            secure.SaveSecretsToFile("encrypted.bin");

            //Test load with key
            var test1 = new SecretsManager();
            
            //Test it throws exception when trying to load a key but no store has been loaded
            var exceptionThrown = false;
            try
            {
                test1.LoadKeyFromPassword("test123");
            }
            catch (NoStoreLoadedException ex)
            {
                exceptionThrown = true;
            }

            if (!exceptionThrown)
            {
                throw new Exception("No exception was thrown when loading key without store!");
            }

            //Test loading encrypted data from disk
            test1.LoadSecretsFromFile("encrypted.bin");

            //Test decrypting with previously-exported key file
            test1.LoadKeyFile("keyfile.bin");

            //Test decryption of basic string
            if (test1.RetrieveSecret<string>("string") != (string) testSuite["string"])
            {
                throw new Exception("Problem retrieving previously-saved string with key from file!");
            }

            //Test decryption of complex type (GUID)
            if (test1.RetrieveSecret<Guid>("guid") != (Guid)testSuite["guid"])
            {
                throw new Exception("Problem retrieving previously-saved GUID with key from file!");
            }

            //Test decryption from password
            var test2 = new SecretsManager();
            test2.LoadSecretsFromFile("encrypted.bin");
            test2.LoadKeyFromPassword("test123");

            //Test decryption of basic int
            if (test1.RetrieveSecret<int>("int") != (int)testSuite["int"])
            {
                throw new Exception("Problem retrieving previously-saved int with key from password!");
            }

            Console.WriteLine("Test passed!");
        }
    }
}
