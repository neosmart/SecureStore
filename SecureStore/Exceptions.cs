using System;

namespace NeoSmart.SecureStore
{
    public class SecretsException : Exception
    {
        public SecretsException(string message = null) : base(message)
        {
        }
    }

    public class NoStoreLoadedException : SecretsException
    {
        public NoStoreLoadedException(string message) : base(message)
        {
        }

        public NoStoreLoadedException() : this("Must first load an existing vault or create a new vault!")
        {
        }
    }

    public class NoKeyLoadedException : SecretsException
    {
        public NoKeyLoadedException(string message) : base(message)
        {
        }

        public NoKeyLoadedException() : this("No decryption key has been loaded yet!")
        {
        }
    }
}
