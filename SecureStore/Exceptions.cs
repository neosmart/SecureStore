using System;

namespace NeoSmart.SecureStore
{
    public class SecretsException : Exception
    {
        public SecretsException(string message = null) : base(message)
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

    public class KeyAlreadyLoadedException : SecretsException
    {
        public KeyAlreadyLoadedException(string message) : base(message)
        {
        }

        public KeyAlreadyLoadedException() : this("A key has already been loaded!")
        {
        }
    }

    public class InvalidKeyFileException : SecretsException
    {
        public InvalidKeyFileException(string message) : base(message)
        {
        }

        public InvalidKeyFileException() : this("The selected file does not contain a valid encryption key!")
        {
        }
    }

    public class TamperedCipherTextException : SecretsException
    {
        public TamperedCipherTextException(string message) : base(message)
        {
        }

        public TamperedCipherTextException() : this("Either a wrong password has been used or the ciphertext in this secure store has been tampered with!")
        {
        }
    }
}
