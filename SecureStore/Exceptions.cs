using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureStore
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
}
