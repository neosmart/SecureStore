using System;
using System.Collections.Generic;
using System.Text;

namespace NeoSmart.SecureStore.Client
{
    // This exception is thrown instead of calling Enivornment.Exit to ensure RAII cleanup
    internal class ExitCodeException : Exception
    {
        internal int ExitCode;

        public ExitCodeException(int exitCode, string msg = "")
            : base(msg)
        {
            ExitCode = exitCode;
        }
    }
}
