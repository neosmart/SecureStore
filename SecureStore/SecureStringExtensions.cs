using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace NeoSmart.SecureStore
{
    static class SecureStringExtensions
    {
        public static void FromInsecure(this SecureString ss, string value)
        {
            ss.Clear();
            ss.AppendInsecure(value);
        }

        public static void AppendInsecure(this SecureString ss, string value)
        {
            foreach (var c in value)
            {
                ss.AppendChar(c);
            }
        }
    }
}
