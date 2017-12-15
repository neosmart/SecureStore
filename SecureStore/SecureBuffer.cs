using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace NeoSmart.SecureStore
{
    public class SecureBuffer : IDisposable
    {
        public readonly byte[] Buffer;
        private readonly GCHandle _gcHandle;

        public SecureBuffer(int size)
        {
            Buffer = new byte[size];
            //prevent the GC from moving this around
            _gcHandle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
        }

        public SecureBuffer(byte[] insecure)
        {
            Buffer = insecure;
            //prevent the GC from moving this around
            _gcHandle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
        }

        public void Dispose()
        {
            //Overwrite key in memory before leaving
#if NETSTANDARD1_3
            var rng = RandomNumberGenerator.Create();
#else
            var rng = new RNGCryptoServiceProvider();
#endif
            rng.GetBytes(Buffer);

#if !NET20 && !NET30 && !NET35
            rng.Dispose();
#endif

            _gcHandle.Free();
        }
    }
}
