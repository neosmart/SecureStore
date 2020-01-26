using System;
using System.Runtime.InteropServices;

namespace NeoSmart.SecureStore
{
    public readonly struct SecureBuffer : IDisposable
    {
        public readonly byte[] Buffer;
        private readonly GCHandle _gcHandle;

        /// <summary>
        /// Creates a new secure buffer in memory, sized to hold
        /// <paramref name="size"/> bytes. All buffer contents will
        /// be shredded when the object is disposed. The secure
        /// buffer memory is pinned while the object is alive.
        /// </summary>
        /// <param name="size"></param>
        public SecureBuffer(int size)
        {
            Buffer = new byte[size];

            // Prevent the GC from moving this around
            _gcHandle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
        }

        /// <summary>
        /// Creates a new secure buffer, attempting to lock down the
        /// passed-in array. No guarantees can be made regarding the
        /// successful shredding of memory after this object is disposed.
        /// </summary>
        /// <param name="insecure">The byte array containing the current
        /// values to be wrapped in a secure buffer.</param>
        public SecureBuffer(byte[] insecure)
        {
            Buffer = insecure;

            // Prevent the GC from moving this around
            _gcHandle = GCHandle.Alloc(Buffer, GCHandleType.Pinned);
        }

        /// <summary>
        /// Creates a new <see cref="SecureBuffer"/> to hold a copy of
        /// the data contained in <paramref name="insecure"/>. Does not
        /// offer any protection, but provides compatibility between
        /// <c>byte[]</c> and <c>SecureBuffer</c>.
        /// </summary>
        /// <param name="insecure"></param>
        /// <param name="offset"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static SecureBuffer From(byte[] insecure, int offset = 0, int? length = null)
        {
            var buffer = new SecureBuffer(length ?? insecure.Length);
            Array.Copy(insecure, offset, buffer.Buffer, 0, length ?? insecure.Length);
            return buffer;
        }

        public void Dispose()
        {
            // Overwrite key in memory before leaving
            SecretsManager.GenerateBytes(Buffer);

            // Un-pin the memory pointed to by the buffer
            _gcHandle.Free();
        }
    }
}
