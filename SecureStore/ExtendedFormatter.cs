using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace SecureStore
{
    internal static class ExtendedFormatter
    {
        public static T Deserialize<T>(this BinaryFormatter formatter, Stream serialized)
        {
            return (T) formatter.Deserialize(serialized);
        }

        public static T Deserialize<T>(this BinaryFormatter formatter, byte[] serialized)
        {
            using (var memStream = new MemoryStream(serialized))
            {
                return formatter.Deserialize<T>(memStream);
            }
        }

        public static byte[] Serialize<T>(this BinaryFormatter formatter, T o)
        {
            using (var memStream = new MemoryStream())
            {
                formatter.Serialize(memStream, o);
                return memStream.ToArray();
            }
        }

        public static object Deserialize(this BinaryFormatter formatter, byte[] serialized)
        {
            using (var memStream = new MemoryStream(serialized))
            {
                return formatter.Deserialize(memStream);
            }
        }
    }
}
