using Newtonsoft.Json;

namespace NeoSmart.SecureStore
{
    public interface ISecretSerializer
    {
        public SecureBuffer Serialize<T>(T @object);
        public T Deserialize<T>(SecureBuffer serialized);
    }

    namespace Serializers
    {
        // This class is used by VaultUpgrade_V1_V2 even if JSON_SERIALIZER is not defined.
        class Utf8JsonSerializer : ISecretSerializer
        {
            public SecureBuffer Serialize<T>(T @object)
            {
                return new SecureBuffer(SecretsManager.DefaultEncoding.GetBytes(JsonConvert.SerializeObject(@object)));
            }

            public T Deserialize<T>(SecureBuffer serialized)
            {
                return JsonConvert.DeserializeObject<T>(SecretsManager.DefaultEncoding.GetString(serialized.Buffer));
            }
        }
    }
}
