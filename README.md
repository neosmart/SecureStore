#SecureStore: the .NET Secrets Manager

SecureStore is a symmetrically-encrypted secrets manager for .NET, that embraces the KISS mentality, focuses on security and ease-of-use, and eschews overly-complicated solutions where possible.

##SecureStore Architecture

While "how to use" might be a more typical first section of the README for libraries, as a security-oriented library, we feel that "how it works" better deserves the initial focus.

Unlike other secrets managers for .NET, SecureStore attempts to walk the fine line between security and pragmatism. All secrets remain encrypted at rest, and there are no needless dependencies such as Docker or a separate secrets manager server. 

At its heart, SecureStore secrets are stored in a JSON file on-disk (to make sure getting your data out is as easy as can be), encrypted via AES-CBC with HMAC-SHA1 for ciphertext authentication. The secrets file is formatted and maintained in a way that makes it version-control-friendly - you can both safely include the secrets file in your project repository ([read more about why you not only can but also _should_ do so](https://neosmart.net/blog/2017/securestore-a-net-secrets-manager/)) and we try to make it diff-friendly by never needlessly re-encrypting stored secrets and stably sorting its contents in a deterministic fashion so your version control system does not go all haywire just because you added a new secret or changed an existing one.

For encryption/decryption, SecureStore can either use a key safely derived from a password of your choosing (currently 10,000 rounds of PBKDF2 SHA1), generate a randomly-created key file, or use a pre-existing key securely created via other means of your choosing. Attempts are made to secure unencrypted data in memory by preventing GC reallocations and only keeping decrypted content as long as needed in memory, overwriting it when its no longer needed. _However, due to the design of the .NET language and the restrictions on unsafe memory access, no guarantees are made about the permanence of decrypted content in the memory._ If you're not sure what this means, don't worry, you should be safe. This is more of an academic detail for most people, and won't impact in any way the security of your secrets store, which you can feel free to publish on the front page of _The New York Times_ and have nothing to worry about.

Everything is self-contained in the SecureStore .NET library, available as a NuGet package. Either the same SecureStore API used for secrets retrieval or a separate, standalone CLI can be used to create and manage the secrets file.

You can read more about the architectural decisions that drive SecureStore in the [original release notes](https://neosmart.net/blog/2017/securestore-a-net-secrets-manager/) for the first, public version of SecureStore.

##Obtaining SecureStore

SecureStore is currently available for all versions of the .NET Framework and .NET Core and can be obtained by either locally cloning this git repository or via NuGet:

    Install-Package SecureStore

##Using SecureStore

As previously mentioned, SecureStore puts a premium on ease-of-use, and you can be up and going in minutes once you've added SecureStore to your .NET or ASP.NET project.

Everything starts and ends with a `SecretsManager` object, available in the `NeoSmart.SecureStore` namespace. The static methods `SecretsManager.CreateStore` and `SecretsManager.LoadStore` can be used to either create a new store or load an existing store; for your security and in an embrace of self-documenting APIs, the constructor for `SecretsManager` has been disabled - a `SecretsManager` instance can only be created via one of these two means.

**Important note:** `SecretsManager` implements `IDisposable` and _must_ only be instantiated in a `using` block! There is important cleanup of crypto resources in the `Dispose()` method!

###Creating Secrets

Your secrets can be created via the .NET `SecretsManager` API or via the standalone `ssclient` CLI (short for SecureStore Client).

####Creating secrets with the .NET API

As mentioned above, the encryption/decryption key used by SecureStore can be created by `SecretsManager`, securely derived from a password of your choice, or loaded from an existing key file provided by yourself. All options are shown below:

```csharp
//a using block MUST be used for security purposes!
using (var sman = SecretsManager.CreateStore())
{
	sman.GenerateKey(); //create a new key via the .NET RNG
	//or
	sman.LoadKeyFromFile("path/to/file"); //use an existing key file
	//or
	sman.LoadKeyFromPassword("p4ssw0rd!"); //securely derive key from passsword

	sman.Set("foo", "bar");
	sman.Set("the answer", 42);

	//optional:
	sman.ExportKey("secrets.key");

	sman.SaveStore("secrets.bin");
}
```

The above code snippet demonstrates a few important points when it comes to using `SecretsManager`:

* A `using (...)` block **must** be used when creating or loading a `SecretsManager` instance.
* Any one (and only one) of the three methods (`GenerateKey()`, `LoadKeyFromFile(path)`, or `LoadKeyFromPassword(password)` may be used to load a private key into memory. An attempt to load multiple keys will cause a `KeyAlreadyLoadedException` to be thrown.
* The `SecretsManager.Set<T>(key, value)` is a generic function. Any type that can be serialized to JSON internally may be used as the secret value. Note that what constitutes a "supported type" may change, strings and integers will always be supported.
* The `SecretsManager.ExportKey(path)` API can be used to export the key that was loaded into memory. Use this interface with obvious caution. This is obviously required when using the `GenerateKey()` API to initialize the private key used by the `SecretsManager` interface.
* Unless `SecretManager.SaveStore(path)` is called, nothing is ever written to disk, including if an existing store was loaded and its contents modified.

Similarly, secrets may be appended to a previously-created store by calling `SecretsManager.LoadStore(path)` instead of `SecretsManager.LoadStore(...)`.

As you can see, apart from the generic `Retrive<T>(key)` method, an exception-safe `SecretsManager.TryRetrieve<T>(key, out T value)` method is also available.

####Creating secrets with `ssclient` CLI

The SecureStore command line interface `ssclient` may also be used to create a secure store. A password may be supplied as a command line argument (if `-p` or `--password` is followed by a value), entered via `stdin` (if `-p` is not provided a value), or from a key file (via a value provided to the `-f` or `--keyfile` parameter). To create a new key file, specify both `--keyfile` and `--generate` and a new key will be saved to the provided key file path.

```
ssclient create -s secrets.bin -p
ssclient update -s secrets.bin -k foo -v bar
```

See the full `ssclient` documentation for further details.

###Retrieving Secrets

Retrieving secrets may also be done via both the .NET API and the `ssclient` CLI. Options exist to iterate over all secrets in a secrets file and to query for the existence of a key in an exception-safe manner.

####Retrieving secrets via the .NET API

The API to retrieve secrets does not differ greatly from that used to create them. Usage is straight-forward:

```csharp
using (var sman = SecretsManager.LoadStore("secrets.bin"))
{
	sman.LoadKeyFromFile("secrets.key");

	var secret = sman.Retrieve("foo");
	if (!sman.TryRetrieve("the answer", out int answer))
	{
		Console.WriteLine("Secret \"the answer\" not found in store!");
	}
}
```

All secrets in a secrets file may be obtained by iterating over the `SecretsManager.Keys` `IEnumerable`:

```csharp
using (var sman = SecretsManager.LoadStore("secrets.bin"))
{
	sman.LoadKeyFromPassword("p4ssw0rd!");

	foreach(var k in sman.Keys)
	{
		Console.WriteLine($"{k}: {sman.Retrieve(k)}");
	}
}
```

Needless to say, this should be used with extreme caution.


####Retrieving secrets via the `ssclient` CLI

The `ssclient` utility also provides similar functionality and can be used to both retrieve a single value or to export a decrypted copy of the store.

    ssclient decrypt -s secrets.bin -k foo -p p4ssword

The above will print `bar` to the command line. No additional text is printed, making it suitable for inclusion in scripts or other workflows that rely on piping or parsing `stdout` content.

A copy of all encrypted data in a store may be obtained via `ssclient decrypt --all` in either json (`--format json`, default) or plain text (`--format text`) formats:

    ssclient decrypt --all -s secrets.bin --keyfile secrets.key

and

    ssclient decrypt --all --format text -s secrets.bin -p

##License and Copyright

SecureStore for .NET is written and developed by Mahmoud Al-Qudsi of NeoSmart Technologies. SecureStore is released to the general public under the terms of the open source MIT license, and all rights not assigned are reserved to NeoSmart Technologies. The name SecureStore is copyright NeoSmart Technologies 2015 - 2016.
