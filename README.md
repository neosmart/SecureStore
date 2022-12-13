# SecureStore: the .NET Secrets Manager

[SecureStore is an open, symmetrically-encrypted secrets file format](https://neosmart.net/blog/2020/securestore-open-secrets-format/) that proudly embraces the KISS mentality, attempts to balance security with ease-of-use, and eschews overly-complicated solutions where possible.

## SecureStore Architecture

While "how to use" might be a more typical first section of the README for libraries, as a security-oriented library, we feel that "how it works" better deserves the initial focus.

Unlike other secrets managers for .NET, SecureStore attempts to walk the fine line between security and pragmatism. All secrets remain encrypted at rest, and there are no needless dependencies such as Docker or a separate secrets manager server.

At its heart, SecureStore secrets are stored in a JSON file on-disk (to make sure getting your data out is as easy as can be), encrypted via AES-128-CBC with a HMAC-SHA1 verification step for ciphertext authentication. The secrets file is formatted and maintained in a way that makes it version-control-friendly - you can both safely include the secrets file in your project repository ([read more about why you not only can but also _should_ do so](https://neosmart.net/blog/2017/securestore-a-net-secrets-manager/)) and we try to make it diff-friendly by never needlessly re-encrypting stored secrets and stably sorting its contents in a deterministic fashion so your version control system does not go haywire just because you added a new secret or changed an existing one.

For encryption/decryption, SecureStore can either use a key safely derived from a password of your choosing (currently via 256,000 rounds of PBKDF2 SHA1), generate a randomly-created key file, or use a pre-existing key securely created via other means of your choosing. Attempts are made to secure unencrypted data in memory by preventing GC reallocations and only keeping decrypted content as long as needed in memory, overwriting it when its no longer needed. _However, due to the design of the .NET language and the restrictions on unsafe memory access, no guarantees are made about the permanence of decrypted content in the memory and we do not consider protecting against a compromised machine to be a design goal._ If you're not sure what this means, don't worry, you should be safe. This is more of an academic detail for most people, and won't impact in any way the security of your secrets store, which you can feel free to publish on the front page of _The New York Times_ and have nothing to worry about.

Everything is self-contained in the SecureStore .NET library, available as a NuGet package. Creating a secrets file and adding secrets to it may be done via the same SecureStore API used for secrets retrieval or you can install the [separate, standalone CLI companion app](./Client) to more easily manage your secrets interactively.

You can read more about the architectural decisions that drive SecureStore in the [original release notes](https://neosmart.net/blog/2017/securestore-a-net-secrets-manager/) and [the updated article covering the cross-platform 1.0 release](https://neosmart.net/blog/2020/securestore-open-secrets-format/).

## Obtaining SecureStore

The SecureStore.NET library is currently available for all versions of the .NET Framework and .NET Core and can be obtained by either locally cloning this git repository and building it or via NuGet:

    Install-Package SecureStore

The companion CLI app for creating and managing secrets files can be installed the same way as all the other `dotnet` tools:

    dotnet tool install --global SecureStore.Client

after which it is available for use in your shell as `SecureStore` (e.g. `SecureStore create secrets.json`). More information on using the command line utility can be found [in its documention](./Client).

## Using SecureStore

As previously mentioned, SecureStore puts a premium on ease-of-use, and you can be up and going in minutes once you've added SecureStore to your .NET or ASP.NET project.

Everything starts and ends with a `SecretsManager` object, available in the `NeoSmart.SecureStore` namespace. The static methods `SecretsManager.CreateStore` and `SecretsManager.LoadStore` can be used to either create a new store or load an existing store; for your security and in an embrace of self-documenting APIs, the constructor for `SecretsManager` has been disabled - a `SecretsManager` instance can only be created via one of these two means.

**Important note:** `SecretsManager` implements `IDisposable` and _must_ only be instantiated in a `using` block! There is important cleanup of crypto resources in the `Dispose()` method!

### Creating Secrets

Your secrets can be created via the .NET `SecretsManager` API or via the standalone `SecureStore` CLI utility.

#### Creating secrets with the .NET API

As mentioned above, the encryption/decryption key used by SecureStore can be created by `SecretsManager`, securely derived from a password of your choice, or loaded from an existing key file provided by yourself. All options are shown below:

```csharp
// A using block MUST be used for security reasons!
using (var sman = SecretsManager.CreateStore())
{
	// Create a new key securely with a CSPRNG:
	sman.GenerateKey();
	// or use an existing key file:
	sman.LoadKeyFromFile("path/to/file");
	// or securely derive key from passsword:
	sman.LoadKeyFromPassword("p4ssw0rd!");

	sman.Set("foo", "bar");
	sman.Set("the answer", new byte[] { 42 });

	// Optionally export the keyfile (even if you created the store with a password)
	sman.ExportKey("secrets.key");

	// Then save the store if you've made any changes to it
	sman.SaveStore("secrets.bin");
}
```

The above code snippet demonstrates a few important points when it comes to using `SecretsManager`:

* A `using (...)` block **must** be used when creating or loading a `SecretsManager` instance.
* Any one (and only one) of the three methods (`GenerateKey()`, `LoadKeyFromFile(path)`, or `LoadKeyFromPassword(password)` may be used to load a private key into memory. An attempt to load multiple keys will cause a `KeyAlreadyLoadedException` to be thrown.
* The `SecretsManager.Set<T>(key, value)` is a generic function natively supporting the serialization of strings and binary lists/arrays. An option to override the default serializer with your own to provide support for other secret types is available.
* The `SecretsManager.ExportKey(path)` API can be used to export the key that was loaded into memory. Use this interface with obvious caution. This is obviously required when using the `GenerateKey()` API to initialize the private key used by the `SecretsManager` interface, but what may not be obvious is that it can be used to create a dual-decryptable store by creating a store with a password but also exporting the associated key. This lets you manage the store using the command line utility interactively with the convenience of a password but transmit the equivalent keyfile to your server for passwordless decryption in production.
* Unless `SecretManager.SaveStore(path)` is called, nothing is ever written to disk, including if an existing store was loaded and its contents modified.

Additionally, secrets may be appended to a previously-created store by calling `SecretsManager.LoadStore(path)` instead of `SecretsManager.CreateStore()`.

#### Creating secrets with `SecureStore` CLI

The SecureStore command line interface may also be used to create a secure store. A encryption key may be supplied as a password in a command line argument (if `-p` or `--password` is followed by a value), entered securely via `stdin` (if `-p` is not provided a value), or from a key file (via a value provided to the `-f` or `--keyfile` parameter). To create a new key file, simply specify `--keyfile` value pointing to a path that does not exist and a new key will be generated, used, and saved to the named path.

```
SecureStore create secrets.json
SecureStore --store secrets.json set foo bar
```

If no path to a store is provided at the command line, the default store `secrets.json` will be used.

See [the full client documentation](./Client) for further details.

### Retrieving Secrets

Retrieving secrets may also be done via both the .NET API and the `SecureStore` CLI. Options exist to iterate over all secrets in a secrets file and to query for the existence of a key in an exception-safe manner.

#### Retrieving secrets via the .NET API

The API to retrieve secrets does not differ greatly from that used to create them. Usage is straight-forward:

```csharp
using (var sman = SecretsManager.LoadStore("secrets.bin"))
{
	sman.LoadKeyFromFile("secrets.key");

	var secret = sman.Get("foo");
	if (!sman.TryGet("the answer", out byte[] answer))
	{
		Console.WriteLine("Secret \"the answer\" not found in store!");
	}
}
```

All secrets in a secrets file may be obtained by iterating over the `SecretsManager.Keys` value, which implements `IEnumerable`:

```csharp
using (var sman = SecretsManager.LoadStore("secrets.bin"))
{
	sman.LoadKeyFromPassword("p4ssw0rd!");

	foreach(var k in sman.Keys)
	{
		Console.WriteLine($"{k}: {sman.Get(k)}");
	}
}
```

Needless to say, this should be used with extreme caution.


#### Retrieving secrets via the `SecureStore` CLI

The `SecureStore` utility also provides similar functionality and can be used to both retrieve a single value or to export a decrypted copy of the store.

    SecureStore get -s secrets.bin foo

The above will prompt for a password and then echo `bar` to the command line. No additional text is printed, making it suitable for inclusion in scripts or other workflows that rely on piping or parsing `stdout` content. The default mode of operation is `--password`/`-p`, which may be omitted as above.

A copy of all encrypted data in a store may be obtained via `ssclient get --all` in either json (`--format json`, default) or plain text (`--format text`) formats:

    SecureStore get --all -s secrets.bin --keyfile secrets.key

and

    SecureStore get --all --format text -s secrets.bin -p

## License and Copyright

SecureStore for .NET is written and developed by Mahmoud Al-Qudsi of NeoSmart Technologies. SecureStore is released to the general public under the terms of the open source MIT license, and all rights not assigned are reserved to NeoSmart Technologies. The names `SecureStore` and `SecureStore.NET` are copyright NeoSmart Technologies 2015 - 2022.
