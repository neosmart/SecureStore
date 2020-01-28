# SecureStore CLI client

This repository houses the companion CLI utility to [the SecureStore.NET library](../SecureStore/),
which may be used to more easily create and manage secrets files that can be later decrypted from
code with the SecureStore library/nuget package.

## Introduction

[SecureStore is an open format for managing secrets versioned alongside your code under source
control](https://neosmart.net/blog/2020/securestore-open-secrets-format/). SecureStore is designed
to be language and framework agnostic, and there are official implementations available in multiple
languages; SecureStore secrets files (typically named `secrets.json`) are strongly typed and
guaranteed binary compatible between the various implementations, they're additionally carefully
designed to be both human-readable and git-friendly so you don't have to worry about merging
conflicts in binary files.

The SecureStore API may be used to both create/manage secrets files and decrypt secrets at runtime,
but most users prefer to use one of the SecureStore command line frontends (like this one!) to
create a secrets file and add/update/delete secrets, and then use the library to decrypt individual
secrets when needed at runtime. [Read more about the SecureStore format and sample usage
here](https://neosmart.net/blog/2020/securestore-open-secrets-format/).

## Installation

The SecureStore .NET Core CLI may be installed by either cloning and building this repository (in
which case it will generate a binary named `ssclient`) or via the .NET Core command-line `dotnet`:

```
dotnet tool install --global SecureStore.Client
```

Which will automatically download and install the latest published version of the SecureStore
client, after which it may be run by executing `SecureStore` in your terminal/shell.

## Usage

The application may be executed in your terminal by running `SecureStore.exe`:

```
ssclient 1.0.3 - SecureStore secrets manager client
Copyright NeoSmart Technologies 2017-2020 - https://github.com/neosmart/SecureStore/

Usage: ssclient [FLAGS] [create|set|get|delete] OPTIONS
        -h  --help      Show this help message and exit
        -v  --version   Print version information and exit
        -s  --store     Load secrets store from provided path
        -p  --password  Prompt for decryption password
        -k  --keyfile   Load decryption key from path

create options:
        -h  --help      Show help for create command options
        -p  --password  Secure store with a key derived from a password
        -k  --keyfile   Path to load or save secure key from/to
delete options:
        -h  --help      Show help for delete command options
        -s  --store     Load secrets store from provided path
        -p  --password  Decrypt store with key derived from password
        -k  --keyfile   Path to load secure key from
get options:
        -h  --help      Show help for decryption command options
        -s  --store     Load secrets store from provided path
        -p  --password  Decrypt store with key derived from password
        -k  --keyfile   Path to load secure key from
        -a  --all       Decrypt the entire contents of the store and print to stdout
        -t  --output-format     Specify the output format: json (default), text
set options:
        -h  --help      Show help for encryption command options
        -s  --store     Load secrets store from provided path
        -p  --password  Decrypt store with key derived from password
        -k  --keyfile   Path to load secure key from
```

### Creating a new store

A new store can be created by simply running `SecureStore create` which will prompt you for a
password and create a new store called `secrets.json` in the current directory, but more options
are available.

The default `SecureStore create` is equivalent to the following:

```
> SecureStore create secrets.json --password
Password: ********
```

SecureStore secrets files can be encrypted with a key derived from a password (as above) or a
securely generated binary keyfile:

```
SecureStore create secrets.json --keyfile secrets.key
```

Which will either create a new keyfile if `secrets.key` does not exist or else use an existing key
located at `secrets.key`. This keyfile is used for both encryption and decryption. SecureStore
secrets files are always symmetrically encrypted.

The easiest way to use SecureStore is to create a secrets file that is secured with a password, but
also export an equivalent key that can be used for passwordless decryption of secrets in your code
for production use:

```
> SecureStore create secrets.json --password --keyfile secrets.key
Password: ********
```

This will prompt you a password, securely derive a key from it, create a new secrets file named
`secrets.json` encrypted with the provided password, and then export the derived equivalent key to a
keyfile name `secrets.key`. This gives you the ease of interacting with and updating the secrets
file locally with a password (so you don't have sensitive keyfiles laying around) while using the
keyfile to decrypt secrets from the store at runtime without a password.

**While secrets files (e.g. `secrets.json`) are encrypted and may be included in source control, the
keyfile must be handled with extreme care and should be securely moved to the production servers or
a key store and then deleted locally!**

### Adding secrets to the store

Secrets can be added to the store via the `set` subcommand. A secret may be provided directly as a
command line argument or supplied interactively for greater security (so that it is not included in
your terminal/shell history) or to avoid argument quoting/parsing issues:

```
> SecureStore --store secrets.json set secretName secretValue
Password: ********
```

If `--store STORE` is omitted, `SecureStore` will default to `secrets.json`. When neither
`-p`/`--password` or `-k`/`--keyfile` is supplied, `SecureStore` will default to password-based
encryption/decryption mode and will prompt for a password to be supplied via stdin.

The syntax for updating/replacing an existing secret is identical. Currently, there is no
confirmation or prompt when replacing an existing secret, so double-check your secret names before
using `SecureStore set`.

### Deleting a secret

If a secret has been revoked or is no longer used, it can be deleted in a similar manner:

```
> SecureStore delete secretName -k secrets.key
```

If `--store STORE` is not used, `SecureStore` will default to a file named `secrets.json` in the
current directory.

If `-p`/`--password` is used instead of `-k`/`--keyfile` (or if neither is used), the user will be
prompted to enter their password before the store is modified. *This isn't technically needed as the
SecureStore secrets file format is not designed to protect against modification of the store itself
(it only protects the secrets inside it), but is required to make sure that you're not inadvertently
deleting a secret from a different secrets file than you intended.*

### Retrieving secrets

The `get` subcommand can be used to retrieve and decrypt a single secret at a time:

```
> SecureStore get secretName
Password: ********
```

Either (or neither) of `-p`/`--password` or `k`/`--keyfile` may be used in conjunction with this
subcommand. If neither is supplied, password mode is implied. `-s`/`--store` may be used to set the
path to the secrets file, default to `secrets.json`.

The only output of `SecureStore get` to `stdout` is the value of the decrypted secret specified by
`secretName`. The `Password: ` prompt and any other output is sent strictly to `stderr`, so it is
safe to use `SecureStore get` in a pipeline.

### Exporting secrets

SecureStore secrets files are intentionally designed to be both strongly defined and portable. It is
possible to use the CLI utility to export a list of all secret names and their associated secret
values, **but this feature should only be used when absolutely necessary and with extreme caution**:

```
> SecureStore get --all -k secrets.key
{
  "aws:s3:password": "mypassword",
  "aws:s3:username": "myusername",
  "secretKey": "secretValue"
}
```

As with all other subcommands, it will default to interactive password mode but a keyfile may be
used instead with `-k`/`--keyfile`, and it will default to decrypting `secrets.json` but an
alternate store may be specified with `-s`/`--store`.

SecureStore can export secrets either as plain text or as json (the default), set via
`--output-format`. As there is no restriction on the name of secrets or their values, it is
recommended to use only the json output mode for programmatic needs, as you can see, it can be
difficult to parse the plain text output:

```
> SecureStore get -a --output-format text
Password: ********
aws:s3:password: mypassword
aws:s3:username: myusername
secretKey: secretValue
```

## Attribution, License, and Copyright

SecureStore was written by Mahmoud Al-Qudsi <mqudsi@neosmart.net> and is developed and maintained by
NeoSmart Technologies. SecureStore and SecureStore.NET are copyrights of NeoSmart Technologies, 2015
- 2020.

SecureStore is released to the general public under the terms of the open source MIT License in the
hopes that it may be useful but without any warranty.
