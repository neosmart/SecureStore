using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Mono.Options;
using System.Reflection;
using System.Text.RegularExpressions;
using System.IO;
using System.Threading.Tasks;
using System.Diagnostics.CodeAnalysis;

namespace NeoSmart.SecureStore.Client
{
    static class Program
    {
        /// <summary>
        /// The maximum number of levels to test when checking if a path is under VCS control.
        /// </summary>
        const int MAX_VCS_CHECK_DEPTH = 48;

        static readonly Assembly Assembly = typeof(Program).GetTypeInfo().Assembly;
        static string AssemblyVersion
        {
            get
            {
                var regex = new Regex("Version=(.*?),");
                var fullVersion = regex.Match(Assembly.FullName!).Groups[1].Value;
                while (fullVersion.EndsWith(".0") && fullVersion.Length > "1.0".Length)
                {
                    fullVersion = fullVersion.Substring(0, fullVersion.Length - 2);
                }

                return fullVersion;
            }
        }

        private static bool Parse(string value, out DecryptFormat format)
        {
            switch (value)
            {
                case "json":
                    format = DecryptFormat.Json;
                    return true;
                case "text":
                    format = DecryptFormat.PlainText;
                    return true;
                default:
                    format = DecryptFormat.None;
                    return false;
            }
        }

        enum CliMode
        {
            None,
            Help,
            Version,
            Create,
            Get,
            Set,
            Delete,
        }

        enum VcsType
        {
            None,
            Git,
        }

        /// <summary>
        /// Checks the path and its parent directories to determine if it is under VCS control.
        /// </summary>
        /// <param name="path">The path to check if managed by VCS.</param>
        /// <returns>The <see cref="VcsType"/> managing the <paramref name="path"/>, or <see cref="VcsType.None"/>.</returns>
        private static VcsType GetVcsType(string path, int maxParents = MAX_VCS_CHECK_DEPTH)
        {
            var vcsPatterns = new[] { (Vcs: VcsType.Git, Path: ".git") };

            var parent = Path.GetDirectoryName(Path.GetFullPath(path));
            for (int i = 0; !string.IsNullOrEmpty(parent) && i < maxParents; ++i)
            {
                foreach (var vcs in vcsPatterns)
                {
                    var vcsPath = Path.Join(parent, vcs.Path);
                    if (Directory.Exists(vcsPath))
                    {
                        return vcs.Vcs;
                    }
                }

                parent = Path.GetDirectoryName(parent);
            }

            return VcsType.None;
        }

        /// <summary>
        /// Add's a VCS ignore rule for the path <paramref name="path"/> in the ignore file <paramref name="ignoreFile"/>
        /// according to the conventions of the VCS <paramref name="vcs"/>.
        /// </summary>
        /// <param name="vcs"></param>
        /// <param name="path"></param>
        /// <returns></returns>
        private async static Task<bool> AddIgnoreRuleAsync(VcsType vcs, string path, string ignoreFileDir)
        {
            var ignoreFile = vcs switch
            {
                VcsType.Git => Path.Combine(ignoreFileDir, ".gitignore"),
                _ => throw new NotImplementedException("Support for this VCS is not yet implemented!"),
            };

            if (Path.GetDirectoryName(ignoreFile) != Path.GetDirectoryName(path))
            {
                throw new InvalidOperationException("Only ignore files in the same directory as the path to ignore are currently supported!");
            }
            if (!File.Exists(path))
            {
                throw new InvalidOperationException($"The file to ignore \"{path}\" is not a regular file!");
            }
            if (File.Exists(ignoreFile) && ((File.GetAttributes(ignoreFile) & (FileAttributes.Directory | FileAttributes.ReadOnly | FileAttributes.Device)) != 0))
            {
                throw new InvalidOperationException($"The ignore file \"{ignoreFile}\" exists and is not a regular file!");
            }

            var ignoreFileStatus = "existing";
            var filename = Path.GetFileName(path);
            var extension = Path.GetExtension(path);

            if (!File.Exists(ignoreFile))
            {
                File.Create(ignoreFile).Dispose();
                ignoreFileStatus = "newly-created";
            }

            // This is a valid exclude rule even if extension is empty
            var wildcardExclude = $"*{extension}";

            using (var reader = new StreamReader(File.Open(ignoreFile, FileMode.Open, FileAccess.Read, FileShare.Read)))
            {
                string? line;
                while ((line = await reader.ReadLineAsync()) != null)
                {
                    // Since we are excluding a file in the same directory, both /foo and foo will match
                    line = line.TrimStart('/').TrimEnd();
                    if (line == filename || line == wildcardExclude)
                    {
                        // The path is already excluded
                        return true;
                    }
                }
            }

            using (var writer = new StreamWriter(File.Open(ignoreFile, FileMode.Append, FileAccess.Write, FileShare.None)))
            {
                await writer.WriteLineAsync("# SecureStore key file ignore rule:");
                await writer.WriteLineAsync($"/{filename}");
            }

            await Console.Error.WriteLineAsync($"Excluding key file in {ignoreFileStatus} VCS ignore file {ignoreFile}");

            return true;
        }

        static async Task Main(string[] mainArgs)
        {
            // Tweak the default VaultVersionPolicy to allow upgrades when the CLI is used to interface
            // with the vault (by default, silent upgrades across major vault versions are prohibited to
            // protect against schema downgrade attacks).
            SecretsManager.VaultVersionPolicy = Versioning.VaultVersionPolicy.Upgrade;

            var args = new List<string>(mainArgs);

            bool help = false;
            bool version = false;
            string? path = null;
            string? password = null;
            string? keyfile = null;
            string? secretName = null;
            string? secretValue = null;
            bool decryptAll = false;
            DecryptFormat format = DecryptFormat.None;

            var globalOptions = new OptionSet
            {
                { "h|help|?", "Show this help message and exit", _ => help = true },
                { "v|version", "Print version information and exit", _ => version = true },
                { "s|store=", "Load secrets store from provided path", s => path = s },
                { "p|password:", "Prompt for decryption password", p => password = p ?? "" },
                { "k|keyfile=", "Load decryption key from path", k => keyfile = k },
            };

            var options = new Dictionary<string, OptionSet>();
            options["create"] = new OptionSet
            {
                { "h|help", "Show help for create command options", _ => help = true },
                // password is : because automated systems may use the command line to specify passwords. This may change!
                { "p|password:", "Secure store with a key derived from a password", p => password = p ?? "" },
                { "k|keyfile=", "Path to load or save secure key from/to", k => keyfile = k },
            };

            options["delete"] = new OptionSet
            {
                { "h|help", "Show help for delete command options", _ => help = true },
                { "s|store=", "Load secrets store from provided path", s => path = s },
                // password is : because automated systems may use the command line to specify passwords. This may change!
                { "p|password:", "Decrypt store with key derived from password", p => password = p ?? "" },
                { "k|keyfile=", "Path to load secure key from", k => keyfile = k },
            };

            options["get"] = new OptionSet
            {
                { "h|help", "Show help for decryption command options", _ => help = true },
                { "s|store=", "Load secrets store from provided path", s => path = s },
                // password is : because automated systems may use the command line to specify passwords. This may change!
                { "p|password:", "Decrypt store with key derived from password", p => password = p ?? "" },
                { "k|keyfile=", "Path to load secure key from", k => keyfile = k },
                { "a|all", "Decrypt the entire contents of the store and print to stdout", _ => decryptAll = true },
                { "t|output-format=", "Specify the output format: json (default), text", t => { if (!Parse(t, out format)) throw new ExitCodeException(1, "Unsupported format specified!"); } }
            };

            options["set"] = new OptionSet
            {
                { "h|help", "Show help for encryption command options", _ => help = true },
                { "s|store=", "Load secrets store from provided path", s => path = s },
                // password is : because automated systems may use the command line to specify passwords. This may change!
                { "p|password:", "Decrypt store with key derived from password", p => password = p ?? "" },
                { "k|keyfile=", "Path to load secure key from", k => keyfile = k },
            };

            void printUsage(TextWriter output)
            {
                output.WriteLine($"ssclient [FLAGS] [create|set|get|delete] OPTIONS");
                PrintOptions(output, null, globalOptions);
                output.WriteLine();

                foreach (var kv in options) {
                    PrintOptions(output, kv.Key, kv.Value);
                }
            }

            if (args.Count == 0)
            {
                Console.Out.Write("Usage: ");
                printUsage(Console.Out);
                Environment.Exit(1);
            }

            // Only try to parse --help and --version
            globalOptions.Parse(args);

            void printVersion()
            {
                Console.Out.WriteLine($"ssclient {AssemblyVersion} - SecureStore secrets manager client");
                Console.Out.WriteLine("Copyright NeoSmart Technologies 2017-2022 - https://github.com/neosmart/SecureStore/");
            }

            if (help)
            {
                printVersion();
                Console.Out.WriteLine();
                Console.Out.Write("Usage: ");
                printUsage(Console.Out);

                Environment.Exit(0);
            }

            if (version)
            {
                printVersion();
                Environment.Exit(0);
            }

            int commandIndex = args.FindIndex(arg => options.ContainsKey(arg));
            if (commandIndex < 0)
            {
                printUsage(Console.Error);
                Environment.Exit(1);
            }

            string command = args[commandIndex].ToLower();
            args.RemoveAt(commandIndex);
            OptionSet parseOptions = options[command];

            int exitCode = 0;
            try
            {
                // Mono.Options is dumb and does not treat --password PASSWORD
                // as an option:value tuple when password is defined as taking an optional value.
                // It instead requires --password=PASSWORD or --password:PASSWORD or -pPASSWORD
                var bareArguments = parseOptions.Parse(args);

                if (bareArguments.Count > 0 && password == string.Empty)
                {
                    // Check if this was the standalone password
                    var possibles = new[] { "-p", "--password", "/p", "/password" };

                    for (int i = 0; i < args.Count - 1; ++i)
                    {
                        if (!possibles.Contains(args[i]))
                        {
                            continue;
                        }

                        // This was the password index
                        var bareIndex = bareArguments.FindIndex(arg => arg == args[i + 1]);
                        if (bareIndex >= 0)
                        {
                            password = bareArguments[bareIndex];
                            bareArguments.RemoveAt(bareIndex);
                            break;
                        }
                    }
                }

                // Consume remaining bare parameters before carrying out any actions so we can validate
                // there are no unexpected bare parameters.
                if (command == "create")
                {
                    if (bareArguments.Count > 0 && string.IsNullOrEmpty(path))
                    {
                        path = bareArguments[0];
                        bareArguments.RemoveAt(0);
                    }
                }
                else if (command == "get" || command == "delete")
                {
                    if (!decryptAll && bareArguments.Count != 1)
                    {
                        Console.Error.WriteLine("Expected the name of a single secret to look up or delete!");
                        throw new ExitCodeException(1);
                    }
                    else if (!decryptAll)
                    {
                        secretName = bareArguments[0];
                        bareArguments.RemoveAt(0);
                    }
                }
                else if (command == "set")
                {
                    if (bareArguments.Count == 1 && bareArguments[0].Contains('='))
                    {
                        var parts = bareArguments[0].Split('=', 2);
                        secretName = parts[0];
                        secretValue = parts[1];
                        bareArguments.RemoveAt(0);
                    }
                    else if (bareArguments.Count == 2 && !bareArguments[1].Contains('='))
                    {
                        secretName = bareArguments[0];
                        secretValue = bareArguments[1];
                        bareArguments.RemoveRange(0, 2);
                    }
                    else
                    {
                        Console.Error.WriteLine("Expected a single \"key=value\" or \"key\" \"value\" to set!");
                        throw new ExitCodeException(1);
                    }
                }

                // Handle common parameters
                // if (bareArguments.Count > 0)
                // {
                //     Console.Error.Write($"BareArguments[0]: {bareArguments[0]}");
                //     Help(Console.Error, "Invalid arguments!", command, parseOptions);
                // }

                if (path is null)
                {
                    // Help(Console.Error, "A path to the secrets store is required!", command, parseOptions);

                    // Default to secrets.json rather than error out
                    path = "secrets.json";
                }

                if (string.IsNullOrWhiteSpace(path))
                {
                    Help(Console.Error, "A path to the secrets store is required!", command, parseOptions);
                }

                if (keyfile == null && password == null)
                {
                    // Help(Console.Error, "Must specify either --password or --keyfile!", command, parseOptions);

                    // Default to password mode instead of erroring out
                    password = string.Empty;
                }

                // We need to differentiate between null (not set) and empty (empty)
                if (password == string.Empty)
                {
                    if (command == "create")
                    {
                        while (string.IsNullOrWhiteSpace(password))
                        {
                            Console.Write("New password: ");
                            var password1 = GetPassword();
                            Console.Write("Confirm password: ");
                            var password2 = GetPassword();
                            if (password1 == password2)
                            {
                                password = password1;
                            }
                        }
                    }
                    else
                    {
                        while (string.IsNullOrWhiteSpace(password))
                        {
                            Console.Write("Password: ");
                            password = GetPassword();
                        }
                    }
                }

                SecretsManager? sman = null;

                // Handle parameters specific to certain commands
                if (command == "create")
                {
                    if (password is null && string.IsNullOrWhiteSpace(keyfile))
                    {
                        Console.Error.WriteLine("A newly created store must have one or both of --password and --keyfile specified");
                        Environment.Exit(1);
                    }
                    if (!string.IsNullOrWhiteSpace(password) && File.Exists(keyfile)
                        && new FileInfo(keyfile).Length > 0)
                    {
                        Confirm($"Overwrite the existing contents of the key file at {keyfile} " +
                            "with a key derived from the provided password? [yes/no]: ");
                    }
                    sman = SecretsManager.CreateStore();
                }
                else
                {
                    if (command == "get")
                    {
                        if (decryptAll && !string.IsNullOrWhiteSpace(secretName))
                        {
                            Help(Console.Error, "Either --all or KEY must be specified as an argument to decrypt (not both)!", command, parseOptions);
                        }
                    }

                    sman = SecretsManager.LoadStore(path);
                }

                using (sman)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        sman.LoadKeyFromPassword(password);
                    }

                    bool keyCreated = false;
                    if (command == "create")
                    {
                        if (File.Exists(path) && new FileInfo(path).Length > 0)
                        {
                            Confirm($"Overwrite existing store at {path}? [yes/no]: ");
                        }
                        if (password == null)
                        {
                            ExitIfNullOrEmpty(keyfile, "A keyfile path is required if no password is provided");

                            if (File.Exists(keyfile) && new FileInfo(keyfile).Length > 0)
                            {
                                sman.LoadKeyFromFile(keyfile);
                            }
                            else
                            {
                                sman.GenerateKey();
                                sman.ExportKey(keyfile);
                                keyCreated = true;
                            }
                        }
                        else if (!string.IsNullOrEmpty(keyfile))
                        {
                            sman.ExportKey(keyfile);
                            keyCreated = true;
                        }
                    }
                    else if (password == null && keyfile != null)
                    {
                        sman.LoadKeyFromFile(keyfile);
                    }

                    if (keyCreated)
                    {
                        var vcsType = GetVcsType(keyfile!);
                        if (vcsType != VcsType.None)
                        {
                            await AddIgnoreRuleAsync(vcsType, keyfile!, Path.GetDirectoryName(keyfile)!);
                        }
                    }

                    var client = new Client(sman);

                    switch (command)
                    {
                        case "create":
                            client.Create();
                            break;
                        case "delete":
                            if (string.IsNullOrEmpty(secretName))
                            {
                                Help(Console.Error, "The name of the secret to delete is required", command, parseOptions);
                            }

                            client.Delete(secretName);
                            break;
                        case "set":
                            if (string.IsNullOrEmpty(secretName))
                            {
                                Help(Console.Error, "The name of the secret to set or update is required", command, parseOptions);
                            }
                            if (string.IsNullOrEmpty(secretValue))
                            {
                                Help(Console.Error, "The value of the secret to set or update is required", command, parseOptions);
                            }

                            client.Update(secretName, secretValue);
                            break;
                        case "get":
                            if (!decryptAll)
                            {
                                if (format != DecryptFormat.None)
                                {
                                    Help(Console.Error, "--format can only be used in conjunction with --all!",
                                        command, parseOptions);
                                }

                                if (string.IsNullOrEmpty(secretName))
                                {
                                    Help(Console.Error, "The name of the secret to retrieve is required", command, parseOptions);
                                }

                                client.Decrypt(secretName);
                            }
                            else
                            {
                                client.DecryptAll(format);
                            }
                            break;
                        default:
                            throw new NotImplementedException($"Case {command} not handled!");
                    }

                    sman.SaveStore(path);
                }
            }
            catch (OptionException ex)
            {
                Console.WriteLine(ex.Message);
                exitCode = 1;
            }
            catch (ExitCodeException ex)
            {
                if (!string.IsNullOrWhiteSpace(ex.Message))
                {
                    Console.WriteLine(ex.Message);
                }
                exitCode = ex.ExitCode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                exitCode = 1;
            }

            Environment.Exit(exitCode);
        }

        [DoesNotReturn]
        static void Help(TextWriter output, string message, string? command = null, OptionSet? options = null)
        {
            output.WriteLine($"Error: {message}");
            if (command != null && options != null)
            {
                output.WriteLine();
                PrintOptions(output, command, options);
            }
            throw new ExitCodeException(1);
        }

        static void PrintOptions(TextWriter output, string? cmd, OptionSet options)
        {
            if (cmd != null)
            {
                output.WriteLine($"{cmd} options:");
            }
            foreach (var option in options)
            {
                output.WriteLine($"\t-{option.GetNames()[0]}  --{option.GetNames()[1]}\t{option.Description}");
            }
        }

        static void Confirm(string message)
        {
            while (true)
            {
                Console.Error.Write(message);
                switch (Console.ReadLine()?.ToLower())
                {
                    case "yes": return;
                    case "no": throw new ExitCodeException(1);
                    default: continue;
                }
            }
        }

        public static string GetPassword()
        {
            var password = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            return password.ToString();
        }

        public static void ExitIfNullOrEmpty([NotNull] this string? s, string message)
        {
            if (string.IsNullOrEmpty(s))
            {
                Help(Console.Error, message);
            }
        }
    }
}
