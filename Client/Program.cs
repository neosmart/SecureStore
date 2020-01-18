using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Mono.Options;
using System.Security;
using System.Diagnostics;
using System.Reflection;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using System.IO;
using System.Xml;

namespace NeoSmart.SecureStore.Client
{
    static class Program
    {
        static Assembly Assembly = typeof(Program).GetTypeInfo().Assembly;
        static string AssemblyVersion
        {
            get
            {
                var regex = new Regex("Version=(.*?),");
                var fullVersion = regex.Match(Assembly.FullName).Groups[1].Value;
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

        static void Main(string[] mainArgs)
        {
            var args = new List<string>(mainArgs);

            bool help = false;
            bool version = false;
            string path = null;
            string password = null;
            string keyfile = null;
            string secretName = null;
            string secretValue = null;
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
                Console.Out.WriteLine("Copyright NeoSmart Technologies 2017-2020 - https://github.com/neosmart/SecureStore/");
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

            string command = args[commandIndex];
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
                        Environment.Exit(1);
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
                        Environment.Exit(1);
                    }
                }

                // Handle common parameters
                // if (bareArguments.Count > 0)
                // {
                //     Console.Error.Write($"BareArguments[0]: {bareArguments[0]}");
                //     Help(Console.Error, "Invalid arguments!", command, parseOptions);
                // }

                if (string.IsNullOrWhiteSpace(path))
                {
                    Help(Console.Error, "A path to the secrets store is required!", command, parseOptions);
                }

                if (keyfile == null && password == null)
                {
                    Help(Console.Error, "Must specify either --password or --keyfile!", command, parseOptions);
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

                SecretsManager sman = null;

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

                    if (command == "create")
                    {
                        if (File.Exists(path) && new FileInfo(path).Length > 0)
                        {
                            Confirm($"Overwrite existing store at {path}? [yes/no]: ");
                        }
                        if (password == null)
                        {
                            if (File.Exists(keyfile) && new FileInfo(keyfile).Length > 0)
                            {
                                sman.LoadKeyFromFile(keyfile);
                            }
                            else
                            {
                                sman.GenerateKey();
                                sman.ExportKey(keyfile);
                            }
                        }
                        else if (!string.IsNullOrEmpty(keyfile))
                        {
                            sman.ExportKey(keyfile);
                        }
                    }
                    else if (password == null && keyfile != null)
                    {
                        sman.LoadKeyFromFile(keyfile);
                    }

                    var client = new Client(sman);

                    switch (command)
                    {
                        case "create":
                            client.Create();
                            break;
                        case "delete":
                            client.Delete(secretName);
                            break;
                        case "set":
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

        static void Help(TextWriter output, string message, string command, OptionSet options)
        {
            output.WriteLine($"Error: {message}");
            if (options != null)
            {
                output.WriteLine();
                PrintOptions(output, command, options);
            }
            throw new ExitCodeException(1);
        }

        static void PrintOptions(TextWriter output, string cmd, OptionSet options)
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
                switch (Console.ReadLine().ToLower())
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
    }
}
