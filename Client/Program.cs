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

        static void Main(string[] args)
        {
            var argv = args;
            int argc = args.Length;

            string path = null;
            string password = null;
            string keyfile = null;
            bool delete = false;
            string key = null;
            string value = null;
            bool decryptAll = false;
            bool generate = false;
            DecryptFormat format = DecryptFormat.None;

            OptionSet globalOptions;

            var createOptions = new OptionSet
            {
                { "s|store=", "Path to the secrets store to be created", s => path = s },
                { "p|password:", "Secure the store with a key derived from a password (optionally provided in the command line)", p => password = p ?? "" },
                { "f|keyfile=", "Secure the store with a randomly generated key, created at the provided path", f => keyfile = f },
                { "g|generate", "Generate a new key and save it to the path specified by --keyfile", g => generate = g != null },
            };

            var updateOptions = new OptionSet
            {
                { "s|store=", "Path to the secrets store to be loaded", s => path = s },
                { "p|password:", "Decrypt the store with a key derived from a password (optionally provided in the command line)", p => password = p ?? "" },
                { "f|keyfile=", "Decrypt the store with a keyfile, located at the provided path", f => keyfile = f },
                { "k|key=", "The (new or existing) key of the (key, value) tuple to create or update", k => key = k },
                { "v|value=", "The (new) value of the (key, value) tuple to create or update", v => value = v },
                { "d|delete=", "The existing key of the (key, value) tuple to delete", k => {key = k; delete = true; } },
            };

            var decryptOptions = new OptionSet
            {
                { "s|store=", "Path to the secrets store to be loaded", s => path = s },
                { "p|password:", "Decrypt the store with a key derived from a password (optionally provided in the command line)", p => password = p ?? "" },
                { "f|keyfile=", "Decrypt the store with a keyfile, located at the provided path", f => keyfile = f },
                { "k|key=", "The (new or existing) key of the (key, value) tuple to create or update", k => key = k },
                { "a|all", "Decrypt the entire contents of the store and print to stdout", a => decryptAll = a != null },
                { "t|format=", "Specify the output format: json (default), text", t => { if (!Parse(t, out format)) throw new ExitCodeException(1, "Unsupported format specified!"); } }
            };

            void printUsage()
            {
                Console.WriteLine($"ssclient [OPTIONS | [create|update|decrypt] OPTIONS]");
                PrintOptions(null, globalOptions);
                Console.WriteLine();
                PrintOptions("create", createOptions);
                PrintOptions("update", updateOptions);
                PrintOptions("decrypt", decryptOptions);
            }

            bool help = false;
            bool version = false;
            globalOptions = new OptionSet
            {
                { "h|help|?", "Show this help message and exit", h => help = true },
                { "v|version", "Print version information and exit", h => version = true },
            };

            if (args.Length == 0)
            {
                Console.Write("Usage: ");
                printUsage();
                Environment.Exit(1);
            }

            //only try to parse --help and --version
            globalOptions.Parse(new[] { args[0] });

            void printVersion()
            {
                Console.WriteLine($"ssclient {AssemblyVersion} - SecureStore secrets manager client");
                Console.WriteLine("Copyright NeoSmart Technologies 2017 - https://github.com/neosmart/SecureStore/");
            }

            if (help)
            {
                printVersion();
                Console.WriteLine();
                Console.Write("Usage: ");
                printUsage();

                Environment.Exit(0);
            }

            if (version)
            {
                printVersion();
                Environment.Exit(0);
            }

            string command = args[0];
            OptionSet options = null;

            switch (command)
            {
                case "create":
                    options = createOptions;
                    break;
                case "update":
                    options = updateOptions;
                    break;
                case "decrypt":
                    options = decryptOptions;
                    break;
                default:
                    Console.WriteLine($"{command}: unsupported command!");
                    Console.WriteLine();
                    printUsage();
                    Environment.Exit(1);
                    break;
            }

            int exitCode = 0;
            try
            {
                //we have no trailing parameters, but Mono.Options is dumb and does not treat --password PASSWORD
                //as an option:value tuple when password is defined as taking an optional value.
                //It instead requires --password=PASSWORD or --password:PASSWORD or -pPASSWORD
                var bareArguments = options.Parse(args.Skip(1));

                bool standalonePassword = false;
                if (bareArguments.Count == 1 && password == "")
                {
                    //check if this was the standalone password
                    var possibles = new[] { "-p", "--password", "/p", "/password" };

                    for (int i = 1; i < argc; ++i)
                    {
                        if (!possibles.Contains(argv[i]))
                        {
                            continue;
                        }

                        //this was the password index
                        if (argc > i + 1 && argv[i + 1] == bareArguments[0])
                        {
                            password = bareArguments[0];
                            standalonePassword = true;
                        }

                        break;
                    }
                }

                //Handle common parameters
                if (!standalonePassword && bareArguments.Count > 0)
                {
                    Help("Invalid arguments!", command, options);
                }

                if (string.IsNullOrWhiteSpace(path))
                {
                    Help("A path to the secrets store is required!", command, options);
                }

                if (keyfile != null && password != null)
                {
                    Help("Cannot specify both --password and --keyfile", command, options);
                }

                if (keyfile == null && password == null)
                {
                    Help("Must specify either --password or --keyfile!", command, options);
                }

                if (password == "")
                {
                    Console.Write("Password: ");
                    password = GetPassword();
                }

                SecretsManager sman = null;

                //Handle parameters specific to certain commands
                if (command == "create")
                {
                    if (generate && keyfile == null)
                    {
                        Help("--generate requires a path specified by --keyfile to export the newly created key to!", command, options);
                    }
                    sman = SecretsManager.CreateStore();
                }
                else
                {
                    if (command == "update")
                    {
                        if (delete && (key != null && value != null))
                        {
                            Help("Cannot specify both --delete and --key or --value!", command, options);
                        }
                        else if (!delete && (key == null || value == null))
                        {
                            Help("Must specify both --key and --value to update!", command, options);
                        }
                    }
                    else if (command == "decrypt")
                    {
                        if (!decryptAll && string.IsNullOrWhiteSpace(key))
                        {
                            Help("Either --all or --key KEY must be specified as an argument to decrypt!", command, options);
                        }
                    }

                    sman = SecretsManager.LoadStore(path);
                }

                using (sman)
                {
                    if (generate)
                    {
                        sman.GenerateKey();
                        sman.ExportKey(keyfile);
                    }
                    else if (keyfile != null)
                    {
                        sman.LoadKeyFromFile(keyfile);
                    }
                    else
                    {
                        sman.LoadKeyFromPassword(password);
                    }

                    var client = new Client(sman);

                    switch (command)
                    {
                        case "create":
                            client.Create();
                            break;
                        case "update":
                            if (delete)
                            {
                                client.Delete(key);
                            }
                            else
                            {
                                client.Update(key, value);
                            }
                            break;
                        case "decrypt":
                            if (!decryptAll)
                            {
                                if (format != DecryptFormat.None)
                                {
                                    Help($"--format can only be used in conjunction with --all!", command, options);
                                }

                                client.Decrypt(key);
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

        static void Help(string message, string command, OptionSet options)
        {
            Console.WriteLine($"Error: {message}");
            if (options != null)
            {
                Console.WriteLine();
                PrintOptions(command, options);
            }
            throw new ExitCodeException(1);
        }

        static void PrintOptions(string cmd, OptionSet options)
        {
            if (cmd != null)
            {
                Console.WriteLine($"{cmd} options:");
            }
            foreach (var option in options)
            {
                Console.WriteLine($"\t-{option.GetNames()[0]}  --{option.GetNames()[1]}\t{option.Description}");
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
