using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NeoSmart.SecureStore
{
    internal abstract class PemWrapper
    {
        public string Header { get; set; } = "-----BEGIN PRIVATE KEY-----";
        public string Trailer { get; set; } = "-----END PRIVATE KEY-----";
    }

    /// <summary>
    /// Reads ASCII-Armored base64 files.
    /// </summary>
    internal class PemReader : PemWrapper
    {
        enum ParseState
        {
            WaitingStart,
            WaitingEnd,
            Complete,
        }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
        private async Task<byte[]> InnerReadAsync(Stream stream, Func<StreamReader, ValueTask<string?>> lineReader)
#else
        private async Task<byte[]> InnerReadAsync(Stream stream, Func<StreamReader, Task<string?>> lineReader)
#endif
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, true, 1024, leaveOpen: true);
            ParseState state = ParseState.WaitingStart;
            var base64 = new StringBuilder();
            string? line;
            while ((line = await lineReader(reader)) is not null)
            {
                line = line.Trim();

                if (state == ParseState.WaitingStart)
                {
                    if (string.Compare(line, Header, StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        state = ParseState.WaitingEnd;
                    }
                    continue;
                }
                else if (string.Compare(line, Trailer, StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    state = ParseState.Complete;
                    break;
                }

                base64.Append(line);
            }

            if (state != ParseState.Complete)
            {
                throw new InvalidKeyFileException("Could not read PEM-encoded key file!");
            }

            return Convert.FromBase64String(base64.ToString());
        }

        public async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancel = default)
        {
#if NET6_0_OR_GREATER
            return await InnerReadAsync(stream, async (reader) => await reader.ReadLineAsync().WaitAsync(cancel));
#else
            return await InnerReadAsync(stream, async (reader) => await reader.ReadLineAsync());
#endif
        }

        public byte[] Read(Stream stream)
        {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
            return InnerReadAsync(stream, reader => new ValueTask<string?>(reader.ReadLine())).Result;
#else
            return InnerReadAsync(stream, reader => Task.FromResult<string?>(reader.ReadLine())).Result;
#endif
        }
    }

    /// <summary>
    /// Writes ASCII-Armored base64 files.
    /// </summary>
    internal class PemWriter : PemWrapper
    {
        enum ParseState
        {
            WaitingStart,
            WaitingEnd,
            Complete,
        }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
        private async Task InnerWriteAsync(Stream stream, ReadOnlyMemory<byte> data, Func<StreamWriter, ReadOnlyMemory<char>, ValueTask> lineWriter)
#else
        private async Task InnerWriteAsync(Stream stream, ReadOnlyMemory<byte> data, Func<StreamWriter, ReadOnlyMemory<char>, Task> lineWriter)
#endif
        {
            using var writer = new StreamWriter(stream, new UTF8Encoding(false), bufferSize: 1024, leaveOpen: true);

            // Write the header
            await lineWriter(writer, Header.AsMemory());

            // Format the body as base64 with a maximum of 64 characters per line.
            // If we ask .NET to insert line breaks, it'll add one after each 76th character but we want after every 64th character
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
            var encoded = Convert.ToBase64String(data.Span, Base64FormattingOptions.None);
#else
            var encoded = Convert.ToBase64String(data.ToArray(), Base64FormattingOptions.None);
#endif

            for (int i = 0; i < encoded.Length; i += 64)
            {
                var line = encoded.AsMemory(i, Math.Min(64, encoded.Length - i));
                await lineWriter(writer, line);
            }

            // Write the trailer
            await lineWriter(writer, Trailer.AsMemory());
        }

        public async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> data, CancellationToken cancel = default)
        {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
            await InnerWriteAsync(stream, data, async (writer, line) => await writer.WriteLineAsync(line, cancel));
#else
            await InnerWriteAsync(stream, data, async (writer, line) => await writer.WriteLineAsync(line.ToString()));
#endif
        }

        public void Write(Stream stream, ReadOnlyMemory<byte> data)
        {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP2_1_OR_GREATER
            _ = InnerWriteAsync(stream, data, (writer, line) => { writer.WriteLine(line); return new ValueTask(); });
#else
            _ = InnerWriteAsync(stream, data, (writer, line) => { writer.WriteLine(line.ToString()); return Task.CompletedTask; });
#endif
        }
    }
}
