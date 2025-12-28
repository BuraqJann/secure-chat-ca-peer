using System;
using System.Buffers.Binary;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Shared;

public static class Framing
{
    public static async Task SendStringAsync(NetworkStream stream, string message, CancellationToken ct = default)
    {
        byte[] payload = Encoding.UTF8.GetBytes(message);
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, payload.Length);

        await stream.WriteAsync(header, 0, 4, ct);
        await stream.WriteAsync(payload, 0, payload.Length, ct);
        await stream.FlushAsync(ct);
    }

    public static async Task<string> ReadStringAsync(NetworkStream stream, CancellationToken ct = default)
    {
        byte[] header = await ReadExactAsync(stream, 4, ct);
        int len = BinaryPrimitives.ReadInt32BigEndian(header);
        if (len < 0 || len > 10_000_000) throw new InvalidDataException("Invalid frame length.");

        byte[] payload = await ReadExactAsync(stream, len, ct);
        return Encoding.UTF8.GetString(payload);
    }

    private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int size, CancellationToken ct)
    {
        byte[] buf = new byte[size];
        int off = 0;

        while (off < size)
        {
            int r = await stream.ReadAsync(buf, off, size - off, ct);
            if (r == 0) throw new IOException("Socket closed.");
            off += r;
        }

        return buf;
    }
}
