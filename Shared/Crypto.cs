using System;
using System.Security.Cryptography;
using System.Text;

namespace Shared;

public static class Crypto
{
    public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        using var hmac = new HMACSHA256(salt);
        byte[] prk = hmac.ComputeHash(ikm);

        byte[] okm = new byte[length];
        byte[] t = Array.Empty<byte>();
        int offset = 0;
        byte counter = 1;

        using var hmac2 = new HMACSHA256(prk);
        while (offset < length)
        {
            hmac2.Initialize();
            if (t.Length > 0) hmac2.TransformBlock(t, 0, t.Length, null, 0);
            if (info.Length > 0) hmac2.TransformBlock(info, 0, info.Length, null, 0);
            hmac2.TransformFinalBlock(new[] { counter }, 0, 1);

            t = hmac2.Hash!;
            int take = Math.Min(t.Length, length - offset);
            Buffer.BlockCopy(t, 0, okm, offset, take);

            offset += take;
            counter++;
        }

        return okm;
    }

    // Output: base64(nonce|tag|cipher)
    public static string AesGcmEncryptToBase64(byte[] key32, string plaintext, string aad)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] ct = new byte[pt.Length];
        byte[] tag = new byte[16];
        byte[] aadBytes = Encoding.UTF8.GetBytes(aad);

        using var gcm = new AesGcm(key32, 16);
        gcm.Encrypt(nonce, pt, ct, tag, aadBytes);

        byte[] packed = new byte[12 + 16 + ct.Length];
        Buffer.BlockCopy(nonce, 0, packed, 0, 12);
        Buffer.BlockCopy(tag, 0, packed, 12, 16);
        Buffer.BlockCopy(ct, 0, packed, 28, ct.Length);

        return Convert.ToBase64String(packed);
    }

    public static string AesGcmDecryptFromBase64(byte[] key32, string packedBase64, string aad)
    {
        byte[] packed = Convert.FromBase64String(packedBase64);
        if (packed.Length < 28) throw new CryptographicException("Bad GCM packet.");

        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] ct = new byte[packed.Length - 28];

        Buffer.BlockCopy(packed, 0, nonce, 0, 12);
        Buffer.BlockCopy(packed, 12, tag, 0, 16);
        Buffer.BlockCopy(packed, 28, ct, 0, ct.Length);

        byte[] pt = new byte[ct.Length];
        byte[] aadBytes = Encoding.UTF8.GetBytes(aad);

        using var gcm = new AesGcm(key32, 16);
        gcm.Decrypt(nonce, ct, tag, pt, aadBytes);

        return Encoding.UTF8.GetString(pt);
    }

    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);
}
