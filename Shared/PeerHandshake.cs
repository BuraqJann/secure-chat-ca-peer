using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Shared;

public static class PeerHandshake
{
    // ✅ Initiator = Connect yapan taraf (Km üretir)
    public static async Task<(byte[] Ks, Certificate MyCert, Certificate PeerCert)> StartAsInitiatorAsync(
        NetworkStream stream,
        string caIp, int caPort,
        RSA myRsa,
        string myId,
        string expectedPeerId,
        CancellationToken ct)
    {
        // 1) CA pub key yükle
        using RSA caRsa = CaKeyLoader.LoadCaPublicRsaOrThrow();

        // 2) My cert al
        string myPubB64 = Convert.ToBase64String(myRsa.ExportRSAPublicKey());
        string myCertRaw = await RequestCertAsync(caIp, caPort, myId, myPubB64, ct);
        Certificate myCert = ValidateOrThrow(myCertRaw, caRsa, myId, myPubB64, who: myId);

        // 3) Sıraya sadık kal: önce kendi cert gönder, sonra peer cert al
        await Framing.SendStringAsync(stream, myCertRaw, ct);

        string peerCertRaw = await Framing.ReadStringAsync(stream, ct);
        Certificate peerCert = ValidateOrThrow(peerCertRaw, caRsa, expectedPeerId, expectedPub: null, who: $"{myId}(peer)");

        // 4) Km üret -> peer public key ile encrypt -> yolla
        using RSA peerRsa = RSA.Create();
        peerRsa.ImportRSAPublicKey(Convert.FromBase64String(peerCert.SubjectPublicKeyBase64), out _);

        byte[] km = RandomNumberGenerator.GetBytes(32);
        byte[] encKm = peerRsa.Encrypt(km, RSAEncryptionPadding.OaepSHA256);
        await Framing.SendStringAsync(stream, "KM|" + Convert.ToBase64String(encKm), ct);

        // 5) Ks türet (salt order: initiatorSerial|responderSerial)
        byte[] salt = Crypto.Sha256(Encoding.UTF8.GetBytes($"{myCert.SerialNumber}|{peerCert.SerialNumber}"));
        byte[] info = Encoding.UTF8.GetBytes("BIM437-AESGCM-SessionKey-v1");
        byte[] ks = Crypto.HkdfSha256(km, salt, info, 32);

        return (ks, myCert, peerCert);
    }

    // ✅ Responder = Listen yapan taraf (Km alır)
    public static async Task<(byte[] Ks, Certificate MyCert, Certificate PeerCert)> StartAsResponderAsync(
        NetworkStream stream,
        string caIp, int caPort,
        RSA myRsa,
        string myId,
        string expectedPeerId,
        CancellationToken ct)
    {
        using RSA caRsa = CaKeyLoader.LoadCaPublicRsaOrThrow();

        // My cert
        string myPubB64 = Convert.ToBase64String(myRsa.ExportRSAPublicKey());
        string myCertRaw = await RequestCertAsync(caIp, caPort, myId, myPubB64, ct);
        Certificate myCert = ValidateOrThrow(myCertRaw, caRsa, myId, myPubB64, who: myId);

        // Responder sıra: önce peer cert al, sonra kendi cert gönder
        string peerCertRaw = await Framing.ReadStringAsync(stream, ct);
        Certificate peerCert = ValidateOrThrow(peerCertRaw, caRsa, expectedPeerId, expectedPub: null, who: $"{myId}(peer)");

        await Framing.SendStringAsync(stream, myCertRaw, ct);

        // Km al
        string kmMsg = await Framing.ReadStringAsync(stream, ct);
        if (!kmMsg.StartsWith("KM|"))
            throw new InvalidOperationException($"Expected KM message, got: {kmMsg}");

        byte[] encKm = Convert.FromBase64String(kmMsg.Substring(3));
        byte[] km = myRsa.Decrypt(encKm, RSAEncryptionPadding.OaepSHA256);

        // Ks türet (salt order: initiatorSerial|responderSerial) => responder: peerSerial|mySerial
        byte[] salt = Crypto.Sha256(Encoding.UTF8.GetBytes($"{peerCert.SerialNumber}|{myCert.SerialNumber}"));
        byte[] info = Encoding.UTF8.GetBytes("BIM437-AESGCM-SessionKey-v1");
        byte[] ks = Crypto.HkdfSha256(km, salt, info, 32);

        return (ks, myCert, peerCert);
    }

    private static async Task<string> RequestCertAsync(string caIp, int caPort, string subjectId, string pubB64, CancellationToken ct)
    {
        using TcpClient client = new TcpClient();
        await client.ConnectAsync(caIp, caPort, ct);
        using NetworkStream s = client.GetStream();

        await Framing.SendStringAsync(s, $"CERT_REQUEST|{subjectId}|{pubB64}", ct);
        string resp = await Framing.ReadStringAsync(s, ct);

        if (resp.StartsWith("ERROR|"))
            throw new InvalidOperationException("CA error: " + resp);

        return resp;
    }

    private static Certificate ValidateOrThrow(string certRaw, RSA caRsa, string expectedSubject, string? expectedPub, string who)
    {
        if (!Certificate.TryParse(certRaw, out var cert, out var parseErr) || cert == null)
            throw new InvalidOperationException($"[{who}] Cert parse fail: {parseErr}");

        if (!CertValidator.VerifyWithCa(cert, caRsa, out var verifyErr,
                expectedSubjectId: expectedSubject,
                expectedPublicKeyBase64: expectedPub))
            throw new InvalidOperationException($"[{who}] Cert verify fail: {verifyErr}");

        return cert;
    }
}
