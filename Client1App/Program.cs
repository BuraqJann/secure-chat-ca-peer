using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Shared;

namespace Client1App
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            const string caIp = "10.0.0.10";
            const int caPort = 5000;

            const string peerIp = "10.0.0.12";
            const int peerPort = 6000;

            using RSA ownRsa = RSA.Create(2048);
            string ownPubBase64 = Convert.ToBase64String(ownRsa.ExportRSAPublicKey());

            Console.WriteLine("[Client1] RSA key pair generated.");

            string ownCertRaw = await RequestCertificateFromCa("Client1", ownPubBase64, caIp, caPort);

            using RSA caRsa = LoadCaPublicRsaOrExit();
            Certificate ownCert = ValidateCertOrExit(ownCertRaw, caRsa, "Client1", ownPubBase64, "Client1");

            Console.WriteLine($"[Client1] Cert OK. ValidUntil={ownCert.NotAfterUtc:O}\n");

            using TcpClient peer = new TcpClient();
            Console.WriteLine("[Client1] Connecting to Client2...");
            await peer.ConnectAsync(peerIp, peerPort);
            using NetworkStream stream = peer.GetStream();

            // Send own cert
            await Framing.SendStringAsync(stream, ownCertRaw);

            // Read peer cert
            string peerCertRaw = await Framing.ReadStringAsync(stream);
            Certificate peerCert = ValidateCertOrExit(peerCertRaw, caRsa, "Client2", null, "Client1(peer)");

            // Send Km encrypted with peer public key
            using RSA peerRsa = RSA.Create();
            peerRsa.ImportRSAPublicKey(Convert.FromBase64String(peerCert.SubjectPublicKeyBase64), out _);

            byte[] km = RandomNumberGenerator.GetBytes(32);
            byte[] encKm = peerRsa.Encrypt(km, RSAEncryptionPadding.OaepSHA256);
            await Framing.SendStringAsync(stream, "KM|" + Convert.ToBase64String(encKm));

            // Derive Ks
            byte[] salt = Crypto.Sha256(Encoding.UTF8.GetBytes($"{ownCert.SerialNumber}|{peerCert.SerialNumber}"));
            byte[] info = Encoding.UTF8.GetBytes("BIM437-AESGCM-SessionKey-v1");
            byte[] ks = Crypto.HkdfSha256(km, salt, info, 32);

            Console.WriteLine("[Client1] Handshake done. Session key Ks (Base64):");
            Console.WriteLine(Convert.ToBase64String(ks));
            Console.WriteLine();

            // Full duplex chat
            string aadOut = "from=Client1;to=Client2;v=1";
            string aadIn  = "from=Client2;to=Client1;v=1";

            using var cts = new CancellationTokenSource();

            var receiveTask = ReceiveLoopAsync(stream, ks, aadIn, cts);
            var sendTask = SendLoopAsync(stream, ks, aadOut, cts);

            Console.WriteLine("Encrypted chat started. You can spam messages now. (/exit to quit)\n");

            await Task.WhenAny(receiveTask, sendTask);
            cts.Cancel();

            try { await Task.WhenAll(receiveTask, sendTask); } catch { /* ignore */ }

            Console.WriteLine("\n[Client1] Closed.");
        }

        private static async Task ReceiveLoopAsync(NetworkStream stream, byte[] ks, string aadIn, CancellationTokenSource cts)
        {
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    string incoming = await Framing.ReadStringAsync(stream, cts.Token);

                    if (incoming == "BYE")
                    {
                        Console.WriteLine("\n[Client1] Peer closed the chat.");
                        cts.Cancel();
                        return;
                    }

                    if (incoming.StartsWith("MSG|"))
                    {
                        string b64 = incoming.Substring(4);
                        try
                        {
                            string plain = Crypto.AesGcmDecryptFromBase64(ks, b64, aadIn);
                            Console.WriteLine($"\nClient2> {plain}");
                            Console.Write("Client1> ");
                        }
                        catch (CryptographicException)
                        {
                            Console.WriteLine("\n[Client1] Decrypt failed (tamper/wrong AAD).");
                            Console.Write("Client1> ");
                        }
                    }
                    else
                    {
                        Console.WriteLine("\n[Client1] Unknown frame: " + incoming);
                        Console.Write("Client1> ");
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine("\n[Client1] ReceiveLoop error: " + ex.Message);
                cts.Cancel();
            }
        }

        private static async Task SendLoopAsync(NetworkStream stream, byte[] ks, string aadOut, CancellationTokenSource cts)
        {
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    Console.Write("Client1> ");
                    string? line = Console.ReadLine();
                    if (line == null) continue;

                    if (line.Trim().Equals("/exit", StringComparison.OrdinalIgnoreCase))
                    {
                        await Framing.SendStringAsync(stream, "BYE");
                        cts.Cancel();
                        return;
                    }

                    string packed = Crypto.AesGcmEncryptToBase64(ks, line, aadOut);
                    await Framing.SendStringAsync(stream, "MSG|" + packed, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine("\n[Client1] SendLoop error: " + ex.Message);
                cts.Cancel();
            }
        }

        private static async Task<string> RequestCertificateFromCa(string subjectId, string pubBase64, string caIp, int caPort)
        {
            using TcpClient client = new TcpClient();
            Console.WriteLine("[Client1] Connecting to CA...");
            await client.ConnectAsync(caIp, caPort);
            using NetworkStream stream = client.GetStream();

            await Framing.SendStringAsync(stream, $"CERT_REQUEST|{subjectId}|{pubBase64}");
            string resp = await Framing.ReadStringAsync(stream);

            if (resp.StartsWith("ERROR|"))
            {
                Console.WriteLine("[Client1] CA error: " + resp);
                Environment.Exit(1);
            }

            return resp;
        }

        private static RSA LoadCaPublicRsaOrExit()
        {
            string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "CAApp", "ca_public.key"));
            if (!File.Exists(path))
            {
                Console.WriteLine("[Client1] CA public key not found. Run CAApp first so ca_public.key is created.");
                Environment.Exit(1);
            }

            string b64 = File.ReadAllText(path).Trim();
            RSA caRsa = RSA.Create();
            caRsa.ImportRSAPublicKey(Convert.FromBase64String(b64), out _);
            return caRsa;
        }

        private static Certificate ValidateCertOrExit(string certRaw, RSA caRsa, string expectedSubject, string? expectedPub, string who)
        {
            if (!Certificate.TryParse(certRaw, out var cert, out var parseErr) || cert == null)
            {
                Console.WriteLine($"[{who}] Cert parse fail: {parseErr}");
                Environment.Exit(1);
            }

            if (!CertValidator.VerifyWithCa(cert, caRsa, out var verifyErr,
                    expectedSubjectId: expectedSubject,
                    expectedPublicKeyBase64: expectedPub))
            {
                Console.WriteLine($"[{who}] Cert verify fail: {verifyErr}");
                Environment.Exit(1);
            }

            return cert;
        }
    }
}
