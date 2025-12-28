using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Shared
{
    public sealed class SecureChatSession : IAsyncDisposable
    {
        private TcpClient? _tcp;
        private TcpListener? _listener;
        private NetworkStream? _stream;

        private RSA? _ownRsa;
        private RSA? _caRsa;

        private Certificate? _ownCert;
        private Certificate? _peerCert;

        private byte[]? _ks;

        private CancellationTokenSource? _cts;
        private Task? _rxTask;

        private string _aadOut = "";
        private string _aadIn = "";

        public bool IsSecure => _ks != null;

        public event Action<string>? Status;
        public event Action<string>? Error;
        public event Action<string, string>? MessageReceived; // (from, msg)
        public event Action? Disconnected;

        // -------------------------
        // Role: Client1 (connector)
        // -------------------------
        public async Task StartAsClient1Async(string caIp, int caPort, string peerIp, int peerPort, string selfId = "Client1")
        {
            if (_cts != null) throw new InvalidOperationException("Session already started.");

            Status?.Invoke("Generating RSA key pair...");
            _ownRsa = RSA.Create(2048);
            string ownPubB64 = Convert.ToBase64String(_ownRsa.ExportRSAPublicKey());

            Status?.Invoke("Requesting certificate from CA...");
            string ownCertRaw = await RequestCertificateFromCaAsync(selfId, ownPubB64, caIp, caPort);

            _caRsa = LoadCaPublicRsaOrThrow();
            _ownCert = ValidateCertOrThrow(ownCertRaw, _caRsa, expectedSubject: selfId, expectedPub: ownPubB64, who: selfId);

            Status?.Invoke($"Certificate OK (ValidUntil={_ownCert.NotAfterUtc:O})");
            Status?.Invoke("Connecting to peer...");

            _tcp = new TcpClient();
            await _tcp.ConnectAsync(peerIp, peerPort);
            _stream = _tcp.GetStream();

            // Send own cert
            await Framing.SendStringAsync(_stream, ownCertRaw);

            // Read peer cert
            string peerCertRaw = await Framing.ReadStringAsync(_stream);
            _peerCert = ValidateCertOrThrow(peerCertRaw, _caRsa, expectedSubject: "Client2", expectedPub: null, who: "peer");

            // Send Km encrypted with peer public key
            using RSA peerRsa = RSA.Create();
            peerRsa.ImportRSAPublicKey(Convert.FromBase64String(_peerCert.SubjectPublicKeyBase64), out _);

            byte[] km = RandomNumberGenerator.GetBytes(32);
            byte[] encKm = peerRsa.Encrypt(km, RSAEncryptionPadding.OaepSHA256);
            await Framing.SendStringAsync(_stream, "KM|" + Convert.ToBase64String(encKm));

            // Derive Ks
            byte[] salt = Crypto.Sha256(Encoding.UTF8.GetBytes($"{_ownCert.SerialNumber}|{_peerCert.SerialNumber}"));
            byte[] info = Encoding.UTF8.GetBytes("BIM437-AESGCM-SessionKey-v1");
            _ks = Crypto.HkdfSha256(km, salt, info, 32);

            _aadOut = "from=Client1;to=Client2;v=1";
            _aadIn  = "from=Client2;to=Client1;v=1";

            StartRxLoop(fromName: "Client2");
            Status?.Invoke("🔒 Secure channel established.");
        }

        // ------------------------
        // Role: Client2 (listener)
        // ------------------------
        public async Task StartAsClient2Async(string caIp, int caPort, string listenIp, int listenPort, string selfId = "Client2")
        {
            if (_cts != null) throw new InvalidOperationException("Session already started.");

            Status?.Invoke("Generating RSA key pair...");
            _ownRsa = RSA.Create(2048);
            string ownPubB64 = Convert.ToBase64String(_ownRsa.ExportRSAPublicKey());

            Status?.Invoke("Requesting certificate from CA...");
            string ownCertRaw = await RequestCertificateFromCaAsync(selfId, ownPubB64, caIp, caPort);

            _caRsa = LoadCaPublicRsaOrThrow();
            _ownCert = ValidateCertOrThrow(ownCertRaw, _caRsa, expectedSubject: selfId, expectedPub: ownPubB64, who: selfId);

            Status?.Invoke($"Certificate OK (ValidUntil={_ownCert.NotAfterUtc:O})");
            Status?.Invoke($"Listening on {listenIp}:{listenPort} ...");

            _listener = new TcpListener(IPAddress.Parse(listenIp), listenPort);
            _listener.Start();

            _tcp = await _listener.AcceptTcpClientAsync();
            _stream = _tcp.GetStream();

            // Read peer cert
            string peerCertRaw = await Framing.ReadStringAsync(_stream);
            _peerCert = ValidateCertOrThrow(peerCertRaw, _caRsa, expectedSubject: "Client1", expectedPub: null, who: "peer");

            // Send own cert
            await Framing.SendStringAsync(_stream, ownCertRaw);

            // Read Km
            string kmMsg = await Framing.ReadStringAsync(_stream);
            if (!kmMsg.StartsWith("KM|")) throw new InvalidOperationException("Expected KM message.");
            byte[] encKm = Convert.FromBase64String(kmMsg.Substring(3));
            byte[] km = _ownRsa.Decrypt(encKm, RSAEncryptionPadding.OaepSHA256);

            // Derive Ks (same order as console)
            byte[] salt = Crypto.Sha256(Encoding.UTF8.GetBytes($"{_peerCert.SerialNumber}|{_ownCert.SerialNumber}"));
            byte[] info = Encoding.UTF8.GetBytes("BIM437-AESGCM-SessionKey-v1");
            _ks = Crypto.HkdfSha256(km, salt, info, 32);

            _aadIn  = "from=Client1;to=Client2;v=1";
            _aadOut = "from=Client2;to=Client1;v=1";

            StartRxLoop(fromName: "Client1");
            Status?.Invoke("🔒 Secure channel established.");
        }

        // -----------
        // Messaging
        // -----------
        public async Task SendAsync(string plainText)
        {
            if (_stream == null || _ks == null) throw new InvalidOperationException("Not connected/secure.");

            string packed = Crypto.AesGcmEncryptToBase64(_ks, plainText, _aadOut);
            await Framing.SendStringAsync(_stream, "MSG|" + packed);
        }

        public async Task CloseAsync()
        {
            try
            {
                if (_stream != null)
                    await Framing.SendStringAsync(_stream, "BYE");
            }
            catch { /* ignore */ }

            await DisposeAsync();
        }

        // -----------
        // RX loop
        // -----------
        private void StartRxLoop(string fromName)
        {
            _cts = new CancellationTokenSource();
            _rxTask = Task.Run(() => RxLoopAsync(fromName, _cts.Token));
        }

        private async Task RxLoopAsync(string fromName, CancellationToken ct)
        {
            try
            {
                if (_stream == null) return;

                while (!ct.IsCancellationRequested)
                {
                    string incoming = await Framing.ReadStringAsync(_stream, ct);

                    if (incoming == "BYE")
                    {
                        Disconnected?.Invoke();
                        return;
                    }

                    if (incoming.StartsWith("MSG|"))
                    {
                        string b64 = incoming.Substring(4);
                        try
                        {
                            if (_ks == null) continue;
                            string plain = Crypto.AesGcmDecryptFromBase64(_ks, b64, _aadIn);
                            MessageReceived?.Invoke(fromName, plain);
                        }
                        catch (CryptographicException)
                        {
                            Error?.Invoke("Decrypt failed (tamper/wrong AAD).");
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException)
            {
                Disconnected?.Invoke();
            }
            catch (Exception ex)
            {
                Error?.Invoke("RxLoop error: " + ex.Message);
                Disconnected?.Invoke();
            }
        }

        // -----------
        // CA helpers
        // -----------
        private static async Task<string> RequestCertificateFromCaAsync(string subjectId, string pubBase64, string caIp, int caPort)
        {
            using TcpClient client = new TcpClient();
            await client.ConnectAsync(caIp, caPort);
            using NetworkStream stream = client.GetStream();

            await Framing.SendStringAsync(stream, $"CERT_REQUEST|{subjectId}|{pubBase64}");
            string resp = await Framing.ReadStringAsync(stream);

            if (resp.StartsWith("ERROR|"))
                throw new InvalidOperationException("CA error: " + resp);

            return resp;
        }

        private static RSA LoadCaPublicRsaOrThrow()
        {
            foreach (var p in CandidateKeyPaths())
            {
                if (!File.Exists(p)) continue;

                string b64 = File.ReadAllText(p).Trim();
                if (string.IsNullOrWhiteSpace(b64)) continue;

                RSA ca = RSA.Create();
                ca.ImportRSAPublicKey(Convert.FromBase64String(b64), out _);
                return ca;
            }

            throw new FileNotFoundException(
                "ca_public.key not found. Run CAApp first (creates CAApp/ca_public.key). " +
                "GUI auto-searches CAApp inside Project_Files.");
        }

        private static string[] CandidateKeyPaths()
        {
            string baseDir = AppContext.BaseDirectory;
            string cwd = Directory.GetCurrentDirectory();

            string? solutionRoot = TryFindSolutionRoot(baseDir) ?? TryFindSolutionRoot(cwd);

            var list = new System.Collections.Generic.List<string>();

            // ✅ 1) ÖNCE CAApp/ca_public.key (en doğru kaynak bu)
            if (!string.IsNullOrWhiteSpace(solutionRoot))
            {
                list.Add(Path.GetFullPath(Path.Combine(solutionRoot, "CAApp", "ca_public.key")));
                list.Add(Path.GetFullPath(Path.Combine(solutionRoot, "CAApp", "bin", "Debug", "net10.0", "ca_public.key")));
            }

            // ✅ 2) Sonra GUI çalışma dizini (stale olma ihtimali var ama fallback)
            list.Add(Path.GetFullPath(Path.Combine(cwd, "ca_public.key")));

            // ✅ 3) Sonra bin altı (fallback)
            list.Add(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "ca_public.key")));

            // ✅ 4) Son fallback tahminler
            list.Add(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "CAApp", "ca_public.key")));
            list.Add(Path.GetFullPath(Path.Combine(cwd, "..", "CAApp", "ca_public.key")));

            return new System.Collections.Generic.HashSet<string>(list).ToArray();
        }

        private static string? TryFindSolutionRoot(string startPath)
        {
            var dir = new DirectoryInfo(Path.GetFullPath(startPath));
            for (int i = 0; i < 10 && dir != null; i++)
            {
                if (dir.Name.Equals("Project_Files", StringComparison.OrdinalIgnoreCase))
                    return dir.FullName;
                dir = dir.Parent;
            }
            return null;
        }

        private static Certificate ValidateCertOrThrow(string certRaw, RSA caRsa, string expectedSubject, string? expectedPub, string who)
        {
            if (!Certificate.TryParse(certRaw, out var cert, out var parseErr) || cert == null)
                throw new InvalidOperationException($"[{who}] Cert parse fail: {parseErr}");

            if (!CertValidator.VerifyWithCa(cert, caRsa, out var verifyErr,
                    expectedSubjectId: expectedSubject,
                    expectedPublicKeyBase64: expectedPub))
                throw new InvalidOperationException($"[{who}] Cert verify fail: {verifyErr}");

            return cert;
        }

        public async ValueTask DisposeAsync()
        {
            try { _cts?.Cancel(); } catch { }

            if (_rxTask != null)
            {
                try { await _rxTask; } catch { }
                _rxTask = null;
            }

            try { _stream?.Close(); } catch { }
            try { _tcp?.Close(); } catch { }
            try { _listener?.Stop(); } catch { }

            _stream = null;
            _tcp = null;
            _listener = null;

            _ownRsa?.Dispose();
            _caRsa?.Dispose();

            _ownRsa = null;
            _caRsa = null;

            _ownCert = null;
            _peerCert = null;

            _ks = null;
            _cts = null;
        }
    }
}
