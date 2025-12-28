using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Shared;

namespace CAApp
{
    internal class Program
    {
        private static RSA _caRsa = RSA.Create(2048);

        static async System.Threading.Tasks.Task Main(string[] args)
        {
            const string ipString = "10.0.0.10";
            const int port = 5000;

            string caPublicKeyBase64 = Convert.ToBase64String(_caRsa.ExportRSAPublicKey());
            Console.WriteLine("[CA] RSA key pair generated (2048 bits).");
            Console.WriteLine("[CA] Public key (Base64):");
            Console.WriteLine(caPublicKeyBase64);
            Console.WriteLine();

            System.IO.File.WriteAllText("ca_public.key", caPublicKeyBase64);
            Console.WriteLine("[CA] Saved public key to ca_public.key\n");

            var ip = IPAddress.Parse(ipString);
            var listener = new TcpListener(ip, port);

            listener.Start();
            Console.WriteLine($"[CA] Listening on {ipString}:{port} ...\n");

            while (true)
            {
                Console.WriteLine("[CA] Waiting for client...");
                using TcpClient client = await listener.AcceptTcpClientAsync();
                Console.WriteLine("[CA] Client connected.");

                try
                {
                    using NetworkStream stream = client.GetStream();
                    string received = await Framing.ReadStringAsync(stream);
                    Console.WriteLine($"[CA] Received: {received}");

                    string response = BuildResponse(received);

                    await Framing.SendStringAsync(stream, response);
                    Console.WriteLine("[CA] Response sent.\n");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[CA] ERROR: " + ex.Message + "\n");
                }
            }
        }

        private static string BuildResponse(string received)
        {
            if (!received.StartsWith("CERT_REQUEST|"))
                return "ERROR|Unknown request type.";

            // CERT_REQUEST|Client1|<ClientPublicKeyBase64>
            string[] parts = received.Split('|');
            if (parts.Length != 3)
                return "ERROR|Invalid certificate request format.";

            string subjectId = parts[1];
            string clientPublicKeyBase64 = parts[2];

            if (string.IsNullOrWhiteSpace(subjectId) || string.IsNullOrWhiteSpace(clientPublicKeyBase64))
                return "ERROR|Empty subject or public key.";

            // Demo için expire almak istersen:
            // DateTime notAfter = notBefore.AddMinutes(1);
            string serialNumber = Guid.NewGuid().ToString("N");
            DateTime notBefore = DateTime.UtcNow;
            DateTime notAfter = notBefore.AddYears(1);

            string dataToSign =
                $"{subjectId}|{serialNumber}|{notBefore:O}|{notAfter:O}|{clientPublicKeyBase64}";
            byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);

            byte[] signatureBytes = _caRsa.SignData(
                dataBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            string signatureBase64 = Convert.ToBase64String(signatureBytes);

            string response =
                $"CERT_RESPONSE|{subjectId}|{serialNumber}|{notBefore:O}|{notAfter:O}|{clientPublicKeyBase64}|{signatureBase64}";

            Console.WriteLine($"[CA] Issued cert for {subjectId} serial={serialNumber}");
            return response;
        }
    }
}
