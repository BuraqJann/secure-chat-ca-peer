using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Shared;

public static class CaKeyLoader
{
    public static RSA LoadCaPublicRsaOrThrow()
    {
        foreach (var p in CandidateKeyPaths())
        {
            try
            {
                if (!File.Exists(p)) continue;

                string b64 = File.ReadAllText(p).Trim();
                if (string.IsNullOrWhiteSpace(b64)) continue;

                var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(Convert.FromBase64String(b64), out _);
                return rsa;
            }
            catch
            {
                // try next
            }
        }

        throw new FileNotFoundException(
            "CA public key not found. Expected ca_public.key near CAApp or in working directory. " +
            "Run CAApp first or ensure CAApp/ca_public.key exists.");
    }

    private static IEnumerable<string> CandidateKeyPaths()
    {
        string baseDir = AppContext.BaseDirectory;
        string cwd = Directory.GetCurrentDirectory();

        string? root = TryFindSolutionRoot(baseDir) ?? TryFindSolutionRoot(cwd);

        var list = new List<string>();

        // ✅ En doğru: proje root -> CAApp/ca_public.key
        if (!string.IsNullOrWhiteSpace(root))
        {
            list.Add(Path.GetFullPath(Path.Combine(root, "CAApp", "ca_public.key")));
            list.Add(Path.GetFullPath(Path.Combine(root, "CAApp", "bin", "Debug", "net10.0", "ca_public.key")));
        }

        // fallback: GUI yanında
        list.Add(Path.GetFullPath(Path.Combine(cwd, "ca_public.key")));

        // fallback: bin altından yukarı
        list.Add(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "ca_public.key")));

        // son fallback tahminler
        list.Add(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "CAApp", "ca_public.key")));
        list.Add(Path.GetFullPath(Path.Combine(cwd, "..", "CAApp", "ca_public.key")));

        // unique
        return new HashSet<string>(list);
    }

    private static string? TryFindSolutionRoot(string start)
    {
        try
        {
            var d = new DirectoryInfo(start);

            // baseDir bazen bin/Debug/netX.Y/... olur, yukarı çık
            for (int i = 0; i < 10 && d != null; i++)
            {
                // Root kriteri: CAApp, Shared, Client1Gui gibi klasörler var mı?
                bool looksLikeRoot =
                    Directory.Exists(Path.Combine(d.FullName, "CAApp")) &&
                    Directory.Exists(Path.Combine(d.FullName, "Shared"));

                if (looksLikeRoot) return d.FullName;
                d = d.Parent;
            }
        }
        catch { }

        return null;
    }
}
