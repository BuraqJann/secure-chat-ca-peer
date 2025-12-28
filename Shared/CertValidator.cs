using System;
using System.Security.Cryptography;
using System.Text;

namespace Shared;

public static class CertValidator
{
    public static bool VerifyWithCa(
        Certificate cert,
        RSA caPublicRsa,
        out string error,
        string? expectedSubjectId = null,
        string? expectedPublicKeyBase64 = null,
        DateTime? nowUtc = null,
        TimeSpan? clockSkew = null)
    {
        error = "";
        nowUtc ??= DateTime.UtcNow;
        clockSkew ??= TimeSpan.FromMinutes(2);

        if (expectedSubjectId != null && cert.SubjectId != expectedSubjectId)
        {
            error = "SubjectId mismatch.";
            return false;
        }

        if (expectedPublicKeyBase64 != null && cert.SubjectPublicKeyBase64 != expectedPublicKeyBase64)
        {
            error = "Public key mismatch.";
            return false;
        }

        if (nowUtc.Value < cert.NotBeforeUtc - clockSkew.Value)
        {
            error = "Certificate not yet valid.";
            return false;
        }

        if (nowUtc.Value > cert.NotAfterUtc + clockSkew.Value)
        {
            error = "Certificate expired.";
            return false;
        }

        byte[] data = Encoding.UTF8.GetBytes(cert.DataToVerify());
        byte[] sig = Convert.FromBase64String(cert.SignatureBase64);

        bool ok = caPublicRsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!ok) error = "CA signature invalid.";
        return ok;
    }
}
