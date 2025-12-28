using System;
using System.Globalization;

namespace Shared;

public record Certificate(
    string SubjectId,
    string SerialNumber,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    string SubjectPublicKeyBase64,
    string SignatureBase64
)
{
    public static bool TryParse(string raw, out Certificate? cert, out string error)
    {
        cert = null;
        error = "";

        var p = raw.Split('|');
        if (p.Length != 7 || p[0] != "CERT_RESPONSE")
        {
            error = "Bad certificate format.";
            return false;
        }

        if (!DateTime.TryParse(p[3], null, DateTimeStyles.RoundtripKind, out var nb) ||
            !DateTime.TryParse(p[4], null, DateTimeStyles.RoundtripKind, out var na))
        {
            error = "Bad time format.";
            return false;
        }

        nb = nb.ToUniversalTime();
        na = na.ToUniversalTime();

        cert = new Certificate(
            SubjectId: p[1],
            SerialNumber: p[2],
            NotBeforeUtc: nb,
            NotAfterUtc: na,
            SubjectPublicKeyBase64: p[5],
            SignatureBase64: p[6]
        );

        return true;
    }

    public string DataToVerify()
        => $"{SubjectId}|{SerialNumber}|{NotBeforeUtc:O}|{NotAfterUtc:O}|{SubjectPublicKeyBase64}";
}
