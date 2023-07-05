using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace BankID.Test;

internal static class SSLCertValidation
{
    public static Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> GetValidation(X509Certificate2 trustCertificate) =>
        (requestMessage, certificate, chain, sslPolicyErrors) => ValidateServerCertificate(requestMessage, certificate, chain, sslPolicyErrors, trustCertificate);
        
    // Inspired by: https://www.meziantou.net/custom-certificate-validation-in-dotnet.htm#dotnet-5-way-of-vali & https://github.com/ActiveLogin/ActiveLogin.Authentication/blob/main/src/ActiveLogin.Authentication.BankId.Core/Cryptography/X509CertificateChainValidator.cs#L16
    public static bool ValidateServerCertificate(
        HttpRequestMessage requestMessage,
        X509Certificate2? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors,
        X509Certificate2 trustCertificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var hasCertificateNameMismatch = sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
        var hasCertificateNotAvailable = sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable);

        if (hasCertificateNameMismatch || hasCertificateNotAvailable)
        {
            return false;
        }

        if (chain == null) return false;

        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Clear();
        chain.ChainPolicy.CustomTrustStore.Add(trustCertificate);

        bool isValid = chain.Build(certificate);

        if (!isValid) return false;

        return chain.ChainElements.Any(x => x.Certificate.Thumbprint == trustCertificate.Thumbprint);
    }
}
