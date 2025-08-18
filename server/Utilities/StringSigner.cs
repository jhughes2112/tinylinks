using System;
using System.Security.Cryptography;
using System.Text;

// This is a helper that allows us to provide a key to each Zone we start up, where we can recognize it was originated by the Cluster itself, since the private key changes every execution.
public class StringSigner
{
    private RSA _rsa = RSA.Create();

	// The input should be Base64 string already
    public string Sign(string base64)
    {
        byte[] inputBytes = Encoding.UTF8.GetBytes(base64);
        byte[] signatureBytes = _rsa.SignData(inputBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        string signature = Convert.ToBase64String(signatureBytes);
        string signedData = $"{Convert.ToBase64String(inputBytes)}.{signature}";
        return signedData;
    }

	// This input should be formatted like: base64string.base64signature
	public bool IsValid(string signedData)
	{
       // Split the input to extract the original base64 string and the signature
        string[] parts = signedData.Split('.');
        if (parts.Length != 2)
        {
            return false;
        }

        // Decode the base64 encoded original data and signature
        byte[] originalData = Convert.FromBase64String(parts[0]);
        byte[] signatureBytes = Convert.FromBase64String(parts[1]);

        // Verify the signature
        bool isValid = _rsa.VerifyData(originalData, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return isValid;
	}
}
