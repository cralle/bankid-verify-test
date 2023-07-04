﻿using BankID.Test;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

var certdata = "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";
var certpass = "qwerty123";
var certbytes = Convert.FromBase64String(certdata);

var certificate = new X509Certificate2(certbytes, certpass);

var handler = new HttpClientHandler();
handler.ClientCertificates.Add(certificate);

handler.ServerCertificateCustomValidationCallback = SSLCertExtensions.ValidateServerCertificate;

var client = new HttpClient(handler);

// This is the QR-code value (expires after some seconds)
var payload = new QrCodePayload("BANKIDF.74226FAAE3E64E70BB03F8E8E18D0439.8.79C416AA74278A70FAC25855F728A3206789B87B6FF6EB00688DB9622EFD2D33");

var jsonPayload = JsonSerializer.Serialize(payload);
Console.WriteLine(jsonPayload);

var httpContent = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

var apiUrl = "https://idcardapi.test.bankid.com/rp/v1/verify";
var response = await client.PostAsync(apiUrl, httpContent);

if (response.IsSuccessStatusCode)
{
    var content = await response.Content.ReadAsStringAsync();
    Console.WriteLine(content);
}
else
{
    Console.WriteLine($"Error: {response.StatusCode}");
    Console.WriteLine($"{await response.Content.ReadAsStringAsync()}");
}

public record QrCodePayload(string QrCode);
