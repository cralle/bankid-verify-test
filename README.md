# BankID - Test verify (simple implementation)

A simple console app that contains an implementation of how to verify "Digital ID".

SSL cert (RP certificate for test) is downloaded [here](https://www.bankid.com/utvecklare/guider/verifiering-av-digitalt-id-kort/testmiljo) and converted to Base64 string then added to variable "certdata" in Program.cs

ValidateServerCertificate checks if the SSL certificate is issued by the trusted Root CA provided in the above link.

[API - Verify digital ID card from BankID](https://www.bankid.com/utvecklare/guider/verifiering-av-digitalt-id-kort/api-verifiera-digitalt-id-kort-fran-bankid)
