# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

This area is about **X.509 parsing, formats, conversions, and common mistakes**.

## X.509: parsing, formats & common mistakes

### Quick parsing

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Useful fields to inspect:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (is it a CA?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formats & conversion

- PEM (Base64 with BEGIN/END headers)
- DER (binary)
- PKCS#7 (`.p7b`) (cert chain, no private key)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Conversions:

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

### Common offensive angles

- Trusting user-provided roots / missing chain validation
- Weak signature algorithms (legacy)
- Name constraints / SAN parsing bugs (implementation-specific)
- Confused deputy issues with client-certificate authentication misbinding

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
