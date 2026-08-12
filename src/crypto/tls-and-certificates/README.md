# TLS and Certificates

{{#include ../../banners/hacktricks-training.md}}

This section covers X.509 inspection, encodings, conversions, and security-relevant validation mistakes.

## X.509 Parsing

OpenSSL can print a certificate's decoded fields, while `asn1parse` shows the underlying ASN.1 structure.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Review at least:

- the subject, issuer, and Subject Alternative Name (SAN);
- key usage and extended key usage;
- basic constraints and path-length constraints;
- the `notBefore` and `notAfter` validity times;
- the public-key parameters and signature algorithm.

Legacy signatures such as MD5- or SHA-1-based certificate signatures are particularly important findings, although the exact acceptance and impact depend on the validator and trust context.<sup>[[3]](#references)</sup>

RFC 5280 defines the Internet X.509 profile and the processing rules for extensions such as SAN, key usage, name constraints, and basic constraints.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** Base64 data between `BEGIN` and `END` boundaries.
- **DER:** the binary Distinguished Encoding Rules representation.
- **PKCS#7/CMS (`.p7b`):** commonly carries certificates and a certificate chain, but not private keys.
- **PKCS#12 (`.p12` or `.pfx`):** can carry private keys, certificates, and supporting certificates.

RFC 7468 specifies the textual encodings used for PKIX, PKCS, and CMS structures; OpenSSL's `pkcs12` command creates and parses PKCS#12 files.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Treat `out.pem` as sensitive: unless options such as `-nokeys` are used, the output may contain private-key material.<sup>[[5]](#references)</sup>

## Security Review Checklist

Apply the certificate-processing requirements in RFC 5280 when reviewing a validator or trust decision.<sup>[[3]](#references)</sup>

- Verify the complete chain to an explicitly trusted anchor; do not trust user-supplied roots implicitly.
- Confirm the hostname or service identity against SAN values.<sup>[[8]](#references)</sup>
- Enforce basic constraints, name constraints, key usage, and extended key usage.
- Reject expired or not-yet-valid certificates and disallowed key or signature algorithms.
- Bind client-certificate identities to the correct application account and authorization context.

## Certificate Transparency Logs

Certificate Transparency provides publicly auditable logs of issued certificates.<sup>[[6]](#references)</sup> Search a domain with crt.sh during authorized asset discovery.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL documentation - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL documentation - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Textual Encodings of PKIX, PKCS, and CMS Structures](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL documentation - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Certificate Search](https://crt.sh/)
- [8] [RFC 9525 - Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525)

{{#include ../../banners/hacktricks-training.md}}
