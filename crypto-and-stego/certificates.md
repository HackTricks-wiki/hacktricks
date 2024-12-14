# Certificates

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## What is a Certificate

A **public key certificate** is a digital ID used in cryptography to prove someone owns a public key. It includes the key's details, the owner's identity (the subject), and a digital signature from a trusted authority (the issuer). If the software trusts the issuer and the signature is valid, secure communication with the key's owner is possible.

Certificates are mostly issued by [certificate authorities](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) in a [public-key infrastructure](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) setup. Another method is the [web of trust](https://en.wikipedia.org/wiki/Web\_of\_trust), where users directly verify each other’s keys. The common format for certificates is [X.509](https://en.wikipedia.org/wiki/X.509), which can be adapted for specific needs as outlined in RFC 5280.

## x509 Common Fields

### **Common Fields in x509 Certificates**

In x509 certificates, several **fields** play critical roles in ensuring the certificate's validity and security. Here's a breakdown of these fields:

* **Version Number** signifies the x509 format's version.
* **Serial Number** uniquely identifies the certificate within a Certificate Authority's (CA) system, mainly for revocation tracking.
* The **Subject** field represents the certificate's owner, which could be a machine, an individual, or an organization. It includes detailed identification such as:
  * **Common Name (CN)**: Domains covered by the certificate.
  * **Country (C)**, **Locality (L)**, **State or Province (ST, S, or P)**, **Organization (O)**, and **Organizational Unit (OU)** provide geographical and organizational details.
  * **Distinguished Name (DN)** encapsulates the full subject identification.
* **Issuer** details who verified and signed the certificate, including similar subfields as the Subject for the CA.
* **Validity Period** is marked by **Not Before** and **Not After** timestamps, ensuring the certificate is not used before or after a certain date.
* The **Public Key** section, crucial for the certificate's security, specifies the algorithm, size, and other technical details of the public key.
* **x509v3 extensions** enhance the certificate's functionality, specifying **Key Usage**, **Extended Key Usage**, **Subject Alternative Name**, and other properties to fine-tune the certificate's application.

#### **Key Usage and Extensions**

* **Key Usage** identifies cryptographic applications of the public key, like digital signature or key encipherment.
* **Extended Key Usage** further narrows down the certificate's use cases, e.g., for TLS server authentication.
* **Subject Alternative Name** and **Basic Constraint** define additional host names covered by the certificate and whether it's a CA or end-entity certificate, respectively.
* Identifiers like **Subject Key Identifier** and **Authority Key Identifier** ensure uniqueness and traceability of keys.
* **Authority Information Access** and **CRL Distribution Points** provide paths to verify the issuing CA and check certificate revocation status.
* **CT Precertificate SCTs** offer transparency logs, crucial for public trust in the certificate.

```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
    cert_data = file.read()
    certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```

### **Difference between OCSP and CRL Distribution Points**

**OCSP** (**RFC 2560**) involves a client and a responder working together to check if a digital public-key certificate has been revoked, without needing to download the full **CRL**. This method is more efficient than the traditional **CRL**, which provides a list of revoked certificate serial numbers but requires downloading a potentially large file. CRLs can include up to 512 entries. More details are available [here](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **What is Certificate Transparency**

Certificate Transparency helps combat certificate-related threats by ensuring the issuance and existence of SSL certificates are visible to domain owners, CAs, and users. Its objectives are:

* Preventing CAs from issuing SSL certificates for a domain without the domain owner's knowledge.
* Establishing an open auditing system for tracking mistakenly or maliciously issued certificates.
* Safeguarding users against fraudulent certificates.

#### **Certificate Logs**

Certificate logs are publicly auditable, append-only records of certificates, maintained by network services. These logs provide cryptographic proofs for auditing purposes. Both issuance authorities and the public can submit certificates to these logs or query them for verification. While the exact number of log servers is not fixed, it's expected to be less than a thousand globally. These servers can be independently managed by CAs, ISPs, or any interested entity.

#### **Query**

To explore Certificate Transparency logs for any domain, visit [https://crt.sh/](https://crt.sh).

Different formats exist for storing certificates, each with its own use cases and compatibility. This summary covers the main formats and provides guidance on converting between them.

## **Formats**

### **PEM Format**

* Most widely used format for certificates.
* Requires separate files for certificates and private keys, encoded in Base64 ASCII.
* Common extensions: .cer, .crt, .pem, .key.
* Primarily used by Apache and similar servers.

### **DER Format**

* A binary format of certificates.
* Lacks the "BEGIN/END CERTIFICATE" statements found in PEM files.
* Common extensions: .cer, .der.
* Often used with Java platforms.

### **P7B/PKCS#7 Format**

* Stored in Base64 ASCII, with extensions .p7b or .p7c.
* Contains only certificates and chain certificates, excluding the private key.
* Supported by Microsoft Windows and Java Tomcat.

### **PFX/P12/PKCS#12 Format**

* A binary format that encapsulates server certificates, intermediate certificates, and private keys in one file.
* Extensions: .pfx, .p12.
* Mainly used on Windows for certificate import and export.

### **Converting Formats**

**PEM conversions** are essential for compatibility:

* **x509 to PEM**

```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```

* **PEM to DER**

```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```

* **DER to PEM**

```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```

* **PEM to P7B**

```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```

* **PKCS7 to PEM**

```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```

**PFX conversions** are crucial for managing certificates on Windows:

* **PFX to PEM**

```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```

* **PFX to PKCS#8** involves two steps:
  1. Convert PFX to PEM

```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```

2. Convert PEM to PKCS8

```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```

* **P7B to PFX** also requires two commands:
  1. Convert P7B to CER

```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```

2. Convert CER and Private Key to PFX

```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```

* **ASN.1 (DER/PEM) editing** (works with certificates or almost any other ASN.1 structure):
  1. Clone [asn1template](https://github.com/wllm-rbnt/asn1template/)

```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```

2. Convert DER/PEM to OpenSSL's generation format

```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```

3. Edit certificatename.tpl according to your requirements

```bash
vim certificatename.tpl
```

4. Rebuild the modified certificate

```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```

***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

