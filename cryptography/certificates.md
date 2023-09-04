# Certificates

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## What is a Certificate

In cryptography, a **public key certificate,** also known as a **digital certificate** or **identity certificate,** is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about the identity of its owner (called the subject), and the digital signature of an entity that has verified the certificate's contents (called the issuer). If the signature is valid, and the software examining the certificate trusts the issuer, then it can use that key to communicate securely with the certificate's subject.

In a typical [public-key infrastructure](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) scheme, the certificate issuer is a [certificate authority](https://en.wikipedia.org/wiki/Certificate\_authority) (CA), usually a company that charges customers to issue certificates for them. By contrast, in a [web of trust](https://en.wikipedia.org/wiki/Web\_of\_trust) scheme, individuals sign each other's keys directly, in a format that performs a similar function to a public key certificate.

The most common format for public key certificates is defined by [X.509](https://en.wikipedia.org/wiki/X.509). Because X.509 is very general, the format is further constrained by profiles defined for certain use cases, such as [Public Key Infrastructure (X.509)](https://en.wikipedia.org/wiki/PKIX) as defined in RFC 5280.

## x509 Common Fields

* **Version Number:** Version of x509 format.
* **Serial Number**: Used to uniquely identify the certificate within a CA's systems. In particular this is used to track revocation information.
* **Subject**: The entity a certificate belongs to: a machine, an individual, or an organization.
  * **Common Name**: Domains affected by the certificate. Can be 1 or more and can contain wildcards.
  * **Country (C)**: Country
  * **Distinguished name (DN)**: The whole subject: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
  * **Locality (L)**: Local place
  * **Organization (O)**: Organization name
  * **Organizational Unit (OU)**: Division of an organisation (like "Human Resources").
  * **State or Province (ST, S or P)**: List of state or province names
* **Issuer**: The entity that verified the information and signed the certificate.
  * **Common Name (CN)**: Name of the certificate authority
  * **Country (C)**: Country of the certificate authority
  * **Distinguished name (DN)**: Distinguished name of the certificate authority
  * **Locality (L)**: Local place where the organisation can be found.
  * **Organization (O)**: Organisation name
  * **Organizational Unit (OU)**: Division of an organisation (like "Human Resources").
* **Not Before**: The earliest time and date on which the certificate is valid. Usually set to a few hours or days prior to the moment the certificate was issued, to avoid [clock skew](https://en.wikipedia.org/wiki/Clock\_skew#On\_a\_network) problems.
* **Not After**: The time and date past which the certificate is no longer valid.
* **Public Key**: A public key belonging to the certificate subject. (This is one of the main parts as this is what is signed by the CA)
  * **Public Key Algorithm**: Algorithm used to generate the public key. Like RSA.
  * **Public Key Curve**: The curve used by the elliptic curve public key algorithm (if apply). Like nistp521.
  * **Public Key Exponent**: Exponent used to derive the public key (if apply). Like 65537.
  * **Public Key Size**: The size of the public key space in bits. Like 2048.
  * **Signature Algorithm**: The algorithm used to sign the public key certificate.
  * **Signature**: A signature of the certificate body by the issuer's private key.
* **x509v3 extensions**
  * **Key Usage**: The valid cryptographic uses of the certificate's public key. Common values include digital signature validation, key encipherment, and certificate signing.
    * In a Web certificate this will appear as a _X509v3 extension_ and will have the value `Digital Signature`
  * **Extended Key Usage**: The applications in which the certificate may be used. Common values include TLS server authentication, email protection, and code signing.
    * In a Web certificate this will appear as a _X509v3 extension_ and will have the value `TLS Web Server Authentication`
  * **Subject Alternative Name:** Allows users to specify additional host **names** for a single SSL **certificate**. The use of the SAN extension is standard practice for SSL certificates, and it's on its way to replacing the use of the common **name**.
  * **Basic Constraint:** This extension describes whether the certificate is a CA certificate or an end entity certificate. A CA certificate is something that signs certificates of others and a end entity certificate is the certificate used in a web page for example (the last par of the chain).
  * **Subject Key Identifier** (SKI): This extension declares a unique **identifier** for the public **key** in the certificate. It is required on all CA certificates. CAs propagate their own SKI to the Issuer **Key Identifier** (AKI) extension on issued certificates. It's the hash of the subject public key.
  * **Authority Key Identifier**: It contains a key identifier which is derived from the public key in the issuer certificate. It's the hash of the issuer public key.
  * **Authority Information Access** (AIA): This extension contains at most two types of information :
    * Information about **how to get the issuer of this certificate** (CA issuer access method)
    * Address of the **OCSP responder from where revocation of this certificate** can be checked (OCSP access method).
  * **CRL Distribution Points**: This extension identifies the location of the CRL from which the revocation of this certificate can be checked. The application that processes the certificate can get the location of the CRL from this extension, download the CRL and then check the revocation of this certificate.
  * **CT Precertificate SCTs**: Logs of Certificate transparency regarding the certificate

### Difference between OCSP and CRL Distribution Points

**OCSP** (RFC 2560) is a standard protocol that consists of an **OCSP client and an OCSP responder**. This protocol **determines revocation status of a given digital public-key certificate** **without** having to **download** the **entire CRL**.\
**CRL** is the **traditional method** of checking certificate validity. A **CRL provides a list of certificate serial numbers** that have been revoked or are no longer valid. CRLs let the verifier check the revocation status of the presented certificate while verifying it. CRLs are limited to 512 entries.\
From [here](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### What is Certificate Transparency

Certificate Transparency aims to remedy certificate-based threats by **making the issuance and existence of SSL certificates open to scrutiny by domain owners, CAs, and domain users**. Specifically, Certificate Transparency has three main goals:

* Make it impossible (or at least very difficult) for a CA to **issue a SSL certificate for a domain without the certificate being visible to the owner** of that domain.
* Provide an **open auditing and monitoring system that lets any domain owner or CA determine whether certificates have been mistakenly or maliciously** issued.
* **Protect users** (as much as possible) from being duped by certificates that were mistakenly or maliciously issued.

#### **Certificate Logs**

Certificate logs are simple network services that maintain **cryptographically assured, publicly auditable, append-only records of certificates**. **Anyone can submit certificates to a log**, although certificate authorities will likely be the foremost submitters. Likewise, anyone can query a log for a cryptographic proof, which can be used to verify that the log is behaving properly or verify that a particular certificate has been logged. The number of log servers doesn’t have to be large (say, much less than a thousand worldwide), and each could be operated independently by a CA, an ISP, or any other interested party.

#### Query

You can query the logs of Certificate Transparency of any domain in [https://crt.sh/](https://crt.sh).

## Formats

There are different formats that can be used to store a certificate.

#### **PEM Format**

* It is the most common format used for certificates
* Most servers (Ex: Apache) expects the certificates and private key to be in a separate files\
  \- Usually they are Base64 encoded ASCII files\
  \- Extensions used for PEM certificates are .cer, .crt, .pem, .key files\
  \- Apache and similar server uses PEM format certificates

#### **DER Format**

* The DER format is the binary form of the certificate
* All types of certificates & private keys can be encoded in DER format
* DER formatted certificates do not contain the "BEGIN CERTIFICATE/END CERTIFICATE" statements
* DER formatted certificates most often use the ‘.cer’ and '.der' extensions
* DER is typically used in Java Platforms

#### **P7B/PKCS#7 Format**

* The PKCS#7 or P7B format is stored in Base64 ASCII format and has a file extension of .p7b or .p7c
* A P7B file only contains certificates and chain certificates (Intermediate CAs), not the private key
* The most common platforms that support P7B files are Microsoft Windows and Java Tomcat

#### **PFX/P12/PKCS#12 Format**

* The PKCS#12 or PFX/P12 format is a binary format for storing the server certificate, intermediate certificates, and the private key in one encryptable file
* These files usually have extensions such as .pfx and .p12
* They are typically used on Windows machines to import and export certificates and private keys

### Formats conversions

**Convert x509 to PEM**

```
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```

#### **Convert PEM to DER**

```
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```

**Convert DER to PEM**

```
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```

**Convert PEM to P7B**

**Note:** The PKCS#7 or P7B format is stored in Base64 ASCII format and has a file extension of .p7b or .p7c. A P7B file only contains certificates and chain certificates (Intermediate CAs), not the private key. The most common platforms that support P7B files are Microsoft Windows and Java Tomcat.

```
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```

**Convert PKCS7 to PEM**

```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```

**Convert pfx to PEM**

**Note:** The PKCS#12 or PFX format is a binary format for storing the server certificate, intermediate certificates, and the private key in one encryptable file. PFX files usually have extensions such as .pfx and .p12. PFX files are typically used on Windows machines to import and export certificates and private keys.

```
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```

**Convert PFX to PKCS#8**\
**Note:** This requires 2 commands

**1- Convert PFX to PEM**

```
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```

**2- Convert PEM to PKCS8**

```
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```

**Convert P7B to PFX**\
**Note:** This requires 2 commands

1- **Convert P7B to CER**

```
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```

**2- Convert CER and Private Key to PFX**

```
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile  cacert.cer
```

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
