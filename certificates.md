# Certificates

## What is a Certificate

In cryptography, a **public key certificate,** also known as a **digital certificate** or **identity certificate,** is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about the identity of its owner \(called the subject\), and the digital signature of an entity that has verified the certificate's contents \(called the issuer\). If the signature is valid, and the software examining the certificate trusts the issuer, then it can use that key to communicate securely with the certificate's subject.

In a typical [public-key infrastructure](https://en.wikipedia.org/wiki/Public-key_infrastructure) \(PKI\) scheme, the certificate issuer is a [certificate authority](https://en.wikipedia.org/wiki/Certificate_authority) \(CA\), usually a company that charges customers to issue certificates for them. By contrast, in a [web of trust](https://en.wikipedia.org/wiki/Web_of_trust) scheme, individuals sign each other's keys directly, in a format that performs a similar function to a public key certificate.

The most common format for public key certificates is defined by [X.509](https://en.wikipedia.org/wiki/X.509). Because X.509 is very general, the format is further constrained by profiles defined for certain use cases, such as [Public Key Infrastructure \(X.509\)](https://en.wikipedia.org/wiki/PKIX) as defined in RFC 5280.

## x509 Common Fields

* **Version Number:** Version of x509 format.
* **Serial Number**: Used to uniquely identify the certificate within a CA's systems. In particular this is used to track revocation information.
* **Subject**: The entity a certificate belongs to: a machine, an individual, or an organization.
  * **Common Name**: Domains affected by the certificate. Can be 1 or more and can contain wildcards.
  * **Country \(C\)**: Country
  * **Distinguished name \(DN\)**: The whole subject: `C=US, ST=California, L=San Francisco, O=Example, Inc., CN=shared.global.example.net`
  * **Locality \(L\)**: Local place
  * **Organization \(O\)**: Organization name
  * **Organizational Unit \(OU\)**: Division of an organisation \(like "Human Resources"\).
  * **State or Province \(ST, S or P\)**: List of state or province names
* **Issuer**: The entity that verified the information and signed the certificate.
  * **Common Name \(CN\)**: Name of the certificate authority
  * **Country \(C\)**: Country of the certificate authority
  * **Distinguished name \(DN\)**: Distinguished name of the certificate authority
  * **Locality \(L\)**: Local place where the organisation can be found.
  * **Organization \(O\)**: Organisation name
  * **Organizational Unit \(OU\)**: Division of an organisation \(like "Human Resources"\).
* **Not Before**: The earliest time and date on which the certificate is valid. Usually set to a few hours or days prior to the moment the certificate was issued, to avoid [clock skew](https://en.wikipedia.org/wiki/Clock_skew#On_a_network) problems.
* **Not After**: The time and date past which the certificate is no longer valid.
* **Public Key**: A public key belonging to the certificate subject. \(This is one of the main parts as this is what is signed by the CA\)
  * **Public Key Algorithm**: Algorithm used to generate the public key. Like RSA.
  * **Public Key Curve**: The curve used by the elliptic curve public key algorithm \(if apply\). Like nistp521.
  * **Public Key Exponent**: Exponent used to derive the public key \(if apply\). Like 65537.
  * **Public Key Size**: The size of the public key space in bits. Like 2048.
  * **Signature Algorithm**: The algorithm used to sign the public key certificate.
  * **Signature**: A signature of the certificate body by the issuer's private key.
* **x509v3 extensions**
  * **Key Usage**: The valid cryptographic uses of the certificate's public key. Common values include digital signature validation, key encipherment, and certificate signing.
    * In a Web certificate this will appear as a _X509v3 extension_ and will have the value `Digital Signature`
  * **Extended Key Usage**: The applications in which the certificate may be used. Common values include TLS server authentication, email protection, and code signing.
    * In a Web certificate this will appear as a _X509v3 extension_ and will have the value `TLS Web Server Authentication`
  * **Subject Alternative Name:**  Allows users to specify additional host **names** for a single SSL **certificate**. The use of the SAN extension is standard practice for SSL certificates, and it's on its way to replacing the use of the common **name**.
  * **Basic Constraint:** This extension describes whether the certificate is a CA certificate or an end entity certificate. A CA certificate is something that signs certificates of others and a end entity certificate is the certificate used in a web page for example \(the last par of the chain\).
  *  **Subject Key Identifier** \(SKI\): This extension declares a unique **identifier** for the public **key** in the certificate. It is required on all CA certificates. CAs propagate their own SKI to the Issuer **Key Identifier** \(AKI\) extension on issued certificates. It's the hash of the subject public key.
  * **Authority Key Identifier**: It contains a key identifier which is derived from the public key in the issuer certificate. It's the hash of the issuer public key.
  * **Authority Information Access** \(AIA\): This extension contains at most two types of information :
    * Information about **how to get the issuer of this certificate** \(CA issuer access method\)
    * Address of the **OCSP responder from where revocation of this certificate** can be checked \(OCSP access method\).
  * **CRL Distribution Points**: This extension identifies the location of the CRL from which the revocation of this certificate can be checked. The application that processes the certificate can get the location of the CRL from this extension, download the CRL and then check the revocation of this certificate.

### Difference between OSCP and CRL Distribution Points

**OCSP** \(RFC 2560\) is a standard protocol that consists of an **OCSP client and an OCSP responder**. This protocol **determines revocation status of a given digital public-key certificate** **without** having to **download** the **entire CRL**.  
**CRL** is the **traditional method** of checking certificate validity. A **CRL provides a list of certificate serial numbers** that have been revoked or are no longer valid. CRLs let the verifier check the revocation status of the presented certificate while verifying it. CRLs are limited to 512 entries.  
From [here](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm#:~:text=OCSP%20%28RFC%202560%29%20is%20a,to%20download%20the%20entire%20CRL.&text=A%20CRL%20provides%20a%20list,or%20are%20no%20longer%20valid.).

