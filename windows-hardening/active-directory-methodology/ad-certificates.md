# AD Certificates

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

## Introduction

### Components of a Certificate

- The **Subject** of the certificate denotes its owner.
- A **Public Key** is paired with a privately held key to link the certificate to its rightful owner.
- The **Validity Period**, defined by **NotBefore** and **NotAfter** dates, marks the certificate's effective duration.
- A unique **Serial Number**, provided by the Certificate Authority (CA), identifies each certificate.
- The **Issuer** refers to the CA that has issued the certificate.
- **SubjectAlternativeName** allows for additional names for the subject, enhancing identification flexibility.
- **Basic Constraints** identify if the certificate is for a CA or an end entity and define usage restrictions.
- **Extended Key Usages (EKUs)** delineate the certificate's specific purposes, like code signing or email encryption, through Object Identifiers (OIDs).
- The **Signature Algorithm** specifies the method for signing the certificate.
- The **Signature**, created with the issuer's private key, guarantees the certificate's authenticity.

### Special Considerations

- **Subject Alternative Names (SANs)** expand a certificate's applicability to multiple identities, crucial for servers with multiple domains. Secure issuance processes are vital to avoid impersonation risks by attackers manipulating the SAN specification.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS acknowledges CA certificates in an AD forest through designated containers, each serving unique roles:

- **Certification Authorities** container holds trusted root CA certificates.
- **Enrolment Services** container details Enterprise CAs and their certificate templates.
- **NTAuthCertificates** object includes CA certificates authorized for AD authentication.
- **AIA (Authority Information Access)** container facilitates certificate chain validation with intermediate and cross CA certificates.

### Certificate Acquisition: Client Certificate Request Flow

1. The request process begins with clients finding an Enterprise CA.
2. A CSR is created, containing a public key and other details, after generating a public-private key pair.
3. The CA assesses the CSR against available certificate templates, issuing the certificate based on the template's permissions.
4. Upon approval, the CA signs the certificate with its private key and returns it to the client.

### Certificate Templates

Defined within AD, these templates outline the settings and permissions for issuing certificates, including permitted EKUs and enrollment or modification rights, critical for managing access to certificate services.

## Certificate Enrollment

The enrollment process for certificates is initiated by an administrator who **creates a certificate template**, which is then **published** by an Enterprise Certificate Authority (CA). This makes the template available for client enrollment, a step achieved by adding the template's name to the `certificatetemplates` field of an Active Directory object.

For a client to request a certificate, **enrollment rights** must be granted. These rights are defined by security descriptors on the certificate template and the Enterprise CA itself. Permissions must be granted in both locations for a request to be successful.

### Template Enrollment Rights

These rights are specified through Access Control Entries (ACEs), detailing permissions like:
- **Certificate-Enrollment** and **Certificate-AutoEnrollment** rights, each associated with specific GUIDs.
- **ExtendedRights**, allowing all extended permissions.
- **FullControl/GenericAll**, providing complete control over the template.

### Enterprise CA Enrollment Rights

The CA's rights are outlined in its security descriptor, accessible via the Certificate Authority management console. Some settings even allow low-privileged users remote access, which could be a security concern.

### Additional Issuance Controls

Certain controls may apply, such as:
- **Manager Approval**: Places requests in a pending state until approved by a certificate manager.
- **Enrolment Agents and Authorized Signatures**: Specify the number of required signatures on a CSR and the necessary Application Policy OIDs.

### Methods to Request Certificates

Certificates can be requested through:
1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), using DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), through named pipes or TCP/IP.
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).

```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Certificate Authentication

Active Directory (AD) supports certificate authentication, primarily utilizing **Kerberos** and **Secure Channel (Schannel)** protocols. 

### Kerberos Authentication Process

In the Kerberos authentication process, a user's request for a Ticket Granting Ticket (TGT) is signed using the **private key** of the user's certificate. This request undergoes several validations by the domain controller, including the certificate's **validity**, **path**, and **revocation status**. Validations also include verifying that the certificate comes from a trusted source and confirming the issuer's presence in the **NTAUTH certificate store**. Successful validations result in the issuance of a TGT. The **`NTAuthCertificates`** object in AD, found at:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

is central to establishing trust for certificate authentication.

### Secure Channel (Schannel) Authentication

Schannel facilitates secure TLS/SSL connections, where during a handshake, the client presents a certificate that, if successfully validated, authorizes access. The mapping of a certificate to an AD account may involve Kerberos’s **S4U2Self** function or the certificate’s **Subject Alternative Name (SAN)**, among other methods.

### AD Certificate Services Enumeration

AD's certificate services can be enumerated through LDAP queries, revealing information about **Enterprise Certificate Authorities (CAs)** and their configurations. This is accessible by any domain-authenticated user without special privileges. Tools like **[Certify](https://github.com/GhostPack/Certify)** and **[Certipy](https://github.com/ly4k/Certipy)** are used for enumeration and vulnerability assessment in AD CS environments.

Commands for using these tools include:

```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

## References

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

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
