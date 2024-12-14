# AD CS Domain Persistence

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

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

It can be determined that a certificate is a CA certificate if several conditions are met:

- The certificate is stored on the CA server, with its private key secured by the machine's DPAPI, or by hardware such as a TPM/HSM if the operating system supports it.
- Both the Issuer and Subject fields of the certificate match the distinguished name of the CA.
- A "CA Version" extension is present in the CA certificates exclusively.
- The certificate lacks Extended Key Usage (EKU) fields.

To extract the private key of this certificate, the `certsrv.msc` tool on the CA server is the supported method via the built-in GUI. Nonetheless, this certificate does not differ from others stored within the system; thus, methods such as the [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) can be applied for extraction.

The certificate and private key can also be obtained using Certipy with the following command:

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Upon acquiring the CA certificate and its private key in `.pfx` format, tools like [ForgeCert](https://github.com/GhostPack/ForgeCert) can be utilized to generate valid certificates:

```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```

{% hint style="warning" %}
The user targeted for certificate forgery must be active and capable of authenticating in Active Directory for the process to succeed. Forging a certificate for special accounts like krbtgt is ineffective.
{% endhint %}

This forged certificate will be **valid** until the end date specified and as **long as the root CA certificate is valid** (usually from 5 to **10+ years**). It's also valid for **machines**, so combined with **S4U2Self**, an attacker can **maintain persistence on any domain machine** for as long as the CA certificate is valid.\
Moreover, the **certificates generated** with this method **cannot be revoked** as CA is not aware of them.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

## Malicious Misconfiguration - DPERSIST3

Opportunities for **persistence** through **security descriptor modifications of AD CS** components are plentiful. Modifications described in the "[Domain Escalation](domain-escalation.md)" section can be maliciously implemented by an attacker with elevated access. This includes the addition of "control rights" (e.g., WriteOwner/WriteDACL/etc.) to sensitive components such as:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

An example of malicious implementation would involve an attacker, who has **elevated permissions** in the domain, adding the **`WriteOwner`** permission to the default **`User`** certificate template, with the attacker being the principal for the right. To exploit this, the attacker would first change the ownership of the **`User`** template to themselves. Following this, the **`mspki-certificate-name-flag`** would be set to **1** on the template to enable **`ENROLLEE_SUPPLIES_SUBJECT`**, allowing a user to provide a Subject Alternative Name in the request. Subsequently, the attacker could **enroll** using the **template**, choosing a **domain administrator** name as an alternative name, and utilize the acquired certificate for authentication as the DA.


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

