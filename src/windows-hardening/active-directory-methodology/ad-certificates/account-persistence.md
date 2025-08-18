# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**This is a small summary of the machine persistence chapters of the awesome research from [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Understanding Active User Credential Theft with Certificates – PERSIST1**

In a scenario where a certificate that allows domain authentication can be requested by a user, an attacker has the opportunity to **request** and **steal** this certificate to **maintain persistence** on a network. By default, the `User` template in Active Directory allows such requests, though it may sometimes be disabled.

Using a tool named [**Certify**](https://github.com/GhostPack/Certify), one can search for valid certificates that enable persistent access:

```bash
Certify.exe find /clientauth
```

It's highlighted that a certificate's power lies in its ability to **authenticate as the user** it belongs to, regardless of any password changes, as long as the certificate remains **valid**.

Certificates can be requested through a graphical interface using `certmgr.msc` or through the command line with `certreq.exe`. With **Certify**, the process to request a certificate is simplified as follows:

```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```

Upon successful request, a certificate along with its private key is generated in `.pem` format. To convert this into a `.pfx` file, which is usable on Windows systems, the following command is utilized:

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

The `.pfx` file can then be uploaded to a target system and used with a tool called [**Rubeus**](https://github.com/GhostPack/Rubeus) to request a Ticket Granting Ticket (TGT) for the user, extending the attacker's access for as long as the certificate is **valid** (typically one year):

```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```

An important warning is shared about how this technique, combined with another method outlined in the **THEFT5** section, allows an attacker to persistently obtain an account’s **NTLM hash** without interacting with the Local Security Authority Subsystem Service (LSASS), and from a non-elevated context, providing a stealthier method for long-term credential theft.

## **Gaining Machine Persistence with Certificates - PERSIST2**

Another method involves enrolling a compromised system’s machine account for a certificate, utilizing the default `Machine` template which allows such actions. If an attacker gains elevated privileges on a system, they can use the **SYSTEM** account to request certificates, providing a form of **persistence**:

```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```

This access enables the attacker to authenticate to **Kerberos** as the machine account and utilize **S4U2Self** to obtain Kerberos service tickets for any service on the host, effectively granting the attacker persistent access to the machine.

## **Extending Persistence Through Certificate Renewal - PERSIST3**

The final method discussed involves leveraging the **validity** and **renewal periods** of certificate templates. By **renewing** a certificate before its expiration, an attacker can maintain authentication to Active Directory without the need for additional ticket enrolments, which could leave traces on the Certificate Authority (CA) server.

### Certificate Renewal with Certify 2.0

Starting with **Certify 2.0** the renewal workflow is fully automated through the new `request-renew` command.  Given a previously issued certificate (in **base-64 PKCS#12** format) an attacker can renew it without interacting with the original owner – perfect for stealthy, long-term persistence:

```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
                         --cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```

The command will return a fresh PFX that is valid for another full lifetime period, allowing you to keep authenticating even after the first certificate expires or is revoked.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}



