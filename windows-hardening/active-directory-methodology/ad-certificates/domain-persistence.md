# AD CS Domain Persistence

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

* The CA certificate exists on the **CA server itself**, with its **private key protected by machine DPAPI** (unless the OS uses a TPM/HSM/other hardware for protection).
* The **Issuer** and **Subject** for the cert are both set to the **distinguished name of the CA**.
* CA certificates (and only CA certs) **have a “CA Version” extension**.
* There are **no EKUs**

The built-in GUI supported way to **extract this certificate private key** is with `certsrv.msc` on the CA server.\
However, this certificate **isn't different** from other certificates stored in the system, so for example check the [**THEFT2 technique**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) to see how to **extract** them.

You can also get the cert and private key using [**certipy**](https://github.com/ly4k/Certipy):

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Once you have the **CA cert** with the private key in `.pfx` format you can use [**ForgeCert**](https://github.com/GhostPack/ForgeCert)  to create valid certificates:

```bash
# Create new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Create new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Use new certificate with Rubeus to authenticate
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# User new certi with certipy to authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```

{% hint style="warning" %}
**Note**: The target **user** specified when forging the certificate needs to be **active/enabled** in AD and **able to authenticate** since an authentication exchange will still occur as this user. Trying to forge a certificate for the krbtgt account, for example, will not work.
{% endhint %}

This forged certificate will be **valid** until the end date specified and as **long as the root CA certificate is valid** (usually from 5 to **10+ years**). It's also valid for **machines**, so combined with **S4U2Self**, an attacker can **maintain persistence on any domain machine** for as long as the CA certificate is valid.\
Moreover, the **certificates generated** with this method **cannot be revoked** as CA is not aware of them.

## Trusting Rogue CA Certificates - DPERSIST2

The object `NTAuthCertificates` defines one or more **CA certificates** in its `cacertificate` **attribute** and AD uses it: During authentication, the **domain controller** checks if **`NTAuthCertificates`** object **contains** an entry for the **CA specified** in the authenticating **certificate’s** Issuer field. If **it is, authentication proceeds**.

An attacker could generate a **self-signed CA certificate** and **add** it to the **`NTAuthCertificates`** object. Attackers can do this if they have **control** over the **`NTAuthCertificates`** AD object (in default configurations only **Enterprise Admin** group members and members of the **Domain Admins** or **Administrators** in the **forest root’s domain** have these permissions). With the elevated access, one can **edit** the **`NTAuthCertificates`** object from any system with `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126` , or using the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).&#x20;

The specified certificate should **work with the previously detailed forgery method with ForgeCert** to generate certificates on demand.

## Malicious Misconfiguration - DPERSIST3

There is a myriad of opportunities for **persistence** via **security descriptor modifications of AD CS** components. Any scenario described in the “[Domain Escalation](domain-escalation.md)” section could be maliciously implemented by an attacker with elevated access, as well as addition of “control rights'' (i.e., WriteOwner/WriteDACL/etc.) to sensitive components. This includes:

* **CA server’s AD computer** object
* The **CA server’s RPC/DCOM server**
* Any **descendant AD object or container** in the container **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
* **AD groups delegated rights to control AD CS by default or by the current organization** (e.g., the built-in Cert Publishers group and any of its members)

For example, an attacker with **elevated permissions** in the domain could add the **`WriteOwner`** permission to the default **`User`** certificate template, where the attacker is the principal for the right. To abuse this at a later point, the attacker would first modify the ownership of the **`User`** template to themselves, and then would **set** **`mspki-certificate-name-flag`** to **1** on the template to enable **`ENROLLEE_SUPPLIES_SUBJECT`** (i.e., allowing a user to supply a Subject Alternative Name in the request). The attacker could then **enroll** in the **template**, specifying a **domain administrator** name as an alternative name, and use the resulting certificate for authentication as the DA.

## References

* All the information of this page was taken from [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
