# AD Certificates

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

### Parts of a certificate

* **Subject** - The owner of the certificate.
* **Public Key** - Associates the Subject with a private key stored separately.
* **NotBefore and NotAfter dates** - Define the duration that the certificate is valid.
* **Serial Number** - An identifier for the certificate assigned by the CA.
* **Issuer** - Identifies who issued the certificate (commonly a CA).
* **SubjectAlternativeName** - Defines one or more alternate names that the Subject may go by. (_Check below_)
* **Basic Constraints** - Identifies if the certificate is a CA or an end entity, and if there are any constraints when using the certificate.
* **Extended Key Usages (EKUs)** - Object identifiers (OIDs) that describe **how the certificate will be used**. Also known as Enhanced Key Usage in Microsoft parlance. Common EKU OIDs include:
  * Code Signing (OID 1.3.6.1.5.5.7.3.3) - The certificate is for signing executable code.
  * Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - The certificate is for encrypting file systems.
  * Secure Email (1.3.6.1.5.5.7.3.4) - The certificate is for encrypting email.
  * Client Authentication (OID 1.3.6.1.5.5.7.3.2) - The certificate is for authentication to another server (e.g., to AD).
  * Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - The certificate is for use in smart card authentication.
  * Server Authentication (OID 1.3.6.1.5.5.7.3.1) - The certificate is for identifying servers (e.g., HTTPS certificates).
* **Signature Algorithm** - Specifies the algorithm used to sign the certificate.
* **Signature** - The signature of the certificates body made using the issuer’s (e.g., a CA’s) private key.

#### Subject Alternative Names

A **Subject Alternative Name** (SAN) is an X.509v3 extension. It allows **additional identities** to be bound to a **certificate**. For example, if a web server hosts **content for multiple domains**, **each** applicable **domain** could be **included** in the **SAN** so that the web server only needs a single HTTPS certificate.

By default, during certificate-based authentication, one way AD maps certificates to user accounts based on a UPN specified in the SAN. If an attacker can **specify an arbitrary SAN** when requesting a certificate that has an **EKU enabling client authentication**, and the CA creates and signs a certificate using the attacker supplied SAN, the **attacker can become any user in the domain**.

### CAs

AD CS defines CA certificates the AD forest trusts in four locations under the container `CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`, each differing by their purpose:

* The **Certification Authorities** container defines **trusted root CA certificates**. These CAs are at the **top of the PKI tree hierarchy** and are the basis of trust in AD CS environments. Each CA is represented as an AD object inside the container where the **objectClass** is set to **`certificationAuthority`** and the **`cACertificate`** property contains the **bytes** of the **CA’s certificate**. Windows propagates these CA certificates to the Trusted Root Certification Authorities certificate store on **each Windows machine**. For AD to consider a certificate as **trusted**, the certificate’s trust **chain** must eventually **end** with **one of the root CA’s** defined in this container.
* The **Enrolment Services** container defines each **Enterprise CA** (i.e., CAs created in AD CS with the Enterprise CA role enabled). Each Enterprise CA has an AD object with the following attributes:
  * An **objectClass** attribute to **`pKIEnrollmentService`**
  * A **`cACertificate`** attribute containing the **bytes of the CA’s certificate**
  * A **`dNSHostName`** property sets the **DNS host of the CA**
  * A **certificateTemplates** field defining the **enabled certificate templates**. Certificate templates are a “blueprint” of settings that the CA uses when creating a certificate, and include things such as the EKUs, enrollment permissions, the certificate’s expiration, issuance requirements, and cryptography settings. We will discuss certificate templates more in detail later.

{% hint style="info" %}
In AD environments, **clients interact with Enterprise CAs to request a certificate** based on the settings defined in a certificate template. Enterprise CA certificates are propagated to the Intermediate Certification Authorities certificate store on each Windows machine
{% endhint %}

* The **NTAuthCertificates** AD object defines CA certificates that enable authentication to AD. This object has an **objectClass** of **`certificationAuthority`** and the object’s **`cACertificate`** property defines an array of **trusted CA certificates**. AD-joined Windows machines propagate these CAs to the Intermediate Certification Authorities certificate store on each machine. **Client** applications can **authenticate** to AD using a certificate only if one the **CAs defined by the NTAuthCertificates** object has **signed** the authenticating client’s certificate.
* The **AIA** (Authority Information Access) container holds the AD objects of intermediate and cross CAs. **Intermediate CAs are “children” of root CAs** in the PKI tree hierarchy; as such, this container exists to aid in **validating certificate chains**. Like the Certification Authorities container, each **CA is represented as an AD object** in the AIA container where the objectClass attribute is set to certificationAuthority and the **`cACertificate`** property contains the **bytes** of the **CA’s certificate**. These CAs are propagated to the Intermediate Certification Authorities certificate store on each Windows machine.

### Client Certificate Request Flow

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

It's the process to **obtain a certificate** from AD CS. At a high level, during enrolment clients first **find an Enterprise CA** based on the **objects in the Enrolment Services** container discussed above.

1. Clients then generate a **public-private key pair** and
2. place the public key in a **certificate signing request (CSR)** message along with other details such as the subject of the certificate and the **certificate template name**. Clients then **sign the CSR with their private key** and send the CSR to an Enterprise CA server.
3. The **CA** server checks if the client **can request certificates**. If so, it determines if it will issue a certificate by looking up the **certificate template** AD object specified in the CSR. The CA will check if the certificate template AD object’s **permissions allow** the authenticating account to **obtain a certificate**.
4. If so, the **CA generates a certificate** using the “blueprint” settings defined by the **certificate template** (e.g., EKUs, cryptography settings, and issuance requirements) and using the other information supplied in the CSR if allowed by the certificate’s template settings. The **CA signs the certificate** using its private key and then returns it to the client.

### Certificate Templates

AD CS stores available certificate templates as AD objects with an **objectClass** of **`pKICertificateTemplate`** located in the following container:

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

An AD certificate template object’s attributes **define its settings, and its security descriptor controls** what **principals can enrol** in the certificate or **edit** the certificate template.

The **`pKIExtendedKeyUsage`** attribute on an AD certificate template object contains an **array of OIDs** enabled in the template. These EKU OIDs affect **what the certificate can be used for.** You can find a [list of possible OIDs here](https://www.pkisolutions.com/object-identifiers-oid-in-pki/).

#### Authentication OIDs

* `1.3.6.1.5.5.7.3.2`: Client Authentication
* `1.3.6.1.5.2.3.4`: PKINIT Client Authentication (needed to be added manually)
* `1.3.6.1.4.1.311.20.2.2`: Smart Card Logon
* `2.5.29.37.0`: Any purpose
* `(no EKUs)`: SubCA
* An additional EKU OID that we found we could abuse is the Certificate Request Agent OID (`1.3.6.1.4.1.311.20.2.1`). Certificates with this OID can be used to **request certificates on behalf of another user** unless specific restrictions are put in place.

## Certificate Enrolment

An admin needs to **create the certificate** template and then an **Enterprise CA “publishes”** the template, making it available to clients to enrol in. AD CS specifies that a certificate template is enabled on an Enterprise CA by **adding the template’s name to the `certificatetemplates` field** of the AD object.

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
AD CS defines enrolment rights - which **principals can request** a certificate – using two security descriptors: one on the **certificate template** AD object and another on the **Enterprise CA itself**.\
A client needs to be granted in both security descriptors in order to be able to request a certificate.
{% endhint %}

### Certificate Templates Enrolment Rights

* **The ACE grants a principal the Certificate-Enrollment extended right**. The raw ACE grants principal the `RIGHT_DS_CONTROL_ACCESS45` access right where the **ObjectType** is set to `0e10c968-78fb-11d2-90d4-00c04f79dc5547`. This GUID corresponds with the **Certificate-Enrolment** extended right.
* **The ACE grants a principal the Certificate-AutoEnrollment extended right**. The raw ACE grants principal the `RIGHT_DS_CONTROL_ACCESS48` access right where the **ObjectType** is set `to a05b8cc2-17bc-4802-a710-e7c15ab866a249`. This GUID corresponds with the **Certificate-AutoEnrollment** extended right.
* **An ACE grants a principal all ExtendedRights**. The raw ACE enables the `RIGHT_DS_CONTROL_ACCESS` access right where the **ObjectType** is set to `00000000-0000-0000-0000-000000000000`. This GUID corresponds with **all extended rights**.
* **An ACE grants a principal FullControl/GenericAll**. The raw ACE enables the FullControl/GenericAll access right.

### Enterprise CA Enrolment Rights

The **security descriptor** configured on the **Enterprise CA** defines these rights and is **viewable** in the Certificate Authority MMC snap-in `certsrv.msc` by right clicking on the CA → Properties → Security.

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

This ultimately ends up setting the Security registry value in the key **`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`** on the CA server. We have encountered several AD CS servers that grant low-privileged users remote access to this key via remote registry:

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

Low-privileged users can also **enumerate this via DCOM** using the `ICertAdminD2` COM interface’s `GetCASecurity` method. However, normal Windows clients need to install the Remote Server Administration Tools (RSAT) to use it since the COM interface and any COM objects that implement it are not present on Windows by default.

### Issuance Requirements

Other requirements could be in place to control who can get a certificate.

#### Manager Approval

**CA certificate manager approval** results in the certificate template setting the `CT_FLAG_PEND_ALL_REQUESTS` (0x2) bit on the AD object’s `msPKI-EnrollmentFlag` attribute. This puts all **certificate requests** based on the template into the **pending state** (visible in the “Pending Requests” section in `certsrv.msc`), which requires a certificate manager to **approve or deny** the request before the certificate is issued:

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### Enrolment Agents, Authorized Signatures, and Application Policies

**This number of authorized signatures** and the **Application policy**. The former controls the **number of signatures required** in the CSR for the CA to accept it. The latter defines the **EKU OIDs that the CSR signing certificate must have**.

A common use for these settings is for **enrolment agents**. An enrolment agent is an AD CS term given to an entity that can **request certificates on behalf of another user**. To do so, the CA must issue the enrolment agent account a certificate containing at least the **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1). Once issued, the enrolment agent can then **sign CSRs and request certificates on behalf of other users**. The CA will **issue** the enrolment agent a **certificate** as **another user** only under the following non-comprehensive set of **conditions** (implemented primarily in default policy module `certpdef.dll`):

* The Windows user authenticating to the CA has enrolment rights to the target certificate template.
* If the certificate template’s schema version is 1, the CA will require signing certificates to have the Certificate Request Agent OID before issuing the certificate. The template’s schema version is the specified in its AD object’s msPKI-Template-Schema-Version property.
* If the certificate template’s schema version is 2:
  * The template must set the “This number of authorized signatures” setting and the specified number of enrolment agents must sign the CSR (the template’s mspkira-signature AD attribute defines this setting). In other words, this setting specifies how many enrollment agents must sign a CSR before the CA even considers issuing a certificate.
  * The template’s “Application policy” issuance restriction must be set to “Certificate Request Agent”.

### Request Certificates

1. Using the Windows **Client Certificate Enrolment Protocol** (MS-WCCE), a set of Distributed Component Object Model (DCOM) interfaces that interact with various AD CS features including enrolment. The **DCOM server is enabled on all AD CS servers by default** and is the most common method by which we have seen clients request certificates.
2. Via the **ICertPassage Remote Protocol** (MS-ICPR), a **remote procedure call** (RPC) protocol can operate over named pipes or TCP/IP.
3. Accessing the **certificate enrolment web interface**. To use this, the ADCS server needs to have the **Certificate Authority Web Enrolment role installed**. Once enabled, a user can navigate to the IIS-hosted ASP web enrolment application running at `http:///certsrv/`.
   * `certipy req -ca 'corp-DC-CA' -username john@corp.local -password Passw0rd -web -debug`
4. Interacting with a **certificate enrolment service** (CES). To use this, a server needs to have the **Certificate Enrolment Web Service role installed**. Once enabled, a user can access the web service at `https:///_CES_Kerberos/service.svc` to request certificates. This service works in tandem with a certificate enrolment policy (CEP) service (installed via the Certificate Enrolment Policy Web Service role), which clients use to **list certificate templates** at the URL `https:///ADPolicyProvider_CEP_Kerberos/service.svc`. Underneath, the certificate enrolment and policy web services implement MS-WSTEP and MS-XCEP, respectively (two SOAP-based protocols).
5. Using the **network device enrolment service**. To use this, a server needs to have the **Network Device Enrolment Service role installed**, which allows clients (namely network devices) to obtain certificates via the **Simple Certificate Enrolment Protocol** (SCEP). Once enabled, an administrator can obtain a one-time password (OTP) from the URL `http:///CertSrv/mscep_admin/`. The administrator can then provide the OTP to a network device and the device will use the SCEP to request a certificate using the URL `http://NDESSERVER/CertSrv/mscep/`.

On a Windows machine, users can request certificates using a GUI by launching `certmgr.msc` (for user certificates) or `certlm.msc` (for computer certificates), expanding the Personal certificate `store → right clicking Certificates → All Tasks → Request New Certificate`.

One can also use the built-in **`certreq.exe`** command or PowerShell’s **`Get-Certificate`** command for certificate enrolment.

## Certificate Authentication

AD supports certificate authentication over **two protocols** by default: **Kerberos** and **Secure Channel** (Schannel).

### Kerberos Authentication and the NTAuthCertificates Container

In summary, a user will **sign** the authenticator for a **TGT request** using the **private key** of their certificate and submit this request to a **domain controller**. The domain controller performs a number of **verification** steps and **issues a TGT** if everything **passes**.

Or, more detailed:

> The **KDC** **validates** the **user's certificate** (time, path, and revocation status) to ensure that the certificate is from a trusted source. The KDC uses CryptoAPI to build a **certification path** from the user's certificate to a **root certification authority** (CA) certificate that resides in the **root store** on the domain controller. The KDC then uses CryptoAPI to verify the **digital signature** on the signed authenticator that was included in the preauthentication data fields. The domain controller verifies the signature and uses the public key from the user's certificate to prove that the request originated from the owner of the private key that corresponds to the public key. **The KDC also verifies that the issuer is trusted and appears in the NTAUTH certificate store.**

The “NTAUTH certificate store” mentioned here refers to an AD object AD CS installs at the following location:

`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

> By publishing the **CA certificate to the Enterprise NTAuth store**, the Administrator indicates that the **CA is trusted** to issue certificates of these types. Windows CAs automatically publish their CA certificates to this store.

This means that when **AD CS creates a new CA** (or it renews CA certificates), it publishes the new certificate to the **`NTAuthCertificates`** object by adding the new certificate to the object’s `cacertificate` attribute:

<figure><img src="../../.gitbook/assets/image (9) (2).png" alt=""><figcaption></figcaption></figure>

During certificate authentication, the DC can then verify that the authenticating certificate chains to a CA certificate defined by the **`NTAuthCertificates`** object. CA certificates in the **`NTAuthCertificates`** object must in turn chain to a root CA. The big takeaway here is the **`NTAuthCertificates`** object is the root of trust for certificate authentication in Active Directory!

### Secure Channel (Schannel) Authentication

Schannel is the security support provider (SSP) Windows leverages when establishing TLS/SSL connections. Schannel supports **client authentication** (amongst many other capabilities), enabling a remote server to **verify the identity of the connecting user**. It accomplishes this using PKI, with certificates being the primary credential.\
During the **TLS handshake**, the server **requests a certificate from the client** for authentication. The client, having previously been issued a client authentication certificate from a CA the server trusts, sends its certificate to the server. The **server then validates** the certificate is correct and grants the user access assuming everything is okay.

<figure><img src="../../.gitbook/assets/image (8) (2) (1).png" alt=""><figcaption></figcaption></figure>

When an account authenticates to AD using a certificate, the DC needs to somehow map the certificate credential to an AD account. **Schannel** first attempts to **map** the **credential** to a **user** account use Kerberos’s **S4U2Self** functionality.\
If that is **unsuccessful**, it will follow the attempt to map the **certificate to a user** account using the certificate’s **SAN extension**, a combination of the **subject** and **issuer** fields, or solely from the issuer. By default, not many protocols in AD environments support AD authentication via Schannel out of the box. WinRM, RDP, and IIS all support client authentication using Schannel, but it **requires additional configuration**, and in some cases – like WinRM – does not integrate with Active Directory.\
One protocol that does commonly work – assuming AD CS has been setup - is **LDAPS**. The cmdlet `Get-LdapCurrentUser` demonstrates how one can authenticate to LDAP using .NET libraries. The cmdlet performs an LDAP “Who am I?” extended operation to display the currently authenticating user:

<figure><img src="../../.gitbook/assets/image (2) (4).png" alt=""><figcaption></figcaption></figure>

## AD CS Enumeration

Just like for most of AD, all the information covered so far is available by querying LDAP as a domain authenticated, but otherwise unprivileged, user.

If we want to **enumerate Enterprise CAs** and their settings, one can query LDAP using the `(objectCategory=pKIEnrollmentService)` LDAP filter on the `CN=Configuration,DC=<domain>,DC=<com>` search base (this search base corresponds with the Configuration naming context of the AD forest). The results will identify the DNS hostname of the CA server, the CA name itself, the certificate start and end dates, various flags, published certificate templates, and more.

**Tools to enumerate vulnerable certificates:**

* [**Certify**](https://github.com/GhostPack/Certify) is a C# tool that can **enumerate useful configuration and infrastructure information about of AD CS environments** and can request certificates in a variety of different ways.
* [**Certipy**](https://github.com/ly4k/Certipy) is a **python** tool to be able to **enumerate and abuse** Active Directory Certificate Services (**AD CS**) **from any system** (with access to the DC) that can generate output for BloodHound created by [**Lyak**](https://twitter.com/ly4k\_) (good person better hacker) .

```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```

## References

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
