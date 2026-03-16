# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

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

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.

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
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) inaunga mkono uthibitishaji wa vyeti, kwa kawaida ikitumia protokoli za **Kerberos** na **Secure Channel (Schannel)**.

### Kerberos Authentication Process

Katika mchakato wa uthibitishaji wa Kerberos, ombi la mtumiaji la Ticket Granting Ticket (TGT) linasainiwa kwa kutumia **funguo binafsi** ya cheti cha mtumiaji. Ombi hili hupitia uthibitisho kadhaa na domain controller, ikiwa ni pamoja na **uhalali**, **njia**, na **hali ya kufutwa** ya cheti. Uthibitisho pia unajumuisha kuthibitisha kwamba cheti kimetoka kwa chanzo kinachotegemewa na kuthibitisha uwepo wa mtumaji katika **NTAUTH certificate store**. Uthibitisho uliofanikiwa husababisha utolewaji wa TGT. Kitu cha **`NTAuthCertificates`** katika AD, kinachopatikana katika:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ni muhimu katika kuanzisha uaminifu kwa uthibitishaji wa vyeti.

### Secure Channel (Schannel) Authentication

Schannel inarahisisha miunganisho salama ya TLS/SSL, ambapo wakati wa handshake, mteja huwasilisha cheti ambacho, ikiwa kitatambuliwa kwa mafanikio, kinaruhusu upatikanaji. Kuoanisha cheti na akaunti ya AD kunaweza kujumuisha kipengele cha Kerberos **S4U2Self** au **Subject Alternative Name (SAN)** ya cheti, miongoni mwa mbinu nyingine.

### AD Certificate Services Enumeration

Certificate services za AD zinaweza kuorodheshwa kupitia maswali ya LDAP, zikifunua taarifa kuhusu **Enterprise Certificate Authorities (CAs)** na mipangilio yao. Hii inapatikana kwa mtumiaji yeyote aliyeathibitishwa kwenye domain bila vibali maalum. Zana kama **[Certify](https://github.com/GhostPack/Certify)** na **[Certipy](https://github.com/ly4k/Certipy)** zinatumika kwa uorodheshaji na tathmini ya udhaifu katika mazingira ya AD CS.

Amri za kutumia zana hizi ni pamoja na:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Udhaifu za Karibuni & Sasisho za Usalama (2022-2025)

| Mwaka | ID / Jina | Athari | Vidokezo Muhimu |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* kwa kuiga vyeti vya akaunti za mashine wakati wa PKINIT. | Patch imejumuishwa katika sasisho za usalama za **May 10 2022**. Ukaguzi & udhibiti wa strong-mapping zilianzishwa kupitia **KB5014754**; mazingira yanapaswa sasa kuwa katika mode ya *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* kwenye AD CS Web Enrollment (certsrv) na majukumu ya CES. | PoC za umma ni chache, lakini vipengele vya IIS vilivyo na dosari mara nyingi vinafichuka ndani ya mtandao. Patch ilitolewa **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Kwa v1 templates, mtumaji mwenye haki za enrollment anaweza kuweka ndani ya CSR **Application Policies/EKUs** ambazo zinalinganishwa na EKUs za template, zikitoa vyeti vya client-auth, enrollment agent, au code-signing. | Imepachikwa tarehe **November 12, 2024**. Badilisha au ziba v1 templates (mfano, default WebServer), punguza EKUs kwa mujibu wa matumizi, na zuia haki za enrollment. |

### Ratiba ya kuimarisha Microsoft (KB5014754)

Microsoft ilianzisha utaratibu wa hatua tatu (Compatibility → Audit → Enforcement) ili kusogeza uthibitishaji wa vyeti vya Kerberos kutoka kwenye ramani dhaifu zisizo wazi. Kuanzia **February 11 2025**, domain controllers hujibadilishia moja kwa moja hadi **Full Enforcement** ikiwa thamani ya rejista `StrongCertificateBindingEnforcement` haijawekwa. Wasimamizi wanapaswa:

1. Patch DC zote & seva za AD CS (May 2022 au baadaye).
2. Monitor Event ID 39/41 kwa ramani dhaifu wakati wa awamu ya *Audit*.
3. Toa upya vyeti vya client-auth zikiwa na **SID extension** mpya au sanidi strong manual mappings kabla ya Februari 2025.

---

## Ugundaji & Uimarishaji wa Usalama

* **Defender for Identity AD CS sensor (2023-2024)** sasa inaonyesha tathmini za nafasi kwa ESC1-ESC8/ESC11 na inatengeneza arifu za wakati halisi kama *“Domain-controller certificate issuance for a non-DC”* (ESC8) na *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Hakikisha sensors zimewekwa kwenye seva zote za AD CS ili kunufaika na ugunduzi huu.
* Disable au weka mipaka kwa njia kali chaguo la **“Supply in the request”** kwenye templates zote; pendelea SAN/EKU zilizo wazi kwa ajili.
* Ondoa **Any Purpose** au **No EKU** kutoka kwa templates isipokuwa zinahitajika kabisa (hii inashughulikia matukio ya ESC2).
* Inyatie idhini ya meneja au workflows za Enrollment Agent za kujitolea kwa templates nyeti (mfano, WebServer / CodeSigning).
* Zuia web enrollment (`certsrv`) na endpoints za CES/NDES kwa mitandao ya kuaminika au zifichwe nyuma ya uthibitishaji wa client-certificate.
* Tekeleza encryption ya RPC enrollment (certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST) ili kupunguza ESC11 (RPC relay). Bendera hii iko **on by default**, lakini mara nyingi imezimwa kwa wateja wa zamani, ambayo inafungua tena hatari ya relay.
* Secured endpoints za enrollment zinazotegemea IIS (CES/Certsrv): zima NTLM inapowezekana au hitaji HTTPS + Extended Protection ili kuzuia relay za ESC8.

---



## Marejeo

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
