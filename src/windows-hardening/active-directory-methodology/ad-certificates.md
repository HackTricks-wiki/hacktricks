# AD Sertifikate

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui sy eienaar aan.
- 'n **Public Key** is gepaard met 'n privaat gehoue sleutel om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, gedefinieer deur **NotBefore** en **NotAfter** datums, merk die sertifikaat se geldigheidsduur.
- 'n unieke **Serial Number**, voorsien deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat addisionele name vir die subject toe, wat identifikasie meer buigsaam maak.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n end-entiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die sertifikaat se spesifieke doeleindes, soos code signing of email encryption, deur Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Signature**, geskep met die issuer se private sleutel, waarborg die sertifikaat se egtheid.

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid na meerdere identiteite uit, noodsaaklik vir servers met meerdere domeine. Sekure uitreikprosesse is van kritieke belang om te voorkom dat aanvallers die SAN-spesifikasie manipuleer en daarmee mimiek pleeg.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD forest deur aangewese kontainers, elk met unieke rolle:

- **Certification Authorities** container hou vertroude root CA-sertifikate.
- **Enrolment Services** container beskryf Enterprise CAs en hul certificate templates.
- **NTAuthCertificates** object sluit CA-sertifikate in wat gemagtig is vir AD authentication.
- **AIA (Authority Information Access)** container fasiliteer sertifikaat-ketting validering met intermediate en cross CA sertifikate.

### Sertifikaatverkryging: Client Certificate Request-vloei

1. Die versoekproses begin met kliente wat 'n Enterprise CA vind.
2. 'n CSR word geskep, wat 'n public key en ander besonderhede bevat, nadat 'n public-private sleutelpaar gegenereer is.
3. Die CA beoordeel die CSR teen beskikbare certificate templates en keur die sertifikaat uit volgens die template se permissies.
4. Na goedkeuring teken die CA die sertifikaat met sy private sleutel en stuur dit terug aan die kliënt.

### Certificate Templates

Gedefinieer binne AD, beskryf hierdie templates die instellings en permissies vir die uitreiking van sertifikate, insluitend toegestane EKUs en enrollment of wysigingsregte, wat kritiek is vir die bestuur van toegang tot certificate services.

**Template schema version matters.** Legacy **v1** templates (byvoorbeeld die ingeboude **WebServer** template) ontbreek verskeie moderne afdwingingsknoppies. Die **ESC15/EKUwu** navorsing het getoon dat op **v1 templates**, 'n versoeker **Application Policies/EKUs** in die CSR kan insluit wat **voorkeur geniet bo** die template se geconfigureerde EKUs, wat dit moontlik maak om client-auth, enrollment agent, of code-signing sertifikate te kry met slegs enrollment regte. Gebruik verkieslik **v2/v3 templates**, verwyder of vervang v1-standaarde, en beperk EKUs noukeurig tot die beoogde doel.

## Sertifikaat Inskrywing

Die inskrywingproses vir sertifikate word geïnisieer deur 'n administrateur wat 'n **certificate template** skep, wat dan deur 'n Enterprise Certificate Authority (CA) **gepubliseer** word. Dit maak die template beskikbaar vir kliëntinskrywings — 'n stap wat bereik word deur die template se naam by die `certificatetemplates` veld van 'n Active Directory object te voeg.

Vir 'n kliënt om 'n sertifikaat aan te vra, moet **enrollment rights** toegewys wees. Hierdie regte word gedefinieer deur security descriptors op die certificate template en op die Enterprise CA self. Permissies moet op albei plekke gegee word vir 'n versoek om suksesvol te wees.

### Sjabloen Inskrywingregte

Hierdie regte word gespesifiseer deur Access Control Entries (ACEs), wat permissies soos die volgende uiteensit:

- **Certificate-Enrollment** en **Certificate-AutoEnrollment** regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide permissies toelaat.
- **FullControl/GenericAll**, wat volledige beheer oor die template gee.

### Enterprise CA Inskrywingregte

Die CA se regte word uiteengesit in sy security descriptor, toeganklik via die Certificate Authority management console. Sommige instellings laat selfs low-privileged gebruikers remote toegang toe, wat 'n sekuriteitsrisiko kan wees.

### Addisionele Uitreikbeheermaatreëls

Sekere beheermaatreëls kan van toepassing wees, soos:

- **Manager Approval**: Plaas versoeke in 'n hangende toestand totdat dit deur 'n certificate manager goedgekeur word.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Application Policy OIDs.

### Metodes om Sertifikate aan te vra

Sertifikate kan aangevra word deur:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), wat DCOM interfaces gebruik.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), in samewerking met die Certificate Enrollment Policy (CEP) service.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, wat die Simple Certificate Enrollment Protocol (SCEP) gebruik.

Windows gebruikers kan ook sertifikate vra via die GUI (`certmgr.msc` of `certlm.msc`) of opdraglynhulpmiddels (`certreq.exe` of PowerShell se `Get-Certificate` opdrag).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur gebruik te maak van **Kerberos** en **Secure Channel (Schannel)** protokolle.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) geteken met die **privaat sleutel** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie verifikasies deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad**, en **herroepingstatus**. Verifikasies sluit ook in die kontrole dat die sertifikaat van 'n betroubare bron kom en die bevestiging van die uitreiker se teenwoordigheid in die **NTAUTH certificate store**. Suksesvolle verifikasies lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`** objek in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal vir die vestiging van vertroue vir sertifikaatautentisering.

### Secure Channel (Schannel) Authentication

Schannel fasiliteer veilige TLS/SSL-verbindinge, waar tydens 'n handshake die kliënt 'n sertifikaat voorlê wat, indien suksesvol gevalideer, toegang magtig. Die toewysing van 'n sertifikaat aan 'n AD-rekening kan Kerberos se **S4U2Self** funksie of die sertifikaat se **Subject Alternative Name (SAN)** betrek, onder andere metodes.

### AD Certificate Services Enumeration

AD se sertifikaatdienste kan via LDAP-navrae gelys word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies openbaar. Dit is toeganklik vir enige domein-geauthentiseerde gebruiker sonder spesiale voorregte. Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsassessering in AD CS-omgewings.

Kommando's vir die gebruik van hierdie gereedskap sluit in:
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

## Onlangse Kwesbaarhede & Sekuriteitsopdaterings (2022-2025)

| Jaar | ID / Naam | Invloed | Belangrike punte |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft verharding tydlyn (KB5014754)

Microsoft het 'n drie-fase uitrol ingestel (Compatibility → Audit → Enforcement) om Kerberos certificate authentication weg te skuif van swak implisiete mappings. As of **February 11 2025**, domain controllers skakel outomaties na **Full Enforcement** as die `StrongCertificateBindingEnforcement` registry value nie gestel is nie. Administrateurs moet:

1. Werk al die DCs & AD CS servers by (May 2022 of later).
2. Monitor Event ID 39/41 vir swak mappings tydens die *Audit* fase.
3. Her-uitreik client-auth certificates met die nuwe **SID extension** of konfigureer sterk handmatige mappings voor February 2025.

---

## Opsporing & Verhardingsverbeterings

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## Verwysings

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
