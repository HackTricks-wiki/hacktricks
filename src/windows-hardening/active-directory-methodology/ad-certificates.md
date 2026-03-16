# AD Sertifikate

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar aan.
- 'n **Public Key** word gepaard met 'n privaat sleutel om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, gedefinieer deur die **NotBefore** en **NotAfter** datums, merk die sertifikaat se geldigheidsduur.
- 'n Unieke **Serial Number**, verskaf deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat addisionele name vir die subject toe en verbeter identifikasie-fleksibiliteit.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n end-entiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** bepaal die sertifikaat se spesifieke doeleindes, soos code signing of e-pos enkripsie, deur Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Signature**, geskep met die uitreiker se private sleutel, waarborg die sertifikaat se egtheid.

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid uit na veelvuldige identiteite, wat belangrik is vir servers met verskeie domeine. Sekere uitreikprosesse moet goed beveilig wees om te voorkom dat aanvallers die SAN-spesifikasie manipuleer en persoonkapingsrisiko veroorsaak.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD-forest deur aangewezen houers, elk met 'n spesifieke rol:

- **Certification Authorities** container hou vertroude root CA-sertifikate.
- **Enrolment Services** container bevat besonderhede oor Enterprise CAs en hul certificate templates.
- **NTAuthCertificates** object sluit CA-sertifikate in wat gemagtig is vir AD-authentisering.
- **AIA (Authority Information Access)** container fasiliteer sertifikaatketting-validasie met intermediate en cross CA-sertifikate.

### Sertifikaatverkryging: Vloei van Klient Sertifikaatversoek

1. Die versoekproses begin deurdat kliënte 'n Enterprise CA vind.
2. 'n CSR word geskep wat 'n public key en ander besonderhede bevat, nadat 'n publieke-privaat sleutelpaar gegenereer is.
3. Die CA evalueer die CSR teen beskikbare certificate templates en gee die sertifikaat uit gebaseer op die template se magte.
4. Na goedkeuring teken die CA die sertifikaat met sy private sleutel en stuur dit terug na die kliënt.

### Sertifikaat-sjablone

In AD gedefinieer, beskryf hierdie templates die instellings en regte vir die uitreiking van sertifikate, insluitend toegelate EKUs en inskrywing- of wysigingsregte — kritiek vir die bestuur van toegang tot sertifikaatdienste.

Template-skemaversie maak saak. Legacy **v1** templates (byvoorbeeld die ingeboude **WebServer** template) ontbreek verskeie moderne afdwingingsopsies. Die **ESC15/EKUwu** navorsing het getoon dat op **v1 templates** 'n versoeker Application Policies/EKUs in die CSR kan inbed wat voorkom bo die template se geconfigureerde EKUs, wat dit moontlik maak om client-auth, enrollment agent of code-signing sertifikate te kry met slegs enrollment-regte. Gebruik voorkeurlik **v2/v3 templates**, verwyder of vervang v1-standaarde, en beperk EKUs nou tot die beoogde doel.

## Sertifikaatinskrywing

Die inskrywingsproses vir sertifikate word geïnisieer deur 'n administrateur wat 'n sertifikaattemplate skep, wat dan deur 'n Enterprise Certificate Authority (CA) gepubliseer word. Dit maak die template beskikbaar vir kliëntinskrywings — 'n stap wat bereik word deur die template se naam by die `certificatetemplates` veld van 'n Active Directory-objek te voeg.

Vir 'n kliënt om 'n sertifikaat te versoek, moet inskrywingsregte toegeken wees. Hierdie regte word gedefinieer deur security descriptors op beide die sertifikaattemplate en op die Enterprise CA self. Permissies moet in albei plekke toegeken word vir 'n versoek om suksesvol te wees.

### Template Inskrivyingsregte

Hierdie regte word gespesifiseer deur Access Control Entries (ACEs) en beskryf permissies soos:

- **Certificate-Enrollment** en **Certificate-AutoEnrollment** regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide permissies moontlik maak.
- **FullControl/GenericAll**, wat volledige beheer oor die template gee.

### Enterprise CA Inskrivyingsregte

Die CA se regte word uiteengesit in sy security descriptor, toeganklik via die Certificate Authority management console. Sommige instellings laat selfs toe dat laag-geprivilegieerde gebruikers op afstand toegang kry, wat 'n sekuriteitsrisiko kan wees.

### Addisionele Uitreikbeheer

Sekere beheermaatreëls kan van toepassing wees, soos:

- **Manager Approval**: Plaas versoeke in 'n hangende toestand totdat 'n sertifikaatbestuurder goedkeur.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Application Policy OIDs.

### Metodes om Sertifikate te Versoek

Sertifikate kan versoek word via:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), gebruikmakend van DCOM-interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), in samewerking met die Certificate Enrollment Policy (CEP) diens.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, gebruikmakend van die Simple Certificate Enrollment Protocol (SCEP).

Windows-gebruikers kan ook sertifikate versoek via die GUI (`certmgr.msc` of `certlm.msc`) of op die opdragreëllyn met `certreq.exe` of PowerShell se `Get-Certificate` command.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaatautentisering

Active Directory (AD) ondersteun sertifikaatautentisering, hoofsaaklik deur gebruik te maak van **Kerberos** en **Secure Channel (Schannel)** protokolle.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek vir 'n Ticket Granting Ticket (TGT) geteken met die **privaat sleutel** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie verifikasies deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad**, en **herroepingsstatus**. Verifikasies sluit ook in om te bevestig dat die sertifikaat van 'n betroubare bron kom en om die uitgewer se teenwoordigheid in die **NTAUTH certificate store** te bevestig. Suksesvolle verifikasies lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`** objek in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.

### Secure Channel (Schannel) Authentication

Schannel fasiliteer veilige TLS/SSL-verbindinge, waar tydens 'n handshake die kliënt 'n sertifikaat aanbied wat, indien suksesvol gevalideer, toegang magtig. Die toewysing van 'n sertifikaat aan 'n AD-rekening kan Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** insluit, onder andere metodes.

### AD Certificate Services Enumeration

AD se sertifikaatdienste kan deur LDAP-navrae opgesom word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies openbaar. Dit is toeganklik vir enige domein-geauthentiseerde gebruiker sonder spesiale voorregte. Gereedskap soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsassessering in AD CS-omgewings.

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

| Year | ID / Naam | Impak | Belangrike punte |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is ingesluit in die **May 10 2022** sekuriteitsopdaterings. Oudit- en strong-mapping-beheer is ingevoer via **KB5014754**; omgewings behoort nou in *Full Enforcement*-modus te wees.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Publieke PoCs is beperk, maar die kwesbare IIS-komponente is dikwels intern blootgestel. Patch beskikbaar vanaf **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Gepatch op **November 12, 2024**. Vervang of supersede v1 templates (bv. default WebServer), beperk EKUs tot die bedoelde doel, en beperk enrollment-regte. |

### Microsoft verhardingstydlyn (KB5014754)

Microsoft het 'n drie-fase uitrol (Compatibility → Audit → Enforcement) ingestel om Kerberos certificate authentication weg te skuif van swak implisiete mappings. Vanaf **February 11 2025** skakel domain controllers outomaties na **Full Enforcement** indien die `StrongCertificateBindingEnforcement` registerwaarde nie gestel is nie. Administrateurs moet:

1. Patch alle DCs & AD CS servers (May 2022 of later).
2. Monitor Event ID 39/41 vir swak mappings tydens die *Audit*-fase.
3. Hernu client-auth sertifikate met die nuwe **SID extension** of konfigureer strong manual mappings voor February 2025.

---

## Opsporing en Verhardingsverbeterings

* **Defender for Identity AD CS sensor (2023-2024)** toon nou posture assessments vir ESC1-ESC8/ESC11 en genereer real-time alerts soos *“Domain-controller certificate issuance for a non-DC”* (ESC8) en *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Verseker dat sensors op alle AD CS servers uitgerol is om voordeel te trek uit hierdie detections.
* Deaktiveer of beperk streng die **“Supply in the request”** opsie op alle templates; verkies eksplisiet gedefinieerde SAN/EKU waardes.
* Verwyder **Any Purpose** of **No EKU** van templates tensy dit absoluut vereis is (adresser ESC2 scenario's).
* Vereis **manager approval** of toegewyde Enrollment Agent workflows vir sensitiewe templates (bv. WebServer / CodeSigning).
* Beperk web enrollment (`certsrv`) en CES/NDES endpoints tot betroubare netwerke of agter client-certificate authentication.
* Handhaaf RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) om ESC11 (RPC relay) te verminder. Die vlag is **on by default**, maar word dikwels gedeaktiveer vir legacy clients, wat die relay-risiko heropen.
* Beveilig **IIS-based enrollment endpoints** (CES/Certsrv): deaktiveer NTLM waar moontlik of vereis HTTPS + Extended Protection om ESC8 relays te blokkeer.

---



## Verwysings

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
