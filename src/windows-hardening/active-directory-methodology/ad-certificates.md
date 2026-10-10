# AD-sertifikate

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar daarvan aan.
- 'n **Public Key** word met 'n privaat gehoude sleutel gepaar om die sertifikaat aan die regmatige eienaar daarvan te koppel.
- Die **Validity Period**, wat deur die **NotBefore**- en **NotAfter**-datums bepaal word, dui die tydperk aan waartydens die sertifikaat geldig is.
- 'n Unieke **Serial Number**, wat deur die Certificate Authority (CA) toegeken word, identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat bykomende name vir die onderwerp toe, wat buigsaamheid in identifikasie verbeter.
- **Basic Constraints** bepaal of die sertifikaat vir 'n CA of 'n eindentiteit is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die spesifieke doeleindes van die sertifikaat, soos kodeondertekening of e-pos-enkripsie, deur middel van Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode waarmee die sertifikaat onderteken word.
- Die **Signature**, wat met die private sleutel van die uitreiker geskep word, waarborg die egtheid van die sertifikaat.<sup>[[4]](#references)</sup>

### Spesiale oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepaslikheid uit na verskeie identiteite, wat noodsaaklik is vir bedieners met verskeie domeine. Veilige uitreikingsprosesse is noodsaaklik om die risiko te vermy dat aanvallers hulself voordoen deur die SAN-spesifikasie te manipuleer.<sup>[[4]](#references)</sup>

### Sertifikaatowerhede (CAs) in Active Directory (AD)

AD CS herken CA-sertifikate in 'n AD-woud deur middel van aangewese houers, wat elk 'n unieke rol vervul:<sup>[[4]](#references)</sup>

- Die **Certification Authorities**-houer bevat vertroude wortel-CA-sertifikate.
- Die **Enrolment Services**-houer bevat besonderhede oor Enterprise CAs en hul sertifikaatsjablone.
- Die **NTAuthCertificates**-objek bevat CA-sertifikate wat vir AD-verifikasie gemagtig is.
- Die **AIA (Authority Information Access)**-houer vergemaklik sertifikaatkettingvalidering met intermediêre en kruis-CA-sertifikate.

### Verkryging van sertifikate: Vloei van 'n kliëntsertifikaatversoek

1. Die versoekproses begin wanneer kliënte 'n Enterprise CA vind.
2. Nadat 'n publieke-private sleutelpaar gegenereer is, word 'n CSR geskep wat 'n publieke sleutel en ander besonderhede bevat.
3. Die CA beoordeel die CSR aan die hand van beskikbare sertifikaatsjablone en reik die sertifikaat uit volgens die sjabloon se toestemmings.
4. Ná goedkeuring onderteken die CA die sertifikaat met sy private sleutel en stuur dit aan die kliënt terug.<sup>[[4]](#references)</sup>

### Sertifikaatsjablone

Hierdie sjablone, wat binne AD gedefinieer word, beskryf die instellings en toestemmings vir die uitreiking van sertifikate, insluitend toegelate EKUs en registrasie- of wysigingsregte. Hulle is noodsaaklik om toegang tot sertifikaatdienste te bestuur.<sup>[[4]](#references)</sup>

**Die sjabloonskemaversion is belangrik.** Ouer **v1**-sjablone (byvoorbeeld die ingeboude **WebServer**-sjabloon) het nie verskeie moderne afdwingingsinstellings nie. Die **ESC15/EKUwu**-navorsing het gewys dat 'n versoeker op **v1-sjablone** **Application Policies/EKUs** in die CSR kan insluit wat **voorrang geniet bo** die EKUs wat in die sjabloon opgestel is. Dit maak client-auth-, enrollment agent- of kodeondertekeningsertifikate moontlik met slegs registrasieregte. Gebruik eerder **v2/v3-sjablone**, verwyder of vervang die v1-verstekwaardes, en beperk EKUs streng tot die beoogde doel.<sup>[[1]](#references)</sup>

## Sertifikaatregistrasie

Die registrasieproses vir sertifikate begin wanneer 'n administrateur **'n sertifikaatsjabloon skep**, wat dan deur 'n Enterprise Certificate Authority (CA) **gepubliseer** word. Dit maak die sjabloon vir kliëntregistrasie beskikbaar. Dit word gedoen deur die sjabloon se naam by die `certificatetemplates`-veld van 'n Active Directory-objek te voeg.<sup>[[4]](#references)</sup>

Om 'n sertifikaat aan te vra, moet 'n kliënt **registrasieregte** hê. Hierdie regte word bepaal deur sekuriteitsbeskrywers op die sertifikaatsjabloon en die Enterprise CA self. Toestemmings moet op albei plekke toegeken word vir 'n versoek om suksesvol te wees.

### Registrasieregte vir sjablone

Hierdie regte word deur Access Control Entries (ACEs) gespesifiseer, wat toestemmings soos die volgende uiteensit:

- **Certificate-Enrollment**- en **Certificate-AutoEnrollment**-regte, elk gekoppel aan spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide toestemmings toelaat.
- **FullControl/GenericAll**, wat volle beheer oor die sjabloon bied.

### Registrasieregte vir Enterprise CAs

Die CA se regte word in sy sekuriteitsbeskrywer uiteengesit, wat deur die Certificate Authority-bestuurskonsole verkry kan word. Sommige instellings laat selfs gebruikers met lae voorregte toe om afstandtoegang te verkry, wat 'n sekuriteitsrisiko kan inhou.

### Bykomende uitreikingskontroles

Sekere kontroles kan van toepassing wees, soos:

- **Bestuurdergoedkeuring**: Plaas versoeke in 'n hangende toestand totdat 'n sertifikaatbestuurder dit goedkeur.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste handtekeninge op 'n CSR en die nodige Application Policy OIDs.

### Metodes om sertifikate aan te vra

Sertifikate kan aangevra word deur middel van:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), deur DCOM-koppelvlakke te gebruik.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur benoemde pype of TCP/IP te gebruik.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment-rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), saam met die Certificate Enrollment Policy (CEP)-diens.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, deur die Simple Certificate Enrollment Protocol (SCEP) te gebruik.

Windows-gebruikers kan ook sertifikate aanvra via die GUI (`certmgr.msc` of `certlm.msc`) of opdragreëlnutsgoed (`certreq.exe` of PowerShell se `Get-Certificate`-opdrag).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Sertifikaatverifikasie

Active Directory (AD) ondersteun sertifikaatverifikasie, hoofsaaklik deur **Kerberos**- en **Secure Channel (Schannel)**-protokolle te gebruik.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word ’n gebruiker se versoek om ’n Ticket Granting Ticket (TGT) met die **private sleutel** van die gebruiker se sertifikaat onderteken. Hierdie versoek ondergaan verskeie validerings deur die domeinbeheerder, insluitend die sertifikaat se **geldigheid**, **pad** en **herroepingsstatus**. Validerings sluit ook in dat bevestig word dat die sertifikaat van ’n vertroude bron afkomstig is en dat die uitreiker in die **NTAUTH-sertifikaatbewaarplek** voorkom. Suksesvolle validerings lei tot die uitreiking van ’n TGT. Die **`NTAuthCertificates`**-objek in AD, wat gevind word by:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

is sentraal tot die vestiging van vertroue vir sertifikaatverifikasie.<sup>[[4]](#references)</sup>

Sedert die **KB5014754**-ontplooiing gaan moderne Kerberos-sertifikaatverifikasie hoofsaaklik oor **karteringsterkte**, nie net EKU's nie.<sup>[[2]](#references)</sup> In versterkte woude:

- 'n Sertifikaat wat slegs 'n **UPN/DNS SAN** bevat, is dalk nie meer voldoende vir aanmelding nie.
- Die KDC verkies 'n **sterk binding**, gewoonlik die **SID-sekuriteitsuitbreiding** (`1.3.6.1.4.1.311.25.2`) of 'n sterk eksplisiete kartering in `altSecurityIdentities`.
- As die sertifikaat nie 'n sterk kartering het nie, teken DC's **Kdcsvc Event ID 39/41** aan in verenigbaarheidsmodus en weier verifikasie in afdwingingsmodus.
- In gemengde aanvalspaaie is **ESC9/ESC16** belangrik omdat hulle die SID-uitbreiding van uitgereikte sertifikate verwyder; operateurs steun dan op eksplisiete karterings of SAN URL SID-formate waar die aanvalspad dit ondersteun.

### Secure Channel (Schannel)-verifikasie

Schannel fasiliteer veilige TLS/SSL-verbindings, waar die kliënt tydens 'n handdruk 'n sertifikaat aanbied wat toegang magtig indien dit suksesvol gevalideer word. Die kartering van 'n sertifikaat na 'n AD-rekening kan onder meer Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** behels.<sup>[[4]](#references)</sup>

Schannel is ook die praktiese terugvalopsie wanneer **PKINIT** nie beskikbaar is nie. As 'n domeinbeheerder byvoorbeeld nie 'n geskikte **Smart Card Logon**-sertifikaat het nie, kan `certipy auth`/PKINIT-nutsmiddels dalk nie 'n TGT verkry nie, maar dieselfde sertifikaat kan steeds bruikbaar wees vir verifikasie en LDAP-bewerkings teen **LDAPS** of **LDAP StartTLS**.

### AD Certificate Services-enumerasie

AD se sertifikaatdienste kan deur LDAP-navrae geënumeer word, wat inligting oor **Enterprise Certificate Authorities (CA's)** en hul konfigurasies openbaar. Enige domeingeverifieerde gebruiker kan hierby uitkom sonder spesiale voorregte. Nutsmiddels soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumerasie en kwesbaarheidsbepaling in AD CS-omgewings.

Opdragte om hierdie nutsmiddels te gebruik, sluit in:

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

## Onlangse kwesbaarhede en sekuriteitsopdaterings (2022-2025)

| Jaar | ID / Naam | Impak | Belangrike wegneem-punte |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Voorregte-eskalasie* deur masjienrekeningsertifikate tydens PKINIT te spoof. | Die patch is ingesluit by die sekuriteitsopdaterings van **10 Mei 2022**. Oudit- en sterkkarteringkontroles is via **KB5014754** ingestel; omgewings behoort nou in *Full Enforcement*-modus te wees.  |
| 2023 | **CVE-2023-35350 / 35351** | *Afgeleë kode-uitvoering* in die AD CS Web Enrollment- (certsrv) en CES-rolle. | Openbare PoCs is beperk, maar die kwesbare IIS-komponente is dikwels intern blootgestel. Patch vanaf **Julie 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Op **v1-templates** kan ’n versoeker met registrasieregte **Application Policies/EKUs** in die CSR insluit, wat voorkeur geniet bo die template se EKUs en sertifikate vir kliëntverifikasie, enrollment agents of kode-ondertekening oplewer. | Gepatch vanaf **12 November 2024**. Vervang of vervang deur nuwer weergawes van v1-templates (bv. die verstek-WebServer-template), beperk EKUs tot die bedoelde gebruik en beperk registrasieregte. |

### Microsoft-verhardingstydlyn (KB5014754)

Microsoft het ’n uitrol in drie fases ingestel (Compatibility → Audit → Enforcement) om Kerberos-sertifikaatverifikasie weg te beweeg van swak implisiete karterings. Vanaf **11 Februarie 2025** skakel domeinbeheerders outomaties oor na **Full Enforcement** as die `StrongCertificateBindingEnforcement`-registerwaarde nie gestel is nie. Microsoft het die tydlyn later aangepas sodat terugval na verenigbaarheidsmodus moontlik bly tot die **9 September 2025**-sekuriteitsopdatering.<sup>[[2]](#references)</sup> Administrateurs behoort:

1. Alle DC's en AD CS-bedieners op te dateer (Mei 2022 of later).
2. Gebeurtenis-ID 39/41 vir swak karterings tydens die *Audit*-fase te monitor.
3. Kliëntverifikasiesertifikate weer uit te reik met die nuwe **SID-uitbreiding**, of sterk handmatige karterings op te stel voordat afdwinging swak karterings blokkeer.

### Operateurnotas vir verharde woude

- **ESC1/ESC6 alleen is in 2025+-omgewings nie meer die hele storie nie.** As jy ’n sertifikaat vir ’n ander hoofentiteit aanvra, het jy gewoonlik ook ’n sterk karteringsartefak nodig, soos die SID-uitbreiding of ’n eksplisiete kartering.
- **ESC15 (EKUwu)** is meestal waardevol in omgewings wat nie gepatch is nie, omdat dit onskadelike **v1**-templates soos **WebServer** in sertifikate omskep wat verifikasie of enrollment-agent-vermoëns het deur **Application Policies** in te voeg. Kerberos PKINIT evalueer steeds EKUs, maar **LDAP Schannel** neem ook Application Policies in ag, wat LDAP-gebaseerde misbruik steeds relevant maak.<sup>[[1]](#references)</sup>
- **ESC16** is ’n CA-wye instelling: as die CA die SID-sekuriteitsuitbreiding wêreldwyd deaktiveer, keer elke uitgereikte sertifikaat terug na swakker karteringsgedrag, tensy die aanvalsketting ’n SID via ’n ander ondersteunde formaat invoeg.
- **ESC7-regte verskil:** ’n CA-`ManageCA`-toekenning kan veranderinge aan instellings soos `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) toelaat, terwyl `ManageCertificates` goedkeuring van versoeke beheer. ’n Eksplisiete Deny op sertifikaatbestuurderregte kan daardie goedkeuringsroete blokkeer, selfs al is ’n Allow ook teenwoordig; beoordeel die effektiewe CA-ACL voordat jy instellings en templates kombineer. Sien [Microsoft se beoordeling van CA-ACL's](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Verbeterings vir opsporing en verharding

* **Defender for Identity AD CS-sensor (2023-2024)** wys nou postuurbeoordelings vir ESC1-ESC8/ESC11 en genereer intydse waarskuwings soos *“Domain-controller certificate issuance for a non-DC”* (ESC8) en *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Maak seker dat sensors op alle AD CS-bedieners ontplooi is om by hierdie opsporings baat te vind.<sup>[[3]](#references)</sup>
* Deaktiveer of beperk die **“Supply in the request”**-opsie streng op alle templates; verkies waardes vir SAN/EKU wat uitdruklik gedefinieer is.
* Verwyder **Any Purpose** of **No EKU** uit templates, tensy dit absoluut noodsaaklik is (hanteer ESC2-scenario's).
* Vereis **goedkeuring deur ’n bestuurder** of toegewyde Enrollment Agent-werkvloeie vir sensitiewe templates (bv. WebServer / CodeSigning).
* Beperk webregistrasie (`certsrv`) en CES/NDES-eindpunte tot vertroude netwerke of plaas dit agter kliëntsertifikaatverifikasie.
* Dwing RPC-registrasiekodering af (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) om ESC11 (RPC relay) te versag. Die vlag is **by verstek aan**, maar word dikwels vir verouderde kliënte gedeaktiveer, wat die relay-risiko weer oopstel.
* Beveilig **IIS-gebaseerde registrasie-eindpunte** (CES/Certsrv): deaktiveer NTLM waar moontlik, of vereis HTTPS + Extended Protection om ESC8-relays te blokkeer.

Beoordeel ESC11 op die gasheer waarop die CA loop; dit kan ’n domeinlidbediener eerder as ’n domeinbeheerder wees. Lees die aktiewe CA se `InterfaceFlags` onder `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; ’n onleesbare of ontbrekende waarde beteken dat die uitslag onbekend is, nie dat RPC-kodering beslis gedeaktiveer is nie. ’n Skoon `IF_ENFORCEENCRYPTICERTREQUEST`-bis is ’n leidraad vir ’n konfigurasieprobleem, maar daar moet steeds ’n bereikbare RPC-registrasie-eindpunt, afdwingbare geloofsbriewe en ’n bruikbare sertifikaattemplate wees. Vir ESC8 is ’n HTTP NTLM-uitdaging alleen onvoldoende: bevestig dat ’n werkende registrasie-eindpunt bestaan.

---

## References

- [1] [EKUwu: Nie net nog ’n AD CS ESC nie](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Veranderinge aan sertifikaatgebaseerde verifikasie op Windows-domeinbeheerders](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Sekuriteitspostuurbeoordelings vir sertifikate - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Gesertifiseerde tweedehands: Misbruik van Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
