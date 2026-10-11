# AD-sertifikate

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van ’n sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar daarvan aan.
- ’n **Public Key** word met ’n privaat gehoude sleutel gepaar om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, wat deur die **NotBefore**- en **NotAfter**-datums gedefinieer word, dui die sertifikaat se geldigheidstydperk aan.
- ’n Unieke **Serial Number**, wat deur die Sertifikaatowerheid (CA) toegeken word, identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat bykomende name vir die onderwerp toe, wat identifikasie meer buigsaam maak.
- **Basic Constraints** dui aan of die sertifikaat vir ’n CA of ’n eindentiteit bedoel is, en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** omskryf die spesifieke doeleindes van die sertifikaat, soos kodeondertekening of e-pos-enkripsie, deur middel van Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode waarmee die sertifikaat onderteken word.
- Die **Signature**, wat met die uitreiker se private key geskep word, waarborg die egtheid van die sertifikaat.<sup>[[4]](#references)</sup>

### Spesiale oorwegings

- **Subject Alternative Names (SANs)** brei ’n sertifikaat se toepaslikheid uit na verskeie identiteite, wat noodsaaklik is vir bedieners met verskeie domeine. Veilige uitreikingsprosesse is noodsaaklik om die risiko van nabootsing te voorkom wanneer aanvallers die SAN-spesifikasie manipuleer.<sup>[[4]](#references)</sup>

### Sertifikaatowerhede (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in ’n AD-woud deur middel van aangewese houers, wat elk ’n unieke rol vervul:<sup>[[4]](#references)</sup>

- Die **Certification Authorities**-houer bevat vertroude wortel-CA-sertifikate.
- Die **Enrolment Services**-houer bevat besonderhede oor Enterprise CAs en hul sertifikaatsjablone.
- Die **NTAuthCertificates**-objek bevat CA-sertifikate wat vir AD-verifikasie gemagtig is.
- Die **AIA (Authority Information Access)**-houer vergemaklik sertifikaatkettingvalidering met intermediêre en kruis-CA-sertifikate.

### Verkryging van sertifikate: Vloei van ’n kliëntsertifikaataanvraag

1. Die aanvraagproses begin wanneer kliënte ’n Enterprise CA opspoor.
2. Nadat ’n publieke-private sleutelspaar gegenereer is, word ’n CSR geskep wat ’n publieke sleutel en ander besonderhede bevat.
3. Die CA beoordeel die CSR aan die hand van beskikbare sertifikaatsjablone en reik die sertifikaat uit volgens die sjabloon se toestemmings.
4. Sodra dit goedgekeur is, onderteken die CA die sertifikaat met sy private key en stuur dit aan die kliënt terug.<sup>[[4]](#references)</sup>

### Sertifikaatsjablone

Hierdie sjablone, wat binne AD gedefinieer word, beskryf die instellings en toestemmings vir die uitreiking van sertifikate, insluitend toegelate EKUs en regte vir inskrywing of wysiging. Dit is noodsaaklik vir die bestuur van toegang tot sertifikaatdienste.<sup>[[4]](#references)</sup>

**Die weergawe van die sjabloonskema is belangrik.** Ouer **v1**-sjablone (byvoorbeeld die ingeboude **WebServer**-sjabloon) het nie verskeie moderne afdwingingsinstellings nie. Die **ESC15/EKUwu**-navorsing het getoon dat ’n aanvraer op **v1-sjablone** **Application Policies/EKUs** in die CSR kan insluit wat **voorrang kry bo** die EKUs wat in die sjabloon opgestel is. Dit maak kliëntverifikasie-, inskrywingsagent- of kodeondertekeningsertifikate moontlik met slegs inskrywingsregte. Gebruik eerder **v2/v3-sjablone**, verwyder of vervang verstekwaardes van v1, en beperk EKUs streng tot die beoogde doel.<sup>[[1]](#references)</sup>

## Sertifikaatinskrywing

Die inskrywingsproses vir sertifikate begin wanneer ’n administrateur **’n sertifikaatsjabloon skep**, wat daarna deur ’n Enterprise Sertifikaatowerheid (CA) **gepubliseer** word. Sodoende word die sjabloon vir kliëntinskrywing beskikbaar gestel. Dit gebeur deur die sjabloon se naam by die `certificatetemplates`-veld van ’n Active Directory-objek te voeg.<sup>[[4]](#references)</sup>

Om ’n sertifikaat aan te vra, moet ’n kliënt **inskrywingsregte** hê. Hierdie regte word deur sekuriteitsbeskrywers op die sertifikaatsjabloon en die Enterprise CA self gedefinieer. Toestemmings moet op albei plekke toegeken word voordat ’n aanvraag kan slaag.

### Inskrywingsregte vir sjablone

Hierdie regte word deur Access Control Entries (ACEs) gespesifiseer, wat toestemmings soos die volgende uiteensit:

- **Certificate-Enrollment**- en **Certificate-AutoEnrollment**-regte, elk gekoppel aan spesifieke GUIDs.
- **ExtendedRights**, wat alle uitgebreide toestemmings toelaat.
- **FullControl/GenericAll**, wat volle beheer oor die sjabloon bied.

### Inskrywingsregte vir Enterprise CAs

Die CA se regte word in sy sekuriteitsbeskrywer uiteengesit, wat via die Certificate Authority-bestuurkonsole verkry kan word. Sommige instellings laat selfs gebruikers met lae voorregte toe om op afstand toegang te verkry, wat ’n sekuriteitsrisiko kan inhou.

### Bykomende uitreikingskontroles

Sekere kontroles kan van toepassing wees, soos:

- **Manager Approval**: Plaas aanvrae in ’n hangende toestand totdat ’n sertifikaatbestuurder dit goedkeur.
- **Enrolment Agents and Authorized Signatures**: Spesifiseer die aantal vereiste handtekeninge op ’n CSR en die nodige Application Policy OIDs.

### Metodes om sertifikate aan te vra

Sertifikate kan aangevra word deur middel van:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), met DCOM-koppelvlakke.
2. **ICertPassage Remote Protocol** (MS-ICPR), deur benoemde pype of TCP/IP.
3. Die **certificate enrollment web interface**, met die Certificate Authority Web Enrollment-rol geïnstalleer.
4. Die **Certificate Enrollment Service** (CES), saam met die Certificate Enrollment Policy (CEP)-diens.
5. Die **Network Device Enrollment Service** (NDES) vir netwerktoestelle, met behulp van die Simple Certificate Enrollment Protocol (SCEP).

Windows-gebruikers kan ook sertifikate via die GUI (`certmgr.msc` of `certlm.msc`) of opdragreëlnutsgoed (`certreq.exe` of PowerShell se `Get-Certificate`-opdrag) aanvra.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Sertifikaatstawing

Active Directory (AD) ondersteun sertifikaatstawing, hoofsaaklik deur die **Kerberos**- en **Secure Channel (Schannel)**-protokolle te gebruik.

### Kerberos-stawingsproses

In die Kerberos-stawingsproses word ’n gebruiker se versoek om ’n Ticket Granting Ticket (TGT) met die **private sleutel** van die gebruiker se sertifikaat onderteken. Die domeinbeheerder voer verskeie bekragtigings van hierdie versoek uit, insluitend die sertifikaat se **geldigheid**, **pad** en **herroepingstatus**. Die bekragtigings sluit ook in dat daar nagegaan word of die sertifikaat van ’n vertroude bron afkomstig is en bevestig word dat die uitreiker in die **NTAUTH-sertifikaatwinkel** voorkom. Suksesvolle bekragtigings lei tot die uitreiking van ’n TGT. Die **`NTAuthCertificates`**-objek in AD, wat gevind kan word by:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

is sentraal tot die vestiging van vertroue vir sertifikaatstawing.<sup>[[4]](#references)</sup>

Sedert die **KB5014754**-ontplooiing gaan moderne Kerberos-sertifikaatstawing hoofsaaklik oor **bindingssterkte**, nie net EKU's nie.<sup>[[2]](#references)</sup> In beveiligde forests:

- 'n Sertifikaat wat net 'n **UPN/DNS SAN** bevat, is dalk nie meer voldoende om aan te meld nie.
- Die KDC verkies 'n **sterk binding**, gewoonlik die **SID-sekuriteitsuitbreiding** (`1.3.6.1.4.1.311.25.2`) of 'n sterk eksplisiete kartering in `altSecurityIdentities`.
- As die sertifikaat nie 'n sterk kartering het nie, teken DC's **Kdcsvc Event ID 39/41** in versoenbaarheidsmodus aan en weier hulle stawing in afdwingingsmodus.
- In gemengde aanvalspaaie is **ESC9/ESC16** belangrik omdat hulle die SID-uitbreiding van uitgereikte sertifikate verwyder; operateurs maak dan staat op eksplisiete karterings of SAN URL SID-formate waar die aanvalspad dit ondersteun.

### Schannel-stawing

Schannel maak veilige TLS/SSL-verbindings moontlik. Tydens 'n handdruk bied die kliënt 'n sertifikaat aan wat, indien dit suksesvol gevalideer word, toegang magtig. Die kartering van 'n sertifikaat na 'n AD-rekening kan onder meer Kerberos se **S4U2Self**-funksie of die sertifikaat se **Subject Alternative Name (SAN)** behels.<sup>[[4]](#references)</sup>

Schannel is ook die praktiese terugvalopsie wanneer **PKINIT** nie beskikbaar is nie. Byvoorbeeld, as 'n domeinbeheerder nie 'n geskikte **Smart Card Logon**-sertifikaat het nie, kan `certipy auth`/PKINIT-nutsgoed dalk nie 'n TGT kry nie, maar dieselfde sertifikaat kan steeds vir stawing en LDAP-bewerkings teen **LDAPS** of **LDAP StartTLS** gebruik word.

### AD-sertifikaatdienste-opsporing

AD se sertifikaatdienste kan deur LDAP-navrae opgespoor word, wat inligting oor **Enterprise Certificate Authorities (CA's)** en hul konfigurasies openbaar. Enige domeen-gewaarmerkte gebruiker kan toegang hiertoe kry sonder spesiale regte. Nutsgoed soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir opsporing en kwesbaarheidsbeoordeling in AD CS-omgewings.

Opdragte vir die gebruik van hierdie nutsgoed sluit in:

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

| Jaar | ID / Naam | Impak | Belangrike gevolgtrekkings |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Voorregte-eskalasie* deur masjienrekeningsertifikate tydens PKINIT te vervals. | Die Patch is ingesluit in die sekuriteitsopdaterings van **10 Mei 2022**. Oudit- en sterkkarteringkontroles is via **KB5014754** ingestel; omgewings behoort nou in die *Full Enforcement*-modus te wees.  |
| 2023 | **CVE-2023-35350 / 35351** | *Afgeleë kode-uitvoering* in die AD CS Web Enrollment (certsrv)- en CES-rolle. | Openbare PoC's is beperk, maar die kwesbare IIS-komponente is dikwels intern blootgestel. Patch vanaf **Julie 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Op **v1-sjablone** kan 'n aanvraer met registrasieregte **Application Policies/EKUs** in die CSR insluit wat voorkeur geniet bo die sjabloon se EKUs, en sodoende sertifikate vir kliëntverifikasie, registrasie-agent of kodeondertekening oplewer. | Gepatch vanaf **12 November 2024**. Vervang of vervang v1-sjablone (bv. die verstek-WebServer-sjabloon), beperk EKUs tot die beoogde doel en beperk registrasieregte. |

### Microsoft-verhardingtydlyn (KB5014754)

Microsoft het 'n uitrol in drie fases ingestel (Compatibility → Audit → Enforcement) om Kerberos-sertifikaatverifikasie weg te beweeg van swak implisiete karterings. Vanaf **11 Februarie 2025** skakel domeinbeheerders outomaties oor na **Full Enforcement** as die `StrongCertificateBindingEnforcement`-registerwaarde nie gestel is nie. Microsoft het die tydlyn later opgedateer sodat terugval na die versoenbaarheidsmodus moontlik bly tot die sekuriteitsopdatering van **9 September 2025**.<sup>[[2]](#references)</sup> Administrateurs behoort:

1. Alle DC's en AD CS-bedieners te patch (Mei 2022 of later).
2. Gebeurtenis-ID 39/41 vir swak karterings tydens die *Audit*-fase te monitor.
3. Kliëntverifikasiesertifikate weer uit te reik met die nuwe **SID-uitbreiding**, of sterk handmatige karterings op te stel voordat afdwinging swak karterings blokkeer.

### Aantekeninge vir operateurs van verharde woude

- **ESC1/ESC6 alleen is in 2025+-omgewings nie meer die hele storie nie.** As jy 'n sertifikaat vir 'n ander hoofentiteit aanvra, benodig jy gewoonlik ook 'n sterk karteringsartefak, soos die SID-uitbreiding of 'n eksplisiete kartering.
- **ESC15 (EKUwu)** is meestal waardevol in ongepatchte omgewings omdat dit onskadelike **v1**-sjablone soos **WebServer** in sertifikate vir verifikasie of registrasie-agente kan omskep deur **Application Policies** in te voeg. Kerberos PKINIT evalueer steeds EKUs, maar **LDAP Schannel** erken ook Application Policies, wat LDAP-gebaseerde misbruik relevant hou.<sup>[[1]](#references)</sup>
- **ESC16** is 'n CA-wye instelling: as die CA die SID-sekuriteitsuitbreiding wêreldwyd deaktiveer, val elke uitgereikte sertifikaat terug na swakker karteringsgedrag, tensy die aanvalsketting 'n SID via 'n ander ondersteunde formaat invoeg.
- **ESC7-regte is onderskeibaar:** 'n CA-`ManageCA`-toekenning kan veranderinge aan instellings soos `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) toelaat, terwyl `ManageCertificates` versoekgoedkeuring beheer. 'n Eksplisiete Deny op sertifikaatbestuurderregte kan daardie goedkeuringsroete blokkeer, selfs al is 'n Allow ook teenwoordig; beoordeel die effektiewe CA ACL voordat jy instellings en sjablone aan mekaar koppel. Sien [Microsoft's CA ACL assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Verbeterings aan opsporing en verharding

* **Defender for Identity AD CS-sensor (2023-2024)** wys nou houdingsbeoordelings vir ESC1-ESC8/ESC11 en genereer intydse waarskuwings soos *“Uitiking van domeinbeheerdersertifikate vir 'n nie-DC”* (ESC8) en *“Voorkom sertifikaatregistrasie met arbitrêre Application Policies”* (ESC15). Maak seker dat sensors op alle AD CS-bedieners ontplooi is om hierdie opsporings te benut.<sup>[[3]](#references)</sup>
* Deaktiveer of beperk die **“Supply in the request”**-opsie streng op alle sjablone; verkies eksplisiet gedefinieerde SAN/EKU-waardes.
* Verwyder **Any Purpose** of **No EKU** uit sjablone, tensy dit absoluut noodsaaklik is (pak ESC2-scenario's aan).
* Vereis **bestuurdergoedkeuring** of toegewyde Enrollment Agent-werkvloeie vir sensitiewe sjablone (bv. WebServer / CodeSigning).
* Beperk webregistrasie (`certsrv`) en CES/NDES-eindpunte tot vertroude netwerke of plaas dit agter kliëntsertifikaatverifikasie.
* Dwing RPC-registrasie-enkripsie af (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) om ESC11 (RPC-relay) te versag. Die vlag is **by verstek aan**, maar word dikwels vir verouderde kliënte gedeaktiveer, wat die relay-risiko heropen.
* Beveilig **IIS-gebaseerde registrasie-eindpunte** (CES/Certsrv): deaktiveer NTLM waar moontlik, of vereis HTTPS + Extended Protection om ESC8-relays te blokkeer.

Beoordeel ESC11 op die gasheer waarop die CA loop; dit kan 'n domeinlidbediener eerder as 'n domeinbeheerder wees. Lees die aktiewe CA se `InterfaceFlags` onder `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; 'n waarde wat nie gelees kan word nie of ontbreek, dui op 'n onbekende resultaat, nie op bewys dat RPC-enkripsie gedeaktiveer is nie. 'n Skoon `IF_ENFORCEENCRYPTICERTREQUEST`-bis is 'n leidraad oor die konfigurasie waarvoor steeds 'n bereikbare RPC-registrasie-eindpunt, afdwingbare geloofsbriewe en 'n bruikbare sertifikaatsjabloon nodig is. Vir ESC8 is 'n HTTP NTLM-uitdaging op sigself nie voldoende nie: bevestig dat daar 'n werkende registrasie-eindpunt is.

---

## References

- [1] [EKUwu: Nie net nog 'n AD CS ESC nie](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Veranderinge aan sertifikaatgebaseerde verifikasie op Windows-domeinbeheerders](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Sekuriteitshoudingbeoordelings vir sertifikate - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
