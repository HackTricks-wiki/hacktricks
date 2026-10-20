# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Om meer oor macOS MDM's te leer, kyk na:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Grondbeginsels

### **Oorsig van MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) word gebruik om verskeie eindgebruikertoestelle, soos slimfone, skootrekenaars en tablette, te bestuur. Dit behels veral vir Apple-platforms (iOS, macOS, tvOS) 'n stel gespesialiseerde funksies, API's en praktyke. MDM werk met behulp van 'n versoenbare MDM-bediener, wat kommersieel beskikbaar of oopbron kan wees, en die [MDM-protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) moet ondersteun. Belangrike punte sluit in:

- Gesentraliseerde beheer oor toestelle.
- Afhanklikheid van 'n MDM-bediener wat aan die MDM-protokol voldoen.
- Die MDM-bediener kan verskeie opdragte na toestelle stuur, byvoorbeeld om data op afstand uit te vee of konfigurasies te installeer.

### **Grondbeginsels van DEP (Device Enrollment Program)**

Apple se [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereenvoudig die integrasie van Mobile Device Management (MDM) deur nul-aanraking-konfigurasie vir iOS-, macOS- en tvOS-toestelle moontlik te maak. DEP outomatiseer die registrasieproses sodat toestelle onmiddellik uit die boks gebruik kan word, met minimale ingryping deur gebruikers of administrateurs. Belangrike aspekte sluit in:

- Laat toestelle toe om met die eerste aktivering self by 'n voorafbepaalde MDM-bediener te registreer.
- Is hoofsaaklik nuttig vir splinternuwe toestelle, maar kan ook gebruik word vir toestelle wat herkonfigureer word.
- Maak 'n eenvoudige opstelling moontlik sodat toestelle vinnig gereed is vir organisatoriese gebruik.

### **Sekuriteitsoorweging**

Dit is belangrik om daarop te let dat DEP se maklike registrasie, hoewel nuttig, ook sekuriteitsrisiko's kan inhou. As beskermingsmaatreëls nie behoorlik vir MDM-registrasie toegepas word nie, kan aanvallers hierdie vaartbelynde proses misbruik om hul toestel by die organisasie se MDM-bediener te registreer deur voor te gee dat dit 'n korporatiewe toestel is.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Sekuriteitswaarskuwing**: Vereenvoudigde DEP-registrasie kan ongemagtigde toestelle moontlik by die organisasie se MDM-bediener laat registreer as behoorlike voorsorgmaatreëls nie ingestel is nie.

### Grondbeginsels: Wat is SCEP (Simple Certificate Enrolment Protocol)?

- 'n Relatief ou protokol, wat geskep is voordat TLS en HTTPS wydverspreid was.
- Bied kliënte 'n gestandaardiseerde manier om 'n **Certificate Signing Request** (CSR) te stuur om 'n sertifikaat te bekom. Die kliënt vra die bediener om 'n ondertekende sertifikaat aan hom te verskaf.

### Wat is Configuration Profiles (ook bekend as mobileconfigs)?

- Apple se amptelike manier om **stelselkonfigurasie in te stel en af te dwing.**
- Lêerformaat wat verskeie payloads kan bevat.
- Gebaseer op property lists (die XML-soort).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Grondbeginsels — Bladsy 70, iOS Security Guide, Januarie 2018.

## Protokolle

### MDM

- Kombinasie van APNs (**Apple-bedieners**) + RESTful API (**MDM**-**verskaffer**-bedieners)
- **Kommunikasie** vind plaas tussen 'n **toestel** en 'n bediener wat met 'n **toestel**-**bestuur**-**produk** geassosieer word
- **Opdragte** word vanaf die MDM na die toestel gestuur in **plist-gekodeerde woordeboeke**
- Alles oor **HTTPS**. MDM-bedieners kan vasgepen wees (en is gewoonlik).
- Apple voorsien die MDM-verskaffer van 'n **APNs-sertifikaat** vir verifikasie

### DEP

- **3 API's**: 1 vir herverkopers, 1 vir MDM-verskaffers, 1 vir toestelidentiteit (ongedokumenteer):
  - Die sogenaamde [DEP "cloud service"-API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). MDM-bedieners gebruik dit om DEP-profiele met spesifieke toestelle te assosieer.
  - Die [DEP-API wat deur Apple Authorized Resellers gebruik word](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle te registreer, registrasiestatus na te gaan en transaksiestatus na te gaan.
  - Die ongedokumenteerde private DEP-API. Apple-toestelle gebruik dit om hul DEP-profiel aan te vra. Op macOS is die `cloudconfigurationd`-binêre verantwoordelik vir kommunikasie oor hierdie API.
- Meer modern en **JSON**-gebaseer (teenoor plist)
- Apple voorsien die MDM-verskaffer van 'n **OAuth-token**

**DEP "cloud service"-API**

- RESTful
- Sinkroniseer toestelrekords vanaf Apple na die MDM-bediener
- Sinkroniseer “DEP-profiele” vanaf die MDM-bediener na Apple (wat Apple later aan die toestel lewer)
- 'n DEP-“profiel” bevat:
  - URL van die MDM-verskaffer se bediener
  - Bykomende vertroude sertifikate vir die bediener-URL (opsionele pinning)
  - Ekstra instellings (bv. watter skerms in Setup Assistant oorgeslaan moet word)

## Reeksnommer

Apple-toestelle wat ná 2010 vervaardig is, het gewoonlik **alfanumeriese reeksnommers van 12 karakters**, waarvan die **eerste drie syfers die vervaardigingsplek aandui**, die volgende **twee** die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers 'n **unieke** **identifiseerder** verskaf, en die **laaste** **vier** syfers die **modelnommer** aandui.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Stappe vir registrasie en bestuur

1. Toestelrekord word geskep (Herverkoper, Apple): Die rekord vir die nuwe toestel word geskep
2. Toestelrekord word toegewys (Kliënt): Die toestel word aan 'n MDM-bediener toegewys
3. Toestelrekord word gesinkroniseer (MDM-verskaffer): MDM sinkroniseer die toestelrekords en stoot die DEP-profiele na Apple
4. DEP-aanmelding (Toestel): Die toestel verkry sy DEP-profiel
5. Profiel word opgespoor (Toestel)
6. Profiel word geïnstalleer (Toestel) a. insluitend MDM-, SCEP- en wortel-CA-payloads
7. MDM-opdrag word uitgereik (Toestel)

![Reeksnommer - Stappe vir registrasie en bestuur: 7. MDM-opdrag word uitgereik (Toestel)](<../../../images/image (694).png>)

Die lêer `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` voer funksies uit wat as **hoëvlak-“stappe”** van die registrasieproses beskou kan word.

### Stap 4: DEP-aanmelding - Verkryging van die aktiveringsrekord

Hierdie deel van die proses vind plaas wanneer 'n **gebruiker 'n Mac vir die eerste keer aanskakel** (of ná 'n volledige uitvee)

![Stappe vir registrasie en bestuur - Stap 4: DEP-aanmelding - Verkryging van die aktiveringsrekord: Hierdie deel van die proses vind plaas wanneer 'n gebruiker 'n Mac vir die eerste keer aanskakel (of ná 'n volledige...](<../../../images/image (1044).png>)

of wanneer `sudo profiles show -type enrollment` uitgevoer word

- Bepaal **of die toestel DEP-geaktiveer is**
- Aktiveringsrekord is die interne naam vir die **DEP-“profiel”**
- Begin sodra die toestel aan die internet gekoppel is
- Word aangedryf deur **`CPFetchActivationRecord`**
- Word via XPC deur **`cloudconfigurationd`** geïmplementeer. Die **"Setup Assistant**" (wanneer die toestel vir die eerste keer aangeskakel word) of die **`profiles`**-opdrag sal **hierdie daemon kontak** om die aktiveringsrekord te verkry.
  - LaunchDaemon (loop altyd as root)

Dit volg 'n paar stappe om die aktiveringsrekord te verkry, wat deur **`MCTeslaConfigurationFetcher`** uitgevoer word. Hierdie proses gebruik 'n enkripsiemetode genaamd **Absinthe**<sup>[[1]](#references)</sup>

1. Verkry **sertifikaat**
   1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inisialiseer** toestand vanaf die sertifikaat (**`NACInit`**)
   1. Gebruik verskeie toestelspesifieke data (d.w.s. **reeksnommer via `IOKit`**)
3. Verkry **sessiesleutel**
   1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Vestig die sessie (**`NACKeyEstablishment`**)
5. Stuur die versoek
   1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) met die data `{ "action": "RequestProfileConfiguration", "sn": "" }`
   2. Die JSON-payload word met Absinthe geënkripteer (**`NACSign`**)
   3. Alle versoeke is oor HTTPS; ingeboude wortelsertifikate word gebruik

![Stappe vir registrasie en bestuur - Stap 4: DEP-aanmelding - Verkryging van die aktiveringsrekord: 3. Alle versoeke is oor HTTPS; ingeboude wortelsertifikate word gebruik](<../../../images/image (566) (1).png>)

Die antwoord is 'n JSON-woordeboek met belangrike data soos:

- **url**: URL van die MDM-verskaffer se gasheer vir die aktiveringsprofiel
- **anchor-certs**: Skikking van DER-sertifikate wat as vertroude ankers gebruik word

### **Stap 5: Profielherwinning**

![Stap 4: DEP-aanmelding - Verkryging van die aktiveringsrekord - Stap 5: Profielherwinning: Stap 5: Profielherwinning](<../../../images/image (444).png>)

- Versoek word gestuur na die **url wat in die DEP-profiel verskaf word**.
- **Ankersertifikate** word gebruik om vertroue te **beoordeel**, indien verskaf.
  - Onthou: die **anchor_certs**-eienskap van die DEP-profiel
- **Versoek is 'n eenvoudige .plist** met toestelidentifikasie
  - Voorbeelde: **UDID, bedryfstelselweergawe**.
- CMS-onderteken, DER-geënkodeer
- Onderteken met die **toestelidentiteitsertifikaat (van APNS)**
- **Sertifikaatketting** bevat 'n verstreke **Apple iPhone Device CA**

![Stap 4: DEP-aanmelding - Verkryging van die aktiveringsrekord - Stap 5: Profielherwinning: Onderteken met die toestelidentiteitsertifikaat (van APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Stap 6: Profielinstallasie

- Sodra dit verkry is, **word die profiel op die stelsel gestoor**
- Hierdie stap begin outomaties (indien in **setup assistant**)
- Word aangedryf deur **`CPInstallActivationProfile`**
- Word deur mdmclient via XPC geïmplementeer
  - LaunchDaemon (as root) of LaunchAgent (as gebruiker), afhangend van die konteks
- Configuration profiles bevat verskeie payloads om te installeer
- Die framework het 'n plugin-gebaseerde argitektuur vir die installering van profiele
- Elke payload-tipe word met 'n plugin geassosieer
  - Kan XPC (in framework) of klassieke Cocoa (in ManagedClient.app) wees
- Voorbeeld:
  - Sertifikaatpayloads gebruik CertificateService.xpc

'n **Aktiveringsprofiel** wat deur 'n MDM-verskaffer verskaf word, **sal gewoonlik die volgende payloads insluit**:

- `com.apple.mdm`: om die toestel by MDM te **registreer**
- `com.apple.security.scep`: om 'n **kliëntsertifikaat** veilig aan die toestel te verskaf.
- `com.apple.security.pem`: om **vertroude CA-sertifikate** in die toestel se System Keychain te **installeer**.
- Die installering van die MDM-payload is gelykstaande aan **MDM-aanmelding in die dokumentasie**
- Die payload **bevat sleuteleienskappe**:
- - MDM-aanmeldings-URL (**`CheckInURL`**)
  - MDM-opdrag-peilings-URL (**`ServerURL`**) + APNs-onderwerp om dit te aktiveer
- Om die MDM-payload te installeer, word 'n versoek na **`CheckInURL`** gestuur
- Geïmplementeer in **`mdmclient`**
- MDM-payload kan van ander payloads afhanklik wees
- Laat toe dat **versoeke aan spesifieke sertifikate vasgepen word**:
  - Eienskap: **`CheckInURLPinningCertificateUUIDs`**
  - Eienskap: **`ServerURLPinningCertificateUUIDs`**
  - Verskaf via PEM-payload
- Laat toe dat 'n identiteitsertifikaat aan die toestel gekoppel word:
  - Eienskap: IdentityCertificateUUID
  - Verskaf via SCEP-payload

### **Stap 7: Luister na MDM-opdragte**

- Nadat MDM-aanmelding voltooi is, kan die verskaffer **stootkennisgewings met APNs uitreik**
- Wanneer dit ontvang word, word dit deur **`mdmclient`** hanteer
- Om vir MDM-opdragte te peil, word 'n versoek na ServerURL gestuur
- Gebruik die voorheen geïnstalleerde MDM-payload:
  - **`ServerURLPinningCertificateUUIDs`** om die versoek vas te pen
  - **`IdentityCertificateUUID`** vir die TLS-kliëntsertifikaat

## Aanvalle

### Toestelle by ander organisasies registreer

'n Toegekende reeksnommer kan die organisasie se registrasieroete identifiseer, maar dit **waarborg nie MDM-registrasie nie**. Die bediener kan gebruikerstawing via `configuration_web_url` vereis voordat die registrasieprofiel teruggestuur word. Bepaal of 'n alternatiewe registrasieroete hierdie kontrole oorslaan, eerder as om aan te neem dat elke toegekende reeksnommer by die toestelvloot kan aansluit.<sup>[[3]](#references)</sup>

Gebruik die onderstaande gekoppelde bladsy vir 'n skelm-registrasieproses. Vir MDM-beheer en pakketlewering ná 'n kompromittering, sien [macOS Red Teaming](../).


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}



## References

- [1] [’n Diepgaande ondersoek na macOS MDM (en hoe dit gekompromitteer kan word)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (sekuriteitsnavorsing oor DEP/MDM-registrasie)](https://duo.com/labs/research/mdm-me-maybe)
- [3] [Apple — Verifikasie deur webaansigte](https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views)
{{#include ../../../banners/hacktricks-training.md}}
