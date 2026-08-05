# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Om meer oor macOS MDMs te leer, kyk na:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basiese beginsels

### **MDM (Mobile Device Management)-oorsig**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) word gebruik om verskeie eindgebruikertoestelle, soos smartphones, laptops en tablets, te bestuur. Spesifiek vir Apple se platforms (iOS, macOS, tvOS) behels dit ’n stel gespesialiseerde features, APIs en praktyke. Die werking van MDM berus op ’n versoenbare MDM-bediener, wat kommersieel beskikbaar of open-source kan wees, en die [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) moet ondersteun. Belangrike punte sluit in:

- Gesentraliseerde beheer oor toestelle.
- Afhanklikheid van ’n MDM-bediener wat die MDM-protokol volg.
- Die MDM-bediener se vermoë om verskeie commands na toestelle te stuur, soos die afgeleë uitvee van data of die installering van konfigurasies.

### **Basiese beginsels van DEP (Device Enrollment Program)**

Apple se [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereenvoudig die integrasie van Mobile Device Management (MDM) deur zero-touch-konfigurasie vir iOS-, macOS- en tvOS-toestelle moontlik te maak. DEP automatiseer die enrollment-proses, sodat toestelle onmiddellik uit die boks operasioneel kan wees, met minimale gebruiker- of administrateur-ingryping. Belangrike aspekte sluit in:

- Stel toestelle in staat om outomaties met ’n voorafbepaalde MDM-bediener te registreer wanneer hulle aanvanklik geaktiveer word.
- Is hoofsaaklik nuttig vir splinternuwe toestelle, maar kan ook gebruik word vir toestelle wat herkonfigurasie ondergaan.
- Fasiliteer ’n eenvoudige opstelling, sodat toestelle vinnig gereed is vir organisatoriese gebruik.

### **Sekuriteitsoorweging**

Dit is belangrik om daarop te let dat die maklike enrollment wat DEP bied, hoewel dit voordelig is, ook sekuriteitsrisiko’s kan inhou. Indien beskermingsmaatreëls nie voldoende vir MDM-enrollment afgedwing word nie, kan aanvallers hierdie vereenvoudigde proses misbruik om hul toestel op die organisasie se MDM-bediener te registreer en dit as ’n korporatiewe toestel voor te doen.<sup>[2]</sup>

> [!CAUTION]
> **Sekuriteitswaarskuwing**: Vereenvoudigde DEP-enrollment kan moontlik ongemagtigde toestelregistrasie op die organisasie se MDM-bediener toelaat indien behoorlike beveiligingsmaatreëls nie ingestel is nie.

### Basiese beginsels: Wat is SCEP (Simple Certificate Enrolment Protocol)?

- ’n Relatief ou protokol wat geskep is voordat TLS en HTTPS wydverspreid was.
- Bied aan clients ’n gestandaardiseerde manier om ’n **Certificate Signing Request** (CSR) te stuur met die doel om ’n sertifikaat te ontvang. Die client sal die bediener vra om aan hom ’n ondertekende sertifikaat te verskaf.

### Wat is Configuration Profiles (ook bekend as mobileconfigs)?

- Apple se amptelike manier om stelselkonfigurasie **te stel en af te dwing**.
- Lêerformaat wat verskeie payloads kan bevat.
- Gebaseer op property lists (die XML-tipe).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protokolle

### MDM

- Kombinasie van APNs (**Apple servers**) + RESTful API (**MDM** **vendor** servers)
- **Kommunikasie** vind plaas tussen ’n **toestel** en ’n bediener wat met ’n **toestel**-**bestuurs**-**produk** geassosieer word.
- **Commands** wat vanaf die MDM na die toestel gestuur word in **plist-encoded dictionaries**
- Alles oor **HTTPS**. MDM-bedieners kan (en word gewoonlik) gepin.
- Apple verskaf aan die MDM vendor ’n **APNs certificate** vir authentication.

### DEP

- **3 APIs**: 1 vir resellers, 1 vir MDM vendors, 1 vir device identity (undocumented):
- Die sogenaamde [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Dit word deur MDM-bedieners gebruik om DEP-profiele met spesifieke toestelle te assosieer.
- Die [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle in te skryf, enrollment-status na te gaan en transaction-status na te gaan.
- Die undocumented private DEP API. Dit word deur Apple Devices gebruik om hul DEP-profiel aan te vra. Op macOS is die `cloudconfigurationd` binary verantwoordelik vir kommunikasie oor hierdie API.
- Meer modern en **JSON**-gebaseer (teenoor plist)
- Apple verskaf aan die MDM vendor ’n **OAuth token**

**DEP "cloud service" API**

- RESTful
- sinkroniseer toestelrekords vanaf Apple na die MDM-bediener
- sinkroniseer “DEP profiles” vanaf die MDM-bediener na Apple (wat later deur Apple aan die toestel gelewer word)
- ’n DEP-“profile” bevat:
- MDM vendor server URL
- Bykomende trusted certificates vir server URL (optional pinning)
- Ekstra settings (bv. watter screens in Setup Assistant oorgeslaan moet word)

## Serial Number

Apple-toestelle wat ná 2010 vervaardig is, het gewoonlik **12-karakter alfanumeriese** serial numbers, waar die **eerste drie syfers die vervaardigingsplek aandui**, die volgende **twee** die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers ’n **unieke** **identifier** verskaf, en die **laaste** **vier** syfers die **model number** verteenwoordig.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Stappe vir enrollment en bestuur

1. Skepping van toestelrekord (Reseller, Apple): Die rekord vir die nuwe toestel word geskep
2. Toewysing van toestelrekord (Customer): Die toestel word aan ’n MDM-bediener toegewys
3. Sinkronisering van toestelrekord (MDM vendor): MDM sinkroniseer die toestelrekords en push die DEP-profiele na Apple
4. DEP check-in (Device): Die toestel ontvang sy DEP-profiel
5. Profielherwinning (Device)
6. Profielinstallasie (Device) a. insluitend MDM-, SCEP- en root CA-payloads
7. Uitstuur van MDM-command (Device)

![Serial Number - Stappe vir enrollment en bestuur: 7. Uitstuur van MDM-command (Device)](<../../../images/image (694).png>)

Die lêer `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` export functions wat as **high-level "steps"** van die enrollment-proses beskou kan word.

### Stap 4: DEP check-in - Verkryging van die Activation Record

Hierdie deel van die proses vind plaas wanneer ’n **gebruiker ’n Mac vir die eerste keer boot** (of ná ’n volledige wipe).

![Stappe vir enrollment en bestuur - Stap 4: DEP check-in - Verkryging van die Activation Record: Hierdie deel van die proses vind plaas wanneer ’n gebruiker ’n Mac vir die eerste keer boot (of ná ’n volledige...](<../../../images/image (1044).png>)

of wanneer `sudo profiles show -type enrollment` uitgevoer word.

- Bepaal **of die toestel DEP-enabled is**
- Activation Record is die interne naam vir DEP-“profile”
- Begin sodra die toestel aan die Internet gekoppel is
- Word deur **`CPFetchActivationRecord`** aangedryf
- Geïmplementeer deur **`cloudconfigurationd`** via XPC. Die **"Setup Assistant**" (wanneer die toestel vir die eerste keer geboot word) of die **`profiles`** command sal **hierdie daemon kontak** om die activation record te verkry.
- LaunchDaemon (loop altyd as root)

Dit volg ’n paar stappe om die Activation Record te verkry, wat deur **`MCTeslaConfigurationFetcher`** uitgevoer word. Hierdie proses gebruik encryption genaamd **Absinthe**<sup>[1]</sup>

1. Verkry **certificate**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiseer** state vanaf certificate (**`NACInit`**)
1. Gebruik verskeie toestelspesifieke data (d.w.s. **Serial Number via `IOKit`**)
3. Verkry **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Establish die session (**`NACKeyEstablishment`**)
5. Maak die request
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en stuur die data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Die JSON-payload word met Absinthe geënkripteer (**`NACSign`**)
3. Alle requests oor HTTPS; ingeboude root certificates word gebruik

![Stappe vir enrollment en bestuur - Stap 4: DEP check-in - Verkryging van die Activation Record: 3. Alle requests oor HTTPS; ingeboude root certificates word gebruik](<../../../images/image (566) (1).png>)

Die response is ’n JSON-dictionary met belangrike data soos:

- **url**: URL van die MDM vendor host vir die activation profile
- **anchor-certs**: Array van DER-certificates wat as trusted anchors gebruik word

### **Stap 5: Profielherwinning**

![Stap 4: DEP check-in - Verkryging van die Activation Record - Stap 5: Profielherwinning: Stap 5: Profielherwinning](<../../../images/image (444).png>)

- Request gestuur na **url provided in DEP profile**.
- **Anchor certificates** word gebruik om **trust te evalueer** indien dit verskaf word.
- Herinnering: die **anchor_certs**-property van die DEP profile
- **Request is ’n eenvoudige .plist** met toestelidentifikasie
- Voorbeelde: **UDID, OS version**.
- CMS-signed, DER-encoded
- Geteken met die **device identity certificate (from APNS)**
- **Certificate chain** sluit ’n expired **Apple iPhone Device CA** in

![Stap 4: DEP check-in - Verkryging van die Activation Record - Stap 5: Profielherwinning: Geteken met die device identity certificate (from APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Stap 6: Profielinstallasie

- Sodra dit herwin is, word **profile op die stelsel gestoor**
- Hierdie stap begin outomaties (indien in **setup assistant**)
- Word deur **`CPInstallActivationProfile`** aangedryf
- Geïmplementeer deur mdmclient oor XPC
- LaunchDaemon (as root) of LaunchAgent (as user), afhangend van die konteks
- Configuration profiles het verskeie payloads om te installeer
- Framework het ’n plugin-based architecture vir die installering van profiles
- Elke payload-tipe word met ’n plugin geassosieer
- Kan XPC (in framework) of classic Cocoa (in ManagedClient.app) wees
- Voorbeeld:
- Certificate Payloads gebruik CertificateService.xpc

Tipies sal ’n **activation profile** wat deur ’n MDM vendor verskaf word, die volgende payloads **insluit**:

- `com.apple.mdm`: om die toestel in MDM **te enroll**
- `com.apple.security.scep`: om ’n **client certificate** veilig aan die toestel te verskaf.
- `com.apple.security.pem`: om trusted CA-certificates in die toestel se System Keychain **te installeer**.
- Installering van die MDM-payload is gelykstaande aan **MDM check-in in the documentation**
- Payload **bevat belangrike properties**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic om dit te trigger
- Om die MDM-payload te installeer, word ’n request na **`CheckInURL`** gestuur
- Geïmplementeer in **`mdmclient`**
- MDM-payload kan van ander payloads afhanklik wees
- Laat toe dat **requests aan spesifieke certificates gepin** word:
- Property: **`CheckInURLPinningCertificateUUIDs`**
- Property: **`ServerURLPinningCertificateUUIDs`**
- Gelewer via PEM-payload
- Laat toe dat ’n identity certificate aan die toestel toegeken word:
- Property: IdentityCertificateUUID
- Gelewer via SCEP-payload

### **Stap 7: Luister vir MDM-commands**

- Nadat MDM check-in voltooi is, kan die vendor **push notifications met APNs stuur**
- By ontvangs word dit deur **`mdmclient`** hanteer
- Om vir MDM-commands te poll, word ’n request na ServerURL gestuur
- Gebruik die voorheen geïnstalleerde MDM-payload:
- **`ServerURLPinningCertificateUUIDs`** vir pinning van die request
- **`IdentityCertificateUUID`** vir TLS client certificate

## Aanvalle

### Enrolling van toestelle in ander organisasies

Soos voorheen aangedui, is slegs ’n Serial Number wat aan daardie organisasie behoort nodig om ’n toestel in ’n organisasie te probeer enroll. Sodra die toestel enrolled is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: certificates, applications, WiFi passwords, VPN configurations [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit ’n gevaarlike entrypoint vir aanvallers wees indien die enrollment-proses nie behoorlik beskerm word nie:<sup>[2]</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Verwysings

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
