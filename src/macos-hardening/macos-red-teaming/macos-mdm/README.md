# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Om meer oor macOS MDMs te leer, kyk na:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)<sup>[[1]](#references)</sup>
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)<sup>[[2]](#references)</sup>

## Basiese beginsels

### **Oorsig van MDM (Mobile Device Management)**

[Mobile Device Management](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) word gebruik om verskeie eindgebruikertoestelle, soos slimfone, skootrekenaars en tablette, te bestuur. Vir Apple se platforms (iOS, macOS, tvOS) behels dit ’n stel gespesialiseerde kenmerke, APIs en praktyke. Die werking van MDM berus op ’n versoenbare MDM-server, wat kommersieel beskikbaar of open source kan wees, en wat die [MDM Protocol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) moet ondersteun. Belangrike punte sluit in:

- Gesentraliseerde beheer oor toestelle.
- Afhanklikheid van ’n MDM-server wat die MDM-protokol volg.
- Die vermoë van die MDM-server om verskeie opdragte na toestelle te stuur, byvoorbeeld om data op afstand uit te vee of konfigurasie te installeer.

### **Basiese beginsels van DEP (Device Enrollment Program)**

Apple se [Device Enrollment Program](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) vereenvoudig die integrasie van Mobile Device Management (MDM) deur zero-touch-konfigurasie vir iOS-, macOS- en tvOS-toestelle moontlik te maak. DEP outomatiseer die enrolment-proses, sodat toestelle onmiddellik uit die boks operasioneel kan wees, met minimale gebruiker- of administrateurintervensie. Belangrike aspekte sluit in:

- Stel toestelle in staat om outonoom met ’n voorafbepaalde MDM-server te registreer tydens aanvanklike aktivering.
- Is hoofsaaklik nuttig vir splinternuwe toestelle, maar ook toepaslik vir toestelle wat herkonfigurasie ondergaan.
- Fasiliteer ’n eenvoudige opstelling, sodat toestelle vinnig gereed is vir organisatoriese gebruik.

### **Sekuriteitsoorweging**

Dit is belangrik om daarop te let dat die maklike enrolment wat DEP bied, hoewel voordelig, ook sekuriteitsrisiko’s kan inhou. Indien beskermingsmaatreëls nie voldoende vir MDM-enrolment afgedwing word nie, kan aanvallers hierdie vereenvoudigde proses uitbuit om hul toestel op die organisasie se MDM-server te registreer en dit as ’n korporatiewe toestel voor te doen.<sup>[[2]](#references)</sup>

> [!CAUTION]
> **Sekuriteitswaarskuwing**: Vereenvoudigde DEP-enrolment kan moontlik ongemagtigde toestelregistrasie op die organisasie se MDM-server toelaat indien behoorlike beskermingsmaatreëls nie ingestel is nie.

### Basiese beginsels Wat is SCEP (Simple Certificate Enrolment Protocol)?

- ’n Relatief ou protokol, wat geskep is voordat TLS en HTTPS wydverspreid was.
- Gee kliënte ’n gestandaardiseerde manier om ’n **Certificate Signing Request** (CSR) te stuur met die doel om ’n sertifikaat te ontvang. Die kliënt sal die server vra om aan hom ’n ondertekende sertifikaat te verskaf.

### Wat is Configuration Profiles (ook bekend as mobileconfigs)?

- Apple se amptelike manier om **stelselkonfigurasie te stel/af te dwing.**
- Lêerformaat wat verskeie payloads kan bevat.
- Gebaseer op property lists (die XML-tipe).
- “can be signed and encrypted to validate their origin, ensure their integrity, and protect their contents.” Basics — Page 70, iOS Security Guide, January 2018.

## Protokolle

### MDM

- Kombinasie van APNs (**Apple server**s) + RESTful API (**MDM** **vendor**-servers)
- **Kommunikasie** vind plaas tussen ’n **toestel** en ’n server wat met ’n **toestel**-**bestuurs**-**produk** geassosieer word
- **Opdragte** word vanaf die MDM na die toestel gestuur in **plist-encoded dictionaries**
- Alles oor **HTTPS**. MDM-servers kan gepinned wees (en is dit gewoonlik).
- Apple verleen aan die MDM vendor ’n **APNs certificate** vir authentication

### DEP

- **3 APIs**: 1 vir herverkopers, 1 vir MDM vendors, 1 vir toestelidentiteit (ongedokumenteerd):
- Die sogenaamde [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Dit word deur MDM-servers gebruik om DEP profiles met spesifieke toestelle te assosieer.
- Die [DEP API used by Apple Authorized Resellers](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle te enrol, enrolment-status na te gaan en transaksiestatus na te gaan.
- Die ongedokumenteerde private DEP API. Dit word deur Apple Devices gebruik om hul DEP profile aan te vra. Op macOS is die `cloudconfigurationd`-binary verantwoordelik vir kommunikasie oor hierdie API.
- Meer modern en op **JSON** gebaseer (teenoor plist)
- Apple verleen ’n **OAuth token** aan die MDM vendor

**DEP "cloud service" API**

- RESTful
- sinkroniseer toestelrekords vanaf Apple na die MDM-server
- sinkroniseer “DEP profiles” vanaf die MDM-server na Apple (wat later deur Apple aan die toestel gelewer word)
- ’n DEP “profile” bevat:
- MDM vendor-server-URL
- Bykomende vertroude sertifikate vir server-URL (opsionele pinning)
- Ekstra instellings (bv. watter skerms in Setup Assistant oorgeslaan moet word)

## Serienommer

Apple-toestelle wat ná 2010 vervaardig is, het oor die algemeen **12-karakter alfanumeriese** serienommers, met die **eerste drie syfers wat die vervaardigingsligging verteenwoordig**, die volgende **twee** wat die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers wat ’n **unieke** **identifiseerder** verskaf, en die **laaste** **vier** syfers wat die **modelnommer** verteenwoordig.


{{#ref}}
macos-serial-number.md
{{#endref}}

## Stappe vir enrolment en bestuur

1. Skepping van toestelrekord (Herverkoper, Apple): Die rekord vir die nuwe toestel word geskep
2. Toewysing van toestelrekord (Kliënt): Die toestel word aan ’n MDM-server toegeken
3. Sinkronisering van toestelrekord (MDM vendor): MDM sinkroniseer die toestelrekords en stoot die DEP profiles na Apple
4. DEP check-in (Toestel): Toestel ontvang sy DEP profile
5. Herwinning van profile (Toestel)
6. Installasie van profile (Toestel) a. insluitend MDM-, SCEP- en root CA-payloads
7. Uitreiking van MDM-opdrag (Toestel)

![Serienommer - Stappe vir enrolment en bestuur: 7. Uitreiking van MDM-opdrag (Toestel)](<../../../images/image (694).png>)

Die lêer `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporteer funksies wat as **hoëvlak-"stappe"** van die enrolment-proses beskou kan word.

### Stap 4: DEP check-in - Verkryging van die Activation Record

Hierdie deel van die proses vind plaas wanneer ’n **gebruiker ’n Mac vir die eerste keer selflaai** (of ná ’n volledige wipe)

![Stappe vir enrolment en bestuur - Stap 4: DEP check-in - Verkryging van die Activation Record: Hierdie deel van die proses vind plaas wanneer ’n gebruiker ’n Mac vir die eerste keer selflaai (of ná ’n volledige...](<../../../images/image (1044).png>)

of wanneer `sudo profiles show -type enrollment` uitgevoer word

- Bepaal **of die toestel DEP-geaktiveer is**
- Activation Record is die interne naam vir DEP “profile”
- Begin sodra die toestel aan die Internet gekoppel is
- Word aangedryf deur **`CPFetchActivationRecord`**
- Geïmplementeer deur **`cloudconfigurationd`** via XPC. Die **"Setup Assistant**" (wanneer die toestel vir die eerste keer gelaai word) of die **`profiles`**-opdrag sal **hierdie daemon kontak** om die activation record te verkry.
- LaunchDaemon (loop altyd as root)

Dit volg ’n paar stappe om die Activation Record te verkry, wat deur **`MCTeslaConfigurationFetcher`** uitgevoer word. Hierdie proses gebruik ’n encryption genaamd **Absinthe**<sup>[[1]](#references)</sup>

1. Verkry **sertifikaat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Initialiseer** toestand vanaf sertifikaat (**`NACInit`**)
1. Gebruik verskeie toestelspesifieke data (d.w.s. **Serienommer via `IOKit`**)
3. Verkry **session key**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Stel die sessie daar (**`NACKeyEstablishment`**)
5. Maak die request
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) wat die data `{ "action": "RequestProfileConfiguration", "sn": "" }` stuur
2. Die JSON-payload word met Absinthe geënkripteer (**`NACSign`**)
3. Alle requests oor HTTPs; ingeboude root certificates word gebruik

![Stappe vir enrolment en bestuur - Stap 4: DEP check-in - Verkryging van die Activation Record: 3. Alle requests oor HTTPs; ingeboude root certificates word gebruik](<../../../images/image (566) (1).png>)

Die response is ’n JSON-dictionary met belangrike data soos:

- **url**: URL van die MDM vendor-host vir die activation profile
- **anchor-certs**: Array van DER-sertifikate wat as vertroude anchors gebruik word

### **Stap 5: Herwinning van Profile**

![Stap 4: DEP check-in - Verkryging van die Activation Record - Stap 5: Herwinning van Profile: Stap 5: Herwinning van Profile](<../../../images/image (444).png>)

- Request word na **url wat in DEP profile verskaf word** gestuur.
- **Anchor certificates** word gebruik om **trust te evalueer** indien dit verskaf word.
- Herinnering: die **anchor_certs**-eienskap van die DEP profile
- **Request is ’n eenvoudige .plist** met toestelidentifikasie
- Voorbeelde: **UDID, OS-weergawe**.
- CMS-signed, DER-encoded
- Onderteken met die **device identity certificate (from APNS)**
- **Certificate chain** sluit vervalde **Apple iPhone Device CA** in

![Stap 4: DEP check-in - Verkryging van die Activation Record - Stap 5: Herwinning van Profile: Onderteken met die device identity certificate (from APNS)](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Stap 6: Installasie van Profile

- Sodra dit verkry is, word **profile op die stelsel gestoor**
- Hierdie stap begin outomaties (indien dit in **setup assistant** plaasvind)
- Word aangedryf deur **`CPInstallActivationProfile`**
- Geïmplementeer deur mdmclient oor XPC
- LaunchDaemon (as root) of LaunchAgent (as gebruiker), afhangend van die konteks
- Configuration profiles het verskeie payloads om te installeer
- Framework het ’n plugin-gebaseerde argitektuur vir die installering van profiles
- Elke payload-tipe word met ’n plugin geassosieer
- Kan XPC (in framework) of klassieke Cocoa (in ManagedClient.app) wees
- Voorbeeld:
- Certificate Payloads gebruik CertificateService.xpc

Tipies sal die **activation profile** wat deur ’n MDM vendor verskaf word, die volgende payloads **insluit**:

- `com.apple.mdm`: om die toestel in MDM te **enrol**
- `com.apple.security.scep`: om veilig ’n **client certificate** aan die toestel te verskaf.
- `com.apple.security.pem`: om vertroude CA-sertifikate in die toestel se System Keychain te **installeer**.
- Die installering van die MDM-payload is gelykstaande aan **MDM check-in in the documentation**
- Payload **bevat sleutel-eienskappe**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Command Polling URL (**`ServerURL`**) + APNs topic om dit te trigger
- Om die MDM-payload te installeer, word ’n request na **`CheckInURL`** gestuur
- Geïmplementeer in **`mdmclient`**
- MDM-payload kan van ander payloads afhanklik wees
- Laat toe dat **requests aan spesifieke sertifikate gepinned word**:
- Eienskap: **`CheckInURLPinningCertificateUUIDs`**
- Eienskap: **`ServerURLPinningCertificateUUIDs`**
- Gelewer via PEM-payload
- Laat toe dat ’n identiteitsertifikaat aan die toestel toegeskryf word:
- Eienskap: IdentityCertificateUUID
- Gelewer via SCEP-payload

### **Stap 7: Luister na MDM-opdragte**

- Nadat MDM check-in voltooi is, kan die vendor **push notifications met APNs stuur**
- By ontvangs word dit deur **`mdmclient`** hanteer
- Om vir MDM-opdragte te poll, word ’n request na ServerURL gestuur
- Gebruik die voorheen geïnstalleerde MDM-payload:
- **`ServerURLPinningCertificateUUIDs`** vir pinning van die request
- **`IdentityCertificateUUID`** vir TLS client certificate

## Aanvalle

### Enrolling van toestelle in ander organisasies

Soos voorheen genoem, is slegs **’n serienommer wat aan daardie organisasie behoort** nodig om te probeer om ’n toestel by ’n organisasie te enrol. Sodra die toestel ingeskryf is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi-wagwoorde, VPN-konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit ’n gevaarlike intreepunt vir aanvallers wees indien die enrolment-proses nie behoorlik beskerm word nie:<sup>[[2]](#references)</sup>


{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

## Verwysings

- [1] [A Deep Dive into macOS MDM (and How it can be Compromised)](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [2] [Duo Labs — "MDM Me Maybe?" (DEP/MDM enrollment security research)](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
