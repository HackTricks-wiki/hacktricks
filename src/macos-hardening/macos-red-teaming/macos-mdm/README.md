# macOS MDM

{{#include ../../../banners/hacktricks-training.md}}

**Om meer oor macOS MDM's te leer, kyk:**

- [https://www.youtube.com/watch?v=ku8jZe-MHUU](https://www.youtube.com/watch?v=ku8jZe-MHUU)
- [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)

## Basiese beginsels

### **MDM (Mobiele Toestelbestuur) Oorsig**

[Mobiele Toestelbestuur](https://en.wikipedia.org/wiki/Mobile_device_management) (MDM) word gebruik om verskeie eindgebruikertoestelle soos slimfone, skootrekenaars en tablette te bestuur. Veral vir Apple se platforms (iOS, macOS, tvOS), dit behels 'n stel gespesialiseerde funksies, API's en praktyke. Die werking van MDM hang af van 'n versoenbare MDM-bediener, wat kommersieel beskikbaar of oopbron kan wees, en moet die [MDM-protokol](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) ondersteun. Sleutelpunte sluit in:

- Gekonsolideerde beheer oor toestelle.
- Afhangend van 'n MDM-bediener wat aan die MDM-protokol voldoen.
- Vermoë van die MDM-bediener om verskeie opdragte na toestelle te stuur, byvoorbeeld, afstandsdata-uitwissing of konfigurasie-installasie.

### **Basiese beginsels van DEP (Toestelregistrasieprogram)**

Die [Toestelregistrasieprogram](https://www.apple.com/business/site/docs/DEP_Guide.pdf) (DEP) wat deur Apple aangebied word, stroomlyn die integrasie van Mobiele Toestelbestuur (MDM) deur nul-aanraaking konfigurasie vir iOS, macOS en tvOS toestelle te fasiliteer. DEP outomatiseer die registrasieproses, wat toestelle in staat stel om reg uit die boks te funksioneer, met minimale gebruikers- of administratiewe ingryping. Belangrike aspekte sluit in:

- Stel toestelle in staat om outonoom met 'n vooraf gedefinieerde MDM-bediener te registreer by die aanvanklike aktivering.
- Primêr voordelig vir splinternuwe toestelle, maar ook toepaslik vir toestelle wat herkonfigureer word.
- Fasiliteer 'n eenvoudige opstelling, wat toestelle vinnig gereed maak vir organisatoriese gebruik.

### **Sekuriteitsoorweging**

Dit is belangrik om daarop te let dat die gemak van registrasie wat deur DEP verskaf word, terwyl dit voordelig is, ook sekuriteitsrisiko's kan inhou. As beskermingsmaatreëls nie voldoende afgedwing word vir MDM-registrasie nie, kan aanvallers hierdie gestroomlynde proses benut om hul toestel op die organisasie se MDM-bediener te registreer, terwyl hulle as 'n korporatiewe toestel voorgee.

> [!CAUTION]
> **Sekuriteitswaarskuwing**: Vereenvoudigde DEP-registrasie kan moontlik ongeoorloofde toestelregistrasie op die organisasie se MDM-bediener toelaat as behoorlike beskermingsmaatreëls nie in plek is nie.

### Wat is SCEP (Eenvoudige Sertifikaatregistrasieprotokol)?

- 'n Relatief ou protokol, geskep voordat TLS en HTTPS algemeen was.
- Gee kliënte 'n gestandaardiseerde manier om 'n **Sertifikaatondertekeningsversoek** (CSR) te stuur ten einde 'n sertifikaat te verkry. Die kliënt sal die bediener vra om vir hom 'n ondertekende sertifikaat te gee.

### Wat is Konfigurasieprofiele (ook bekend as mobileconfigs)?

- Apple se amptelike manier om **stelselskonfigurasie in te stel/af te dwing.**
- Lêerformaat wat verskeie payloads kan bevat.
- Gebaseer op eiendomslyste (die XML-tipe).
- “kan onderteken en geënkripteer word om hul oorsprong te valideer, hul integriteit te verseker, en hul inhoud te beskerm.” Basiese beginsels — Bladsy 70, iOS Sekuriteitsgids, Januarie 2018.

## Protokolle

### MDM

- Kombinasie van APNs (**Apple bediener**s) + RESTful API (**MDM** **verkoper** bedieners)
- **Kommunikasie** vind plaas tussen 'n **toestel** en 'n bediener wat geassosieer is met 'n **toestel** **bestuur** **produk**
- **Opdragte** gelewer van die MDM na die toestel in **plist-gecodeerde woordeboeke**
- Oral oor **HTTPS**. MDM-bedieners kan (en is gewoonlik) ge-pin.
- Apple gee die MDM-verkoper 'n **APNs sertifikaat** vir verifikasie

### DEP

- **3 API's**: 1 vir herverkopers, 1 vir MDM-verkopers, 1 vir toestelidentiteit (nie gedokumenteer nie):
- Die sogenaamde [DEP "cloud service" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Dit word deur MDM-bedieners gebruik om DEP-profiele met spesifieke toestelle te assosieer.
- Die [DEP API wat deur Apple Geautoriseerde Herverkopers gebruik word](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) om toestelle te registreer, registrasiestatus te kontroleer, en transaksie-status te kontroleer.
- Die nie gedokumenteerde private DEP API. Dit word deur Apple Toestelle gebruik om hul DEP-profiel aan te vra. Op macOS is die `cloudconfigurationd` binêre verantwoordelik vir kommunikasie oor hierdie API.
- Meer modern en **JSON** gebaseer (teenoor plist)
- Apple gee 'n **OAuth-token** aan die MDM-verkoper

**DEP "cloud service" API**

- RESTful
- sinkroniseer toestelrekords van Apple na die MDM-bediener
- sinkroniseer “DEP-profiele” na Apple van die MDM-bediener (later aan die toestel gelewer deur Apple)
- 'n DEP “profiel” bevat:
- MDM-verkoper bediener URL
- Bykomende vertroude sertifikate vir bediener URL (opsionele pinning)
- Ekstra instellings (bv. watter skerms om in die Setup Assistant oor te slaan)

## Serienommer

Apple-toestelle wat na 2010 vervaardig is, het oor die algemeen **12-karakter alfanumeriese** serienommers, met die **eerste drie syfers wat die vervaardigingsligging verteenwoordig**, die volgende **twee** wat die **jaar** en **week** van vervaardiging aandui, die volgende **drie** syfers wat 'n **unieke** **identifiseerder** verskaf, en die **laaste** **vier** syfers wat die **modelnommer** verteenwoordig.

{{#ref}}
macos-serial-number.md
{{#endref}}

## Stappe vir registrasie en bestuur

1. Toestelrekord skep (Herverkoper, Apple): Die rekord vir die nuwe toestel word geskep
2. Toestelrekord toewys (Kliënt): Die toestel word aan 'n MDM-bediener toegewy
3. Toestelrekord sinkroniseer (MDM-verkoper): MDM sinkroniseer die toestelrekords en druk die DEP-profiele na Apple
4. DEP inligting (Toestel): Toestel ontvang sy DEP-profiel
5. Profielherwinning (Toestel)
6. Profielinstallasie (Toestel) a. insluitend MDM, SCEP en wortel CA payloads
7. MDM-opdrag uitreiking (Toestel)

![](<../../../images/image (694).png>)

Die lêer `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` voer funksies uit wat as **hoëvlak "stappe"** van die registrasieproses beskou kan word.

### Stap 4: DEP inligting - Verkryging van die Aktiveringsrekord

Hierdie deel van die proses vind plaas wanneer 'n **gebruiker 'n Mac vir die eerste keer opstart** (of na 'n volledige skoonmaak)

![](<../../../images/image (1044).png>)

of wanneer `sudo profiles show -type enrollment` uitgevoer word

- Bepaal **of toestel DEP geaktiveer is**
- Aktiveringsrekord is die interne naam vir **DEP “profiel”**
- Begin sodra die toestel aan die internet gekoppel is
- Gedryf deur **`CPFetchActivationRecord`**
- Geïmplementeer deur **`cloudconfigurationd`** via XPC. Die **"Setup Assistant"** (wanneer die toestel eerste keer opgestart word) of die **`profiles`** opdrag sal **hierdie daemon** kontak om die aktiveringsrekord te verkry.
- LaunchDaemon (loop altyd as root)

Dit volg 'n paar stappe om die Aktiveringsrekord te verkry wat deur **`MCTeslaConfigurationFetcher`** uitgevoer word. Hierdie proses gebruik 'n enkripsie genaamd **Absinthe**

1. Verkry **sertifikaat**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Begin** toestand vanaf sertifikaat (**`NACInit`**)
1. Gebruik verskeie toestelspesifieke data (d.w.s. **Serienommer via `IOKit`**)
3. Verkry **sessiesleutel**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Vestig die sessie (**`NACKeyEstablishment`**)
5. Maak die versoek
1. POST na [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) en stuur die data `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. Die JSON payload is geënkripteer met behulp van Absinthe (**`NACSign`**)
3. Alle versoeke oor HTTPs, ingeboude wortelsertifikate word gebruik

![](<../../../images/image (566) (1).png>)

Die antwoord is 'n JSON-woordeboek met belangrike data soos:

- **url**: URL van die MDM-verkoper gasheer vir die aktiveringsprofiel
- **anchor-certs**: Array van DER-sertifikate wat as vertroude ankers gebruik word

### **Stap 5: Profielherwinning**

![](<../../../images/image (444).png>)

- Versoek gestuur na **url verskaf in DEP-profiel**.
- **Anchor sertifikate** word gebruik om **vertroue te evalueer** indien verskaf.
- Herinnering: die **anchor_certs** eienskap van die DEP-profiel
- **Versoek is 'n eenvoudige .plist** met toestelidentifikasie
- Voorbeelde: **UDID, OS weergawe**.
- CMS-onderteken, DER-gecodeer
- Onderteken met behulp van die **toestelidentiteitsertifikaat (van APNS)**
- **Sertifikaatchain** sluit vervalle **Apple iPhone Device CA** in

![](<../../../images/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (2) (2).png>)

### Stap 6: Profielinstallasie

- Sodra verkry, **word profiel op die stelsel gestoor**
- Hierdie stap begin outomaties (indien in **setup assistant**)
- Gedryf deur **`CPInstallActivationProfile`**
- Geïmplementeer deur mdmclient oor XPC
- LaunchDaemon (as root) of LaunchAgent (as gebruiker), afhangende van konteks
- Konfigurasieprofiele het verskeie payloads om te installeer
- Raamwerk het 'n plugin-gebaseerde argitektuur vir die installering van profiele
- Elke payload tipe is geassosieer met 'n plugin
- Kan XPC (in raamwerk) of klassieke Cocoa (in ManagedClient.app) wees
- Voorbeeld:
- Sertifikaatpayloads gebruik CertificateService.xpc

Tipies, **aktiveringsprofiel** verskaf deur 'n MDM-verkoper sal **die volgende payloads insluit**:

- `com.apple.mdm`: om die toestel in MDM te **registreer**
- `com.apple.security.scep`: om 'n **kliëntsertifikaat** veilig aan die toestel te verskaf.
- `com.apple.security.pem`: om **vertroude CA-sertifikate** aan die toestel se Stelselsleutelhouer te installeer.
- Die installering van die MDM-payload is gelyk aan **MDM check-in in die dokumentasie**
- Payload **bevat sleutel eienskappe**:
- - MDM Check-In URL (**`CheckInURL`**)
- MDM Opdrag Polling URL (**`ServerURL`**) + APNs onderwerp om dit te aktiveer
- Om MDM-payload te installeer, word 'n versoek na **`CheckInURL`** gestuur
- Geïmplementeer in **`mdmclient`**
- MDM-payload kan op ander payloads afhanklik wees
- Laat **versoeke toe om aan spesifieke sertifikate ge-pin te word**:
- Eienskap: **`CheckInURLPinningCertificateUUIDs`**
- Eienskap: **`ServerURLPinningCertificateUUIDs`**
- Gelewer via PEM payload
- Laat toestel toe om met 'n identiteitssertifikaat toegeskryf te word:
- Eienskap: IdentityCertificateUUID
- Gelewer via SCEP payload

### **Stap 7: Luister na MDM-opdragte**

- Nadat MDM check-in voltooi is, kan verkoper **stoot kennisgewings gebruik maak van APNs**
- By ontvangs, hanteer deur **`mdmclient`**
- Om vir MDM-opdragte te poll, word 'n versoek na ServerURL gestuur
- Maak gebruik van die voorheen geïnstalleerde MDM-payload:
- **`ServerURLPinningCertificateUUIDs`** vir pinning versoek
- **`IdentityCertificateUUID`** vir TLS kliëntsertifikaat

## Aanvalle

### Registrasie van Toestelle in Ander Organisasies

Soos voorheen opgemerk, om te probeer om 'n toestel in 'n organisasie te registreer, **is slegs 'n Serienommer wat aan daardie Organisasie behoort, nodig**. Sodra die toestel geregistreer is, sal verskeie organisasies sensitiewe data op die nuwe toestel installeer: sertifikate, toepassings, WiFi-wagwoorde, VPN-konfigurasies [en so aan](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).\
Daarom kan dit 'n gevaarlike toegangspunt vir aanvallers wees as die registrasieproses nie korrek beskerm word nie:

{{#ref}}
enrolling-devices-in-other-organisations.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
