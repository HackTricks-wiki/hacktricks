# Privaatheidsbewarende kommunikasie en deling

{{#include ../banners/hacktricks-training.md}}

End-to-end encryption beskerm inhoud. Dit verberg nie outomaties die rekening, telefoonnommer, kontakgrafiek, IP-adres, push token, kennisgewingvoorskou, tydsberekening, lêermetadata of ontvangersgedrag nie. Kies 'n hulpmiddel volgens die metadata wat dit verwyder en die waarnemers wat dit bekendstel.

## Vergelyk kommunikasiemodelle

| Hulpmiddel/model | Nuttige eienskap | Oorblywende waarnemers en beperkings |
|---|---|---|
| Signal | Volwasse E2EE; usernames kan kontak begin sonder om die nommer te deel; sealed sender verminder diensmetadata | Telefoonnommer word vir registrasie vereis; diens, push provider, kontakte en endpoints behou sommige waarnemings |
| SimpleX | Geen globale user identifier nie; per-kontak-queues; opsionele Tor-transport | Relay-tydsberekening/transport, push service, uitnodigings en endpoints; nuwer/kleiner ekosisteem |
| Briar | Direkte sinchronisasie; Tor aanlyn; Bluetooth/Wi-Fi aflyn; geen sentrale boodskapstoorplek nie | Kontakte en endpoints; plaaslike radio-waarnemers; Android-gefokus; albei kante moet beskikbaar wees of Mailbox gebruik |
| OnionShare | Direkte file/receive/chat/site oor 'n tydelike onion service; geen storage provider nie | Sender se rekenaar is die diens; link bearer leer toegang; tydsberekening en endpoints bly sigbaar |
| `age` encrypted file | Eenvoudige recipient-key encryption, onafhanklik van transport | Transport sien sender/recipient/tydsberekening/grootte; lêername/archive metadata en endpoints bly sigbaar |
| Gewone e-pos + TLS | Server-to-server channel encryption | Albei mail providers kan normaalweg inhoud lees en routing/account metadata behou |

## Signal: private kontak sonder nommerbekendmaking

Signal usernames kan 'n chat begin sonder om die gebruiker se telefoonnommer aan die nuwe kontak bekend te maak, maar 'n telefoonnommer bly nodig vir registrasie.<sup>[[1]](#references)</sup> Sealed sender is 'n inkrementele metadatabeskerming, nie weerstand teen alle IP-/tydsberekeningskorrelasie nie.<sup>[[2]](#references)</sup>

### Werkvloei

1. Installeer Signal vanaf die amptelike app store/project en dateer die OS eers op.
2. Registreer met 'n nommer wat jy wettiglik mag gebruik. Moenie rented SMS activations, iemand anders se nommer of 'n provider account wat met vals identiteit verkry is, gebruik nie.
3. Gaan na **Settings → Privacy → Phone Number** en stel wie die nommer kan sien en wie die rekening volgens die threat model deur nommer kan vind.
4. Skep 'n username vir ontdekking deur nuwe kontakte. Deel die presiese link/QR deur 'n reeds geauthentiseerde kanaal; usernames kan verander en is nie die profielnaam nie.
5. Deaktiveer kontakoplaai/-toestemmings indien gerief nie die koppeling werd is nie, en voeg kontakte handmatig by waar die platform dit ondersteun.
6. Maak die kontakbesonderhede oop en vergelyk die safety number/QR oor 'n tweede kanaal of persoonlik voordat sensitiewe inhoud gestuur word.
7. Hersien linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults en backup behavior.
8. Stuur 'n nie-sensitiewe toetsboodskap en bel. Ondersoek lock-screen-, desktop-, wearable- en cloud-notification-spore aan albei kante.
9. Behandel 'n veranderde safety number of onverwagte linked device as 'n ondersoekgebeurtenis, nie as 'n waarskuwing wat outomaties afgemaak moet word nie.

Moenie 'n pseudonieme profielfoto, bio, groeplidmaatskap of skedule met 'n identifiserende Signal-konteks meng nie.

## SimpleX: per-kontak-verbindings sonder 'n globale identifier

SimpleX stuur boodskappe deur unidirectional queues en ken nie 'n network-wide user identifier toe nie. Sy eie beleid dokumenteer steeds transport sessions, temporary server data, push-notification tradeoffs en endpoint responsibility.<sup>[[3]](#references)</sup>

### Werkvloei

1. Laai 'n maintained client vanaf die amptelike project/store af en verifieer die publisher. Gebruik 'n toegewyde OS/app-profiel wanneer identiteite nie moet meng nie.
2. Skep 'n **local** profiel met 'n konteks-spesifieke display name en beeld. Die verwydering van die app sonder 'n backup kan die profiel en verbindings verloor.
3. Kies die notification mode doelbewus met die eerste bekendstelling. Onmiddellike mobile push kan bykomende metadata aan Apple/Google-infrastruktuur blootlê.
4. Skep 'n eenmalige uitnodigingslink vir een kontak. Dra dit deur 'n geauthentiseerde kanaal oor; enigiemand wat 'n lewendige uitnodiging bekom, kan probeer om dit te gebruik.
5. Maak die kontakbesonderhede oop nadat jy verbind het en vergelyk die security code persoonlik of oor 'n onafhanklike geverifieerde kanaal.<sup>[[4]](#references)</sup>
6. Gebruik 'n incognito per-group-profiel waar dit ondersteun word, eerder as om dieselfde profiel oor onverwante groepe te hergebruik.
7. Stel die client se ondersteunde Tor transport op indien die plaaslike netwerk/server nie die direkte IP moet sien nie. Bevestig die verbinding ná die verandering; moenie 'n unsupported system proxy forseer nie.
8. Hersien delivery receipts, link previews, calls, automatic downloads en database export/backup. Elkeen verander metadata of endpoint-blootstelling.
9. Toets recovery op 'n ekstra geïsoleerde toestel sonder om gedupliseerde lewendige profieltoestand te laat loop; die project waarsku dat gelyktydige kopieë conversations kan ontwrig.

'n Globale identifier voorkom nie dat 'n kontak die gebruiker deur inhoud, profielhergebruik, uitnodigingsaflewering, tydsberekening of sosiale grafiek identifiseer nie.

## Briar: direkte en ontwrigtingsbestande messaging

Briar sinchroniseer direk tussen toestelle, deur Tor wanneer aanlyn en deur Bluetooth/Wi-Fi tydens plaaslike onderbrekings. Die amptelike threat model neem slegs beperkte adversarial monitoring van kortafstand-radio aan, dus is plaaslike wireless nie onsigbaar nie.<sup>[[5]](#references)</sup>

### Werkvloei

1. Installeer vanaf die amptelike Briar-distribution en verifieer die package source. Gebruik 'n ondersteunde Android-toestel met huidige security updates.
2. Skep 'n local account met 'n unieke konteks-bynaam en sterk wagwoord. Daar is geen password-reset path nie; toets dat die unlock secret herwinbaar is.
3. Voeg kontakte van aangesig tot aangesig by deur mekaar se QR codes te skandeer waar moontlik. Dit authentiseer die kontak en vermy dat 'n link deur 'n korreleerbare kanaal gestuur word.
4. Skakel in connectivity settings slegs die benodigde transports aan: Tor/Internet, Wi-Fi en/of Bluetooth. Deaktiveer plaaslike radios wanneer dit nie nodig is nie.
5. Evalueer Briar Mailbox op 'n toegewyde toestel wat aan krag gekoppel is vir asynchronous delivery; inventariseer dit en beskerm dit fisies soos 'n message server.
6. Stuur 'n onskadelike toets terwyl Internet beskikbaar is, en toets daarna die beplande outage path met Internet gedeaktiveer in 'n eienaar-goedgekeurde ligging.
7. Ondersoek Android backups, notification previews, screenshots en exported content. Plaaslike encrypted storage word blootgestel wanneer die endpoint ontsluit of gekompromitteer is.
8. Verwyder verlore kontakte/toestelle en tree die hele konteks af indien fisiese bewaring of die account password gekompromitteer is.

## OnionShare: direkte tydelike oordrag

OnionShare laat 'n onion service op die sender/receiver se rekenaar loop; lêers word nie na 'n storage provider opgelaai nie, en verkeer is end-to-end encrypted binne Tor.<sup>[[6]](#references)</sup> Die volledige onion URL is 'n bearer capability en moet beskerm word.

### GUI-lêerdelingswerkvloei

1. Installeer OnionShare vanaf sy amptelike signed distribution en Tor Browser aan die recipient-kant.
2. Plaas **gesaniteerde kopieë** van lêers in 'n toegewyde staging directory. Moenie OnionShare na 'n persoonlike home directory wys nie.
3. Maak **Share Files** oop, voeg slegs die gestageerde lêers by, laat die private key/access protection geaktiveer, en hou **Stop sharing after files have been sent** geaktiveer vir een recipient.
4. Begin sharing en stuur die volledige onion URL deur 'n reeds geauthentiseerde E2EE-kanaal. Moenie dit in e-pos, issue trackers of openbare chats plak nie.
5. Die recipient maak die URL in Tor Browser oop, verifieer die verwagte lêername/grootte met die sender en laai dit af.
6. Albei kante vergelyk 'n vooraf ooreengekome of apart afgelewerde SHA-256 digest vir integriteit wanneer die lêer self die security boundary is.
7. Bevestig dat OnionShare ná die download gestop het; anders stop dit handmatig en sluit die application.
8. Verwyder die gestageerde kopie volgens die retention policy en ondersoek OnionShare se history/log settings vir onbedoelde bekendmaking van lêername.

### CLI-werkvloei

Die amptelike CLI aanvaar lêers as positional arguments en stop ná die verstek-enkele-voltooide share. Op 'n host met die amptelike CLI/Tor geïnstalleer:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Lewer die volledige URL veilig. Moenie `--public`, `--no-autostop-sharing`, verbose filename logging of persistence byvoeg nie, tensy die threat model die gevolglike blootstelling uitdruklik vereis.<sup>[[7]](#references)</sup>

Behandel ontvangde dokumente as vyandig. Maak hulle in 'n weggooibare VM/Dangerzone-style renderer oop eerder as op die gasheer wat jou identiteit dra.

## Enkripteer 'n lêer onafhanklik met `age`

Transport-independent encryption is nuttig wanneer 'n storage/e-posverskaffer moontlik die objek kan sien. Dit verberg nie die sender, ontvanger, grootte, tydsberekening of lêernaam nie, tensy dit afsonderlik hanteer word.

### Opstelling van ontvanger
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Verifieer die publieke ontvangerstring deur ’n tweede kanaal. Die sender voer dan uit:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Die ontvanger dekripteer dit na 'n nuwe pad:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Die amptelike CLI waarsku dat `-o` ’n bestaande uitvoer oorskryf, dus gebruik ’n nuwe gids en verifieer die digest/inhoud voordat jy dit verskuif.<sup>[[8]](#references)</sup> Moet nooit die identiteitslêer saam met die syferteks stuur nie.

## Reproduceerbare lêersaniteringspyplyn

Die verwydering van metadata is formaatspesifiek. Bewaar ’n geënkripteerde oorspronklike wanneer egtheid, forensiese ondersoek of bewysbewaring belangrik is; werk op ’n kopie.

### JPEG-voorbeeld
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Dit volg ExifTool se veiliger JPEG-riglyne: om blindelings elke tag te verwyder, kan ook kleurinligting verwyder.<sup>[[9]](#references)</sup> Inspekteer daarna die pixels visueel vir gesigte, weerkaatsings, skerms, landmerke en unieke skade-/geraaspatrone.

### Office/PDF-werkvloei

1. Hou die bewerkbare oorspronklike geënkripteer en van die publikasiekonteks aflyn.
2. Verwyder opmerkings, nagespoorde wysigings, versteekte skyfies/blaaie, ingebedde lêers, persoonlike templates en dokumenteienskappe in die outeursprogram.
3. Voer ’n nuwe PDF uit vanaf ’n toegewyde skoon profiel; moenie na ’n cloud-drukker “druk” nie.
4. Inspekteer met beide formaatgewyse nutsprogramme en ’n weggooibare visuele renderer:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Soek die gerenderde uitvoer na name, paaie, e-posadresse en hersieningsteks. Rasterisering kan aktiewe strukture verwyder, maar benadeel toeganklikheid/soektog en verwyder nie sigbare inhoud of skryfstyl nie.
6. Bereken die hash van die finale artefak en dra **slegs** daardie kopie deur die publikasiekompartement oor.

## Privacy Pass: anonieme magtiging vir diensontwerpers

Privacy Pass skei token-**uitreiking** van **inlossing**. ’n Oorsprong kan weet dat ’n kliënt ’n deur ’n issuer goedgekeurde token besit sonder om die kliënt se spesifieke uitreikingsinteraksie te ken. Die hergebruik van ’n token, unieke metadata, tydsberekening of sameswering kan linkability weer instel.<sup>[[10]](#references)</sup>

Veilige ontplooiingspatroon:

1. Definieer die stelling wat die token bewys (byvoorbeeld geskiktheid vir rate limiting), nie ’n versteekte globale identiteit nie.
2. Gebruik die gestandaardiseerde argitektuur en uitreikingsprotokolle; moenie blind-signature cryptography van nuuts af implementeer nie.
3. Skei issuer/attester- en oorsprongadministrasie waar die verlangde eienskap dit vereis.
4. Minimaliseer publieke/private token-metadata en verseker dat anonymity sets groot genoeg is.
5. Reik bondels uit voor gebruik waar dit ondersteun word, sodat die uitreikingstyd nie maklik met die inlossingstyd ooreenstem nie.
6. Los elke token een keer in, valideer die oorspronggebonde uitdaging en skrap vervalde token-toestand.
7. Verhoed dat cookies, IP-logging en toepassingrekeninge die token-privaatheidseienskap stilweg verydel.
8. Toets of issuer- en oorspronglogs ’n beheerde uitreikings- en inlossingsgebeurtenis kan koppel deur tydsberekening, metadata of unieke foute te gebruik.

Privacy Pass is ’n toepassingfunksie, nie iets wat ’n gebruiker op ’n arbitrêre rekening kan aanbring nie.

## Kontrolelys vir kommunikasieverifikasie

- [ ] Kontak/uitnodiging/sleutel is onafhanklik geverifieer.
- [ ] Blootstelling van telefoonnommer, gebruikersnaam, profiel, groep en kontakoplaaie word verstaan.
- [ ] Direkte IP-, relay-, Tor-, push-provider- en plaaslike-radio-waarnemers is gelys.
- [ ] Kennisgewingvoorskoue, wearables, gekoppelde desktops en rugsteun is getoets.
- [ ] Lêers is gesuiwer, indien nodig encrypted, en in ’n weggooibare konteks oopgemaak.
- [ ] Herstel werk sonder om onverwante identiteite te oorbrug.
- [ ] Logs, geskiedenis en tydelike deeldienste het ’n afsluitings-/retensiereël.

## References

- [1] [Signal — Privaatheid van telefoonnommers en gebruikersname](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privaatheidsbeleid en gebruiksvoorwaardes](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privaatheids- en sekuriteitsgids](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — Hoe dit werk](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Sekuriteitsontwerp](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Gevorderde gebruik en CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — amptelike CLI en gebruik](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Metadata veilig verwyder](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass-argitektuur](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}
