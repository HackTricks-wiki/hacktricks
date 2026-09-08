# Privaatheidsbewarende kommunikasie en deling

End-to-end encryption beskerm inhoud. Dit verberg nie outomaties die rekening, telefoonnommer, kontakgrafiek, IP-adres, push-token, kennisgewingvoorskou, tydsberekening, lêermetadata of ontvangersgedrag nie. Kies 'n instrument volgens die metadata wat dit verwyder en die waarnemers wat dit bekendstel.

## Vergelyk kommunikasie-modelle

| Instrument/model | Nuttige eienskap | Oorblywende waarnemers en beperkings |
|---|---|---|
| Signal | Volwasse E2EE; usernames kan kontak begin sonder om die nommer te deel; sealed sender verminder diensmetadata | Telefoonnommer word vir registrasie vereis; diens, push-verskaffer, kontakte en endpoints behou sommige waarnemings |
| SimpleX | Geen globale gebruikersidentifiseerder nie; toue per kontak; opsionele Tor-transport | Relay-tydsberekening/-transport, push-diens, uitnodigings en endpoints; nuwer/kleiner ekosisteem |
| Briar | Direkte sinchronisasie; Tor aanlyn; Bluetooth/Wi-Fi vanlyn; geen sentrale boodskapstoorplek nie | Kontakte en endpoints; plaaslike radio-waarnemers; Android-gefokus; beide kante moet beskikbaar wees of Mailbox gebruik |
| OnionShare | Direkte lêer/ontvangs/klets/werf oor 'n tydelike onion service; geen storage provider nie | Sender se rekenaar is die diens; die skakeldraer leer toegang; tydsberekening en endpoints bly sigbaar |
| `age`-geënkripteerde lêer | Eenvoudige ontvanger-sleutel-enkripsie onafhanklik van transport | Transport sien sender/ontvanger/tydsberekening/grootte; lêername/argiefmetadata en endpoints bly sigbaar |
| Gewone e-pos + TLS | Bediener-tot-bediener-kanaalenkripsie | Albei posverskaffers kan inhoud normaalweg lees en roeterings-/rekeningmetadata behou |

## Signal: private kontak sonder nommerbekendmaking

Signal-usernames kan 'n klets begin sonder om die gebruiker se telefoonnommer aan die nuwe kontak te openbaar, maar 'n telefoonnommer bly nodig vir registrasie.<sup>[[1]](#references)</sup> Sealed sender is 'n inkrementele metadatabeskerming, nie weerstand teen alle IP-/tydsberekeningskorrelasie nie.<sup>[[2]](#references)</sup>

### Werksvloei

1. Installeer Signal vanaf die amptelike app store/projek en werk eers die OS op.
2. Registreer met 'n nommer wat jy wettiglik mag gebruik. Moenie gehuurde SMS-aktiverings, iemand anders se nommer of 'n verskafferrekening wat met valse identiteit verkry is, gebruik nie.
3. Gaan na **Settings → Privacy → Phone Number** en stel volgens die threat model wie die nommer kan sien en wie die rekening volgens nommer kan vind.
4. Skep 'n username vir ontdekking deur nuwe kontakte. Deel die presiese skakel/QR deur 'n reeds geverifieerde kanaal; usernames kan verander en is nie die profielnaam nie.
5. Deaktiveer kontakoplaai/-toestemmings as gerief nie die koppeling werd is nie, en voeg kontakte handmatig by waar die platform dit ondersteun.
6. Maak die kontakbesonderhede oop en vergelyk die safety number/QR oor 'n tweede kanaal of persoonlik voordat jy sensitiewe inhoud stuur.
7. Hersien linked devices, registration lock/PIN, notification previews, screen security, call relaying, verstekke vir disappearing messages en backup-gedrag.
8. Stuur 'n nie-sensitiewe toetsboodskap en maak 'n oproep. Ondersoek lock-screen-, desktop-, wearable- en cloud-notification-spore aan albei kante.
9. Behandel 'n veranderde safety number of onverwagte linked device as 'n ondersoekgebeurtenis, nie as 'n waarskuwing wat outomaties geïgnoreer moet word nie.

Moenie 'n pseudonieme profielfoto, bio, groeplidmaatskap of skedule met 'n identifiserende Signal-konteks meng nie.

## SimpleX: verbindings per kontak sonder 'n globale identifiseerder

SimpleX roeteer boodskappe deur eenrigting-toue en ken nie 'n netwerk-wye gebruikersidentifiseerder toe nie. Sy eie beleid dokumenteer steeds transport-sessies, tydelike bedienerdata, afwegings rondom push notifications en endpoint-verantwoordelikheid.<sup>[[3]](#references)</sup>

### Werksvloei

1. Laai 'n onderhoude client vanaf die amptelike projek/store af en verifieer die uitgewer. Gebruik 'n toegewyde OS-/app-profiel wanneer identiteite nie moet meng nie.
2. Skep 'n **plaaslike** profiel met 'n konteks-spesifieke vertoonnaam en beeld. Die verwydering van die app sonder 'n backup kan die profiel en verbindings verloor.
3. Kies die notification mode doelbewus wanneer die app die eerste keer begin. Onmiddellike mobiele push kan bykomende metadata aan Apple-/Google-infrastruktuur blootstel.
4. Skep 'n eenmalige uitnodigingskakel vir een kontak. Dra dit deur 'n geverifieerde kanaal oor; enigiemand wat 'n aktiewe uitnodiging verkry, kan probeer om dit te gebruik.
5. Nadat jy verbind het, maak die kontakbesonderhede oop en vergelyk die security code persoonlik of oor 'n onafhanklike geverifieerde kanaal.<sup>[[4]](#references)</sup>
6. Gebruik 'n incognito per-group-profiel waar dit ondersteun word, in plaas daarvan om dieselfde profiel oor onverwante groepe te hergebruik.
7. Stel die client se ondersteunde Tor-transport op as die plaaslike netwerk/bediener nie die direkte IP moet sien nie. Bevestig die verbinding ná die verandering; moenie 'n nie-ondersteunde stelsel-proxy afdwing nie.
8. Hersien afleweringsbewyse, skakelvoorskoue, oproepe, outomatiese downloads en databasis-uitvoer/backup. Elkeen verander metadata- of endpoint-blootstelling.
9. Toets recovery op 'n ekstra geïsoleerde toestel sonder om gedupliseerde aktiewe profieltoestand te gebruik; die projek waarsku dat gelyktydige kopieë gesprekke kan ontwrig.

Geen globale identifiseerder verhoed dat 'n kontak die gebruiker deur inhoud, profielhergebruik, uitnodigingsaflewering, tydsberekening of sosiale grafiek identifiseer nie.

## Briar: direkte en ontwrigtingsbestande boodskappe

Briar sinchroniseer direk tussen toestelle, deur Tor wanneer dit aanlyn is en deur Bluetooth/Wi-Fi tydens plaaslike onderbrekings. Die amptelike threat model aanvaar slegs beperkte vyandige monitering van kortafstandradio, dus is plaaslike wireless nie onsigbaar nie.<sup>[[5]](#references)</sup>

### Werksvloei

1. Installeer vanaf die amptelike Briar-verspreiding en verifieer die pakketbron. Gebruik 'n ondersteunde Android-toestel met huidige security updates.
2. Skep 'n plaaslike rekening met 'n unieke konteks-bynaam en sterk wagwoord. Daar is geen wagwoord-resetpad nie; toets dat die ontsluitsleutel herwinbaar is.
3. Voeg kontakte van aangesig tot aangesig by deur mekaar se QR-kodes te skandeer waar moontlik. Dit verifieer die kontak en vermy die stuur van 'n skakel deur 'n korreleerbare kanaal.
4. Aktiveer in connectivity settings slegs die transports wat nodig is: Tor/Internet, Wi-Fi en/of Bluetooth. Deaktiveer plaaslike radio's wanneer dit nie nodig is nie.
5. Vir asinchrone aflewering, evalueer Briar Mailbox op 'n toegewyde toestel wat aan krag gekoppel is; inventariseer en beskerm dit fisies soos 'n message server.
6. Stuur 'n onskadelike toets terwyl Internet beskikbaar is, en toets daarna die beplande onderbrekingspad met Internet gedeaktiveer op 'n plek waarvoor die eienaar toestemming gegee het.
7. Ondersoek Android-backups, notification previews, screenshots en uitgevoerde inhoud. Plaaslike geënkripteerde stoorplek word blootgestel wanneer die endpoint ontsluit/gekompromitteer is.
8. Verwyder verlore kontakte/toestelle en tree die hele konteks af indien fisiese beheer of die rekeningwagwoord gekompromitteer is.

## OnionShare: direkte tydelike oordrag

OnionShare bedryf 'n onion service op die sender/ontvanger se rekenaar; lêers word nie na 'n storage provider opgelaai nie, en verkeer is end-to-end encrypted binne Tor.<sup>[[6]](#references)</sup> Die volledige onion-URL is 'n bearer capability en moet beskerm word.

### GUI-lêerdelingswerksvloei

1. Installeer OnionShare vanaf die amptelike ondertekende verspreiding en Tor Browser aan die ontvanger se kant.
2. Plaas **gesaniteerde kopieë** van lêers in 'n toegewyde staging directory. Moenie OnionShare na 'n persoonlike tuisgids wys nie.
3. Maak **Share Files** oop, voeg slegs die gestage lêers by, laat private-key/access protection geaktiveer, en hou **Stop sharing after files have been sent** geaktiveer vir een ontvanger.
4. Begin deling en stuur die volledige onion-URL deur 'n reeds geverifieerde E2EE-kanaal. Moenie dit in e-pos, issue trackers of publieke kletse plak nie.
5. Die ontvanger maak die URL in Tor Browser oop, verifieer die verwagte lêername/grootte met die sender en laai dit af.
6. Albei kante vergelyk 'n vooraf ooreengekome of afsonderlik afgelewerde SHA-256-digest vir integriteit wanneer die lêer self die security boundary is.
7. Bevestig dat OnionShare ná die download gestop het; anders stop dit handmatig en sluit die toepassing.
8. Verwyder die gestage kopie volgens die retention policy en ondersoek OnionShare se history/log-instellings vir onbedoelde lêernaambekendmaking.

### CLI-werksvloei

Die amptelike CLI aanvaar lêers as positional arguments en stop ná die verstek-enkele voltooide share. Op 'n host waarop die amptelike CLI/Tor geïnstalleer is:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Lewer die volledige URL veilig. Moenie `--public`, `--no-autostop-sharing`, verbose filename logging of persistence byvoeg nie, tensy die bedreigingsmodel die gevolglike blootstelling uitdruklik vereis.<sup>[[7]](#references)</sup>

Behandel ontvangde dokumente as vyandig. Maak hulle in ’n weggooibare VM/Dangerzone-styl renderer oop eerder as op die identiteit-draende host.

## Enkripteer ’n lêer onafhanklik met `age`

Transport-onafhanklike enkripsie is nuttig wanneer ’n storage/e-posverskaffer die objek kan sien. Dit verberg nie die sender, ontvanger, grootte, tydsberekening of filename nie, tensy dit afsonderlik hanteer word.

### Opstel van ontvanger
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Verifieer die publieke ontvangerstring deur ’n tweede kanaal. Die sender voer dan die volgende uit:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Die ontvanger dekripteer dit na 'n nuwe pad:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Die amptelike CLI waarsku dat `-o` ’n bestaande uitvoer oorskryf, dus gebruik ’n nuwe gids en verifieer die digest/inhoud voordat jy dit verskuif.<sup>[[8]](#references)</sup> Moet nooit die identiteitslêer saam met die ciphertext stuur nie.

## Reproduseerbare lêer-saneringspyplyn

Die verwydering van metadata is formaatspesifiek. Behou ’n geënkripteerde oorspronklike wanneer egtheid, forensiese ondersoek of bewysketting belangrik is; werk op ’n kopie.

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
Dit volg ExifTool se veiliger JPEG-riglyne: om elke tag blindelings te verwyder, kan ook kleurinligting verwyder.<sup>[[9]](#references)</sup> Inspekteer dan die pixels visueel vir gesigte, refleksies, skerms, landmerke en unieke skade-/geraaspatrone.

### Kantoor/PDF-werkvloei

1. Hou die redigeerbare oorspronklike geënkripteer en van die publikasiekonteks aflyn.
2. Verwyder opmerkings, nagespoorde veranderinge, versteekte skyfies/velle, ingebedde lêers, persoonlike sjablone en dokumenteienskappe in die outeurstoepassing.
3. Voer ’n nuwe PDF vanuit ’n toegewyde skoon profiel uit; moenie dit na ’n wolkdrukker “druk” nie.
4. Inspekteer dit met beide formaatsbewuste nutsmiddels en ’n weggooibare visuele weergaweerder:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Soek die weergegee uitvoer na name, paaie, e-posadresse en hersieningsteks. Rasterisering kan aktiewe strukture verwyder, maar benadeel toeganklikheid/soektog en verwyder nie sigbare inhoud of skryfstyl nie.
6. Hash die finale artefak en dra **slegs** daardie kopie deur die publikasiekompartement oor.

## Privacy Pass: anonieme magtiging vir diensontwerpers

Privacy Pass skei token **uitreiking** van **inwisseling**. ’n Oorsprong kan leer dat ’n kliënt ’n token besit wat deur ’n uitreiker goedgekeur is, sonder om die kliënt se spesifieke uitreikingsinteraksie te leer. Hergebruik van ’n token, unieke metadata, tydsberekening of sameswering kan linkability herinstel.<sup>[[10]](#references)</sup>

Veilige ontplooiingspatroon:

1. Definieer die stelling wat die token bewys (byvoorbeeld geskiktheid vir ’n tariefbeperking), nie ’n verborge globale identiteit nie.
2. Gebruik die gestandaardiseerde argitektuur en uitreikingsprotokolle; moenie blind-signature-kriptografie van nuuts af implementeer nie.
3. Ske i die uitreiker/attester- en oorsprongadministrasie waar die verlangde eienskap dit vereis.
4. Minimaliseer publieke/private token-metadata en verseker dat anonimiteitstelle groot genoeg is.
5. Reik bondels uit voordat dit gebruik word waar dit ondersteun word, sodat uitreikingstyd nie maklik met inwisselingstyd ooreenstem nie.
6. Wissel elke token een keer in, valideer die oorspronggebonde uitdaging en verwyder toestand vir vervalde tokens.
7. Verhoed dat cookies, IP-logging en toepassingrekeninge die token-privaatheidseienskap stilweg verydel.
8. Toets of uitreiker- en oorspronglogboeke ’n beheerde uitreikings- en inwisselingsgebeurtenis kan verbind deur tydsberekening, metadata of unieke foute te gebruik.

Privacy Pass is ’n toepassingkenmerk, nie iets wat ’n gebruiker op ’n arbitrêre rekening kan aanbring nie.

## Kommunikasieverifikasie-kontrolelys

- [ ] Kontakpersoon/uitnodiging/sleutel is onafhanklik geverifieer.
- [ ] Blootstelling van telefoonnommer, gebruikersnaam, profiel, groep en opgelaaide kontakte word verstaan.
- [ ] Direkte IP-, relay-, Tor-, push-provider- en plaaslike-radiowaarnemers word gelys.
- [ ] Kennisgewingvoorskoue, draagbare toestelle, gekoppelde rekenaars en rugsteune is getoets.
- [ ] Lêers is gesaniteer, indien nodig geënkripteer en in ’n weggooibare konteks oopgemaak.
- [ ] Herstel werk sonder om onverwante identiteite te oorbrug.
- [ ] Logboeke, geskiedenis en tydelike deeldienste het ’n afskakelings-/behoudsreël.

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
