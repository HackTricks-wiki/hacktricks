# Side-Channel Attacks met afleweringsbevestigings in E2EE-boodskapprogramme

{{#include ../banners/hacktricks-training.md}}

Afleweringsbevestigings is verpligtend in moderne end-to-end encrypted (E2EE)-boodskapprogramme, omdat clients moet weet wanneer ’n ciphertext gedekripteer is, sodat hulle ratcheting state en ephemeral keys kan weggooi. Die bediener stuur ondeursigtige blobs aan, dus word toestelbevestigings (dubbele regmerkies) deur die ontvanger uitgestuur ná suksesvolle dekripsie. Deur die round-trip time (RTT) tussen ’n aksie wat deur ’n aanvaller geaktiveer word en die ooreenstemmende afleweringsbevestiging te meet, word ’n hoë-resolusie-tydskanaal blootgelê wat toesteltoestand en aanlynteenwoordigheid lek, en wat vir covert DoS misbruik kan word. Multi-device-ontplooiings met “client-fanout” versterk die lekkasie, omdat elke geregistreerde toestel die probe dekripteer en sy eie bevestiging terugstuur.<sup>[[1]](#references)</sup>

## Bronne van afleweringsbevestigings teenoor seine wat vir gebruikers sigbaar is

Kies boodskapsoorte wat altyd ’n afleweringsbevestiging uitstuur, maar geen UI-artefakte op die slagoffer se toestel vertoon nie. Die tabel hieronder som die empiries bevestigde gedrag op:<sup>[[1]](#references)</sup>

| Boodskapprogram | Aksie | Afleweringsbevestiging | Slagofferkennisgewing | Notas |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Teksboodskap | ● | ● | Altyd opvallend → net nuttig om die toestand te initialiseer. |
| | Reaksie | ● | ◐ (slegs as daar op ’n boodskap van die slagoffer gereageer word) | Self-reaksies en verwyderings bly stil. |
| | Wysig | ● | Platform-afhanklike silent push | Wysigvenster ≈20 min; bevestiging word steeds ná verstryking uitgestuur. |
| | Verwyder vir almal | ● | ○ | UI laat ~60 h toe, maar latere pakkette word steeds bevestig. |
| **Signal** | Teksboodskap | ● | ● | Dieselfde beperkings as WhatsApp. |
| | Reaksie | ● | ◐ | Self-reaksies is onsigbaar vir die slagoffer. |
| | Wysig/Verwyder | ● | ○ | Die bediener dwing ’n venster van ~48 h af en laat tot 10 wysigings toe, maar laat pakkette word steeds bevestig. |
| **Threema** | Teksboodskap | ● | ● | Multi-device-bevestigings word saamgevoeg, dus word slegs een RTT per probe sigbaar. |

Sleutel: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-afhanklike UI-gedrag word inline aangedui. Skakel leesbevestigings af indien nodig, maar afleweringsbevestigings kan nie in WhatsApp of Signal afgeskakel word nie.<sup>[[1]](#references)</sup>

## Aanvallerdoelwitte en -modelle

* **G1 – Toestelfingerprinting:** Tel hoeveel bevestigings per probe aankom, groepeer RTT’s om die bedryfstelsel/client af te lei (Android teenoor iOS of desktop), en monitor aanlyn-/aflyn-oorgange.
* **G2 – Gedragsmonitering:** Behandel die hoëfrekwensie-RTT-reeks (≈1 Hz is stabiel) as ’n tydreeks en lei af wanneer die skerm aan/af is, wanneer die app voorgrond/agtergrond is, pendel- teenoor werksure, ens.
* **G3 – Hulpbronuitputting:** Hou die radio’s/SVE’s van elke slagoffertoestel wakker deur eindelose stil probes te stuur, wat die battery/data dreineer en die gehalte van video-oproepe verswak.<sup>[[1]](#references)</sup>

Twee bedreigingsakteurs is genoeg om die misbruikoppervlak te beskryf:<sup>[[1]](#references)</sup>

1. **Creepy companion:** deel reeds ’n gesprek met die slagoffer en misbruik self-reaksies, verwyderings van reaksies, of herhaalde wysigings/uitveeaksies wat aan bestaande boodskap-ID’s gekoppel is.
2. **Spooky stranger:** registreer ’n weggooirekening en stuur reaksies wat verwys na boodskap-ID’s wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en bevestig dit steeds, hoewel die UI die toestandverandering weggooi, dus is geen vorige gesprek nodig nie.

## Gereedskap vir toegang tot rou protokolle

Gebruik clients wat genoeg van die onderliggende E2EE-protokol blootlê om ondersteunde pakkette buite UI-beperkings saam te stel en presiese tydstempels te log; arbitrêre boodskap-ID’s moet vir elke implementering nagegaan word:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumenteer die stuur en ontvangs van afleweringsbevestigings; [Cobalt](https://github.com/Auties00/Cobalt) (nie-amptelike Java/Kotlin Web- en mobile API) dokumenteer boodskapbewerkings soos reageer, wysig en verwyder. Gebruik hul gedokumenteerde API’s eerder as om aan te neem dat elke interne frame blootgelê word.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) bied CLI-, JSON-RPC- en D-Bus-koppelvlakke, terwyl [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) ’n Java-biblioteek is om met Signal te kommunikeer.<sup>[[5]](#references)[[7]](#references)</sup> Huidige `signal-cli`-sintaksis gebruik `sendReaction RECIPIENT --target-author --target-timestamp`; hou `receive` of `daemon` aan die loop sodat protokolopdaterings steeds verwerk word.<sup>[[6]](#references)</sup> Voorbeeld van ’n self-reaksie-wisseling:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Metings in die Careless Whisper-artikel het bevind dat afleweringskwitansies oor toestelle gesinchroniseer word, sodat slegs een kwitansie per boodskap blootgestel word, selfs in ’n multitoestelopstelling.<sup>[[1]](#references)</sup>
* **Gereed-om-te-gebruik PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) bevat WhatsApp-/Signal-backends, gebruik by verstek silent delete probes en merk `active` teenoor `standby` met ’n rollende-mediaandrempel (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is ’n ligter, WhatsApp-eerste CLI met `--delay`, `--concurrent`, CSV-/Prometheus-uitvoerders en Grafana-vriendelike uitvoer.<sup>[[9]](#references)</sup> Gebruik albei eerder as verkenningshulpmiddels as protokolverwysings; die belangrike insig is hoe min kode nodig is sodra toegang tot die rou kliënt beskikbaar is.

Wanneer pasgemaakte nutsmiddels nie beskikbaar is nie, kan amptelike kliënte of blaaierontwikkelaarnutsmiddels steeds stil aksies uitvoer en die tydsberekening van geënkripteerde verkeer blootlê; rou API’s verwyder UI-vertragings en laat ongeldige bewerkings toe.<sup>[[1]](#references)</sup>

## Griezelige metgesel: stille monsternemingslus

1. Kies enige historiese boodskap wat jy in die klets geskryf het, sodat die slagoffer nooit die "reaksie"-ballonne sien verander nie.
2. Wissel af tussen ’n sigbare emoji en ’n leë reaksielas (geënkodeer as `""` in WhatsApp-protobufs of as `--remove` in signal-cli). Elke versending lewer ’n toestel-ACK op, al is daar geen UI-verandering vir die slagoffer nie.
3. Teken die versendingstyd en die aankomstyd van elke afleweringskwitansie aan. ’n 1 Hz-lus soos die volgende lewer onbepaald RTT-spore per toestel:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Omdat WhatsApp/Signal onbeperkte reaksie-opdaterings aanvaar, hoef die aanvaller nooit nuwe kletsinhoud te plaas of oor wysigingsvensters bekommerd te wees nie.<sup>[[1]](#references)</sup>

## Spookagtige vreemdeling: ondersoek van arbitrêre telefoonnommers

1. Registreer ’n nuwe WhatsApp/Signal-rekening en haal die publieke identiteitsleutels vir die teikennommer op (word outomaties tydens sessie-opstelling gedoen).
2. Stel ’n reaksiepakkie saam wat na ’n ewekansige `message_id` verwys wat geen van die partye ooit gesien het nie; die artikel rapporteer dat beide WhatsApp en Signal sulke reaksies aanvaar en steeds afleweringsbewyse genereer.<sup>[[1]](#references)</sup>
3. Stuur die pakkie selfs al bestaan daar geen gesprekdraad nie. Die slagoffertoestelle dekripteer dit, kan nie die basiese boodskap vind nie en verwerp die toestandsverandering, maar bevestig steeds die inkomende syferteks en stuur toestelbewyse terug aan die aanvaller.
4. Herhaal dit voortdurend om RTT-reekse op te bou sonder ’n vorige gesprek of sigbare kennisgewing.<sup>[[1]](#references)</sup>

As jy eers moet vasstel watter nommers geregistreer is, of toestelvoorraad op groot skaal vooraf wil opbou, koppel dit met [kontakontdekking / registrasie-orakels](../pentesting-web/registration-vulnerabilities.md) eerder as om ewekansige E.164-reekse met die hand te raai.

Gepubliseerde werk oor kontakontdekking het getoon waarom dit operasioneel saak maak: met akkurate telefoonnommer-voorvoegsel-tabelle en beskeie hulpbronne kon navorsers ongeveer `10%` van Amerikaanse selfoonnommers op WhatsApp en `100%` op Signal bevraagteken voordat hulle na doelgerigte ondersoeke oorgegaan het.<sup>[[11]](#references)</sup> In die praktyk hou vooraf filtering vir aktiewe rekeninge jou begroting vir stille probes gefokus op nommers wat pakkies werklik sal dekripteer.

Onlangse WhatsApp-weergawes bied ook `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Beskou dit as ’n deursetbeperker: die tracker-dokumentasie sê WhatsApp blokkeer boodskappe met ’n hoë volume van onbekende rekeninge, maar maak nie die drempel bekend nie; dit voorkom dus nie reaksieprobes heeltemal nie.<sup>[[8]](#references)</sup>

## Hergebruik van wysigings en skrappings as geheime snellers

* **Herhaalde skrappings:** Nadat ’n boodskap een keer vir almal geskrap is, het verdere skrappakkies wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke toestel dekripteer en bevestig hulle steeds.
* **Bewerkings buite die venster:** WhatsApp dwing ~60 h-skrappings- / ~20 min-wysigingsvensters in die UI af; Signal dwing ~48 h af. Saamgestelde protokolboodskappe buite hierdie vensters word stilweg op die slagoffertoestel geïgnoreer, maar bewyse word steeds oorgedra, sodat aanvallers onbepaald lank ná die gesprek geëindig het kan ondersoek instel.
* **Ongeldige payloads:** Die artikel rapporteer dat ongeldige boodskappe steeds bevestig kan word; presiese gedrag vir verkeerd geformateerde liggame of geskrapte ID’s hang van die implementering af, dus toets voordat jy daarop staatmaak.<sup>[[1]](#references)</sup>

## Multi-toestelversterking en fingerprinting

* Op WhatsApp en Signal dekripteer elke geassosieerde toestel (foon, rekenaartoepassing, blaaiermetgesel) die probe onafhanklik en stuur sy eie ack terug. Deur die aantal bewyse per probe te tel, word die presiese aantal toestelle onthul.<sup>[[1]](#references)</sup>
* As ’n toestel vanlyn is, word sy bewys in ’n tou geplaas en met heraansluiting uitgestuur. Gapings lek dus aanlyn-/vanlyn-siklusse en selfs pendelskedules (bv. rekenaarbewyse hou op tydens reis).
* RTT-verspreidings verskil volgens platform en omgewing omdat bedryfstelsel, model, kliënt en netwerktoestande die tydsberekening beïnvloed. Groepeer RTT’s (bv. k-means op mediaan-/afwykingskenmerke) om “Android-handstel”, “iOS-handstel”, “Electron-rekenaar”, ens. te etiketteer.
* Omdat die sender die ontvanger se sleutelvoorraad moet ophaal voordat dit enkripteer, kan die aanvaller ook dophou wanneer nuwe toestelle gepaar word; ’n skielike toename in toestelgetal of nuwe RTT-groep is ’n sterk aanduiding.<sup>[[1]](#references)</sup>

**Fingerprinting vanaf tou-bewyse:** Stuur verskeie probes met verskillende boodskap-ID’s terwyl die teikentoestel vanlyn is. Wanneer dit weer koppel, korreleer die ID’s in die teruggestuurde afleweringsbewyse en kyk of hulle apart of saam in een bewys gegroepeer is, en of gegroepeerde ID’s hul stuurvolgorde behou of omkeer. In die getoetste kliënte het WhatsApp Android/iOS afsonderlike afleweringsbewyse teruggestuur, terwyl Web, Windows en macOS hulle saamgevoeg het; macOS het die saamgevoegde volgorde omgekeer. Signal Desktop het bewyse saamgevoeg, anders as sy mobiele kliënte. Dit kan ’n kliënt identifiseer wat weer koppel, selfs wanneer RTT-verspreidings oorvleuel. Moenie afleweringsbewyse verwar met leesbewyse nie; hul groeperingsreëls verskil.<sup>[[1]](#references)</sup>

Vir ’n afsonderlike WhatsApp-probe wat **prekey-hervullings aan die bedienerkant** lees sonder om boodskappe af te lewer, sien [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md).

## Monsternemingstempo, touvorming en saamgevoegde bewyse

* **WhatsApp se burst-verdraagsaamheid:** Gepubliseerde metings het gerapporteer dat WhatsApp stille reaksie-bursts so vinnig as een probe elke `50 ms` aanvaar het sonder duidelike touvorming aan die bedienerkant. Dit is nuttig vir kort kalibrasiebursts, vinnige toesteltelling of om ’n dreineringsaanval vinnig op te skaal.
* **Signal se langtermyn-touvorming:** Signal het kort bursts verdra, maar het begin om volgehoue verkeer van verskeie probes per sekonde in ’n tou te plaas. Vir langtermynmonitering, hou die tempo naby `1 Hz` (of laer) sodat elke bewys steeds die huidige toesteltoestand weerspieël eerder as die leegmaak van ’n agterstand.
* **Heraansluitingsartefakte:** Wanneer ’n toestel weer aanlyn kom, groepeer sommige kliënte verskeie vertraagde bewyse of stuur hulle vinnig uit. Behandel hierdie bewysbursts as ’n toestandoorgangsmerker eerder as onafhanklike RTT-monsters, anders sal jou groepering / `active` vs `idle`-klassifiseerder te veel by heraansluitingsgeraas aanpas.<sup>[[1]](#references)</sup>

## Gedragsafleiding uit RTT-nasporings

1. Neem monsters teen ≥1 Hz om OS-skeduleringseffekte vas te vang. Met WhatsApp op iOS korreleer RTT’s van <1 s sterk met ’n skerm wat aan / voorgrond is, en >1 s met ’n skerm wat af is / agtergrondbeperking.
2. Bou eenvoudige klassifiseerders (drempeltoetsing of twee-groep-k-means) wat elke RTT as "active" of "idle" etiketteer. Voeg etikette in reekse saam om slaaptye, pendelritte, werksure of tye wanneer die rekenaarmetgesel aktief is, af te lei.
3. Korreleer gelyktydige probes na elke toestel om te sien wanneer gebruikers van selfoon na rekenaar oorskakel, wanneer metgeselle vanlyn gaan, en of die toepassing deur push of ’n volgehoue socket beperk word.
4. Vermy in werklike netwerke ’n enkele hardgekodeerde `1 s`-drempel. Kalibreer elke toestel met ’n kort aanloopvenster en hou ’n rollende basislyn (byvoorbeeld, die device-activity-tracker PoC gebruik `threshold = 0.9 * median RTT`) sodat Wi-Fi-/sellulêre afwykings nie jou klassifiseerder laat faal nie.<sup>[[1]](#references)[[8]](#references)</sup>

## Liggingafleiding uit aflewerings-RTT

Dieselfde tydsberekeningsprimitief kan hergebruik word om af te lei waar die ontvanger is, nie net of hulle aktief is nie. Die `Hope of Delivery`-werk het getoon dat opleiding op RTT-verspreidings vir bekende ontvangerliggings ’n aanvaller later in staat stel om die slagoffer se ligging slegs uit afleweringsbevestigings te klassifiseer:<sup>[[2]](#references)</sup>

* Bou ’n basislyn vir dieselfde teiken terwyl hulle op verskeie bekende plekke is (tuis, by die kantoor, op kampus, land A teenoor land B, ens.).
* Versamel vir elke ligging baie RTT’s van normale boodskappe en haal eenvoudige kenmerke uit, soos mediaan, variansie of persentielgroepe.
* Vergelyk tydens die werklike aanval die nuwe probereeks met die opgeleide groepe. Die artikel rapporteer dat selfs liggings binne dieselfde stad dikwels onderskei kan word, met `>80%` akkuraatheid in ’n drie-ligging-opstelling.
* Dit werk die beste wanneer die aanvaller die senderomgewing beheer en onder soortgelyke netwerktoestande ondersoek instel, omdat die gemete pad die ontvanger se toegangsnetwerk, wakkerwordvertraging en boodskapperinfrastruktuur insluit.<sup>[[2]](#references)</sup>

Anders as die stille reaksie-/wysigings-/skrapaanvalle hierbo, vereis liggingafleiding nie ongeldige boodskap-ID’s of versteekte pakkies wat toestande verander nie. Gewone boodskappe met normale afleweringsbevestigings is genoeg, so die kompromis is minder stealth, maar het wyer toepasbaarheid oor boodskappers heen.

## Stealthy hulpbronuitputting

Omdat elke stille probe gedekripteer en bevestig moet word, veroorsaak die aanhoudende stuur van reaksiewisselings, ongeldige wysigings of delete-for-everyone-pakkies ’n toepassingslaag-DoS:<sup>[[1]](#references)</sup>

* Dwing die radio/modem om elke sekonde uit te stuur/te ontvang → merkbare batteryafname, veral op ledige handstelle.
* Genereer opwaartse/afwaartse verkeer wat mobiele dataplanne verbruik en kan meeding met latensiesensitiewe kenmerke soos video-oproepe.<sup>[[1]](#references)</sup>
* Groot ongeldige payloads voeg verwerkingswerk by, maar die artikel rapporteer dat kriptografie self ’n weglaatbare deel van die batterykoste uitmaak.<sup>[[1]](#references)</sup>
* Op WhatsApp aanvaar ongeldige reaksies veel meer data as wat ’n normale emoji sou aandui: gepubliseerde metings het bedieneraanvaarding van tot ongeveer `1 MB` per reaksie gevind.
* Oorgroot reaksies hou op om betroubare afleweringsbewyse te lewer wanneer die liggaam groter as ongeveer `30 bytes` word, maar hulle word steeds aangestuur en verwerk voordat hulle weggegooi word. Hou reaksieliggame klein wanneer jy ACK’s nodig het; vergroot hulle net wanneer die doel suiwer uitputting of geheime eenrigtingvervoer is.
* Openbare metings het ongeveer `3.7 MB/s` (`~13.3 GB/h`) se slagofferverkeer in hierdie modus bereik.



## References

- [1] [Roekelose gefluister: Uitbuiting van stille afleweringsbewyse om gebruikers op mobiele kitsboodskappers te monitor](https://arxiv.org/html/2411.11194v4)
- [2] [Hoop op aflewering: Onttrekking van gebruikersliggings uit mobiele kitsboodskappers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli-manbladsy](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Hoe om hoë volumes onbekende boodskappe te blokkeer | WhatsApp-hulpsentrum](https://faq.whatsapp.com/3379690015658337)
- [11] [Alle nommers is Amerikaans: Grootskaalse misbruik van kontakontdekking in mobiele boodskappers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
