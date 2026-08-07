# Side-channel-aanvalle op afleweringskwitansies in E2EE-boodskapdienste

{{#include ../banners/hacktricks-training.md}}

Afleweringskwitansies is verpligtend in moderne end-tot-end-geënkripteerde (E2EE) boodskapdienste omdat kliënte moet weet wanneer ’n ciphertext gedekripteer is, sodat hulle ratcheting state en ephemeral keys kan weggooi. Die server stuur ondeursigtige blobs aan, en toestelerkennings (dubbele regmerkies) word deur die ontvanger uitgestuur nadat dekripsie suksesvol was. Deur die round-trip time (RTT) tussen ’n aanvaller-geaktiveerde aksie en die ooreenstemmende afleweringskwitansie te meet, word ’n hoë-resolusie-timingskanaal blootgelê wat toestelstatus en aanlynteenwoordigheid lek, en vir covert DoS misbruik kan word. Multi-device “client-fanout”-ontplooiings versterk die lekkasie omdat elke geregistreerde toestel die probe dekripteer en sy eie kwitansie terugstuur.<sup>[[1]](#references)</sup>

## Bronne van afleweringskwitansies teenoor seine wat vir die gebruiker sigbaar is

Kies boodskapsoorte wat altyd ’n afleweringskwitansie uitstuur, maar geen UI-artefakte op die slagoffer vertoon nie. Die tabel hieronder som die empiries bevestigde gedrag op:<sup>[[1]](#references)</sup>

| Messenger | Aksie | Afleweringskwitansie | Slagofferkennisgewing | Aantekeninge |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Teksboodskap | ● | ● | Altyd sigbaar → slegs nuttig om state te inisialiseer. |
| | Reaksie | ● | ◐ (slegs wanneer op slagoffer se boodskap gereageer word) | Selfreaksies en verwyderings bly stil. |
| | Wysiging | ● | Platformafhanklike stil push | Wysigingsvenster ≈20 min; word steeds ge-ack ná verstryking. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar latere pakkette word steeds ge-ack. |
| **Signal** | Teksboodskap | ● | ● | Dieselfde beperkings as WhatsApp. |
| | Reaksie | ● | ◐ | Selfreaksies is onsigbaar vir die slagoffer. |
| | Wysiging/Verwydering | ● | ○ | Server dwing ’n ~48 h-venster af en laat tot 10 wysigings toe, maar laat pakkette word steeds ge-ack. |
| **Threema** | Teksboodskap | ● | ● | Multi-device-kwitansies word saamgevoeg, dus word slegs een RTT per probe sigbaar. |

Legende: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platformafhanklike UI-gedrag word inline aangedui. Skakel read receipts af indien nodig, maar delivery receipts kan nie in WhatsApp of Signal afgeskakel word nie.<sup>[[1]](#references)</sup>

## Aanvallerdoelwitte en modelle

* **G1 – Toestelfingerprinting:** Tel hoeveel kwitansies per probe aankom, groepeer RTT’s om OS/kliënt (Android teenoor iOS teenoor desktop) af te lei, en monitor aanlyn-/aflynoorgange.
* **G2 – Gedragsmonitering:** Behandel die hoëfrekwensie-RTT-reeks (≈1 Hz is stabiel) as ’n tydreeks en lei skerm aan/af, app voorgrond/agtergrond, pendel- teenoor werkure, ensovoorts af.
* **G3 – Hulpbronuitputting:** Hou die radio’s/SVE’s van elke slagoffertoestel wakker deur aanhoudende stil probes te stuur, wat battery/data dreineer en VoIP/RTC-gehalte verswak.<sup>[[1]](#references)</sup>

Twee threat actors is voldoende om die misbruikoppervlak te beskryf:<sup>[[1]](#references)</sup>

1. **Creepy companion:** deel reeds ’n gesprek met die slagoffer en misbruik selfreaksies, verwyderings van reaksies, of herhaalde wysigings/verwyderings wat aan bestaande boodskap-ID’s gekoppel is.
2. **Spooky stranger:** registreer ’n burner account en stuur reaksies wat verwys na message ID’s wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en erken hulle steeds, selfs al verwerp die UI die state change, sodat geen vorige gesprek nodig is nie.

## Tooling vir raw protocol access

Maak staat op kliënte wat die onderliggende E2EE-protokol blootstel sodat jy pakkette buite UI-beperkings kan saamstel, arbitrêre `message_id`s kan spesifiseer en presiese tydstempels kan log:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web-protokol) of [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) laat jou toe om raw `ReactionMessage`-, `ProtocolMessage`- (edit/delete) en `Receipt`-frames uit te stuur terwyl die double-ratchet-state gesinchroniseer bly.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli), gekombineer met [libsignal-service-java](https://github.com/signalapp/libsignal-service-java), stel elke boodskapsoort via CLI/API bloot.<sup>[[5]](#references)[[7]](#references)</sup> Huidige `signal-cli`-sintaksis gebruik `sendReaction RECIPIENT --target-author --target-timestamp`; hou `receive` of `daemon` aan die loop sodat delivery receipts werklik versamel word.<sup>[[6]](#references)</sup> Voorbeeld van ’n selfreaksie-skakelaar:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Die Android-kliënt se bronkode dokumenteer hoe delivery receipts gekonsolideer word voordat hulle die toestel verlaat, wat verduidelik waarom die side channel daar weglaatbare bandwydte het.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) bevat WhatsApp/Signal-backends, gebruik standaard stil delete-probes, en merk `active` teenoor `standby` met ’n rolling-median-drempel (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is ’n ligter WhatsApp-first CLI met `--delay`, `--concurrent`, CSV/Prometheus-exporters en Grafana-vriendelike uitvoer.<sup>[[9]](#references)</sup> Behandel albei as reconnaissance helpers eerder as protocol references; die belangrike gevolgtrekking is hoe min kode nodig is sodra raw client access beskikbaar is.

Wanneer custom tooling nie beskikbaar is nie, kan jy steeds stil aksies vanaf WhatsApp Web of Signal Desktop aktiveer en die geënkripteerde websocket/WebRTC-kanaal sniff, maar raw APIs verwyder UI-vertragings en laat ongeldige operasies toe.

## Creepy companion: stil sampling-lus

1. Kies enige historiese boodskap wat jy self in die gesprek geskryf het sodat die slagoffer nooit sien dat “reaction”-borrels verander nie.
2. Wissel af tussen ’n sigbare emoji en ’n leë reaksie-payload (geënkodeer as `""` in WhatsApp-protobufs of as `--remove` in signal-cli). Elke transmissie lewer ’n device ack ondanks geen UI-delta vir die slagoffer nie.
3. Teken die send time en elke delivery receipt se aankomstyd aan. ’n 1 Hz-lus soos die volgende lewer onbepaald RTT-spore per toestel:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal onbeperkte reaction updates aanvaar, hoef die aanvaller nooit nuwe gesprekinhoud te plaas of oor edit windows bekommerd te wees nie.<sup>[[1]](#references)</sup>

## Spooky stranger: probing van arbitrêre telefoonnommers

1. Registreer ’n nuwe WhatsApp/Signal-account en haal die publieke identity keys vir die teikennommer op (dit gebeur outomaties tydens session setup).
2. Stel ’n reaction/edit/delete-pakket saam wat verwys na ’n ewekansige `message_id` wat deur geen party gesien is nie (WhatsApp aanvaar arbitrêre `key.id` GUID’s; Signal gebruik millisekonde-tydstempels).
3. Stuur die pakket selfs al bestaan geen thread nie. Die slagoffertoestelle dekripteer dit, vind nie die basismessage nie, verwerp die state change, maar erken steeds die inkomende ciphertext en stuur device receipts terug na die aanvaller.
4. Herhaal voortdurend om RTT-reekse op te bou sonder om ooit in die slagoffer se chat list te verskyn.<sup>[[1]](#references)</sup>

As jy eers moet vasstel watter nommers geregistreer is, of device inventories op skaal vooraf wil saai, kombineer dit met [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) eerder as om ewekansige E.164-reekse met die hand te raai.

Gepubliseerde contact-discovery-navorsing het gewys waarom dit operasioneel belangrik is: met akkurate telefoonnommer-voorvoegtabelle en beperkte hulpbronne kon navorsers ongeveer `10%` van Amerikaanse selfoonnommers op WhatsApp en `100%` op Signal navraag doen voordat hulle na targeted probing oorgegaan het.<sup>[[11]](#references)</sup> In die praktyk hou vooraf-filtrering van aktiewe accounts jou silent-probe-begroting gefokus op nommers wat pakkette werklik sal dekripteer.

Onlangse WhatsApp-builds stel ook `Settings -> Privacy -> Advanced -> Block unknown account messages` bloot.<sup>[[10]](#references)</sup> Behandel dit as ’n throughput limiter, nie as ’n oplossing nie: dit benadeel hoofsaaklik volgehoue stranger-only flooding en is irrelevant wanneer jy reeds ’n bekende kontak is.

## Herwinning van wysigings en verwyderings as covert triggers

* **Herhaalde verwyderings:** Nadat ’n boodskap een keer met Delete for everyone verwyder is, het verdere delete-pakkette wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke toestel dekripteer en erken hulle steeds.
* **Operasies buite die venster:** WhatsApp dwing ~60 h delete- / ~20 min edit-windows in die UI af; Signal dwing ~48 h af. Saamgestelde protocol messages buite hierdie windows word stilweg op die slagoffertoestel geïgnoreer, maar receipts word gestuur, sodat aanvallers onbepaald lank ná die gesprek geëindig het kan probe.
* **Ongeldige payloads:** Misvormde edit-bodies of deletes wat na reeds verwyderde boodskappe verwys, veroorsaak dieselfde gedrag—dekripsie plus receipt, met geen artefakte wat vir die gebruiker sigbaar is nie.<sup>[[1]](#references)</sup>

## Multi-device-versterking en fingerprinting

* Elke geassosieerde toestel (foon, desktop-app, browser-companion) dekripteer die probe onafhanklik en stuur sy eie ack terug. Deur receipts per probe te tel, word die presiese aantal toestelle onthul.
* Indien ’n toestel aflyn is, word sy receipt in ’n queue geplaas en met herverbinding uitgestuur. Gapings lek dus aanlyn-/aflynsiklusse en selfs pendelskedules (byvoorbeeld: desktop-receipts stop tydens reis).
* RTT-verspreidings verskil per platform weens OS-kragbestuur en push-wakeups. Groepeer RTT’s (byvoorbeeld k-means op mediaan-/variansie-eienskappe) om “Android handset”, “iOS handset”, “Electron desktop”, ensovoorts te etiketteer.
* Omdat die sender die ontvanger se key inventory moet ophaal voordat dit kan enkripteer, kan die aanvaller ook monitor wanneer nuwe toestelle gepaar word; ’n skielike toename in die aantal toestelle of ’n nuwe RTT-cluster is ’n sterk aanduiding.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing en stacked receipts

* **WhatsApp burst tolerance:** Gepubliseerde metings het gerapporteer dat WhatsApp stil reaction-bursts so vinnig as een probe elke `50 ms` aanvaar het sonder duidelike server-side queueing. Dit is nuttig vir kort kalibrasie-bursts, vinnige toestel-telling of om ’n drain attack vinnig op te skaal.
* **Signal long-run queueing:** Signal het kort bursts verdra, maar het volgehoue multi-probe-per-sekonde-verkeer begin queue. Vir langtermynmonitering, hou die cadence rondom `1 Hz` (of laer) sodat elke receipt steeds die huidige toestelstatus weerspieël eerder as backlog drain.
* **Reconnect artefacts:** Wanneer ’n toestel weer aanlyn kom, batch sommige kliënte verskeie vertraagde receipts of stuur hulle vinnig uit. Behandel sulke receipt-bursts as ’n state-transition marker eerder as onafhanklike RTT-samples, anders sal jou clustering / `active` teenoor `idle` classifier reconnect-geraas oormatig pas.<sup>[[1]](#references)</sup>

## Afleiding van gedrag uit RTT-spore

1. Sample teen ≥1 Hz om OS-scheduling-effekte vas te lê. Met WhatsApp op iOS korreleer RTT’s van <1 s sterk met skerm-aan/voorgrond, en RTT’s van >1 s met skerm-af/agtergrond-throttling.
2. Bou eenvoudige classifiers (drempelbepaling of two-cluster k-means) wat elke RTT as “active” of “idle” etiketteer. Groepeer etikette in streaks om slaaptye, pendeltye, werkure of wanneer die desktop-companion aktief is, af te lei.
3. Korreleer gelyktydige probes na elke toestel om te sien wanneer gebruikers van mobile na desktop oorskakel, wanneer companions aflyn gaan, en of die app deur push teenoor persistent socket rate limited word.
4. Vermy in werklike netwerke ’n enkele hardgekodeerde `1 s`-drempel. Bootstrap elke toestel met ’n kort warm-up window en hou ’n rolling baseline (byvoorbeeld, `threshold = 0.9 * median RTT`) sodat Wi-Fi-/sellulêre drywing nie jou classifier laat ineenstort nie.<sup>[[1]](#references)</sup>

## Liggingafleiding uit delivery RTT

Dieselfde timing primitive kan hergebruik word om af te lei waar die ontvanger is, nie net of hy/sy aktief is nie. Die `Hope of Delivery`-werk het getoon dat opleiding op RTT-verspreidings vir bekende ontvangerliggings ’n aanvaller later in staat stel om die slagoffer se ligging slegs uit delivery confirmations te klassifiseer:<sup>[[2]](#references)</sup>

* Bou ’n baseline vir dieselfde teiken terwyl hulle op verskeie bekende plekke is (huis, kantoor, kampus, land A teenoor land B, ensovoorts).
* Versamel vir elke ligging baie normale boodskap-RTT’s en onttrek eenvoudige eienskappe soos mediaan, variansie of persentiel-buckets.
* Vergelyk tydens die werklike aanval die nuwe probe-reeks met die opgeleide clusters. Die paper rapporteer dat selfs liggings binne dieselfde stad dikwels van mekaar onderskei kan word, met `>80%` akkuraatheid in ’n 3-ligging-opstelling.
* Dit werk die beste wanneer die aanvaller die sender-omgewing beheer en probes onder soortgelyke netwerktoestande uitvoer, omdat die gemete pad die ontvanger se access network, wake-up latency en messenger-infrastruktuur insluit.<sup>[[2]](#references)</sup>

Anders as die silent reaction/edit/delete-aanvalle hierbo, vereis location inference nie ongeldige message ID’s of stealthy state-changing pakkette nie. Gewone boodskappe met normale delivery confirmations is voldoende, dus is die afweging laer stealth, maar wyer toepasbaarheid oor messengers heen.

## Stealthy resource exhaustion

Omdat elke silent probe gedekripteer en erken moet word, skep die voortdurende stuur van reaction toggles, ongeldige edits of Delete for everyone-pakkette ’n application-layer DoS:<sup>[[1]](#references)</sup>

* Dwing die radio/modem om elke sekonde te stuur/ontvang → merkbare battery-uitputting, veral op idle handsets.
* Genereer ongemeterde opwaartse/afwaartse verkeer wat mobiele dataplanne verbruik terwyl dit in TLS/WebSocket-geraas saamsmelt.
* Beset crypto-threads en stel jitter in latency-sensitive features (VoIP, video calls) bekend, selfs al sien die gebruiker nooit kennisgewings nie.
* Op WhatsApp aanvaar invalid reactions veel meer data as wat ’n normale emoji aandui: gepubliseerde metings het server-side acceptance van tot ongeveer `1 MB` per reaction gevind.
* Oversized reactions hou op om betroubare delivery receipts te produseer wanneer die body groter as ongeveer `30 bytes` word, maar word steeds aangestuur en verwerk voordat dit verwerp word. Hou reaction bodies klein wanneer jy ACK’s nodig het; vergroot hulle slegs wanneer die doel pure drain of covert one-way transport is.
* Publieke metings het ongeveer `3.7 MB/s` (`~13.3 GB/h`) se slagofferverkeer in hierdie modus bereik.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
