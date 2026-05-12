# Afleweringsontvangs Side-Channel Aanvalle in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Afleweringsontvangs is verpligtend in moderne end-to-end encrypted (E2EE) messengers omdat clients moet weet wanneer 'n ciphertext gedekripteer is sodat hulle ratcheting state en ephemeral keys kan weggooi. Die server stuur opaque blobs aan, so toestelbevestigings (dubbele regmerkies) word deur die ontvanger uitgereik ná suksesvolle dekripsie. Deur die round-trip time (RTT) te meet tussen 'n deur die aanvaller geaktiveerde aksie en die ooreenstemmende afleweringsontvangs, word 'n hoë-resolusie tydkanaal blootgelê wat toestelstate, aanlyn teenwoordigheid, en misbruik vir covert DoS lek. Multi-device "client-fanout" ontplooiings versterk die leak omdat elke geregistreerde toestel die probe dekripteer en sy eie ontvangs terugstuur.

## Bronne van afleweringsontvangs vs. sigbare gebruikersseine

Kies boodskaptipes wat altyd 'n afleweringsontvangs uitreik maar geen UI-artefakte op die slagoffer toon nie. Die tabel hieronder som die empiries bevestigde gedrag op:

| Messenger | Aksie | Afleweringsontvangs | Slagofferkennisgewing | Notas |
|-----------|--------|---------------------|------------------------|-------|
| **WhatsApp** | Teksboodskap | ● | ● | Altyd geraasvol → net bruikbaar om state te bootstrap. |
| | Reaksie | ● | ◐ (net as daar op die slagoffer se boodskap gereageer word) | Self-reactions en verwyderings bly stil. |
| | Edit | ● | Platform-afhanklike stil push | Edit-venster ≈20 min; steeds ack’d ná verstryking. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar latere packets word steeds ack’d. |
| **Signal** | Teksboodskap | ● | ● | Selfde beperkings as WhatsApp. |
| | Reaksie | ● | ◐ | Self-reactions onsigbaar vir die slagoffer. |
| | Edit/Delete | ● | ○ | Server dwing ~48 h venster af, laat tot 10 edits toe, maar laat packets word steeds ack’d. |
| **Threema** | Teksboodskap | ● | ● | Multi-device ontvangs word geaggregeer, so slegs een RTT per probe word sigbaar. |

Legenda: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-afhanklike UI-gedrag word inline genoem. Skakel read receipts af indien nodig, maar afleweringsontvangs kan nie in WhatsApp of Signal afgeskakel word nie.

## Aanvallerdoelwitte en modelle

* **G1 – Device fingerprinting:** Tel hoeveel ontvangs per probe aankom, cluster RTTs om OS/client af te lei (Android vs iOS vs desktop), en monitor online/offline-oorgange.
* **G2 – Gedragsmonitering:** Behandel die hoëfrekwensie RTT-reeks (≈1 Hz is stabiel) as 'n tydreeks en lei screen on/off, app foreground/background, pendel vs werkure, ens. af.
* **G3 – Hulpbronuitputting:** Hou radio’s/CPU’s van elke slagoffer-toestel wakker deur nooit-eindigende stil probes te stuur, battery/data uit te put en VoIP/RTC-gehalte te verswak.

Twee dreigingsakteurs is genoeg om die misbruikoppervlak te beskryf:

1. **Creepy companion:** deel reeds 'n chat met die slagoffer en misbruik self-reactions, reaction removals, of herhaalde edits/deletes wat aan bestaande message IDs gekoppel is.
2. **Spooky stranger:** registreer 'n burner account en stuur reactions wat na message IDs verwys wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en erken dit steeds al gooi die UI die state change weg, so geen vorige gesprek is nodig nie.

## Tooling vir rou protocol-toegang

Vertrou op clients wat die onderliggende E2EE protocol blootstel sodat jy packets buite UI-beperkings kan saamstel, arbitrêre `message_id`s kan spesifiseer, en presiese timestamps kan log:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) of [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) laat jou toe om rou `ReactionMessage`, `ProtocolMessage` (edit/delete), en `Receipt` frames uit te stuur terwyl die double-ratchet state gesinchroniseer bly.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) gekombineer met [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) stel elke boodskaptipe via CLI/API bloot. Huidige `signal-cli` sintaks gebruik `sendReaction RECIPIENT --target-author --target-timestamp`; hou `receive` of `daemon` aan die gang sodat afleweringsontvangs werklik ingesamel word. Voorbeeld self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Bronkode van die Android client dokumenteer hoe afleweringsontvangs gekonsolideer word voordat hulle die toestel verlaat, wat verduidelik hoekom die side channel daar byna geen bandwidth het nie.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) bevat WhatsApp/Signal backends, gebruik by verstek stil delete probes, en benoem `active` vs `standby` met 'n rolling-median drempel (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is 'n ligter WhatsApp-eerste CLI met `--delay`, `--concurrent`, CSV/Prometheus exporters, en Grafana-vriendelike uitset. Beskou albei as verkenningshelpers eerder as protocolverwysings; die belangrike punt is hoe min code nodig is sodra rou client-toegang bestaan.

Wanneer pasgemaakte tooling nie beskikbaar is nie, kan jy steeds stil aksies vanaf WhatsApp Web of Signal Desktop aktiveer en die encrypted websocket/WebRTC-kanaal sniff, maar rou APIs verwyder UI-vertragings en laat ongeldige operasies toe.

## Creepy companion: stil steekproeflus

1. Kies enige historiese boodskap wat jy in die chat geskryf het sodat die slagoffer nooit "reaction" ballonne sien verander nie.
2. Wissel af tussen 'n sigbare emoji en 'n leë reaction payload (geënkodeer as `""` in WhatsApp protobufs of `--remove` in signal-cli). Elke transmissie lewer 'n toestel-ack op ondanks geen UI-verskil vir die slagoffer nie.
3. Timestamp die stuurtyd en elke afleweringsontvangs se aankoms. 'n 1 Hz lus soos die volgende gee per-toestel RTT-traces onbepaald:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal onbeperkte reaction-opdaterings aanvaar, hoef die aanvaller nooit nuwe chat-inhoud te plaas of oor edit-vensters te bekommer nie.

## Spooky stranger: ondersoek van arbitrêre telefoonnommers

1. Registreer 'n nuwe WhatsApp/Signal account en haal die publieke identiteit-sleutels vir die teiken nommer op (word outomaties gedoen tydens sessie-opstelling).
2. Stel 'n reaction/edit/delete packet saam wat na 'n ewekansige `message_id` verwys wat nooit deur enige party gesien is nie (WhatsApp aanvaar arbitrêre `key.id` GUIDs; Signal gebruik millisekonde-timestamps).
3. Stuur die packet selfs al bestaan daar geen thread nie. Die slagoffer-toestelle dekripteer dit, faal om die basisboodskap te pas, gooi die state change weg, maar erken steeds die inkomende ciphertext, en stuur toestelontvangs terug na die aanvaller.
4. Herhaal dit voortdurend om RTT-reekse te bou sonder om ooit in die slagoffer se chatlys te verskyn.

As jy eers moet uitvind watter nommers geregistreer is of toestel-inventarisse op skaal vooraf wil saai, koppel dit met [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) eerder as om ewekansige E.164-reekse met die hand te raai.

Onlangse WhatsApp-builds stel ook `Settings -> Privacy -> Advanced -> Block unknown account messages` bloot. Behandel dit as 'n throughput limiter, nie 'n regstelling nie: dit benadeel hoofsaaklik volgehoue stranger-only flooding en is irrelevant sodra jy reeds 'n bekende kontak is.

## Herwinning van edits en deletes as covert triggers

* **Herhaalde deletes:** Nadat 'n boodskap een keer deleted-for-everyone is, het verdere delete packets wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke toestel dekripteer en erken dit steeds.
* **Buite-venster operasies:** WhatsApp dwing ~60 h delete / ~20 min edit vensters in die UI af; Signal dwing ~48 h af. Saamgestelde protocol messages buite hierdie vensters word stilweg op die slagoffer-toestel geïgnoreer, maar ontvangs word steeds gestuur, so aanvallers kan vir onbeperk lang ná die gesprek geëindig het, ondersoek doen.
* **Ongeldige payloads:** Misvormde edit bodies of deletes wat na reeds gesuiwerde boodskappe verwys, ontlok dieselfde gedrag—dekripsie plus ontvangs, nul gebruikerssigbare artefakte.

## Multi-device versterking & fingerprinting

* Elke geassosieerde toestel (foon, desktop app, browser companion) dekripteer die probe onafhanklik en stuur sy eie ack terug. Deur ontvangs per probe te tel, word die presiese toestelgetal blootgelê.
* As 'n toestel offline is, word sy ontvangs in die tou geplaas en by herverbindings uitgestuur. Gapings lek dus online/offline-siklusse en selfs pendelskedules (bv. desktop ontvangs stop tydens reis).
* RTT-verdelings verskil per platform weens OS power management en push wakeups. Cluster RTTs (bv. k-means op median/variance features) om “Android handset", “iOS handset", “Electron desktop", ens. te benoem.
* Omdat die sender die ontvanger se key inventory moet ophaal voordat dit enkripteer, kan die aanvaller ook dophou wanneer nuwe toestelle gepaar word; 'n skielike toename in toestelgetal of nuwe RTT-cluster is 'n sterk aanduiding.

## Gedragsafleiding uit RTT-traces

1. Steekproef teen ≥1 Hz om OS-skeduleringseffekte vas te vang. Met WhatsApp op iOS korreleer <1 s RTTs sterk met screen-on/foreground, >1 s met screen-off/background throttling.
2. Bou eenvoudige classifiers (thresholding of twee-cluster k-means) wat elke RTT as "active" of "idle" benoem. Aggregate labels in streaks om slaaptye, pendelroetes, werkure, of wanneer die desktop companion aktief is, af te lei.
3. Korreleer gelyktydige probes na elke toestel om te sien wanneer gebruikers van mobile na desktop skakel, wanneer companions offline gaan, en of die app deur push vs persistent socket rate limited word.
4. Vermy in werklike netwerke 'n enkele hardcoded `1 s` threshold. Bootstrap elke toestel met 'n kort warm-up venster en hou 'n rolling baseline (byvoorbeeld, `threshold = 0.9 * median RTT`) sodat Wi-Fi/cellular drift nie jou classifier laat ineenstort nie.

## Liggingafleiding uit aflewerings RTT

Dieselfde tyds-primitive kan herdoel word om af te lei waar die ontvanger is, nie net of hulle aktief is nie. Die `Hope of Delivery` werk het gewys dat opleiding op RTT-verdelings vir bekende ontvangerliggings 'n aanvaller later toelaat om die slagoffer se ligging uit afleweringsbevestigings alleen te klassifiseer:

* Bou 'n baseline vir dieselfde teiken terwyl hulle op verskeie bekende plekke is (huis, kantoor, kampus, land A vs land B, ens.).
* Vir elke ligging, versamel baie normale boodskap RTTs en ekstraheer eenvoudige features soos median, variance, of percentile buckets.
* Tydens die werklike aanval, vergelyk die nuwe probe-reeks teen die getrainde clusters. Die paper rapporteer dat selfs liggings binne dieselfde stad dikwels geskei kan word, met `>80%` akkuraatheid in 'n 3-ligging opstelling.
* Dit werk die beste wanneer die aanvaller die sender-omgewing beheer en onder soortgelyke netwerktoestande probe, omdat die gemete pad die ontvanger se access network, wake-up latency, en messenger-infrastruktuur insluit.

Anders as die stil reaction/edit/delete-aanvalle hierbo, vereis liggingafleiding nie ongeldige message IDs of stealthy state-changing packets nie. Gewone boodskappe met normale afleweringsbevestigings is genoeg, so die afruil is laer stealth maar breër toepasbaarheid oor messengers.

## Stealthy hulpbronuitputting

Omdat elke stil probe gedekripteer en erken moet word, skep die voortdurende stuur van reaction toggles, ongeldige edits, of delete-for-everyone packets 'n application-layer DoS:

* Dwing die radio/modem om elke sekonde te stuur/ontvang → merkbare batteryverbruik, veral op idle handsets.
* Genereer ongemeterde upstream/downstream traffic wat mobile data plans verbruik terwyl dit in TLS/WebSocket-geraas opgaan.
* Beset crypto threads en voer jitter in latency-sensitiewe features in (VoIP, video calls) al sien die gebruiker nooit kennisgewings nie.
* Op WhatsApp aanvaar ongeldige reactions baie meer data as wat 'n normale emoji aandui: gepubliseerde metings het server-side aanvaarding tot ongeveer `1 MB` per reaction gevind.
* Oorgroot reactions hou op om betroubare afleweringsontvangs te produseer sodra die body ongeveer `30 bytes` oorskry, maar hulle word steeds aangestuur en verwerk voor verwerping. Hou reaction bodies klein wanneer jy ACKs nodig het; blaas hulle net op wanneer die doel pure drain of covert eenrigtingvervoer is.
* Publieke metings het ongeveer `3.7 MB/s` (`~13.3 GB/h`) van slagofferverkeer in hierdie modus bereik.

## Verwysings

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
