# Afleweringskwitansie Side-Channel Aanvalle in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Afleweringskwitansies is verpligtend in moderne end-to-end encrypted (E2EE) messengers omdat clients moet weet wanneer 'n ciphertext gedekripteer is sodat hulle ratcheting state en ephemeral keys kan weggooi. Die server stuur opaque blobs aan, so device acknowledgements (dubbele regmerkies) word deur die ontvanger uitgereik ná suksesvolle dekripsie. Die meet van die round-trip time (RTT) tussen 'n attacker-gestarte aksie en die ooreenstemmende afleweringskwitansie ontbloot 'n hoë-resolusie tydkanaal wat device state, online presence, en kan misbruik word vir covert DoS. Multi-device "client-fanout" deployments versterk die leak omdat elke geregistreerde device die probe dekripteer en sy eie kwitansie terugstuur.

## Afleweringskwitansie-bronne vs. user-visible seine

Kies boodskaptipes wat altyd 'n afleweringskwitansie uitstuur, maar nie UI-artifakte op die slagoffer vertoon nie. Die tabel hieronder som die empiries bevestigde gedrag op:

| Messenger | Aksie | Afleweringskwitansie | Slagofferkennisgewing | Notas |
|-----------|--------|----------------------|------------------------|-------|
| **WhatsApp** | Teksboodskap | ● | ● | Altijd raserig → slegs nuttig om state te bootstrap. |
| | Reaksie | ● | ◐ (slegs as dit op slagoffer se boodskap reageer) | Self-reactions en verwyderings bly stil. |
| | Edit | ● | Platform-afhanklike stil push | Edit window ≈20 min; steeds ack’d ná verstryking. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar latere packets word steeds ack’d. |
| **Signal** | Teksboodskap | ● | ● | Dieselfde beperkings as WhatsApp. |
| | Reaksie | ● | ◐ | Self-reactions onsigbaar vir slagoffer. |
| | Edit/Delete | ● | ○ | Server handhaaf ~48 h window, laat tot 10 edits toe, maar laat packets word steeds ack’d. |
| **Threema** | Teksboodskap | ● | ● | Multi-device kwitansies word geaggregeer, so slegs een RTT per probe word sigbaar. |

Legenda: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-afhanklike UI-gedrag word inline genoem. Skakel read receipts af indien nodig, maar afleweringskwitansies kan nie in WhatsApp of Signal afgeskakel word nie.

## Attacker-doelwitte en modelle

* **G1 – Device fingerprinting:** Tel hoeveel kwitansies per probe aankom, cluster RTTs om OS/client af te lei (Android vs iOS vs desktop), en hou online/offline-oorgange dop.
* **G2 – Gedragsmonitering:** Behandel die hoëfrekwensie RTT-reeks (≈1 Hz is stabiel) as 'n time-series en lei screen on/off, app foreground/background, pendel vs werkure, ens. af.
* **G3 – Hulpbronuitputting:** Hou radios/CPUs van elke slagoffer-device wakker deur eindelose stil probes te stuur, battery/data te dreineer en VoIP/RTC-gehalte te verlaag.

Twee threat actors is genoeg om die misbruikoppervlak te beskryf:

1. **Creepy companion:** deel reeds 'n chat met die slagoffer en misbruik self-reactions, reaction removals, of herhaalde edits/deletes gekoppel aan bestaande message IDs.
2. **Spooky stranger:** registreer 'n burner account en stuur reactions wat message IDs verwys wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en erken dit steeds al verwerp die UI die state change, so geen vorige gesprek is nodig nie.

## Tooling vir raw protocol access

Vertrou op clients wat die onderliggende E2EE protocol blootstel sodat jy packets buite UI-beperkings kan bou, arbitrêre `message_id`s kan spesifiseer, en presiese timestamps kan log:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) of [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) laat jou raw `ReactionMessage`, `ProtocolMessage` (edit/delete), en `Receipt` frames uitstuur terwyl die double-ratchet state gesinkroniseer bly.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) saam met [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) stel elke boodskaptipe via CLI/API bloot. Huidige `signal-cli` sintaks gebruik `sendReaction RECIPIENT --target-author --target-timestamp`; hou `receive` of `daemon` aan die loop sodat afleweringskwitansies werklik ingesamel word. Voorbeeld van self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Bron van die Android client dokumenteer hoe afleweringskwitansies gekonsolideer word voordat hulle die device verlaat, wat verduidelik waarom die side channel daar byna geen bandwydte het nie.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) lewer WhatsApp/Signal backends, gebruik standaard stil delete probes, en merk `active` vs `standby` met 'n rolling-median threshold (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is 'n ligter WhatsApp-eerste CLI met `--delay`, `--concurrent`, CSV/Prometheus exporters, en Grafana-vriendelike uitset. Behandel albei as reconnaissance helpers eerder as protocol references; die belangrike punt is hoe min code nodig is sodra raw client access bestaan.

Wanneer custom tooling nie beskikbaar is nie, kan jy steeds stil aksies vanaf WhatsApp Web of Signal Desktop uitlok en die encrypted websocket/WebRTC-kanaal snif, maar raw APIs verwyder UI-vertragings en laat ongeldige operasies toe.

## Creepy companion: stil sampling loop

1. Kies enige historiese boodskap wat jy in die chat geskryf het sodat die slagoffer nooit "reaction" ballonne sien verander nie.
2. Wissel tussen 'n sigbare emoji en 'n leë reaction payload (geënkodeer as `""` in WhatsApp protobufs of `--remove` in signal-cli). Elke transmissie lewer 'n device ack ten spyte van geen UI-delta vir die slagoffer nie.
3. Tydstempel die stuurtyd en elke afleweringskwitansie-aankoms. 'n 1 Hz loop soos die volgende gee per-device RTT traces vir onbepaalde tyd:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal onbeperkte reaction updates aanvaar, hoef die attacker nooit nuwe chat content te plaas of oor edit windows bekommerd te wees nie.

## Spooky stranger: toets arbitrêre foonnommers

1. Registreer 'n vars WhatsApp/Signal account en haal die public identity keys vir die teikennommer op (word outomaties gedoen tydens session setup).
2. Bou 'n reaction/edit/delete packet wat na 'n ewekansige `message_id` verwys wat deur geen party ooit gesien is nie (WhatsApp aanvaar arbitrêre `key.id` GUIDs; Signal gebruik millisekonde timestamps).
3. Stuur die packet al bestaan geen thread nie. Die slagoffer-devices dekripteer dit, slaag nie daarin om die base message te pas nie, verwerp die state change, maar erken steeds die inkomende ciphertext, en stuur device receipts terug aan die attacker.
4. Herhaal voortdurend om RTT series te bou sonder om ooit in die slagoffer se chat lys te verskyn.

As jy eers moet uitvind watter nommers geregistreer is of device inventories op skaal wil vooraf vul, koppel dit met [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) eerder as om ewekansige E.164 ranges met die hand te raai.

Gepubliseerde contact-discovery werk het gewys waarom dit operasioneel saak maak: met akkurate phone-prefix tables en beskeie hulpbronne kon navorsers ongeveer `10%` van US mobile nommers op WhatsApp en `100%` op Signal navraag doen voordat hulle na geteikende probing beweeg het. In die praktyk hou voorfiltering van live accounts eers jou silent-probe begroting gefokus op nommers wat werklik packets sal dekripteer.

Onlangse WhatsApp builds stel ook `Settings -> Privacy -> Advanced -> Block unknown account messages` bloot. Behandel dit as 'n throughput limiter, nie 'n fix nie: dit benadeel hoofsaaklik volgehoue stranger-only flooding en is irrelevant sodra jy reeds 'n bekende kontak is.

## Herwinning van edits en deletes as covert triggers

* **Herhaalde deletes:** Nadat 'n boodskap een keer deleted-for-everyone is, het verdere delete packets wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke device dekripteer en erken dit steeds.
* **Buite-window operasies:** WhatsApp handhaaf ~60 h delete / ~20 min edit windows in die UI; Signal handhaaf ~48 h. Gemaakte protocol messages buite hierdie vensters word stilweg op die slagoffer-device geïgnoreer, maar kwitansies word steeds oorgedra, so attackers kan onbepaald lank toets lank ná die gesprek geëindig het.
* **Ongeldige payloads:** Misvormde edit bodies of deletes wat reeds gesuiwerde messages verwys, lok dieselfde gedrag uit—dekripsie plus kwitansie, nul user-visible artefakte.

## Multi-device versterking & fingerprinting

* Elke geassosieerde device (foon, desktop app, browser companion) dekripteer die probe onafhanklik en stuur sy eie ack terug. Die tel van kwitansies per probe onthul die presiese device-aantal.
* As 'n device offline is, word sy kwitansie in 'n ry geplaas en by herverbinding uitgestuur. Gapings leak dus online/offline-siklusse en selfs pendelskedules (bv. desktop receipts stop tydens reis).
* RTT-verdelings verskil per platform weens OS power management en push wakeups. Cluster RTTs (bv. k-means op median/variance kenmerke) om “Android handset", “iOS handset", “Electron desktop", ens. te merk.
* Omdat die sender die ontvanger se key inventory moet haal voor enkripsie, kan die attacker ook sien wanneer nuwe devices gepaar word; 'n skielike toename in device-aantal of nuwe RTT cluster is 'n sterk aanduiding.

## Sampling cadence, queueing, en gestapelde kwitansies

* **WhatsApp burst tolerance:** Gepubliseerde metings het gerapporteer dat WhatsApp stil-reaction bursts so vinnig as een probe elke `50 ms` aanvaar het sonder duidelike server-side queueing. Dit is nuttig vir kort kalibrasie-bursts, vinnige device counting, of om vinnig 'n drain attack op te jaag.
* **Signal long-run queueing:** Signal het kort bursts verdra, maar het begin om volgehoue multi-probe-per-second verkeer te queue. Vir langtermyn monitering, hou die cadence rondom `1 Hz` (of laer) sodat elke kwitansie steeds die huidige device state weerspieël eerder as backlog-dreinering.
* **Reconnect artefacts:** Wanneer 'n device weer online kom, batch sommige clients of flush vinnig veelvuldige vertraagde kwitansies. Behandel daardie kwitansie-bursts as 'n state-transition merker eerder as as onafhanklike RTT-samples, of jou clustering / `active` vs `idle` classifier sal reconnect noise oorpas.

## Gedragsafleiding uit RTT traces

1. Sample teen ≥1 Hz om OS scheduling-effekte vas te vang. Met WhatsApp op iOS korreleer <1 s RTTs sterk met screen-on/foreground, >1 s met screen-off/background throttling.
2. Bou eenvoudige classifiers (thresholding of twee-cluster k-means) wat elke RTT as "active" of "idle" merk. Aggregeer labels in streaks om bedtye, pendelritte, werkure, of wanneer die desktop companion aktief is, af te lei.
3. Korreleer gelyktydige probes na elke device om te sien wanneer gebruikers van mobile na desktop skuif, wanneer companions offline gaan, en of die app deur push vs persistent socket rate limited word.
4. In regte netwerke, vermy 'n enkele hardcoded `1 s` threshold. Bootstrap elke device met 'n kort warm-up venster en hou 'n rolling baseline (byvoorbeeld, `threshold = 0.9 * median RTT`) sodat Wi-Fi/cellular drift nie jou classifier laat ineenstort nie.

## Liggingafleiding uit aflewerings RTT

Dieselfde tyds-primitive kan hergebruik word om af te lei waar die ontvanger is, nie net of hulle aktief is nie. Die `Hope of Delivery`-werk het gewys dat opleiding op RTT-verdelings vir bekende ontvangerliggings 'n attacker later in staat stel om die slagoffer se ligging uit afleweringsbevestigings alleen te klassifiseer:

* Bou 'n baseline vir dieselfde teiken terwyl hulle op verskeie bekende plekke is (huis, kantoor, kampus, land A vs land B, ens.).
* Vir elke ligging, versamel baie normale boodskap RTTs en ekstraheer eenvoudige kenmerke soos median, variance, of percentile buckets.
* Tydens die werklike aanval, vergelyk die nuwe probe-reeks teen die getrainde clusters. Die paper rapporteer dat selfs liggings binne dieselfde stad dikwels geskei kan word, met `>80%` akkuraatheid in 'n 3-ligging opstelling.
* Dit werk die beste wanneer die attacker die sender-omgewing beheer en onder soortgelyke netwerktoestande toets, omdat die gemete pad die ontvanger se access network, wake-up latency, en messenger-infrastruktuur insluit.

Anders as die stil reaction/edit/delete-aanvalle hierbo, vereis liggingafleiding nie ongeldige message IDs of stealthy state-changing packets nie. Gewone boodskappe met normale afleweringsbevestigings is genoeg, so die afruil is laer stealth maar wyer toepaslikheid oor messengers.

## Stealthy hulpbronuitputting

Omdat elke stil probe gedekripteer en erken moet word, skep die deurlopende stuur van reaction toggles, ongeldige edits, of delete-for-everyone packets 'n application-layer DoS:

* Dwing die radio/modem om elke sekonde te stuur/ontvang → merkbare battery-afname, veral op idle handsets.
* Genereer ongemeetde upstream/downstream verkeer wat mobile data plans verbruik terwyl dit in TLS/WebSocket noise insmelt.
* Beset crypto threads en introduceer jitter in latency-sensitiewe funksies (VoIP, video calls) al sien die gebruiker nooit kennisgewings nie.
* Op WhatsApp aanvaar ongeldige reactions veel meer data as wat 'n normale emoji suggereer: gepubliseerde metings het server-side aanvaarding tot ongeveer `1 MB` per reaction gevind.
* Oorgroot reactions hou op om betroubare afleweringskwitansies te produseer sodra die body groter as ongeveer `30 bytes` word, maar hulle word steeds vorentoe gestuur en verwerk voor verwerping. Hou reaction bodies klein wanneer jy ACKs nodig het; vergroot hulle slegs wanneer die doel suiwer drain of covert eenrigting vervoer is.
* Publieke metings het ongeveer `3.7 MB/s` (`~13.3 GB/h`) van slagoffer-verkeer in hierdie modus bereik.

## Verwysings

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
