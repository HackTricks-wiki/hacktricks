# Afleweringsbewys Side-Channel Aanvalle in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Afleweringsbewyse is verpligtend in moderne end-to-end encrypted (E2EE) messengers omdat clients moet weet wanneer ’n ciphertext gedekripteer is sodat hulle ratcheting state en ephemeral keys kan weggooi. Die server stuur opaque blobs aan, so device acknowledgements (double checkmarks) word deur die ontvanger uitgestuur nadat dekripsie suksesvol was. Om die round-trip time (RTT) te meet tussen ’n attacker-gestarte aksie en die ooreenstemmende afleweringsbewys, openbaar ’n hoë-resolusie tydkanaal wat device state, online presence, en kan misbruik word vir covert DoS. Multi-device "client-fanout" deployments versterk die leak omdat elke geregistreerde device die probe dekripteer en sy eie bewys terugstuur.

## Bronne van afleweringsbewyse vs. gebruiker-sigbare seine

Kies boodskaptipes wat altyd ’n afleweringsbewys uitstuur maar geen UI-artefakte op die slagoffer vertoon nie. Die tabel hieronder som die empiries bevestigde gedrag op:

| Messenger | Aksie | Afleweringsbewys | Slagofferkennisgewing | Notas |
|-----------|--------|------------------|-----------------------|-------|
| **WhatsApp** | Teksboodskap | ● | ● | Altyd lawaaierig → slegs nuttig om state te bootstrapping. |
| | Reaksie | ● | ◐ (slegs as op slagoffer se boodskap gereageer word) | Self-reactions en verwyderings bly stil. |
| | Edit | ● | Platform-afhanklike silent push | Edit window ≈20 min; steeds ack’d ná verstryking. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar later packets word steeds ack’d. |
| **Signal** | Teksboodskap | ● | ● | Selfde beperkings as WhatsApp. |
| | Reaksie | ● | ◐ | Self-reactions onsigbaar vir slagoffer. |
| | Edit/Delete | ● | ○ | Server handhaaf ~48 h window, laat tot 10 edits toe, maar laat packets word steeds ack’d. |
| **Threema** | Teksboodskap | ● | ● | Multi-device receipts word geaggregeer, so slegs een RTT per probe word sigbaar. |

Legenda: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-afhanklike UI-gedrag word inline genoem. Skakel read receipts af indien nodig, maar afleweringsbewyse kan nie in WhatsApp of Signal afgeskakel word nie.

## Attacker doelwitte en modelle

* **G1 – Device fingerprinting:** Tel hoeveel bewysstukke per probe aankom, cluster RTTs om OS/client af te lei (Android vs iOS vs desktop), en monitor online/offline-oorgange.
* **G2 – Gedragsmonitering:** Behandel die hoëfrekwensie RTT-reeks (≈1 Hz is stabiel) as ’n time-series en lei screen on/off, app foreground/background, pendel vs werksure, ens. af.
* **G3 – Hulpbron-uitputting:** Hou radios/CPUs van elke slagofferdevice wakker deur eindelose stil probes te stuur, battery/data uit te put en VoIP/RTC-gehalte te verswak.

Twee threat actors is genoeg om die abuse surface te beskryf:

1. **Creepy companion:** deel reeds ’n chat met die slagoffer en misbruik self-reactions, reaction removals, of herhaalde edits/deletes wat aan bestaande message IDs gekoppel is.
2. **Spooky stranger:** registreer ’n burner account en stuur reactions wat message IDs verwys wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en erken dit steeds al verwerp die UI die state change, so geen vorige gesprek is nodig nie.

## Tooling vir raw protocol access

Vertrou op clients wat die onderliggende E2EE-protokol blootstel sodat jy packets buite UI-beperkings kan maak, arbitrêre `message_id`s kan spesifiseer, en presiese timestamps kan log:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) of [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) laat jou raw `ReactionMessage`, `ProtocolMessage` (edit/delete), en `Receipt` frames uitstuur terwyl die double-ratchet state gesinkroniseer bly.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) saam met [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) stel elke boodskaptipe via CLI/API bloot. Voorbeeld self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Bron van die Android client dokumenteer hoe afleweringsbewyse gekonsolideer word voordat hulle die device verlaat, wat verduidelik hoekom die side channel daar minimale bandwidth het.
* **Turnkey PoCs:** publieke projekte soos `device-activity-tracker` en `careless-whisper-python` outomatiseer reeds stil delete/reaction probes en RTT-klassifikasie. Behandel hulle as kant-en-klaar reconnaissance helpers eerder as protocol references; die interessante deel is dat hulle bevestig die aanval is operasioneel eenvoudig sodra raw client access bestaan.

Wanneer pasgemaakte tooling nie beskikbaar is nie, kan jy steeds stil aksies vanaf WhatsApp Web of Signal Desktop trigger en die encrypted websocket/WebRTC-kanaal sniff, maar raw APIs verwyder UI-vertragings en laat ongeldige operasies toe.

## Creepy companion: stil sampling loop

1. Kies enige historiese boodskap wat jy in die chat geskryf het sodat die slagoffer nooit "reaction" balloons sien verander nie.
2. Wissel tussen ’n sigbare emoji en ’n leë reaction payload (gekodeer as `""` in WhatsApp protobufs of `--remove` in signal-cli). Elke transaksie lewer ’n device ack al is daar geen UI delta vir die slagoffer nie.
3. Timestamp die send time en elke delivery receipt-aankoms. ’n 1 Hz loop soos die volgende gee per-device RTT traces onbepaald:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal onbeperkte reaction updates aanvaar, hoef die attacker nooit nuwe chat content te plaas of oor edit windows bekommerd te wees nie.

## Spooky stranger: probing arbitrary phone numbers

1. Registreer ’n vars WhatsApp/Signal-rekening en haal die public identity keys vir die teikennommer op (word outomaties tydens sessionsetup gedoen).
2. Maak ’n reaction/edit/delete packet wat na ’n ewekansige `message_id` verwys wat nooit deur enige party gesien is nie (WhatsApp aanvaar arbitrêre `key.id` GUIDs; Signal gebruik millisekonde timestamps).
3. Stuur die packet al bestaan daar geen thread nie. Die slagofferdevices dekripteer dit, slaag nie daarin om die basisboodskap te match nie, verwerp die state change, maar erken steeds die inkomende ciphertext, en stuur device receipts terug na die attacker.
4. Herhaal voortdurend om RTT-series te bou sonder om ooit in die slagoffer se chat lys te verskyn.

## Herwinning van edits en deletes as covert triggers

* **Herhaalde deletes:** Nadat ’n boodskap een keer delete-for-everyone is, het verdere delete packets wat na dieselfde `message_id` verwys geen UI-effek nie maar elke device dekripteer en erken hulle steeds.
* **Operasies buite window:** WhatsApp handhaaf ~60 h delete / ~20 min edit windows in die UI; Signal handhaaf ~48 h. Crafted protocol messages buite hierdie windows word stilweg op die slagofferdevice geïgnoreer, maar receipts word steeds oorgedra, so attackers kan onbepaald lank ná die gesprek geëindig het, probe.
* **Ongeldige payloads:** Misvormde edit bodies of deletes wat na reeds purged messages verwys, veroorsaak dieselfde gedrag—dekripsie plus receipt, geen gebruiker-sigbare artefakte nie.

## Multi-device versterking & fingerprinting

* Elke geassosieerde device (foon, desktop app, browser companion) dekripteer die probe onafhanklik en stuur sy eie ack terug. Deur receipts per probe te tel, openbaar die presiese device count.
* As ’n device offline is, word sy receipt in die waglys geplaas en uitgestuur sodra dit weer koppel. Gapings lek dus online/offline-siklusse en selfs pendelskedules (bv. desktop receipts stop tydens reis).
* RTT-verdelings verskil per platform weens OS power management en push wakeups. Cluster RTTs (bv. k-means op median/variance features) om “Android handset", “iOS handset", “Electron desktop", ens. te label.
* Omdat die sender die ontvanger se key inventory moet haal voordat dit enkripteer, kan die attacker ook sien wanneer nuwe devices gepaar word; ’n skielike toename in device count of nuwe RTT-cluster is ’n sterk aanduiding.

## Gedragsinferensie uit RTT traces

1. Sample teen ≥1 Hz om OS scheduling effects vas te vang. Met WhatsApp op iOS korreleer <1 s RTTs sterk met screen-on/foreground, >1 s met screen-off/background throttling.
2. Bou eenvoudige classifiers (thresholding of two-cluster k-means) wat elke RTT as "active" of "idle" label. Aggregeer labels in streaks om bedtye, pendel, werksure, of wanneer die desktop companion aktief is, af te lei.
3. Korreleer gelyktydige probes na elke device om te sien wanneer users van mobile na desktop oorskakel, wanneer companions offline gaan, en of die app deur push vs persistent socket rate limited word.

## Ligginginferensie uit delivery RTT

Dieselfde tydprimitive kan herdoel word om af te lei waar die ontvanger is, nie net of hulle aktief is nie. Die `Hope of Delivery` werk het gewys dat training op RTT-verdelings vir bekende ontvangerliggings ’n attacker later toelaat om die slagoffer se ligging uit afleweringsbevestigings alleen te klassifiseer:

* Bou ’n baseline vir dieselfde target terwyl hulle op verskeie bekende plekke is (huis, kantoor, kampus, land A vs land B, ens.).
* Vir elke ligging, versamel baie normale boodskap RTTs en haal eenvoudige features uit soos median, variance, of percentile buckets.
* Tydens die regte aanval, vergelyk die nuwe probe-reeks teen die getrainde clusters. Die paper rapporteer dat selfs liggings binne dieselfde stad dikwels geskei kan word, met `>80%` accuracy in ’n 3-location setting.
* Dit werk die beste wanneer die attacker die sender-omgewing beheer en probes onder soortgelyke netwerktoestande uitstuur, omdat die gemete pad die ontvanger access network, wake-up latency, en messenger-infrastruktuur insluit.

Anders as die stil reaction/edit/delete-aanvalle hierbo, vereis ligginginferensie nie ongeldige message IDs of stealthy state-changing packets nie. Gewone boodskappe met normale delivery confirmations is genoeg, so die afruil is laer stealth maar breër toepasbaarheid oor messengers.

## Stealthy resource exhaustion

Omdat elke stil probe gedekripteer en erken moet word, skep die deurlopende stuur van reaction toggles, ongeldige edits, of delete-for-everyone packets ’n application-layer DoS:

* Dwing die radio/modem om elke sekonde te send/receive → merkbare battery drain, veral op idle handsets.
* Genereer ongemeetde upstream/downstream traffic wat mobile data plans verbruik terwyl dit in TLS/WebSocket-noise insmelt.
* Beset crypto threads en bring jitter in latency-sensitive features (VoIP, video calls) al sien die user geen notifications nie.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
