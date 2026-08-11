# Side-channel-aanvalle op afleweringskwitansies in E2EE-boodskapdienste

{{#include ../banners/hacktricks-training.md}}

Afleweringskwitansies is verpligtend in moderne end-to-end encrypted (E2EE)-boodskapdienste omdat clients moet weet wanneer ’n ciphertext gedekripteer is sodat hulle ratcheting state en ephemeral keys kan weggooi. Die server stuur opaque blobs aan, dus word device acknowledgements (dubbele regmerkies) deur die recipient uitgestuur nadat dekripsie suksesvol was. Deur die round-trip time (RTT) tussen ’n attacker-triggered action en die ooreenstemmende delivery receipt te meet, word ’n hoë-resolusie timing channel blootgelê wat device state en online presence lek, en wat vir covert DoS misbruik kan word. Multi-device “client-fanout”-deployments versterk die leakage omdat elke registered device die probe dekripteer en sy eie receipt terugstuur.<sup>[[1]](#references)</sup>

## Bronne van afleweringskwitansies teenoor gebruikerssigbare seine

Kies message types wat altyd ’n delivery receipt uitstuur, maar geen UI artifacts by die victim vertoon nie. Die tabel hieronder som die empiries bevestigde gedrag op:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Altyd noisy → slegs nuttig om state te bootstrap. |
| | Reaction | ● | ◐ (slegs wanneer op victim message gereageer word) | Self-reactions en removals bly stil. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; word steeds ge-ack ná expiry. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar latere packets word steeds ge-ack. |
| **Signal** | Text message | ● | ● | Dieselfde beperkings as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions is onsigbaar vir die victim. |
| | Edit/Delete | ● | ○ | Server dwing ’n ~48 h window af, laat tot 10 edits toe, maar laat packets word steeds ge-ack. |
| **Threema** | Text message | ● | ● | Multi-device receipts word geaggregeer, dus word slegs een RTT per probe sigbaar. |

Legende: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-dependent UI-gedrag word inline aangedui. Skakel read receipts af indien nodig, maar delivery receipts kan nie in WhatsApp of Signal afgeskakel word nie.<sup>[[1]](#references)</sup>

## Aanvallerdoelwitte en modelle

* **G1 – Device fingerprinting:** Tel hoeveel receipts per probe aankom, cluster RTTs om OS/client (Android teenoor iOS teenoor desktop) af te lei, en monitor online/offline transitions.
* **G2 – Behavioural monitoring:** Behandel die hoëfrekwensie-RTT-series (≈1 Hz is stabiel) as ’n time-series en lei screen on/off, app foreground/background, commuting teenoor working hours, ens. af.
* **G3 – Resource exhaustion:** Hou die radios/CPUs van elke victim device wakker deur oneindige silent probes te stuur, wat battery/data uitput en video-call quality verswak.<sup>[[1]](#references)</sup>

Twee threat actors is voldoende om die abuse surface te beskryf:<sup>[[1]](#references)</sup>

1. **Creepy companion:** deel reeds ’n chat met die victim en misbruik self-reactions, reaction removals, of herhaalde edits/deletes wat aan bestaande message IDs gekoppel is.
2. **Spooky stranger:** registreer ’n burner account en stuur reactions wat verwys na message IDs wat nooit in die plaaslike conversation bestaan het nie; WhatsApp en Signal dekripteer en acknowledgeer dit steeds, al verwerp die UI die state change, dus is geen vorige conversation nodig nie.

## Tooling vir raw protocol access

Maak staat op clients wat genoeg van die onderliggende E2EE-protocol blootstel om supported packets buite UI constraints te skep en presiese timestamps te log; arbitrary message IDs vereis dat elke implementation nagegaan word:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumenteer die stuur en ontvangs van delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web and mobile API) dokumenteer message operations soos reacting, editing en deleting. Gebruik hul gedokumenteerde APIs eerder as om aan te neem dat elke internal frame blootgestel word.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) stel CLI-, JSON-RPC- en D-Bus-interfaces bloot, terwyl [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) ’n Java-library is om met Signal te kommunikeer.<sup>[[5]](#references)[[7]](#references)</sup> Huidige `signal-cli`-syntax gebruik `sendReaction RECIPIENT --target-author --target-timestamp`; hou `receive` of `daemon` aan die gang sodat protocol updates steeds verwerk word.<sup>[[6]](#references)</sup> Voorbeeld van ’n self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Measurements in die Careless Whisper-paper het bevind dat delivery receipts oor devices gesinchroniseer word, dus word slegs een receipt per message blootgestel, selfs in ’n multi-device setup.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) bevat WhatsApp/Signal-backends, gebruik standaard silent delete probes, en benoem `active` teenoor `standby` met ’n rolling-median threshold (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is ’n ligter WhatsApp-first CLI met `--delay`, `--concurrent`, CSV/Prometheus-exporters en Grafana-friendly output.<sup>[[9]](#references)</sup> Behandel albei as reconnaissance helpers eerder as protocol references; die belangrike punt is hoe min code nodig is sodra raw client access bestaan.

Wanneer custom tooling nie beskikbaar is nie, kan official clients of browser developer tools steeds silent actions trigger en encrypted traffic timing blootstel; raw APIs verwyder UI-delays en laat invalid operations toe.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Kies enige historical message wat jy in die chat ge-authored het sodat die victim nooit “reaction”-ballonne sien verander nie.
2. Wissel af tussen ’n sigbare emoji en ’n leë reaction payload (geënkodeer as `""` in WhatsApp protobufs of `--remove` in signal-cli). Elke transmission lewer ’n device ack ondanks geen UI-delta vir die victim nie.
3. Timestamp die send time en elke delivery receipt arrival. ’n 1 Hz-loop soos die volgende lewer per-device RTT-traces onbepaald:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal unlimited reaction updates aanvaar, hoef die attacker nooit nuwe chat content te post of oor edit windows bekommerd te wees nie.<sup>[[1]](#references)</sup>

## Spooky stranger: probing van arbitrary phone numbers

1. Registreer ’n vars WhatsApp/Signal-account en haal die public identity keys vir die teiken-nommer op (dit gebeur outomaties tydens session setup).
2. Skep ’n reaction packet wat verwys na ’n random `message_id` wat deur geen van die partye gesien is nie; die paper rapporteer dat beide WhatsApp en Signal sulke reactions aanvaar en steeds delivery receipts genereer.<sup>[[1]](#references)</sup>
3. Stuur die packet al bestaan geen thread nie. Die victim devices dekripteer dit, vind geen ooreenstemmende base message nie, verwerp die state change, maar acknowledgeer steeds die incoming ciphertext en stuur device receipts terug na die attacker.
4. Herhaal voortdurend om RTT-series te bou sonder ’n vorige conversation of sigbare notification.<sup>[[1]](#references)</sup>

As jy eers moet ontdek watter nommers geregistreer is, of device inventories op skaal vooraf wil seed, chain dit met [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) eerder as om random E.164-ranges met die hand te raai.

Gepubliseerde contact-discovery-navorsing het gewys waarom dit operasioneel belangrik is: met akkurate phone-prefix tables en beskeie resources kon navorsers ongeveer `10%` van US-mobile numbers op WhatsApp en `100%` op Signal query voordat hulle na targeted probing oorgegaan het.<sup>[[11]](#references)</sup> In praktyk hou pre-filtering van live accounts eers jou silent-probe budget gefokus op nommers wat packets werklik sal dekripteer.

Onlangse WhatsApp-builds stel ook `Settings -> Privacy -> Advanced -> Block unknown account messages` bloot.<sup>[[10]](#references)</sup> Behandel dit as ’n throughput limiter: die tracker documentation sê WhatsApp blokkeer high-volume messages van unknown accounts, maar disclose nie die threshold nie, dus voorkom dit probe reactions nie volledig nie.<sup>[[8]](#references)</sup>

## Herwinning van edits en deletes as covert triggers

* **Repeated deletes:** Nadat ’n message een keer deleted-for-everyone is, het verdere delete packets wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke device dekripteer en acknowledgeer dit steeds.
* **Out-of-window operations:** WhatsApp dwing ~60 h delete / ~20 min edit windows in die UI af; Signal dwing ~48 h af. Crafted protocol messages buite hierdie windows word stilweg op die victim device geïgnoreer, maar receipts word gestuur, sodat attackers onbepaald lank ná die conversation geëindig het kan probe.
* **Invalid payloads:** Die paper rapporteer dat invalid messages steeds ge-ack kan word; presiese gedrag vir malformed bodies of purged IDs is implementation-dependent, dus moet jy toets voordat jy daarop staatmaak.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Op WhatsApp en Signal dekripteer elke associated device (phone, desktop app, browser companion) die probe onafhanklik en stuur sy eie ack terug. Deur receipts per probe te tel, word die presiese device count onthul.<sup>[[1]](#references)</sup>
* As ’n device offline is, word sy receipt gequeue en by reconnection uitgestuur. Gaps lek dus online/offline cycles en selfs commuting schedules (bv. desktop receipts stop tydens travel).
* RTT-distributions verskil volgens platform en environment omdat OS, model, client en network conditions timing beïnvloed. Cluster RTTs (bv. k-means op median/variance features) om “Android handset”, “iOS handset”, “Electron desktop”, ens. te label.
* Omdat die sender die recipient se key inventory moet retrieve voordat dit kan encrypt, kan die attacker ook monitor wanneer nuwe devices paired word; ’n skielike toename in device count of nuwe RTT-cluster is ’n sterk indicator.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing en stacked receipts

* **WhatsApp burst tolerance:** Gepubliseerde measurements het gerapporteer dat WhatsApp silent-reaction bursts so vinnig as een probe elke `50 ms` aanvaar het sonder ooglopende server-side queueing. Dit is nuttig vir kort calibration bursts, vinnige device counting, of om ’n drain attack vinnig op te skaal.
* **Signal long-run queueing:** Signal het kort bursts verdra, maar het sustained multi-probe-per-second traffic begin queue. Vir langtermyn-monitoring, hou die cadence rondom `1 Hz` (of laer) sodat elke receipt steeds die huidige device state weerspieël eerder as backlog drain.
* **Reconnect artefacts:** Wanneer ’n device weer online kom, batch of flush sommige clients verskeie delayed receipts vinnig. Behandel hierdie receipt bursts as ’n state-transition marker eerder as onafhanklike RTT-samples, anders sal jou clustering / `active` teenoor `idle` classifier reconnect noise overfit.<sup>[[1]](#references)</sup>

## Behaviour inference uit RTT-traces

1. Sample teen ≥1 Hz om OS-scheduling effects vas te lê. Met WhatsApp op iOS korreleer RTTs van <1 s sterk met screen-on/foreground, en >1 s met screen-off/background throttling.
2. Bou eenvoudige classifiers (thresholding of two-cluster k-means) wat elke RTT as “active” of “idle” label. Aggregate labels in streaks om bedtimes, commutes, work hours, of wanneer die desktop companion active is, af te lei.
3. Korrelleer simultaneous probes na elke device om te sien wanneer users van mobile na desktop switch, wanneer companions offline gaan, en of die app deur push teenoor persistent socket rate limited word.
4. Vermy in real networks ’n enkele hardcoded `1 s` threshold. Bootstrap elke device met ’n kort warm-up window en hou ’n rolling baseline (byvoorbeeld, die device-activity-tracker PoC gebruik `threshold = 0.9 * median RTT`) sodat Wi-Fi/cellular drift nie jou classifier laat instort nie.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference uit delivery RTT

Dieselfde timing primitive kan hergebruik word om af te lei waar die recipient is, nie slegs of hulle active is nie. Die `Hope of Delivery`-werk het gewys dat training op RTT-distributions vir bekende receiver locations ’n attacker later in staat stel om die victim se location slegs uit delivery confirmations te klassifiseer:<sup>[[2]](#references)</sup>

* Bou ’n baseline vir dieselfde target terwyl hulle op verskeie bekende plekke is (home, office, campus, country A teenoor country B, ens.).
* Versamel vir elke location baie normale message RTTs en onttrek eenvoudige features soos median, variance of percentile buckets.
* Vergelyk tydens die werklike attack die nuwe probe-series met die trained clusters. Die paper rapporteer dat selfs locations binne dieselfde city dikwels geskei kan word, met `>80%` accuracy in ’n 3-location setting.
* Dit werk die beste wanneer die attacker die sender environment beheer en onder soortgelyke network conditions probes uitvoer, omdat die measured path die recipient access network, wake-up latency en messenger infrastructure insluit.<sup>[[2]](#references)</sup>

Anders as die silent reaction/edit/delete-attacks hierbo, vereis location inference nie invalid message IDs of stealthy state-changing packets nie. Plain messages met normale delivery confirmations is voldoende, dus is die tradeoff laer stealth maar wyer applicability oor messengers heen.

## Stealthy resource exhaustion

Omdat elke silent probe gedekripteer en ge-ack moet word, skep die voortdurende stuur van reaction toggles, invalid edits of delete-for-everyone packets ’n application-layer DoS:<sup>[[1]](#references)</sup>

* Dwing die radio/modem om elke sekonde te transmit/receive → merkbare battery drain, veral op idle handsets.
* Genereer upstream/downstream traffic wat mobile data plans verbruik en kan meeding met latency-sensitive features soos video calls.<sup>[[1]](#references)</sup>
* Groot invalid payloads voeg processing work by, maar die paper rapporteer dat cryptography self ’n negligible deel van battery cost is.<sup>[[1]](#references)</sup>
* Op WhatsApp aanvaar invalid reactions veel meer data as wat ’n normale emoji suggereer: gepubliseerde measurements het server-side acceptance van tot ongeveer `1 MB` per reaction gevind.
* Oversized reactions hou op om betroubare delivery receipts te produseer sodra die body groter as ongeveer `30 bytes` word, maar word steeds forwarded en processed voordat dit discarded word. Hou reaction bodies klein wanneer jy ACKs nodig het; maak hulle slegs groter wanneer die doel pure drain of covert one-way transport is.
* Public measurements het ongeveer `3.7 MB/s` (`~13.3 GB/h`) se victim traffic in hierdie mode bereik.

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
