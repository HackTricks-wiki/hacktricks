# Side-Channel-aanvalle met afleweringskwitansies in E2EE-boodskapdienste

Afleweringskwitansies is noodsaaklik in moderne end-tot-end-geënkripteerde (E2EE) boodskapdienste omdat kliënte moet weet wanneer ’n ciphertext gedekripteer is sodat hulle ratcheting state en ephemeral keys kan weggooi. Die server stuur ondeursigtige blobs aan, dus word toestelbevestigings (dubbele regmerkies) deur die ontvanger uitgestuur nadat dekripsie suksesvol was. Deur die round-trip time (RTT) tussen ’n attacker-geaktiveerde aksie en die ooreenstemmende afleweringskwitansie te meet, word ’n hoë-resolusie timing channel blootgestel wat toestelstatus en aanlyn-teenwoordigheid lek, en vir covert DoS misbruik kan word. Multi-device “client-fanout”-deployments versterk die leakage omdat elke geregistreerde toestel die probe dekripteer en sy eie kwitansie terugstuur.<sup>[[1]](#references)</sup>

## Bronne van afleweringskwitansies teenoor gebruiker-sigbare seine

Kies boodskapsoorte wat altyd ’n afleweringskwitansie uitstuur, maar nie UI-artifacts op die slagoffer vertoon nie. Die tabel hieronder som die empiries bevestigde gedrag op:<sup>[[1]](#references)</sup>

| Messenger | Aksie | Afleweringskwitansie | Slagofferkennisgewing | Notas |
|-----------|--------|----------------------|-----------------------|-------|
| **WhatsApp** | Teksboodskap | ● | ● | Altyd noisy → slegs nuttig om state te bootstrap. |
| | Reaction | ● | ◐ (slegs wanneer op slagoffer se boodskap gereageer word) | Self-reactions en removals bly stil. |
| | Edit | ● | Platform-afhanklike silent push | Edit-venster ≈20 min; steeds ge-ack ná verstryking. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar latere packets word steeds ge-ack. |
| **Signal** | Teksboodskap | ● | ● | Dieselfde beperkings as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions is onsigbaar vir die slagoffer. |
| | Edit/Delete | ● | ○ | Server dwing ’n ~48 h-venster af, laat tot 10 edits toe, maar laat packets word steeds ge-ack. |
| **Threema** | Teksboodskap | ● | ● | Multi-device-kwitansies word geaggregeer, dus word slegs een RTT per probe sigbaar. |

Sleutel: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-afhanklike UI-gedrag word inline aangedui. Deaktiveer read receipts indien nodig, maar delivery receipts kan nie in WhatsApp of Signal afgeskakel word nie.<sup>[[1]](#references)</sup>

## Attacker-doelwitte en -modelle

* **G1 – Device fingerprinting:** Tel hoeveel kwitansies per probe aankom, cluster RTT’s om OS/client (Android teenoor iOS teenoor desktop) af te lei, en monitor aanlyn-/aflynoorgange.
* **G2 – Behavioural monitoring:** Behandel die hoëfrekwensie-RTT-reeks (≈1 Hz is stabiel) as ’n tydreeks en lei screen on/off, app foreground/background, pendel- teenoor werksure, ensovoorts af.
* **G3 – Resource exhaustion:** Hou die radio’s/CPU’s van elke slagoffertoestel wakker deur eindelose silent probes te stuur, wat battery/data uitput en video-call-gehalte verlaag.<sup>[[1]](#references)</sup>

Twee threat actors is voldoende om die abuse surface te beskryf:<sup>[[1]](#references)</sup>

1. **Creepy companion:** deel reeds ’n chat met die slagoffer en misbruik self-reactions, reaction removals, of herhaalde edits/deletes wat aan bestaande message IDs gekoppel is.
2. **Spooky stranger:** registreer ’n burner account en stuur reactions wat verwys na message IDs wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en acknowledgeer dit steeds, hoewel die UI die state change weggooi, dus is geen vorige gesprek nodig nie.

## Tooling vir raw protocol access

Maak staat op kliënte wat genoeg van die onderliggende E2EE-protokol blootstel om supported packets buite UI-beperkings te skep en presiese timestamps te log; arbitrary message IDs vereis dat elke implementering nagegaan word:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumenteer die stuur en ontvangs van delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web- en mobile API) dokumenteer message operations soos reacting, editing en deleting. Gebruik hul gedokumenteerde API’s eerder as om aan te neem dat elke interne frame blootgestel word.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) stel CLI-, JSON-RPC- en D-Bus-interfaces bloot, terwyl [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) ’n Java-library is om met Signal te kommunikeer.<sup>[[5]](#references)[[7]](#references)</sup> Huidige `signal-cli`-syntax gebruik `sendReaction RECIPIENT --target-author --target-timestamp`; hou `receive` of `daemon` aan die loop sodat protocol updates steeds verwerk word.<sup>[[6]](#references)</sup> Voorbeeld van ’n self-reaction-toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Metings in die Careless Whisper-paper het bevind dat delivery receipts oor toestelle gesinchroniseer word, dus word slegs een kwitansie per boodskap blootgestel, selfs in ’n multi-device-opstelling.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) bevat WhatsApp/Signal-backends, gebruik silent delete probes by verstek, en merk `active` teenoor `standby` met ’n rolling-median threshold (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) is ’n ligter WhatsApp-first CLI met `--delay`, `--concurrent`, CSV/Prometheus-exporters en Grafana-vriendelike output.<sup>[[9]](#references)</sup> Behandel albei as reconnaissance helpers eerder as protocol references; die belangrikste gevolgtrekking is hoe min code nodig is sodra raw client access bestaan.

Wanneer custom tooling nie beskikbaar is nie, kan official clients of browser developer tools steeds silent actions trigger en encrypted traffic timing blootstel; raw APIs verwyder UI-delays en laat invalid operations toe.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Kies enige historiese boodskap wat jy in die chat geskryf het sodat die slagoffer nooit sien dat “reaction”-ballonne verander nie.
2. Wissel tussen ’n sigbare emoji en ’n leë reaction payload (geënkodeer as `""` in WhatsApp protobufs of `--remove` in signal-cli). Elke transmission lewer ’n device ack ondanks geen UI-delta vir die slagoffer nie.
3. Tydstempel die send time en elke delivery receipt arrival. ’n 1 Hz-loop soos die volgende lewer onbepaald per-device RTT-traces:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal unlimited reaction updates aanvaar, hoef die attacker nooit nuwe chat content te post of oor edit-windows bekommerd te wees nie.<sup>[[1]](#references)</sup>

## Spooky stranger: probing van arbitrary phone numbers

1. Registreer ’n nuwe WhatsApp/Signal-account en haal die public identity keys vir die teikennommer op (dit gebeur outomaties tydens session setup).
2. Skep ’n reaction packet wat na ’n random `message_id` verwys wat deur geen van die partye gesien is nie; die paper rapporteer dat beide WhatsApp en Signal sulke reactions aanvaar en steeds delivery receipts genereer.<sup>[[1]](#references)</sup>
3. Stuur die packet selfs al bestaan geen thread nie. Die slagoffer se toestelle dekripteer dit, kan dit nie aan die base message koppel nie, gooi die state change weg, maar acknowledgeer steeds die incoming ciphertext en stuur device receipts terug na die attacker.
4. Herhaal voortdurend om RTT-series op te bou sonder ’n vorige gesprek of sigbare kennisgewing.<sup>[[1]](#references)</sup>

As jy eers moet vasstel watter nommers geregistreer is of device inventories op skaal vooraf wil seed, chain dit met [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) eerder as om random E.164-ranges met die hand te raai.

Gepubliseerde contact-discovery-navorsing het gewys waarom dit operasioneel belangrik is: met akkurate phone-prefix-tabelle en beskeie hulpbronne kon navorsers ongeveer `10%` van Amerikaanse selfoonnommers op WhatsApp en `100%` op Signal query voordat hulle met targeted probing voortgegaan het.<sup>[[11]](#references)</sup> In praktyk hou pre-filtering van live accounts jou silent-probe-budget gefokus op nommers wat packets werklik sal dekripteer.

Onlangse WhatsApp-builds stel ook `Settings -> Privacy -> Advanced -> Block unknown account messages` bloot.<sup>[[10]](#references)</sup> Behandel dit as ’n throughput-limiter: die tracker-dokumentasie sê WhatsApp blokkeer hoë-volume-boodskappe van onbekende accounts, maar openbaar nie die threshold nie; dit verhoed dus nie probe reactions volledig nie.<sup>[[8]](#references)</sup>

## Recycling van edits en deletes as covert triggers

* **Repeated deletes:** Nadat ’n boodskap een keer vir almal deleted-for-everyone is, het verdere delete packets wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke toestel dekripteer en acknowledgeer dit steeds.
* **Out-of-window operations:** WhatsApp dwing ~60 h delete- en ~20 min edit-windows in die UI af; Signal dwing ~48 h af. Crafted protocol messages buite hierdie windows word stilweg op die slagoffertoestel geïgnoreer, maar receipts word steeds gestuur; attackers kan dus onbepaald lank ná die gesprek geëindig het probe.
* **Invalid payloads:** Die paper rapporteer dat invalid messages steeds ge-ack kan word; presiese gedrag vir malformed bodies of purged IDs hang van die implementering af, dus moet jy dit toets voordat jy daarop staatmaak.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Op WhatsApp en Signal dekripteer elke geassosieerde toestel (phone, desktop app, browser companion) die probe onafhanklik en stuur sy eie ack terug. Deur receipts per probe te tel, word die presiese aantal toestelle onthul.<sup>[[1]](#references)</sup>
* Indien ’n toestel offline is, word sy receipt in ’n queue geplaas en met herverbinding uitgestuur. Gapings lek dus aanlyn-/aflyn-siklusse en selfs pendelskedules (byvoorbeeld, desktop-receipts hou tydens reis op).
* RTT-distribusies verskil volgens platform en omgewing omdat OS, model, client en network conditions timing beïnvloed. Cluster RTT’s (byvoorbeeld k-means op median/variance-features) om “Android handset”, “iOS handset”, “Electron desktop”, ensovoorts te label.
* Omdat die sender die ontvanger se key inventory moet ophaal voordat dit encrypt, kan die attacker ook monitor wanneer nuwe toestelle gepaar word; ’n skielike toename in device count of ’n nuwe RTT-cluster is ’n sterk aanduiding.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing en stacked receipts

* **WhatsApp burst tolerance:** Gepubliseerde metings het gerapporteer dat WhatsApp silent-reaction-bursts so vinnig as een probe elke `50 ms` aanvaar het sonder duidelike server-side queueing. Dit is nuttig vir kort calibration bursts, vinnige device counting, of om ’n drain attack vinnig op te skaal.
* **Signal long-run queueing:** Signal het kort bursts verdra, maar het sustained multi-probe-per-second-verkeer begin queuen. Vir langtermyn-monitering, hou die cadence rondom `1 Hz` (of laer) sodat elke receipt steeds die huidige device state weerspieël eerder as backlog drain.
* **Reconnect artefacts:** Wanneer ’n toestel weer aanlyn kom, batch of flush sommige clients verskeie vertraagde receipts vinnig. Behandel hierdie receipt-bursts as ’n state-transition-marker eerder as onafhanklike RTT-samples, anders sal jou clustering / `active` teenoor `idle`-classifier reconnect noise overfit.<sup>[[1]](#references)</sup>

## Behaviour inference uit RTT-traces

1. Sample teen ≥1 Hz om OS-schedulingseffekte vas te vang. Met WhatsApp op iOS korreleer RTT’s van <1 s sterk met screen-on/foreground, en RTT’s van >1 s met screen-off/background-throttling.
2. Bou eenvoudige classifiers (thresholding of two-cluster k-means) wat elke RTT as “active” of “idle” label. Aggregate labels in streaks om slaaptye, pendeltye, werksure, of wanneer die desktop companion aktief is, af te lei.
3. Correlate simultaneous probes na elke toestel om te sien wanneer gebruikers van mobile na desktop oorskakel, wanneer companions offline gaan, en of die app deur push teenoor persistent socket rate limited word.
4. Vermy in real networks ’n enkele hardcoded `1 s`-threshold. Bootstrap elke toestel met ’n kort warm-up window en hou ’n rolling baseline (byvoorbeeld, die device-activity-tracker PoC gebruik `threshold = 0.9 * median RTT`) sodat Wi-Fi/cellular-drift nie jou classifier laat misluk nie.<sup>[[1]](#references)[[8]](#references)</sup>

## Ligging-afleiding uit delivery RTT

Dieselfde timing primitive kan hergebruik word om af te lei waar die ontvanger is, nie net of hulle aktief is nie. Die `Hope of Delivery`-werk het gewys dat training op RTT-distribusies vir bekende ontvangerliggings ’n attacker later in staat stel om die slagoffer se ligging slegs uit delivery confirmations te klassifiseer:<sup>[[2]](#references)</sup>

* Bou ’n baseline vir dieselfde target terwyl hulle op verskeie bekende plekke is (huis, kantoor, kampus, land A teenoor land B, ensovoorts).
* Versamel vir elke ligging baie normale message RTT’s en ekstraheer eenvoudige features soos median, variance of percentile-buckets.
* Vergelyk tydens die werklike attack die nuwe probe-series met die trained clusters. Die paper rapporteer dat selfs liggings binne dieselfde stad dikwels onderskei kan word, met `>80%` accuracy in ’n 3-location-setting.
* Dit werk die beste wanneer die attacker die sender environment beheer en onder soortgelyke network conditions probe, omdat die gemete pad die recipient access network, wake-up latency en messenger infrastructure insluit.<sup>[[2]](#references)</sup>

Anders as die silent reaction/edit/delete-attacks hierbo, vereis location inference nie invalid message IDs of stealthy state-changing packets nie. Plain messages met normale delivery confirmations is voldoende, dus is die tradeoff laer stealth maar wyer toepasbaarheid oor messengers heen.

## Stealthy resource exhaustion

Omdat elke silent probe gedekripteer en ge-acknowledge moet word, skep die voortdurende stuur van reaction toggles, invalid edits of delete-for-everyone-packets ’n application-layer DoS:<sup>[[1]](#references)</sup>

* Dwing die radio/modem om elke sekonde te transmit/receive → merkbare battery drain, veral op idle handsets.
* Genereer upstream/downstream-verkeer wat mobiele dataplanne verbruik en kan meeding met latency-sensitive features soos video calls.<sup>[[1]](#references)</sup>
* Groot invalid payloads voeg processing work by, maar die paper rapporteer dat cryptography self ’n onbeduidende deel van battery cost is.<sup>[[1]](#references)</sup>
* Op WhatsApp aanvaar invalid reactions veel meer data as wat ’n normale emoji suggereer: gepubliseerde metings het server-side acceptance van ongeveer `1 MB` per reaction gevind.
* Oversized reactions hou op om betroubare delivery receipts te produseer wanneer die body ongeveer `30 bytes` oorskry, maar word steeds aangestuur en verwerk voordat dit weggegooi word. Hou reaction bodies klein wanneer jy ACKs benodig; vergroot hulle slegs wanneer die doel pure drain of covert one-way transport is.
* Publieke metings het ongeveer `3.7 MB/s` (`~13.3 GB/h`) aan slagofferverkeer in hierdie modus bereik.

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
