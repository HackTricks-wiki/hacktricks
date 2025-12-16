# Sy kanaal-aanvalle via afleweringskwitansies in E2EE-boodskappers

{{#include ../banners/hacktricks-training.md}}

Afleweringskwitansies is verpligtend in moderne end-to-end encrypted (E2EE) boodskappers aangesien kliënte moet weet wanneer 'n ciphertext gedekripteer is sodat hulle ratcheting state en ephemeral keys kan weggooi. Die bediener stuur ondoorgrondelike blobs deur, so toestelbevestigings (double checkmarks) word deur die ontvanger uitgee nadat dekripsie suksesvol was. Deur die round-trip time (RTT) te meet tussen 'n aanvaller-geaktiveerde aksie en die ooreenstemmende afleweringskwitansie ontrafel jy 'n hoë-resolusie tydkanaal wat device state, aanlyn-teenwoordigheid en kan misbruik word vir covert DoS. Multi-device "client-fanout" deployments versterk die leak omdat elke geregistreerde toestel die probe dekripteer en sy eie kwitansie terugstuur.

## Afleweringskwitansiebronne vs. gebruiker-sigbare seine

Kies boodskapsoorte wat altyd 'n afleweringskwitansie uitstuur maar nie UI-artefakte op die slagoffer openbaar nie. Die tabel hieronder som die empiries bevestigde gedrag op:

| Messenger | Aksie | Afleweringskwitansie | Slagoffer-kennisgewing | Aantekeninge |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tekstboodskap | ● | ● | Altyd opvallend → slegs nuttig om beginstaat te bootstrap. |
| | Reaksie | ● | ◐ (slegs as daar op 'n boodskap van die slagoffer geantwoord word) | Selfreaksies en verwyderings bly stil. |
| | Edit | ● | Platform-afhanklike stil push | Edit-venster ≈20 min; nog steeds ack’d ná verstryking. |
| | Delete for everyone | ● | ○ | UI laat ~60 h toe, maar later pakkette word steeds ack’d. |
| **Signal** | Tekstboodskap | ● | ● | Selfde beperkings as WhatsApp. |
| | Reaksie | ● | ◐ | Selfreaksies onsigbaar vir die slagoffer. |
| | Edit/Delete | ● | ○ | Bediener handhaaf ~48 h venster, laat tot 10 wysigings toe, maar laatte pakkette word steeds ack’d. |
| **Threema** | Tekstboodskap | ● | ● | Multi-device kwitansies word gekonsolideer, so net een RTT per probe word sigbaar. |

Legend: ● = altyd, ◐ = voorwaardelik, ○ = nooit. Platform-afhanklike UI-gedrag is inline genoteer. Skakel read receipts af indien nodig, maar afleweringskwitansies kan nie in WhatsApp of Signal gedeaktiveer word nie.

## Aanvaller-doelwitte en modelle

* **G1 – Apparaat-vingerafdrukke:** Tel hoeveel kwitansies per probe arriveer, groepeer RTTs om OS/klient af te lei (Android vs iOS vs desktop), en monitor aanlyn/aflyn oorgange.
* **G2 – Gedragsmonitering:** Behandel die hoë-frekwensie RTT-reeks (≈1 Hz is stabiel) as 'n tydreeks en leid skerm aan/af, app voorgrond/agtergrond, pendel- vs werksure, ens. af.
* **G3 – Hulpbron-uitputting:** Hou radios/CPU's van elke slagoffer-toestel wakker deur nooit-ophoudende stille probes te stuur, wat battery/data uitput en VoIP/RTC kwaliteit degradeer.

Twee dreig-akteurs beskryf die misbruikoppervlak voldoende:

1. **Creepy companion:** deel reeds 'n klets met die slagoffer en misbruik self-reaksies, reaksieverwyderings, of herhaalde wysigings/verwyderings gebind aan bestaande message IDs.
2. **Spooky stranger:** registreer 'n burner rekening en stuur reaksies wat na message IDs verwys wat nooit in die plaaslike gesprek bestaan het nie; WhatsApp en Signal dekripteer en erken dit steeds alhoewel die UI die staat weggooi, so geen voorafgaande gesprek is benodig nie.

## Gereedskap vir rou protokoltoegang

Vertrou op kliënte wat die onderliggende E2EE-protokol blootstel sodat jy pakkette buite UI-beperkings kan saamstel, arbitrêre `message_id`s kan spesifiseer, en presiese tydstempels kan log:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) of [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) laat jou toe om rou `ReactionMessage`, `ProtocolMessage` (edit/delete), en `Receipt` frames uit te stuur terwyl die double-ratchet state in sinchronisasie gehou word.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) gekombineer met [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) openbaar elke boodskaptipe via CLI/API. Voorbeeld self-reaksie-schakelaar:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Die bron van die Android-klient dokumenteer hoe afleweringskwitansies saamgevoeg word voordat hulle die toestel verlaat, wat verduidelik waarom die side channel daar verwaarlikbare bandbreedte het.

Wanneer pasgemaakte gereedskap onbeskikbaar is, kan jy steeds stille aksies vanaf WhatsApp Web of Signal Desktop aktiveer en die enkripsieerde websocket/WebRTC-kanaal sniff, maar rou APIs verwyder UI-vertragings en laat ongeldig-operasies toe.

## Creepy companion: stilte-monsternemingslus

1. Kies enige historiese boodskap wat jy in die klets geskryf het sodat die slagoffer nooit "reaksie" ballonnetjies sien verander nie.
2. Wissel af tussen 'n sigbare emoji en 'n leë reaksie-payload (gekodeer as `""` in WhatsApp protobufs of `--remove` in signal-cli). Elke transmissie gee 'n toestel-ack ondanks dat daar geen UI-delta vir die slagoffer is nie.
3. Tydstempel die stuurtyd en elke afleweringskwitansie-ontvangs. 'n 1 Hz lus soos die volgende gee per-toestel RTT-spore oneindig:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Omdat WhatsApp/Signal onbeperkte reaksie-opdaterings aanvaar, hoef die aanvaller nooit nuwe kletsinhoud te plaas of oor edit-vensters bekommerd te wees nie.

## Spooky stranger: probeer arbitrêre telefoonnommers

1. Registreer 'n vars WhatsApp/Signal-rekening en haal die publieke identity keys vir die teiken-nommer (gedoen outomaties tydens sessie-opstelling).
2. Stel 'n reaksie/edit/delete-pakket saam wat na 'n ewekansige `message_id` verwys wat nooit deur enige party gesien is nie (WhatsApp aanvaar arbitrêre `key.id` GUIDs; Signal gebruik millisekonde-tydstempels).
3. Stuur die pakket alhoewel geen draad bestaan nie. Die slagoffer-toestelle dekripteer dit, misluk om die basisboodskap te pas, verwerp die staatverandering, maar erken steeds die inkomende ciphertext en stuur toestelkwitansies terug aan die aanvaller.
4. Herhaal deurlopend om RTT-reekse te bou sonder om ooit in die slagoffer se kletslys te verskyn.

## Hergebruik van wysigings en verwyderings as geheime triggers

* **Herhaalde verwyderings:** Nadat 'n boodskap een keer "delete-for-everyone" is, het verdere verwyderingspakkette wat na dieselfde `message_id` verwys geen UI-effek nie, maar elke toestel dekripteer en erken dit steeds.
* **Buite-venster operasies:** WhatsApp handhaaf ~60 h delete / ~20 min edit vensters in die UI; Signal handhaaf ~48 h. Opgestel protokolboodskappe buite hierdie vensters word stilweg op die slagoffer-toestel geïgnoreer, maar kwitansies word wel gestuur, so aanvallers kan oneindig ver daarna probe uitvoer.
* **Ongeldige payloads:** Verkeerd gevormde edit-bodies of verwyderings wat na reeds uitgevee boodskappe verwys, lok dieselfde gedrag—dekripsie plus kwitansie, geen gebruiker-sigbare artefakte nie.

## Multi-device versterking & vingerafdrukke

* Elke geassosieerde toestel (foon, desktop app, blaaier-kompaan) dekripteer die probe onafhanklik en stuur sy eie ack terug. Om kwitansies per probe te tel, openbaar die presiese toestelbedrag.
* As 'n toestel aflyn is, word sy kwitansie in die ry geplaas en uitgee by herverbinding. Gapings lek dus aanlyn/aflyn-siklusse en selfs pendel-skemas (bv. desktop-kwitansies stop tydens reis).
* RTT-verspreidings verskil per platform weens OS-kragbestuur en push-wakeups. Groepeer RTTs (bv. k-means op median/variance eienskappe) om “Android handset", “iOS handset", “Electron desktop", ens. te benoem.
* Aangesien die sender die ontvanger se key-inventory moet kry voordat enkripsie plaasvind, kan die aanvaller ook kyk wanneer nuwe toestelle gekoppeld word; 'n skielike toename in toesteltelling of 'n nuwe RTT-kluster is 'n sterk aanduiding.

## Gedragsinferensie vanaf RTT-spore

1. Sampel by ≥1 Hz om OS-skedulerings-effekte vas te vang. Met WhatsApp op iOS korreleer <1 s RTTs sterk met skerm-aan/voorrgrond, >1 s met skerm-af/agtergrond-demping.
2. Bou eenvoudige klassifikators (drempeling of twee-kluster k-means) wat elke RTT as "aktief" of "inaktief" etiketteer. Agregeer etikette in loppe om slaaptye, pendels, werksure, of wanneer die desktop-kompaan aktief is te bepaal.
3. Korrelleer gelyktydige probes na elke toestel om te sien wanneer gebruikers van mobiel na desktop skakel, wanneer kompane offline gaan, en of die app deur push vs volhoubare sokkets ge-rate-limit word.

## Stilswyende hulpbronuitputting

Aangesien elke stille probe gedekripteer en erken moet word, skep deurlopende reaksie-schakels, ongeldige wysigings, of delete-for-everyone pakkette 'n application-layer DoS:

* Dwing die radio/modem om elke sekonde te stuur/ontvang → merkbare battery-uitputting, veral op idle handsets.
* Genereer ongemete upstream/downstream verkeer wat mobiele data-planne opbruik terwyl dit in TLS/WebSocket-ruis meng.
* Beslaan crypto-drade en introduceer jitter in latensie-sensitiewe funksies (VoIP, video-oproepe) alhoewel die gebruiker nooit kennisgewings sien nie.

## Verwysings

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
