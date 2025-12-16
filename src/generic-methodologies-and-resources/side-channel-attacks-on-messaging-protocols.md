# Mishambulizi ya Channel Pembeni ya Delivery Receipts katika Messenger za E2EE

{{#include ../banners/hacktricks-training.md}}

Delivery receipts ni lazima katika messenger za kisasa za end-to-end encrypted (E2EE) kwa sababu clients zinahitaji kujua wakati ciphertext ilifichuliwa ili waondoe ratcheting state na ephemeral keys. Server inazituma opaque blobs, hivyo acknowledgements za kifaa (double checkmarks) hutolewa na mpokeaji baada ya decryption kufanikiwa. Kupima round-trip time (RTT) kati ya hatua iliyosababishwa na mshambuliaji na delivery receipt inayolingana kunafichua channel ya timing ya azimio-japya ambayo leaks device state, uwepo mtandaoni, na inaweza kutumiwa kwa DoS ya siri. Utekelezaji wa multi-device "client-fanout" huongeza leakage kwa sababu kila kifaa kilichojiandikisha hufungua probe na kurejesha resiti yake mwenyewe.

## Delivery receipt sources vs. user-visible signals

Chagua aina za ujumbe ambazo kila mara zinatuma delivery receipt lakini hazionyeshi artifacts za UI kwa mwathiriwa. Jedwali hapa chini lina muhtasari wa tabia iliyothibitishwa kwa majaribio:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Daima noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Legend: ● = always, ◐ = conditional, ○ = never. Tabia ya UI inayotegemea platform imeorodheshwa ndani. Zima read receipts ikiwa inahitajika, lakini delivery receipts haiwezi kuzimwa kwenye WhatsApp au Signal.

## Attacker goals and models

* **G1 – Device fingerprinting:** Hesabu ni resiti ngapi zinakuja kwa probe, cluster RTTs kufahamu OS/client (Android vs iOS vs desktop), na angalia mabadiliko ya online/offline.
* **G2 – Behavioural monitoring:** Tibu mfululizo wa RTT wa thamani ya juu (≈1 Hz ni thabiti) kama time-series na tambua screen on/off, app foreground/background, safari vs saa za kazi, n.k.
* **G3 – Resource exhaustion:** Weka radios/CPUs za kila kifaa cha mwathiriwa zikianza kufanya kazi kwa kutuma silent probes zisizoisha, zikitoa betri/data na kuharibu ubora wa VoIP/RTC.

Wachezaji wawili wa tishio yanatosha kuelezea uso wa utumiaji:

1. **Creepy companion:** tayari anashiriki chat na mwathiriwa na hutumia self-reactions, reaction removals, au edits/deletes zinazorudiwa zikiwa zimetengwa kwa message IDs zilizopo.
2. **Spooky stranger:** anasajili akaunti ya burner na kutuma reactions zikirejelea message IDs ambazo hazjawahi kuwepo kwenye mazungumzo ya ndani; WhatsApp na Signal bado hufungua na kukiri hata kama UI inatupa mabadiliko ya state, kwa hivyo hakuna mazungumzo ya awali yanahitajika.

## Tooling for raw protocol access

Tegemea clients zinazofichua protocol ya E2EE kwa undani ili uweze kutunga packets nje ya vizingiti vya UI, kubainisha `message_id` yoyote, na kuandika timestamps sahihi:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) au [Cobalt](https://github.com/Auties00/Cobalt) (inayolenga mobil) zinakuwezesha kutuma raw `ReactionMessage`, `ProtocolMessage` (edit/delete), na `Receipt` frames huku zikidumisha double-ratchet state.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) pamoja na [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) zinafichua kila aina ya ujumbe kupitia CLI/API. Mfano wa self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Chanzo cha client ya Android kinaandika jinsi delivery receipts zinavyojumuishwa kabla hazijaondoka kwenye kifaa, kinasema kwa nini side channel ina bandwidth ndogo hapo.

Wakati tooling maalum haipatikani, bado unaweza kusababisha vitendo vya kimya kutoka WhatsApp Web au Signal Desktop na kusniff encrypted websocket/WebRTC channel, lakini raw APIs zinaondoa ucheleweshaji wa UI na kuruhusu operesheni zisizo halali.

## Creepy companion: silent sampling loop

1. Chagua ujumbe wa kihistoria ulioandikwa na wewe kwenye chat ili mwathiriwa asiwahi kuona mabadiliko ya "reaction".
2. Badilisha kati ya emoji inayoonekana na payload ya reaction tupu (imekodishwa kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila utumaji hutolewa device ack licha ya hakuna tofauti ya UI kwa mwathiriwa.
3. Weka timestamp ya wakati wa kutuma na kila tiba ya delivery receipt inayofika. Loop ya 1 Hz kama ifuatavyo inatoa traces za RTT kwa kifaa kila mara:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Kwa sababu WhatsApp/Signal zinakubali updates za reaction zisizo na kikomo, mshambuliaji hahitaji kamwe kuchapisha maudhui mapya ya chat au kuogopa windows za edit.

## Spooky stranger: probing arbitrary phone numbers

1. Sajili akaunti mpya ya WhatsApp/Signal na pokea public identity keys za nambari lengwa (hii hufanywa kiotomatiki wakati wa setup ya session).
2. Tunga packet ya reaction/edit/delete inayorejelea random `message_id` ambayo hakuwahi kuonekana na upande wowote (WhatsApp inakubali GUID za `key.id` yoyote; Signal inatumia timestamps za millisecond).
3. Tuma packet hata kama hakuna thread iliyopo. Vifaa vya mwathiriwa vinasoma ciphertext, yashindwa kulinganisha na message ya msingi, yanatupa state change, lakini bado yanakiri ciphertext inayoingizwa, yakituma device receipts kwa mshambuliaji.
4. Rudia mfululizo ili kujenga mfululizo wa RTT bila kamwe kuonekana kwenye orodha za mazungumzo za mwathiriwa.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Baada ya ujumbe kufutwa-kwenye-wote mara moja, packets za delete zinazorudia zinazorejelea hiyo `message_id` hazina athari za UI lakini kila kifaa bado hufungua na kukiri.
* **Out-of-window operations:** WhatsApp inalinda dirisha la ~60 h kwa delete / ~20 min kwa edit kwenye UI; Signal inalinda ~48 h. Ujumbe za protocol zilizotengenezwa nje ya windows hizi zinatupwa kimya kwenye kifaa cha mwathiriwa lakini receipts zinatumwa, kwa hivyo washambuliaji wanaweza kuprobe bila kikomo hata baada ya mazungumzo kumalizika.
* **Invalid payloads:** Mwili wa edit uliharibika au deletes zinazorejelea ujumbe uliofutwa tayari zinaleta tabia hiyo hiyo—decryption pamoja na receipt, hakuna athari zinazoonekana kwa mtumiaji.

## Multi-device amplification & fingerprinting

* Kifaa kilichohusishwa kila kimojaz hufungua probe kwa kujitegemea na kurudisha ack yake yenyewe. Kuhesabu receipts kwa probe kunaonyesha idadi kamili ya vifaa.
* Ikiwa kifaa kimoja kiko offline, resiti yake itawekwa kwenye safu na itatolewa wakati kingeunganishwa tena. Mapengo kwa hiyo huleta leak ya cycles za online/offline na hata ratiba za safari (mfano, resiti za desktop huacha wakati wa safari).
* Mgawanyo wa RTT hutofautiana kwa jukwaa kutokana na usimamizi wa nguvu wa OS na push wakeups. Cluster RTTs (mfano, k-means juu ya median/variance features) ili kutambulisha “Android handset", “iOS handset", “Electron desktop", n.k.
* Kwa sababu mtumaji lazima apate inventory ya key za mpokeaji kabla ya ku-encrypt, mshambuliaji anaweza pia kuangalia wakati vifaa vipya vinapounganishwa; ongezeko la ghafla la idadi ya vifaa au cluster mpya ya RTT ni kiashiria thabiti.

## Behaviour inference from RTT traces

1. Sampuli kwa ≥1 Hz ili kukamata athari za scheduling za OS. Kwa WhatsApp kwenye iOS, RTT <1 s zina uhusiano mkubwa na screen-on/foreground, >1 s zinaonyesha screen-off/background throttling.
2. Jenga classifiers rahisi (thresholding au k-means ya cluster mbili) zinazoelezea kila RTT kama "active" au "idle". Jumlisha lebo hizi katika mrefu ili kupata saa za kulala, safari, saa za kazi, au wakati companion wa desktop anatumika.
3. Endanisha probes kwa wakati mmoja kuelekea kila kifaa kuona wakati watumiaji wanabadilisha kutoka simu kwenda desktop, wakati companions wanaenda offline, na kama app inahifadhiwa kwa push vs socket ya kudumu.

## Stealthy resource exhaustion

Kwa sababu kila probe ya kimya lazima ifunguliwe na kukiri, kutuma mara kwa mara reaction toggles, edits zisizo halali, au delete-for-everyone packets kunaunda application-layer DoS:

* Lazoa radio/modem kutuma/kupokea kila sekunde → kupunguza betri kwa urahisi, hasa kwenye handsets zilizo idle.
* Inazalisha trafiki isiyopimwa upstream/downstream inayotumia mipango ya data ya simu huku ikijificha ndani ya kelele za TLS/WebSocket.
* Inachukua threads za crypto na kuleta jitter katika huduma nyeti kwa latency (VoIP, video calls) ingawa mtumiaji kamwe haoni arifa.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
