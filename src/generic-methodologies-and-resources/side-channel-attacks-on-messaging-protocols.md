# Mashambulizi ya Side-Channel kupitia Risiti za Uwasilishaji katika E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Risiti za uwasilishaji ni za lazima katika E2EE messengers za kisasa kwa sababu clients zinahitaji kujua wakati ciphertext ilipotolewa kutoka usimbaji fiche ili ziweze kutupa hali ya ratcheting na funguo za muda mfupi. Server husambaza blobs zisizoeleweka, kwa hiyo acknowledgements za kifaa (alama mbili za tiki) hutumwa na mpokeaji baada ya kutoa ujumbe kwa mafanikio kutoka usimbaji fiche. Kupima muda wa kwenda na kurudi (RTT) kati ya kitendo kilichoanzishwa na mshambuliaji na risiti ya uwasilishaji inayohusiana hufichua timing channel ya ubora wa juu inayovuja hali ya kifaa na uwepo mtandaoni, na inaweza kutumiwa vibaya kwa DoS ya siri. Usambazaji wa "client-fanout" wa vifaa vingi huongeza uvujaji kwa sababu kila kifaa kilichosajiliwa hutoa probe kutoka usimbaji fiche na kurudisha risiti yake.<sup>[[1]](#references)</sup>

## Vyanzo vya risiti za uwasilishaji dhidi ya ishara zinazoonekana kwa mtumiaji

Chagua aina za ujumbe ambazo hutuma risiti ya uwasilishaji kila wakati lakini hazionyeshi mabaki ya UI kwa mwathiriwa. Jedwali hapa chini linafupisha tabia iliyothibitishwa kwa majaribio:<sup>[[1]](#references)</sup>

| Messenger | Kitendo | Risiti ya uwasilishaji | Arifa kwa mwathiriwa | Maelezo |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Ujumbe wa maandishi | ● | ● | Huleta kelele kila wakati → ni muhimu tu kuanzisha hali. |
| | Reaction | ● | ◐ (ikiwa tu reaction inajibu ujumbe wa mwathiriwa) | Self-reactions na kuondoa reaction hubaki kimya. |
| | Kuhariri | ● | Silent push hutegemea platform | Kipindi cha kuhariri ≈ dakika 20; bado hupokea ack baada ya muda kuisha. |
| | Kufuta kwa kila mtu | ● | ○ | UI huruhusu takriban saa 60, lakini packets zinazotumwa baadaye bado hupokea ack. |
| **Signal** | Ujumbe wa maandishi | ● | ● | Vizuizi sawa na vya WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions hazionekani kwa mwathiriwa. |
| | Kuhariri/Kufuta | ● | ○ | Server hutekeleza kipindi cha takriban saa 48, huruhusu hadi edits 10, lakini packets zinazotumwa kwa kuchelewa bado hupokea ack. |
| **Threema** | Ujumbe wa maandishi | ● | ● | Risiti za vifaa vingi hujumlishwa, kwa hiyo RTT moja tu kwa kila probe huonekana. |

Maana ya alama: ● = kila wakati, ◐ = hutegemea hali, ○ = kamwe. Tabia ya UI inayotegemea platform imeelezwa ndani ya jedwali. Zima read receipts ikihitajika, lakini risiti za uwasilishaji haziwezi kuzimwa katika WhatsApp au Signal.<sup>[[1]](#references)</sup>

## Malengo na mifano ya mshambuliaji

* **G1 – Kutambua kifaa:** Hesabu risiti ngapi zinafika kwa kila probe, panga RTT katika makundi ili kukisia OS/client (Android dhidi ya iOS dhidi ya desktop), na fuatilia mabadiliko ya hali ya mtandaoni/nje ya mtandao.
* **G2 – Kufuatilia tabia:** Chukulia mfululizo wa RTT wa masafa ya juu (≈1 Hz ni thabiti) kama mfululizo wa data za muda na ukisie skrini kuwashwa/kuzimwa, app kuwa mbele/nyuma, muda wa safari dhidi ya saa za kazi, n.k.
* **G3 – Kumaliza rasilimali:** Weka radios/CPUs za kila kifaa cha mwathiriwa zikiwa hai kwa kutuma probes zisizo na mwisho na zisizoonekana, ukimaliza betri/data na kudhoofisha ubora wa video-call.<sup>[[1]](#references)</sup>

Wahusika wawili wa tishio wanatosha kueleza eneo la matumizi mabaya:<sup>[[1]](#references)</sup>

1. **Mwenza wa kutisha:** tayari anashiriki chat na mwathiriwa na hutumia vibaya self-reactions, kuondoa reactions, au kuhariri/kufuta mara kwa mara kwa kutumia message IDs zilizopo.
2. **Mgeni wa kutisha:** husajili akaunti ya muda na kutuma reactions zinazorejelea message IDs ambazo hazijawahi kuwepo kwenye mazungumzo ya ndani; WhatsApp na Signal bado huzitoa kutoka usimbaji fiche na kutoa acknowledgements ingawa UI hutupa mabadiliko ya hali, kwa hiyo hakuna mazungumzo ya awali yanayohitajika.

## Zana za kufikia raw protocol

Tumia clients zinazoonyesha sehemu ya kutosha ya E2EE protocol ili kuunda packets zinazotumika nje ya vizuizi vya UI na kurekodi timestamps sahihi; message IDs za kiholela zinahitaji kuhakikiwa katika kila implementation:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) inaeleza jinsi ya kutuma na kupokea risiti za uwasilishaji; [Cobalt](https://github.com/Auties00/Cobalt) (API isiyo rasmi ya Java/Kotlin Web na mobile) inaeleza shughuli za ujumbe kama vile ku-react, kuhariri na kufuta. Tumia APIs zilizoelezwa badala ya kudhani kila internal frame inapatikana.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) hutoa interfaces za CLI, JSON-RPC na D-Bus, huku [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) ikiwa Java library ya kuwasiliana na Signal.<sup>[[5]](#references)[[7]](#references)</sup> Sintaksia ya sasa ya `signal-cli` hutumia `sendReaction RECIPIENT --target-author --target-timestamp`; acha `receive` au `daemon` ikiendelea kufanya kazi ili protocol updates ziendelee kuchakatwa.<sup>[[6]](#references)</sup> Mfano wa kuwasha/kuzima self-reaction:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Vipimo katika karatasi ya Careless Whisper vilibaini kuwa risiti za uwasilishaji husawazishwa kati ya vifaa, kwa hivyo risiti moja tu kwa kila ujumbe huonekana hata katika usanidi wa vifaa vingi.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) ina backends za WhatsApp/Signal, hutumia silent delete probes kwa chaguomsingi, na huainisha `active` dhidi ya `standby` kwa kutumia kizingiti cha rolling median (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) ni CLI nyepesi zaidi inayolenga WhatsApp, yenye `--delay`, `--concurrent`, exporters za CSV/Prometheus, na matokeo yanayofaa Grafana.<sup>[[9]](#references)</sup> Zichukulie zote mbili kama zana saidizi za uchunguzi wa awali badala ya marejeleo ya itifaki; jambo muhimu ni kuona jinsi msimbo mchache unavyohitajika mara tu ufikiaji wa raw client unapopatikana.

Zana maalum zisipopatikana, clients rasmi au zana za msanidi wa kivinjari bado zinaweza kuanzisha vitendo visivyoonekana na kufichua muda wa trafiki iliyosimbwa kwa njia fiche; raw APIs huondoa ucheleweshaji wa UI na kuruhusu operesheni zisizo halali.<sup>[[1]](#references)</sup>

## Msaidizi wa kutisha: mzunguko wa sampuli zisizoonekana

1. Chagua ujumbe wowote wa zamani ulioutuma kwenye gumzo ili mwathiriwa asione kamwe viputo vya "reaction" vikibadilika.
2. Badilishana kati ya emoji inayoonekana na payload tupu ya reaction (iliyowekwa msimbo kama `""` katika WhatsApp protobufs au `--remove` katika signal-cli). Kila utumaji husababisha ack ya kifaa licha ya kutokuwa na mabadiliko ya UI kwa mwathiriwa.
3. Rekodi muda wa kutuma na kila risiti ya uwasilishaji inapowasili. Mzunguko wa 1 Hz kama huu ufuatao hutoa mfululizo wa RTT wa kila kifaa bila kikomo:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Kwa kuwa WhatsApp/Signal hukubali masasisho ya reactions bila kikomo, mshambuliaji hahitaji kamwe kuchapisha maudhui mapya ya gumzo au kuwa na wasiwasi kuhusu muda wa kufanya edit.<sup>[[1]](#references)</sup>

## Mgeni wa kutisha: kuchunguza nambari za simu kiholela

1. Sajili akaunti mpya ya WhatsApp/Signal na upate identity keys za umma za nambari lengwa (hufanyika kiotomatiki wakati wa kusanidi session).
2. Tengeneza reaction packet inayorejelea `message_id` ya nasibu ambayo haijawahi kuonekana na upande wowote; karatasi ya utafiti inaripoti kuwa WhatsApp na Signal zote hukubali reactions kama hizo na bado hutengeneza delivery receipts.<sup>[[1]](#references)</sup>
3. Tuma packet hiyo hata kama hakuna thread. Vifaa vya mwathiriwa hu-decrypt packet, hushindwa kulinganisha ujumbe msingi, hutupa mabadiliko ya state, lakini bado huthibitisha kupokea ciphertext inayoingia kwa kutuma device receipts kwa mshambuliaji.
4. Rudia mchakato huo mfululizo ili kujenga mfululizo wa RTT bila mazungumzo ya awali au notification inayoonekana.<sup>[[1]](#references)</sup>

Ikiwa kwanza unahitaji kugundua ni nambari zipi zimesajiliwa au unataka kujaza mapema orodha za vifaa kwa kiwango kikubwa, unganisha mbinu hii na [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) badala ya kubahatisha safu za E.164 kwa mkono.

Utafiti uliochapishwa kuhusu contact-discovery ulionyesha umuhimu wa hili kiutendaji: kwa kutumia majedwali sahihi ya viambishi vya nambari za simu na rasilimali za wastani, watafiti waliweza kuuliza takriban `10%` ya nambari za simu za mkononi za Marekani kwenye WhatsApp na `100%` kwenye Signal kabla ya kuendelea na uchunguzi lengwa.<sup>[[11]](#references)</sup> Kwa vitendo, kuchuja akaunti zinazotumika kwanza hufanya bajeti yako ya silent-probe ilenge nambari ambazo kwa hakika zita-decrypt packets.

Miundo ya hivi karibuni ya WhatsApp pia ina chaguo la `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Ichukulie kama kizuizi cha throughput: nyaraka za tracker zinasema WhatsApp huzuia ujumbe mwingi kutoka kwa akaunti zisizojulikana lakini haifichui kiwango cha juu, kwa hiyo haizuii kabisa probe reactions.<sup>[[8]](#references)</sup>

## Kutumia tena edits na deletes kama vichochezi fiche

* **Deletes zinazorudiwa:** Baada ya ujumbe kufutwa kwa kila mtu mara moja, delete packets zaidi zinazorejelea `message_id` hiyo hiyo hazina athari kwenye UI, lakini kila kifaa bado huzidecrypt na kuzithibitisha.
* **Operesheni nje ya muda unaoruhusiwa:** WhatsApp hutekeleza vipindi vya takriban saa 60 vya delete / dakika 20 vya edit kwenye UI; Signal hutekeleza takriban saa 48. Ujumbe wa protocol uliotengenezwa nje ya vipindi hivi hupuuzwa kimyakimya kwenye kifaa cha mwathiriwa, lakini receipts hutumwa, hivyo washambuliaji wanaweza kuendelea kuchunguza kwa muda usio na kikomo baada ya mazungumzo kumalizika.
* **Payloads zisizo sahihi:** Karatasi ya utafiti inaripoti kuwa ujumbe usio sahihi bado unaweza kuthibitishwa; tabia kamili kwa bodies zilizoharibika au IDs zilizofutwa inategemea utekelezaji, kwa hiyo jaribu kabla ya kuitegemea.<sup>[[1]](#references)</sup>

## Uongezaji wa athari kwenye vifaa vingi na fingerprinting

* Kwenye WhatsApp na Signal, kila kifaa kinachohusishwa (simu, desktop app, browser companion) hu-decrypt probe kivyake na kurudisha ack yake. Kuhesabu receipts kwa kila probe hufichua idadi kamili ya vifaa.<sup>[[1]](#references)</sup>
* Kifaa kikiwa offline, receipt yake huwekwa kwenye foleni na kutumwa kinapounganishwa tena. Kwa hiyo, mapengo hufichua mizunguko ya kuwa online/offline na hata ratiba za safari za kila siku (kwa mfano, receipts za desktop hukoma wakati wa safari).
* Usambazaji wa RTT hutofautiana kulingana na platform na mazingira kwa sababu OS, model, client na hali ya mtandao huathiri muda. Panga RTT katika makundi (kwa mfano, k-means inayotumia vipengele vya median/variance) ili kutambua “Android handset”, “iOS handset”, “Electron desktop”, n.k.
* Kwa kuwa mtumaji lazima apate orodha ya recipient’s key inventory kabla ya kusimba ujumbe, mshambuliaji anaweza pia kufuatilia wakati vifaa vipya vinapooanishwa; ongezeko la ghafla la idadi ya vifaa au kundi jipya la RTT ni kiashiria kikubwa.<sup>[[1]](#references)</sup>

**Fanya fingerprinting kwa kutumia receipts zilizowekwa kwenye foleni:** Tuma probes kadhaa zenye message IDs tofauti kifaa lengwa kikiwa offline. Kinapounganishwa tena, linganisha IDs kwenye delivery receipts zilizorudishwa na uangalie kama ni receipts tofauti au zimeunganishwa kwenye receipt moja, na kama IDs zilizounganishwa zinahifadhi au kubadilisha mpangilio wa utumaji. Kwenye clients zilizojaribiwa, WhatsApp Android/iOS zilirudisha delivery receipts tofauti, ilhali Web, Windows na macOS zilizijumuisha pamoja; macOS ilibadilisha mpangilio wa IDs zilizojumuishwa. Signal Desktop ilijumuisha receipts, tofauti na clients zake za simu. Hii inaweza kutambua client inayounganishwa tena hata wakati usambazaji wa RTT unafanana. Usichanganye delivery receipts na read receipts, ambazo kanuni zake za kuziunganisha ni tofauti.<sup>[[1]](#references)</sup>

Kwa probe tofauti ya WhatsApp inayosoma **server-side prekey refills** bila kupeleka ujumbe, angalia [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md).

## Muda wa uchukuaji wa sampuli, foleni, na receipts zilizounganishwa

* **Uvumilivu wa WhatsApp kwa bursts:** Vipimo vilivyochapishwa viliripoti kuwa WhatsApp ilikubali bursts za silent-reaction kwa kasi ya probe moja kila `50 ms` bila foleni dhahiri upande wa server. Hii inafaa kwa bursts fupi za calibration, kuhesabu vifaa haraka, au kuongeza kasi ya drain attack.
* **Foleni za muda mrefu za Signal:** Signal ilivumilia bursts fupi lakini ilianza kuweka kwenye foleni trafiki endelevu ya probes nyingi kwa sekunde. Kwa ufuatiliaji wa muda mrefu, weka cadence karibu na `1 Hz` (au chini) ili kila receipt iakisi hali ya sasa ya kifaa badala ya foleni inayomalizwa.
* **Athari za kuunganishwa tena:** Kifaa kinaporudi online, baadhi ya clients huweka pamoja au hutuma kwa kasi receipts kadhaa zilizochelewa. Zichukulie bursts hizo za receipts kama alama ya mabadiliko ya hali badala ya sampuli huru za RTT, la sivyo clustering / classifier yako ya `active` dhidi ya `idle` itajifunza kupita kiasi kutokana na kelele za kuunganishwa tena.<sup>[[1]](#references)</sup>

## Kukisia tabia kutoka kwa RTT traces

1. Chukua sampuli kwa ≥1 Hz ili kunasa athari za upangaji wa kazi za OS. Kwa WhatsApp kwenye iOS, RTT za <1 s zinahusiana sana na skrini kuwashwa/app kuwa mbele, na RTT za >1 s zinahusiana na skrini kuzimwa/app kuwa nyuma ya pazia na kupunguzwa kasi.
2. Jenga classifiers rahisi (kwa kutumia thresholds au two-cluster k-means) zinazoweka kila RTT kwenye kundi la "active" au "idle". Kusanya lebo hizo katika mfululizo ili kubaini nyakati za kulala, safari za kila siku, saa za kazi, au wakati desktop companion inatumika.
3. Linganisha probes zinazotumwa kwa wakati mmoja kwa kila kifaa ili kuona watumiaji wanapobadilika kutoka simu kwenda desktop, companions zinapokuwa offline, na kama app inadhibitiwa kasi na push au persistent socket.
4. Kwenye mitandao halisi, epuka threshold moja isiyobadilika ya `1 s`. Anzisha kila kifaa kwa kipindi kifupi cha warm-up na tumia baseline inayosasishwa kila mara (kwa mfano, device-activity-tracker PoC hutumia `threshold = 0.9 * median RTT`) ili mabadiliko ya Wi-Fi/cellular yasivuruge classifier yako.<sup>[[1]](#references)[[8]](#references)</sup>

## Kukisia eneo kutoka kwa delivery RTT

Mbinu hii hii ya kupima muda inaweza kutumiwa tena kukisia aliko recipient, si tu kama yuko active. Utafiti wa `Hope of Delivery` ulionyesha kuwa mafunzo yanayotumia usambazaji wa RTT wa maeneo yanayojulikana ya wapokeaji humwezesha mshambuliaji baadaye kuainisha eneo la mwathiriwa kwa kutumia delivery confirmations pekee:<sup>[[2]](#references)</sup>

* Tengeneza baseline ya target yuleyule akiwa katika maeneo kadhaa yanayojulikana (nyumbani, ofisini, chuoni, nchi A dhidi ya nchi B, n.k.).
* Kwa kila eneo, kusanya RTT nyingi za kawaida za ujumbe na utoe features rahisi kama median, variance, au percentile buckets.
* Wakati wa attack halisi, linganisha mfululizo mpya wa probe na makundi yaliyofundishwa. Karatasi ya utafiti inaripoti kuwa hata maeneo yaliyo ndani ya jiji moja mara nyingi yanaweza kutofautishwa, kwa usahihi wa `>80%` katika mpangilio wa maeneo 3.
* Hii hufanya kazi vizuri zaidi mshambuliaji anapodhibiti mazingira ya mtumaji na kufanya probes chini ya hali zinazofanana za mtandao, kwa sababu njia inayopimwa inajumuisha mtandao wa ufikiaji wa recipient, muda wa kuamshwa kwa kifaa, na miundombinu ya messenger.<sup>[[2]](#references)</sup>

Tofauti na mashambulizi ya silent reaction/edit/delete yaliyoelezwa hapo juu, kukisia eneo hakuhitaji message IDs zisizo sahihi au packets fiche zinazobadilisha state. Ujumbe wa kawaida wenye delivery confirmations za kawaida unatosha, hivyo kuna tradeoff ya stealth ndogo lakini matumizi mapana zaidi kwenye messengers.

## Kumaliza rasilimali kwa njia fiche

Kwa kuwa kila silent probe lazima idecryptiwe na kuthibitishwa, kutuma reaction toggles, edits zisizo sahihi, au packets za delete-for-everyone mfululizo husababisha DoS ya application-layer:<sup>[[1]](#references)</sup>

* Hulazimisha radio/modem kutuma/kupokea kila sekunde → betri huisha kwa kiwango kinachoonekana, hasa kwenye simu zisizotumika.
* Hutengeneza trafiki ya upstream/downstream inayotumia data ya simu na inaweza kushindana na vipengele vinavyohitaji latency ndogo kama simu za video.<sup>[[1]](#references)</sup>
* Payloads kubwa zisizo sahihi huongeza kazi ya uchakataji, lakini karatasi ya utafiti inaripoti kuwa cryptography yenyewe hutumia sehemu ndogo sana ya betri.<sup>[[1]](#references)</sup>
* Kwenye WhatsApp, reactions zisizo sahihi hukubali data nyingi zaidi kuliko emoji ya kawaida inavyoweza kudokeza: vipimo vilivyochapishwa vilipata kukubaliwa upande wa server hadi takriban `1 MB` kwa reaction.
* Reactions kubwa kupita kiasi huacha kutoa delivery receipts za kuaminika body inapozidi takriban `30 bytes`, lakini bado hutumwa na kuchakatwa kabla ya kutupwa. Weka reaction bodies ndogo unapohitaji ACKs; zikuze tu lengo linapokuwa kumaliza rasilimali pekee au usafirishaji fiche wa njia moja.
* Vipimo vya umma vilifikia takriban `3.7 MB/s` (`~13.3 GB/h`) ya trafiki ya mwathiriwa kwa kutumia mbinu hii.



## References

- [1] [Careless Whisper: Kutumia Vibaya Silent Delivery Receipts Kufuatilia Watumiaji kwenye Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Kutoa Maeneo ya Watumiaji kutoka kwa Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [ukurasa wa mwongozo wa signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Jinsi ya kuzuia idadi kubwa ya ujumbe usiojulikana | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [Nambari Zote ni za Marekani: Matumizi Mabaya ya Kiwango Kikubwa ya Contact Discovery kwenye Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
