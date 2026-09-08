# Mbinu za Kuficha Asili ya Fedha

{{#include ../banners/hacktricks-training.md}}

Faragha ya malipo ni tatizo la kubaini mhusika, si tatizo la chapa ya malipo. Operesheni huacha ushahidi wakati thamani inapopatikana, kuhamishwa, kubadilishwa, kutumika na kuwasilishwa. Anwani ya public-chain inaweza kutumia jina bandia, huku exchange, mtoa kadi, mfanyabiashara, kifaa cha rununu au kamera ya usafirishaji ikimtambua mtu aliye nyuma yake.

Ukurasa huu unaeleza mifumo ya kuficha asili ya fedha inayotumiwa katika uhalifu wa mtandao na operesheni zinazohusishwa na mataifa, ili walinzi waweze kuitambua. **HautoI utaratibu wa money laundering, kukwepa sanctions, kutumia utambulisho bandia au kukwepa KYC.**

## Mchoro wa thamani wa mwanzo hadi mwisho
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Mhusika hujaribu kuzuia mwangalizi yeyote kuona ncha zote mbili. Wachunguzi hufanya kinyume: huhifadhi rekodi katika kila mpaka, kusawazisha muda/thamani/ada na kutambua **reconvergence point** ambapo personas tofauti hutumia tena facilitator, kifaa, akaunti, merchant au destination mmoja.

## Instruments na waangalizi wao halisi

| Instrument | Iliyofichwa kutoka kwa merchant/public | Bado inaonekana kwa |
|---|---|---|
| Issuer virtual card/token | nambari ya msingi ya kadi | issuer, network/token provider, wallet, merchant account na delivery systems |
| Prepaid/gift value | wakati mwingine jina halali katika ununuzi wa kawaida | retailer/payment rail, activation/redemption service, cameras, kifaa na delivery |
| Cash | public ledger na remote issuer | counterparties, cameras, withdrawal/serial controls inapohusika, physical search |
| Bitcoin/new address | jina halali la moja kwa moja | kila blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | simple common-input/payment heuristics | public transaction, coordinator/peer/network metadata na tabia ya matumizi ya baadaye |
| Privacy coin | public sender/receiver/amount, kulingana na protocol | acquisition/off-ramp, wallet endpoint, network observer na counterparty |
| Centralized mixer | direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets na counterparties |
| Cross-chain bridge/swap | continuity kwenye chain moja | chains zote mbili, bridge/swap service, timing/value na liquidity constraints |
| OTC/P2P broker | direct exchange account katika baadhi ya hali | broker, communications, bank/cash movement, counterparties na devices |

## Cards, prepaid value, nominees na mules

### Virtual na masked cards

Issuer anaweza kuunda nambari ya kadi iliyofungwa kwa merchant au ya matumizi ya mara moja. Hii hupunguza merchant exposure na matumizi tena ya nambari hiyo kwa merchants mbalimbali. Issuer bado huihusisha na mteja, funding account, kifaa, IP na transaction. Billing descriptors, merchant account, shipping address na browser data bado vinaweza kuunganishwa.

Uuzaji wa kadi za “No-name” haumaanishi anonymous settlement. Issuers na distributors waliodhibitiwa wanaweza kufanya identity checks, kuhifadhi records, kuweka geography/amount limits na kujibu legal process. Kadi iliyopatikana kupitia stolen identity inaongeza identity theft; haiondoi issuer/device/merchant telemetry.

### Prepaid na gift value

Prepaid cards na gift codes hutenganisha redemption ya baadaye na payment instrument ya awali, lakini huunda kitu chenye nambari na matukio ya ununuzi, activation, balance-query na redemption. Mifumo yenye umuhimu ni pamoja na ununuzi wa wingi, kurudiwa kwa denomination iliyo chini kidogo ya controls, redemption ya haraka katika eneo la mbali, kifaa kimoja kuangalia balances nyingi, au cards nyingi kuungana kwenye merchant/account moja.

### Nominees, money mules na merchant fronts

Nominee au mule hutoa akaunti na identity halali inayokaa kati ya operator na service. Networks zinaweza kuweka tabaka za recruiters, account holders, payment processors, shell merchants na cash-out brokers. Hii huongeza umbali, lakini kila mshiriki huongeza mawasiliano, ada, kutokulingana kwa tabia na uwezekano wa kuwa shahidi anayeshirikiana. Front companies huongeza records za incorporation, tax, banking, director, invoice, hosting na shipment.

Defenders wanapaswa kuchunguza shared devices/IPs, beneficiary reuse, migongano ya geolocation, velocity isiyolingana na historia ya akaunti, circular transfers, senders wengi wasiohusiana wanaoungana, na onward movement ya mara moja. Usidhani kuwa named account holder ndiye actor anayedhibiti; mchukulie kama node inayohitaji role determination.

## Public-chain transaction-obfuscation patterns

### Address rotation na coin control

Kuunda address mpya kwa kila receipt huzuia address reuse iliyo rahisi, lakini transactions bado zinaweza kuhusishwa kupitia common inputs, change detection, exact value/time na consolidation ya baadaye. **Coin control** huwezesha wallet kuchagua outputs zipi itumie na kuepuka kuunganisha compartments. Huboresha hygiene; haiwezi kuondoa link ambayo tayari iko public.

### Peel chains

Peel chain hutumia balance kubwa mara kwa mara, ikituma kiasi kidogo outward na kurudisha salio lililosalia kwenye address mpya:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Anwani hubadilika katika kila hatua, lakini mwendelezo wa thamani, mpangilio wa muda na muundo wa transaction mara nyingi huunda chain inayotambulika. Hot wallets halali za exchange zinaweza kufanya vivyo hivyo, hivyo attribution inahitaji ushahidi wa service/context. DOJ imetumia uchanganuzi wa peel-chain katika kesi za forfeiture zinazohusishwa na DPRK.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** chanzo kimoja hugawanya fedha kwenye anwani nyingi ili kuongeza mzigo wa uchunguzi au kuandaa conversion za sambamba.
- **Fan-in:** vyanzo vingi hujumuishwa katika collector mmoja, hivyo kufichua udhibiti wa pamoja au service.
- **Structuring:** transfers ndogo zinazorudiwa hulenga kuepuka viwango vya ukaguzi au kuchanganyika na volume ya kawaida.
- **Commingling:** fedha zisizo halali na fedha zisizohusiana hushiriki wallets, pools au services, jambo linalofanya madai rahisi ya uwiano kuwa yasiyo salama.

Umbo la graph ni lead, si uthibitisho. Analysts wanapaswa kuzingatia fees, UTXO/account model, tabia ya service na kanuni za change.

### CoinJoin and PayJoin

Katika CoinJoin ya kawaida, washiriki kadhaa huchangia inputs na kupokea outputs katika transaction moja ya ushirikiano, mara nyingi zikiwa na denominations zinazolingana. Hii huvunja dhana kwamba kila input na output katika transaction ina owner mmoja. Anonymity set inawekewa mipaka na idadi ya washiriki na tabia ya baadaye: change isiyolingana, toxic change, consolidation au kuvuka service inayojulikana kunaweza kuanzisha tena links.

PayJoin hubadilisha payment ya kawaida ili payer na payee wote wachangie inputs, hivyo kubatilisha moja kwa moja heuristic ya common-input ownership kwa transaction hiyo. Kimsingi ni protocol ya payment privacy, si service ya bulk laundering. Detection inapaswa kuepuka kutangaza kwamba inputs zote zina owner mmoja, na inapaswa kueleza uncertainty badala ya kulazimisha cluster ya uwongo.

### Centralized mixers and tumblers

Centralized mixer hupokea deposits na baadaye hulipa coins tofauti kutoka kwenye reserve iliyounganishwa, mara nyingi baada ya fees na delays. Privacy yake hutegemea ukubwa wa pool, withdrawal policy, logs, uaminifu wa operator na uwezo wa kupinga seizure. Uchambuzi wa muda/value wa entry na exit, deposit addresses, clustering ya service wallets na records vinaweza kupunguza seti hiyo. Operators wanaweza kuiba fedha au kuhifadhi mapping kamili.

Mfiduo wa kisheria ni mkubwa na hutegemea jurisdiction. Kesi za DOJ dhidi ya ChipMixer, Samourai Wallet na developers/operators wa Tornado Cash, pamoja na litigation inayobadilika kuhusu sanctions, zinaonyesha kwamba facts za protocol, custody, control na money-transmission ni muhimu; label kama “decentralized” si hitimisho la kisheria.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping hubadilisha asset au kuihamisha kupitia bridge, hivyo kuvunja query ya ledger moja lakini si mwendelezo wa kiuchumi:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Wachambuzi huhusisha mikataba ya bridge/anwani za kuweka fedha za huduma, mpangilio wa miamala, muda, kiwango cha ubadilishaji, ada, liquidity na kiasi cha kipekee. Swaps zinazorudiwa zinaweza kuongeza utata huku zikiongeza telemetry ya provider/API/wallet. FATF hutambua chain hopping, mixers, huduma za peer-to-peer na sarafu zinazoongeza anonymity kama viashiria vya hatari zinapochanganywa na muktadha wa kutiliwa shaka.<sup>[[3]](#references)</sup>

### NFTs, kamari na ununuzi wa wafanyabiashara

Biashara za NFT za kujinunulia au za kula njama zinaweza kuzipa fedha simulizi linaloonekana la mauzo; kamari inaweza kubadilisha deposits kuwa withdrawals; bidhaa zinaweza kubadilisha thamani ya kidijitali kuwa inventory inayoweza kuuzwa tena. Njia hizi huacha akaunti za marketplace, viungo vya creator/royalty, grafu za wash trading, odds/history ya michezo, logs za kifaa, ushahidi wa delivery na wa kuuza tena. Hasara au ada si uthibitisho kwamba chanzo cha fedha kilitoweka.

## Sarafu za cryptocurrency zinazolinda privacy

Privacy protocols hutofautiana kitaalamu:

- **Monero** hutumia anwani za matumizi ya mara moja, ring signatures na kiasi cha siri, hivyo kupunguza uonekano wa wazi wa mtumaji/mpokeaji/kiasi. Ufuatiliaji wa mtandao, kuvunjwa kwa usalama wa wallet, acquisition/off-ramp na rekodi za counterparty hubaki nje ya ulinzi huo wa on-chain.
- **Zcash shielded pools** zinaweza kuficha mtumaji, mpokeaji na kiasi pale shielded transactions zinapotumika; anwani za uwazi na mabadiliko kati ya pools hubaki hadharani, na mifumo ya matumizi huathiri ukubwa halisi wa anonymity set.
- **Bitcoin** huwa transparent kwa default. Anwani mpya, CoinJoin, PayJoin na Lightning hubadilisha dhana fulani za kuunganisha miamala, lakini hazifanyi layers zote kuwa private.

Privacy technology ina matumizi halali ya usalama na kibiashara. Kwa mtazamo wa uchunguzi, ledger inapotoa taarifa chache, ushahidi wa endpoint, service, network na binadamu huwa muhimu zaidi. Usihitimishe kamwe kuwa kuna uhalifu kutokana na kuchagua privacy-preserving protocol pekee.

## DPRK multi-layer case model

Madai ya umma ya DOJ na hatua za forfeiture zinaeleza mchakato ulioundwa kwa layers, si ujanja mmoja:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers walitumia nyaraka za utambulisho za kubuniwa/kuibwa na VPNs kupata ajira za remote;
2. waajiri walilipa cryptocurrency, ikiwemo stablecoins;
3. fedha zilisogezwa kwa kiasi kidogo, zikavuka chains au tokens, zikanunua NFTs au kuchanganywa;
4. fedha nyingine zilizoibwa ziliingia kwenye mixers;
5. OTC traders na front companies walibadilisha thamani kuwa malipo ya fiat au bidhaa;
6. facilitators, akaunti na njia za blockchain zilizorudiwa ziliwawezesha wachunguzi kuunganisha tena layers hizo.

Treasury ilisema Lazarus alitumia Blender.io kuchakata sehemu ya wizi wa Axie Infinity/Ronin, huku FBI ikiwa imechapisha anwani na kuhimiza bridges, exchanges, waendeshaji wa RPC na kampuni za analytics kuzuia fedha zinazohusishwa na wizi wa baadaye wa TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Somo ni la pande mbili: state actors hutumia huduma za kawaida za kibiashara/uhalifu, na public blockchains huwawezesha defenders kufuatilia thamani hata majina yanapokuwa hayajulikani mwanzoni.

## Detection workflow

1. **Hifadhi transaction identifiers na rekodi ghafi.** Screenshots na thamani za fiat zilizozungushwa hazitoshi.
2. **Sanifisha assets na muda.** Rekodi chain, token contract, units, muda wa block, time zone ya service, ada na chanzo cha exchange rate.
3. **Weka lebo ya kiwango cha uaminifu wa ushahidi.** Tofautisha anwani iliyochapishwa na service, contract event ya deterministic, clustering heuristic na intelligence ya nje.
4. **Fuatilia pande zote mbili.** Tafuta chanzo cha funding, usambazaji wa mara moja, reconvergence, bridge exits, service deposits na matumizi/delivery.
5. **Unganisha ushahidi wa off-chain.** KYC ya akaunti, kifaa, IP, support tickets, API keys, rekodi za bank/payment, shipping na mawasiliano mara nyingi hutatua utata.
6. **Jaribu maelezo mbadala.** Exchanges, custodians, payroll na privacy protocols zinaweza kutoa fan-in/out au co-spends bila umiliki wa pamoja wa manufaa.
7. **Fuatilia badala ya kufunga mapema.** Output iliyolala inaweza kuhusishwa na mtu au huduma inapofikia service baadaye.
8. **Tumia wajibu wa sasa wa sanctions/AML kwa ushauri wa counsel.** Rules na designations hubadilika; uhusiano wa kihistoria si mbadala wa legal analysis ya sasa.

## Safe red-team procurement model

Timu iliyoidhinishwa inaweza kuhitaji SOC ya target isitambue malipo ya hosting yake, huku engagement controller akibaki na accountability:

- tumia engagement-specific organization card au corporate wallet iliyoandikwa;
- weka billing, tax na provider records kuwa sahihi;
- mtenganishe operator na majukumu ya procurement na punguza access kwenye attribution map;
- usitumie mule, false identity, stolen card, sanctions workaround au exchanger asiye na leseni;
- rekodi asset, amount, owner, service, date, refund path na teardown evidence;
- baada ya exercise, mjulishe controller kuhusu payment/provider indicators husika.

Hii huleta **blindness kwa mshiriki wa exercise**, si blindness kwa sheria, provider au governance.

## References

- [1] [US DOJ — Mfumo wa Utekelezaji wa Cryptocurrency (mfano wa peel-chain na uchunguzi wa DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Uvunjaji wa ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Viashiria vya Hatari vya Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Mwakilishi wa DPRK Foreign Trade Bank akishtakiwa katika njama za crypto-laundering](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Malalamiko ya forfeiture kuhusu $7.74 milioni yanayodaiwa kuoshwa kwa ajili ya DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanctions za Blender.io na fedha za Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Korea Kaskazini inawajibika kwa wizi wa Bybit wa 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Matumizi ya regulations kwa users, administrators na exchangers wa virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
