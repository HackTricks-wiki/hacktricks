# Mbinu za Kuficha Asili ya Miamala ya Kifedha

Faragha ya malipo ni tatizo la kubaini mhusika, si tatizo la chapa ya malipo. Operesheni huacha ushahidi wakati thamani inapopatikana, kuhamishwa, kubadilishwa, kutumiwa na kukabidhiwa. Anwani ya public-chain inaweza kuwa ya jina bandia, huku exchange, mtoa kadi, merchant, kifaa cha simu au kamera ya usafirishaji ikimtambulisha mtu aliye nyuma yake.

Ukurasa huu unaeleza mifumo ya kuficha asili ya fedha inayotumiwa katika uhalifu wa mtandao na operesheni zinazohusishwa na mataifa, ili walinzi waweze kuitambua. **Hautoi utaratibu wa laundering, kukwepa sanctions, kutumia utambulisho wa uongo au kukwepa KYC.**

## Grafu ya thamani kutoka mwanzo hadi mwisho
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Mhusika hujaribu kuzuia mwangalizi yeyote kuona ncha zote mbili. Wachunguzi hufanya kinyume chake: huhifadhi rekodi katika kila mpaka, kusawazisha muda/thamani/ada na kutambua **reconvergence point** ambapo personas tofauti hutumia tena facilitator, kifaa, akaunti, merchant au destination mmoja.

## Instruments na observers wao halisi

| Instrument | Iliyofichwa kutoka kwa merchant/public | Bado inaonekana kwa |
|---|---|---|
| Issuer virtual card/token | nambari ya msingi ya kadi | issuer, network/token provider, wallet, merchant account na delivery systems |
| Prepaid/gift value | wakati mwingine jina halali kwenye ununuzi wa kawaida | retailer/payment rail, activation/redemption service, cameras, kifaa na delivery |
| Cash | public ledger na remote issuer | counterparties, cameras, withdrawal/serial controls inapohusika, physical search |
| Bitcoin/new address | jina halali la moja kwa moja | kila blockchain observer; wallet/network peers; acquisition/off-ramp services |
| CoinJoin/PayJoin | simple common-input/payment heuristics | public transaction, coordinator/peer/network metadata na tabia ya matumizi ya baadaye |
| Privacy coin | public sender/receiver/amount, kulingana na protocol | acquisition/off-ramp, wallet endpoint, network observer na counterparty |
| Centralized mixer | direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets na counterparties |
| Cross-chain bridge/swap | continuity kwenye chain moja | chains zote mbili, bridge/swap service, timing/value na liquidity constraints |
| OTC/P2P broker | direct exchange account katika baadhi ya hali | broker, communications, bank/cash movement, counterparties na devices |

## Cards, prepaid value, nominees na mules

### Virtual na masked cards

Issuer anaweza kuunda merchant-locked au disposable card number. Hii hupunguza merchant exposure na matumizi tena ya nambari kati ya merchants. Issuer bado huihusisha na customer, funding account, kifaa, IP na transaction. Billing descriptors, merchant account, shipping address na browser data hubaki zinaweza kuunganishwa.

Uuzaji wa kadi za “No-name” haumaanishi anonymous settlement. Issuers na distributors wanaodhibitiwa wanaweza kufanya identity checks, kuhifadhi rekodi, kuweka geography/amount limits na kujibu legal process. Kadi iliyopatikana kupitia stolen identity huongeza identity theft; haiondoi issuer/device/merchant telemetry.

### Prepaid na gift value

Prepaid cards na gift codes hutenganisha redemption ya baadaye na payment instrument ya awali, lakini huunda kitu chenye nambari pamoja na matukio ya ununuzi, activation, balance-query na redemption. Mifumo muhimu ni pamoja na ununuzi wa kiasi kikubwa, kurudiwa kwa denominations zilizo chini kidogo ya controls, redemption ya haraka katika eneo la mbali, kifaa kimoja kuangalia balances nyingi, au cards nyingi kuishia kwenye merchant/account moja.

### Nominees, money mules na merchant fronts

Nominee au mule hutoa akaunti na utambulisho halali unaokaa kati ya operator na service. Networks zinaweza kuweka tabaka za recruiters, account holders, payment processors, shell merchants na cash-out brokers. Hii huunda umbali, lakini kila mshiriki huongeza communications, fees, kutolingana kwa tabia na shahidi anayeweza kushirikiana. Front companies huongeza rekodi za incorporation, tax, banking, director, invoice, hosting na shipment.

Defenders wanapaswa kuchunguza shared devices/IPs, beneficiary reuse, geolocation contradictions, velocity isiyolingana na historia ya akaunti, circular transfers, senders wengi wasiohusiana wanaoishia pamoja, na onward movement ya haraka. Usidhani kwamba account holder aliyepewa jina ndiye actor anayesimamia; mchukulie kama node inayohitaji role determination.

## Public-chain transaction-obfuscation patterns

### Address rotation na coin control

Kuunda address mpya kwa kila receipt huzuia address reuse iliyo wazi, lakini transactions bado zinaweza kuhusishwa kupitia common inputs, change detection, exact value/time na consolidation ya baadaye. **Coin control** huwezesha wallet kuchagua outputs za kutumia na kuepuka kuunganisha compartments. Huboresha hygiene; haiwezi kuondoa link ambayo tayari iko public.

### Peel chains

Peel chain hutumia balance kubwa mara kwa mara, ikituma kiasi kidogo nje na kurudisha salio lililosalia kwenye address mpya:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Anwani hubadilika katika kila hatua, lakini mwendelezo wa thamani, mpangilio wa muda na muundo wa miamala mara nyingi huunda chain inayotambulika. Hot wallets halali za exchange zinaweza kufanya vivyo hivyo, kwa hiyo attribution inahitaji ushahidi wa huduma/context. DOJ imetumia uchanganuzi wa peel-chain katika kesi za forfeiture zinazohusishwa na DPRK.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** chanzo kimoja hugawanya fedha kwenye anwani nyingi ili kuongeza mzigo wa uchunguzi au kuandaa conversion zinazofanyika sambamba.
- **Fan-in:** vyanzo vingi hujumuika kwenye collector mmoja, jambo linalofichua control ya pamoja au huduma.
- **Structuring:** transfers ndogo zinazorudiwa hulenga kuepuka viwango vya ukaguzi au kuchanganyika na volume ya kawaida.
- **Commingling:** fedha haramu na fedha zisizohusiana hushiriki wallets, pools au services, hivyo kufanya madai rahisi ya mgao kuwa si salama.

Muundo wa graph ni lead, si uthibitisho. Analysts wanapaswa kuzingatia fees, UTXO/account model, tabia ya service na kanuni za change.

### CoinJoin and PayJoin

Katika CoinJoin ya kawaida, washiriki kadhaa huchangia inputs na kupokea outputs katika transaction shirikishi moja, mara nyingi zikiwa na denominations sawa za output. Hii huvunja dhana kwamba kila input na output katika transaction ina owner mmoja. Anonymity set ina mipaka inayowekwa na idadi ya washiriki na tabia ya baadaye: change isiyo sawa, toxic change, consolidation au kuvuka service inayojulikana kunaweza kurejesha links.

PayJoin hubadilisha payment ya kawaida ili payer na payee wote wachangie inputs, jambo linalobatilisha moja kwa moja common-input ownership heuristic kwa transaction hiyo. Kimsingi ni payment privacy protocol, si bulk laundering service. Detection inapaswa kuepuka kutangaza kwamba inputs zote zina owner mmoja na inapaswa kuonyesha uncertainty badala ya kulazimisha cluster ya uongo.

### Centralized mixers and tumblers

Centralized mixer hupokea deposits na baadaye hulipa coins tofauti kutoka kwenye pooled reserve, mara nyingi baada ya fees na delays. Privacy yake inategemea ukubwa wa pool, withdrawal policy, logs, uaminifu wa operator na uwezo wa kustahimili seizure. Uchambuzi wa muda/thamani wa entry na exit, deposit addresses, service wallet clustering na records unaweza kupunguza seti ya uwezekano. Operators wanaweza kuiba fedha au kuhifadhi mapping kamili.

Mfiduo wa kisheria ni mkubwa na hutofautiana kulingana na jurisdiction. Kesi za DOJ dhidi ya ChipMixer, Samourai Wallet na developers/operators wa Tornado Cash, pamoja na litigation inayobadilika kuhusu sanctions, zinaonyesha kwamba facts za protocol, custody, control na money-transmission ni muhimu; lebo kama “decentralized” si hitimisho la kisheria.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Chain hopping hubadilisha asset au kuihamisha kupitia bridge, hivyo kuvunja query ya ledger moja lakini si continuity ya kiuchumi:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Wachambuzi huhusianisha bridge contracts/service deposit addresses, mpangilio wa miamala, muda, exchange rate, fees, liquidity na unique amount. Swaps zinazorudiwa zinaweza kuongeza utata huku zikiongeza telemetry ya provider/API/wallet. FATF hutambua chain hopping, mixers, huduma za peer-to-peer na currencies zilizoimarishwa kwa anonymity kama viashiria vya hatari zinapounganishwa na muktadha wa kutiliwa shaka.<sup>[[3]](#references)</sup>

### NFTs, gambling na manunuzi ya merchant

Miamala ya NFT ya kujinunulia au ya kushirikiana inaweza kuzipa fedha simulizi la mauzo linaloonekana kuwa halali; gambling inaweza kubadilisha deposits kuwa withdrawals; bidhaa zinaweza kubadilisha thamani ya kidijitali kuwa inventory inayoweza kuuzwa tena. Njia hizi huacha marketplace accounts, creator/royalty links, wash-trading graphs, odds/play history, device logs, delivery na resale evidence. Hasara au fee si uthibitisho kwamba provenance ilitoweka.

## Cryptocurrencies zinazohifadhi faragha

Privacy protocols hutofautiana kitaalamu:

- **Monero** hutumia one-time addresses, ring signatures na confidential amounts, hivyo kupunguza uonekano wa hadharani wa sender/receiver/amount. Network observation, wallet compromise, acquisition/off-ramp na counterparty records hubaki nje ya ulinzi huo wa on-chain.
- **Zcash shielded pools** zinaweza kuficha sender, receiver na amount wakati shielded transactions zinapotumika; transparent addresses na mabadiliko kati ya pools hubaki hadharani, na matumizi huathiri anonymity set inayofanya kazi.
- **Bitcoin** huwa transparent kwa default. New addresses, CoinJoin, PayJoin na Lightning hubadilisha assumptions fulani za linkage, lakini hazifanyi layers zote kuwa private.

Privacy technology ina matumizi halali ya usalama na kibiashara. Kwa mtazamo wa uchunguzi, ledger inapotoa taarifa chache, endpoint, service, network na human evidence huwa muhimu zaidi. Usihitimishe kamwe uhalifu kutokana na uchaguzi wa privacy-preserving protocol pekee.

## DPRK multi-layer case model

Madai ya hadharani ya DOJ na hatua za forfeiture yanaeleza mchakato ulioundwa na hatua kadhaa, si ujanja mmoja:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. workers walitumia nyaraka za utambulisho za kubuniwa/kuba, pamoja na VPNs, kupata ajira za remote;
2. employers walilipa cryptocurrency, ikiwemo stablecoins;
3. fedha zilisogezwa kwa amounts ndogo, zikavuka chains au tokens, zikanunua NFTs au zikachanganywa na fedha nyingine;
4. fedha nyingine zilizoibwa ziliingizwa kwenye mixers;
5. OTC traders na front companies zilibadilisha thamani kuwa malipo ya fiat au bidhaa;
6. facilitators, accounts na blockchain paths zilizorudiwa ziliwawezesha wachunguzi kuunganisha tena layers hizo.

Treasury ilisema Lazarus alitumia Blender.io kuchakata sehemu ya wizi wa Axie Infinity/Ronin, huku FBI ikiwa imechapisha addresses na kuhimiza bridges, exchanges, RPC operators na analytics firms kuzuia fedha zinazohusishwa na wizi wa baadaye wa TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Somo ni la pande mbili: state actors hutumia commercial/criminal services za kawaida, na public blockchains huwawezesha defenders kufuatilia thamani hata majina yasipojulikana mwanzoni.

## Detection workflow

1. **Hifadhi transaction identifiers na records ghafi.** Screenshots na fiat values zilizozungushwa hazitoshi.
2. **Sawazisha assets na muda.** Rekodi chain, token contract, units, block time, service time zone, fees na chanzo cha exchange-rate.
3. **Weka alama ya confidence ya evidence.** Tofautisha address iliyochapishwa na service, contract event ya deterministic, clustering heuristic na external intelligence.
4. **Fuatilia pande zote mbili.** Tafuta funding origin, immediate dispersal, reconvergence, bridge exits, service deposits na spend/delivery.
5. **Unganisha off-chain evidence.** Account KYC, device, IP, support tickets, API keys, bank/payment, shipping na communication records mara nyingi hutatua utata.
6. **Jaribu maelezo mbadala.** Exchanges, custodians, payroll na privacy protocols zinaweza kuunda fan-in/out au co-spends bila common beneficial ownership.
7. **Fuatilia badala ya kufunga mapema.** Dormant output inaweza kuhusishwa na mhusika inapofikia service baadaye.
8. **Tekeleza wajibu wa sasa wa sanctions/AML kwa ushauri wa counsel.** Rules na designations hubadilika; historical association si mbadala wa current legal analysis.

## Safe red-team procurement model

Timu iliyoidhinishwa inaweza kuhitaji target SOC isitambue hosting payment yake, huku engagement controller akibaki na accountability:

- tumia engagement-specific organization card au documented corporate wallet;
- weka billing, tax na provider records zikiwa sahihi;
- mtenganishe operator na procurement duties na punguza access ya attribution map;
- usitumie mule, false identity, stolen card, sanctions workaround au unlicensed exchanger kamwe;
- rekodi asset, amount, owner, service, date, refund path na teardown evidence;
- baada ya zoezi, mfichulie controller payment/provider indicators husika.

Hii huunda **blindness kwa mshiriki wa zoezi**, si blindness kwa sheria, provider au governance.

## References

- [1] [US DOJ — Mfumo wa Utekelezaji wa Cryptocurrency (mfano wa peel-chain na uchunguzi wa DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Uporaji wa ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Viashiria vya Hatari vya Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Mwakilishi wa Foreign Trade Bank wa DPRK ashtakiwa katika njama za crypto-laundering](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Malalamiko ya forfeiture kuhusu $7.74 milioni yanayodaiwa kulaunderiwa kwa ajili ya DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Sanctions za Blender.io na fedha za Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Korea Kaskazini inawajibika kwa wizi wa Bybit wa 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Matumizi ya regulations kwa watumiaji, administrators na exchangers wa virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
