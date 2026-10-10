# Red Teaming ya Web3 Inayozingatia Thamani (MITRE AADAPT)

{{#include ../../banners/hacktricks-training.md}}

Mfumo wa MITRE Adversarial Actions in Digital Asset Payment Techniques (AADAPT) huainisha vitendo na mbinu za washambuliaji zinazolenga mifumo ya mali za kidijitali.<sup>[[1]](#references)</sup> Uchukulie kama **msingi wa threat modeling**: orodhesha kila kipengele kinachoweza kuunda, kupanga bei, kuidhinisha au kuelekeza mali, husisha sehemu hizo za mawasiliano na mbinu za AADAPT, kisha tengeneza hali za red-team zinazopima ikiwa mazingira yanaweza kuzuia hasara ya kiuchumi isiyoweza kurejeshwa.

## 1. Orodhesha vipengele vinavyobeba thamani
Tengeneza ramani ya kila kitu kinachoweza kuathiri hali ya thamani, hata kama kiko off-chain.<sup>[[2]](#references)</sup>

- **Huduma za utiaji saini za uangalizi** (vikundi vya HSM/KMS, Vault/KMaaS, API za utiaji saini zinazotumiwa na bots au kazi za back-office). Rekodi vitambulisho vya funguo, sera, utambulisho wa automation na michakato ya uidhinishaji.
- **Njia za usimamizi na uboreshaji** wa contracts (wasimamizi wa proxy, governance timelocks, funguo za kusitisha dharura, sajili za vigezo). Jumuisha nani/nini kinaweza kuziita, na kwa quorum au ucheleweshaji upi.
- **Mantiki ya itifaki ya on-chain** inayoshughulikia ukopeshaji, AMMs, vaults, staking, bridges au njia za settlement. Andika invariants inazozitegemea (bei za oracle, uwiano wa dhamana, marudio ya rebalance…).
- **Automation ya off-chain** inayounda transactions (bots za market-making, pipeline za CI/CD, cron jobs, serverless functions). Mara nyingi huwa na API keys au service principals zinazoweza kuomba saini.
- **Oracles na data feeds** (muundo wa aggregator, quorum, viwango vya deviation, marudio ya masasisho). Bainisha kila chanzo cha upstream kinachotegemewa na mantiki ya hatari ya automation.
- **Bridges na routers za cross-chain** (contracts za lock/mint, relayers, kazi za settlement) zinazounganisha chains au mifumo ya uangalizi.

Matokeo yanayohitajika: mchoro wa mtiririko wa thamani unaoonyesha jinsi mali zinavyosogea, nani anayeidhinisha uhamishaji, na ni ishara zipi za nje zinazoathiri mantiki ya biashara.

## 2. Linganisha vipengele na tabia za AADAPT
Tafsiri taksonomia ya AADAPT kuwa watahiniwa halisi wa mashambulizi kwa kila kipengele.<sup>[[2]](#references)</sup>

| Kipengele | Eneo kuu la AADAPT |
| --- | --- |
| Mifumo ya utiaji saini/KMS | Wizi wa credentials, kukwepa sera, matumizi mabaya ya utiaji saini, kutwaa udhibiti wa governance |
| Oracles/feeds | Kuweka sumu kwenye ingizo, kuchezea aggregation, kukwepa viwango vya deviation |
| Itifaki za on-chain | Udanganyifu wa kiuchumi kwa flash-loan, kuvunja invariants, kubadilisha usanidi wa vigezo |
| Pipeline za automation | Utambulisho wa bot/CI uliodukuliwa, kurudia batch, deployment isiyoidhinishwa |
| Bridges/routers | Kukwepa mifumo ya cross-chain, kuficha chanzo cha fedha kwa hop za haraka, kutolingana kwa settlement |

Ulinganisho huu unahakikisha kuwa unajaribu si contracts pekee, bali pia kila utambulisho/automation inayoweza kuelekeza thamani kwa njia isiyo ya moja kwa moja.

## 3. Panga vipaumbele kwa uwezekano wa mshambuliaji kufanikiwa dhidi ya athari kwa biashara

1. **Udhaifu wa kiutendaji**: CI credentials zilizo wazi, majukumu ya IAM yenye ruhusa nyingi kupita kiasi, sera za KMS zilizosanidiwa vibaya, akaunti za automation zinazoweza kuomba saini zozote, buckets za umma zenye usanidi wa bridge, n.k.
2. **Udhaifu mahususi wa thamani**: vigezo dhaifu vya oracle, contracts zinazoweza kuboreshwa bila idhini ya wahusika wengi, liquidity inayoathiriwa na flash-loan, vitendo vya governance vinavyokwepa timelocks.

Shughulikia orodha kama mshambuliaji: anza na njia za kuingia za kiutendaji zinazoweza kufanikiwa leo, kisha endelea kwenye njia changamano za udanganyifu wa itifaki/uchumi.<sup>[[2]](#references)</sup>

## 4. Tekeleza katika mazingira yaliyodhibitiwa yanayofanana na uzalishaji halisi
- **Mainnets zilizoforkiwa / testnets zilizotengwa**: nakili bytecode, storage na liquidity ili njia za flash-loan, mabadiliko ya oracle na mtiririko wa bridge vifanye kazi mwanzo hadi mwisho bila kugusa fedha halisi.<sup>[[2]](#references)</sup>
- **Kupanga ukubwa wa athari**: fafanua circuit breakers, modules zinazoweza kusitishwa, runbooks za rollback na funguo za admin za majaribio kabla ya kuanzisha hali ya majaribio.
- **Uratibu wa wadau**: wajulishe wasimamizi wa mali, waendeshaji wa oracle, washirika wa bridge na timu za compliance ili timu zao za ufuatiliaji zitarajie trafiki hiyo.
- **Idhini ya kisheria**: andika scope, idhini na masharti ya kusitisha pale ambapo simulations zinaweza kufikia mifumo iliyodhibitiwa.

## 5. Telemetry inayolingana na mbinu za AADAPT
Sanidi mikondo ya telemetry ili kila hali ya majaribio itoe data ya ugunduzi inayoweza kuchukuliwa hatua.<sup>[[2]](#references)</sup>

- **Traces za kiwango cha chain**: grafu kamili za miito, matumizi ya gas, nonces za transaction na mihuri ya muda ya block—ili kujenga upya bundles za flash-loan, miundo inayofanana na reentrancy na miito inayovuka contracts.
- **Logs za programu/API**: unganisha kila tx ya on-chain na utambulisho wa mtu au automation (session ID, OAuth client, API key, CI job ID), pamoja na IPs na mbinu za uthibitishaji.
- **Logs za KMS/HSM**: key ID, principal aliyeita, matokeo ya sera, anwani lengwa na misimbo ya sababu kwa kila saini. Weka viwango vya msingi vya muda wa mabadiliko na shughuli zenye hatari kubwa.
- **Metadata ya oracle/feed**: muundo wa chanzo cha data kwa kila sasisho, thamani iliyoripotiwa, tofauti na wastani unaosogea, viwango vilivyochochewa na njia za failover zilizotumika.
- **Traces za bridge/swap**: linganisha matukio ya lock/mint/unlock kwenye chains kwa kutumia correlation IDs, chain IDs, utambulisho wa relayer na muda wa kila hop.
- **Alama za anomaly**: vipimo vilivyotokana kama ongezeko kubwa la slippage, uwiano usio wa kawaida wa dhamana, msongamano wa gas usio wa kawaida au kasi ya cross-chain.

Weka scenario IDs au synthetic user IDs kwenye kila kitu ili wachambuzi waweze kuoanisha vinavyoonekana na mbinu ya AADAPT inayojaribiwa.

## 6. Mzunguko wa purple-team na vipimo vya ukomavu
1. Endesha hali ya majaribio katika mazingira yaliyodhibitiwa na rekodi ugunduzi (alerts, dashboards, responders walioarifiwa).<sup>[[2]](#references)</sup>
2. Linganisha kila hatua na mbinu mahususi za AADAPT pamoja na vinavyoonekana vilivyotolewa kwenye sehemu za chain/app/KMS/oracle/bridge.
3. Tengeneza na tekeleza dhana za ugunduzi (sheria za threshold, utafutaji wa correlation, ukaguzi wa invariants).
4. Rudia hadi muda wa wastani wa kugundua (MTTD) na muda wa wastani wa kudhibiti (MTTC) ufikie viwango vinavyokubalika kwa biashara na playbooks zisitishe kwa uhakika upotevu wa thamani.

Fuatilia ukomavu wa programu kwa vipimo vitatu:<sup>[[2]](#references)</sup>
- **Mwonekano**: kila njia muhimu ya thamani ina telemetry katika kila sehemu.
- **Ufunikaji**: idadi ya mbinu za AADAPT zilizopewa kipaumbele zilizojaribiwa mwanzo hadi mwisho.
- **Mwitikio**: uwezo wa kusitisha contracts, kubatilisha funguo au kusimamisha mtiririko kabla ya hasara isiyoweza kurejeshwa.

Hatua za kawaida: (1) kukamilisha orodha ya thamani na ulinganisho wa AADAPT, (2) hali ya kwanza ya majaribio ya mwanzo hadi mwisho yenye ugunduzi uliotekelezwa, (3) mizunguko ya robo mwaka ya purple-team inayopanua ufunikaji na kupunguza MTTD/MTTC.<sup>[[2]](#references)</sup>

## 7. Violezo vya hali za majaribio
Tumia michoro hii inayoweza kurudiwa ili kubuni simulations zinazoendana moja kwa moja na tabia za AADAPT.<sup>[[2]](#references)</sup>

### Hali A – Udanganyifu wa kiuchumi kwa flash-loan
- **Lengo**: kukopa mtaji wa muda mfupi ndani ya transaction moja ili kupotosha bei/liquidity za AMM na kuchochea mikopo, liquidation au mint zisizo na bei sahihi kabla ya kurejesha mkopo.
- **Utekelezaji**:
  1. Fork chain lengwa na jaza pools kwa liquidity inayofanana na ya uzalishaji.
  2. Kopa kiasi kikubwa kupitia flash loan.
  3. Fanya swaps zilizopimwa kwa makini ili kuvuka mipaka ya bei/threshold inayotegemewa na mantiki ya ukopeshaji, vault au derivative.
  4. Ita contract lengwa mara tu baada ya upotoshaji (kopa, liquidate, mint) na urejeshe flash loan.
- **Upimaji**: Je, uvunjaji wa invariant ulifanikiwa? Je, vichunguzi vya slippage/price-deviation, circuit breakers au hooks za kusitisha za governance vilichochewa? Ilipita muda gani kabla analytics haijatambua muundo usio wa kawaida wa gas/call graph?

### Hali B – Kuweka sumu kwenye oracle/data feed
- **Lengo**: kubaini kama feeds zilizochezewa zinaweza kuchochea vitendo vya kiotomatiki vinavyoharibu (liquidations nyingi, settlements zisizo sahihi).
- **Utekelezaji**:
  1. Kwenye fork/testnet, deploy feed hasidi au rekebisha uzito wa aggregator/quorum/marudio ya masasisho kiasi cha kuzidi deviation inayovumilika.
  2. Acha contracts tegemezi zitumie thamani zilizowekewa sumu na kutekeleza mantiki yake ya kawaida.
- **Upimaji**: Alerts za nje ya kiwango katika feed, kuamilishwa kwa fallback oracle, utekelezaji wa mipaka ya chini/juu, na muda kati ya kuanza kwa anomaly na mwitikio wa mwendeshaji.

### Hali C – Matumizi mabaya ya credentials/utiaji saini
- **Lengo**: kujaribu ikiwa kuhujumu signer mmoja au utambulisho wa automation kunaruhusu uboreshaji, mabadiliko ya vigezo au utoaji wa fedha kutoka treasury bila idhini.
- **Utekelezaji**:
  1. Orodhesha utambulisho wenye haki nyeti za utiaji saini (waendeshaji, CI tokens, service accounts zinazoita KMS/HSM, washiriki wa multisig).
  2. Igiza kuhujumu (tumia tena credentials/funguo zao ndani ya scope ya maabara).
  3. Jaribu vitendo vya upendeleo: boresha proxies, badilisha vigezo vya hatari, mint/sitisha mali au anzisha mapendekezo ya governance.
- **Upimaji**: Je, logs za KMS/HSM zinatoa alerts za anomaly (wakati wa siku, mabadiliko ya anwani lengwa, mlipuko wa shughuli zenye hatari kubwa)? Je, sera au viwango vya multisig vinaweza kuzuia matumizi mabaya ya upande mmoja? Je, throttles/rate limits au idhini za ziada zinatekelezwa?

### Hali D – Kukwepa ufuatiliaji wa cross-chain na mapengo ya traceability
- **Lengo**: kutathmini jinsi watetezi wanavyoweza kufuatilia na kuzuia mali zinazofichwa haraka kupitia bridges, DEX routers na privacy hops.
- **Utekelezaji**:
  1. Unganisha shughuli za lock/mint katika bridges za kawaida, changanya swaps/mixers kwenye kila hop, na udumishe correlation IDs kwa kila hop.
  2. Ongeza kasi ya uhamishaji ili kujaribu uwezo wa ufuatiliaji (multi-hop ndani ya dakika/blocks).
- **Upimaji**: Muda wa kuoanisha matukio katika telemetry na analytics za kibiashara za chain, ukamilifu wa njia iliyojengwa upya, uwezo wa kutambua sehemu za kusimamishia mali katika tukio halisi, na usahihi wa alerts za kasi/thamani isiyo ya kawaida ya cross-chain.

## References

- [1] [Mfumo wa MITRE AADAPT wa Vitisho vya Mtandaoni kwa Mali za Kidijitali (MITRE)](https://www.mitre.org/sites/default/files/2025-05/PR-25-1118-aadpt-cyber-threat-framework-for-digital-assets.pdf)
- [2] [Mfumo wa MITRE AADAPT kama Ramani ya Njia ya Red Team (Bishop Fox)](https://bishopfox.com/blog/mitre-aadapt-framework-as-a-red-team-roadmap)
{{#include ../../banners/hacktricks-training.md}}
