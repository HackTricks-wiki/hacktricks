# Blockchain na Fedha za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na kuwezesha utekelezaji wa makubaliano kiotomatiki bila wapatanishi.
- **Decentralized Applications (dApps)** hujengwa kwa kutumia smart contracts, zikiwa na front-end rahisi kutumia na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, huku tokens zikiwakilisha thamani au umiliki katika miktadha mahususi.
  - **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha mifumo ya Decentralized Exchange na mashirika ya Decentralized Autonomous, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha uthibitishaji salama na unaokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** hutegemea nguvu ya kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji wathibitishaji kumiliki kiasi fulani cha tokens, hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu kuhusu Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kwa saini za kidijitali, kuhakikisha ni mmiliki wa private key pekee anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji saini nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala ina **inputs** (chanzo cha fedha), **outputs** (mahali zinapoenda), **fees** (zinazolipwa kwa wachimbaji), na **scripts** (kanuni za muamala).

### Lightning Network

Hulenga kuboresha uwezo wa Bitcoin kushughulikia miamala kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ndiyo hutangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha kutokujulikana kwa kuficha viunganishi vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu zinajumuisha biashara za fedha taslimu, uchimbaji, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins ionekane kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huwa masuala yanayozua wasiwasi. Huu hapa ni muhtasari rahisi wa mbinu kadhaa za kawaida ambazo washambuliaji wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Kwa kawaida, ni nadra inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu unaohusika. Kwa hiyo, **anwani mbili za input katika muamala mmoja mara nyingi huchukuliwa kuwa zinamilikiwa na mtu yuleyule**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu itatumwa kwa anwani nyingine, iliyobaki huenda kwenye anwani mpya ya chenji. Wanaochunguza wanaweza kudhani anwani hii mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hili, huduma za mixing au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## Kufichuliwa kwenye Mitandao ya Kijamii na Majukwaa

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo **kurahisisha kuunganisha anwani hiyo na mmiliki wake**.

## Uchambuzi wa Grafu ya Miamala

Miamala inaweza kuonyeshwa kama grafu, ikifichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii hutegemea kuchanganua miamala yenye inputs na outputs nyingi ili kukisia ni output ipi ni chenji inayorejeshwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kutafanya change output kuwa kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Kutumia Tena Anwani kwa Lazima**

Washambuliaji wanaweza kutuma kiasi kidogo kwa anwani zilizotumika awali, wakitumaini mpokeaji ataviunganisha na inputs nyingine katika miamala ya baadaye, na hivyo kuhusisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani tupu zilizotumika awali ili kuzuia uvujaji huu wa faragha.

## **Mbinu Nyingine za Uchambuzi wa Blockchain**

- **Kiasi Halisi cha Malipo:** Miamala isiyo na chenji huenda ikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Nambari Zilizokaribishwa:** Nambari iliyokaribishwa katika muamala huashiria malipo; output isiyokaribishwa huenda ikawa chenji.
- **Utambuzi wa Wallet:** Wallets tofauti zina mifumo ya kipekee ya kuunda miamala, inayowawezesha wachambuzi kutambua programu iliyotumika na huenda pia anwani ya chenji.
- **Uhusiano wa Kiasi na Muda:** Kufichua nyakati au kiasi cha miamala kunaweza kurahisisha kuifuatilia.

## **Uchambuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuhusisha miamala au block na anwani za IP, na hivyo kuhatarisha faragha ya watumiaji. Hili ni kweli hasa ikiwa taasisi inaendesha nodes nyingi za Bitcoin, na hivyo kuongeza uwezo wake wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi na ulinzi wa faragha, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Fedha Taslimu**: Kupata bitcoin kwa kutumia fedha taslimu.
- **Njia Mbadala za Fedha Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ukiifanya peke yako kwa sababu mining pools zinaweza kujua anwani ya IP ya miner. [Taarifa kuhusu Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na hakupendekezwi.

## Huduma za Kuchanganya

Kwa kutumia huduma ya kuchanganya, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti badala yake**, jambo linalofanya iwe vigumu kumfuatilia mmiliki wa awali. Hata hivyo, hili linahitaji kuiamini huduma hiyo kwamba haitahifadhi logs na kwamba itarudisha bitcoins. Chaguo mbadala za kuchanganya ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti kuwa muamala mmoja, na hivyo kufanya iwe vigumu zaidi kwa yeyote anayejaribu kulinganisha inputs na outputs. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa inputs na outputs bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya smart-contract ya Ethereum inayotenganisha deposits na withdrawals za baadaye, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Aina tofauti ya CoinJoin, **PayJoin** (au P2EP), huficha muamala wa wahusika wawili (kwa mfano, mteja na mfanyabiashara) ili uonekane kama muamala wa kawaida, bila outputs zinazolingana ambazo ni sifa bainifu ya CoinJoin. Hii hufanya iwe vigumu sana kuitambua na inaweza kubatilisha heuristic ya umiliki wa pamoja wa inputs inayotumiwa na taasisi zinazofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikiendelea kutotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kutatiza kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet na Blockchain**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa kwenye kifaa cha mtumiaji, hivyo haiwezekani kwa washambuliaji kutambua ni miamala au anwani zipi zinazomvutia mtumiaji.
- **Uchujaji wa block upande wa mteja**: Mbinu hii inahusisha kuunda vichujio kwa kila block kwenye blockchain, na kuwezesha wallet kutambua miamala inayohusika bila kufichua mambo mahususi yanayomvutia kwa wachunguzi wa mtandao. Wallet nyepesi hupakua vichujio hivi na kupakua block nzima tu inapopata inayolingana na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hufanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuboresha faragha unapowasiliana na mtandao.

## **Kuzuia Matumizi ya Anwani Tena**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia anwani tena kunaweza kuathiri faragha kwa kuunganisha miamala na huluki ileile. Wallet za kisasa zimeundwa kuzuia matumizi ya anwani tena.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi dhidi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji matokeo ya chenji huboresha faragha kwa kutatiza mbinu za kutambua chenji.
- **Matokeo mengi ya chenji**: Ikiwa kuepuka chenji hakuwezekani, kuunda matokeo mengi ya chenji bado kunaweza kuboresha faragha.

# **Monero: Kielelezo cha Kutokujulikana**

Monero imeundwa kuweka kipaumbele kwa faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kimahesabu zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huwekwa katika **gwei**. Kwa mfano, muamala unaogharimu gwei 2,310,000 (au ETH 0.00231) huwa na kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ya kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu zaidi ili kuhakikisha hawalipi kupita kiasi; kiasi kinachozidi hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Miamala huhitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hubainishwa kutokana na sahihi, hivyo haihitajiki kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni za msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akipa kipaumbele faragha na usalama.

## Red Teaming ya Web3 Inayozingatia Thamani

- Orodhesha vipengele vinavyoshikilia thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi anavyoweza kufanya hivyo.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kuongeza mamlaka.
- Fanyia mazoezi misururu ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kurekodi masharti yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuvurugwa kwa Mchakato wa Kusaini wa Web3

- Uchezewaji wa msururu wa ugavi wa kiolesura cha wallet unaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na hivyo kupata sahihi halali za kutwaa udhibiti wa proxy inayotumia delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Utoaji wa Abstraction kwa Akaunti (ERC-4337)

- Kasoro za kawaida katika smart account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, replay ya ERC-1271, na kumaliza ada kupitia revert baada ya uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Tumia mutation testing kutafuta maeneo dhaifu katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit maalum ya programu kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **semantic constraints zinazokosekana**, prover hasidi anaweza kutoa proof inayothibitishwa huku **vipimo vya umma au invariant inayodaiwa vikiwa si kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia witness/circuit bytes za faragha kama **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzifanyia deserialization kwa kutumia helpers zisizokagua, kama `rkyv::access_unchecked`, isipokuwa bytes hizo zilithibitishwa hapo awali kupitia njia tofauti.
- Thibitisha enum discriminants, relative pointers, lengths na indexes zilizopakiwa kutoka kwenye data iliyoserializwa isiyoaminika kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Mbinu ya ukaguzi ya vitendo:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambulizi anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` inayofuata kwenye thamani hiyo inatia shaka.

### Ugeuzaji wa counter kupitia jump table / UB

Ikiwa Rust itabadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **counter/vikwazo muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi za instruction**.
3. Discriminant iliyo nje ya masafa huweka index nje ya jump table ya kwanza na kuelekeza kwenye msimbo unaohusishwa na ya pili.

Matokeo: operesheni bado hutekelezwa, lakini njia ya uhasibu hurukwa. Katika zkVM, hili linaweza kughushi proofs zinazoripoti metrics zisizowezekana, kama vile gates chache, operesheni ghali chache, au rasilimali nyingine zenye vikomo zilizoghushiwa.

Orodha ya ukaguzi:

- Tafuta enum zinazodhibitiwa na mshambulizi na kuserialishwa kutoka kwa witness/private input.
- Kagua kauli za `match` zinazorudiwa kwenye field ileile ya opcode/kind.
- Chukulia `unsafe` + deserialization isiyokaguliwa + dispatch kubwa ya opcode kuwa mchanganyiko wenye hatari kubwa.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko source.

### Kukosekana kwa vikwazo vya kisemantiki katika interpreters zinazoweza kubadilishwa au maalumu

Usihakikishe usalama wa memory pekee; hakikisha pia **kanuni za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa instruction sets zinazoweza kubadilishwa/zinazofanana na quantum, hakikisha kwamba operands zinazopaswa kuwa tofauti zimewekewa kikwazo cha kuwa tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

huwa si salama ikiwa mgeni hatakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito hubadilika na kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya reset deterministiki**, ikivunja dhana za urejeshaji wa hali ya awali na kuwezesha hesabu zisizokusudiwa kwa gharama nafuu zaidi. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hili linaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakikwepa modeli ya gharama ambayo verifier anaamini inatekelezwa.

### Cha kupima katika mifumo ya ZK

- Fanya fuzzing kwa parsers zote za guest kwa kutumia encodings za witness/private-input zenye hitilafu.
- Hakikisha uthibitishaji wa masafa ya enum unafanyika kabla ya opcode dispatch.
- Ongeza ukaguzi wa maana kwa operand aliasing na aina nyingine za maagizo zisizo halali.
- Linganisha counters zinazoripotiwa/za umma na implementation huru ya marejeo.
- Kumbuka kwamba proof halali bado inaweza kuthibitisha **taarifa isiyo sahihi** ikiwa programu ya guest ina hitilafu.

## Uidhinishaji Unaotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Unyonyaji wa DeFi/AMM

Ikiwa unatafiti unyonyaji wa vitendo wa DEX na AMM (Uniswap v4 hooks, unyonyaji wa rounding/precision, swaps zinazovuka kizingiti na kuimarishwa na flash loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa pools zenye uzani wa mali nyingi zinazohifadhi balances pepe kwenye cache na zinaweza kutiwa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Uthibitisho wa stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Ufafanuzi wa Public Key na Private Key - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Miamala ya saini nyingi ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Miamala | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tulishinda proof ya zero-knowledge ya Google ya uchanganuzi wa kriptografia ya quantum](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda sarafu za kidijitali za elliptic curve dhidi ya udhaifu wa quantum: Makadirio ya rasilimali na mbinu za kupunguza hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Hifadhi ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
