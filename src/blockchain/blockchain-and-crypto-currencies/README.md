# Blockchain na Sarafu za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na kuendesha utekelezaji wa makubaliano bila waamuzi.
- **Decentralized Applications (dApps)** hujengwa juu ya smart contracts, zikiwa na kiolesura cha mbele kinachofaa watumiaji na sehemu ya nyuma iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, ilhali tokens huwakilisha thamani au umiliki katika miktadha maalum.
  - **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha miamala inathibitishwa kwa usalama na kwa makubaliano kwenye blockchain:

- **Proof of Work (PoW)** hutegemea nguvu ya kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji wathibitishaji kumiliki kiasi fulani cha tokens, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu kuhusu Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kwa sahihi za kidijitali, zinazohakikisha kuwa mmiliki wa ufunguo wa faragha pekee ndiye anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Multisignature Transactions** huhitaji sahihi nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala huwa na **inputs** (chanzo cha fedha), **outputs** (mahali fedha zinakopelekwa), **fees** (zinazolipwa kwa wachimbaji), na **scripts** (sheria za muamala).

### Lightning Network

Hulenga kuongeza uwezo wa Bitcoin wa kushughulikia miamala kwa kuruhusu miamala mingi ndani ya chaneli, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Umiliki wa Pamoja wa Ingizo** na **Ugunduzi wa Anwani ya Chenji ya UTXO**, hutumia mifumo ya miamala. Mbinu kama **Mixers** na **CoinJoin** huboresha kutokujulikana kwa kuficha viunganishi vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu hizo ni pamoja na biashara za pesa taslimu, uchimbaji, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins ionekane kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huzua wasiwasi. Huu hapa ni muhtasari rahisi wa baadhi ya mbinu za kawaida ambazo washambuliaji wanaweza kutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Dhana ya Umiliki wa Pamoja wa Ingizo**

Kwa kawaida, ni nadra ingizo kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kwa sababu ya ugumu unaohusika. Kwa hiyo, **anwani mbili za ingizo katika muamala mmoja mara nyingi hudhaniwa kuwa za mmiliki mmoja**.

## **Ugunduzi wa Anwani ya Chenji ya UTXO**

UTXO, au **Matokeo ya Muamala Yasiyotumika**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu itatumwa kwa anwani nyingine, salio huenda kwenye anwani mpya ya chenji. Watazamaji wanaweza kudhani anwani hii mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hatari hii, huduma za kuchanganya au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Kufichuka Kupitia Mitandao ya Kijamii na Mijadala**

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo **kurahisisha kuhusisha anwani na mmiliki wake**.

## **Uchambuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, ikifichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristiki ya Ingizo Lisilohitajika (Heuristiki ya Chenji Bora)**

Heuristiki hii hutegemea kuchanganua miamala yenye ingizo na matokeo mengi ili kukisia ni matokeo gani ni chenji inayorejeshwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kunafanya output ya chenji iwe kubwa kuliko input yoyote moja, hilo linaweza kuchanganya heuristic.

## **Kulazimisha Kutumia Tena Anwani**

Washambuliaji wanaweza kutuma kiasi kidogo cha bitcoin kwenye anwani zilizotumika hapo awali, wakitumaini kwamba mpokeaji ataziunganisha na inputs nyingine katika miamala ya baadaye, na hivyo kuhusisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallet zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani zilizotumika na ambazo hazina salio, ili kuzuia leak hii ya faragha.

## **Mbinu Nyingine za Kuchanganua Blockchain**

- **Kiasi Halisi cha Malipo:** Miamala isiyo na chenji huenda ikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Namba Zilizokaribiana:** Namba iliyokaribiana kwenye muamala hudokeza kuwa ni malipo, huku output isiyokaribiana huenda ikawa chenji.
- **Utambuzi wa Wallet:** Wallet tofauti zina mifumo ya kipekee ya kuunda miamala, hivyo wachanganuzi wanaweza kutambua software iliyotumika na huenda pia anwani ya chenji.
- **Uhusiano wa Kiasi na Muda:** Kufichua nyakati au kiasi cha miamala kunaweza kufanya miamala ifuatilike.

## **Uchanganuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuhusisha miamala au blocks na anwani za IP, na hivyo kuhatarisha faragha ya watumiaji. Hili hutokea hasa ikiwa mtu au shirika linaendesha nodes nyingi za Bitcoin, jambo linaloongeza uwezo wao wa kufuatilia miamala.

## Zaidi

Kwa orodha ya kina ya mashambulizi na ulinzi wa faragha, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Fedha Taslimu**: Kupata bitcoin kwa kutumia fedha taslimu.
- **Njia Mbadala za Fedha Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kupata bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ikiwa unafanya mining peke yako, kwa sababu mining pools zinaweza kujua anwani ya IP ya mchimbaji. [Maelezo kuhusu Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Mixing

Kwa kutumia huduma ya mixing, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kama malipo**, jambo linalofanya iwe vigumu kumfuatilia mmiliki wa awali. Hata hivyo, hii inahitaji kuiamini huduma kwamba haitahifadhi logs na kwamba itarejesha bitcoins hizo. Chaguo mbadala za mixing ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti na kuifanya muamala mmoja, hivyo kutatiza kazi ya mtu yeyote anayejaribu kulinganisha inputs na outputs. Licha ya ufanisi wake, miamala yenye ukubwa wa inputs na outputs wa kipekee bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya Ethereum smart-contract inayotenganisha amana na utoaji wa baadaye, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Aina ya CoinJoin, **PayJoin** (au P2EP), huficha muamala kati ya pande mbili (kwa mfano, mteja na mfanyabiashara) kwa kuufanya uonekane kama muamala wa kawaida, bila outputs zinazolingana ambazo hutambulisha CoinJoin. Hii hufanya iwe vigumu sana kuitambua na inaweza kubatilisha heuristic ya umiliki wa pamoja wa inputs inayotumiwa na mashirika yanayofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki isiyotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu zaidi. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo kufanya isiwezekane kwa washambuliaji kutambua miamala au anwani ambazo mtumiaji anavutiwa nazo.
- **Uchujaji wa block upande wa mteja**: Mbinu hii inahusisha kuunda vichujio kwa kila block kwenye blockchain, na kuziwezesha wallet kutambua miamala husika bila kufichua maslahi mahususi kwa wachunguzi wa mtandao. Wallet nyepesi hupakua vichujio hivi, na kupakua block nzima tu pale anwani za mtumiaji zinapolingana nazo.

## **Kutumia Tor kwa Kutotambulika**

Kwa kuwa Bitcoin hutumia mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuboresha faragha unapowasiliana na mtandao.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuhusisha miamala na huluki ileile. Wallet za kisasa zimeundwa ili kuzuia matumizi ya anwani tena.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawa malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi dhidi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji matokeo ya chenji huboresha faragha kwa kutatiza mbinu za kutambua chenji.
- **Matokeo mengi ya chenji**: Ikiwa haiwezekani kuepuka chenji, kuunda matokeo mengi ya chenji bado kunaweza kuboresha faragha.

# **Monero: Taa ya Kutotambulika**

Monero imeundwa kuweka faragha ya miamala kuwa kipaumbele.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kihesabu zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huonyeshwa kwa **gwei**. Kwa mfano, muamala unaogharimu gwei 2,310,000 (au ETH 0.00231) huhusisha kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ya kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu zaidi ili kuhakikisha hawalipi kupita kiasi; kiasi kinachozidi hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Miamala huhitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu ni kwamba, anwani ya mtumaji hutambuliwa kutokana na sahihi, hivyo si lazima iwekwe kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na mifumo hii ni ya msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akitanguliza faragha na usalama.

## Red Teaming ya Web3 Inayozingatia Thamani

- Orodhesha vipengele vyenye thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi anavyoweza kufanya hivyo.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kupandisha mamlaka.
- Fanyia mazoezi misururu ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kurekodi masharti ya awali yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuvurugwa kwa Mchakato wa Kusaini wa Web3

- Ubadilishaji hasidi wa supply chain ya violesura vya wallet unaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na kukusanya sahihi halali za kutwaa proxy zinazotumia delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Utoaji wa Abstraction ya Akaunti (ERC-4337)

- Hali za kawaida za kushindwa kwa smart-account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, mashambulizi ya replay ya ERC-1271, na kuondoa ada kupitia revert-baada-ya-uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Kutumia mutation testing kutafuta maeneo dhaifu katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit mahususi ya programu kuthibitisha dai, verifier hujifunza tu kwamba **programu ya guest ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **deserialization isiyo salama**, **tabia isiyobainishwa**, au **vikwazo vya kisemantiki vinavyokosekana**, prover hasidi anaweza kutengeneza proof inayothibitishwa huku **vipimo vya umma au invariant inayodaiwa vikiwa si vya kweli**.<sup>[[7]](#references)</sup>

### Deserialization isiyo salama ndani ya proof guests

- Chukulia bytes za private witness/circuit kama **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzifanya deserialization kwa kutumia helpers zisizofanya ukaguzi, kama `rkyv::access_unchecked`, isipokuwa bytes zilishathibitishwa kwa njia nyingine.
- Thibitisha enum discriminants, relative pointers, lengths na indexes zilizopakiwa kutoka kwenye data iliyoserialishwa isiyoaminika kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Mbinu ya ukaguzi ya vitendo:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` ya baadaye kwenye thamani hiyo huwa ya kutiliwa shaka.

### Jump-table / UB counter bypass

Ikiwa Rust itabadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **vihesabio/vikwazo muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi za maagizo**.
3. Discriminant iliyo nje ya masafa huenda nje ya jump table ya kwanza na kutua kwenye msimbo unaohusishwa na ya pili.

Matokeo: operesheni bado hutekelezwa, lakini njia ya uhasibu hurukwa. Katika zkVM, hii inaweza kutengeneza proofs zinazoripoti vipimo visivyowezekana, kama vile gates chache zaidi, operesheni ghali chache zaidi au rasilimali nyingine zenye mipaka zilizopotoshwa.

Orodha ya ukaguzi:

- Tafuta enums zinazodhibitiwa na mshambuliaji na ku-deserialize kutoka kwa witness/private input.
- Kagua kauli za `match` zinazorudiwa kwenye field ileile ya opcode/kind.
- Chukulia mchanganyiko wa `unsafe` + unchecked deserialization + ugawaji mkubwa wa opcode kuwa hatari kubwa.
- Reverse engineer binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko source.

### Vikwazo vya kisemantiki vinavyokosekana katika interpreters zinazoweza kubadilishwa au zilizobobea

Usihakiki tu usalama wa kumbukumbu; hakiki pia **kanuni za kisemantiki** ambazo proof inakusudiwa kutekeleza.

Kwa instruction set zinazoweza kubadilishwa au zinazofanana na quantum, hakikisha kwamba operands zinazopaswa kuwa tofauti kweli zimewekewa kikwazo cha kuwa tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

inakuwa si salama ikiwa mfumo-mgeni hautakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito huo huishia kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya reset inayoweza kubashiriwa**, ikivunja dhana za urejeshaji na kuwezesha ukokotoaji usiokusudiwa kwa gharama ndogo. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hili linaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakikwepa modeli ya gharama ambayo verifier inaamini inatekelezwa.

### Mambo ya kujaribu katika mifumo ya ZK

- Fanya fuzzing kwa parser zote za guest ukitumia encoding za witness/private-input zenye hitilafu.
- Hakikisha uhalalishaji wa masafa ya enum unafanyika kabla ya opcode dispatch.
- Ongeza ukaguzi wa kisemantiki wa operand aliasing na miundo mingine batili ya instruction.
- Linganisha counters zinazoripotiwa/za umma na utekelezaji huru wa marejeo.
- Kumbuka kuwa proof halali bado inaweza kuthibitisha **kauli isiyo sahihi** ikiwa programu ya guest ina hitilafu.

## Uidhinishaji Unaotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Uvunjaji wa Usalama wa DeFi/AMM

Ikiwa unatafiti uvunjaji wa usalama wa DEX na AMM kwa vitendo (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, swaps zinazovuka kizingiti kwa kutumia flash loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa weighted pools zenye assets nyingi zinazohifadhi virtual balances kwenye cache na zinaweza kuwekewa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Ufunguo wa Umma na Ufunguo wa Faragha Umefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Miamala ya saini nyingi ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Miamala | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tuliishinda proof ya Google's zero-knowledge ya uchanganuzi wa quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Sarafu za Kidijitali za Elliptic Curve dhidi ya Udhaifu wa Quantum: Makadirio ya Rasilimali na Hatua za Kupunguza Hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Hazina ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
