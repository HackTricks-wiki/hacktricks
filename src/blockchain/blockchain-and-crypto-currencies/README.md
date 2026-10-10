# Blockchain na Sarafu za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na hivyo kuendesha utekelezaji wa makubaliano bila wapatanishi.
- **Decentralized Applications (dApps)** hujengwa kwa kutumia smart contracts, zikiwa na kiolesura cha mbele kinachorahisisha matumizi na sehemu ya nyuma iliyo wazi na inayoweza kukaguliwa.
- **Tokens na Coins** hutofautiana kwa kuwa coins hutumika kama pesa za kidijitali, huku tokens zikiwakilisha thamani au umiliki katika miktadha mahususi.
  - **Utility Tokens** hutoa ufikiaji wa huduma, na **Security Tokens** huashiria umiliki wa mali.
- **DeFi** humaanisha Decentralized Finance, inayotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** humaanisha mifumo ya kubadilishana iliyogatuliwa na mashirika huru yaliyogatuliwa, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha uthibitishaji salama wa miamala unaokubaliwa kwenye blockchain:

- **Proof of Work (PoW)** hutegemea uwezo wa kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji wathibitishaji kumiliki kiasi fulani cha tokens, na hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu kuhusu Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kwa kutumia saini za kidijitali, kuhakikisha kuwa ni mmiliki wa private key pekee anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Miamala ya Multisignature** huhitaji saini nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala ina **inputs** (chanzo cha fedha), **outputs** (mahali zinakopelekwa), **fees** (zinazolipwa kwa wachimbaji), na **scripts** (kanuni za muamala).

### Lightning Network

Lengo lake ni kuongeza uwezo wa Bitcoin wa kushughulikia miamala kwa kuruhusu miamala mingi ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mbinu kama **Mixers** na **CoinJoin** huboresha kutokujulikana kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Mbinu hizo ni pamoja na biashara ya pesa taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins zionekane kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huwa sababu za wasiwasi. Huu hapa muhtasari rahisi wa baadhi ya mbinu za kawaida ambazo washambuliaji wanaweza kutumia kuvunja faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Dhana ya Umiliki wa Pembejeo za Pamoja**

Kwa kawaida, ni nadra pembejeo kutoka kwa watumiaji tofauti kuunganishwa kwenye muamala mmoja kwa sababu ya ugumu unaohusika. Kwa hiyo, **anwani mbili za pembejeo katika muamala mmoja mara nyingi huchukuliwa kuwa za mmiliki mmoja**.

## **Kutambua Anwani ya Utoaji wa UTXO**

UTXO, au **Matokeo ya Muamala Yasiyotumika**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu ndiyo inayotumwa kwa anwani nyingine, salio hutumwa kwenye anwani mpya ya chenji. Watazamaji wanaweza kudhani kuwa anwani hii mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hatari hii, kutumia huduma za kuchanganya fedha au anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Kufichuka kwenye Mitandao ya Kijamii na Majukwaa**

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo **kurahisisha kuhusisha anwani hiyo na mmiliki wake**.

## **Uchanganuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, ikifichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristiki ya Pembejeo Isiyohitajika (Heuristiki ya Chenji Bora)**

Heuristiki hii hutegemea kuchanganua miamala yenye pembejeo na matokeo mengi ili kukisia ni matokeo gani ni chenji inayorudishwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kutafanya change output kuwa kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Forced Address Reuse**

Washambuliaji wanaweza kutuma kiasi kidogo kwa anwani zilizotumika hapo awali, wakitumaini kwamba mpokeaji atazichanganya na inputs nyingine katika transactions zijazo, na hivyo kuunganisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani tupu ambazo tayari zimetumika, ili kuzuia leak hii ya faragha.

## **Mbinu Nyingine za Uchanganuzi wa Blockchain**

- **Kiasi Halisi cha Malipo:** Transactions zisizo na chenji huenda zikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Namba Zilizokaribishwa:** Namba iliyokaribishwa katika transaction huashiria kuwa ni malipo, huku output isiyokaribishwa huenda ikawa chenji.
- **Utambuzi wa Wallet:** Wallet tofauti zina mifumo ya kipekee ya kuunda transactions, inayowaruhusu wachanganuzi kutambua software iliyotumika na huenda pia anwani ya chenji.
- **Uhusiano wa Kiasi na Muda:** Kufichua muda au kiasi cha transactions kunaweza kufanya transactions zifuatilike.

## **Uchanganuzi wa Trafiki**

Kwa kufuatilia trafiki ya mtandao, washambuliaji wanaweza kuunganisha transactions au blocks na anwani za IP, na kuhatarisha faragha ya watumiaji. Hili ni kweli hasa ikiwa taasisi inaendesha nodes nyingi za Bitcoin, jambo linaloongeza uwezo wake wa kufuatilia transactions.

## Zaidi

Kwa orodha kamili ya mashambulizi ya faragha na mbinu za kujilinda, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transactions za Bitcoin Zisizojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Transactions za Pesa Taslimu**: Kupata bitcoin kwa kutumia pesa taslimu.
- **Njia Mbadala za Pesa Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ikiwa unafanya peke yako, kwa kuwa mining pools zinaweza kujua anwani ya IP ya mchimbaji. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Mixing

Kwa kutumia huduma ya mixing, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kama malipo**, jambo linalofanya iwe vigumu kumfuatilia mmiliki wa awali. Hata hivyo, hii inahitaji kuamini huduma hiyo isihifadhi logs na irudishe bitcoins kweli. Chaguo mbadala za mixing ni pamoja na kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha transactions nyingi za watumiaji tofauti kuwa transaction moja, na kufanya iwe vigumu kwa yeyote anayejaribu kulinganisha inputs na outputs. Licha ya ufanisi wake, transactions zenye ukubwa wa kipekee wa inputs na outputs bado zinaweza kufuatiliwa.

Mifano ya transactions ambazo huenda zilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa mixer ya smart-contract ya Ethereum inayotenganisha deposits na withdrawals za baadaye, angalia [Tornado Cash](https://tornado.cash).

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha transaction inayofanywa na wahusika wawili (kwa mfano, mteja na mfanyabiashara) ionekane kama transaction ya kawaida, bila outputs zenye thamani sawa zinazotambulisha CoinJoin. Hii hufanya iwe vigumu sana kuitambua na inaweza kubatilisha heuristic ya umiliki wa inputs zinazofanana inayotumiwa na taasisi za ufuatiliaji wa transactions.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki isiyotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo haiwezekani kwa washambuliaji kutambua ni miamala au anwani zipi zinazomvutia mtumiaji.
- **Uchujaji wa block upande wa mteja**: Mbinu hii inahusisha kuunda vichujio kwa kila block kwenye blockchain, ili wallet ziweze kutambua miamala inayohusika bila kufichua maslahi mahususi kwa wachunguzi wa mtandao. Wallet nyepesi hupakua vichujio hivi, na kupakua block kamili tu inapopatikana inayolingana na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hufanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuimarisha faragha unapowasiliana na mtandao.

## **Kuzuia Kutumia Tena Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha miamala na huluki ileile. Wallet za kisasa zimeundwa ili kuzuia matumizi ya tena ya anwani.

## **Mikakati ya Kulinda Faragha ya Miamala**

- **Miamala mingi**: Kugawa malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi ya faragha.
- **Kuepuka chenji**: Kuchagua miamala isiyohitaji matokeo ya chenji huimarisha faragha kwa kuvuruga mbinu za kutambua chenji.
- **Matokeo mengi ya chenji**: Ikiwa haiwezekani kuepuka chenji, kuunda matokeo mengi ya chenji bado kunaweza kuboresha faragha.

# **Monero: Mwanga wa Kutokujulikana**

Monero imeundwa kuweka kipaumbele kwa faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kimahesabu zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huwekwa kwa **gwei**. Kwa mfano, muamala unaogharimu gwei 2,310,000 (au ETH 0.00231) unahusisha kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele inayochochea validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu zaidi ili kuhakikisha hawalipi kupita kiasi; kiasi kinachozidi hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Inahitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hukokotolewa kutoka kwenye sahihi, hivyo haihitajiki kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akiweka kipaumbele kwa faragha na usalama.

## Red Teaming ya Web3 Inayozingatia Thamani

- Orodhesha vipengele vinavyoshikilia thamani (signers, oracles, bridges, automation) ili kuelewa ni nani anayeweza kuhamisha fedha na jinsi anavyoweza kufanya hivyo.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kupandisha marupurupu.
- Fanya mazoezi ya minyororo ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kuweka kumbukumbu za masharti ya awali yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhujumu Mtiririko wa Uwekaji Sahihi wa Web3

- Kuhujumu mnyororo wa usambazaji wa wallet UIs kunaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na hivyo kukusanya sahihi halali za kuteka proxy zinazotumia delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Aina za kawaida za hitilafu za smart-account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, replay ya ERC-1271, na kumaliza ada kupitia revert-baada-ya-uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Kutumia mutation testing kutafuta mapengo katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa Guest wa ZK Proof / zkVM

Prover inapotumia **zkVM** au proof circuit maalum ya programu kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **vikwazo vya kisemantiki vinavyokosekana**, prover hasidi anaweza kutoa proof inayothibitishwa huku **vipimo vya umma au invariant inayodaiwa vikiwa si vya kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia witness/circuit bytes za faragha kama **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzifungua kwa kutumia helpers zisizokagua, kama `rkyv::access_unchecked`, isipokuwa bytes hizo tayari zimethibitishwa kwa njia nyingine.
- Enum discriminants, relative pointers, urefu na indexes zinazopakiwa kutoka kwenye data iliyoserialishwa isiyoaminika lazima zithibitishwe kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa memory.

Muundo wa vitendo wa ukaguzi:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` ya baadaye kwenye thamani hiyo inatia shaka.

### Kupita counters za UB kwa kutumia jump table

Rust ikibadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **counters/vizuizi muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi ya instruction**.
3. Discriminant iliyo nje ya masafa hufikia nje ya jump table ya kwanza na kutua kwenye code inayohusishwa na ya pili.

Matokeo: operesheni bado hutekelezwa, lakini njia ya uhasibu hurukwa. Katika zkVM, hii inaweza kughushi proofs zinazoripoti metrics zisizowezekana, kama vile gates chache, operesheni ghali chache, au rasilimali nyingine zenye mipaka zilizopotoshwa.

Orodha ya ukaguzi:

- Tafuta enums zinazodhibitiwa na mshambuliaji na kuserialishwa kutoka kwa witness/private input.
- Kagua kauli za `match` zinazorudiwa kwenye field ileile ya opcode/kind.
- Chukulia `unsafe` + deserialization isiyokaguliwa + dispatch kubwa ya opcode kama mchanganyiko wenye hatari kubwa.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko source.

### Vizuizi vya kisemantiki vinavyokosekana katika interpreters zinazoweza kutenduliwa/maalum

Usihakiki usalama wa memory pekee; hakiki pia **sheria za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa instruction sets zinazoweza kutenduliwa/zilizo kama quantum, hakikisha kwamba operands zinazopaswa kuwa tofauti zimewekewa kizuizi cha kuwa tofauti. Operesheni inayofanana na Toffoli/CCX iliyotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

inakuwa si salama ikiwa guest haitakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito hupunguzwa na kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya deterministic reset**, inayovunja dhana za reversibility na kuwezesha hesabu zisizokusudiwa kwa gharama ndogo. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hili linaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakipita model ya gharama ambayo verifier inaamini inatekelezwa.

### Mambo ya kujaribu katika mifumo ya ZK

- Fuzz guest parser zote kwa encodings za witness/private-input zenye hitilafu.
- Thibitisha enum range kabla ya opcode dispatch.
- Ongeza ukaguzi wa semantiki kwa operand aliasing na miundo mingine batili ya instruction.
- Linganisha counters zinazoripotiwa/za umma na implementation huru ya marejeo.
- Kumbuka kuwa proof halali bado inaweza kuthibitisha **kauli isiyo sahihi** ikiwa guest program ina hitilafu.

## Uidhinishaji Unaotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

Ikiwa unachunguza exploitation ya vitendo dhidi ya DEX na AMM (Uniswap v4 hooks, matumizi mabaya ya rounding/precision, swaps za kuvuka threshold zilizoimarishwa na flash-loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa weighted pool za mali nyingi zinazohifadhi virtual balances kwenye cache na zinaweza kuwekewa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Ufunguo wa Umma na Ufunguo wa Faragha Umeelezwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Muamala wa saini nyingi ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Miámala | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tuliishinda proof ya Google's zero-knowledge ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda Sarafu za Kidijitali za Elliptic Curve dhidi ya Udhaifu wa Quantum: Makadirio ya Rasilimali na Hatua za Kupunguza Hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Hazina ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
