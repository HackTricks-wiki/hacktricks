# Blockchain na Sarafu za Kidijitali

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Mikataba Mahiri (Smart Contracts)** ni programu zinazotekelezwa kwenye blockchain masharti fulani yanapotimizwa, na kuendesha utekelezaji wa makubaliano bila wapatanishi.
- **Programu Zisizogatuliwa (dApps)** hujengwa kwa kutumia mikataba mahiri, zikiwa na kiolesura cha mbele kinachorahisisha matumizi na sehemu ya nyuma iliyo wazi na inayoweza kukaguliwa.
- **Tokeni na Sarafu** hutofautiana kwa kuwa sarafu hutumika kama pesa za kidijitali, huku tokeni zikiwakilisha thamani au umiliki katika miktadha mahususi.
  - **Tokeni za Matumizi (Utility Tokens)** hutoa ufikiaji wa huduma, na **Tokeni za Dhamana (Security Tokens)** huashiria umiliki wa mali.
- **DeFi** ni kifupi cha Fedha Zisizogatuliwa (Decentralized Finance), zinazotoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAO** humaanisha Majukwaa ya Soko la Kubadilishana Yasiyogatuliwa (Decentralized Exchange Platforms) na Mashirika Huru Yasiyogatuliwa (Decentralized Autonomous Organizations), mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano huhakikisha miamala inathibitishwa kwa usalama na kwa makubaliano kwenye blockchain:

- **Proof of Work (PoW)** hutegemea nguvu ya kompyuta kuthibitisha miamala.
- **Proof of Stake (PoS)** huhitaji wathibitishaji kumiliki kiasi fulani cha tokeni, hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.<sup>[[1]](#references)</sup>

## Mambo Muhimu kuhusu Bitcoin

### Miamala

Miamala ya Bitcoin huhusisha kuhamisha fedha kati ya anwani. Miamala huthibitishwa kwa saini za kidijitali, kuhakikisha ni mmiliki wa ufunguo wa faragha pekee anayeweza kuanzisha uhamisho.<sup>[[2]](#references)</sup>

#### Vipengele Muhimu:

- **Miamala ya Saini Nyingi (Multisignature Transactions)** huhitaji saini nyingi ili kuidhinisha muamala.<sup>[[3]](#references)</sup>
- Miamala huwa na **ingizo** (chanzo cha fedha), **matokeo** (unakopelekwa), **ada** (inayolipwa kwa wachimbaji), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha uwezo wa Bitcoin kushughulikia miamala mingi kwa kuruhusu miamala kadhaa kufanyika ndani ya channel, huku hali ya mwisho pekee ikitangazwa kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama vile **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mbinu kama **Mixers** na **CoinJoin** huboresha kutokutambulika kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoin Bila Kujulikana

Mbinu hizo ni pamoja na biashara za pesa taslimu, uchimbaji, na kutumia mixers. **CoinJoin** huchanganya miamala kadhaa ili kufanya ufuatiliaji kuwa mgumu, huku **PayJoin** ikificha CoinJoins kama miamala ya kawaida ili kuongeza faragha.

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi huwa sababu za wasiwasi. Huu hapa ni muhtasari rahisi wa baadhi ya mbinu za kawaida ambazo washambuliaji hutumia kuhatarisha faragha ya Bitcoin.<sup>[[6]](#references)</sup>

## **Dhana ya Umiliki wa Pamoja wa Ingizo**

Kwa kawaida, ni nadra ingizo kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu unaohusika. Kwa hiyo, **anwani mbili za ingizo katika muamala mmoja mara nyingi hudhaniwa kuwa za mmiliki mmoja**.

## **Ugunduzi wa Anwani ya Chenji ya UTXO**

UTXO, yaani **Matokeo ya Muamala Yasiyotumika (Unspent Transaction Output)**, lazima itumike yote katika muamala. Ikiwa sehemu yake tu itatumwa kwa anwani nyingine, salio huenda kwenye anwani mpya ya chenji. Watazamaji wanaweza kudhani anwani hii mpya ni ya mtumaji, na hivyo kuhatarisha faragha.

### Mfano

Ili kupunguza hatari hii, huduma za uchanganyaji au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Kufichuka kwenye Mitandao ya Kijamii na Mijadala**

Wakati mwingine watumiaji hushiriki anwani zao za Bitcoin mtandaoni, na hivyo **kurahisisha kuunganisha anwani na mmiliki wake**.

## **Uchambuzi wa Grafu ya Miamala**

Miamala inaweza kuonyeshwa kama grafu, zikifichua miunganisho inayowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Heuristiki ya Ingizo Lisilohitajika (Heuristiki ya Chenji Bora)**

Heuristiki hii hutegemea kuchanganua miamala yenye ingizo na matokeo mengi ili kukisia ni tokeo gani ni chenji inayorejeshwa kwa mtumaji.

### Mfano

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Ikiwa kuongeza inputs zaidi kunafanya change output kuwa kubwa kuliko input yoyote moja, kunaweza kuchanganya heuristic.

## **Forced Address Reuse**

Washambuliaji wanaweza kutuma kiasi kidogo cha fedha kwenye anwani zilizotumika awali, wakitumaini mpokeaji atazichanganya na inputs nyingine katika miamala ya baadaye, na hivyo kuunganisha anwani hizo.

### Tabia Sahihi ya Wallet

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani tupu zilizotumika awali ili kuzuia leak hii ya faragha.

## **Mbinu Nyingine za Blockchain Analysis**

- **Kiasi Halisi cha Malipo:** Miamala isiyo na change huenda ikawa kati ya anwani mbili zinazomilikiwa na mtumiaji yuleyule.
- **Nambari Zilizokamilika:** Nambari iliyokamilika katika muamala hudokeza kuwa ni malipo, huku output isiyokamilika huenda ikawa change.
- **Wallet Fingerprinting:** Wallets tofauti zina mifumo ya kipekee ya kuunda miamala, inayowaruhusu wachambuzi kutambua software iliyotumika na huenda pia anwani ya change.
- **Ulinganifu wa Kiasi na Muda:** Kufichua muda au kiasi cha miamala kunaweza kufanya miamala ifuatilike.

## **Traffic Analysis**

Kwa kufuatilia traffic ya mtandao, washambuliaji wanaweza kuunganisha miamala au blocks na anwani za IP, na hivyo kuhatarisha faragha ya watumiaji. Hili ni kweli hasa ikiwa huluki inaendesha Bitcoin nodes nyingi, jambo linaloongeza uwezo wake wa kufuatilia miamala.

## Zaidi

Kwa orodha kamili ya mashambulizi na ulinzi wa faragha, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Miamala ya Bitcoin Isiyojulikana

## Njia za Kupata Bitcoins Bila Kujulikana

- **Miamala ya Fedha Taslimu**: Kupata bitcoin kwa kutumia fedha taslimu.
- **Njia Mbadala za Fedha Taslimu**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa ikifanywa peke yako kwa sababu mining pools huenda zikajua anwani ya IP ya mchimbaji. [Maelezo kuhusu Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Wizi**: Kinadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kujulikana, ingawa ni kinyume cha sheria na haipendekezwi.

## Huduma za Mixing

Kwa kutumia huduma ya mixing, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kama malipo**, jambo linalofanya iwe vigumu kufuatilia mmiliki wa awali. Hata hivyo, hili linahitaji kuiamini huduma hiyo isihifadhi logs na irudishe bitcoins kwa kweli. Njia mbadala za mixing zinajumuisha kasino za Bitcoin.

## CoinJoin

**CoinJoin** huunganisha miamala mingi kutoka kwa watumiaji tofauti na kuifanya muamala mmoja, na hivyo kutatiza juhudi za mtu yeyote anayejaribu kulinganisha inputs na outputs. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa inputs na outputs bado inaweza kufuatiliwa.

Mifano ya miamala ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa maelezo zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa Ethereum smart-contract mixer inayotenganisha deposits na withdrawals za baadaye, tazama [Tornado Cash](https://tornado.cash).

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), huficha muamala kati ya wahusika wawili (kwa mfano, mteja na mfanyabiashara) kwa kuufanya uonekane kama muamala wa kawaida, bila outputs zinazolingana ambazo ni sifa bainifu ya CoinJoin. Hii hufanya iwe vigumu sana kuitambua na inaweza kubatilisha heuristic ya umiliki wa inputs zinazofanana inayotumiwa na huluki zinazofuatilia miamala.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Miamala kama iliyo hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikiendelea kutotofautishika na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kulinda faragha ya miamala.

# Mbinu Bora za Kulinda Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, ni muhimu kusawazisha wallet na blockchain. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node huhakikisha faragha ya kiwango cha juu. Miamala yote iliyowahi kufanywa huhifadhiwa ndani ya kifaa, hivyo maadui hawawezi kutambua ni miamala au anwani zipi zinazomvutia mtumiaji.
- **Uchujaji wa block upande wa mteja**: Mbinu hii inahusisha kuunda vichujio kwa kila block katika blockchain, na kuruhusu wallet kutambua miamala husika bila kufichua mambo mahususi yanayomvutia mtumiaji kwa watazamaji wa mtandao. Wallet nyepesi hupakua vichujio hivi, na kupakua block nzima tu kunapopatikana inayolingana na anwani za mtumiaji.

## **Kutumia Tor kwa Kutokujulikana**

Kwa kuwa Bitcoin hufanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP na kuimarisha faragha unapowasiliana na mtandao.

## **Kuzuia Matumizi Tena ya Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia anwani tena kunaweza kuhatarisha faragha kwa kuunganisha miamala na huluki ileile. Wallet za kisasa zimeundwa kuzuia matumizi tena ya anwani.

## **Mikakati ya Faragha ya Miamala**

- **Miamala mingi**: Kugawa malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala na kuzuia mashambulizi dhidi ya faragha.
- **Kuepuka change**: Kuchagua miamala isiyohitaji change outputs huboresha faragha kwa kuvuruga mbinu za kutambua change.
- **Change outputs nyingi**: Ikiwa haiwezekani kuepuka change, kuzalisha change outputs nyingi bado kunaweza kuboresha faragha.

# **Monero: Kielelezo cha Kutokujulikana**

Monero imeundwa kuweka kipaumbele kwenye faragha ya miamala.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima juhudi za kikokotozi zinazohitajika kutekeleza shughuli kwenye Ethereum, na bei yake huwekwa kwa **gwei**. Kwa mfano, muamala unaogharimu gwei 2,310,000 (au ETH 0.00231) huhusisha kikomo cha gas na ada ya msingi, pamoja na ada ya kipaumbele ya kuhamasisha validator kuujumuisha. Watumiaji wanaweza kuweka ada ya juu kabisa ili kuhakikisha hawalipi zaidi ya inavyohitajika; kiasi kinachozidi hurejeshwa.<sup>[[5]](#references)</sup>

## **Kutekeleza Miamala**

Miamala kwenye Ethereum huhusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Miamala huhitaji ada na lazima ijumuishwe kwenye block. Taarifa muhimu katika muamala ni pamoja na mpokeaji, sahihi ya mtumaji, thamani, data ya hiari, kikomo cha gas na ada. Muhimu zaidi, anwani ya mtumaji hutambuliwa kutokana na sahihi, hivyo haihitajiki kwenye data ya muamala.<sup>[[4]](#references)</sup>

Mbinu na taratibu hizi ni za msingi kwa yeyote anayetaka kutumia sarafu za kidijitali huku akiweka kipaumbele kwenye faragha na usalama.

## Uwekaji Kipaumbele kwa Thamani katika Red Teaming ya Web3

- Orodhesha vipengele vinavyohusisha thamani (signers, oracles, bridges, automation) ili kuelewa nani anaweza kuhamisha fedha na jinsi gani.
- Linganisha kila kipengele na mbinu husika za MITRE AADAPT ili kufichua njia za kuongeza ruhusa.
- Fanyia mazoezi minyororo ya mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kurekodi masharti ya awali yanayowezesha unyonyaji.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kuhatarisha Mchakato wa Kusaini wa Web3

- Uchezewaji wa supply chain wa UI za wallet unaweza kubadilisha payload za EIP-712 kabla tu ya kusainiwa, na kupata sahihi halali kwa ajili ya takeover za proxy zinazotegemea delegatecall (kwa mfano, kubadilisha slot-0 ya Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Utoaji wa Abstraction ya Akaunti (ERC-4337)

- Hali za kawaida za hitilafu za smart-account ni pamoja na kukwepa udhibiti wa ufikiaji wa `EntryPoint`, sehemu za gas zisizosainiwa, uthibitishaji unaobadilisha hali, replay ya ERC-1271, na kumaliza ada kupitia revert baada ya uthibitishaji.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Usalama wa Smart Contract

- Tumia mutation testing kutafuta maeneo dhaifu katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Uadilifu wa ZK Proof / zkVM Guest

Prover anapotumia **zkVM** au proof circuit maalumu kwa programu kuthibitisha dai, verifier hujifunza tu kwamba **guest program ilitekelezwa kama ilivyoandikwa**. Ikiwa guest ina **unsafe deserialization**, **undefined behavior**, au **semantic constraints zinazokosekana**, prover hasidi anaweza kutengeneza proof inayothibitishwa ilhali **vipimo vya umma au invariant inayodaiwa si kweli**.<sup>[[7]](#references)</sup>

### Unsafe deserialization ndani ya proof guests

- Chukulia witness/circuit bytes za faragha kuwa **ingizo lisiloaminika kutoka kwa mshambuliaji**, hata kama zimefichwa na proof.
- Epuka kuzideserialize kwa kutumia helper zisizokagua, kama `rkyv::access_unchecked`, isipokuwa bytes zilishathibitishwa kwa njia nyingine.
- Discriminant za enum, relative pointers, urefu na faharasa zinazopakiwa kutoka kwenye data iliyoserialishwa isiyoaminika lazima zithibitishwe kabla hazijaathiri mtiririko wa udhibiti au ufikiaji wa kumbukumbu.

Mfumo wa vitendo wa ukaguzi:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Ikiwa field kama `op.kind` ni enum na mshambuliaji anaweza kuingiza **discriminant iliyo nje ya masafa**, kila `match` inayofuata kwenye thamani hiyo inapaswa kuchukuliwa kuwa ya kutiliwa shaka.

### Kukwepa ukaguzi wa jump table / UB

Ikiwa Rust itabadilisha `match` kubwa kuwa **jump table**, discriminant batili ya enum inaweza kusababisha **mtiririko wa udhibiti usiofafanuliwa**. Muundo hatari ni:<sup>[[7]](#references)[[9]](#references)</sup>

1. `match` moja husasisha **vihesabio/vizuizi muhimu kwa usalama**.
2. `match` ya pili hutekeleza **semantiki halisi za instruction**.
3. Discriminant iliyo nje ya masafa hupita kwenye faharasa nje ya jump table ya kwanza na kuelekeza kwenye msimbo unaohusishwa na ya pili.

Matokeo: operesheni bado hutekelezwa, lakini njia ya uhasibu hurukwa. Katika zkVM, hili linaweza kughushi proofs zinazoripoti vipimo visivyowezekana, kama vile gates chache, operesheni chache za gharama kubwa, au rasilimali nyingine zenye vikomo zilizoghushiwa.

Orodha ya ukaguzi:

- Tafuta enums zinazodhibitiwa na mshambuliaji na ambazo zinaserialishwa kutoka kwenye witness/private input.
- Kagua kauli za `match` zinazojirudia kwenye field ileile ya opcode/kind.
- Chukulia mchanganyiko wa `unsafe` + deserialization isiyokagua + dispatch kubwa ya opcode kuwa hatari kubwa.
- Fanya reverse engineering ya binary iliyotolewa inapohitajika; mpangilio wa jump table unaweza kuwa muhimu zaidi kuliko source.

### Vizuizi vya kisemantiki vinavyokosekana katika interpreters zinazoweza kutenduliwa/maalum

Usihakiki usalama wa kumbukumbu pekee; hakiki pia **kanuni za kisemantiki** ambazo proof inapaswa kutekeleza.

Kwa seti za instructions zinazoweza kutenduliwa/zinaofanana na quantum, hakikisha kwamba operands zinazopaswa kutofautiana zinadhibitiwa ili ziwe tofauti kweli. Operesheni ya aina ya Toffoli/CCX inayotekelezwa kama:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

Huwa si salama ikiwa guest haitakataa:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Katika hali hiyo, mpito hupunguzwa kuwa:

```text
q = q ^ (q & q) = 0
```

Hii huunda **primitive ya deterministic reset**, ikivunja dhana za reversibility na kuwezesha computations zisizokusudiwa kwa gharama nafuu. Katika mifumo ya proof inayothibitisha matumizi ya rasilimali, hii inaweza kuwawezesha washambuliaji kutimiza ukaguzi wa utendaji huku wakikwepa modeli ya gharama ambayo verifier anaamini inatekelezwa.

### Mambo ya kujaribu katika mifumo ya ZK

- Fuzz parsers zote za guest kwa encodings za witness/private-input zilizoharibika.
- Hakikisha enum range inathibitishwa kabla ya opcode dispatch.
- Ongeza ukaguzi wa semantic kwa operand aliasing na aina nyingine za maelekezo batili.
- Linganisha counters zilizoripotiwa/za umma na reference implementation huru.
- Kumbuka kwamba proof halali bado inaweza kuthibitisha **kauli isiyo sahihi** ikiwa guest program ina hitilafu.

## Uidhinishaji Unaotegemea Hali

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Unyonyaji wa DeFi/AMM

Ikiwa unatafiti unyonyaji wa vitendo wa DEX na AMM (hooks za Uniswap v4, matumizi mabaya ya rounding/precision, swaps za kuvuka viwango vya threshold zinazokuzwa na flash loan), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa pools zenye uzani wa mali nyingi ambazo huhifadhi virtual balances kwenye cache na zinaweza kuathiriwa wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Uthibitisho wa hisa - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Ufunguo wa Umma na Ufunguo wa Faragha Vimefafanuliwa - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Miamala ya saini nyingi ni nini? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Miamala | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas na ada | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Faragha - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Tumeishinda proof ya Google's ya zero-knowledge proof ya quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Kulinda sarafu za kidijitali za Elliptic Curve dhidi ya udhaifu wa quantum: Makadirio ya rasilimali na hatua za kupunguza hatari (toleo lililorekebishwa)](https://arxiv.org/abs/2603.28846v2)
- [9] [Hifadhi ya proof-of-concept ya Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
