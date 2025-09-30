# Blockchain na Sarafu za Crypto

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** zimetamkwa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanapokutana, zikifanya utekelezaji wa makubaliano kwa njia ya otomatiki bila wadhamini.
- **Decentralized Applications (dApps)** zinajengwa juu ya smart contracts, zikikuja na front-end rafiki kwa mtumiaji na back-end inayoonekana na inayoweza kukaguliwa.
- **Tokens & Coins** zinaeleweka tofauti ambapo coins hutumika kama pesa za kidijitali, wakati tokens zinaonyesha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** zinatoa ufikiaji kwa huduma, na **Security Tokens** zinaonyesha umiliki wa mali.
- **DeFi** ina maana ya Decentralized Finance, ikitoa huduma za kifedha bila mamlaka ya kati.
- **DEX** na **DAOs** zinarejelea Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano zinahakikisha uthibitisho wa muamala kwa usalama na kwa makubaliano kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu za kompyuta kwa ajili ya uthibitisho wa muamala.
- **Proof of Stake (PoS)** inahitaji validators kushikilia kiasi fulani cha tokens, ikipunguza matumizi ya nishati ikilinganishwa na PoW.

## Misingi ya Bitcoin

### Miamala

Miamala ya Bitcoin inahusisha uhamishaji wa fedha kati ya anwani. Miamala inathibitishwa kupitia saini za digital, kuhakikisha kuwa mmiliki wa private key pekee ndiye anaweza kuanzisha uhamishaji.

#### Vipengele Muhimu:

- **Multisignature Transactions** zinahitaji saini nyingi ili kuruhusu muamala.
- Miamala inajumuisha **inputs** (chanzo cha fedha), **outputs** (mahali mafao yataelekezwa), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inakusudia kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, ikituma tu hali ya mwisho kwenye blockchain.

## Wasiwasi wa Faragha wa Bitcoin

Shambulio za faragha, kama **Common Input Ownership** na **UTXO Change Address Detection**, zinatumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha uwasilishaji wa siri kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Njia zinajumuisha biashara kwa pesa taslimu, mining, na kutumia mixers. **CoinJoin** inachanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, wakati **PayJoin** inaficha CoinJoins kama miamala ya kawaida kwa faragha iliyoongezeka.

# Shambulio za Faragha za Bitcoin

# Muhtasari wa Shambulio za Faragha za Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na utambulisho wa watumiaji mara nyingi ni suala la wasiwasi. Hapa ni muhtasari rahisi wa mbinu kadhaa za kawaida kupitia ambazo wadukuzi wanaweza kudhuru faragha ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa kawaida ni nadra kwa inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu unaohusika. Kwa hivyo, **anwani mbili za input katika muamala huo huo mara nyingi huhesabiwa kuwa za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa ni sehemu tu ya UTXO inatumiwa kutumwa kwa anwani nyingine, kilichobaki kinarudi kwa anwani mpya ya change. Waangalizi wanaweza kudhani anwani hii mpya ni ya mtumaji, hivyo kuharibu faragha.

### Mfano

Ili kupunguza hili, huduma za Mixers au kutumia anwani nyingi zinaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, na kufanya kuwa rahisi **kuunganisha anwani na mmiliki wake**.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama grafu, ikifichua muunganisho za watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchambua miamala yenye inputs na outputs nyingi ili kubahatisha ni output gani ni change inayorejea kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza more inputs kunafanya the change output kuwa kubwa kuliko any single input, inaweza kuchanganya the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani zilizotumika tayari na zilizo tupu ili kuzuia this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Miamala isiyo na change ina uwezekano wa kuwa kati ya anwani mbili zinazomilikiwa na mtumiaji mmoja.
- **Round Numbers:** Nambari za mviringo katika muamala zinaashiria kuwa ni malipo, na output isiyekuwa mviringo ina uwezekano wa kuwa the change.
- **Wallet Fingerprinting:** Wallet fingerprinting hutumia mifumo ya kipekee ya uundaji wa miamala tofauti kati ya wallets, kuruhusu wachambuzi kutambua software iliyotumika na pengine anwani ya change.
- **Amount & Timing Correlations:** Kufichua nyakati au kiasi cha miamala kunaweza kufanya miamala kuwa traceable.

## **Traffic Analysis**

Kwa kuangalia trafiki ya mtandao, attackers wanaweza kuunganisha miamala au blocks na anwani za IP, hivyo kuhatarisha faragha ya mtumiaji. Hii ni kweli hasa ikiwa taasisi inafanya kazi nodes nyingi za Bitcoin, ikiongeza uwezo wake wa kufuatilia miamala.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kupitia pesa taslimu.
- **Cash Alternatives**: Kununua gift cards na kubadilishana mtandaoni kwa bitcoin.
- **Mining**: The most private method to earn bitcoins ni kupitia mining, hasa pale inafanywa peke yako kwa sababu mining pools zinaweza kujua anwani ya IP ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kwa nadharia, kuiba bitcoin kunaweza kuwa njia nyingine ya kuipata bila kutambulika, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, mtumiaji anaweza send bitcoins na kupokea different bitcoins kwa kurudishwa, jambo linalofanya iwe vigumu kufuata mmiliki wa awali. Hata hivyo, hii inahitaji kuamini huduma kuwa haitahifadhi logs na kwamba itarudisha bitcoins kwa kweli. Mbinu mbadala za mixing ni pamoja na Bitcoin casinos.

## CoinJoin

CoinJoin inachanganya miamala mingi kutoka kwa watumiaji tofauti kuwa muamala mmoja, na kufanya iwe ngumu kwa yeyote kuoanisha inputs na outputs. Licha ya ufanisi wake, miamala yenye sizes za input na output za kipekee bado zinaweza kufuatiliwa.

Mfano wa miamala ambayo yanaweza kuwa yameutumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa taarifa zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa huduma sawa kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo hufanya miamala isiyotambulika kwa kutumia fedha kutoka kwa miners.

## PayJoin

A variant of CoinJoin, PayJoin (or P2EP), inaficha muamala kati ya wahusika wawili (mfano, mteja na muuzaji) kama muamala wa kawaida, bila outputs sawa za kipekee za CoinJoin. Hii inafanya iwe ngumu sana kugundua na inaweza kubatilisha the common-input-ownership heuristic inayotumiwa na entities za transaction surveillance.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama ile hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikiendelea kuwa haionekani tofauti na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika kutafuta faragha ya miamala.

# Mbinu Bora za Faragha kwa Sarafu za Crypto

## **Wallet Synchronization Techniques**

Ili kudumisha faragha na usalama, kusawazisha wallets na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node inahakikisha faragha ya juu kabisa. Miamala yote iliyofanywa huhifadhiwa kwa ndani, na kuifanya isiwezekane kwa adui kutambua ni miamala au anwani gani mtumiaji anavutiwa nazo.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda vichujio kwa kila block katika blockchain, ikiruhusu wallets kutambua miamala inayohusika bila kufichua maslahi maalum kwa wachunguzi wa mtandao. Lightweight wallets hupakua vichujio hivi, na kuchukua block kamili tu pale patapo kuwa na mechi na anwani za mtumiaji.

## **Utilizing Tor for Anonymity**

Kutokana na Bitcoin kufanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP, kuboresha faragha wakati wa kuingiliana na mtandao.

## **Preventing Address Reuse**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha miamala na kiumbe kimoja. Wallets za kisasa zinachochea kuepuka matumizi ya anwani ya zamani kupitia muundo wao.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, na kuzuwia mashambulizi ya faragha.
- **Change avoidance**: Kuchagua miamala ambazo hazihitaji change outputs kunaboresha faragha kwa kuvuruga mbinu za kugundua change.
- **Multiple change outputs**: Ikiwa kuepuka change haitawezekana, kuzalisha change outputs nyingi bado kunaweza kuboresha faragha.

# **Monero: Mnara wa Usiri**

Monero inashughulikia hitaji la ukimya kamili katika miamala za kidijitali, ikiweka kiwango cha juu kwa faragha.

# **Ethereum: Gas na Miamala**

## **Understanding Gas**

Gas hupima juhudi za kihesabu zinazohitajika kutekeleza operesheni kwenye Ethereum, zilipwa kwa **gwei**. Kwa mfano, muamala wenye gharama 2,310,000 gwei (au 0.00231 ETH) unahusisha gas limit na base fee, pamoja na tip ya kuwahamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi kupita kiasi, na ziada kurudishwa.

## **Executing Transactions**

Miamala kwenye Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Zinahitaji ada na lazima ziminingwe. Taarifa muhimu katika muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit, na ada. Kwa kuzingatia, anwani ya mtumaji inatokana na saini, ikiondoa haja ya kuionyesha katika data ya muamala.

Mazoezi na mifumo hii ni msingi kwa yeyote anayetaka kushiriki na cryptocurrencies huku akikipa kipaumbele faragha na usalama.

## Smart Contract Security

- Mutation testing ili kutafuta maeneo yasiyoonekana katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

Ikiwa unatafiti unyonyaji wa vitendo wa DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
