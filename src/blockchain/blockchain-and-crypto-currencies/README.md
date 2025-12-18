# Blockchain na Sarafu za Crypto

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** huainishwa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanapotimizwa, zikitekeleza makubaliano moja kwa moja bila wasimamizi wa kati.
- **Decentralized Applications (dApps)** zinajengwa juu ya Smart Contracts, zikiwa na mbele inayomfaa mtumiaji na back-end iliyo wazi na inayoweza ukaguzi.
- **Tokens & Coins** zinatofautiana ambapo coins hutumika kama fedha za kidijitali, wakati tokens zinawakilisha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** huruhusu upatikanaji wa huduma, na **Security Tokens** zinaonyesha umiliki wa mali.
- **DeFi** inamaanisha Decentralized Finance, ikitoa huduma za kifedha bila mamlaka za kati.
- **DEX** na **DAOs** zinarejea kwa Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano zinahakikisha uthibitisho salama na uliokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu za kompyuta kwa ajili ya uhakiki wa miamala.
- **Proof of Stake (PoS)** inahitaji validators kumiliki kiasi fulani cha tokens, hivyo kupunguza matumizi ya nishati ikilinganishwa na PoW.

## Misingi ya Bitcoin

### Miamala

Miamala ya Bitcoin inahusisha kuhamisha fedha kati ya anwani. Miamala inathibitishwa kwa kutumia saini za kidijitali, kuhakikisha kuwa mmiliki wa private key pekee ndiye anaweza kuanzisha uhamishaji.

#### Vipengele Muhimu:

- **Multisignature Transactions** zinahitaji saini nyingi ili kuidhinisha muamala.
- Miamala ina vipengele vya **inputs** (chanzo cha fedha), **outputs** (mahali pa kwenda), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, na kutangaza tu hali ya mwisho kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha usiri kwa kuficha viunganishi vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Njia ni pamoja na biashara kwa pesa taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, wakati **PayJoin** inaficha CoinJoins kama miamala ya kawaida kwa ajili ya faragha zaidi.

# Mashambulizi ya Faragha ya Bitcoin

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika dunia ya Bitcoin, faragha ya miamala na usiri wa watumiaji mara nyingi ni chanzo cha wasiwasi. Hapa kuna muhtasari wa njia kadhaa za kawaida ambazo washambuliaji wanaweza kutumia kudhoofisha faragha ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa ujumla ni nadra kwa inputs kutoka kwa watumiaji tofauti kuchanganywa katika muamala mmoja kutokana na ugumu wa mchakato. Kwa hivyo, **anwani mbili za input katika muamala uleule mara nyingi huhukumiwa kuwa ni za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu tu ya UTXO imetumwa kwa anwani nyingine, sehemu inayobaki inaenda kwa anwani mpya ya mabadiliko. Waangalizi wanaweza kudhani kuwa anwani mpya ni ya mtumaji, hivyo kudhoofisha faragha.

### Mfano

Kupunguza hili, huduma za kuchanganya au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, na kufanya iwe rahisi kuunganisha anwani na mmiliki wake.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama grafu, ikifichua uhusiano unaowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchambua miamala yenye inputs na outputs nyingi ili kubahatisha ni output gani ni change inayorudishwa kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza zaidi inputs kunafanya the change output kuwa kubwa kuliko any single input, inaweza kuchanganya the heuristic.

## **Forced Address Reuse**

Washambuliaji wanaweza kutuma kiasi kidogo kwa addresses zilizotumika hapo awali, wakitumai mpokeaji atawaunganisha na inputs nyingine katika transactions za baadaye, na kwa hivyo kuunganisha addresses pamoja.

### Tabia Sahihi ya Wallet

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye addresses ambazo tayari zimetumika na ni empty, ili kuzuia this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions bila change huenda zinatokea kati ya addresses mbili zinazomilikiwa na mtumiaji mmoja.
- **Round Numbers:** Round number katika transaction inaashiria kuwa ni malipo, na output isiyo-round ina uwezekano kuwa change.
- **Wallet Fingerprinting:** Wallets tofauti zinao patterns za uundaji wa transactions, ikiruhusu wachambuzi kutambua software iliyotumika na kwa uwezekano change address.
- **Amount & Timing Correlations:** Kufichua transaction times au amounts kunaweza kufanya transactions ziweze kufuatiliwa.

## **Traffic Analysis**

Kwa kusimamia network traffic, washambuliaji wanaweza kuunganisha transactions au blocks na IP addresses, hivyo kuathiri user privacy. Hii ni hasa kweli ikiwa shirika linaendesha Bitcoin nodes nyingi, na hivyo kuongeza uwezo wao wa kufuatilia transactions.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Muamala za Bitcoin Bila Kutambulika

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kwa kutumia cash.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia ya siri zaidi ya kupata bitcoins ni kupitia mining, hasa ukiifanya peke yako kwa sababu mining pools yanaweza kujua IP address ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kwa nadharia, kuiba bitcoin inaweza kuwa njia nyingine ya kuipata bila kutambulika, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, mtumiaji anaweza **send bitcoins** na kupokea **different bitcoins in return**, jambo ambalo linafanya kufuatilia mmiliki wa awali kuwa vigumu. Hata hivyo, hili linahitaji kuamini huduma hiyo kuwa haitahifadhi logs na kwamba itarejesha bitcoins kwa hakika. Chaguo mbadala za mixing ni pamoja na Bitcoin casinos.

## CoinJoin

CoinJoin inaunganisha transactions nyingi kutoka kwa watumiaji tofauti kuwa moja, ikifanya mchakato kuwa mgumu kwa yeyote anayetaka kulinganisha inputs na outputs. Licha ya ufanisi wake, transactions zenye ukubwa wa input na output wa kipekee bado zinaweza kufuatiliwa.

Mifano ya transactions ambazo zinaweza kuwa zimetumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa taarifa zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa huduma kama hiyo kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo hufanya transactions kuwa za kutojulikana kwa kutumia fedha kutoka kwa miners.

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), linavificha transaction kati ya pande mbili (mfano, mteja na muuzaji) kama transaction ya kawaida, bila outputs sawa zinazotambulika za CoinJoin. Hii inafanya iwe vigumu sana kugundua na inaweza kuharibu common-input-ownership heuristic inayotumika na vyombo vinavyofuatilia transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# Mazoea Bora kwa Usiri katika Sarafu za Kripto

## **Mbinu za Kulinganisha Pochi**

Ili kudumisha usiri na usalama, kulinganisha pochi na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node inahakikisha usiri mkubwa. Miamala yote iliyofanywa huhifadhiwa kwa njia ya ndani, na kufanya iwe vigumu kwa wapinzani kubaini ni miamala au anwani gani mtumiaji anaiangalia.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda vichujio kwa kila block kwenye blockchain, ikiruhusu pochi kubaini miamala inayohusiana bila kufichua maslahi maalum kwa walioangalia mtandao. Lightweight wallets hupakua vichujio hivi, zikipakua blocks kamili tu wakati kuna mlinganisho na anwani za mtumiaji.

## **Kutumia Tor kwa Kutofahamika**

Kwa kuwa Bitcoin inafanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP, kuboresha usiri wakati wa kuingiliana na mtandao.

## **Kuzuia Kutumika Tena kwa Anwani**

Ili kulinda usiri, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha usiri kwa kuunganisha miamala na kiumbe kimoja. Wallets za kisasa zinatilia shaka matumizi ya anwani mara nyingi kupitia muundo wao.

## **Mikakati ya Usiri wa Muamala**

- **Multiple transactions**: Kugawanya malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, kuzuia mashambulizi ya usiri.
- **Change avoidance**: Kuchagua miamala ambayo hayahitaji change outputs kunaboresha usiri kwa kuvuruga mbinu za kugundua change.
- **Multiple change outputs**: Ikiwa kuepuka change haiwezekani, kuzalisha multiple change outputs bado kunaweza kuboresha usiri.

# **Monero: Mwanga wa Kutofahamika**

Monero inashughulikia haja ya kutofahamika kabisa katika miamala ya kidijitali, ikiweka viwango vya juu vya usiri.

# **Ethereum: Gas na Miamala**

## **Kuelewa Gas**

Gas hupima jitihada za kihesabu zinazohitajika kutekeleza shughuli kwenye Ethereum, na inauzwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) unajumuisha gas limit na base fee, pamoja na tip kwa kuwahamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipii ziada, na ziada kurudishwa.

## **Kutekeleza Miamala**

Miamala kwenye Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za watumiaji au smart contract. Zinahitaji ada na lazima zichimbwe. Taarifa muhimu katika muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit, na ada. Kwa ujumla, anwani ya mtumaji hutambuliwa kutoka kwa saini, hivyo haitakiwi kuingizwa katika data ya muamala.

Haya mazoea na mifumo ni msingi kwa yeyote anayetaka kuingiliana na sarafu za kripto huku akiweka kipaumbele kwenye usiri na usalama.

## Value-Centric Web3 Red Teaming

- Orodhesha sehemu zinazoleta thamani (signers, oracles, bridges, automation) ili kuelewa nani anaweza kusogeza fedha na jinsi.
- Ramisha kila sehemu kwa mbinu zinazofaa za MITRE AADAPT ili kufichua njia za kuongeza mamlaka.
- Fanyeni mazoezi ya mnyororo wa mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kuandika masharti yanayoweza kutumika.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutation testing ili kupata sehemu zisizoonekana katika test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Marejeo

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
