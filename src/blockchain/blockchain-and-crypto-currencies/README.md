# Blockchain na Sarafu za Kripto

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** zinafafanuliwa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanapotimizwa, zikiautomate utekelezaji wa makubaliano bila wahusika wa kati.
- **Decentralized Applications (dApps)** zinajengwa juu ya Smart Contracts, zikiwa na front-end rafiki kwa mtumiaji na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** zinatofautishwa kwa kuwa coins hutumika kama pesa za kidigitali, wakati tokens zinaonyesha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** zinatoa ufikiaji wa huduma, na **Security Tokens** zinataja umiliki wa mali.
- **DeFi** inamaanisha Decentralized Finance, ikitoa huduma za kifedha bila mamlaka ya kati.
- **DEX** na **DAOs** zinarejelea Majukwaa ya Kubadilishia Yasiyo ya Kati na Mashirika ya Kujiendesha Yasiyo ya Kati, mtawalia.

## Consensus Mechanisms

Mekanism za makubaliano zinahakikisha uthibitisho salama na uliokubaliwa wa miamala kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu ya kompyuta kwa ajili ya uhakiki wa miamala.
- **Proof of Stake (PoS)** inahitaji validators kumiliki kiasi fulani cha tokens, ikipunguza matumizi ya nishati ukilinganisha na PoW.

## Misingi ya Bitcoin

### Transactions

Miamala ya Bitcoin inahusisha uhamisho wa fedha kati ya anwani. Miamala inathibitishwa kupitia sahihi za kidigitali, kuhakikisha kwamba mmiliki pekee wa funguo binafsi anaweza kuanzisha uhamisho.

#### Vipengele Muhimu:

- **Multisignature Transactions** zinahitaji sahihi nyingi ili kutoa idhini ya muamala.
- Miamala inaangukia katika **inputs** (chanzo cha fedha), **outputs** (mahali pa kwenda), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, ikitangaza tu hali ya mwisho kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama **Common Input Ownership** na **UTXO Change Address Detection**, hunufaika na mifumo ya muamala. Mikakati kama **Mixers** na **CoinJoin** huboresha ufiwa wa siri kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kutambulika

Njia ni pamoja na biashara kwa pesa taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, wakati **PayJoin** inaficha CoinJoins kama miamala ya kawaida kwa faragha iliyoongezeka.

# Shambulio za Faragha za Bitcoin

# Muhtasari wa Shambulio za Faragha za Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi ni vigezo vinavyotatizwa. Hapa kuna muhtasari uliorahisishwa wa baadhi ya mbinu za kawaida ambazo washambuliaji wanaweza kutumia kuvuruga faragha ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa ujumla ni nadra kwa inputs kutoka kwa watumiaji tofauti kuchanganywa katika muamala mmoja kutokana na ugumu unaoshirikishwa. Kwa hivyo, **anwani mbili za input katika muamala mmoja mara nyingi huhesabiwa kuwa zinamtambulisha mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu tu yake inatumwa kwenye anwani nyingine, salio linalobaki hupelekwa kwenye anwani mpya ya change. Waangalizi wanaweza kubaini kwamba anwani hiyo mpya inamtambulisha mtumaji, hivyo kudhoofisha faragha.

### Mfano

Ili kupunguza hili, huduma za kuchanganya (mixing) au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, na kuifanya iwe rahisi **kuunganisha anwani na mmiliki wake**.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama grafu, ikifichua muunganiko zinazowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchambua miamala yenye inputs na outputs nyingi ili kutabiri ni output gani ni change inayorudi kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza inputs zaidi kunafanya change output kuwa kubwa kuliko input yoyote moja, inaweza kuchanganya heuristic.

## **Forced Address Reuse**

Washambuliaji wanaweza kutuma kiasi kidogo kwa addresses zilizotumika hapo awali, wakitumai mpokeaji atasanganisha hizi na inputs nyingine katika transactions zijazo, na hivyo kuunganisha addresses pamoja.

### Correct Wallet Behavior

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwa addresses zilizotumika tayari na zilizo tupu ili kuzuia privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions bila change zina uwezekano kuwa kati ya addresses mbili zinazomilikiwa na mtumiaji mmoja.
- **Round Numbers:** Namba za mviringo katika transaction zinaonyesha ni payment, ambapo output isiyo-round ina uwezekano kuwa change.
- **Wallet Fingerprinting:** Wallets tofauti zina mifumo ya kipekee ya kuunda transactions, ikimruhusu mchambuzi kutambua software iliyotumika na pengine change address.
- **Amount & Timing Correlations:** Kufichua transaction times au amounts kunaweza kufanya transactions ziweze kufuatiliwa.

## **Traffic Analysis**

Kwa kufuatilia network traffic, washambuliaji wanaweza kuunganisha transactions au blocks na IP addresses, kukiuka faragha ya watumiaji. Hii hasa ni kweli ikiwa entiti inaendesha node nyingi za Bitcoin, ikiongeza uwezo wao wa kufuatilia transactions.

## More

Kwa orodha kamili ya privacy attacks na defenses, tembelea [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kupitia pesa taslimu.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia yenye faragha zaidi ya kupata bitcoins ni kupitia mining, hasa pale inapo fanywa peke yako kwa sababu mining pools zinaweza kujua IP address ya mchimbaji. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kivitendo, kuiba bitcoin inaweza kuwa njia nyingine ya kuipata bila kutambulika, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, mtumiaji anaweza send bitcoins na kupokea different bitcoins kwa kurudishwa, jambo linalofanya kuwa vigumu kufuatilia mmiliki wa awali. Hata hivyo, hii inahitaji kuwa na imani kwa huduma hiyo isitoe logs na kwamba itarudisha bitcoins kwa kweli. Chaguzi nyingine za kuchanganya ni pamoja na Bitcoin casinos.

## CoinJoin

CoinJoin inaunganisha multiple transactions kutoka kwa watumiaji tofauti kuwa moja, ikiyafanya iwe ngumu kwa yeyote kuoanisha inputs na outputs. Licha ya ufanisi wake, transactions zenye ukubwa wa kipekee wa input na output bado zinaweza kufuatiliwa.

Mifano ya transactions ambazo huenda zilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Kwa habari zaidi, tembelea [CoinJoin](https://coinjoin.io/en). Kwa huduma inayofanana kwenye Ethereum, angalia [Tornado Cash](https://tornado.cash), ambayo inaanonymize transactions kwa fedha kutoka kwa miners.

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), linaficha transaction kati ya pande mbili (mfano, mteja na mfanyabiashara) kama transaction ya kawaida, bila outputs sawa zinazotambulika za CoinJoin. Hii inafanya iwe ngumu sana kugundua na inaweza kuharibu common-input-ownership heuristic inayotumika na vyombo vinavyofuatilia transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama ilivyo hapo juu zinaweza kuwa PayJoin, zikiboresha faragha huku zikiwa hazitambuliki kwa miamala ya bitcoin ya kawaida.

**Matumizi ya PayJoin yanaweza kuathiri kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika harakati za faragha ya miamala.

# Mbinu Bora za Faragha katika Sarafu za Kidijitali

## **Wallet Synchronization Techniques**

Ili kudumisha faragha na usalama, kusawazisha wallets na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain nzima, full node inahakikisha faragha ya juu kabisa. Miamala yote iliyofanywa huhifadhiwa kwa ndani, na hivyo kuifanya iwe haiwezekani kwa maadui kubaini ni miamala gani au anwani zipi mtumiaji anavutiwa nazo.
- **Client-side block filtering**: Mbinu hii inajumuisha kuunda filters kwa kila block katika blockchain, ikimruhusu wallet kutambua miamala zinazohusiana bila kufichua maslahi maalum kwa wachunguzi wa mtandao. Lightweight wallets hupakua filters hizi, zikichukua full blocks tu wakati kuna mechi na anwani za mtumiaji.

## **Utilizing Tor for Anonymity**

Kwa kuwa Bitcoin inaendesha kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP, hivyo kuongeza faragha wakati wa kuingiliana na mtandao.

## **Preventing Address Reuse**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia anwani tena kunaweza kudhoofisha faragha kwa kuunganisha miamala na kiumbe kimoja. Wallets za kisasa zinahimiza kuepuka matumizi ya anwani tena kwa muundo wao.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Kugawa malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, kuzuia mashambulizi ya faragha.
- **Change avoidance**: Kuchagua miamala isiyohitaji change outputs kunaboresha faragha kwa kuvuruga mbinu za kugundua change.
- **Multiple change outputs**: Ikiwa kuepuka change haiwezekani, kuunda change outputs nyingi bado kunaweza kuboresha faragha.

# **Monero: A Beacon of Anonymity**

Monero inashughulikia haja ya kutofahamika kabisa katika miamala za kidijitali, ikiweka kiwango cha juu cha faragha.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas hupima kazi ya kihesabu inayohitajika kutekeleza operesheni kwenye Ethereum, iliyopimwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) unahusisha gas limit na base fee, pamoja na tip ili kuwahamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi zaidi, na ziada kurejeshwa.

## **Executing Transactions**

Miamala katika Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au za smart contract. Zinahitaji ada na lazima zichimbwe. Taarifa muhimu katika muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit, na ada. Vilevile, anwani ya mtumaji hutokana na saini, hivyo sihitajike kuwa imejumuishwa katika data ya muamala.

Mazoezi na mifumo hii ni msingi kwa yeyote anayetaka kushiriki katika sarafu za kidijitali huku akikipa kipaumbele faragha na usalama.

## Marejeo

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

Ikiwa unatafiti practical exploitation ya vitendo ya DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
