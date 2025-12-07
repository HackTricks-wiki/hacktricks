# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Misingi

- **Smart Contracts** hufafanuliwa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanapotimizwa, zikiautomatisha utekelezaji wa makubaliano bila wadala.
- **Decentralized Applications (dApps)** zinajengwa juu ya smart contracts, zikiwa na front-end rahisi kwa mtumiaji na back-end iliyo wazi na inayoweza kukaguliwa.
- **Tokens & Coins** zinatofautishwa ambapo coins hutumika kama pesa za kidigitali, wakati tokens zinawakilisha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** zinatoa ufikiaji wa huduma, na **Security Tokens** zinaashiria umiliki wa mali.
- **DeFi** inasimama kwa Decentralized Finance, inayo toa huduma za kifedha bila mamlaka za kati.
- **DEX** na **DAOs** zinarejea kwa Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mekanizimu za Makubaliano

Mekanizimu za makubaliano zinahakikisha usalama na uthibitisho wa miamala kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu za kompyuta kwa ajili ya uthibitisho wa miamala.
- **Proof of Stake (PoS)** inahitaji validators kuwa na kiasi fulani cha tokens, kupunguza matumizi ya nishati ikilinganishwa na PoW.

## Misingi ya Bitcoin

### Miamala

Miamala ya Bitcoin inahusisha kuhamisha fedha kati ya anwani. Miamala inathibitishwa kupitia saini za dijitali, kuhakikisha kwamba mmiliki wa private key pekee ndiye anaweza kuanzisha uhamisho.

#### Vipengele Muhimu:

- **Multisignature Transactions** zinahitaji saini nyingi ili kuidhinisha muamala.
- Miamala ina **inputs** (chanzo cha fedha), **outputs** (mahali pa kwenda), **fees** (zinazolipwa kwa miners), na **scripts** (sheria za muamala).

### Lightning Network

Inalenga kuboresha uwezo wa Bitcoin kwa kuruhusu miamala mingi ndani ya channel, ikitangaza tu hali ya mwisho kwenye blockchain.

## Waswasi wa Faragha wa Bitcoin

Mashambulizi ya faragha, kama **Common Input Ownership** na **UTXO Change Address Detection**, yanatumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha usiri kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kujulikana

Njia ni pamoja na biashara ya cash, kuchimba (mining), na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji kuwa mgumu, wakati **PayJoin** inaficha CoinJoins kama miamala ya kawaida kwa faragha iliyoongezeka.

# Bitcoin Privacy Atacks

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na utambulisho wa watumiaji mara nyingi ni sababu za wasiwasi. Hapa kuna muhtasari rahisi wa njia kadhaa za kawaida ambazo washambuliaji wanaweza kuathiri faragha ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa ujumla ni nadra kwa inputs kutoka kwa watumiaji tofauti kuchanganywa katika muamala mmoja kutokana na ugumu unaohusika. Kwa hivyo, **anachukuliwa mara nyingi kuwa anwani mbili za input katika muamala mmoja zinamilikiwa na mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike kikamilifu katika muamala. Ikiwa sehemu tu ya UTXO inatumwa kwa anwani nyingine, kiasi kilichobaki kinaenda kwenye anwani mpya ya change. Wachunguzi wanaweza kudhani anwani hii mpya ni ya mtumaji, hivyo kuingilia faragha.

### Mfano

Ili kupunguza hili, huduma za kuchanganya (mixing) au kutumia anwani nyingi zinaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, na kufanya iwe rahisi **kuunganisha anwani na mmiliki wake**.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama grafu, ikifichua muunganiko inayoweza kuwepo kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchambua miamala yenye inputs na outputs nyingi ili kubahatisha ni output gani ni change inarudishwa kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Miamala isiyokuwa na change inaonekana kuwa kati ya anwani mbili zinazomilikiwa na mtumiaji mmoja.
- **Round Numbers:** Nambari za mduara katika muamala zinaashiria kuwa ni malipo, na output isiyo ya mduara ina uwezekano kuwa change.
- **Wallet Fingerprinting:** Nafasi tofauti za utengenezaji miamala za wallets zinaweza kumsaidia mchambuzi kubaini software inayotumika na pengine anwani ya change.
- **Amount & Timing Correlations:** Kufichua nyakati za muamala au kiasi kunaweza kufanya miamala iwekwe njia ya kufuatiliwa.

## **Traffic Analysis**

By monitoring network traffic, attackers can potentially link transactions or blocks to IP addresses, compromising user privacy. This is especially true if an entity operates many Bitcoin nodes, enhancing their ability to monitor transactions.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** merges multiple transactions from different users into one, complicating the process for anyone trying to match inputs with outputs. Despite its effectiveness, transactions with unique input and output sizes can still potentially be traced.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama ile hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki isioweza kutofautishwa na miamala ya kawaida za Bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za jadi za ufuatiliaji**, na kuifanya kuwa maendeleo yenye matumaini katika jitihada za kupata faragha ya miamala.

# Mbinu Bora za Faragha katika Sarafu za Kidijitali

## **Wallet Synchronization Techniques**

Ili kudumisha faragha na usalama, kusawazisha wallets na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain yote, full node huhakikishia faragha ya juu kabisa. Miamala yote iliyofanywa huhifadhiwa kwa ndani, ikifanya isiwezekane kwa wapinzani kutambua ni miamala gani au anwani gani mtumiaji anavutiwa nazo.
- **Client-side block filtering**: Mbinu hii inahusisha kuunda vichujio kwa kila block ndani ya blockchain, ikiruhusu wallets kutambua miamala muhimu bila kufichua maslahi maalum kwa watazamaji wa mtandao. Wallets nyepesi hupakua vichujio hivi, na kuchukua blocks kamili tu wakati patokanapo na anwani za mtumiaji.

## **Utilizing Tor for Anonymity**

Kwa kuwa Bitcoin inafanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP, hivyo kuboresha faragha wakati wa kuingiliana na mtandao.

## **Preventing Address Reuse**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia anwani tena kunaweza kuhatarisha faragha kwa kuunganisha miamala na chombo kimoja. Wallets za kisasa zinaepuka matumizi ya anwani mara kwa mara kupitia muundo wao.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Kugawa malipo katika miamala kadhaa kunaweza kuficha kiasi cha muamala, na kukwamisha mashambulizi ya faragha.
- **Change avoidance**: Kuchagua miamala ambazo hazihitaji change outputs huongeza faragha kwa kuvuruga mbinu za utambuzi wa change.
- **Multiple change outputs**: Iwapo kuepuka change hawezekani, kuzalisha multiple change outputs bado kunaweza kuboresha faragha.

# **Monero: A Beacon of Anonymity**

Monero inashughulikia haja ya kutokujulikana kabisa katika miamala ya kidijitali, ikiweka kiwango cha juu cha faragha.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas hupima juhudi za kihesabu zinazohitajika kutekeleza operesheni kwenye Ethereum, na bei yake iko katika **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) unajumuisha gas limit na base fee, pamoja na tip ili kuwahamasisha miners. Watumiaji wanaweza kuweka max fee kuhakikisha hawalipi kupita kiasi, na ziada ikarudishwa.

## **Executing Transactions**

Miamala kwenye Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za watumiaji au za smart contract. Zinahitaji ada na lazima ziminingwe. Taarifa muhimu katika muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit, na ada. Kwa kutambuliwa, anwani ya mtumaji hutolewa kutokana na saini, ikifanya isihitajike kuwa kwenye data ya muamala.

Mazoezi na mekanisimu hizi ni misingi kwa yeyote anayetaka kushiriki na sarafu za kidijitali huku akiipa kipaumbele faragha na usalama.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

Ikiwa unatafiti uvunjaji wa vitendo wa DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa pools zenye mali nyingi za uzito ambazo zinahifadhi virtual balances na zinaweza kuathiriwa (poisoned) wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
