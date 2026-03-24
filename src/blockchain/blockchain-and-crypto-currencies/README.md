# Blockchain na Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Misingi

- **Smart Contracts** zinasemekana kuwa programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanapotimizwa, zikifanya utekelezaji wa makubaliano kiotomatiki bila madalali.
- **Decentralized Applications (dApps)** zinajengwa juu ya Smart Contracts, zikiwa na front-end rafiki kwa mtumiaji na back-end wazi na inayoweza kukaguliwa.
- **Tokens & Coins** zinatofautishwa ambapo coins hutumika kama pesa za kidijitali, wakati tokens zinaonyesha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** hutoa ufikivu kwa huduma, na **Security Tokens** zinaashiria umiliki wa mali.
- **DeFi** inamaanisha Decentralized Finance, ikitoa huduma za kifedha bila mamlaka za kati.
- **DEX** na **DAOs** zinaashiria Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mekanizimu za Makubaliano

Mekanizimu za makubaliano zinahakikisha uthibitisho wa miamala uliokubalika na salama kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu za kompyuta kwa ajili ya uhakiki wa miamala.
- **Proof of Stake (PoS)** inahitaji validators kumiliki kiasi fulani cha tokens, ikipunguza matumizi ya nishati ikilinganishwa na PoW.

## Misingi ya Bitcoin

### Miamala

Miamala ya Bitcoin inahusisha uhamishaji wa fedha kati ya anwani. Miamala huhakikiwa kupitia saini za kidijitali, kuhakikisha kuwa mmiliki wa private key pekee ndiye anaweza kuanzisha uhamisho.

#### Vipengele Muhimu:

- **Multisignature Transactions** zinahitaji saini nyingi ili kuidhinisha muamala.
- Miamala ina jumla ya **inputs** (chanzo cha fedha), **outputs** (mahali pa kwenda), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, na kutangaza tu hali ya mwisho kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Mashambulizi ya faragha, kama **Common Input Ownership** na **UTXO Change Address Detection**, hutumia mifumo ya miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha usiri kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins kwa siri

Njia zinajumuisha biashara kwa pesa taslimu, mining, na kutumia mixers. **CoinJoin** huunganisha miamala mingi ili kufanya ufuatiliaji kuwa mgumu, wakati **PayJoin** unaficha CoinJoins kama miamala ya kawaida kwa usiri ulioboreshwa.

# Bitcoin Privacy Shambulizi

# Muhtasari wa Mashambulizi ya Faragha ya Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na ujasis wa watumiaji mara nyingi ni jambo la wasiwasi. Hapa kuna muhtasari uliorahisishwa wa mbinu kadhaa za kawaida ambazo wadukuzi wanaweza kutumia kuingilia faragha ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa ujumla ni nadra kwa inputs kutoka kwa watumiaji tofauti kuunganishwa katika muamala mmoja kutokana na ugumu unaohusika. Hivyo, **anwani mbili za input katika muamala huo mara nyingi huhesabiwa kuwa za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike kikamilifu katika muamala. Ikiwa sehemu tu imepelekwa kwa anwani nyingine, salio litasogezwa kwenda kwa anwani mpya ya change. Waangalizi wanaweza kudhani kuwa anwani hii mpya ni ya mtumaji, hivyo kuathiri faragha.

### Mfano

Kupunguza hili, huduma za mixing au kutumia anwani nyingi zinaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushare anwani zao za Bitcoin mtandaoni, na kufanya iwe rahisi kuunganisha anwani na mmiliki wake.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama grafu, ikifichua muunganisho kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristiki hii inategemea uchambuzi wa miamala yenye inputs na outputs nyingi ili kubashiri ni output ipi ni change inayorudishwa kwa mtumaji.

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

- **Exact Payment Amounts:** Transactions without change are likely between two addresses owned by the same user.
- **Round Numbers:** A round number in a transaction suggests it's a payment, with the non-round output likely being the change.
- **Wallet Fingerprinting:** Different wallets have unique transaction creation patterns, allowing analysts to identify the software used and potentially the change address.
- **Amount & Timing Correlations:** Disclosing transaction times or amounts can make transactions traceable.

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
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**The utilization of PayJoin could significantly disrupt traditional surveillance methods**, making it a promising development in the pursuit of transactional privacy.

# Mazoea Bora kwa Faragha katika Sarafu za Kripto

## **Wallet Synchronization Techniques**

Ili kudumisha faragha na usalama, kusawazisha wallet na blockchain ni muhimu. Mbinu mbili zinajitokeza:

- **Full node**: Kwa kupakua blockchain yote, full node inahakikisha faragha kwa kiwango cha juu. Miamala yote iliyofanywa huhifadhiwa kwa ndani, na kuifanya isiwezekane kwa wapinzani kutambua ni miamala au anwani gani mtumiaji anavutiwa nayo.
- **Client-side block filtering**: Mbinu hii inajumuisha kutengeneza vichujio kwa kila block kwenye blockchain, kuruhusu wallets kutambua miamala inayofaa bila kufichua maslahi maalum kwa watazamaji wa mtandao. Wallet nyepesi hupakua vichujio hivi, wakichukua blocks kamili tu wakati kuna mechi na anwani za mtumiaji.

## **Utilizing Tor for Anonymity**

Kwa kuwa Bitcoin inafanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuificha anwani yako ya IP, kuboresha faragha wakati wa kuingiliana na mtandao.

## **Preventing Address Reuse**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuharibu faragha kwa kuunganisha miamala na entiti moja. Wallet za kisasa zinapinga matumizi ya anwani tena kupitia muundo wao.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Kugawa malipo kwa miamala kadhaa kunaweza kuficha kiasi cha muamala, na kuzuia mashambulizi ya faragha.
- **Change avoidance**: Kuchagua miamala ambazo hazihitaji change outputs kunaboresha faragha kwa kuvuruga mbinu za kugundua change.
- **Multiple change outputs**: Ikiwa kuepuka change haiwezekani, kuzalisha multiple change outputs bado kunaweza kuboresha faragha.

# **Monero: A Beacon of Anonymity**

Monero inashughulikia haja ya usiri wa kutosha katika miamala ya dijitali, ikiweka kiwango cha juu kwa faragha.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas hupima jitihada za kihisabati zinazohitajika kutekeleza operesheni kwenye Ethereum, zikilipwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) unajumuisha gas limit na base fee, pamoja na tip kwa kuwahamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi zaidi ya inner, na ziada kurudishwa.

## **Executing Transactions**

Miamala kwenye Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Zinahitaji ada na lazima ziminywe. Taarifa muhimu kwenye muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit, na ada. Inafaa kutambua kuwa anwani ya mtumaji hutokana na saini, hivyo haidiwi ijazwe ndani ya data ya muamala.

Haya mazoea na mifumo ni msingi kwa yeyote anayetaka kushiriki na sarafu za kripto huku akiweka kipaumbele faragha na usalama.

## Value-Centric Web3 Red Teaming

- Fanya karatasi ya components zinazoleta thamani (signers, oracles, bridges, automation) ili kuelewa nani anaweza kusogeza fedha na kwa jinsi gani.
- Ramani kila component kwa MITRE AADAPT tactics inayofaa ili kufichua njia za kupandisha vibali (privilege escalation).
- Fanya mazoezi ya mnyororo wa mashambulizi ya flash-loan/oracle/credential/cross-chain ili kuthibitisha athari na kuandika vigezo vinavyoweza kutumika.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering ya wallet UIs inaweza kubadilisha EIP-712 payloads kabla ya kusaini, ikikusanya saini halali kwa delegatecall-based proxy takeovers (mfano, slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Mbinu za kawaida za kushindwa kwa smart-account zinajumuisha kupitisha EntryPoint access control, unsigned gas fields, stateful validation, ERC-1271 replay, na fee-drain kupitia revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing ili kupata maeneo yasiyoonekana vizuri ndani ya test suites:

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

Ikiwa unatafiti matumizi ya vitendo ya kuExploit DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa pools zenye uzito wa mali nyingi ambazo zinahifadhi virtual balances na zinaweza kuchomwa (poisoned) wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
