# Blockchain na Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Dhana za Msingi

- **Smart Contracts** zimetamkwa kama programu zinazotekelezwa kwenye blockchain wakati masharti fulani yanapotimizwa, zikiautomate utekelezaji wa makubaliano bila watu wa kati.
- **Decentralized Applications (dApps)** zinajengwa juu ya Smart Contracts, zikiwa na kiolesura cha mtumiaji rafiki na back-end wazi, inayoweza kukaguliwa.
- **Tokens & Coins** hutofautishwa ambapo coins hutumika kama fedha za kidijitali, wakati tokens zinawakilisha thamani au umiliki katika muktadha maalum.
- **Utility Tokens** hutoa ufikiaji kwa huduma, na **Security Tokens** zinaashiria umiliki wa mali.
- **DeFi** inamaanisha Decentralized Finance, ikitoa huduma za kifedha bila mamlaka kuu.
- **DEX** na **DAOs** zinarejea kwa Decentralized Exchange Platforms na Decentralized Autonomous Organizations, mtawalia.

## Mbinu za Makubaliano

Mbinu za makubaliano zinahakikisha miamala inathibitishwa kwa usalama na kwa makubaliano kwenye blockchain:

- **Proof of Work (PoW)** inategemea nguvu za kimakosa kwa uhakiki wa miamala.
- **Proof of Stake (PoS)** inahitaji validators kushikilia kiasi fulani cha tokens, ikipunguza matumizi ya nishati ikilinganishwa na PoW.

## Misingi ya Bitcoin

### Miamala

Miamala ya Bitcoin inahusisha kuhamisha fedha kati ya anwani. Miamala inathibitishwa kupitia saini za kidijitali, kuhakikisha kuwa mmiliki wa private key pekee ndiye anaweza kuanzisha uhamishaji.

#### Vipengele Muhimu:

- **Multisignature Transactions** zinahitaji saini nyingi ili kuidhinisha muamala.
- Miamala inajumuisha **inputs** (chanzo cha fedha), **outputs** (mahali pa kwenda), **fees** (zinazolipwa kwa miners), na **scripts** (kanuni za muamala).

### Lightning Network

Inalenga kuboresha scalability ya Bitcoin kwa kuruhusu miamala mingi ndani ya channel, ikitangaza tu hali ya mwisho kwenye blockchain.

## Masuala ya Faragha ya Bitcoin

Privacy attacks, kama **Common Input Ownership** na **UTXO Change Address Detection**, hutumia muundo wa miamala. Mikakati kama **Mixers** na **CoinJoin** huboresha anonymity kwa kuficha viungo vya miamala kati ya watumiaji.

## Kupata Bitcoins Bila Kuitambulisha

Njia ni pamoja na biashara kwa pesa taslimu, mining, na kutumia mixers. **CoinJoin** huchanganya miamala mingi ili kufanya ufuatiliaji mgumu, wakati **PayJoin** huficha CoinJoins kama miamala ya kawaida kwa faragha iliyoongezwa.

# Shambulio za Faragha za Bitcoin

# Muhtasari wa Shambulio za Faragha za Bitcoin

Katika ulimwengu wa Bitcoin, faragha ya miamala na kutokujulikana kwa watumiaji mara nyingi ni jambo la wasiwasi. Hapa kuna muhtasari uliorahisishwa wa mbinu kadhaa za kawaida ambazo wawindaji wanaweza kutumia kuvunja faragha ya Bitcoin.

## **Common Input Ownership Assumption**

Kwa ujumla ni nadra kwa inputs kutoka kwa watumiaji tofauti kuchanganywa katika muamala mmoja kutokana na ugumu unaohusika. Hivyo, **anwani mbili za input katika muamala huo huo mara nyingi huhesabiwa kuwa za mmiliki mmoja**.

## **UTXO Change Address Detection**

UTXO, au **Unspent Transaction Output**, lazima itumike yote katika muamala. Ikiwa sehemu tu ya UTXO inatumwa kwa anwani nyingine, mabaki yaenda kwa anwani mpya ya change. Wachunguzi wanaweza kudhani anwani hii mpya ni ya mtumaji, hivyo kuathiri faragha.

### Mfano

Kupunguza hili, huduma za kuchanganya au kutumia anwani nyingi kunaweza kusaidia kuficha umiliki.

## **Social Networks & Forums Exposure**

Watumiaji wakati mwingine hushiriki anwani zao za Bitcoin mtandaoni, kufanya iwe rahisi kuhusisha anwani na mmiliki wake.

## **Transaction Graph Analysis**

Miamala inaweza kuonyeshwa kama grafu, ikifunua uhusiano unaowezekana kati ya watumiaji kulingana na mtiririko wa fedha.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Heuristic hii inategemea kuchambua miamala yenye inputs na outputs nyingi ili kubahatisha ni output gani ni change inayorudi kwa mtumaji.

### Mfano
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Ikiwa kuongeza ingizo zaidi kunafanya output ya change kuwa kubwa kuliko ingizo lolote moja, kunaweza kuchanganya heuristi.

## **Forced Address Reuse**

Wavamizi wanaweza kutuma kiasi kidogo kwa anwani zilizotumika hapo awali, wakitarajia mpokeaji kuziunganisha na inputs nyingine katika miamala ya baadaye, na hivyo kuunganisha anwani pamoja.

### Tabia Sahihi ya Wallet

Wallets zinapaswa kuepuka kutumia coins zilizopokelewa kwenye anwani ambazo tayari zimetumika na ambazo ni tupu ili kuzuia privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Miamala isiyo na change ina uwezekano mkubwa kuwa ni kati ya anwani mbili zinazomilikiwa na mtumiaji mmoja.
- **Round Numbers:** Nambari ya mdundo katika muamala inapendekeza ni malipo, na output isiyo ya mdundo kwa uwezekano kuwa ndiyo change.
- **Wallet Fingerprinting:** Wallets tofauti zina mifumo ya kipekee ya kutengeneza miamala, ambayo inawawezesha wachambuzi kubaini software iliyotumika na pengine change address.
- **Amount & Timing Correlations:** Kufichua wakati wa miamala au kiasi kunaweza kufanya miamala iwe rahisi kufuatiliwa.

## Traffic Analysis

Kwa kufuatilia trafiki ya mtandao, wavamizi wanaweza kuunganisha miamala au blocks na IP addresses, na kuathiri faragha ya watumiaji. Hii ni hasa kweli ikiwa taasisi inafanya kazi na nodes nyingi za Bitcoin, ikiongezea uwezo wake wa kufuatilia miamala.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Kupata bitcoin kwa pesa taslimu.
- **Cash Alternatives**: Kununua gift cards na kuzibadilisha mtandaoni kwa bitcoin.
- **Mining**: Njia ya faragha zaidi ya kupata bitcoins ni kupitia mining, hasa unapofanya peke yako kwa sababu mining pools zinaweza kujua IP address ya miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Kitheoretically, kuiba bitcoin inaweza kuwa njia nyingine ya kupata kwa njia isiyotambulika, ingawa ni kinyume cha sheria na haipendekezwi.

## Mixing Services

Kwa kutumia mixing service, mtumiaji anaweza **kutuma bitcoins** na kupokea **bitcoins tofauti kwa kurudisha**, ambayo inafanya iwe vigumu kufuatilia mmiliki wa awali. Hata hivyo, hili linahitaji kuamini service kwamba haitahifadhi logs na kwamba itarudisha bitcoins kweli. Chaguo mbadala za mixing ni pamoja na Bitcoin casinos.

## CoinJoin

**CoinJoin** inaunganisha miamala mingi kutoka kwa watumiaji tofauti kuwa muamala mmoja, na kufanya mchakato kuwa mgumu kwa yeyote anayetafuta kulinganisha inputs na outputs. Licha ya ufanisi wake, miamala yenye ukubwa wa kipekee wa input na output bado zinaweza kufuatiliwa kwa uwezekano.

Miamala ya mfano ambayo huenda ilitumia CoinJoin ni `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` na `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Toleo la CoinJoin, **PayJoin** (au P2EP), linatofautisha muamala kati ya pande mbili (mfano, mteja na muuzaji) kama muamala wa kawaida, bila outputs sawa za kipekee za CoinJoin. Hii inafanya iwe vigumu kubaini na inaweza kuharibu heuristic ya common-input-ownership inayotumika na wakala wa ufuatiliaji wa miamala.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Miamala kama ile hapo juu inaweza kuwa PayJoin, ikiboresha faragha huku ikibaki isiyotofautishwa na miamala ya kawaida ya bitcoin.

**Matumizi ya PayJoin yanaweza kuvuruga kwa kiasi kikubwa mbinu za ufuatiliaji za jadi**, na kuiweka kama maendeleo ya kuahidi katika harakati za faragha ya miamala.

# Mazoea Bora kwa Faragha katika Sarafu za Kidijitali

## **Mbinu za Kusawazisha Wallet**

Ili kudumisha faragha na usalama, kusawazisha wallet na blockchain ni muhimu. Njia mbili zinajitokeza kama muhimu:

- **Full node**: Kwa kupakua blockchain nzima, Full node inahakikisha faragha ya juu kabisa. Miamala yote iliyofanywa huhifadhiwa kwa ndani, na kufanya isiwezekane kwa adui kuamua ni miamala au anwani zipi mtumiaji anazovutiwa nazo.
- **Client-side block filtering**: Njia hii inahusisha kuunda filters kwa kila block katika blockchain, kuruhusu wallets kutambua miamala inayohusiana bila kufichua maslahi maalum kwa watazamaji wa mtandao. Wallet nyepesi hupakua filters hizi, na kuichukua block kamili tu wakati kuna mechi na anwani za mtumiaji.

## **Kutumia Tor kwa Kutotambulika**

Kwa kuwa Bitcoin inafanya kazi kwenye mtandao wa peer-to-peer, inashauriwa kutumia Tor kuficha anwani yako ya IP, kuboresha faragha unaposhirikiana na mtandao.

## **Kuzuia Kutumika Tena kwa Anwani**

Ili kulinda faragha, ni muhimu kutumia anwani mpya kwa kila muamala. Kutumia tena anwani kunaweza kuhatarisha faragha kwa kuunganisha miamala na kiumbe kimoja. Wallet za kisasa zinaonya dhidi ya utumizi upya wa anwani kupitia muundo wao.

## **Mikakati ya Faragha ya Miamala**

- **Miamala mingi**: Kugawanya malipo kuwa miamala kadhaa kunaweza kuficha kiasi cha muamala, na kuzuia mashambulizi ya faragha.
- **Kuepuka kuunda change outputs**: Kuchagua miamala ambayo hayahitaji change outputs huongeza faragha kwa kuvuruga mbinu za kugundua change.
- **Change outputs nyingi**: Ikiwa kuepuka change haiwezekani, kuzalisha change outputs nyingi bado kunaweza kuboresha faragha.

# **Monero: A Beacon of Anonymity**

Monero inashughulikia hitaji la kutotambulika kabisa katika miamala za dijitali, ikiweka viwango vya juu vya faragha.

# **Ethereum: Gas and Transactions**

## **Kuelewa Gas**

Gas hupima jitihada za kihesabu zinazohitajika kutekeleza operesheni kwenye Ethereum, zinazopimwa kwa **gwei**. Kwa mfano, muamala unaogharimu 2,310,000 gwei (au 0.00231 ETH) unajumuisha gas limit na base fee, pamoja na tip ya kuhamasisha miners. Watumiaji wanaweza kuweka max fee ili kuhakikisha hawalipi kupita kiasi, na ziada kurudishwa.

## **Kutekeleza Miamala**

Miamala kwenye Ethereum inahusisha mtumaji na mpokeaji, ambao wanaweza kuwa anwani za mtumiaji au smart contract. Zinahitaji ada na lazima zimiminwe. Taarifa muhimu katika muamala ni pamoja na mpokeaji, saini ya mtumaji, thamani, data ya hiari, gas limit, na ada. Muhimu, anwani ya mtumaji hutolewa kutokana na saini, hivyo haitegemeiwi kuwekwa katika data ya muamala.

Mazingira haya na mifumo ni msingi kwa yeyote anayetaka kushiriki na sarafu za kidijitali wakati akitoa kipaumbele kwa faragha na usalama.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

## Uvunjaji wa DeFi/AMM

Ikiwa unatafuta utafiti wa uvunjaji wa vitendo wa DEXes na AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), angalia:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Kwa pools za uzito wa mali nyingi zinazohifadhi virtual balances na zinaweza kuchomwa sumu wakati `supply == 0`, soma:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
