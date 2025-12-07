# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes vervul is, en outomatiseer die uitvoering van ooreenkomste sonder tussengangers.
- **Decentralized Applications (dApps)** bou voort op Smart Contracts, en het 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei deurdat coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui eiendomsreg van bate aan.
- **DeFi** staan vir Decentralized Finance, en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksie-validasies op die blockchain:

- **Proof of Work (PoW)** vertrou op rekenaarkrag vir transaksie-verifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik verminder in vergelyking met PoW.

## Bitcoin Kernbeginsels

### Transaksies

Bitcoin transaksies behels die oordrag van fondse tussen adresse. Transaksies word geverifieer deur digitale handtekeninge, wat verseker dat slegs die eienaar van die private sleutel oordragte kan inisieer.

#### Sleutelelemente:

- **Multisignature Transactions** vereis meerdere handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners), en **scripts** (transaksie-reëls).

### Lightning Network

Streef daarna om Bitcoin se skaalbaarheid te verbeter deur meerdere transaksies binne 'n kanaal toe te laat, en slegs die finale toestand na die blockchain te stuur.

## Bitcoin Privaatheidsbekommernisse

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, benut transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksie-skakels tussen gebruikers te verberg.

## Anonieme verkryging van Bitcoins

Metodes sluit in kontanttransaksies, mining, en die gebruik van mixers. **CoinJoin** meng meerdere transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies verdoesel vir groter privaatheid.

# Bitcoin Privaatheidsaanvalle

# Opsomming van Bitcoin Privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels 'n bron van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.

## **Common Input Ownership Assumption**

Oor die algemeen is dit skaars dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die komplekse aard. Daarom word **twee input-adresse in dieselfde transaksie dikwels aanvaar as behorend aan dieselfde eienaar**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig bestee word in 'n transaksie. As slegs 'n gedeelte daarvan na 'n ander adres gestuur word, gaan die oorblywende na 'n nuwe change address. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te versag, kan mixing-dienste of die gebruik van meerdere adresse help om eienaarskap te verberg.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gevisualiseer word, wat potensiële verbindings tussen gebruikers openbaar op grond van die vloei van fondse.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met meerdere inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Aanvallers kan klein bedrae stuur na adresse wat reeds gebruik is, in die hoop dat die ontvanger dit by ander inputs in toekomstige transaksies voeg en sodoende adresse aan mekaar koppel.

### Correct Wallet Behavior

Wallets moet vermy om munte wat op reeds gebruikte, leë adresse ontvang is te gebruik om hierdie privacy leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder wisselgeld is waarskynlik tussen twee adresse wat aan dieselfde gebruiker behoort.
- **Round Numbers:** 'n Afronde getal in 'n transaksie dui aan dat dit 'n betaling is, en die nie-afronde uitset is waarskynlik die wisselgeld.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir transaksie-skep, wat ontleders toelaat om die sagteware te identifiseer wat gebruik is en moontlik die wisseladres.
- **Amount & Timing Correlations:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blocks aan IP addresses koppel en sodoende gebruikers se privaatheid kompromitteer. Dit is veral waar as 'n entiteit baie Bitcoin node bedryf, wat hul vermoë om transaksies te monitor verbeter.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Verkryging van bitcoin deur kontant.
- **Cash Alternatives**: Koop van gift cards en ruil dit aanlyn vir bitcoin.
- **Mining**: Die mees private metode om bitcoins te verdien is deur mining, veral as dit alleen gedoen word, aangesien mining pools moontlik die miner se IP address ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties kan diefstal van bitcoin 'n ander metode wees om dit anoniem te bekom, hoewel dit onwettig is en nie aanbeveel word nie.

## Mixing Services

Deur 'n mixing service te gebruik, kan 'n gebruiker **bitcoins stuur** en in ruil **ander bitcoins ontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue in die diens om nie logs te hou nie en om die bitcoins werklik terug te gee. Alternatiewe mixing-opsies sluit Bitcoin casinos in.

## CoinJoin

CoinJoin saamsmelt verskeie transaksies van verskillende gebruikers in een, wat dit vir enigiemand moeiliker maak om inputs met outputs te koppel. Ten spyte van die doeltreffendheid daarvan, kan transaksies met unieke input- en outputgroottes steeds moontlik getraceer word.

Voorbeelduitbetalings wat CoinJoin gebruik kan hê sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, PayJoin (or P2EP), vermom die transaksie tussen twee partye (bv. 'n klant en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke outputs van CoinJoin. Dit maak dit uiters moeilik om te ontdek en kan die common-input-ownership heuristic wat deur transaksie-surveillance entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bostaande kan PayJoin wees, wat privaatheid verbeter terwyl hulle ononderskeibaar van standaard bitcoin-transaksies bly.

**Die gebruik van PayJoin kan tradisionele toesigmetodes beduidend ontwrig**, wat dit ’n belowende ontwikkeling in die strewe na transaksionele privaatheid maak.

# Beste praktyke vir privaatheid in kripto-geldeenhede

## **Wallet-sinchroniseringstegnieke**

Om privaatheid en veiligheid te behou, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Full node**: Deur die hele blockchain af te laai verseker ’n full node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word lokaal gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer watter transaksies of adresse die gebruiker interesseer.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat wallets toelaat om relevante transaksies te identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te lê. Lightweight wallets laai hierdie filters af en haal net volle blokke op wanneer ’n pas met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n peer-to-peer-netwerk funksioneer, word die gebruik van Tor aanbeveel om jou IP-adres te maskeer en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om ’n nuwe adres vir elke transaksie te gebruik. Hergebruik van adresse kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Meervoudige transaksies**: Om ’n betaling in verskeie transaksies op te breek kan die transaksiebedrag verberg en privaatheidsaanvalle teenwerk.
- **Vermyding van change**: Om te kies vir transaksies wat geen change-outputs benodig verbeter privaatheid deur change-deteksiemetodes te ontwrig.
- **Meervoudige change-outputs**: As verandering nie vermy kan word nie, kan die genereer van verskeie change-outputs steeds privaatheid verbeter.

# **Monero: ’n baken van anonimiteit**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel ’n hoë standaard vir privaatheid.

# **Ethereum: Gas en transaksies**

## **Begrip van Gas**

Gas meet die rekenkundige poging nodig om operasies op Ethereum uit te voer en word geprys in **gwei**. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basisfooi, met ’n fooi (tip) om mynwerkers te stimuleer. Gebruikers kan ’n maksfooi stel om te verseker dat hulle nie oorbetaal nie; die oorskot word terugbetaal.

## **Die uitvoering van transaksies**

Transaksies in Ethereum behels ’n sender en ’n ontvanger, wat óf gebruikers- óf smart contract-adresse kan wees. Hulle vereis ’n fooi en moet gemaind word. Essensiële inligting in ’n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Opmerklik is dat die sender se adres uit die handtekening afgelei word, wat die behoefte om dit in die transaksiedata op te neem uitskakel.

Hierdie praktyke en meganismes lê die fondament vir enigiemand wat met kripto-geldeenhede wil werk terwyl privaatheid en veiligheid prioriteit geniet.

## Smart Contract Sekuriteit

- Mutasietoetsing om blinde kolletjies in toetsuite te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Verwysings

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

As jy praktiese eksploitering van DEXes en AMMs navors (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), kyk:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset gewigte swembaddens wat virtuele balansies kas en besmet kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
