# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese Begrippe

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes vervul is, wat die uitvoering van ooreenkomste outomatiseer sonder tussengangers.
- **Decentralized Applications (dApps)** bou op Smart Contracts, met 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei deurdat coins dien as digitale geld, terwyl tokens waarde of eienaarskap in spesifieke kontekste voorstel.
- **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui eiendomsreg aan.
- **DeFi** staan vir Decentralized Finance, wat finansiële dienste sonder sentrale owerhede bied.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Consensus-meganismes

Consensus-meganismes verseker veilige en ooreengekome transaksieverifikasie op die blockchain:

- **Proof of Work (PoW)** berus op rekenaarkrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens besit, wat die energieverbruik in vergelyking met PoW verminder.

## Bitcoin Basiese Beginsels

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word gevalideer deur digitale handtekeninge, wat verseker dat slegs die eienaar van die private sleutel oordragte kan inisieer.

#### Sleutelelemente:

- **Multisignature Transactions** vereis meerdere handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners), en **scripts** (transaksie-reëls).

### Lightning Network

Is daarop gemik om Bitcoin se skalabiliteit te verbeter deur veelvuldige transaksies binne 'n kanaal toe te laat, en slegs die finale toestand aan die blockchain te stuur.

## Bitcoin Privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, benut transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te versluier.

## Bitcoin Anoniem Verkry

Metodes sluit in kontanttransaksies, mining, en die gebruik van mixers. **CoinJoin** meng meerdere transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verhoogde privaatheid.

# Bitcoin Privaatheidsaanvalle

# Opsomming van Bitcoin Privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimatiteit van gebruikers dikwels kommerwekkend. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.

## **Common Input Ownership Assumption**

Dit is oor die algemeen skaars dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die betrokkenheid van kompleksiteit. Daarom word **twee input-adresse in dieselfde transaksie dikwels aanvaar om aan dieselfde eienaar te behoort**.

## **UTXO Change Address Detection**

'n UTXO, of Unspent Transaction Output, moet in 'n transaksie heeltemal bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die oorblyfsel na 'n nuwe change-adres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid ondermyn.

### Voorbeeld

Om dit te versag kan mixers of die gebruik van verskeie adresse help om eienaarskap te versluier.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke geïvisualiseer word, wat potensiële verbindings tussen gebruikers blootlê gebaseer op die vloei van fondse.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met meerdere inputs en outputs om te raai watter output die change is wat aan die sender teruggaan.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As dit meer inputs byvoeg wat die change-uitset groter maak as enige enkele input, kan dit die heuristiek in die war steek.

## **Forced Address Reuse**

Aanvallers kan klein bedrae stuur na voorheen gebruikte adresse, in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer, en sodoende adresse aan mekaar koppel.

### Correct Wallet Behavior

Wallets moet vermy om munte wat op reeds gebruikte, leë adresse ontvang is, te gebruik, om hierdie privacy leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder 'n wisseluitset is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** 'n Ronde getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-ronde uitset wat waarskynlik die wissel is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir transaksiegelvorming, wat ontleders in staat stel om die sagteware te identifiseer wat gebruik is en moontlik die wisseladres.
- **Amount & Timing Correlations:** Die openbaarmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel, wat die privaatheid van gebruikers in die gedrang bring. Dit is veral waar as 'n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë om transaksies te monitor versterk.

## More

Vir 'n omvattende lys van privacy attacks and defenses, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

Deur 'n mixing service te gebruik, kan 'n gebruiker **send bitcoins** en ontvang **different bitcoins in return**, wat dit moeilik maak om die oorspronklike eienaar te spoor. Dit vereis egter vertroue in die diens om nie logs te hou nie en om die bitcoins werklik terug te gee. Alternatiewe mengopsies sluit Bitcoin-kasino's in.

## CoinJoin

**CoinJoin** kombineer meerdere transaksies van verskillende gebruikers in een, wat dit moeiliker maak vir enigiemand om insette met uitsette te koppel. Ten spyte van die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik getraceer word.

Voorbeeldtransaksies wat dalk CoinJoin gebruik het sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), verdoesel die transaksie tussen twee partye (bv. 'n kliënt en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette wat tipies is van CoinJoin. Dit maak dit buitengewoon moeilik om te ontdek en kan die common-input-ownership heuristiek wat deur transaksiebewakings-entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar bly van standaard bitcoin-transaksies.

**Die gebruik van PayJoin kan tradisionele toesighoudingsmetodes beduidend ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.

# Beste praktyke vir privaatheid in kripto-geldeenhede

## **Beursie-sinkroniseringstegnieke**

Om privaatheid en veiligheid te handhaaf, is dit noodsaaklik om beursies met die blockchain te sinkroniseer. Twee metodes val op:

- **Full node**: Deur die hele blockchain af te laai, verseker 'n full node maksimum privaatheid. Alle ooit gedane transaksies word plaaslik gestoor, wat dit vir teenstanders onmoontlik maak om te identifiseer watter transaksies of adresse die gebruiker betrokke is.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat beursies in staat stel om relevante transaksies te identifiseer sonder om spesifieke belangstelling aan netwerkwaarnemers bloot te stel. Liggewig-beursies laai hierdie filters af en haal slegs volle blokke wanneer 'n ooreenkomst met die gebruiker se adresse gevind word.

## **Die gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer-netwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verskuil, wat privaatheid verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Hergebruik van adresse kan privaatheid in gevaar stel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksie-privaatheid**

- **Multiple transactions**: Deur 'n betaling in verskeie transaksies te verdeel kan die transaksiebedrag vervaag, wat privaatheidsaanvalle keer.
- **Change avoidance**: Kies transaksies wat geen change-uitsette vereis nie; dit verbeter privaatheid deur metodes vir die opsporing van change te ontwrig.
- **Multiple change outputs**: As dit nie moontlik is om change te vermy nie, kan die genereer van meerdere change-uitsette steeds privaatheid verbeter.

# **Monero: 'n Bakens van Anonimiteit**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas en Transaksies**

## **Begrip van Gas**

Gas meet die rekenkundige moeite wat nodig is om bewerkings op Ethereum uit te voer, geprys in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimiet en 'n basisfoo, met 'n wenk om miners te stimuleer. Gebruikers kan 'n maksimumfooi stel om te verseker hulle betaal nie te veel nie; die oorskot word terugbetaal.

## **Transaksies uitvoer**

Transaksies op Ethereum behels 'n sender en 'n ontvanger, wat of gebruikers- of smart contract-adresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Belangrik: die sender se adres word afgeleide uit die handtekening, wat die noodsaaklikheid om dit in die transaksiedata op te neem uitskakel.

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met cryptocurrencies wil omgaan terwyl privaatheid en veiligheid prioriteit geniet.

## Value-Centric Web3 Red Teaming

- Maak 'n inventaris van waarde-draende komponente (signers, oracles, bridges, automation) om te verstaan wie fondse kan beweeg en hoe.
- Karteer elke komponent na toepaslike MITRE AADAPT taktieke om privilegie-opskaleringspaaie bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain aanvalskettings om impak te valideer en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Gereelde slim-rekening faalmodusse sluit die omseiling van `EntryPoint` toegangbeheer, ongetekende gasvelde, stateful-validasie, ERC-1271 replay, en fooi-uitputting via revert-after-validation in.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutasietoetsing om blinde kolletjies in toetsbundels te vind:

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

## DeFi/AMM-uitbuiting

As jy praktiese uitbuiting van DEXes en AMMs navors (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), kyk:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset gewigpoele wat virtuele balanse cache en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
