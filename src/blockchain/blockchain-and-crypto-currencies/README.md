# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes vervul is, wat die uitvoering van ooreenkomste outomatiseer sonder tussengangers.
- **Decentralized Applications (dApps)** bou voort op smart contracts, met 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei waar coins dien as digitale geld, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui eienaarskap van 'n bate aan.
- **DeFi** staan vir Decentralized Finance, wat finansiële dienste sonder sentrale owerhede bied.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksieverifikasie op die blockchain:

- **Proof of Work (PoW)** berus op rekenaarkrag vir transaksie-verifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik verminder in vergelyking met PoW.

## Bitcoin-essensies

### Transaksies

Bitcoin transaksies behels die oordrag van fondse tussen addresses. Transaksies word gevalideer deur digital signatures, wat verseker dat slegs die eienaar van die private key transfers kan inisieer.

#### Sleutelkomponente:

- **Multisignature Transactions** vereis meerdere signatures om 'n transaksie te magtig.
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners), en **scripts** (transaksie-reëls).

### Lightning Network

Streef daarna om Bitcoin se skaalaanpasbaarheid te verbeter deur toe te laat dat meerdere transaksies binne 'n kanaal plaasvind, en slegs die finale toestand na die blockchain uitgesaai word.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, ontgin transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieverbindings tussen gebruikers te verberg.

## Bitcoins anoniem verkry

Metodes sluit kontanthandel, mining, en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om opspoorbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies wegsteek vir verhoogde privaatheid.

# Bitcoin-privaatheidsaanvalle

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels kommerwekkend. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.

## **Common Input Ownership Assumption**

Dit is oor die algemeen skaars dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die betrokken kompleksiteit. Dus word **twee input addresses in dieselfde transaksie dikwels veronderstel om aan dieselfde eienaar te behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet heeltemal bestee word in 'n transaksie. As slegs 'n deel daarvan aan 'n ander address gestuur word, gaan die oorblywende na 'n nuwe change address. Waarnemers kan aanvaar dat hierdie nuwe address aan die sender behoort, wat privaatheid in gedrang bring.

### Voorbeeld

Om dit te versag, kan mixing services of die gebruik van veelvuldige addresses help om eienaarskap te verberg.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin addresses aanlyn, wat dit **maklik maak om die address aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gesien word, wat potensiële verbindings tussen gebruikers onthul gebaseer op die vloei van fondse.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek berus op die ontleding van transaksies met veelvuldige inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change-uitset groter maak as enige enkele input, kan dit die heuristiek verwar.

## **Gedwonge adreshergebruik**

Aanvallers kan klein bedrae na reeds gebruikte adresse stuur in die hoop dat die ontvanger dit in toekomstige transaksies met ander inputs kombineer, en sodoende adresse aan mekaar koppel.

### Korrekte Wallet-gedrag

Wallets moet vermy om munte wat ontvang is op reeds gebruikte, leë adresse te gebruik om hierdie privacy leak te voorkom.

## **Ander blockchain-ontledingstegnieke**

- **Presiese betaalbedrae:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde getalle:** 'n Ronde getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-ronde uitset wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir transaksies se samestelling, wat analiste toelaat om die sagteware te identifiseer en moontlik die change-adres te bepaal.
- **Bedrag & tydkorrelasies:** Die bekendmaking van transaksietye of bedrae kan transaksies naspeurbaar maak.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blocks aan IP addresses koppel, wat gebruikers se privaatheid in gevaar stel. Dit is veral waar as 'n entiteit baie Bitcoin nodes bedryf, wat hul vermoë om transaksies te monitor verbeter.

## Meer

Vir 'n omvattende lys van privacy-aanvalle en verdedigings, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonieme Bitcoin-transaksies

## Manere om bitcoins anoniem te verkry

- **Kontanttransaksies:** Bitcoin verkry deur kontant.
- **Kontantalternatiewe:** Koop van geskenkkaarte en ruil dit aanlyn vir bitcoin.
- **Mining:** Die mees private metode om bitcoins te verdien is deur mining, veral as dit alleen gedoen word omdat mining pools moontlik die miner se IP address ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal:** Teoreties kan diefstal van bitcoin 'n ander metode wees om dit anoniem te bekom, alhoewel dit onwettig is en nie aanbeveel word.

## Mengdienste

Deur 'n mengdiens te gebruik, kan 'n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue dat die diens nie logs hou nie en die bitcoins inderdaad terugstuur. Alternatiewe mengopsies sluit Bitcoin casinos in.

## CoinJoin

**CoinJoin** slaan meerdere transaksies van verskillende gebruikers saam in een, wat die proses bemoeilik vir enigiemand wat inputs met outputs probeer koppel. Ten spyte van sy doeltreffendheid kan transaksies met unieke input- en outputgroottes steeds potensieel opgespoor word.

Voorbeeltransaksies wat moontlik CoinJoin gebruik het sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met fondse van miners.

## PayJoin

'n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. 'n kliënt en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette wat CoinJoin herken. Dit maak dit buitengewoon moeilik om te ontdek en kan die common-input-ownership heuristic wat deur transaksietoezicht-entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bostaande kan PayJoin wees, wat privaatheid verbeter terwyl hulle ononderskeibaar bly van standaard bitcoin-transaksies.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.

# Beste praktyke vir privaatheid in kripto-geldeenhede

## **Wallet-sinchroniseringstegnieke**

Om privaatheid en sekuriteit te behou, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes val op:

- **Full node**: Deur die volledige blockchain af te laai, verseker 'n full node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir teenstanders onmoontlik maak om te identifiseer watter transaksies of adresse vir die gebruiker van belang is.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat wallets toelaat om relevante transaksies te identifiseer sonder om spesifieke belangstellings aan netwerkkykers bloot te lê. Liggewig wallets laai hierdie filters af en haal slegs volle blokke op wanneer 'n ooreenkoms met die gebruiker se adresse gevind word.

## **Die gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer netwerk funksioneer, word die gebruik van Tor aanbeveel om jou IP-adres te verberg, en sodoende privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Hergebruik van adresse kan privaatheid kompromitteer deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksie-privaatheid**

- **Meervoudige transaksies**: Om 'n betaling in verskeie transaksies te splits, kan die bedrag verhul en privaatheidsaanvalle verhoed.
- **Change avoidance**: Deur transaksies te kies wat geen change outputs benodig nie, verbeter jy privaatheid deur change detection-metodes te ontwrig.
- **Multiple change outputs**: As vermyding van change nie uitvoerbaar is nie, kan die genereer van meerdere change outputs steeds privaatheid verbeter.

# **Monero: 'n baken van anonimiteit**

Monero bekamp die behoefte aan absolute anonimiteit in digitale transaksies en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas en transaksies**

## **Gas verstaan**

Gas meet die rekenkundige moeite wat nodig is om operasies op Ethereum uit te voer, en word geprys in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimit en 'n basisfooi, met 'n tip om miners te aanspoor. Gebruikers kan 'n maksimumfooi stel om te verseker dat hulle nie te veel betaal nie, en die oorskot word terugbetaal.

## **Uitvoering van transaksies**

Transaksies op Ethereum behels 'n sender en 'n ontvanger, wat óf gebruikers- óf smart contract-adresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimit en fooie in. Opmerkingswaardig is dat die sender se adres uit die handtekening afgelei word, wat die behoefte om dit in die transaksiedata op te neem, uitskakel.

Hierdie praktyke en meganismes vorm die grondslag vir enigiemand wat met cryptocurrencies wil deelneem en privaatheid en veiligheid prioriteit gee.

## Value-Centric Web3 Red Teaming

- Inventariseer waarde-draende komponente (signers, oracles, bridges, automation) om te verstaan wie fondse kan skuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om voorregte-eskalasie-paaie bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain aanvalskettings om impak te valideer en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Kompromissie

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Sekuriteit

- Mutation testing om blindekolle in toetsstelle te vind:

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

Vir multi-asset gewogen pools wat virtuele balanse cache en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
