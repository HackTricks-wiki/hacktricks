# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Smartkontrakte** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes vervul is, wat die uitvoering van ooreenkomste outomatiseer sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou voort op smartkontrakte, met 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei deurdat coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui eienaarskap van bates aan.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Desentraliseerde Wisselplatforms en Desentraliseerde Autonome Organisasies.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksiebevestiging op die blockchain:

- **Proof of Work (PoW)** berus op rekenaarkrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik in vergelyking met PoW verminder.

## Bitcoin-basiskennis

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge geverifieer, wat verseker dat slegs die eienaar van die private sleutel oordragte kan inisieer.

#### Sleutelkomponente:

- **Multisignature Transactions** vereis meerdere handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners), en **scripts** (transaksiewette).

### Lightning Network

Het ten doel om Bitcoin se skaalbaarheid te verbeter deur meerdere transaksies binne 'n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, misbruik transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksiekoppeling tussen gebruikers te vervaag.

## Bitcoins Anoniem Verkry

Metodes sluit kontanttransaksies, mynbou, en die gebruik van mixers in. **CoinJoin** meng meerdere transaksies om spoorbaarheid ingewikkelder te maak, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verhoogde privaatheid.

# Bitcoin Privaatheidsaanvalle

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers gereeld 'n bron van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.

## **Common Input Ownership Assumption**

Dit kom gewoonlik selde voor dat inputs van verskillende gebruikers in een transaksie saamgevoeg word weens die kompleksiteit daarvan. Daarom word **twee inputadresse in dieselfde transaksie dikwels vereenselwig as die van dieselfde eienaar**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig bestee word in 'n transaksie. Indien slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe veranderingsadres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van meerdere adresse help om eienaarskap te verberg.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gevisualiseer word, wat potensiële verbindings tussen gebruikers toon gebaseer op die vloei van fondse.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met meerdere inputs en outputs om te raai watter output die verandering is wat na die stuurder terugstuur.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change-uitset groter maak as enige enkele input, kan dit die heuristiek in die war steek.

## **Forced Address Reuse**

Aanvallers mag klein bedrae stuur na voorheen gebruikte adresse in die hoop dat die ontvanger hierdie met ander inputs in toekomstige transaksies kombineer en sodoende adresse aan mekaar koppel.

### Korrekte Wallet-gedrag

Wallets moet vermy om munte wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privaatheids leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat aan dieselfde gebruiker behoort.
- **Round Numbers:** 'n Ronde getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-ronde uitset wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir transaksieskepping, wat analiste toelaat om die sagteware wat gebruik is te identifiseer en moontlik die change-adres.
- **Amount & Timing Correlations:** Die bekendmaking van transaksietye of bedrae kan transaksies naspeurbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvalle moontlik transaksies of blokke met IP-adresse verbind en gebruikers se privaatheid in gedrang bring. Dit is veral waar as 'n entiteit baie Bitcoin nodes bedryf, wat hul vermoë om transaksies te monitor verbeter.

## Meer

Vir 'n omvattende lys van privaatheids-aanvalle en verdediging, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins Anoniem te Verkry

- **Kontanttransaksies**: Bitcoins deur kontant bekom.
- **Kontant-alternatiewe**: Koop geskenkkaarte en ruil dit aanlyn vir bitcoin.
- **Mynbou**: Die mees privaatte metode om bitcoins te verdien is deur mynbou, veral solo, aangesien myngroepe dalk die miner se IP-adres ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin 'n ander manier wees om dit anoniem te bekom, alhoewel dit onwettig is en nie aanbeveel word nie.

## Mixing Services

Deur 'n mixing service te gebruik, kan 'n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar te spoor. Dit vereis egter vertroue in die diens om nie logs te hou nie en om werklik die bitcoins terug te gee. Alternatiewe mixing-opsies sluit Bitcoin-casinos in.

## CoinJoin

CoinJoin saamsmelt verskeie transaksies van verskillende gebruikers in een, wat dit moeiliker maak vir enigiemand om inputs aan outputs te koppel. Ten spyte van die doeltreffendheid daarvan, kan transaksies met unieke input- en outputgroottes steeds moontlik opgespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met fondse van miners.

## PayJoin

'n Variant van CoinJoin, **PayJoin** (of P2EP), verberg die transaksie tussen twee partye (bv. 'n kliënt en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om te bespeur en kan die common-input-ownership heuristic wat deur transaksiebewakingsentiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos hierbo kan PayJoin wees, wat privaatheid verbeter terwyl dit onskeibaar bly van standaard bitcoin-transaksies.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.

# Beste praktyke vir privaatheid in kripto-geldeenhede

## **Wallet Synchronization Techniques**

Om privaatheid en sekuriteit te behou, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes tree uit:

- **Full node**: Deur die hele blockchain af te laai, verseker 'n full node maksimum privaatheid. Alle ooit uitgevoerde transaksies word lokaal gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer waarna die gebruiker belangstel.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat wallets in staat stel om relevante transaksies te identifiseer sonder om spesifieke belange aan netwerkwaarnemers bloot te stel. Liggewig-wallets laai hierdie filters af en haal slegs volle blokke wanneer 'n ooreenstemming met die gebruiker se adresse gevind word.

## **Utilizing Tor for Anonymity**

Aangesien Bitcoin op 'n peer-to-peer netwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te maskeer, wat privaatheid verhoog wanneer jy met die netwerk kommunikeer.

## **Preventing Address Reuse**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie 'n nuwe adres te gebruik. Hergebruik van adresse kan privaatheid in gedrang bring deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adressehergebruik deur hul ontwerp.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Om 'n betaling in verskeie transaksies te verdeel kan die bedrag verduister en privaatheidsaanvalle dwarsboom.
- **Change avoidance**: Kies vir transaksies wat geen change outputs benodig nie — dit verbeter privaatheid deur change-detectiemetodes te ontwrig.
- **Multiple change outputs**: As die vermyding van change nie haalbaar is nie, kan die genereer van verskeie change outputs steeds privaatheid verbeter.

# **Monero: A Beacon of Anonymity**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas and Transactions**

## **Begrip van Gas**

Gas meet die rekenkundige poging wat nodig is om operasies op Ethereum uit te voer, geprys in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos behels 'n gaslimiet en 'n basisfooi, met 'n wenk om miners te stimuleer. Gebruikers kan 'n maksimumfooi stel om te verseker dat hulle nie oorbetaal nie; die oorskot word terugbetaal.

## **Uitvoering van transaksies**

Transaksies op Ethereum behels 'n sender en 'n ontvanger, wat beide 'n gebruiker- of smart contract-adres kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Opmerkend is dat die sender se adres uit die handtekening afgeleid word, wat die behoefte om dit in die transaksiedata op te neem uitskakel.

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met kripto-geldeenhede wil omgaan terwyl privaatheid en sekuriteit prioriteit geniet.

## Smart Contract Security

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

## DeFi/AMM Exploitation

As jy praktiese eksploitasie van DEXes en AMMs bestudeer (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), kyk:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
