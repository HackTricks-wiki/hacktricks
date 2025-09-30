# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes vervul is, en outomatiseer die uitvoering van ooreenkomste sonder tussengangers.
- **Gedecentraliseerde toepassings (dApps)** bou op Smart Contracts voort en het 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei waar munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui eienaarskap van bates aan.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksiebevestigings op die blockchain:

- **Proof of Work (PoW)** berus op rekenaarkrag vir transaksieverifiëring.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik verminder in vergelyking met PoW.

## Bitcoin Basiese Inligting

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word geverifieer deur digitale handtekeninge, wat verseker dat slegs die eienaar van die private sleutel oordragte kan inisieer.

#### Sleutelelemente:

- **Multisignature Transactions** vereis meerdere handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners), en **scripts** (transaksiereëls).

### Lightning Network

Strewe daarna om Bitcoin se skaalbaarheid te verbeter deur meerdere transaksies binne 'n kanaal toe te laat, en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin Privaatheidsake

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, benut transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksielinks tussen gebruikers te verberg.

## Anoniem Bitcoins Verkry

Metodes sluit in kontanttransaksies, mynbou, en die gebruik van mixers. **CoinJoin** meng meerdere transaksies om spoorbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies verdoesel vir verhoogde privaatheid.

# Bitcoin Privaatheid Aanvalle

# Opsomming van Bitcoin Privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels ŉ bron van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.

## **Common Input Ownership Assumption**

Dit is gewoonlik skaars dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit wat betrokke is. Dus word **twee input-adresse in dieselfde transaksie dikwels aanvaar om aan dieselfde eienaar te behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As net 'n deel daarvan aan 'n ander adres gestuur word, gaan die res na 'n nuwe change-adres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verberg.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gesien word, wat potensiële verbindings tussen gebruikers toon gebaseer op die vloei van fondse.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met veelvuldige inputs en outputs om te raai watter output die change is wat aan die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change-uitset groter maak as enige enkele input, kan dit die heuristiek in die war bring.

## **Gedwonge hergebruik van adresse**

Aanvallers kan klein bedrae stuur na voorheen gebruikte adresse, in die hoop dat die ontvanger dit met ander insette in toekomstige transaksies kombineer en sodoende adresse aan mekaar koppel.

### Korrekte wallet-gedrag

Wallets behoort te vermy om coins wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privacy leak te voorkom.

## **Andere Blockchain-ontledingstegnieke**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** 'n Rond getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-rond uitset wat waarskynlik die wissel is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke transaksie-skep patrone, wat ontleders toelaat om die sagteware te identifiseer wat gebruik is en moontlik die change-adres.
- **Amount & Timing Correlations:** Die openbaarmaking van transaksietye of -bedrae kan transaksies opspoorbaar maak.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokkies aan IP addresses koppel en gebruikers se privaatheid kompromitteer. Dit is veral waar as 'n entiteit baie Bitcoin nodes bedryf, wat hul vermoë om transaksies te monitor verbeter.

## Meer

Vir 'n omvattende lys van privacy-aanvalle en verdedigings, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins Anoniem te Kry

- **Kontanttransaksies**: Verkryging van bitcoin deur kontant.
- **Kontantalternatiewe**: Aankoop van geskenkkaarte en ruil daarvan aanlyn vir bitcoin.
- **Mynbou**: Die privaatste metode om bitcoins te verdien is deur mynbou, veral as dit alleen gedoen word, want mining pools mag die miner se IP-adres ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin 'n ander metode wees om dit anoniem te verkry, alhoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur 'n mixing service te gebruik, kan 'n gebruiker bitcoins stuur en ander bitcoins in ruil ontvang, wat dit moeilik maak om die oorspronklike eienaar te spoor. Dit vereis egter vertroue in die diens om nie logs te hou nie en om die bitcoins werklik terug te stuur. Alternatiewe mengopsies sluit Bitcoin-casinos in.

## CoinJoin

CoinJoin meng meerdere transaksies van verskillende gebruikers in een, wat die proses bemoeilik vir enigiemand wat insette met uitsette wil koppel. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds potensieel opspoorbaar wees.

Voorbeeltransaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met fondse van miners.

## PayJoin

'n Variant van CoinJoin, **PayJoin** (of P2EP), verdoesel die transaksie tussen twee partye (bv. 'n klant en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om te ontdek en kan die common-input-ownership heuristiek wat deur transaksiebewakingsentiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar bly van standaard bitcoin-transaksies.

**Die gebruik van PayJoin kan tradisionele toesigmetodes beduidend ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.

# Beste praktyke vir privaatheid in kripto-geldeenhede

## **Wallet-sinkroniseringstegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit belangrik om wallets met die blockchain te sinkroniseer. Twee metodes steek uit:

- **Full node**: Deur die hele blockchain af te laai verseker 'n full node maksimum privaatheid. Alle ooit uitgevoerde transaksies word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te bepaal watter transaksies of adresse die gebruiker betref.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat wallets in staat stel om relevante transaksies te identifiseer sonder om spesifieke belange aan netwerkwaarnemers bloot te stel. Liggewig-wallets laai hierdie filters af en haal slegs volle blokke op wanneer 'n ooreenkoms met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer-netwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te versluier en sodoende privaatheid te verbeter wanneer jy met die netwerk interaksie het.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Die hergebruik van adresse kan privaatheid kompromitteer deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Multiple transactions**: Deur 'n betaling in verskeie transaksies te verdeel kan die transaksiebedrag verberg en privaatheidsaanvalle dwarsboom.
- **Change avoidance**: Deur te kies vir transaksies wat geen change-uitsette vereis, verbeter privaatheid deur change-detektiemetodes te ontwrig.
- **Multiple change outputs**: As die vermyding van change nie haalbaar is nie, kan die genereer van meervoudige change-uitsette steeds privaatheid verbeter.

# **Monero: 'n Baken van anonimiteit**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas en transaksies**

## **Gas verstaan**

Gas meet die rekenkundige moeite benodig om operasies op Ethereum uit te voer, en word geprys in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, het 'n gaslimiet en 'n basisfooi, plus 'n tip om myners te stimuleer. Gebruikers kan 'n maksimumfooi stel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.

## **Uitvoering van transaksies**

Transaksies op Ethereum betrek 'n sender en 'n ontvanger, wat óf gebruikers- óf smart contract-adresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Wesentlike inligting in 'n transaksie sluit die ontvanger, sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Belangrik: die sender se adres word uit die handtekening afgelei, wat die noodsaaklikheid om dit in die transaksiedata op te neem uitskakel.

Hierdie praktyke en meganismes vorm die fondament vir enigiemand wat met kripto-geldeenhede wil omgaan en privaatheid en sekuriteit prioriseer.

## Verwysings

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Eksploitasie

As jy navorsing doen oor praktiese eksploitasie van DEXes en AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), kyk:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
