# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Slimkontrakte** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes vervul is, wat uitvoering van ooreenkomste outomatiseer sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou op slimkontrakte en het 'n gebruikersvriendelike voorwerf en 'n deursigtige, ouditbare agterwerf.
- **Tokens & Coins** onderskei deurdat coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Nut-tokens** gee toegang tot dienste, en **sekuriteitstokens** dui eienaarskap van bates aan.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidasies op die blockchain:

- **Bewys van Werk (PoW)** berus op rekenaarkrag vir transaksieverifikasie.
- **Bewys van Inset (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik vergelykbaar met PoW verminder.

## Bitcoin-basisbeginsels

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word geverifieer deur digitale handtekeninge, wat verseker dat slegs die eienaar van die privaat sleutel oordragte kan inisieer.

#### Sleutelelemente:

- **Multisignatuur-transaksies** vereis meerdere handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **insette** (bron van fondse), **uitsette** (bestemming), **fooie** (betaal aan miners), en **skripte** (transaksie-reëls).

### Lightning Network

Richt daarop om Bitcoin se skaalbaarheid te verbeter deur toelaat dat veelvuldige transaksies binne 'n kanaal plaasvind, en slegs die finale toestand aan die blockchain uitgesaai word.

## Bitcoin-privaatheidskomplikasies

Privaatheid-aanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, maak misbruik van transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te versluier.

## Bitcoins Anoniem Verkry

Metodes sluit kontant-transaksies, mining, en die gebruik van mixers in. **CoinJoin** meng veelvuldige transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies verskuil vir verhoogde privaatheid.

# Bitcoin-privaatheid-aanvalle

# Opsomming van Bitcoin-privaatheid-aanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels kommerwekkend. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromiteer.

## **Common Input Ownership Assumption**

Dit is oor die algemeen skaars dat insette van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit daaraan verbonde. Dus word **twee insetadresse in dieselfde transaksie dikwels veronderstel om aan dieselfde eienaar te behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As slegs 'n deel daarvan aan 'n ander adres gestuur word, gaan die oorblywende bedrag na 'n nuwe change-adres. Waarnemers kan veronderstel dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromitteer.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van veelvuldige adresse help om eienaarskap te verduister.

## **Sociale netwerke & forums blootstelling**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaksie-grafiekontleding**

Transaksies kan as grafieke gevisualiseer word, wat potensiële verbindings tussen gebruikers onthul gebaseer op die vloei van fondse.

## **Onnodige Inset Heuristiek (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met veelvuldige insette en uitsette om te raai watter uitset die verandering is wat terugkeer na die sender.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die toevoeging van meer insette daartoe lei dat die wissel-uitset groter is as enige enkele inset, kan dit die heuristiek in die war bring.

## **Forced Address Reuse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur in die hoop dat die ontvanger hierdie met ander insette in toekomstige transaksies kombineer, en sodoende adresse met mekaar verbind.

### Correct Wallet Behavior

Wallets moet vermy om munte wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privaatheids leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** 'n Ronde getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-ronde uitset wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir transaksieskepping, wat analiste in staat stel om die sagteware wat gebruik is te identifiseer en moontlik die change address.
- **Amount & Timing Correlations:** Die openbaarmaking van transaksietye of -bedrae kan transaksies opspoorbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel, wat gebruikers se privaatheid in gedrang bring. Dit is veral waar as 'n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë verbeter om transaksies te monitor.

## Meer

Vir 'n omvattende lys van privacy-aanvalle en verdedigings, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins Anoniem te Kry

- **Kontanttransaksies**: Verkryging van bitcoin deur kontant.
- **Kontantalternatiewe**: Aankoop van geskenkkaarte en omruiling aanlyn vir bitcoin.
- **Mining**: Die privaatste metode om bitcoins te verdien is deur mynbou, veral wanneer dit alleen gedoen word omdat mining pools moontlik die myner se IP-adres ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties sou diefstal van bitcoin 'n ander metode wees om dit anoniem te bekom, alhoewel dit onwettig is en nie aanbeveel word.

## Mengdienste

Deur 'n mengdiens te gebruik, kan 'n gebruiker bitcoins stuur en verskillende bitcoins terug ontvang, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue in die diens dat hulle nie logs behou en dat hulle die bitcoins werklik teruggee. Alternatiewe mengopsies sluit Bitcoin-kasino's in.

## CoinJoin

CoinJoin koppel meerdere transaksies van verskillende gebruikers saam in een, wat die proses bemoeilik vir enigiemand wat insette met uitsette probeer koppel. Ten spyte van die doeltreffendheid daarvan kan transaksies met unieke inset- en uitsetgroottes steeds moontlik opgetraceer word.

Voorbeeld-transaksies wat moontlik CoinJoin gebruik het sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met fondse van miners.

## PayJoin

'n Variant van CoinJoin, **PayJoin** (of P2EP), camoufleer die transaksie tussen twee partye (bv. 'n klant en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om te identifiseer en kan die common-input-ownership heuristic wat deur transaksiesurveillance-entiteite gebruik word ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos hierbo kan PayJoin wees, wat privaatheid verbeter terwyl hulle ononderskei­baar van standaard bitcoin-transaksies bly.

**Die gebruik van PayJoin kan tradisionele toesigmetodes beduidend ontwrig**, wat dit 'n belowende ontwikkeling in die strewe na transaksionele privaatheid maak.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Wallet Synchronization Techniques**

Om privaatheid en veiligheid te behou, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Full node**: Deur die volledige blockchain af te laai, verseker 'n full node maksimum privaatheid. Alle ooit gedane transaksies word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer watter transaksies of adresse die gebruiker interesseer.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat wallets toelaat om relevante transaksies te identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te lê. Liggewig wallets laai hierdie filters af en haal slegs volledige blokke wanneer 'n ooreenkoms met die gebruiker se adresse gevind word.

## **Utilizing Tor for Anonymity**

Aangesien Bitcoin op 'n peer-to-peer netwerk opereer, word dit aanbeveel om Tor te gebruik om jou IP-adres te maskeer, wat privaatheid verbeter wanneer jy met die netwerk kommunikeer.

## **Preventing Address Reuse**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Die hergebruik van adresse kan privaatheid kompromitteer deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Om 'n betaling in verskeie transaksies te verdeel kan die transaksiebedrag versluier en privaatheidsaanvalle belemmer.
- **Change avoidance**: Deur transaksies te kies wat geen change-outputs vereis, verbeter privaatheid deur change-detektiemetodes te ontwrig.
- **Multiple change outputs**: As dit nie prakties is om change te vermy nie, kan die skepping van meervoudige change-outputs steeds privaatheid verbeter.

# **Monero: A Beacon of Anonymity**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas meet die rekentejiede wat benodig word om operasies op Ethereum uit te voer, geprys in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimiet en 'n basiskoste, met 'n tip om miners te motiveer. Gebruikers kan 'n maksfooi stel om te verseker dat hulle nie oorbetaal nie; die oorskot word terugbetaal.

## **Executing Transactions**

Transaksies op Ethereum betrek 'n sender en 'n ontvanger, wat of gebruikersadresse of smart contract-adresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Belangrik: die sender se adres word uit die handtekening afgelei, wat die behoefte om dit in die transaksiedata op te neem, uitskakel.

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met kriptogeldeenhede wil handel terwyl hulle privaatheid en veiligheid prioritiseer.

## Value-Centric Web3 Red Teaming

- Inventariseer waarde-draende komponente (signers, oracles, bridges, automation) om te verstaan wie fondse kan beweeg en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT taktieke om privilegie-eskalasie-paaie bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain-aanvalskettings om impak te valideer en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

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

As jy praktiese uitbuiting van DEXes en AMMs ondersoek (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), kyk:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset gewigspools wat virtuele balansies cache en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
