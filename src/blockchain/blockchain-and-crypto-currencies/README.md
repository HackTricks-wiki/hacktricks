{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Slimme Kontrakte** word gedefinieer as programme wat op 'n blockchain uitvoer wanneer sekere voorwaardes nagekom word, wat die uitvoering van ooreenkomste outomatiseer sonder intermediêre.
- **Gedecentraliseerde Toepassings (dApps)** bou voort op slim kontrakte, met 'n gebruikersvriendelike front-end en 'n deursigtige, auditeerbare back-end.
- **Tokens & Munte** onderskei waar munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Nut Tokens** bied toegang tot dienste, en **Sekuriteit Tokens** dui eienaarskap van bates aan.
- **DeFi** staan vir Gedecentraliseerde Finansies, wat finansiële dienste bied sonder sentrale owerhede.
- **DEX** en **DAOs** verwys na Gedecentraliseerde Uitruil Platforms en Gedecentraliseerde Outonome Organisasies, onderskeidelik.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksie-validasies op die blockchain:

- **Bewys van Werk (PoW)** staat op rekenaarkrag vir transaksie-verifikasie.
- **Bewys van Belang (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik in vergelyking met PoW verminder.

## Bitcoin Essensieel

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word geverifieer deur digitale handtekeninge, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.

#### Sleutelkomponente:

- **Multihandtekening Transaksies** vereis verskeie handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **insette** (bron van fondse), **uitsette** (bestemming), **fooie** (betaal aan mynwerkers), en **scripts** (transaksie-reëls).

### Lightning Netwerk

Streef daarna om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne 'n kanaal toe te laat, en slegs die finale toestand aan die blockchain te broadcast.

## Bitcoin Privaatheidkwessies

Privaatheidaanvalle, soos **Algemene Inset Eienaarskap** en **UTXO Veranderadres Ontdekking**, benut transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieverbindinge tussen gebruikers te verdoesel.

## Verkryging van Bitcoins Anoniem

Metodes sluit kontanthandel, mynwerk en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om die opspoorbaarheid te kompliseer, terwyl **PayJoin** CoinJoins as gewone transaksies verdoesel vir verhoogde privaatheid.

# Bitcoin Privaatheid Aanvalle

# Samevatting van Bitcoin Privaatheid Aanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels onderwerpe van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin privaatheid kan kompromitteer.

## **Algemene Inset Eienaarskap Aannames**

Dit is oor die algemeen selde dat insette van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit wat betrokke is. Dus, **twee inset adresse in dieselfde transaksie word dikwels veronderstel om aan dieselfde eienaar te behoort**.

## **UTXO Veranderadres Ontdekking**

'n UTXO, of **Onbestedigde Transaksie-uitset**, moet heeltemal in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die oorblywende na 'n nuwe veranderadres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromitteer.

### Voorbeeld

Om dit te verminder, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Sosiale Netwerke & Forums Blootstelling**

Gebruikers deel soms hul Bitcoin adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaksie Grafiek Analise**

Transaksies kan as grafieke gevisualiseer word, wat potensiële verbindings tussen gebruikers onthul op grond van die vloei van fondse.

## **Onnodige Inset Heuristiek (Optimale Verander Heuristiek)**

Hierdie heuristiek is gebaseer op die analise van transaksies met verskeie insette en uitsette om te raai watter uitset die verandering is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As jy meer invoere byvoeg wat die verandering uitvoer groter maak as enige enkele invoer, kan dit die heuristiek verwarrend maak.

## **Gedwonge Adres Hergebruik**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit saam met ander invoere in toekomstige transaksies kombineer, wat adresse aan mekaar koppel.

### Korrek Wallet Gedrag

Wallets moet vermy om munte wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privaatheidslek te voorkom.

## **Ander Blockchain Analise Tegnieke**

- **Presiese Betalingsbedrae:** Transaksies sonder verandering is waarskynlik tussen twee adresse wat aan dieselfde gebruiker behoort.
- **Ronde Getalle:** 'n Ronde getal in 'n transaksie dui aan dat dit 'n betaling is, met die nie-ronde uitvoer wat waarskynlik die verandering is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke transaksie skeppingspatrone, wat ontleders in staat stel om die sagteware wat gebruik is te identifiseer en moontlik die verandering adres.
- **Bedrag & Tyds korrelasies:** Die bekendmaking van transaksietye of -bedrae kan transaksies opspoorbaar maak.

## **Verkeersanalise**

Deur netwerkverkeer te monitor, kan aanvallers potensieel transaksies of blokke aan IP adresse koppel, wat gebruikers se privaatheid in gevaar stel. Dit is veral waar as 'n entiteit baie Bitcoin nodes bedryf, wat hul vermoë om transaksies te monitor verbeter.

## Meer

Vir 'n omvattende lys van privaatheid aanvalle en verdediging, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonieme Bitcoin Transaksies

## Manier om Bitcoins Anoniem te Verkry

- **Kontant Transaksies**: Verkryging van bitcoin deur kontant.
- **Kontant Alternatiewe**: Aankoop van geskenkbewyse en dit aanlyn vir bitcoin ruil.
- **Myn**: Die mees private metode om bitcoins te verdien is deur mynbou, veral wanneer dit alleen gedoen word omdat mynboupoele die mynwerker se IP adres mag ken. [Mynpoele Inligting](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin 'n ander metode wees om dit anoniem te verkry, alhoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur 'n mengdiens te gebruik, kan 'n gebruiker **bitcoins stuur** en **verskillende bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar te spoor. Tog vereis dit vertroue in die diens om nie logs te hou nie en om werklik die bitcoins terug te stuur. Alternatiewe mengopsies sluit Bitcoin-kasino's in.

## CoinJoin

**CoinJoin** kombineer verskeie transaksies van verskillende gebruikers in een, wat die proses vir enigiemand wat probeer om invoere met uitvoere te pas, kompliseer. Ten spyte van sy doeltreffendheid, kan transaksies met unieke invoer- en uitvoergroottes steeds potensieel opgespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies met fondse van mynwerkers anoniem maak.

## PayJoin

'n Variant van CoinJoin, **PayJoin** (of P2EP), verberg die transaksie tussen twee partye (bv. 'n klant en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitvoer wat tipies van CoinJoin is. Dit maak dit uiters moeilik om te detecteer en kan die algemene-invoer-eienaarskap heuristiek wat deur transaksie toesig entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar bly van standaard bitcoin transaksies.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksie privaatheid.

# Beste Praktyke vir Privaatheid in Kriptogeldeenhede

## **Waldoorsinkroniseringstegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om waldoors met die blockchain te sinkroniseer. Twee metodes val op:

- **Volle node**: Deur die hele blockchain af te laai, verseker 'n volle node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer watter transaksies of adresse die gebruiker belangstel in.
- **Kliënt-kant blokfiltering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat waldoors in staat stel om relevante transaksies te identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Liggewig waldoors laai hierdie filters af, en haal slegs volle blokke af wanneer 'n ooreenstemming met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir Anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer netwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg, wat privaatheid verbeter wanneer jy met die netwerk interaksie het.

## **Voorkoming van Adres Hergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Hergebruik van adresse kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne waldoors ontmoedig adres hergebruik deur hul ontwerp.

## **Strategieë vir Transaksie Privaatheid**

- **Meervoudige transaksies**: Om 'n betaling in verskeie transaksies te verdeel kan die transaksiebedrag verdoesel, wat privaatheid aanvalle verhoed.
- **Verandering vermyding**: Om transaksies te kies wat nie verandering-uitsette vereis nie, verbeter privaatheid deur verandering detectiemetodes te ontwrig.
- **Meervoudige verandering-uitsette**: As dit nie moontlik is om verandering te vermy nie, kan die generering van meervoudige verandering-uitsette steeds privaatheid verbeter.

# **Monero: 'n Baken van Anonimiteit**

Monero adressering die behoefte aan absolute anonimiteit in digitale transaksies, wat 'n hoë standaard vir privaatheid stel.

# **Ethereum: Gas en Transaksies**

## **Begrip van Gas**

Gas meet die rekenkundige inspanning wat nodig is om operasies op Ethereum uit te voer, geprys in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimiet en 'n basisfooi, met 'n fooi om mynwerkers te motiveer. Gebruikers kan 'n maksimum fooi stel om te verseker dat hulle nie oorbetaal nie, met die oorskot wat terugbetaal word.

## **Uitvoering van Transaksies**

Transaksies in Ethereum behels 'n sender en 'n ontvanger, wat óf gebruiker of slimkontrak adresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, sender se handtekening, waarde, opsionele data, gaslimiet, en fooie in. Opmerklik is dat die sender se adres afgelei word van die handtekening, wat die behoefte daaraan in die transaksiedata uitskakel.

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat wil betrokke raak by kriptogeldeenhede terwyl hulle privaatheid en sekuriteit prioritiseer.

## Verwysings

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../../banners/hacktricks-training.md}}
