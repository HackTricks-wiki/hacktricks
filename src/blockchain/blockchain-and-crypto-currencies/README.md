# Blockchain en Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat die uitvoering van ooreenkomste sonder tussengangers outomatiseer.
- **Decentralized Applications (dApps)** bou voort op smart contracts, met 'n gebruikersvriendelike voorkant en 'n deursigtige, ouditeerbare agterkant.
- **Tokens & Coins** verskil daarin dat coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Utility Tokens** verleen toegang tot dienste, en **Security Tokens** dui bate-eienaarskap aan.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidering op die blockchain:

- **Proof of Work (PoW)** maak staat op rekenaarkrag om transaksies te verifieer.
- **Proof of Stake (PoS)** vereis dat valideerders 'n sekere hoeveelheid tokens hou, wat energieverbruik verlaag in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-basiese beginsels

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis verskeie handtekeninge om 'n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (aan miners betaal) en **scripts** (transaksiereëls).

### Lightning Network

Die doel is om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne 'n kanaal toe te laat, en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Anonieme verkryging van Bitcoins

Metodes sluit kontanttransaksies, mining en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan aantas.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen ongewoon dat inputs van verskillende gebruikers weens die kompleksiteit in een transaksie gekombineer word. Daarom word **daar dikwels aanvaar dat twee input-adresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe wisseladres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaksiegrafiekontleding**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse onthul.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met veelvuldige inputs en outputs om te raai watter output die wisselgeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die wisselgeld-uitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Gedwonge Hergebruik van Adresse**

Aanvallers kan klein bedrae na adresse stuur wat voorheen gebruik is, in die hoop dat die ontvanger dit met ander insette in toekomstige transaksies kombineer en sodoende adresse aan mekaar koppel.

### Korrekte beursiegedrag

Beursies moet vermy om munte te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheidslek te voorkom.

## **Ander Blockchain-ontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder wisselgeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is; die nie-ronde uitset is waarskynlik die wisselgeld.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware en moontlik die wisselgeldadres te identifiseer.
- **Bedrag- en tydkorrelasies:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikers se privaatheid in gevaar stel. Dit geld veral wanneer ’n entiteit baie Bitcoin-nodes bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings, besoek [Bitcoin-privaatheid op Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonieme Bitcoin-transaksies

## Maniere om anoniem Bitcoins te kry

- **Kontanttransaksies**: Verkryging van bitcoin met kontant.
- **Kontantalternatiewe**: Koop geskenkbewyse en ruil dit aanlyn vir bitcoin.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynbou, veral wanneer jy dit alleen doen, aangesien mynboupoele dalk die mynwerker se IP-adres ken. [Inligting oor mynboupoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan die steel van bitcoin ’n ander manier wees om dit anoniem te verkry, hoewel dit onwettig en nie aanbeveelbaar is nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins daarvoor terugontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter dat die gebruiker vertrou dat die diens nie logs hou nie en die bitcoins wel terugstuur. Bitcoin-casino’s is ’n alternatiewe mengopsie.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers saam in een, wat dit moeiliker maak vir enigiemand om insette met uitsette te verbind. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik nagespoor word.

Voorbeelde van transaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die heuristiek vir gemeenskaplike inset-eienaarskap wat deur transaksietoesig-entiteite gebruik word, ongeldig maak.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie van standaard-bitcointransaksies onderskei kan word nie.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling in die strewe na transaksieprivaatheid maak.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Tegnieke vir beursiesinchronisasie**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinchroniseer. Twee metodes staan uit:

- **Volledige node**: Deur die hele blokketting af te laai, verseker ’n volledige node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir teenstanders onmoontlik maak om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkant-blokfiltrering**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te lê. Liggewigbeursies laai hierdie filters af en haal slegs volledige blokke op wanneer ’n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknienetwerk werk, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie ’n nuwe adres te gebruik. Hergebruik van adresse kan privaatheid in gedrang bring deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verbloem word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingelduitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingelduitsette**: As dit nie haalbaar is om kleingeld te vermy nie, kan die skep van veelvuldige kleingelduitsette steeds privaatheid verbeter.

# **Monero: ’n baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Begrip van gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basisfooi, met ’n prioriteitsfooi om valideringsnodusse aan te spoor om die transaksie in te sluit. Gebruikers kan ’n maksimumfooi instel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat óf gebruiker- óf slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet in ’n blok ingesluit word. Noodsaaklike inligting in ’n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word veral uit die handtekening afgelei, wat beteken dat dit nie in die transaksiedata nodig is nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is grondliggend vir enigiemand wat met kriptogeldeenhede wil werk terwyl privaatheid en sekuriteit vooropgestel word.

## Web3 Red Teaming wat op waarde fokus

- Inventariseer waardedraende komponente (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan toepaslike MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flitslenings/orakels/eiebewyse/oorgrensaksies om die impak te bekragtig en uitbuitbare voorvereistes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van die Web3-ondertekeningswerkvloei

- Peuterwerk met die voorsieningsketting van beursie-UI’s kan EIP-712-loonvragte net voor ondertekening verander en geldige handtekeninge oes vir proxy-oorname gebaseer op delegatecall (bv. oorwriting van slot-0 van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraksie van rekeninge (ERC-4337)

- Algemene mislukkingsmodusse van slimrekeninge sluit in die omseiling van toegangsbeheer in `EntryPoint`, ongetekende gasvelde, toestandsgebonde validering, ERC-1271-herhaling en fooi-uitputting deur ’n terugrol ná validering.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Slimkontrak-sekuriteit

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK-bewys-/zkVM-gasheerintegriteit

Wanneer ’n bewysleweraar ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder slegs dat die **gasheerprogram uitgevoer is soos geskryf**. As die gasheer **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysleweraar ’n bewys genereer wat slaag terwyl die **openbare maatstawwe of beweerde invariant vals is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgasheerprogramme

- Behandel private witness-/kringgrepe as **ongeloofwaardige aanvallersinvoer**, selfs al word dit deur die bewys verberg.
- Vermy deserialisering daarmee met ongekontroleerde helpers soos `rkyv::access_unchecked`, tensy die grepe reeds buite die stelsel gevalideer is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet gevalideer word voordat hulle beheerlogika of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **buite-reeks-discriminant** kan inspuit, word elke daaropvolgende `match` op daardie waarde verdag.

### Omseiling van tellers met springtabel / UB

As Rust ’n groot `match` na ’n **springtabel** omskakel, kan ’n ongeldige enum-discriminant **ongedefinieerde beheer vloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Buite-reeks-discriminant indekseer verby die eerste springtabel en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit bewyse vervals wat onmoontlike maatstawwe rapporteer, soos minder hekke, minder duur bewerkings of ander vervalste begrensde hulpbronne.

Kontrolelys vir hersiening:

- Soek enums wat deur ’n aanvaller beheer word en uit witness-/private invoer gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + onkontroleerde deserialisering + groot opcode-versending as ’n hoërisikokombinasie.
- Reverse engineer die geëmiteerde binêre lêer wanneer nodig; die uitleg van die springtabel kan belangriker wees as die bronkode.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde tolke

Moenie net geheueveiligheid bekragtig nie; bekragtig ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Vir omkeerbare/kwantumagtige instruksiestelle, maak seker dat operande wat verskillend moet wees, werklik beperk word om verskillend te wees. ’n Toffoli-/CCX-agtige bewerking wat soos volg geïmplementeer word:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

word onveilig as die gas nie verwerp nie:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In daardie geval reduseer die oorgang tot:

```text
q = q ^ (q & q) = 0
```

Dit skep ’n **deterministiese terugstel-primitief**, wat omkeerbaarheidsaannames verbreek en goedkoper, onbedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbronverbruik attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die kostemodel omseil wat die verifieerder glo afgedwing word.

### Wat om in ZK-stelsels te toets

- Fuzz alle guest-parsers met misvormde witness-/private-input-enkoderings.
- Bevestig enum-reeksvalidering voordat opcode-dispatch plaasvind.
- Voeg semantiese kontroles by vir operandaliasing en ander ongeldige instruksievorme.
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die guest-program foutief is.

## Toestemming wat van toestand afhang

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-uitbuiting

As jy praktiese uitbuiting van DEX’e en AMM’s ondersoek (Uniswap v4-hooks, afrondings-/presisie-uitbuiting, swaps wat drempels oorskry en deur flash loans versterk word), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-bate-geweegde poele wat virtuele saldo’s kas en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Openbare sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multisig-transaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se nulkennisbewys van kwantumkriptoanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kromme-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronskattings en versagtingsmaatreëls (reggestelde weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits-bewys-van-konsep-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
