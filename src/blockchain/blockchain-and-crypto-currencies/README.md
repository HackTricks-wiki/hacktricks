# Blokketting en kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Slimkontrakte** word gedefinieer as programme wat op ’n blokketting uitgevoer word wanneer sekere voorwaardes nagekom word. Dit outomatiseer die uitvoering van ooreenkomste sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou voort op slimkontrakte en beskik oor ’n gebruikersvriendelike voorkant en ’n deursigtige, ouditeerbare agterkant.
- **Tokens en munte** verskil daarin dat munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Nutsheidstokens** verleen toegang tot dienste, en **sekuriteitstokens** dui op bate-eienaarskap.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAO’s** verwys onderskeidelik na Gedesentraliseerde Uitruilplatforms en Gedesentraliseerde Outonome Organisasies.

## Konsensusmeganismes

Konsensusmeganismes verseker dat transaksies veilig bekragtig word en dat daar oor die bekragtiging ooreengekom word:

- **Proof of Work (PoW)** maak op rekenaarkrag staat om transaksies te verifieer.
- **Proof of Stake (PoS)** vereis dat valideerders ’n sekere hoeveelheid tokens besit, wat energieverbruik verminder in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-noodsaaklikhede

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan inisieer.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multihandtekeningstransaksies** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **insette** (bron van fondse), **uitsette** (bestemming), **fooie** (aan mynwerkers betaal) en **skripte** (transaksiereëls).

### Lightning Network

Die doel is om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat, terwyl slegs die finale toestand na die blokketting uitgesaai word.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verbloem.

## Bitcoin anoniem bekom

Metodes sluit kontanttransaksies, mynbou en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is transaksieprivaatheid en gebruikersanonimiteit dikwels rede tot kommer. Hier is ’n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privaatheid kan skend.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen ongewoon dat insette van verskillende gebruikers in een transaksie gekombineer word weens die kompleksiteit daarvan. Daarom word **daar dikwels aanvaar dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

’n UTXO, of **onbestede transaksie-uitset**, moet in ’n transaksie ten volle bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe kleingeldadres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te vermy, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verbloem.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaksiegraafontleding**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse onthul.

## **Onnodige-insetheuristiek (optimale-kleingeldheuristiek)**

Hierdie heuristiek berus op die ontleding van transaksies met verskeie insette en uitsette om te raai watter uitset die kleingeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die wisselgeld groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Gedwonge hergebruik van adresse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer en sodoende adresse aan mekaar koppel.

### Korrekte beursiegedrag

Beursies behoort te vermy om munte te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheidslek te voorkom.

## **Ander blockchain-ontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder wisselgeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is; die nie-ronde uitset is waarskynlik die wisselgeld.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware en moontlik die wisselgeldadres te identifiseer.
- **Bedrag- en tydskorrelasies:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikersprivaatheid in gevaar stel. Dit is veral waar as ’n entiteit baie Bitcoin-nodusse bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te verkry

- **Kontanttransaksies**: Verkryging van bitcoin deur kontant te gebruik.
- **Kontantalternatiewe**: Aankoop van geskenkbewyse en aanlynruil daarvan vir bitcoin.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynbou, veral wanneer dit alleen gedoen word, omdat mynpoele moontlik die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin nog ’n manier wees om dit anoniem te verkry, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins daarvoor terugkry**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue dat die diens nie logboeke hou nie en die bitcoins werklik terugbesorg. Alternatiewe mengopsies sluit Bitcoin-casino’s in.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers in een saam, wat dit moeiliker maak vir enigiemand wat probeer om insette by uitsette te pas. Ten spyte van die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik opgespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom ’n transaksie tussen twee partye (bv. ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die heuristiek vir gemeenskaplike inseteienaarskap ongeldig maak wat deur transaksietoesig-entiteite gebruik word.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar bly van standaard-bitcointransaksies.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksieprivaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Tegnieke vir beursiesinchronisasie**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinchroniseer. Twee metodes staan uit:

- **Volledige node**: Deur die hele blokketting af te laai, verseker ’n volledige node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir aanvallers onmoontlik maak om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Blokfiltrering aan die kliëntkant**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te lê. Liggewig-beursies laai hierdie filters af en haal slegs volledige blokke af wanneer ’n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknienetwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om ’n nuwe adres vir elke transaksie te gebruik. Hergebruik van adresse kan privaatheid in gevaar stel deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verdoesel word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingelduitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingelduitsette**: As kleingeld nie vermy kan word nie, kan die skep van veelvuldige kleingelduitsette steeds privaatheid verbeter.

# **Monero: ’n baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Verstaan gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basistarief, met ’n prioriteitstarief om valideerders aan te moedig om die transaksie in te sluit. Gebruikers kan ’n maksimumtarief stel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat gebruikers- of slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet in ’n blok ingesluit word. Belangrike inligting in ’n transaksie sluit die ontvanger, die sender se handtekening, die waarde, opsionele data, die gaslimiet en fooie in. Die sender se adres word merkwaardig genoeg uit die handtekening afgelei, wat beteken dat dit nie in die transaksiedata hoef te wees nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is grondliggend vir enigiemand wat met kriptogeldeenhede wil werk terwyl privaatheid en sekuriteit vooropgestel word.

## Waardegesentreerde Web3 Red Teaming

- Maak ’n inventaris van komponente wat waarde hou (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flash loans/orakels/bewyse van identiteit/kettingoorgrensaanvalle om die impak te bekragtig en uitbuitbare voorvereistes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van Web3-ondertekeningswerkvloei

- Manipulasie van die voorsieningsketting van beursie-UI’s kan EIP-712-vragte net voor ondertekening verander en geldige handtekeninge oes vir delegatecall-gebaseerde proxy-oorname (bv. oorskryf van slot-0 van Safe se masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Rekeningabstraksie (ERC-4337)

- Algemene foutmodusse vir slimrekeninge sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, toestandafhanklike validering, ERC-1271-herhaling en fooidreinering deur terugrol ná validering.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Slimkontrak-sekuriteit

- Mutasietoetsing om blinde kolle in toetssuites op te spoor:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integriteit van ZK-bewyse / zkVM-gas

Wanneer ’n bewysgenereerder ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder slegs dat die **gasprogram uitgevoer is soos geskryf**. As die gas **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysgenereerder ’n bewys genereer wat slaag terwyl die **openbare maatstawwe of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgaste

- Behandel private getuie-/kringgrepe as **onbetroubare aanvallerinvoer**, selfs al word dit deur die bewys versteek.
- Vermy om dit met ongekontroleerde hulpfunksies soos `rkyv::access_unchecked` te deserialiseer, tensy die grepe reeds buite die proses bekragtig is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet bekragtig word voordat hulle beheervloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **diskriminant buite die geldige reeks** kan inspuit, word elke daaropvolgende `match` op daardie waarde verdag.

### Jump-table / UB counter bypass

As Rust ’n groot `match` na ’n **springtabel** omskakel, kan ’n ongeldige enum-diskriminant **ongedefinieerde beheervloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Diskriminant buite die geldige reeks indekseer verby die eerste springtabel en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die boekhoudingspad word oorgeslaan. In ’n zkVM kan dit bewyse vervals wat onmoontlike maatstawwe rapporteer, soos minder gates, minder duur bewerkings of ander vervalste beperkte hulpbronne.

Kontrolelys vir hersiening:

- Soek enum-waardes wat deur ’n aanvaller beheer word en uit witness/private input gedeserialiseer word.
- Inspekteer herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + ongekontroleerde deserialisering + groot opcode-diapatching as ’n hoërisiko-kombinasie.
- Reverse engineer die gegenereerde binêre lêer indien nodig; die uitleg van die springtabel kan belangriker wees as die bronkode.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreteerders

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Vir omkeerbare/kwantumagtige instruksiestelle, maak seker dat operande wat verskillend moet wees, inderdaad beperk word om verskillend te wees. ’n Toffoli-/CCX-agtige bewerking wat soos volg geïmplementeer word:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

word onveilig as die gas nie verwerp nie:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In daardie geval vereenvoudig die oorgang tot:

```text
q = q ^ (q & q) = 0
```

This skep ’n **deterministiese terugstelprimitief** wat omkeerbaarheidsaannames verbreek en goedkoper, onbedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbrongebruik sertifiseer, kan aanvallers hiermee funksionele kontroles slaag terwyl hulle die kostemodel omseil wat die verifieerder glo afgedwing word.

### Wat om in ZK-stelsels te toets

- Fuzz alle gasparsers met misvormde enkoderings van witness/private-input.
- Bevestig dat enum-reeksvalidering plaasvind voordat opcode-versending plaasvind.
- Voeg semantiese kontroles by vir operand-aliasing en ander ongeldige instruksievorme.
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die gasprogram foutief is.

## Toestandsafhanklike magtiging

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-uitbuiting

As jy praktiese uitbuiting van DEX’e en AMM’s ondersoek (Uniswap v4-hooks, misbruik van afronding/precisie, flash-loan-versterkte swaps wat drempels oorskry), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-bate-geweegde poele wat virtuele saldo’s kas en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Bewys van belang - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Openbare sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is transaksies met veelvuldige handtekeninge? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se zero-knowledge-bewys van kwantumkriptanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kurwe-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronskattings en versagtings (reggestelde weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits-bewys-van-konsep-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
