# Blockchain en kriptogeldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Slimkontrakte** word gedefinieer as programme wat op ’n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word. Dit outomatiseer die uitvoering van ooreenkomste sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou voort op slimkontrakte en beskik oor ’n gebruikersvriendelike voorkant en ’n deursigtige, ouditbare agterkant.
- **Tokens en munte** verskil daarin dat munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Nutstokens** gee toegang tot dienste, en **sekuriteitstokens** dui op bate-eienaarskap.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAO’s** verwys onderskeidelik na gedesentraliseerde uitruilplatforms en gedesentraliseerde outonome organisasies.

## Konsensusmeganismes

Konsensusmeganismes verseker dat transaksies op die blockchain veilig en volgens ooreenkoms bekragtig word:

- **Bewys van Werk (PoW)** maak staat op rekenaarkrag om transaksies te verifieer.
- **Bewys van Inset (PoS)** vereis dat valideerders ’n sekere hoeveelheid tokens hou, wat energieverbruik verlaag in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-basics

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multihandtekeningtransaksies** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **invoere** (bron van fondse), **uitvoere** (bestemming), **fooie** (aan mynwerkers betaal) en **skripte** (transaksiereëls).

### Lightning Network

Die doel is om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **gemeenskaplike invoereienaarskap** en **UTXO-wisseladresopsporing**, buit transaksiepatrone uit. Strategieë soos **mengdienste** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verberg.

## Bitcoin anoniem verkry

Metodes sluit kontanthandel, mynbou en die gebruik van mengdienste in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die Bitcoin-wêreld is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier is ’n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privaatheid kan skend.<sup>[[6]](#references)</sup>

## **Aanname van gemeenskaplike invoereienaarskap**

Dit is oor die algemeen ongewoon dat invoere van verskillende gebruikers in een transaksie gekombineer word weens die kompleksiteit daarvan. Daarom word **daar dikwels aangeneem dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **Opsporing van UTXO-wisseladresse**

’n UTXO, of **Onbestede transaksie-uitset**, moet volledig in ’n transaksie bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe wisseladres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gedrang bring.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verberg.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaksiegraafontleding**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse onthul.

## **Heuristiek vir onnodige invoere (optimale-wisselheuristiek)**

Hierdie heuristiek berus op die ontleding van transaksies met verskeie invoere en uitvoere om te raai watter uitvoer die wisselgeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die kleingeld-uitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Gedwonge hergebruik van adresse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer en sodoende adresse aan mekaar koppel.

### Korrekte beursiegedrag

Beursies behoort te vermy om munte te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheidslek te voorkom.

## **Ander blockchain-ontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder kleingeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde getalle:** ’n Ronde getal in ’n transaksie dui daarop dat dit ’n betaling is, terwyl die nie-ronde uitset waarskynlik die kleingeld is.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware en moontlik die kleingeldadres te identifiseer.
- **Korrelasies tussen bedrae en tydstippe:** Die bekendmaking van transaksietye of -bedrae kan dit moontlik maak om transaksies op te spoor.

## **Verkeerontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikersprivaatheid in gevaar stel. Dit is veral die geval as ’n entiteit baie Bitcoin-nodusse bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te verkry

- **Kontanttransaksies**: Verkryging van bitcoin deur kontant te gebruik.
- **Kontantalternatiewe**: Koop geskenkbewyse en ruil dit aanlyn vir bitcoin.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynbou, veral as dit alleen gedoen word, omdat mynpoele moontlik die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin ’n ander manier wees om dit anoniem te verkry, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins daarvoor terugontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter dat die gebruiker vertrou dat die diens nie logs hou nie en die bitcoins wel terugstuur. Bitcoin-casino’s is ’n alternatiewe mengopsie.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers saam in een, wat dit moeiliker maak vir enigiemand om insette met uitsette te verbind. Ten spyte van die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik opgespoor word.

Voorbeelde van transaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei, sien [Tornado Cash](https://tornado.cash).

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. ’n kliënt en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die algemene-inset-eienaarskapheuristiek wat deur transaksietoesighoudende entiteite gebruik word, ongeldig maak.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar van standaard-bitcointransaksies bly.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksieprivaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Tegnieke vir beursiesinchronisasie**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinchroniseer. Twee metodes staan uit:

- **Volle node**: Deur die hele blokketting af te laai, verseker ’n volle node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir teenstanders onmoontlik maak om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkant-blokfiltrering**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Liggewigbeursies laai hierdie filters af en haal slegs volledige blokke op wanneer ’n pasmaat met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknienetwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie ’n nuwe adres te gebruik. Hergebruik van adresse kan privaatheid in gevaar stel deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verdoesel word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingelduitsette vereis nie, verbeter privaatheid deur metodes vir kleingeldherkenning te ontwrig.
- **Veelvuldige kleingelduitsette**: As dit nie haalbaar is om kleingeld te vermy nie, kan die skep van veelvuldige kleingelduitsette steeds privaatheid verbeter.

# **Monero: ’n Baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Verstaan van gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. ’n Transaksie wat byvoorbeeld 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basisfooi, met ’n prioriteitsfooi om insluiting deur ’n valideerder aan te moedig. Gebruikers kan ’n maksimumfooi instel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat gebruikers- of slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet in ’n blok ingesluit word. Noodsaaklike transaksie-inligting sluit die ontvanger, sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word veral uit die handtekening afgelei, wat dit onnodig maak om dit by die transaksiedata in te sluit.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met kriptogeldeenhede wil werk terwyl privaatheid en sekuriteit vooropgestel word.

## Waardegesentreerde Web3 Red Teaming

- Stel ’n inventaris op van waardedraende komponente (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flitslenings/orakels/geloofsbriewe/kettingoorgrenskomponente om die impak te bevestig en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van Web3-ondertekenwerkvloei

- Toepeutering met die voorsieningsketting van wallet-UI’s kan EIP-712-vragte onmiddellik voor ondertekening verander en geldige handtekeninge insamel vir proxy-oorname op grond van delegatecall (bv. oorskryf van slot-0 van Safe se masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Rekeningabstraksie (ERC-4337)

- Algemene foutmodusse van slimrekeninge sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, toestandsvolle validering, ERC-1271-herhaling en fooidreinasie deur terugrol ná validering.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sekuriteit van slimkontrakte

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integriteit van ZK-bewyse / zkVM-gaste

Wanneer ’n bewysleweraar ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, kom die verifieerder net te wete dat die **gasprogram uitgevoer is soos geskryf**. As die gas **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysleweraar ’n bewys genereer wat slaag terwyl die **openbare maatstawwe of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgaste

- Behandel private getuie-/kringgrepe as **onbetroubare aanvallersinvoer**, selfs al word hulle deur die bewys versteek.
- Vermy deserialisering daarvan met ongekontroleerde hulpfunksies soos `rkyv::access_unchecked`, tensy die grepe reeds op ’n ander manier gevalideer is.
- Enum-onderskeiers, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet gevalideer word voordat hulle beheervloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **discriminant buite die geldige reeks** kan inspuit, is elke daaropvolgende `match` oor daardie waarde verdag.

### Omseiling van tellers met ’n springtabel / UB

As Rust ’n groot `match` in ’n **springtabel** omskakel, kan ’n ongeldige enum-discriminant **ongedefinieerde beheer­vloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Discriminant buite die geldige reeks indekseer verby die eerste springtabel en beland in kode wat met die tweede geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit bewyse vervals wat onmoontlike maatstawwe rapporteer, soos minder hekke, minder duur bewerkings of ander vervalste beperkte hulpbronne.

Kontrolelys vir hersiening:

- Soek na aanvallerbeheerde enums wat uit witness-/private invoer gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + ongekontroleerde deserialisering + groot opcode-versending as ’n kombinasie met hoë risiko.
- Reverse-engineer die gegenereerde binary wanneer nodig; die uitleg van springtabelle kan belangriker wees as die bronkode.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreteerders

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Maak vir omkeerbare/kwantumagtige instruksiestelle seker dat operande wat verskillend moet wees, inderdaad beperk word om verskillend te wees. ’n Toffoli-/CCX-agtige bewerking wat soos volg geïmplementeer word:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

word onveilig as die gas dit nie verwerp nie:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In daardie geval vereenvoudig die oorgang tot:

```text
q = q ^ (q & q) = 0
```

Dit skep ’n **deterministiese reset-primitief** wat omkeerbaarheidsaannames verbreek en goedkoper, onbedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbronverbruik attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die kostemodel omseil wat die verifieerder glo afgedwing word.

### Onderbeperkte prover-advies en modulêre rekenkunde

Waardes wat vanaf ’n **advies-/getuienstapel** gelaai word, word deur die prover beheer, selfs wanneer hulle beskryf word as voorafberekende kwosiënte, reste, inverse of wenke. ’n Bewys stel slegs vas dat die getuie aan die geïmplementeerde beperkings voldoen; dit stel nie die bedoelde berekening vas as daardie beperkings ’n tipe-, reeks- of kanonieke-vorm-kontrole weglaat nie.<sup>[[13]](#references)</sup>

Vir ’n reduksie- of Euklidiese-delingshulpfunksie, oudit die volledige heelgetalrelasie eerder as net die finale aftrekking of vermenigvuldiging. Elke limb van `q` en `r` moet tot sy verklaarde breedte beperk word, die rekonstruksie `x = q * m + r` moet in die bedoelde heelgetalvoorstelling geld, en die kanonieke grens `0 <= r < m` moet afgedwing word. Valideer ’n waarde **voordat** dit aan ’n nouer `u32`/`u64`-instruksie deurgegee word; ’n noue bewerking bewys nie terugwerkend dat die oorspronklike veld-element of multi-limb-waarde die verwagte tipe gehad het nie.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Die `mod_12289`-fout in Miden illustreer die uitbuitingspatroon: die kwosiënt is as ’n 64-bis-waarde met twee limbs nagegaan, maar die adviesverskafde res het `u32overflowing_sub` bereik sonder ekwivalente validering. ’n Kwaadwillige prover kon ongeldige kwosiënt- en reswaardes koördineer sodat die geïmplementeerde aftrekkingsbeperkings steeds geld, terwyl die prosedure ’n nie-wiskundige res teruggee. Omdat hierdie resultaat vir Falcon-verifikasie gebruik is, kon die soundness-fout uitgebuit word om vervalste magtiginghandtekeninge te skep, eerder as om bloot ’n verkeerde rekenkundige resultaat te lewer.<sup>[[13]](#references)</sup>

### Oudit van kriptografiese VM's met implisiete stapels

Stapeltale verberg operande, dus lig eers die instruksies na ’n IR waarin elke verbruikte en geproduseerde stapelwaarde ’n uitdrukking met herkoms is. ’n Konserwatiewe ontledingspyplyn kan dan:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Bou die oproepgrafiek en lei prosedure-invoer-/afvoerstapeleffekte af.
2. Voer ondersteunde instruksies simbolies uit en lig die beheervloei na SSA-/gestruktureerde uitdrukkings.
3. Propageer abstrakte feite soos `Unknown`, `ProvenU32`, `Bool`, waardeherkoms en plaaslike initialisering totdat ’n vaste punt bereik word.
4. Merk adviesafgeleide waardes wat getipeerde rekenkunde of nie-nul-teikens bereik sonder ’n saniteerder op **elke** inkomende pad.
5. Vergelyk verklaarde en afgeleide handtekeninge en verifieer dat elke uitgang oproeper-besitte stapelwaardes behou.

Behandel ’n onbekende handtekening of nie-ondersteunde konstruksie as ’n **ontledingsgaping**, nie as ’n skoon uitslag nie. Dinamiese oproepe, lusse wat nie stapelneutraal is nie en vertakkings met verskillende stapeleffekte kan dit onmoontlik maak om stapelgleufnasporing betroubaar te doen; ’n veiliger dekompileerder verwerp of merk sulke gevalle eerder as om geloofwaardige maar verkeerde pseudokode uit te gee.<sup>[[10]](#references)[[13]](#references)</sup>

By beheervloeisamevoegings, behou ’n eienskap slegs wanneer dit op elke voorganger geld (byvoorbeeld, `ProvenU32 join Unknown = Unknown`). Onderskei ook tussen vastepuntkonvergensie en die bereik van ’n iterasielimiet: slegs ’n gekonvergeerde, betroubare oorbenadering kan regverdig dat die afwesigheid van ’n diagnostiese boodskap as bewys dien dat alle voorgestelde uitvoerings aan die eienskap voldoen.<sup>[[11]](#references)</sup>

### Gebruik bewysverpligtinge om verborge voorvereistes bloot te lê

Vir klein instruksiestelle, vertaal prosedures na ’n uitvoerbare formele VM-model en bewys sowel die resultaat as die volledige stapeltransformasie. Die stelling moet terminering, getipeerde insette, die verwagte uitvoervoorvoegsel en die behoud van die onaangeraakte oproeperstapel dek. Gaan die stelling net so noukeurig na as die bewys: die kern kan ’n bewys van ’n per ongeluk verswakte bewering valideer.<sup>[[12]](#references)[[13]](#references)</sup>

Onverwagte hipoteses is nuttige bevindings. In die Miden-oorsig het ’n bewys vir 64-bis-rotasie na regs `shift mod 32 != 0` vereis, wat ’n foutgeval vir groot insette blootgelê het wanneer die skuif ’n veelvoud van 32 was; ’n ander bewys het bevind dat 256-bis-`wrapping_mul` oproeper-besitte stapelwaardes weggegooi het. Voeg die ontdekte randgeval by die toetse, en herstel dan die implementering of versterk die openbare voorvereiste doelbewus eerder as om die ekstra aanname stilweg te aanvaar.<sup>[[12]](#references)[[13]](#references)</sup>

### Wat om in ZK-stelsels te toets

- Fuzz alle gasheerontleders met misvormde witness-/private-invoerkodering.
- Bevestig enum-omvangvalidering voor opcode-versending.
- Voeg semantiese kontroles by vir operand-aliasing en ander ongeldige instruksievorme.
- Volg elke advies-/witness-bron tot by elke getipeerde rekenkundige teiken en vereis validering op elke pad.<sup>[[11]](#references)[[13]](#references)</sup>
- Toets rekenkundige helpers met nie-kanonieke limbs, buitebereik-reswaardes en grenswaardes vir skuiftellings.<sup>[[12]](#references)[[13]](#references)</sup>
- Bevestig stapelhoogte en behoud van waardes onder die prosedure se verklaarde argumente by elke terugkeer.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die gasheerprogram foutief is.

## Toestandafhanklike magtiging

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-uitbuiting

As jy praktiese uitbuiting van DEX'e en AMM's ondersoek (Uniswap v4 hooks, misbruik van afronding/akkuraatheid, flash-loan-versterkte swaps wat drempels oorskry), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-bate-geweegde poele wat virtuele saldo's kas en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Bewys van belang - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Openbare sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multi-handtekeningtransaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se zero-knowledge-bewys van kwantumkriptanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kromme-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronskattings en versagtingsmaatreëls (reggestelde weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits-bewys-van-konsep-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM-dekompileerderargitektuur](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM-statiese-ontledingsenjin](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-na-Lean-model en korrektheidsbewyse](https://github.com/trailofbits/masm-lean)
- [13] [Ouditering in die era van (goed genoeg) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
