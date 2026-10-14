# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Smart Contracts** word gedefinieer as programme wat op ’n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat ooreenkomste outomatiseer sonder tussengangers.
- **Decentralized Applications (dApps)** bou voort op smart contracts, met ’n gebruikersvriendelike front-end en ’n deursigtige, ouditeerbare back-end.
- **Tokens & Coins** verskil daarin dat coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui op bate-eienaarskap.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale gesag.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

Vir terminologie oor spotbestellings, termynkontrakte, hefboomfinansiering en opsies wat in kriptomarkte gebruik word, sien [Beleggingsterme](investment-terms.md).

## Konsensusmeganismes

Konsensusmeganismes verseker dat transaksies op die blockchain veilig en volgens ooreenkoms bekragtig word:

- **Proof of Work (PoW)** maak staat op rekenaarkrag om transaksies te verifieer.
- **Proof of Stake (PoS)** vereis dat validators ’n sekere hoeveelheid tokens hou, wat energieverbruik verminder in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-noodsaaklikhede

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners) en **scripts** (transaksiereëls).

### Lightning Network

Dit beoog om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Kommer oor Bitcoin-privaatheid

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Bitcoin anoniem bekom

Metodes sluit in kontanthandel, mining en die gebruik van mixers. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom om privaatheid verder te verbeter.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier is ’n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan benadeel.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen ongewoon dat inputs van verskillende gebruikers in ’n enkele transaksie gekombineer word weens die betrokke kompleksiteit. Daarom word **daar dikwels aanvaar dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

’n UTXO, of **Unspent Transaction Output**, moet volledig in ’n transaksie bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe kleingeldadres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid benadeel.

### Voorbeeld

Om dit te beperk, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## Blootstelling op sosiale netwerke en forums

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## Transaksiegraaf-ontleding

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse openbaar.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met verskeie inputs en outputs om te raai watter output die kleingeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die change-uitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Forced Address Reuse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer en sodoende adresse aan mekaar koppel.

### Korrekte beursiegedrag

Beursies behoort te voorkom dat coins wat ontvang is by reeds gebruikte, leë adresse gebruik word, om hierdie privaatheidslek te voorkom.

## **Ander blockchain-ontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is, en die nie-ronde uitset is waarskynlik die change.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware te identifiseer en moontlik die change-adres te bepaal.
- **Korrelasies tussen bedrae en tydstippe:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Verkeerontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikersprivaatheid in gevaar stel. Dit is veral die geval as ’n entiteit baie Bitcoin-nodes bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te kry

- **Kontanttransaksies**: Verkryging van bitcoin deur kontant te gebruik.
- **Kontantalternatiewe**: Koop geskenkbewyse en ruil dit aanlyn vir bitcoin.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur myn te doen, veral wanneer dit alleen gedoen word, aangesien mynpoele dalk die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin nog ’n manier wees om dit anoniem te bekom, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter vertroue dat die diens nie logs hou nie en wel die bitcoins terugstuur. Alternatiewe mengopsies sluit Bitcoin-casino’s in.

## CoinJoin

**CoinJoin** kombineer verskeie transaksies van verskillende gebruikers in een, wat dit moeiliker maak vir enigiemand om insette met uitsette te pas. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. ’n kliënt en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die heuristiek vir gemeenskaplike inset-eienaarskap wat deur transaksie-toesigentiteite gebruik word, ongeldig maak.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie van standaard-bitcointransaksies onderskei kan word nie.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig** en is dus ’n belowende ontwikkeling in die strewe na transaksieprivaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Tegnieke vir beursiesinkronisering**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinchroniseer. Twee metodes staan uit:

- **Volledige node**: Deur die hele blokketting af te laai, verseker ’n volledige node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir teenstanders onmoontlik maak om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Blokfiltrering aan die kliëntkant**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Liggewigbeursies laai hierdie filters af en haal slegs volledige blokke op wanneer ’n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknienetwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg en sodoende privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie ’n nuwe adres te gebruik. Adreshergebruik kan privaatheid in gedrang bring deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verbloem word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingelduitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingelduitsette**: As dit nie haalbaar is om kleingeld te vermy nie, kan die skep van veelvuldige kleingelduitsette steeds privaatheid verbeter.

# **Monero: ’n Baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid te prioritiseer.

# **Ethereum: Gas en transaksies**

## **Begrip van gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, het ’n gaslimiet en ’n basisfooi, met ’n prioriteitsfooi om validators aan te spoor om die transaksie in te sluit. Gebruikers kan ’n maksimumfooi stel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat albei óf gebruikeradresse óf slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet in ’n blok ingesluit word. Noodsaaklike inligting in ’n transaksie sluit die ontvanger, die sender se handtekening, die waarde, opsionele data, die gaslimiet en fooie in. Die sender se adres word veral uit die handtekening afgelei, wat beteken dat dit nie in die transaksiedata nodig is nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met kriptogeldeenhede wil omgaan terwyl privaatheid en sekuriteit geprioritiseer word.

## Web3 Red Teaming met fokus op waarde

- Maak ’n inventaris van komponente wat waarde bevat (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flitslenings/orakels/geloofsbriewe/kruiskettingaanvalle om die impak te bevestig en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van Web3-ondertekeningswerkvloei

- Knoeiery met die voorsieningsketting van wallet-UI’s kan EIP-712-vragte verander net voordat dit onderteken word, en sodoende geldige handtekeninge insamel vir proxy-oorname met delegatecall (bv. oorskryf van slot-0 van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Rekeningabstraksie (ERC-4337)

- Algemene fouttipes in slimrekeninge sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, toestandsvolle validering, ERC-1271-herhaling en fooidreinering deur ná validering terug te keer.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Slimkontraksekuriteit

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integriteit van ZK-bewyse / zkVM-gasprogramme

Wanneer ’n bewysleweraar ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder slegs dat die **gasprogram uitgevoer is soos geskryf**. As die gasprogram **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysleweraar ’n bewys genereer wat slaag terwyl die **openbare maatstawwe of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgassprogramme

- Behandel private getuie-/kringgrepe as **ongeloofwaardige aanvallersinvoer**, selfs al word hulle deur die bewys verberg.
- Vermy deserialisering met ongekontroleerde hulpfunksies soos `rkyv::access_unchecked`, tensy die grepe reeds buite die band gevalideer is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit ongeloofwaardige geserialiseerde data gelaai word, moet gevalideer word voordat hulle beheervloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **diskriminant buite die toegelate reeks** kan inspuit, word elke daaropvolgende `match` oor daardie waarde verdag.

### Jump-table / UB counter bypass

As Rust ’n groot `match` na ’n **jump table** omskakel, kan ’n ongeldige enum-diskriminant **ongedefinieerde beheervloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Diskriminant buite die toegelate reeks indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeninghoudingspad word oorgeslaan. In ’n zkVM kan dit bewyse vervals wat onmoontlike statistieke rapporteer, soos minder gates, minder duur bewerkings of ander vervalste beperkte hulpbronne.

Kontrolelys vir hersiening:

- Soek na aanvallerbeheerde enums wat uit witness-/private invoer gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + ongekontroleerde deserialisering + groot opcode-versending as ’n hoërisikokombinasie.
- Ontleed die gegenereerde binêre lêer indien nodig; die uitleg van die jump table kan belangriker wees as die bronkode.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreteerders

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Vir omkeerbare/kwantumagtige instruksiestelle, maak seker dat operande wat verskillend moet wees, wel beperk word om verskillend te wees. ’n Toffoli-/CCX-agtige bewerking wat soos volg geïmplementeer word:<sup>[[7]](#references)[[8]](#references)</sup>

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

Dit skep ’n **deterministiese terugstelprimitief** wat omkeerbaarheidsaannames verbreek en goedkoper, onbedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbronverbruik attesteer, kan aanvallers hiermee funksionele kontroles slaag terwyl hulle die kostemodel omseil wat die verifieerder meen afgedwing word.

### Onderbeperkte prover-advies en modulêre rekenkunde

Waardes wat vanaf ’n **advies-/getuie-stapel** gelaai word, word deur die prover beheer, selfs wanneer hulle as voorafberekende kwosiënte, reste, inverse of wenke beskryf word. ’n Bewys stel slegs vas dat die getuie aan die geïmplementeerde beperkings voldoen; dit stel nie die bedoelde berekening vas as daardie beperkings ’n tipe-, omvang- of kanonieke-vorm-kontrole weglaat nie.<sup>[[13]](#references)</sup>

Wanneer jy ’n reduksie- of Euklidiese-delingshulpfunksie oudit, moet jy die volledige heelgetalrelasie nagaan, nie net die finale aftrekking of vermenigvuldiging nie. Elke limb van `q` en `r` moet tot sy verklaarde breedte beperk word, die rekonstruksie `x = q * m + r` moet in die bedoelde heelgetalvoorstelling geld, en die kanonieke grens `0 <= r < m` moet afgedwing word. Valideer ’n waarde **voordat** jy dit aan ’n nouer `u32`/`u64`-instruksie deurgee; ’n nou bewerking bewys nie terugwerkend dat die oorspronklike veldselement of meer-limb-waarde die verwagte tipe gehad het nie.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Die `mod_12289`-fout in Miden illustreer die uitbuitingspatroon: die kwosiënt is as ’n 64-bis-waarde met twee limbs nagegaan, maar die adviesverskafde reswaarde het `u32overflowing_sub` bereik sonder gelykwaardige validering. ’n Kwaadwillige bewyser kon ongeldige kwosiënt- en reswaardes koördineer sodat die geïmplementeerde aftrekkingsbeperkings steeds gegeld het, terwyl die prosedure ’n nie-wiskundige reswaarde teruggegee het. Omdat hierdie resultaat in Falcon-verifikasie gebruik is, kon die klankheidsfout uitgebuit word om vervalste magtigingshandtekeninge te skep, eerder as om bloot ’n verkeerde rekenkundige resultaat te lewer.<sup>[[13]](#references)</sup>

### Oudit van kriptografiese VM’s met implisiete stapels

Taalomgewings met ’n stapel verberg operande, dus lig jy eers instruksies op na ’n IR waarin elke verbruikte en geproduseerde stapelwaarde ’n uitdrukking met herkoms is. ’n Konserwatiewe ontledingspyplyn kan dan:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Bou die oproepgrafiek en lei die stapel-effekte vir prosedure-invoer en -uitvoer af.
2. Voer ondersteunde instruksies simbolies uit en lig beheervloei op na SSA-/gestruktureerde uitdrukkings.
3. Propager abstrakte feite soos `Unknown`, `ProvenU32`, `Bool`, waardeherkoms en plaaslike inisialisering totdat ’n vaste punt bereik word.
4. Merk adviesafgeleide waardes wat getipeerde rekenkunde of nie-nul-afvoerpunte bereik sonder ’n saniteerder op **elke** inkomende pad.
5. Vergelyk verklaarde en afgeleide handtekeninge en verifieer dat elke uitgang die oproeper se waardes op die stapel behou.

Behandel ’n onbekende handtekening of nie-ondersteunde konstruksie as ’n **ontledingsgaping**, nie as ’n skoon resultaat nie. Dinamiese oproepe, lusse wat nie stapelneutraal is nie, en vertakkings met verskillende stapel-effekte kan betroubare dop van stapelgleuwe onmoontlik maak; ’n veiliger dekompileerder verwerp of merk hierdie gevalle eerder as om geloofwaardige maar verkeerde pseudokode uit te voer.<sup>[[10]](#references)[[13]](#references)</sup>

By beheervloei-aansluitings, behou ’n eienskap slegs wanneer dit op elke voorganger geld (byvoorbeeld, `ProvenU32 join Unknown = Unknown`). Onderskei ook konvergensie na ’n vaste punt van die bereiking van ’n iterasielimiet: slegs ’n gekonvergeerde, betroubare oorbenadering kan regverdig dat die afwesigheid van ’n diagnose as bewys dien dat alle voorgestelde uitvoerings aan die eienskap voldoen.<sup>[[11]](#references)</sup>

### Gebruik bewysverpligtinge om verborge voorwaardes bloot te lê

Vir klein instruksiestelle, vertaal prosedures na ’n uitvoerbare formele VM-model en bewys sowel die resultaat as die volledige stapeltransformasie. Die stelling moet terminering, getipeerde invoere, die verwagte uitvoervoorvoegsel en die behoud van die onaangeraakte oproeperstapel dek. Gaan die stelling net so noukeurig na as die bewys: die kern kan ’n bewys van ’n onbedoeld verswakte bewering valideer.<sup>[[12]](#references)[[13]](#references)</sup>

Onverwagte hipoteses is nuttige bevindings. In die Miden-oorsig het ’n bewys vir 64-bis-rotasie na regs vereis dat `shift mod 32 != 0`, wat ’n randgeval blootgelê het wat vir groot invoere misluk wanneer die skuif ’n veelvoud van 32 was; ’n ander bewys het bevind dat 256-bis-`wrapping_mul` waardes wat aan die oproeper behoort, van die stapel verwyder het. Voeg die ontdekte randgeval by die toetse en herstel dan die implementering of verskerp doelbewus die openbare voorwaarde, eerder as om die ekstra aanname stilweg te aanvaar.<sup>[[12]](#references)[[13]](#references)</sup>

### Wat om in ZK-stelsels te toets

- Fuzz alle gastontleders met misvormde kodering van getuienis/privaatinvoer.
- Bevestig dat enum-reeksvalidering plaasvind voordat opcode-versending begin.
- Voeg semantiese kontroles by vir operandaliasering en ander ongeldige instruksievorme.
- Volg elke advies-/getuienisbron na elke getipeerde rekenkundige afvoerpunt en vereis validering op elke pad.<sup>[[11]](#references)[[13]](#references)</sup>
- Toets rekenkundige helpers met nie-kanonieke limbs, reswaardes buite bereik en grenswaardes vir skuiftellings.<sup>[[12]](#references)[[13]](#references)</sup>
- Bevestig by elke terugkeer die stapelhoogte en die behoud van waardes onder die prosedure se verklaarde argumente.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die gastprogram foutief is.

## Magtiging Afhanklik van Toestand

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-uitbuiting

As jy praktiese uitbuiting van DEX’e en AMM’s ondersoek (Uniswap v4 hooks, misbruik van afronding/akkuraatheid, flash-loan-versterkte swaps wat drempels oorskry), kyk na:

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
- [3] [Wat is multi-handtekeningtransaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se zero-knowledge-bewys van kwantumkriptanalise verslaan](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kurwe-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronskattings en versagtingsmaatreëls (reggestelde weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits se bewys-van-konsep-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM-dekompileerderargitektuur](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM-statiese-ontledingsenjin](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-na-Lean-model en korrektheidsbewyse](https://github.com/trailofbits/masm-lean)
- [13] [Oudit in die era van (goed genoeg) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
