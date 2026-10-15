# Blockchain en kriptogeldeenhede

{{#include ../../banners/hacktricks-training.md}}

Hierdie hoofstuk behandel blockchain-konsepte en on-chain-sekuriteit. Begin met [Bitcoin P2P-diensenumerasie](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md) vir ’n blootgestelde Bitcoin-peer; gebruik [DApp-pentesting](../../pentesting-web/dapps-DecentralizedApplications.md) vir ’n blaaier-frontend, wallet-verbinding of off-chain-backend. Gebruik die [hoofstuk oor kriptogeldeenheidprivaatheid](../../privacy/cryptocurrency-privacy.md) vir privaatheidsbedrywighede met kriptogeldeenhede en hul beperkings.

## Basiese konsepte

- **Smart Contracts** word gedefinieer as programme wat op ’n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat die uitvoering van ooreenkomste sonder tussengangers outomatiseer.
- **Decentralized Applications (dApps)** bou voort op smart contracts en beskik oor ’n gebruikersvriendelike front-end en ’n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei tussen coins, wat as digitale geld dien, en tokens, wat waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Utility Tokens** verleen toegang tot dienste, en **Security Tokens** dui op bate-eienaarskap.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

Sien [Beleggingsterme](investment-terms.md) vir terminologie oor spot-orders, futures, hefboomfinansiering en opsies wat in kriptomarkte gebruik word.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidering op die blockchain:

- **Proof of Work (PoW)** maak staat op rekenaarkrag om transaksies te verifieer.
- **Proof of Stake (PoS)** vereis dat validators ’n sekere hoeveelheid tokens besit, wat energieverbruik verminder in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-noodsaaklikhede

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word met digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die private key oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fooie** (aan miners betaal) en **scripts** (transaksiereëls).

### Lightning Network

Dit poog om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Bitcoin anoniem verkry

Metodes sluit in kontanttransaksies, mining en die gebruik van mixers. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier is ’n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privaatheid kan ondermyn.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen ongewoon dat inputs van verskillende gebruikers in een transaksie gekombineer word weens die kompleksiteit daarvan. Daarom word **daar dikwels aanvaar dat twee input-adresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

’n UTXO, of **Unspent Transaction Output**, moet volledig in ’n transaksie bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe kleingeldadres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit teë te werk, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse blootlê.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek berus op die ontleding van transaksies met verskeie inputs en outputs om te raai watter output die kleingeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die change-uitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Gedwonge adreshergebruik**

Aanvallers kan klein bedrae na adresse stuur wat voorheen gebruik is, in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer en sodoende adresse aan mekaar koppel.

### Korrekte gedrag van beursies

Beursies behoort te verhoed dat munte wat ontvang is op reeds gebruikte, leë adresse gebruik word, om hierdie privaatheidslek te voorkom.

## **Ander tegnieke vir blokkettingontleding**

- **Presiese betalingsbedrae:** Transaksies sonder kleingeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is, terwyl die nie-ronde uitset waarskynlik die kleingeld is.
- **Beursiefingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware en moontlik die kleingeldadres te identifiseer.
- **Korrelasies tussen bedrae en tydsberekening:** Die bekendmaking van transaksietye of -bedrae kan dit moontlik maak om transaksies op te spoor.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikers se privaatheid benadeel. Dit is veral die geval as ’n entiteit baie Bitcoin-nodusse bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n volledige lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te verkry

- **Kontanttransaksies**: Bitcoin met kontant verkry.
- **Kontantalternatiewe**: Geskenkbewyse koop en dit aanlyn vir bitcoin verruil.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynbou, veral wanneer dit alleen gedoen word, omdat mynpoele dalk die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin nog ’n manier wees om dit anoniem te verkry, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil daarvoor ontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue dat die diens nie logs hou nie en wel die bitcoins terugbesorg. Alternatiewe mengopsies sluit Bitcoin-casino’s in.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers in een saam, wat dit moeiliker maak vir enigiemand om insette met uitsette te pas. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik opgespoor word.

Voorbeelde van transaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom ’n transaksie tussen twee partye (bv. ’n kliënt en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die heuristiek vir gemeenskaplike invoereienaarskap wat deur transaksietoesigentiteite gebruik word, ongeldig maak.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie van standaard-bitcointransaksies onderskei kan word nie.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksieprivaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Tegnieke vir beursiesinkronisering**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blockchain te sinkroniseer. Twee metodes staan uit:

- **Full node**: Deur die hele blockchain af te laai, verseker ’n full node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir teenstanders onmoontlik maak om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Client-side-blokfiltrering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Liggewigbeursies laai hierdie filters af en haal slegs volledige blokke af wanneer ’n pasmaat met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknie-tot-eweknie-netwerk werk, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om ’n nuwe adres vir elke transaksie te gebruik. Hergebruik van adresse kan privaatheid in gevaar stel deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verbloem word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingelduitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingelduitsette**: As kleingeld nie vermy kan word nie, kan die skep van veelvuldige kleingelduitsette steeds privaatheid verbeter.

# **Monero: ’n baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Verstaan van gas**

Gas meet die rekenaarmatige inspanning wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. ’n Transaksie wat byvoorbeeld 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basisfooi, met ’n prioriteitsfooi om insluiting deur ’n valideerder aan te moedig. Gebruikers kan ’n maksimumfooi stel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoer van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat gebruikers- of slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet in ’n blok ingesluit word. Noodsaaklike inligting in ’n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word opmerklik genoeg uit die handtekening afgelei, wat beteken dat dit nie in die transaksiedata nodig is nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is grondliggend vir enigiemand wat met kriptogeldeenhede wil werk en privaatheid en sekuriteit voorop wil stel.

## Web3-rooispanwerk met fokus op waarde

- Maak ’n inventaris van komponente wat waarde bevat (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flash loans/orakels/aanmeldbesonderhede/oor-ketting om impak te bevestig en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van Web3-ondertekeningswerkvloei

- Kaping van die voorsieningsketting van wallet-UI’s kan EIP-712-vragte verander net voor ondertekening, en geldige handtekeninge insamel vir proxy-oorname gebaseer op delegatecall (bv. oorskryf van slot-0 van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraksie van rekeninge (ERC-4337)

- Algemene mislukkingsmodusse van slimrekeninge sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, toestandsvolle validering, ERC-1271-herhaling en fooi-uitputting deur terugrol ná validering.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Slimkontrak-sekuriteit

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integriteit van ZK-bewyse / zkVM-gaste

Wanneer ’n bewyslewer ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder slegs dat die **gastprogram uitgevoer is soos geskryf**. As die gas **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewyslewer ’n bewys genereer wat slaag terwyl die **openbare statistieke of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgaste

- Behandel private witness-/kringgrepe as **onbetroubare aanvallersinvoer**, selfs al word hulle deur die bewys versteek.
- Vermy deserialisering daarvan met hulpfunksies sonder kontroles, soos `rkyv::access_unchecked`, tensy die grepe reeds buite die stelsel gevalideer is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet gevalideer word voordat hulle beheervloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **buitebereik-diskriminant** kan inspuit, word elke stroomaf-`match` op daardie waarde verdag.

### Omseiling van jump table / UB-kontroles

As Rust ’n groot `match` na ’n **jump table** omskakel, kan ’n ongeldige enum-diskriminant **ongedefinieerde beheervloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Buitebereik-diskriminant indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die boekhoudingspad word oorgeslaan. In ’n zkVM kan dit vervalste bewyse oplewer wat onmoontlike maatstawwe rapporteer, soos minder gates, minder duur bewerkings of ander vervalste hulpbronlimiete.

Kontrolelys vir hersiening:

- Soek na aanvallerbeheerde enums wat uit witness-/private invoer gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Behandel `unsafe` + ongekontroleerde deserialisering + groot opcode-versending as ’n hoërisikokombinasie.
- Voer reverse engineering van die uitgegeven binary uit wanneer nodig; die uitleg van die jump table kan belangriker as die bronkode wees.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreters

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys moet afdwing.

Maak vir omkeerbare/kwantumagtige instruksiestelle seker dat operande wat verskillend moet wees, werklik beperk word om verskillend te wees. ’n Toffoli-/CCX-agtige bewerking wat soos volg geïmplementeer word:<sup>[[7]](#references)[[8]](#references)</sup>

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

This skep ’n **deterministiese terugstelprimitief**, wat aannames oor omkeerbaarheid verbreek en goedkoper, onbedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbronverbruik attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die kostemodel omseil wat die verifieerder glo afgedwing word.

### Onderbeperkte prover-advies en modulêre rekenkunde

Waardes wat vanaf ’n **advies-/getuigestapel** gelaai word, word deur die prover beheer, selfs wanneer hulle beskryf word as voorafberekende kwosiënte, reste, inverses of wenke. ’n Bewys stel slegs vas dat die getuie aan die geïmplementeerde beperkings voldoen; dit stel nie die bedoelde berekening vas as daardie beperkings ’n tipe-, reeks- of kanoniekevormkontrole weglaat nie.<sup>[[13]](#references)</sup>

Vir ’n reduksie- of Euklidiese-delingshelper, oudit die volledige heelgetalrelasie eerder as net die finale aftrekking of vermenigvuldiging. Elke limb van `q` en `r` moet tot sy verklaarde breedte beperk word, die rekonstruksie `x = q * m + r` moet in die bedoelde heelgetalvoorstelling geld, en die kanonieke grens `0 <= r < m` moet afgedwing word. Valideer ’n waarde **voordat** dit aan ’n nouer `u32`/`u64`-instruksie deurgegee word; ’n nou bewerking bewys nie terugwerkend dat die oorspronklike veld­element of meerlimb-waarde die verwagte tipe gehad het nie.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Die `mod_12289`-fout in Miden illustreer die exploit-patroon: die kwosiënt is as ’n 64-bis-waarde met twee limbs nagegaan, maar die adviesverskafte res het `u32overflowing_sub` bereik sonder gelykwaardige validering. ’n Kwaadwillige prover kon ongeldige kwosiënt- en reswaardes koördineer sodat die geïmplementeerde aftrekkingsbeperkings steeds nagekom is, terwyl die prosedure ’n nie-wiskundige res teruggegee het. Omdat hierdie resultaat vir Falcon-verifikasie gebruik is, kon die soundness-fout tot vervalste magtigingshandtekeninge eskaleer, eerder as om bloot ’n verkeerde rekenkundige resultaat op te lewer.<sup>[[13]](#references)</sup>

### Oudit van kriptografiese VM’s met implisiete stapels

Stapeltale verberg operande, dus moet jy instruksies eers na ’n IR omskakel waarin elke verbruikte en geproduseerde stapelwaarde ’n uitdrukking met herkoms is. ’n Konserwatiewe ontledingspyplyn kan dan:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Die oproepgrafiek bou en die stapel-invoer-/uitvoer-effekte van prosedures aflei.
2. Ondersteunde instruksies simbolies uitvoer en beheervloei na SSA-/gestruktureerde uitdrukkings omskakel.
3. Abstrakte feite soos `Unknown`, `ProvenU32`, `Bool`, waardeherkoms en plaaslike inisialisering voortplant totdat ’n vaste punt bereik word.
4. Waardes wat uit advies afgelei is en by getipeerde rekenkundige bewerkings of nie-nul-teikens uitkom, merk as daar nie op **elke** inkomende pad ’n sanitizer is nie.
5. Verklaarde en afgeleide handtekeninge vergelyk en verifieer dat elke uitgang die oproeper se eie stapelwaardes behou.

Beskou ’n onbekende handtekening of nie-ondersteunde konstruksie as ’n **ontledingsgaping**, nie as ’n skoon resultaat nie. Dinamiese oproepe, lusse wat nie die stapel balanseer nie, en vertakkings met verskillende stapel-effekte kan betroubare nasporing van stapelgleuwe onmoontlik maak; ’n veiliger decompiler verwerp of merk eerder hierdie gevalle as om aanneemlike maar verkeerde pseudokode uit te voer.<sup>[[10]](#references)[[13]](#references)</sup>

By beheervloei-aansluitings, behou ’n eienskap slegs wanneer dit op elke voorganger geld (byvoorbeeld, `ProvenU32 join Unknown = Unknown`). Onderskei ook tussen konvergensie by ’n vaste punt en die bereik van ’n iterasielimiet: slegs ’n gekonvergeerde, sound oorbenadering kan regverdig dat die afwesigheid van ’n diagnostiese waarskuwing as bewys dien dat alle voorgestelde uitvoerings aan die eienskap voldoen.<sup>[[11]](#references)</sup>

### Gebruik bewysverpligtinge om verborge voorwaardes bloot te lê

Vir klein instruksiestelle, vertaal prosedures na ’n uitvoerbare formele VM-model en bewys beide die resultaat en die volledige stapeltransformasie. Die stelling moet terminering, getipeerde insette, die verwagte uitvoervoorvoegsel en behoud van die onaangeraakte oproeperstapel dek. Oudit die stelling net so noukeurig soos die bewys: die kernel kan ’n bewys van ’n per ongeluk verswakte bewering valideer.<sup>[[12]](#references)[[13]](#references)</sup>

Onverwagte hipoteses is nuttige bevindings. In die Miden-oorsig het ’n bewys vir 64-bis-regsrotasie `shift mod 32 != 0` vereis, wat ’n mislukte randgeval vir groot insette blootgelê het wanneer die skof ’n veelvoud van 32 was; ’n ander bewys het bevind dat 256-bis-`wrapping_mul` waardes wat aan die oproeper behoort, weggegooi het. Voeg die ontdekte randgeval by die toetse, en herstel dan die implementering of versterk doelbewus die openbare voorwaarde eerder as om die bykomende aanname stilweg te aanvaar.<sup>[[12]](#references)[[13]](#references)</sup>

### Wat om in ZK-stelsels te toets

- Fuzz alle gasheerparsers met misvormde enkoderings van witness/private-input.
- Bevestig enum-reeksvalidering voor opcode-versending.
- Voeg semantiese kontroles vir operand-aliasing en ander ongeldige instruksievorme by.
- Volg elke advies-/witness-bron na elke getipeerde rekenkundige teiken en vereis validering op elke pad.<sup>[[11]](#references)[[13]](#references)</sup>
- Toets rekenkundige helperfunksies met nie-kanonieke limbs, buite-reeks-rosse en skoflimiete.<sup>[[12]](#references)[[13]](#references)</sup>
- Bevestig die stapelhoogte en behoud van waardes onder die prosedure se verklaarde argumente by elke terugkeer.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die gasheerprogram foutief is.

## Magtiging Afhanklik van Toestand

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

As jy praktiese uitbuiting van DEX’s en AMM’s ondersoek (Uniswap v4 hooks, afrondings-/presisie-misbruik, swaps wat drempeloorskryding met flash loans versterk), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-bate-geweegde poele wat virtuele saldo’s kas en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Bewys van belang - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Publieke sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multi-handtekeningtransaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se nulkennisbewys van kwantumkriptoanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kromme-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronramings en versagtingsmaatreëls (gelapte weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits se proof-of-concept-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM-decompiler-argitektuur](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM-statiese-ontledingsenjin](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-na-Lean-model en korrektheidsbewyse](https://github.com/trailofbits/masm-lean)
- [13] [Oudit in die era van (goed genoeg) AI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
