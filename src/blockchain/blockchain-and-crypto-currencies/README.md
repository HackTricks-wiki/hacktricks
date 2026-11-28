# Blockchain en kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

Hierdie hoofstuk behandel blockchain-konsepte en on-chain-sekuriteit. Vir ’n blootgestelde Bitcoin-peer, begin met [Bitcoin P2P-diensenumerasie](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); vir ’n blaaierfrontend, beursiekoppeling of off-chain-backend, gebruik [DApp-pentesting](../../pentesting-web/dapps-DecentralizedApplications.md). Vir kriptogeldeenheid-privaatheidsbedrywighede en hul beperkings, gebruik die [hoofstuk oor kriptogeldeenheid-privaatheid](../../privacy/cryptocurrency-privacy.md).

## Basiese konsepte

- **Slim kontrakte** word gedefinieer as programme wat op ’n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat ooreenkomste outomatiseer sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou voort op slim kontrakte, met ’n gebruikersvriendelike voorkant en ’n deursigtige, ouditbare agterkant.
- **Tokens en munte** verskil daarin dat munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Nutstokens** verleen toegang tot dienste, en **sekuriteitstokens** dui bate-eienaarskap aan.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAO's** verwys onderskeidelik na Gedesentraliseerde Beursplatforms en Gedesentraliseerde Outonome Organisasies.

Vir terminologie oor lokomarkbestellings, termynkontrakte, hefboomwerking en opsies wat in kriptomarkte gebruik word, sien [Beleggingsterme](investment-terms.md). Vir misbruik van befondsingskoerse in perpetual-protokolle, sien [Uitbuiting van perpetual-befondsingskoerse](perpetual-funding-rate-exploitation.md).

## Konsensusmeganismes

Konsensusmeganismes verseker veilige transaksievalidering waaroor daar op die blockchain ooreengekom word:

- **Proof of Work (PoW)** maak staat op rekenaarkrag om transaksies te verifieer.
- **Proof of Stake (PoS)** vereis dat valideerders ’n sekere hoeveelheid tokens hou, wat energieverbruik verminder in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-noodsaaklikhede

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature-transaksies** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **insette** (bron van fondse), **uitsette** (bestemming), **fooie** (aan mynwerkers betaal) en **skripte** (transaksiereëls).

### Lightning Network

Dit is daarop gemik om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Bitcoin anoniem verkry

Metodes sluit kontanttransaksies, mynbou en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid moeiliker te maak, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die Bitcoin-wêreld is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels ’n bron van kommer. Hier is ’n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privaatheid kan ondermyn.<sup>[[6]](#references)</sup>

## **Aanname van gemeenskaplike inseteienaarskap**

Dit is oor die algemeen ongewoon dat insette van verskillende gebruikers in ’n enkele transaksie gekombineer word weens die betrokke kompleksiteit. Daarom word **daar dikwels aangeneem dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **Opsporing van UTXO-wisseladres**

’n UTXO, of **Onbestede transaksie-uitset**, moet volledig in ’n transaksie bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe wisseladres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaksiegraafontleding**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse blootlê.

## **Heuristiek vir onnodige insette (optimale-wisselheuristiek)**

Hierdie heuristiek berus op die ontleding van transaksies met verskeie insette en uitsette om te raai watter uitset die wisselgeld is wat na die sender teruggaan.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die wisselgeld-uitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Gedwonge adreshergebruik**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer en sodoende adresse aan mekaar koppel.

### Korrekte beursiegedrag

Beursies behoort te vermy om munte te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheidsleak te voorkom.

## **Ander blokkettingontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder wisselgeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is, terwyl die nie-ronde uitset waarskynlik die wisselgeld is.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware en moontlik die wisselgeldadres te identifiseer.
- **Korrelasies tussen bedrae en tydstippe:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikersprivaatheid in gevaar stel. Dit geld veral as ’n entiteit baie Bitcoin-nodes bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te kry

- **Kontanttransaksies**: Bitcoins met kontant verkry.
- **Kontantalternatiewe**: Geskenkbewyse koop en dit aanlyn vir bitcoins verruil.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynwerk, veral as dit alleen gedoen word, omdat mynpoele dalk die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoins ’n ander manier wees om dit anoniem te verkry, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter dat die diens vertrou word om nie logs te hou nie en om die bitcoins inderdaad terug te stuur. Bitcoin-casino’s is ’n alternatiewe mengopsie.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers saam in een, wat dit moeiliker maak vir enigiemand wat insette met uitsette probeer koppel. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die gemeenskaplike-insette-eienaarskapheuristiek wat deur transaksietoesig-entiteite gebruik word, ongeldig maak.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar van standaard bitcoin-transaksies bly.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Wallet-sinchroniseringstegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Volledige node**: Deur die hele blockchain af te laai, verseker ’n volledige node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir aanvallers om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkantblokfiltrering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, sodat wallets relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te lê. Liggewig-wallets laai hierdie filters af en haal slegs volledige blokke op wanneer ’n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknie-netwerk werk, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie ’n nuwe adres te gebruik. Adreshergebruik kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies te verdeel, kan die transaksiebedrag verdoesel word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingeld-uitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingeld-uitsette**: As dit nie haalbaar is om kleingeld te vermy nie, kan die skep van veelvuldige kleingeld-uitsette steeds privaatheid verbeter.

# **Monero: ’n Baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Verstaan gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basistarief, met ’n prioriteitstarief om insluiting deur ’n validator aan te moedig. Gebruikers kan ’n maksimumtarief stel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoer van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat óf gebruiker- óf smart-contract-adresse kan wees. Dit vereis ’n fooi en moet in ’n blok ingesluit word. Noodsaaklike transaksie-inligting sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word opmerklik uit die handtekening afgelei, wat beteken dat dit nie in die transaksiedata nodig is nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is grondliggend vir enigiemand wat met kriptogeldeenhede wil werk en terselfdertyd privaatheid en sekuriteit voorop wil stel.

## Web3-rooispantoetsing met fokus op waarde

- Inventariseer komponente wat waarde dra (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flash loans/orakels/geloofsbriewe/oor verskeie kettings om die impak te bekragtig en uitbuitbare voorvereistes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3-ondertekeningswerkvloei-kompromittering

- Peutering met die voorsieningsketting van wallet-UI’s kan EIP-712-vragte net voor ondertekening verander en geldige handtekeninge insamel vir delegatecall-gebaseerde proxy-oorname (bv. oorskryf van slot 0 van Safe se masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Rekeningabstraksie (ERC-4337)

- Algemene mislukkingswyses vir smart accounts sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, toestandsvolle validering, ERC-1271-herhaling en fooidreinering deur terugrol ná validering.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-contract-sekuriteit

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK-bewys-/zkVM-gasheerintegriteit

Wanneer ’n bewysleweraar ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder slegs dat die **gasheerprogram uitgevoer is soos geskryf**. As die gasheer **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysleweraar ’n bewys genereer wat geldig verklaar word terwyl die **openbare maatstawwe of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgashere

- Behandel private witness-/kringgrepe as **onbetroubare aanvallersinvoer**, selfs al word hulle deur die bewys versteek.
- Vermy die deserialisering daarvan met ongekontroleerde helpers soos `rkyv::access_unchecked`, tensy die grepe reeds buite die bewys om gevalideer is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet gevalideer word voordat dit beheer-vloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **discriminant buite die toegelate reeks** kan inspuit, word elke daaropvolgende `match` oor daardie waarde verdag.

### Omseiling van kontrole met jump table / UB

As Rust ’n groot `match` in ’n **jump table** omskakel, kan ’n ongeldige enum-discriminant **ongedefinieerde beheervloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Discriminant buite die toegelate reeks indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit vervalste bewyse oplewer wat onmoontlike maatstawwe rapporteer, soos minder gates, minder duur bewerkings of ander vervalste hulpbronne met ’n limiet.

Kontrolelys vir hersiening:

- Soek na enums wat deur die aanvaller beheer word en uit witness-/private invoer gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + deserialisering sonder kontroles + groot opcode-dispatch as ’n kombinasie met hoë risiko.
- Reverse-engineer die gegenereerde binary wanneer nodig; die jump-table-uitleg kan belangriker wees as die bronkode.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreteerders

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Vir omkeerbare/kwantumagtige instruksiestelle moet jy seker maak dat operande wat verskillend moet wees, werklik beperk word om verskillend te wees. ’n Toffoli/CCX-agtige bewerking wat geïmplementeer word as:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

word onveilig as die gas dit nie verwerp nie:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In daardie geval stort die oorgang ineen tot:

```text
q = q ^ (q & q) = 0
```

Dit skep ’n **deterministiese terugstelprimitief**, wat aannames oor omkeerbaarheid verbreek en goedkoper, nie-bedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbronverbruik staaf, kan aanvallers hiermee funksionele kontroles slaag terwyl hulle die kostemodel omseil wat die verifieerder glo afgedwing word.

### Onvoldoende begrensde prover-advies en modulêre rekenkunde

Waardes wat vanaf ’n **advies-/getuienstapel** gelaai word, word deur die prover beheer, selfs wanneer dit as voorafberekende kwosiënte, reste, inverses of wenke beskryf word. ’n Bewys stel slegs vas dat die getuie aan die geïmplementeerde beperkings voldoen; dit stel nie die bedoelde berekening vas as daardie beperkings ’n tipe-, omvang- of kanonieke-vormkontrole weglaat nie.<sup>[[13]](#references)</sup>

Oudit vir ’n reduksie- of Euklidiese-delingshulpfunksie die volledige heelgetalrelasie, nie net die finale aftrekking of vermenigvuldiging nie. Elke limb van `q` en `r` moet tot sy verklaarde breedte beperk word, die rekonstruksie `x = q * m + r` moet in die bedoelde heelgetalvoorstelling geld, en die kanonieke grens `0 <= r < m` moet afgedwing word. Valideer ’n waarde **voordat** jy dit aan ’n nouer `u32`-/`u64`-instruksie deurgee; ’n noue bewerking bewys nie met terugwerkende krag dat die oorspronklike veldelment of multilimietwaarde die verwagte tipe gehad het nie.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Die `mod_12289`-fout in Miden illustreer die uitbuitingspatroon: die kwosiënt is as ’n tweewoord-64-bis-waarde nagegaan, maar die res wat deur advice verskaf is, het `u32overflowing_sub` bereik sonder gelykwaardige validering. ’n Kwaadwillige prover kon ongeldige kwosiënt- en reswaardes koördineer sodat die geïmplementeerde aftrekkingsbeperkings steeds gegeld het, terwyl die prosedure ’n nie-wiskundige res teruggegee het. Omdat hierdie resultaat vir Falcon-verifikasie gebruik is, kon die klankheidsfout tot vervalste magtigingshandtekeninge eskaleer, eerder as om bloot ’n verkeerde rekenkundige resultaat te lewer.<sup>[[13]](#references)</sup>

### Oudit van kriptografiese VM's met implisiete stapels

Stapeltale verberg operande, dus lig eers instruksies na ’n IR waarin elke verbruikte en geproduseerde stapelwaarde ’n uitdrukking met herkoms is. ’n Konserwatiewe ontledingspyplyn kan dan:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Bou die oproepgrafiek en lei die stapel-effekte van prosedure-in- en -uitsette af.
2. Voer ondersteunde instruksies simbolies uit en lig die beheervloei na SSA-/gestruktureerde uitdrukkings.
3. Propageer abstrakte feite soos `Unknown`, `ProvenU32`, `Bool`, waardeherkoms en plaaslike inisialisering totdat ’n vaste punt bereik word.
4. Merk advies-afgeleide waardes wat getipeerde rekenkunde of nie-nul-bestemmings bereik sonder ’n saniteerder op **elke** inkomende pad.
5. Vergelyk verklaarde en afgeleide handtekeninge en verifieer dat elke uitgang die oproeper se eie stapelwaardes behou.

Behandel ’n onbekende handtekening of nie-ondersteunde konstruksie as ’n **ontledingsgaping**, nie as ’n skoon resultaat nie. Dinamiese oproepe, lusse wat nie stapelneutraal is nie, en vertakkings met verskillende stapel-effekte kan betroubare dop van stapelgleuwe onmoontlik maak; ’n veiliger dekompileerder verwerp of merk hierdie gevalle eerder as om aanneemlike maar verkeerde pseudokode uit te gee.<sup>[[10]](#references)[[13]](#references)</sup>

By beheervloei-aansluitings, behou ’n eienskap slegs wanneer dit op elke voorganger geld (byvoorbeeld, `ProvenU32 join Unknown = Unknown`). Onderskei ook tussen konvergensie na ’n vaste punt en die bereiking van ’n iterasielimiet: slegs ’n gekonvergeerde, betroubare oorskatting kan die afwesigheid van ’n diagnostiese waarskuwing regverdig as bewys dat alle voorgestelde uitvoerings aan die eienskap voldoen.<sup>[[11]](#references)</sup>

### Gebruik bewysverpligtinge om verborge voorvereistes bloot te lê

Vir klein instruksiestelle, vertaal prosedures na ’n uitvoerbare formele VM-model en bewys beide die resultaat en die volledige stapeltransformasie. Die stelling moet beëindiging, getipeerde invoere, die verwagte uitvoervoorvoegsel en die behoud van die onaangeraakte oproeperstapel dek. Oudit die stelling net so sorgvuldig soos die bewys: die kern kan ’n bewys van ’n per ongeluk verswakte aanspraak valideer.<sup>[[12]](#references)[[13]](#references)</sup>

Onverwagte hipoteses is nuttige bevindings. In die Miden-oorsig het ’n bewys vir 64-bis-regsrotasie `shift mod 32 != 0` vereis, wat ’n mislukte randgeval vir groot invoere blootgelê het wanneer die skuif ’n veelvoud van 32 was; ’n ander bewys het bevind dat 256-bis-`wrapping_mul` waardes op die oproeper se eie stapel weggegooi het. Voeg die ontdekte grensgeval by die toetse, en maak dan die implementering reg of versterk die openbare voorvereiste doelbewus eerder as om die ekstra aanname stilweg te aanvaar.<sup>[[12]](#references)[[13]](#references)</sup>

### Wat om in ZK-stelsels te toets

- Fuzz alle guest-parsers met misvormde enkoderings van witness/private input.
- Bevestig enum-reeksvalidering voor opcode-versending.
- Voeg semantiese kontroles by vir operandaliasing en ander ongeldige instruksievorme.
- Volg elke advice-/witness-bron na elke getipeerde rekenkundebestemming en vereis validering op elke pad.<sup>[[11]](#references)[[13]](#references)</sup>
- Toets rekenkundige helpers met nie-kanonieke limbs, buitebereik-reste en grenswaardes vir skuiftellings.<sup>[[12]](#references)[[13]](#references)</sup>
- Bevestig stapelhoogte en die behoud van waardes onder die prosedure se verklaarde argumente by elke terugkeer.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die guest-program foutief is.

## Toestandsafhanklike magtiging

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

As jy praktiese uitbuiting van DEX'e en AMM's ondersoek (Uniswap v4-hooks, afrondings-/presisie-misbruik, flash-loan-versterkte swaps wat drempels oorskry), kyk na:

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
- [7] [Trail of Bits - Ons het Google se nulkennisbewys van kwantumkriptoanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kromme-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronramings en versagtings (reggestelde weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits-bewys-van-konsep-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM-dekompileerderargitektuur](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [MASM-statiese-analise-enjin](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-na-Lean-model en korrektheidsbewyse](https://github.com/trailofbits/masm-lean)
- [13] [Oudit in die era van (goed-genoeg) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
