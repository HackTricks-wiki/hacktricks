# Blockchain en kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Slimkontrakte** word gedefinieer as programme wat op ’n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word. Dit outomatiseer die uitvoering van ooreenkomste sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou voort op slimkontrakte en beskik oor ’n gebruikersvriendelike voorkant en ’n deursigtige, ouditeerbare agterkant.
- **Tokens en munte** verskil daarin dat munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Nutsdienstokens** verleen toegang tot dienste, en **sekuriteitstokens** dui op eienaarskap van bates.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAO’s** verwys onderskeidelik na Gedesentraliseerde Beursplatforms en Gedesentraliseerde Outonome Organisasies.

## Konsensusmeganismes

Konsensusmeganismes verseker dat transaksies op die blockchain veilig en volgens ooreenkoms bekragtig word:

- **Bewys van werk (PoW)** maak op rekenaarkrag staat om transaksies te verifieer.
- **Bewys van belang (PoS)** vereis dat valideerders ’n sekere hoeveelheid tokens besit, wat energieverbruik verlaag in vergelyking met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-beginsels

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word met digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multihandtekeningtransaksies** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **insette** (bron van fondse), **uitsette** (bestemming), **fooie** (aan miners betaal) en **scripts** (transaksiereëls).

### Lightning Network

Die doel is om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat, terwyl slegs die finale toestand na die blockchain uitgesaai word.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verbloem.

## Verkryging van Bitcoins anoniem

Metodes sluit kontanttransaksies, mining en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die Bitcoin-wêreld is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels kommerwekkend. Hier volg ’n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privaatheid kan aantas.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen ongewoon dat insette van verskillende gebruikers in een transaksie gekombineer word weens die kompleksiteit daarvan. Daarom word **daar dikwels aanvaar dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

’n UTXO, oftewel ’n **Onbestede transaksie-uitset**, moet in sy geheel in ’n transaksie bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe wisselgeldadres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat die privaatheid aantas.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verbloem.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaksiegraaf-analise**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse openbaar.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek berus op die ontleding van transaksies met verskeie insette en uitsette om te raai watter uitset die wisselgeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die veranderingsuitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Geforseerde adreshergebruik**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit met ander insette in toekomstige transaksies kombineer en sodoende adresse aan mekaar koppel.

### Korrekte beursiegedrag

Beursies behoort te vermy om munte te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheidsleak te voorkom.

## **Ander blokkettingontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder kleingeld is waarskynlik tussen twee adresse wat aan dieselfde gebruiker behoort.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is, met die nie-ronde uitset wat waarskynlik die kleingeld is.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte sagteware en moontlik die kleingeldadres te identifiseer.
- **Bedrag- en tydkorrelasies:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Verkeersontleding**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikers se privaatheid in gevaar stel. Dit geld veral as ’n entiteit baie Bitcoin-nodes bedryf, wat sy vermoë om transaksies te monitor verbeter.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te bekom

- **Kontanttransaksies**: Verkryging van bitcoin deur kontant te gebruik.
- **Kontantalternatiewe**: Koop geskenkbewyse en ruil dit aanlyn vir bitcoin.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynwerk, veral as dit alleen gedoen word, omdat mynpoele moontlik die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin nog ’n manier wees om dit anoniem te bekom, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter dat die diens vertrou word om nie logboeke te hou nie en om die bitcoins werklik terug te gee. Bitcoin-casino’s is ’n alternatiewe mengopsie.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers saam in een, wat dit moeiliker maak vir enigiemand wat insette met uitsette probeer ooreenstem. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik nagespoor word.

Voorbeelde van transaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-smartkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom ’n transaksie tussen twee partye (bv. ’n kliënt en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die gemeenskaplike-inset-eienaarskapheuristiek wat deur transaksietoesighou-entiteite gebruik word, ongeldig maak.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie van standaard-bitcointransaksies onderskei kan word nie.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksieprivaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Tegnieke vir beursiesinkronisering**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinkroniseer. Twee metodes staan uit:

- **Volledige nodus**: Deur die hele blokketting af te laai, verseker ’n volledige nodus maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir aanvallers onmoontlik maak om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkantblokfiltrering**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te lê. Liggewigbeursies laai hierdie filters af en haal slegs volledige blokke op wanneer ’n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op ’n eweknienetwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van hergebruik van adresse**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie ’n nuwe adres te gebruik. Hergebruik van adresse kan privaatheid in gevaar stel deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig die hergebruik van adresse deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies te verdeel, kan die transaksiebedrag verduister word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingelduitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingelduitsette**: As dit nie haalbaar is om kleingeld te vermy nie, kan die skep van veelvuldige kleingelduitsette steeds privaatheid verbeter.

# **Monero: ’n baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Verstaan gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basisfooi, met ’n prioriteitsfooi om insluiting deur ’n valideerder aan te moedig. Gebruikers kan ’n maksimumfooi stel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies op Ethereum behels ’n sender en ’n ontvanger, wat gebruikers- of slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet in ’n blok ingesluit word. Noodsaaklike transaksie-inligting sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word veral uit die handtekening afgelei, sodat dit nie in die transaksiedata nodig is nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is grondliggend vir enigiemand wat met kriptogeldeenhede wil omgaan en privaatheid en sekuriteit voorop wil stel.

## Waardegerigte Web3-rooispanwerk

- Inventariseer komponente wat waarde dra (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flash-loans/orakels/aanmeldbewyse/ kruis-ketting om impak te bekragtig en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van die Web3-ondertekeningswerkvloei

- Peuterwerk met die voorsieningsketting van beursie-UI’s kan EIP-712-loonvragte net voor ondertekening verander en geldige handtekeninge insamel vir proxy-oorname op grond van delegatecall (bv. oorskryf van slot-0 van Safe se masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstraksie van rekeninge (ERC-4337)

- Algemene foutmodusse van slimrekeninge sluit in omseiling van toegangsbeheer in `EntryPoint`, ongetekende gasvelde, toestandsvolle validering, ERC-1271-herhaling en fooidreinasie via terugdraai ná validering.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sekuriteit van slimkontrakte

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integriteit van ZK-bewyse / zkVM-gaste

Wanneer ’n bewysleweraar ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder net dat die **gasprogram uitgevoer is soos geskryf**. As die gas **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysleweraar ’n bewys genereer wat slaag terwyl die **openbare maatstawwe of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgaste

- Behandel private getuiedata/kringgrepe as **onbetroubare aanvallersinvoer**, selfs al word dit deur die bewys versteek.
- Vermy deserialisering daarvan met ongekontroleerde helpers soos `rkyv::access_unchecked`, tensy die grepe reeds buite die proses bekragtig is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet bekragtig word voordat hulle beheervloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **discriminant buite die toegelate reeks** kan inspuit, word elke downstream `match` oor daardie waarde verdag.

### Omseiling van tellers deur jump table / UB

As Rust ’n groot `match` na ’n **jump table** omskakel, kan ’n ongeldige enum-discriminant **ongedefinieerde beheervloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Discriminant buite die toegelate reeks indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit vervalste bewyse oplewer wat onmoontlike statistieke rapporteer, soos minder gates, minder duur bewerkings of ander vervalste beperkte hulpbronne.

Hersieningskontrolelys:

- Soek na aanvallerbeheerde enums wat uit witness-/private invoer gedeserialiseer word.
- Inspekteer herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + unchecked deserialization + groot opcode-dispatch as ’n kombinasie met hoë risiko.
- Reverse engineer die gegenereerde binary wanneer nodig; die uitleg van die jump table kan belangriker as die bronkode wees.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreters

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Vir omkeerbare/kwantumagtige instruksiestelle moet jy verseker dat operande wat onderskeidend moet wees, inderdaad beperk word om onderskeidend te wees. ’n Toffoli-/CCX-agtige bewerking wat geïmplementeer word as:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

word onveilig as die gasstelsel dit nie verwerp nie:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In daardie geval vereenvoudig die oorgang tot:

```text
q = q ^ (q & q) = 0
```

Dit skep ’n **deterministiese terugstelprimitief** wat omkeerbaarheidsaannames verbreek en goedkoper, nie-beoogde berekeninge moontlik maak. In bewysstelsels wat hulpbrongebruik staaf, kan aanvallers funksionele kontroles slaag terwyl hulle die kostemodel omseil wat die verifieerder meen afgedwing word.

### Wat om in ZK-stelsels te toets

- Fuzz alle guest-parsers met misvormde witness-/private-invoerkoderinge.
- Bevestig dat enum-reeksvalidering plaasvind voordat opcode-dispatch plaasvind.
- Voeg semantiese kontroles by vir operand-aliasing en ander ongeldige instruksievorme.
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die guest-program foutief is.

## Staatafhanklike magtiging

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

As jy praktiese uitbuiting van DEX’e en AMM’s navors (Uniswap v4 hooks, afrondings-/presisie-misbruik, swaps wat drempels oorskry en deur flash loans versterk word), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Bestudeer die volgende vir multi-bate-geweegde poele wat virtuele saldo’s kas en vergiftig kan word wanneer `supply == 0`:

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
- [7] [Trail of Bits - Ons het Google se nulkennisbewys van kwantumkriptanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kromme-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronskattings en versagtingsmaatreëls (reggestelde weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits-bewys-van-konsep-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
