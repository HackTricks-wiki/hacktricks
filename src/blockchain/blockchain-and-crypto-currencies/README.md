# Blokketting en kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Slimkontrakte** word gedefinieer as programme wat op ’n blokketting uitgevoer word wanneer sekere voorwaardes nagekom word. Dit outomatiseer die uitvoering van ooreenkomste sonder tussengangers.
- **Gedesentraliseerde toepassings (dApps)** bou voort op slimkontrakte en beskik oor ’n gebruikersvriendelike voorkant en ’n deursigtige, ouditeerbare agterkant.
- **Tokens en munte** verskil daarin dat munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
  - **Nutstokens** bied toegang tot dienste, en **sekuriteitstokens** dui op eienaarskap van bates.
- **DeFi** staan vir Gedesentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAO’s** verwys onderskeidelik na Gedesentraliseerde Handelsplatforms en Gedesentraliseerde Outonome Organisasies.

## Konsensusmeganismes

Konsensusmeganismes verseker dat transaksies op die blokketting veilig en volgens ooreenkoms bekragtig word:

- **Proof of Work (PoW)** maak staat op rekenaarkrag om transaksies te verifieer.
- **Proof of Stake (PoS)** vereis dat valideerders ’n sekere hoeveelheid tokens besit, wat energieverbruik verminder vergeleke met PoW.<sup>[[1]](#references)</sup>

## Bitcoin-noodsaaklikhede

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge bekragtig, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multihandtekeningstransaksies** vereis verskeie handtekeninge om ’n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **invoere** (bron van fondse), **uitsette** (bestemming), **fooie** (betaal aan mynwerkers) en **skripte** (transaksiereëls).

### Lightning Network

Die doel is om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne ’n kanaal toe te laat en slegs die finale toestand na die blokketting uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Anonieme verkryging van bitcoins

Metodes sluit in kontanttransaksies, mynbou en die gebruik van mixers. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier volg ’n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privaatheid kan ondermyn.<sup>[[6]](#references)</sup>

## **Aanname van gemeenskaplike invoereienaarskap**

Dit is oor die algemeen ongewoon dat invoere van verskillende gebruikers in ’n enkele transaksie gekombineer word weens die kompleksiteit daarvan. Daarom word **daar dikwels aanvaar dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **Opsporing van UTXO-wisseladresse**

’n UTXO, of **Onbestede transaksie-uitset**, moet volledig in ’n transaksie bestee word. As slegs ’n deel daarvan na ’n ander adres gestuur word, gaan die res na ’n nuwe wisseladres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid in gevaar stel.

### Voorbeeld

Om dit te versag, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan die eienaar te koppel**.

## **Transaksiegraafanalise**

Transaksies kan as grafieke voorgestel word, wat moontlike verbande tussen gebruikers op grond van die geldvloei onthul.

## **Heuristiek vir onnodige invoere (optimale wisselheuristiek)**

Hierdie heuristiek berus op die ontleding van transaksies met verskeie invoere en uitsette om te raai watter uitset die wisselgeld is wat na die sender terugkeer.

### Voorbeeld

```bash
2 btc --> 4 btc
3 btc     1 btc
```

As die byvoeging van meer insette die change-uitset groter maak as enige enkele inset, kan dit die heuristiek verwar.

## **Gedwonge hergebruik van adresse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander insette kombineer en sodoende adresse aan mekaar koppel.

### Korrekte gedrag van beursies

Beursies moet vermy om munte te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheidslek te voorkom.

## **Ander blockchain-ontledingstegnieke**

- **Presiese betalingsbedrae:** Transaksies sonder kleingeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde bedrae:** ’n Ronde bedrag in ’n transaksie dui daarop dat dit ’n betaling is; die nie-ronde uitset is waarskynlik die kleingeld.
- **Beursievingerafdrukke:** Verskillende beursies het unieke patrone vir die skep van transaksies. Dit stel ontleders in staat om die gebruikte sagteware en moontlik die kleingeldadres te identifiseer.
- **Korrelasies tussen bedrae en tydstippe:** Die bekendmaking van transaksietye of -bedrae kan dit moontlik maak om transaksies na te speur.

## **Verkeersanalise**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel en sodoende gebruikers se privaatheid in gevaar stel. Dit geld veral as ’n entiteit baie Bitcoin-nodes bedryf, wat sy vermoë om transaksies te monitor, vergroot.

## Meer

Besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy) vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings.

# Anonieme Bitcoin-transaksies

## Maniere om Bitcoins anoniem te kry

- **Kontanttransaksies**: Verkryging van bitcoin met kontant.
- **Kontantalternatiewe**: Aankoop van geskenkbewyse en aanlynruil daarvan vir bitcoin.
- **Mynbou**: Die privaatste manier om bitcoins te verdien, is deur mynbou, veral as dit alleen gedoen word, omdat mynpoele dalk die mynwerker se IP-adres ken. [Inligting oor mynpoele](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin nog ’n manier wees om dit anoniem te bekom, hoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur ’n mengdiens te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter dat die gebruiker die diens vertrou om nie logs by te hou nie en om die bitcoins werklik terug te stuur. Bitcoin-casino’s is ’n alternatiewe mengopsie.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers saam in een, wat dit moeiliker maak vir enigiemand om insette met uitsette te koppel. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke groottes van insette en uitsette steeds moontlik nagespoor word.

Voorbeelde van transaksies waarin CoinJoin moontlik gebruik is, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Besoek [CoinJoin](https://coinjoin.io/en) vir meer inligting. Sien [Tornado Cash](https://tornado.cash) vir ’n Ethereum-slimkontrakmenger wat deposito’s van latere onttrekkings skei.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die heuristiek vir gemeenskaplike eienaarskap van insette ongeldig maak wat deur transaksietoesighoudende entiteite gebruik word.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl hulle ononderskeibaar van standaard bitcoin-transaksies bly.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksieprivaatheid.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Beursie-sinchroniseringstegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinchroniseer. Twee metodes staan uit:

- **Volle node**: Deur die hele blokketting af te laai, verseker ’n volle node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om vas te stel in watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkant-blokfiltrering**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, sodat beursies relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Liggewigbeursies laai hierdie filters af en haal slegs volledige blokke op wanneer ’n ooreenstemming met die gebruiker se adresse gevind word.

## **Tor gebruik vir anonimiteit**

Aangesien Bitcoin op ’n eweknie-netwerk werk, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie ’n nuwe adres te gebruik. Hergebruik van adresse kan privaatheid in gevaar stel deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur ’n betaling in verskeie transaksies te verdeel, kan die transaksiebedrag verbloem word en privaatheidsaanvalle verydel word.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingeld-uitsette vereis nie, verbeter privaatheid deur metodes vir die opsporing van kleingeld te ontwrig.
- **Veelvuldige kleingeld-uitsette**: As dit nie moontlik is om kleingeld te vermy nie, kan die skep van veelvuldige kleingeld-uitsette steeds privaatheid verbeter.

# **Monero: ’n Baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid voorop te stel.

# **Ethereum: Gas en transaksies**

## **Verstaan gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels ’n gaslimiet en ’n basisfooi, met ’n prioriteitsfooi om valideerders aan te spoor om dit in te sluit. Gebruikers kan ’n maksimumfooi instel om te verseker dat hulle nie te veel betaal nie; die oorskot word terugbetaal.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies in Ethereum behels ’n sender en ’n ontvanger, wat albei gebruiker- of slimkontrakadresse kan wees. Hulle vereis ’n fooi en moet by ’n blok ingesluit word. Noodsaaklike transaksie-inligting sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word veral uit die handtekening afgelei, wat beteken dat dit nie in die transaksiedata nodig is nie.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is grondliggend vir enigiemand wat met kriptogeldeenhede wil werk terwyl privaatheid en sekuriteit vooropgestel word.

## Waarde-gesentreerde Web3 Red Teaming

- Inventariseer komponente wat waarde dra (ondertekenaars, orakels, brûe, outomatisering) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir voorregte-eskalasie bloot te lê.
- Oefen aanvalskettings met flash loans/orakels/eiebewyse/kruisketting-aanvalle om impak te bekragtig en uitbuitbare voorvereistes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van Web3-ondertekeningswerkvloei

- Peuterwerk met die voorsieningsketting van beursie-koppelvlakke kan EIP-712-loonvragte net voor ondertekening verander en geldige handtekeninge insamel vir delegatecall-gebaseerde proxy-oorname (bv. slot-0-oorwriting van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Rekeningabstraksie (ERC-4337)

- Algemene foutmodusse van slimrekeninge sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, toestandvolle validering, ERC-1271-herhaling en fooi-uitputting deur ná validering terug te draai.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Slimkontrak-sekuriteit

- Mutasietoetsing om blinde kolle in toetssuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK-bewys-/zkVM-gasheerintegriteit

Wanneer ’n bewysleweraar ’n **zkVM** of ’n toepassingspesifieke bewyskring gebruik om ’n bewering te staaf, leer die verifieerder slegs dat die **gasheerprogram uitgevoer is soos geskryf**. As die gasheer **onveilige deserialisering**, **ongedefinieerde gedrag** of **ontbrekende semantiese beperkings** bevat, kan ’n kwaadwillige bewysleweraar ’n bewys genereer wat valideer terwyl die **openbare maatstawwe of beweerde invariant onwaar is**.<sup>[[7]](#references)</sup>

### Onveilige deserialisering binne bewysgashere

- Behandel private getuienis-/kringgrepe as **onbetroubare aanvallersinvoer**, selfs al word hulle deur die bewys versteek.
- Vermy om hulle met ongekontroleerde hulpfunksies soos `rkyv::access_unchecked` te deserialiseer, tensy die grepe reeds buite die band gevalideer is.
- Enum-diskriminante, relatiewe wysers, lengtes en indekse wat uit onbetroubare geserialiseerde data gelaai word, moet gevalideer word voordat hulle beheervloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **buitebereik-discriminant** kan inspuit, word elke daaropvolgende `match` oor daardie waarde verdag.

### Jump-table / UB-omseiling van tellerkontroles

As Rust ’n groot `match` na ’n **jump table** omskakel, kan ’n ongeldige enum-discriminant **ongedefinieerde beheer vloei** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksiesemantiek** uit.
3. ’n Buitebereik-discriminant indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit vervalste bewyse oplewer wat onmoontlike maatstawwe rapporteer, soos minder gates, minder duur bewerkings of ander vervalste, begrensde hulpbronwaardes.

Kontrolelys vir hersiening:

- Soek na aanvaller-beheerde enums wat uit witness-/private invoer gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode-/kind-veld.
- Beskou `unsafe` + ongekontroleerde deserialisering + groot opcode-dispatch as ’n hoërisikokombinasie.
- Reverse-engineer die gegenereerde binary wanneer nodig; die uitleg van jump tables kan belangriker wees as die bronkode.

### Ontbrekende semantiese beperkings in omkeerbare/gespesialiseerde interpreteerders

Moenie net geheueveiligheid valideer nie; valideer ook die **semantiese reëls** wat die bewys veronderstel is om af te dwing.

Vir omkeerbare/kwantumagtige instruksiestelle moet jy verseker dat operande wat verskillend moet wees, werklik beperk word om verskillend te wees. ’n Toffoli-/CCX-agtige bewerking wat soos volg geïmplementeer word:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

raak onveilig as die gas nie verwerp nie:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In daardie geval vereenvoudig die oorgang tot:

```text
q = q ^ (q & q) = 0
```

Dit skep ’n **deterministiese reset-primitief** wat omkeerbaarheidsaannames verbreek en goedkoper, onbedoelde berekeninge moontlik maak. In bewysstelsels wat hulpbronverbruik staaf, kan aanvallers hiermee funksionele kontroles slaag terwyl hulle die kostemodel omseil wat die verifieerder meen afgedwing word.

### Wat om in ZK-stelsels te toets

- Fuzz alle guest-parsers met misvormde witness-/private-input-koderings.
- Bevestig enum-reeksvalidering voordat opcode-versending plaasvind.
- Voeg semantiese kontroles vir operand-aliasing en ander ongeldige instruksievorme by.
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike verwysingsimplementering.
- Onthou dat ’n geldige bewys steeds die **verkeerde stelling** kan bewys as die guest-program foutief is.

## Toestandafhanklike magtiging

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

As jy praktiese uitbuiting van DEX’e en AMM’s ondersoek (Uniswap v4 hooks, afrondings-/presisie-misbruik, swaps wat drempels oorskry en deur flash loans versterk word), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset-geweegde pools wat virtuele saldo’s kas en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Openbare sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multi-handtekeningtransaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se zero-knowledge-bewys van kwantumkriptanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kurwe-kriptogeldeenhede teen kwantumkwesbaarhede: hulpbronskattings en versagtingsmaatreëls (reggemaakte weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits se proof-of-concept-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
