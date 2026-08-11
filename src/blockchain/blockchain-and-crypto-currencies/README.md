# Blockchain en Kripto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Slimkontrakte** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat die uitvoering van ooreenkomste sonder tussengangers outomatiseer.
- **Gedesentraliseerde toepassings (dApps)** bou voort op slimkontrakte en bevat 'n gebruikersvriendelike voorkant en 'n deursigtige, kontroleerbare agterkant.
- **Tokens en Coins** onderskei waar coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** verleen toegang tot dienste, en **Security Tokens** dui op bate-eienaarskap.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidering op die blockchain:

- **Proof of Work (PoW)** maak staat op rekenkrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik in vergelyking met PoW verminder.<sup>[[1]](#references)</sup>

## Bitcoin-basiese beginsels

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die private sleutel oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis veelvuldige handtekeninge om 'n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (aan miners betaal), en **scripts** (transaksiereëls).

### Lightning Network

Beoog om Bitcoin se skaalbaarheid te verbeter deur veelvuldige transaksies binne 'n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Verkryging van Bitcoins anoniem

Metodes sluit in kontanthandel, mining en die gebruik van mixers. **CoinJoin** meng veelvuldige transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels kommerwekkend. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen seldsaam dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit wat daarmee gepaardgaan. Daarom word daar dikwels aanvaar dat **twee input-adresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die oorblywende gedeelte na 'n nuwe change-adres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromitteer.

### Voorbeeld

Om dit te versag, kan mixing-dienste of die gebruik van veelvuldige adresse help om eienaarskap te verdoesel.

## **Blootstelling op sosiale netwerke en forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaksiegraaf-analise**

Transaksies kan as grafieke gevisualiseer word, wat moontlike verbindings tussen gebruikers op grond van die vloei van fondse onthul.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristic is gebaseer op die ontleding van transaksies met veelvuldige inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change-uitset groter as enige enkele input maak, kan dit die heuristic verwar.

## **Forced Address Reuse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander inputs kombineer en sodoende adresse aan mekaar koppel.

### Correct Wallet Behavior

Wallets moet vermy om coins wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privacy leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** ’n Ronde getal in ’n transaksie dui daarop dat dit ’n betaling is, met die nie-ronde uitset wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke transaksieskeppingspatrone, wat analysts in staat stel om die gebruikte sagteware te identifiseer en moontlik die change-adres te bepaal.
- **Amount & Timing Correlations:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blocks aan IP-adresse koppel, wat gebruikers se privaatheid in gevaar stel. Dit is veral waar as ’n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë om transaksies te monitor, verbeter.

## More

Vir ’n omvattende lys van privacy-aanvalle en -verdedigings, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin deur kontant te bekom.
- **Cash Alternatives**: Gift cards te koop en dit aanlyn vir Bitcoin te verruil.
- **Mining**: Die mees private metode om bitcoins te verdien, is deur mining, veral wanneer dit alleen gedoen word, omdat mining pools moontlik die miner se IP-adres ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties kan diefstal van Bitcoin nog ’n metode wees om dit anoniem te bekom, hoewel dit onwettig en nie aanbeveel is nie.

## Mixing Services

Deur ’n mixing service te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter vertroue dat die service nie logs hou nie en wel die bitcoins terugstuur. Alternatiewe mixing-opsies sluit Bitcoin-casinos in.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers in een saam, wat die proses bemoeilik vir enigiemand wat probeer om inputs aan outputs te koppel. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke input- en output-groottes steeds moontlik nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir ’n Ethereum smart-contract mixer wat deposits van latere withdrawals skei, sien [Tornado Cash](https://tornado.cash).

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (byvoorbeeld ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke outputs van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die common-input-ownership heuristic ongeldig maak wat deur entiteite wat transaksies monitor, gebruik word.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie van standaard-bitcointransaksies onderskei kan word nie.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling in die strewe na transaksionele privaatheid maak.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Wallet-sinchronisasietegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Volledige node**: Deur die hele blockchain af te laai, verseker 'n volledige node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir adversaries onmoontlik maak om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Filter van blokke aan die kliëntkant**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, sodat wallets relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Lightweight wallets laai hierdie filters af en haal slegs volledige blokke op wanneer 'n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer-netwerk funksioneer, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk kommunikeer.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Die hergebruik van adresse kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur 'n betaling oor verskeie transaksies te verdeel, kan die transaksiebedrag verdoesel word, wat privaatheidsaanvalle verydel.
- **Vermyding van kleingeld**: Die keuse van transaksies wat nie kleingeld-uitsette vereis nie, verbeter privaatheid deur metodes vir kleingeldopsporing te ontwrig.
- **Veelvuldige kleingeld-uitsette**: Indien dit nie moontlik is om kleingeld te vermy nie, kan die generering van veelvuldige kleingeld-uitsette steeds privaatheid verbeter.

# **Monero: 'n Baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid te prioritiseer.

# **Ethereum: Gas en transaksies**

## **Begrip van Gas**

Gas meet die berekeningswerk wat nodig is om operasies op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimiet en 'n basiese fooi, met 'n prioriteitsfooi om validator-insluiting aan te moedig. Gebruikers kan 'n maksimumfooi instel om te verseker dat hulle nie te veel betaal nie, met die oorskot wat terugbetaal word.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies in Ethereum behels 'n sender en 'n ontvanger, wat óf gebruiker- óf smart contract-adresse kan wees. Hulle vereis 'n fooi en moet in 'n blok ingesluit word. Noodsaaklike inligting in 'n transaksie sluit die ontvanger, sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Die sender se adres word egter uit die handtekening afgelei, wat die behoefte daaraan in die transaksiedata uitskakel.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is fundamenteel vir enigeen wat met kriptogeldeenhede wil werk terwyl privaatheid en sekuriteit geprioritiseer word.

## Waardegesentreerde Web3 Red Teaming

- Inventariseer komponente wat waarde bevat (signers, oracles, bridges, automation) om te verstaan wie fondse kan verskuif en hoe.
- Karteer elke komponent aan relevante MITRE AADAPT-taktieke om paaie vir privilege escalation bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain-aanvalskettings om impak te valideer en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van die Web3 Signing Workflow

- Supply-chain-manipulasie van wallet-UIs kan EIP-712-payloads onmiddellik voor signing verander en geldige handtekeninge insamel vir delegatecall-gebaseerde proxy-oornames (byvoorbeeld slot-0-oorskrywing van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Algemene foutmodusse van smart accounts sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gasvelde, stateful validation, ERC-1271-replay en fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing om blinde kolle in testsuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Wanneer 'n prover 'n **zkVM** of 'n toepassingspesifieke proof circuit gebruik om 'n bewering te staaf, leer die verifier slegs dat die **guest program uitgevoer is soos geskryf**. Indien die guest **unsafe deserialization**, **undefined behavior** of **ontbrekende semantiese beperkings** bevat, kan 'n kwaadwillige prover 'n proof genereer wat valideer terwyl die **publieke maatstawwe of beweerde invariant vals is**.<sup>[[7]](#references)</sup>

### Unsafe deserialization binne proof guests

- Behandel private witness/circuit-grepe as **onbetroubare aanvallersinvoer**, selfs al word dit deur die proof versteek.
- Vermy om dit met unchecked helpers soos `rkyv::access_unchecked` te deserialiseer, tensy die grepe reeds buite die band gevalideer is.
- Enum-discriminants, relatiewe pointers, lengtes en indekse wat uit onbetroubare serialized data gelaai word, moet gevalideer word voordat hulle beheerbvloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **out-of-range discriminant** kan inspuit, word elke daaropvolgende `match` oor daardie waarde verdag.

### Jump-table / UB counter bypass

As Rust ’n groot `match` na ’n **jump table** verlaag, kan ’n ongeldige enum-discriminant **undefined control flow** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **security-critical counters/constraints** by.
2. ’n Tweede `match` voer die **werklike instruksie-semantiek** uit.
3. ’n Discriminant buite die geldige reeks indekseer verby die eerste jump table en land in kode wat met die tweede een geassosieer word.

Gevolg: die operasie word steeds uitgevoer, maar die accounting-pad word oorgeslaan. In ’n zkVM kan dit proofs vervals wat onmoontlike metrics rapporteer, soos minder gates, minder duur operasies of ander vervalste beperkte hulpbronne.

Review-kontrolelys:

- Soek enums wat deur ’n aanvaller beheer word en uit witness/private input gedeserialiseer word.
- Inspekteer herhaalde `match`-stellings oor dieselfde opcode/kind-veld.
- Behandel `unsafe` + unchecked deserialization + groot opcode dispatch as ’n hoërisiko-kombinasie.
- Reverse engineer die gegenereerde binary wanneer nodig; jump-table-uitleg kan belangriker as die bronkode wees.

### Ontbrekende semantiese constraints in omkeerbare/gespesialiseerde interpreters

Moenie net memory safety valideer nie; valideer ook die **semantiese reëls** wat die proof bedoel is om af te dwing.

Vir omkeerbare/quantum-like instruction sets, verseker dat operands wat uniek moet wees, werklik constrained is om uniek te wees. ’n Toffoli/CCX-like operasie wat geïmplementeer word as:<sup>[[7]](#references)[[8]](#references)</sup>
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
This skep ’n **deterministiese reset primitive**, wat omkeerbaarheidsaannames verbreek en goedkoper nie-bedoelde berekeninge moontlik maak. In proof systems wat resource usage attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die cost model omseil wat die verifier glo afgedwing word.

### Wat om in ZK systems te toets

- Fuzz all guest parsers with malformed witness/private-input encodings.
- Assert enum range validation before opcode dispatch.
- Add semantic checks for operand aliasing and other invalid instruction forms.
- Compare reported/public counters against an independent reference implementation.
- Remember that a valid proof can still prove the **wrong statement** if the guest program is buggy.

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold-crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Bewys van stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Publieke sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptic curve cryptocurrencies teen quantum-kwesbaarhede: Hulpbronskattings en versagtings (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
