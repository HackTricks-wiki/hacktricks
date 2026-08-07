# Blockchain en Crypto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat die uitvoering van ooreenkomste sonder tussengangers outomatiseer.
- **Decentralized Applications (dApps)** bou voort op smart contracts, met 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei waar coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** verleen toegang tot dienste, en **Security Tokens** dui bate-eienaarskap aan.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidering op die blockchain:

- **Proof of Work (PoW)** maak staat op rekenaarkrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik in vergelyking met PoW verminder.<sup>[[1]](#references)</sup>

## Bitcoin-noodsaaklikhede

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die private key oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis veelvuldige handtekeninge om 'n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (aan miners betaal) en **scripts** (transaksiereëls).

### Lightning Network

Het ten doel om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne 'n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Verkryging van Bitcoins anoniem

Metodes sluit in kontanttransaksies, mining en die gebruik van mixers. **CoinJoin** meng veelvuldige transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verbeterde privaatheid.

# Bitcoin-privaatheidsaanvalle

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen seldsaam dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit daarvan. Daarom word daar dikwels aanvaar dat **twee input-adresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe change-adres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromitteer.

### Voorbeeld

Om dit te versag, kan mixing-dienste of die gebruik van veelvuldige adresse help om eienaarskap te verdoesel.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gevisualiseer word, wat moontlike verbindings tussen gebruikers op grond van die vloei van fondse openbaar.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met veelvuldige inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change-output groter as enige enkele input maak, kan dit die heuristic verwar.

## **Forced Address Reuse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander inputs kombineer en sodoende adresse aan mekaar koppel.

### Correct Wallet Behavior

Wallets moet vermy om coins te gebruik wat op reeds gebruikte, leë adresse ontvang is, om hierdie privaatheids-leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** ’n Ronde getal in ’n transaksie dui daarop dat dit ’n betaling is, met die nie-ronde output wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir die skep van transaksies, wat analysts in staat stel om die gebruikte sagteware en moontlik die change-adres te identifiseer.
- **Amount & Timing Correlations:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blocks aan IP-adresse koppel, wat gebruikers se privaatheid in gevaar stel. Dit is veral waar indien ’n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë om transaksies te monitor, verbeter.

## More

Vir ’n omvattende lys van privaatheidsaanvalle en verdediging, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin deur middel van kontant verkry.
- **Cash Alternatives**: Gift cards aankoop en dit aanlyn vir Bitcoin verruil.
- **Mining**: Die privaatste metode om bitcoins te verdien, is deur mining, veral wanneer dit alleen gedoen word, omdat mining pools moontlik die miner se IP-adres kan ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties kan diefstal van bitcoin nog ’n metode wees om dit anoniem te verkry, hoewel dit onwettig en nie aanbeveel is nie.

## Mixing Services

Deur ’n mixing service te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter vertroue dat die diens nie logs hou nie en die bitcoins werklik terugstuur. Alternatiewe mixing-opsies sluit Bitcoin-casinos in.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers in een saam, wat die proses bemoeilik vir enigiemand wat probeer om inputs aan outputs te koppel. Ten spyte van die doeltreffendheid daarvan, kan transaksies met unieke input- en output-groottes steeds moontlik nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir ’n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies met fondse van miners anonimiseer.

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (byvoorbeeld ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke outputs van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die common-input-ownership heuristic wat deur transaksiebewakingsentiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie van standaard-bitcointransaksies onderskei kan word nie.

**Die benutting van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling in die nastrewing van transaksionele privaatheid maak.

# Beste praktyke vir privaatheid in kriptogeldeenhede

## **Wallet-sinchronisasietegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Full node**: Deur die volledige blockchain af te laai, verseker 'n full node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir aanvallers onmoontlik maak om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, sodat wallets relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Lightweight wallets laai hierdie filters af en haal slegs volledige blokke op wanneer 'n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer-netwerk werk, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk interaksie het.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Die hergebruik van adresse kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Multiple transactions**: Deur 'n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verbloem word, wat privaatheidsaanvalle verydel.
- **Change avoidance**: Die keuse van transaksies wat nie change outputs vereis nie, verbeter privaatheid deur change-detection-metodes te ontwrig.
- **Multiple change outputs**: Indien dit nie moontlik is om change te vermy nie, kan die generering van verskeie change outputs steeds privaatheid verbeter.

# **Monero: 'n Baken van anonimiteit**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas en transaksies**

## **Begrip van Gas**

Gas meet die berekeningspoging wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gas limit en 'n base fee, met 'n tip om miners aan te spoor. Gebruikers kan 'n max fee stel om te verseker dat hulle nie te veel betaal nie, met die oorskot wat terugbetaal word.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies in Ethereum behels 'n sender en 'n recipient, wat óf gebruiker- óf smart contract-adresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Noodsaaklike inligting in 'n transaksie sluit die recipient, sender se handtekening, waarde, opsionele data, gas limit en fooie in. Die sender se adres word opvallend genoeg uit die handtekening afgelei, wat die behoefte daaraan in die transaksiedata uitskakel.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met kriptogeldeenhede wil werk terwyl privaatheid en sekuriteit geprioritiseer word.

## Waardegesentreerde Web3 Red Teaming

- Inventariseer waarde-draende komponente (signers, oracles, bridges, automation) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om privilege-escalation-paaie bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain-aanvalskettings om impak te valideer en uitbuitbare voorafvoorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van Web3 Signing Workflow

- Supply-chain-tampering van wallet-UIs kan EIP-712-payloads onmiddellik voor signing verander en geldige handtekeninge insamel vir delegatecall-gebaseerde proxy-takeovers (bv. slot-0-oor­skrywing van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Algemene smart-account-failure modes sluit in die omseiling van `EntryPoint`-toegangsbeheer, unsigned gas fields, stateful validation, ERC-1271-replay en fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing om blinde kolle in testsuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Wanneer 'n prover 'n **zkVM** of 'n toepassingspesifieke proof circuit gebruik om 'n bewering te staaf, leer die verifier slegs dat die **guest program uitgevoer is soos geskryf**. Indien die guest **unsafe deserialization**, **undefined behavior** of **missing semantic constraints** bevat, kan 'n kwaadwillige prover 'n proof genereer wat valideer terwyl die **public metrics of claimed invariant vals is**.<sup>[[7]](#references)</sup>

### Unsafe deserialization binne proof guests

- Behandel private witness/circuit-bytes as **onbetroubare aanvallerinvoer**, selfs al word dit deur die proof verberg.
- Vermy deserialisering daarvan met unchecked helpers soos `rkyv::access_unchecked`, tensy die bytes reeds buite die band gevalideer is.
- Enum-discriminants, relative pointers, lengtes en indekse wat uit onbetroubare serialized data gelaai word, moet gevalideer word voordat hulle beheer vloei of geheuetoegang beïnvloed.

Praktiese ouditpatroon:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **out-of-range discriminant** kan inspuit, word elke downstream `match` op daardie waarde verdag.

### Jump-table / UB counter bypass

As Rust ’n groot `match` in ’n **jump table** omskakel, kan ’n ongeldige enum-discriminant **undefined control flow** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **security-critical counters/constraints** by.
2. ’n Tweede `match` voer die **real instruction semantics** uit.
3. ’n **Out-of-range discriminant** indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die operasie word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit proofs vervals wat onmoontlike metrics rapporteer, soos minder gates, minder duur operasies of ander vervalste beperkte hulpbronne.

Review-kontrolelys:

- Soek enums wat deur ’n aanvaller beheer word en uit witness/private input gedeserialiseer word.
- Ondersoek herhaalde `match`-stellings oor dieselfde opcode/kind-veld.
- Behandel `unsafe` + unchecked deserialization + groot opcode-dispatch as ’n hoërisiko-kombinasie.
- Reverse engineer die gecompileerde binary wanneer nodig; die uitleg van jump tables kan belangriker as die bronkode wees.

### Ontbrekende semantiese constraints in reversible/specialized interpreters

Moenie slegs memory safety valideer nie; valideer ook die **semantic rules** wat die proof veronderstel is om af te dwing.

Vir reversible/quantum-like instruction sets, maak seker dat operande wat uniek moet wees, werklik deur constraints as uniek afgedwing word. ’n Toffoli/CCX-like operasie wat geïmplementeer word as:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
word onveilig indien die gasheer dit nie verwerp nie:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In daardie geval stort die oorgang ineen tot:
```text
q = q ^ (q & q) = 0
```
Dit skep ’n **deterministiese reset-primitief**, wat omkeerbaarheidsaannames verbreek en goedkoper nie-bedoelde berekeninge moontlik maak. In proof systems wat hulpbrongebruik attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die kostemodel omseil wat die verifieerder glo afgedwing word.

### Wat om in ZK systems te toets

- Fuzz alle guest parsers met misvormde witness/private-input-enkoderings.
- Bevestig enum-reekse voordat opcode dispatch plaasvind.
- Voeg semantiese kontroles vir operand-aliasing en ander ongeldige instruksievorme by.
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike reference implementation.
- Onthou dat ’n valid proof steeds die **verkeerde stelling** kan bewys as die guest program foutief is.

## DeFi/AMM Exploitation

As jy praktiese exploitation van DEXes en AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps) ondersoek, kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset weighted pools wat virtual balances cache en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Verwysings

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
