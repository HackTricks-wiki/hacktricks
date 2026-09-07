# Blockchain en Crypto-geldeenhede

{{#include ../../banners/hacktricks-training.md}}

## Basiese konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat die uitvoering van ooreenkomste sonder tussengangers outomatiseer.
- **Decentralized Applications (dApps)** bou voort op smart contracts en bevat 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei waar coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** verleen toegang tot dienste, en **Security Tokens** dui op bate-eienaarskap.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidasies op die blockchain:

- **Proof of Work (PoW)** maak staat op rekenkrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik in vergelyking met PoW verminder.<sup>[[1]](#references)</sup>

## Bitcoin-basiese beginsels

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die private key oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis verskeie handtekeninge om 'n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (aan miners betaal), en **scripts** (transaksiereëls).

### Lightning Network

Het ten doel om Bitcoin se skaalbaarheid te verbeter deur verskeie transaksies binne 'n kanaal toe te laat en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Verkryging van Bitcoins anoniem

Metodes sluit kontanttransaksies, mining en die gebruik van mixers in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir groter privaatheid.

# Opsomming van Bitcoin-privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels rede tot kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privaatheid kan kompromitteer.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen skaars dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit wat daarby betrokke is. Daarom word daar dikwels aanvaar dat **twee input-adresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe change-adres. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromitteer.

### Voorbeeld

Om dit te beperk, kan mixing-dienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Social Networks & Forums Exposure**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gevisualiseer word, wat potensiële verbindings tussen gebruikers op grond van die vloei van fondse openbaar.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die ontleding van transaksies met verskeie inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change output groter as enige enkele input maak, kan dit die heuristiek verwar.

## **Forced Address Reuse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander inputs kombineer en sodoende adresse aan mekaar koppel.

### Correct Wallet Behavior

Wallets behoort te vermy om coins wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privaatheidslek te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** ’n Ronde getal in ’n transaksie dui daarop dat dit ’n betaling is, met die nie-ronde uitset wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir die skep van transaksies, wat ontleders in staat stel om die gebruikte software en moontlik die change-adres te identifiseer.
- **Amount & Timing Correlations:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspoorbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel, wat gebruikersprivaatheid benadeel. Dit is veral waar as ’n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë om transaksies te monitor, verbeter.

## More

Vir ’n omvattende lys van privaatheidsaanvalle en -verdedigings, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin deur middel van kontant verkry.
- **Cash Alternatives**: Geskenkkaarte aankoop en dit aanlyn vir bitcoin ruil.
- **Mining**: Die mees private metode om bitcoins te verdien, is deur mining, veral wanneer dit alleen gedoen word, omdat mining pools moontlik die miner se IP-adres ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties kan diefstal van bitcoin nog ’n metode wees om dit anoniem te verkry, hoewel dit onwettig en nie aanbeveel word nie.

## Mixing Services

Deur ’n mixing service te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter vertroue dat die service nie logs hou nie en die bitcoins werklik terugstuur. Alternatiewe mixing-opsies sluit Bitcoin-casino’s in.

## CoinJoin

**CoinJoin** kombineer verskeie transaksies van verskillende gebruikers in een, wat die proses bemoeilik vir enigiemand wat probeer om inputs aan outputs te koppel. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke groottes van inputs en outputs steeds moontlik nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir ’n Ethereum smart-contract mixer wat deposits van latere withdrawals skei, sien [Tornado Cash](https://tornado.cash).

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (byvoorbeeld ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke outputs van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die common-input-ownership-heuristiek wat deur transaksietoesig-entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar van standaard bitcoin-transaksies bly.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling in die nastrewing van transaksieprivaatheid maak.

# Beste praktyke vir privaatheid in cryptocurrency

## **Wallet-sinchronisasietegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Full node**: Deur die volledige blockchain af te laai, verseker 'n full node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit vir adversaries onmoontlik maak om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke blok in die blockchain, wat wallets in staat stel om relevante transaksies te identifiseer sonder om spesifieke belangstellings aan netwerkwaarnemers bloot te stel. Lightweight wallets laai hierdie filters af en haal slegs volledige blokke wanneer 'n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer-netwerk funksioneer, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die netwerk interaksie het.

## **Voorkoming van adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Die hergebruik van adresse kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur 'n betaling in verskeie transaksies te verdeel, kan die transaksiebedrag verbloem word, wat privacy attacks verydel.
- **Vermyding van kleingeld**: Deur transaksies te kies wat nie change outputs vereis nie, word privaatheid verbeter deur change detection methods te ontwrig.
- **Veelvuldige change outputs**: Indien die vermyding van kleingeld nie haalbaar is nie, kan die generering van veelvuldige change outputs steeds privaatheid verbeter.

# **Monero: 'n Baken van anonimiteit**

Monero is ontwerp om transaksieprivaatheid te prioritiseer.

# **Ethereum: Gas en transaksies**

## **Verstaan van Gas**

Gas meet die berekeningspoging wat nodig is om operasies op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gas limit en 'n base fee, met 'n priority fee om validator-insluiting aan te moedig. Gebruikers kan 'n max fee instel om te verseker dat hulle nie te veel betaal nie, met die oorskot wat terugbetaal word.<sup>[[5]](#references)</sup>

## **Uitvoering van transaksies**

Transaksies in Ethereum behels 'n sender en 'n recipient, wat óf gebruiker- óf smart contract-adresse kan wees. Hulle vereis 'n fee en moet in 'n blok ingesluit word. Belangrike inligting in 'n transaksie sluit die recipient, sender se signature, waarde, opsionele data, gas limit en fees in. Die sender se adres word veral uit die signature afgelei, wat die behoefte daaraan in die transaksiedata uitskakel.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met cryptocurrencies wil werk terwyl privaatheid en sekuriteit geprioritiseer word.

## Value-Centric Web3 Red Teaming

- Inventariseer komponente wat waarde dra (signers, oracles, bridges, automation) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-taktieke om privilege escalation paths bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain attack chains om impak te valideer en exploitable preconditions te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van die Web3 Signing Workflow

- Supply-chain tampering van wallet-UIs kan EIP-712-payloads onmiddellik voor signing verander en geldige signatures buitmaak vir delegatecall-based proxy takeovers (bv. slot-0 overwrite van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Algemene smart-account failure modes sluit in die omseiling van `EntryPoint`-toegangsbeheer, unsigned gas fields, stateful validation, ERC-1271 replay en fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing om blind spots in test suites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest-integriteit

Wanneer 'n prover 'n **zkVM** of 'n toepassingspesifieke proof circuit gebruik om 'n bewering te staaf, leer die verifier slegs dat die **guest program uitgevoer is soos geskryf**. Indien die guest **unsafe deserialization**, **undefined behavior** of **missing semantic constraints** bevat, kan 'n kwaadwillige prover 'n proof genereer wat valideer terwyl die **public metrics** of **claimed invariant** vals is.<sup>[[7]](#references)</sup>

### Unsafe deserialization binne proof guests

- Behandel private witness/circuit bytes as **untrusted attacker input**, selfs al word dit deur die proof verberg.
- Vermy die deserialisering daarvan met unchecked helpers soos `rkyv::access_unchecked`, tensy die bytes reeds out-of-band gevalideer is.
- Enum-discriminants, relative pointers, lengths en indexes wat uit untrusted serialized data gelaai word, moet gevalideer word voordat hulle control flow of memory access beïnvloed.

Praktiese ouditpatroon:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
As ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **out-of-range discriminant** kan inspuit, word elke downstream `match` op daardie waarde verdag.

### Jump-table / UB counter bypass

As Rust ’n groot `match` na ’n **jump table** verlaag, kan ’n ongeldige enum-discriminant **undefined control flow** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` dateer **security-critical counters/constraints** op.
2. ’n Tweede `match` voer die **real instruction semantics** uit.
3. ’n Discriminant buite die geldige reeks indekseer verby die eerste jump table en land in kode wat met die tweede een geassosieer word.

Gevolg: die operasie word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit proofs vervals wat onmoontlike metrics rapporteer, soos minder gates, minder duur operasies of ander vervalste begrensde hulpbronne.

Review-kontrolelys:

- Soek enums wat deur die aanvaller beheer word en uit witness/private input gedeserialiseer word.
- Inspekteer herhaalde `match`-stellings oor dieselfde opcode/kind-veld.
- Behandel `unsafe` + unchecked deserialization + groot opcode dispatch as ’n hoërisiko-kombinasie.
- Reverse engineer die gegenereerde binary wanneer nodig; jump-table-uitleg kan belangriker as die bronkode wees.

### Ontbrekende semantiese constraints in omkeerbare/gespesialiseerde interpreters

Moenie net memory safety valideer nie; valideer ook die **semantic rules** wat die proof moet afdwing.

Vir omkeerbare/kwantumagtige instruction sets, verseker dat operands wat onderskeidelik moet wees, werklik beperk word om onderskeidelik te wees. ’n Toffoli/CCX-agtige operasie wat geïmplementeer word as:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
word onveilig indien die gas nie verwerp nie:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In daardie geval stort die oorgang ineen tot:
```text
q = q ^ (q & q) = 0
```
This skep 'n **deterministiese reset primitive**, wat reversibility-aannames verbreek en goedkoper nie-bedoelde berekeninge moontlik maak. In proof systems wat resource usage attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die cost model omseil wat die verifier glo afgedwing word.

### Wat om in ZK systems te toets

- Fuzz all guest parsers met malformed witness/private-input encodings.
- Assert enum range validation before opcode dispatch.
- Add semantic checks for operand aliasing and other invalid instruction forms.
- Compare reported/public counters against an independent reference implementation.
- Remember that a valid proof can still prove the **wrong statement** if the guest program is buggy.

## Staatafhanklike Authorization

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

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

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Publieke sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multi-signature-transaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se zero-knowledge proof van quantum cryptanalysis geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van Elliptic Curve Cryptocurrencies teen Quantum Vulnerabilities: Resource Estimates en Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
