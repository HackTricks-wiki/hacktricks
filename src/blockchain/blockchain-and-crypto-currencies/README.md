# Blockchain en Crypto-geldeenhede

## Basiese Konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en wat die uitvoering van ooreenkomste sonder tussengangers outomatiseer.
- **Decentralized Applications (dApps)** bou voort op smart contracts, met 'n gebruikersvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei waar coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** verleen toegang tot dienste, en **Security Tokens** dui op bate-eienaarskap.
- **DeFi** staan vir Decentralized Finance en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Consensus Mechanisms

Consensus mechanisms verseker veilige en ooreengekome transaksievaliderings op die blockchain:

- **Proof of Work (PoW)** maak staat op rekenaarkrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik in vergelyking met PoW verminder.<sup>[[1]](#references)</sup>

## Bitcoin Essentials

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die private key oordragte kan begin.<sup>[[2]](#references)</sup>

#### Sleutelkomponente:

- **Multisignature Transactions** vereis verskeie handtekeninge om 'n transaksie te magtig.<sup>[[3]](#references)</sup>
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (aan miners betaal), en **scripts** (transaksiereëls).

### Lightning Network

Het ten doel om Bitcoin se scalability te verbeter deur verskeie transaksies binne 'n channel toe te laat, en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin Privacy Concerns

Privacy-aanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, buit transaksiepatrone uit. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Verkryging van Bitcoins Anoniem

Metodes sluit in kontanttransaksies, mining en die gebruik van mixers. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verhoogde privacy.

# Opsomming van Bitcoin Privacy Attacks

In die wêreld van Bitcoin is die privacy van transaksies en die anonimiteit van gebruikers dikwels onderwerpe van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privacy kan kompromitteer.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Dit is oor die algemeen seldsaam dat inputs van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die kompleksiteit wat daarmee gepaardgaan. Daarom word **twee input-adresse in dieselfde transaksie dikwels aanvaar om aan dieselfde eienaar te behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet volledig in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe change address. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privacy in gevaar stel.

### Voorbeeld

Om dit te versag, kan mixing services of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Blootstelling op Social Networks & Forums**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaction Graph Analysis**

Transaksies kan as grafieke gevisualiseer word, wat moontlike verbande tussen gebruikers op grond van die vloei van fondse openbaar.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristic is gebaseer op die ontleding van transaksies met verskeie inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As die byvoeging van meer inputs die change-output groter as enige enkele input maak, kan dit die heuristic verwar.

## **Forced Address Reuse**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit in toekomstige transaksies met ander inputs kombineer en sodoende adresse aan mekaar koppel.

### Correct Wallet Behavior

Wallets moet vermy om coins wat op reeds gebruikte, leë adresse ontvang is, te gebruik om hierdie privacy leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaksies sonder change is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Round Numbers:** ’n Ronde getal in ’n transaksie dui daarop dat dit ’n betaling is, met die nie-ronde output wat waarskynlik die change is.
- **Wallet Fingerprinting:** Verskillende wallets het unieke patrone vir die skep van transaksies, wat analysts in staat stel om die gebruikte sagteware en moontlik die change-adres te identifiseer.
- **Amount & Timing Correlations:** Die bekendmaking van transaksietye of -bedrae kan transaksies naspeurbaar maak.

## **Traffic Analysis**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel, wat gebruikersprivaatheid in gevaar stel. Dit is veral waar as ’n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë om transaksies te monitor, verbeter.

## More

Vir ’n omvattende lys van privacy attacks en verdediging, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Om bitcoin deur middel van kontant te bekom.
- **Cash Alternatives**: Om geskenkbewyse te koop en dit aanlyn vir bitcoin te verruil.
- **Mining**: Die mees private metode om bitcoins te verdien, is deur mining, veral wanneer dit alleen gedoen word, omdat mining pools moontlik die miner se IP-adres ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties kan diefstal van bitcoin nog ’n metode wees om dit anoniem te bekom, hoewel dit onwettig en nie aanbeveel word nie.

## Mixing Services

Deur ’n mixing service te gebruik, kan ’n gebruiker **bitcoins stuur** en **ander bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar na te spoor. Dit vereis egter vertroue dat die diens nie logs hou nie en die bitcoins werklik terugstuur. Alternatiewe mixing-opsies sluit Bitcoin-casino’s in.

## CoinJoin

**CoinJoin** kombineer verskeie transaksies van verskillende gebruikers in een, wat die proses bemoeilik vir enigiemand wat inputs aan outputs probeer koppel. Ondanks die doeltreffendheid daarvan, kan transaksies met unieke input- en output-groottes steeds moontlik nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238` in.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir ’n Ethereum smart-contract mixer wat deposits van latere withdrawals skei, sien [Tornado Cash](https://tornado.cash).

## PayJoin

’n Variant van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. ’n klant en ’n handelaar) as ’n gewone transaksie, sonder die kenmerkende gelyke outputs van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die common-input-ownership heuristic ongeldig maak wat deur entiteite gebruik word wat transaksies monitor.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit ononderskeibaar van standaard-bitcointransaksies bly.

**Die benutting van PayJoin kan tradisionele surveillance-metodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling in die nastrewing van transaksieprivaatheid maak.

# Beste Praktyke vir Privaatheid in Cryptocurrencies

## **Wallet-sinchroniseringstegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om wallets met die blockchain te sinchroniseer. Twee metodes staan uit:

- **Volledige node**: Deur die volledige blockchain af te laai, verseker 'n volledige node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke block in die blockchain, sodat wallets relevante transaksies kan identifiseer sonder om spesifieke belangstellings aan network-waarnemers bloot te stel. Lightweight wallets laai hierdie filters af en haal slegs volledige blocks op wanneer 'n passing met die gebruiker se adresse gevind word.

## **Gebruik van Tor vir Anonimiteit**

Aangesien Bitcoin op 'n peer-to-peer-network funksioneer, word die gebruik van Tor aanbeveel om jou IP-adres te verberg en privaatheid te verbeter wanneer jy met die network interaksie het.

## **Voorkoming van Adreshergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie 'n nuwe adres te gebruik. Die hergebruik van adresse kan privaatheid benadeel deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir Transaksieprivaatheid**

- **Veelvuldige transaksies**: Deur 'n betaling in verskeie transaksies op te deel, kan die transaksiebedrag verdoesel word, wat privacy attacks verydel.
- **Vermyding van kleingeld**: Deur transaksies te kies wat nie kleingeld-uitsette vereis nie, word privaatheid verbeter deur change detection-metodes te ontwrig.
- **Veelvuldige kleingeld-uitsette**: Indien dit nie haalbaar is om kleingeld te vermy nie, kan die generering van veelvuldige kleingeld-uitsette steeds privaatheid verbeter.

# **Monero: 'n Baken van Anonimiteit**

Monero is ontwerp om transaksieprivaatheid te prioritiseer.

# **Ethereum: Gas en Transaksies**

## **Verstaan van Gas**

Gas meet die berekeningswerk wat nodig is om bewerkings op Ethereum uit te voer, en word in **gwei** geprys. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gas-limiet en 'n basisfooi, met 'n prioriteitsfooi om validator-insluiting aan te moedig. Gebruikers kan 'n maksimumfooi stel om te verseker dat hulle nie te veel betaal nie, met die oorskot wat terugbetaal word.<sup>[[5]](#references)</sup>

## **Uitvoer van Transaksies**

Transaksies in Ethereum behels 'n sender en 'n ontvanger, wat óf gebruikeradresse óf smart contract-adresse kan wees. Hulle vereis 'n fooi en moet in 'n block ingesluit word. Belangrike inligting in 'n transaksie sluit die ontvanger, sender se handtekening, waarde, opsionele data, gas-limiet en fooie in. Opmerklik is dat die sender se adres uit die handtekening afgelei word, wat die behoefte daaraan in die transaksiedata uitskakel.<sup>[[4]](#references)</sup>

Hierdie praktyke en meganismes is fundamenteel vir enigeen wat met cryptocurrencies wil werk terwyl privaatheid en sekuriteit geprioritiseer word.

## Waardegesentreerde Web3 Red Teaming

- Inventariseer komponente wat waarde bevat (signers, oracles, bridges, automation) om te verstaan wie fondse kan verskuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT-tactics om privilege escalation-paaie bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain-aanvalskettings om impak te valideer en exploitable preconditions te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittering van die Web3 Signing Workflow

- Supply-chain-tampering van wallet-UIs kan EIP-712-payloads net voor signing wysig en geldige signatures insamel vir delegatecall-gebaseerde proxy takeovers (bv. slot-0-oorbeskrywing van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Algemene smart-account-failure modes sluit in die omseiling van `EntryPoint`-toegangsbeheer, ongetekende gas-velde, stateful validation, ERC-1271-replay en fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing om blindekolle in test suites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Wanneer 'n prover 'n **zkVM** of 'n toepassingspesifieke proof circuit gebruik om 'n bewering te staaf, leer die verifier slegs dat die **guest program uitgevoer is soos geskryf**. Indien die guest **unsafe deserialization**, **undefined behavior** of **missing semantic constraints** bevat, kan 'n kwaadwillige prover 'n proof genereer wat valideer terwyl die **publieke metrics of beweerde invariant vals is**.<sup>[[7]](#references)</sup>

### Unsafe deserialization binne proof guests

- Behandel private witness/circuit-bytes as **untrusted attacker input**, selfs al word hulle deur die proof versteek.
- Vermy om hulle met unchecked helpers soos `rkyv::access_unchecked` te deserialiseer, tensy die bytes reeds out-of-band gevalideer is.
- Enum-discriminants, relative pointers, lengtes en indekse wat uit onbetroubare serialized data gelaai word, moet gevalideer word voordat hulle control flow of memory access beïnvloed.

Praktiese audit-patroon:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Indien ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **out-of-range discriminant** kan injecteer, word elke downstream `match` op daardie waarde verdag.

### Jump-table / UB counter bypass

Indien Rust ’n groot `match` in ’n **jump table** verlaag, kan ’n ongeldige enum-discriminant **undefined control flow** veroorsaak. ’n Gevaarlike patroon is:<sup>[[7]](#references)[[9]](#references)</sup>

1. Een `match` werk **sekuriteitskritieke tellers/beperkings** by.
2. ’n Tweede `match` voer die **werklike instruksie-semantiek** uit.
3. ’n Discriminant buite die geldige reeks indekseer verby die eerste jump table en beland in kode wat met die tweede een geassosieer word.

Gevolg: die bewerking word steeds uitgevoer, maar die rekeningkundige pad word oorgeslaan. In ’n zkVM kan dit bewyse vervals wat onmoontlike metrieke rapporteer, soos minder gates, minder duur bewerkings, of ander vervalste begrensde hulpbronne.

Hersieningskontrolelys:

- Soek enums wat deur ’n aanvaller beheer word en uit witness/private input gedeserialiseer word.
- Inspekteer herhaalde `match`-stellings oor dieselfde opcode/kind-veld.
- Behandel `unsafe` + unchecked deserialization + groot opcode dispatch as ’n hoërisiko-kombinasie.
- Reverse engineer die uitgegeven binêre lêer wanneer nodig; die uitleg van die jump table kan belangriker wees as die bronkode.

### Missing semantic constraints in reversible/specialized interpreters

Moenie slegs geheuesekuriteit valideer nie; valideer ook die **semantiese reëls** wat die bewys moet afdwing.

Vir reversible/quantum-like instruction sets, maak seker dat operande wat onderskei moet wees, werklik beperk word om onderskeie te wees. ’n Toffoli/CCX-like-bewerking wat geïmplementeer word as:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
word onveilig as die gas nie verwerp nie:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In daardie geval vou die oorgang saam tot:
```text
q = q ^ (q & q) = 0
```
Dit skep ’n **deterministiese reset-primitief**, wat omkeerbaarheidsaannames verbreek en goedkoper nie-bedoelde berekeninge moontlik maak. In proof systems wat hulpbrongebruik attesteer, kan dit aanvallers in staat stel om funksionele kontroles te slaag terwyl hulle die kostemodel omseil wat die verifier glo afgedwing word.

### Wat om in ZK-stelsels te toets

- Fuzz alle guest-parsers met misvormde witness/private-input-enkoderings.
- Verseker enum-reeksvalidasie voordat opcode-dispatch plaasvind.
- Voeg semantiese kontroles vir operand-aliasing en ander ongeldige instruction-vorms by.
- Vergelyk gerapporteerde/openbare tellers met ’n onafhanklike reference-implementering.
- Onthou dat ’n geldige proof steeds die **verkeerde stelling** kan bewys as die guest-program foutief is.

## DeFi/AMM-uitbuiting

As jy praktiese exploitation van DEX'e en AMM'e (Uniswap v4 hooks, afrondings-/presisie-misbruik, flash-loan-versterkte threshold-crossing-swaps) ondersoek, kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset weighted pools wat virtuele saldo's cache en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Openbare sleutel en private sleutel verduidelik - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Wat is multi-signature-transaksies? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaksies | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas en fooie | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privaatheid - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Ons het Google se zero-knowledge-proof van quantum-kriptoanalise geklop](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Beveiliging van elliptiese-kurwe-cryptocurrencies teen quantum-kwesbaarhede: Hulpbronskattings en versagtings (reggemaakte weergawe)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits se proof-of-concept-bewaarplek](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
