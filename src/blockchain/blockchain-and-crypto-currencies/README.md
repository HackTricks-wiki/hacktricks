# Blockchain en Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basiese Konsepte

- **Smart Contracts** word gedefinieer as programme wat op 'n blockchain uitgevoer word wanneer sekere voorwaardes nagekom word, en outomatiseer agreement-uitvoerings sonder tussengangers.
- **Decentralized Applications (dApps)** bou op smart contracts, met 'n gebruiksvriendelike front-end en 'n deursigtige, ouditbare back-end.
- **Tokens & Coins** onderskei waar coins as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Utility Tokens** gee toegang tot dienste, en **Security Tokens** dui bate-eienaarskap aan.
- **DeFi** staan vir Decentralized Finance, en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAOs** verwys onderskeidelik na Decentralized Exchange Platforms en Decentralized Autonomous Organizations.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidering op die blockchain:

- **Proof of Work (PoW)** maak staat op berekeningskrag vir transaksieverifikasie.
- **Proof of Stake (PoS)** vereis dat validators 'n sekere hoeveelheid tokens hou, wat energieverbruik verminder in vergelyking met PoW.

## Bitcoin Essentials

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die private key oordragte kan inisieer.

#### Sleutelkomponente:

- **Multisignature Transactions** vereis veelvuldige handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inputs** (bron van fondse), **outputs** (bestemming), **fees** (betaal aan miners), en **scripts** (transaksiereëls).

### Lightning Network

Beoog om Bitcoin se skaalbaarheid te verbeter deur veelvuldige transaksies binne 'n kanaal toe te laat, en slegs die finale toestand na die blockchain uit te saai.

## Bitcoin-Privaatheidskwessies

Privaatheidsaanvalle, soos **Common Input Ownership** en **UTXO Change Address Detection**, misbruik transaksiepatrone. Strategieë soos **Mixers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen users te verdoesel.

## Bitcoin Anoniem Verkry

Metodes sluit kontanttransaksies, mining, en die gebruik van mixers in. **CoinJoin** meng veelvuldige transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verhoogde privaatheid.

# Bitcoin Privacy Atacks

# Opsomming van Bitcoin-Privaatheidsaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van users dikwels onderwerpe van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur attackers Bitcoin-privaatheid kan kompromitteer.

## **Common Input Ownership Assumption**

Dit is oor die algemeen skaars dat inputs van verskillende users in 'n enkele transaksie gekombineer word weens die kompleksiteit wat betrokke is. Daarom word **twee input-adresse in dieselfde transaksie dikwels aanvaar asof hulle aan dieselfde eienaar behoort**.

## **UTXO Change Address Detection**

'n UTXO, of **Unspent Transaction Output**, moet heeltemal in 'n transaksie bestee word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die oorblyfsel na 'n nuwe change address. Waarnemers kan aanvaar dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromitteer.

### Voorbeeld

Om dit te versag, kan mixing services of die gebruik van veelvuldige adresse help om eienaarskap te verdoesel.

## **Exposure deur Sosiale Netwerke & Forums**

Users deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaksiegrafiekanalise**

Transaksies kan as grafieke gevisualiseer word, wat moontlike verbindings tussen users onthul op grond van die vloei van fondse.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Hierdie heuristiek is gebaseer op die analise van transaksies met veelvuldige inputs en outputs om te raai watter output die change is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
As jy meer invoere byvoeg, maak dit die change-uitset groter as enige enkele invoer, en dit kan die heuristic verwar.

## **Forced Address Reuse**

Aanvallers kan klein bedrae stuur na voorheen gebruikte addresses, in die hoop dat die ontvanger dit met ander inputs in toekomstige transactions kombineer, en sodoende addresses aan mekaar koppel.

### Correct Wallet Behavior

Wallets moet vermy om coins te gebruik wat ontvang is op reeds gebruikte, leë addresses om hierdie privacy leak te voorkom.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions sonder change is waarskynlik tussen twee addresses wat deur dieselfde gebruiker besit word.
- **Round Numbers:** ’n Ronde getal in ’n transaction dui daarop dat dit ’n payment is, met die nie-ronde output waarskynlik as die change.
- **Wallet Fingerprinting:** Verskillende wallets het unieke transaction creation patterns, wat analysts toelaat om die software te identifiseer wat gebruik is en moontlik die change address.
- **Amount & Timing Correlations:** Die openbaarmaking van transaction times of bedrae kan transactions traceable maak.

## **Traffic Analysis**

Deur network traffic te monitor, kan attackers moontlik transactions of blocks koppel aan IP addresses, wat user privacy kompromitteer. Dit is veral waar as ’n entity baie Bitcoin nodes bedryf, wat hul vermoë om transactions te monitor versterk.

## More

Vir ’n omvattende lys van privacy attacks en defenses, besoek [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Verkry bitcoin deur kontant.
- **Cash Alternatives**: Koop gift cards en ruil dit aanlyn vir bitcoin.
- **Mining**: Die mees private metode om bitcoins te verdien is deur mining, veral wanneer dit alleen gedoen word omdat mining pools die miner se IP address kan ken. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoreties kan die steel van bitcoin nog ’n metode wees om dit anoniem te verkry, hoewel dit onwettig is en nie aanbeveel word nie.

## Mixing Services

Deur ’n mixing service te gebruik, kan ’n user **send bitcoins** en **different bitcoins in return** ontvang, wat dit moeilik maak om die oorspronklike owner te traceer. Tog vereis dit trust in die service om nie logs te hou nie en om werklik die bitcoins terug te stuur. Alternatiewe mixing opsies sluit Bitcoin casinos in.

## CoinJoin

**CoinJoin** merge multiple transactions from different users into one, wat die proses bemoeilik vir enigiemand wat probeer om inputs met outputs te match. Ten spyte van die doeltreffendheid daarvan, kan transactions met unieke input- en outputgroottes steeds moontlik traceer word.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguise the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit steeds ononderskeibaar bly van standaard bitcoin transaksies.

**Die gebruik van PayJoin kan tradisionele toesigmetodes aansienlik ontwrig**, wat dit ’n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.

# Best Practices vir Privaatheid in Cryptocurrencies

## **Wallet Synchronization Techniques**

Om privaatheid en sekuriteit te handhaaf, is die sinkronisering van wallets met die blockchain noodsaaklik. Twee metodes staan uit:

- **Full node**: Deur die hele blockchain af te laai, verseker ’n full node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Client-side block filtering**: Hierdie metode behels die skep van filters vir elke block in die blockchain, wat wallets in staat stel om relevante transaksies te identifiseer sonder om spesifieke belange aan netwerkwaarnemers bloot te stel. Liggewig wallets laai hierdie filters af, en haal slegs volledige blocks wanneer ’n passing met die gebruiker se adresse gevind word.

## **Utilizing Tor for Anonymity**

Aangesien Bitcoin op ’n peer-to-peer network werk, word die gebruik van Tor aanbeveel om jou IP address te masker, wat privaatheid verbeter wanneer jy met die network interaksie het.

## **Preventing Address Reuse**

Om privaatheid te beskerm, is dit noodsaaklik om ’n nuwe address vir elke transaksie te gebruik. Om addresses te hergebruik kan privaatheid kompromitteer deur transaksies aan dieselfde entiteit te koppel. Moderne wallets ontmoedig address hergebruik deur hul ontwerp.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Om ’n betaling in verskeie transaksies te verdeel kan die transaksiebedrag verberg en privaatheidsaanvalle verydel.
- **Change avoidance**: Om transaksies te kies wat nie change outputs vereis nie, verbeter privaatheid deur change detection metodes te ontwrig.
- **Multiple change outputs**: As die vermyding van change nie haalbaar is nie, kan die generering van verskeie change outputs steeds privaatheid verbeter.

# **Monero: A Beacon of Anonymity**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan, en stel ’n hoë standaard vir privaatheid.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas meet die rekenaarwerk wat nodig is om operasies op Ethereum uit te voer, geprys in **gwei**. Byvoorbeeld, ’n transaksie wat 2,310,000 gwei kos (of 0.00231 ETH) behels ’n gas limit en ’n base fee, met ’n tip om miners aan te spoor. Gebruikers kan ’n max fee stel om te verseker dat hulle nie te veel betaal nie, met die oorskot wat terugbetaal word.

## **Executing Transactions**

Transaksies in Ethereum behels ’n sender en ’n ontvanger, wat óf user- óf smart contract addresses kan wees. Hulle vereis ’n fooi en moet gemined word. Essensiële inligting in ’n transaksie sluit die ontvanger, sender se signature, value, opsionele data, gas limit, en fooie in. Belangrik: die sender se address word uit die signature afgelei, wat die behoefte daaraan in die transaksiedata uitskakel.

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat met cryptocurrencies wil werk terwyl privaatheid en sekuriteit geprioritiseer word.

## Value-Centric Web3 Red Teaming

- Maak ’n inventaris van value-bearing components (signers, oracles, bridges, automation) om te verstaan wie fondse kan skuif en hoe.
- Koppel elke komponent aan relevante MITRE AADAPT taktieke om privilege escalation paths bloot te lê.
- Oefen flash-loan/oracle/credential/cross-chain aanvalskettings om impak te valideer en uitbuitbare voorwaardes te dokumenteer.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering van wallet UIs kan EIP-712 payloads net voor signing verander, en geldige signatures oes vir delegatecall-gebaseerde proxy takeovers (bv. slot-0 overwrite van Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Algemene smart-account failure modes sluit in omseiling van `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, en fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing om blind spots in toetsuites te vind:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Wanneer ’n prover ’n **zkVM** of ’n toepassingspesifieke proof circuit gebruik om ’n claim te attesteer, leer die verifier slegs dat die **guest program uitgevoer is soos geskryf**. As die guest **unsafe deserialization**, **undefined behavior**, of **missing semantic constraints** bevat, kan ’n kwaadwillige prover ’n proof genereer wat verifieer, terwyl die **public metrics of beweerde invariant vals is**.

### Unsafe deserialization inside proof guests

- Behandel private witness/circuit bytes as **untrusted attacker input** selfs al word hulle deur die proof versteek.
- Vermy deserialisering daarvan met ongekontroleerde helpers soos `rkyv::access_unchecked` tensy die bytes reeds buite-band gevalideer is.
- Enum discriminants, relative pointers, lengths, en indexes wat uit onbetroubare geserialiseerde data gelaai word, moet gevalideer word voordat hulle control flow of memory access beïnvloed.

Praktiese ouditpatroon:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
As `op.kind` ’n veld soos `op.kind` ’n enum is en ’n aanvaller ’n **buite-reeks diskriminant** kan inspuit, word elke downstream `match` op daardie waarde verdag.

### Jump-table / UB counter bypass

As Rust ’n groot `match` na ’n **jump table** verlaag, kan ’n ongeldige enum-diskriminant **undefined control flow** veroorsaak. ’n Gevaarlike patroon is:

1. Een `match` werk **veiligheidskritieke tellers/constraints** by.
2. ’n Tweede `match` voer die **werklike instruction semantics** uit.
3. ’n Diskriminant buite reeks indekseer verby die eerste jump table en beland in code wat met die tweede een geassosieer is.

Gevolg: die operation voer steeds uit, maar die accounting path word oorgeslaan. In ’n zkVM kan dit proofs vervals wat onmoontlike metrics rapporteer soos minder gates, minder duur operations, of ander vervalste bounded resources.

Review checklist:

- Soek vir aanvaller-beheerde enums wat uit witness/private input gedeserialiseer word.
- Inspekteer herhaalde `match` statements oor dieselfde opcode/kind-veld.
- Behandel `unsafe` + unchecked deserialization + groot opcode dispatch as ’n hoërisiko-kombinasie.
- Reverse engineer die uitgesette binary wanneer nodig; jump-table layout kan belangriker as die source wees.

### Missing semantic constraints in reversible/specialized interpreters

Moenie net memory safety valideer nie; valideer ook die **semantic rules** wat die proof bedoel is om af te dwing.

Vir reversible/quantum-like instruction sets, maak seker operands wat verskillend moet wees, word werklik as verskillend constrained. ’n Toffoli/CCX-agtige operation geïmplementeer as:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
word onveilig as die gas nie verwerp nie:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In daardie geval stort die oorgang in tot:
```text
q = q ^ (q & q) = 0
```
Dit skep ’n **deterministic reset primitive**, breek omkeerbaarheidsaannames en maak goedkoper nie-bedoelde berekenings moontlik. In proof systems wat hulpbrongebruik attesteer, kan dit aanvallers toelaat om funksionele kontroles te slaag terwyl hulle die kostemodel wat die verifier glo afgedwing word, omseil.

### Wat om te toets in ZK systems

- Fuzz alle guest parsers met malformed witness/private-input encodings.
- Stel enum range validation vas voor opcode dispatch.
- Voeg semantiese kontroles by vir operand aliasing en ander ongeldige instruction forms.
- Vergelyk gerapporteerde/public counters met ’n onafhanklike reference implementation.
- Onthou dat ’n geldige proof steeds die **verkeerde statement** kan bewys as die guest program buggy is.

## DeFi/AMM Exploitation

As jy praktiese exploitation van DEXes en AMMs ondersoek (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), kyk na:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Vir multi-asset weighted pools wat virtual balances cache en vergiftig kan word wanneer `supply == 0`, bestudeer:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
