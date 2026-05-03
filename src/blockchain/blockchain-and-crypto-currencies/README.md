# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und die Ausführung von Vereinbarungen ohne Vermittler automatisieren.
- **Decentralized Applications (dApps)** bauen auf smart contracts auf und verfügen über ein benutzerfreundliches Front-End sowie ein transparentes, prüfbares Back-End.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten Wert oder Besitz repräsentieren.
- **Utility Tokens** gewähren Zugriff auf Dienste, und **Security Tokens** signalisieren Besitz an Assets.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Autoritäten.
- **DEX** und **DAOs** beziehen sich auf Decentralized Exchange Platforms bzw. Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und abgestimmte Transaktionsvalidierungen auf der blockchain:

- **Proof of Work (PoW)** basiert auf Rechenleistung zur Verifizierung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert den Energieverbrauch im Vergleich zu PoW.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Geldern zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des private key Überweisungen initiieren kann.

#### Schlüsselkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **inputs** (Quelle der Gelder), **outputs** (Ziel), **fees** (an miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden und nur der finale Zustand an die blockchain übertragen wird.

## Bitcoin-Datenschutzbedenken

Privacy-Angriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie die Transaktionsverbindungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Zu den Methoden gehören Bartransaktionen, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Nachverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt, um die Privacy zu erhöhen.

# Bitcoin Privacy Atacks

# Zusammenfassung der Bitcoin Privacy Attacks

In der Welt von Bitcoin sind die Privacy von Transaktionen und die Anonymität der Nutzer oft Anlass zur Sorge. Hier ist ein vereinfachter Überblick über mehrere gängige Methoden, mit denen Angreifer die Bitcoin-Privacy kompromittieren können.

## **Common Input Ownership Assumption**

Es ist im Allgemeinen selten, dass inputs verschiedener Nutzer in einer einzigen Transaktion kombiniert werden, aufgrund der damit verbundenen Komplexität. Daher wird oft angenommen, dass **zwei input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, oder **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue change address. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, was die Privacy beeinträchtigt.

### Example

Um dies zu mindern, können Mixing-Dienste oder die Verwendung mehrerer Adressen helfen, den Besitz zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **leicht ist, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden und potenzielle Verbindungen zwischen Nutzern auf Basis des Geldflusses offenlegen.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren inputs und outputs, um zu erraten, welcher output das an den Absender zurückgehende change ist.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs den Wechsel-Output größer macht als irgendeinen einzelnen Input, kann das die Heuristik verwirren.

## **Forced Address Reuse**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese mit anderen Inputs in zukünftigen Transaktionen kombiniert und so Adressen miteinander verknüpft.

### Correct Wallet Behavior

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits genutzten, leeren Adressen empfangen wurden, um diesen Privacy leak zu verhindern.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaktionen ohne Wechsel sind wahrscheinlich zwischen zwei Adressen desselben Users.
- **Round Numbers:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei der nicht-runde Output wahrscheinlich der Wechsel ist.
- **Wallet Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, wodurch Analysten die verwendete Software und möglicherweise die Wechseladresse identifizieren können.
- **Amount & Timing Correlations:** Das Offenlegen von Transaktionszeiten oder -beträgen kann Transaktionen nachvollziehbar machen.

## **Traffic Analysis**

Durch das Überwachen des Netzwerkverkehrs können Angreifer potenziell Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der User gefährden. Dies gilt besonders, wenn eine Entität viele Bitcoin-Nodes betreibt, da dies ihre Fähigkeit zur Überwachung von Transaktionen verbessert.

## More

Für eine umfassende Liste von Privacy-Angriffen und Defenses siehe [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Erwerb von Bitcoin durch Bargeld.
- **Cash Alternatives**: Kauf von Geschenkkarten und anschließender Online-Tausch gegen Bitcoin.
- **Mining**: Die privateste Methode, Bitcoin zu verdienen, ist durch Mining, besonders wenn man allein mined, da Mining-Pools die IP-Adresse des Miners kennen könnten. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretisch könnte das Stehlen von Bitcoin eine weitere Methode sein, um sie anonym zu erwerben, obwohl das illegal und nicht empfohlen ist.

## Mixing Services

Durch die Nutzung eines Mixing service kann ein User **Bitcoins senden** und **andere Bitcoins im Gegenzug erhalten**, was das Nachverfolgen des ursprünglichen Owners erschwert. Dafür muss man dem Service jedoch vertrauen, dass er keine Logs speichert und die Bitcoins tatsächlich zurücksendet. Alternative Mixing-Optionen umfassen Bitcoin casinos.

## CoinJoin

**CoinJoin** kombiniert mehrere Transaktionen von verschiedenen Users zu einer einzigen, was den Prozess für jeden erschwert, der Inputs mit Outputs abgleichen will. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen dennoch potenziell zurückverfolgt werden.

Beispieltransaktionen, die möglicherweise CoinJoin verwendet haben, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Für weitere Informationen siehe [CoinJoin](https://coinjoin.io/en). Für einen ähnlichen Service auf Ethereum siehe [Tornado Cash](https://tornado.cash), das Transaktionen mit Geldern von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als normale Transaktion, ohne die charakteristischen gleich großen Outputs von CoinJoin. Dadurch ist sie extrem schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik ungültig machen, die von Transaction Surveillance Entities verwendet wird.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben könnten PayJoin sein und die Privatsphäre verbessern, während sie nicht von standard bitcoin transactions zu unterscheiden bleiben.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich stören**, was ihn zu einer vielversprechenden Entwicklung im Streben nach Transaktionsprivatsphäre macht.

# Best Practices für Privatsphäre in Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu wahren, ist das Synchronisieren von wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain sorgt ein full node für maximale Privatsphäre. Alle jemals durchgeführten Transaktionen werden lokal gespeichert, wodurch es Angreifern unmöglich wird zu erkennen, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Client-side block filtering**: Diese Methode umfasst das Erstellen von Filtern für jeden Block in der Blockchain, sodass wallets relevante Transaktionen identifizieren können, ohne spezifische Interessen gegenüber Netzwerkbeobachtern offenzulegen. Leichte wallets laden diese Filter herunter und holen nur dann vollständige Blöcke, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird die Nutzung von Tor empfohlen, um deine IP-Adresse zu maskieren und die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Verhindern von Address Reuse**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne wallets raten von Address Reuse durch ihr Design ab.

## **Strategien für Transaktionsprivatsphäre**

- **Multiple transactions**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Privacy-Angriffe erschweren.
- **Change avoidance**: Die Wahl von Transaktionen, die keine Change-Outputs erfordern, erhöht die Privatsphäre, indem Methoden zur Erkennung von Change gestört werden.
- **Multiple change outputs**: Wenn es nicht möglich ist, Change zu vermeiden, können mehrere Change-Outputs dennoch die Privatsphäre verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero adressiert das Bedürfnis nach absoluter Anonymität bei digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der zur Ausführung von Operationen auf Ethereum benötigt wird, bepreist in **gwei**. Eine Transaktion mit Kosten von 2,310,000 gwei (oder 0.00231 ETH) umfasst zum Beispiel ein Gas-Limit und eine Base Fee, sowie ein Tip, um Miner zu incentivieren. Nutzer können eine Max Fee festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen; der Überschuss wird erstattet.

## **Transaktionen ausführen**

Transaktionen in Ethereum umfassen einen Sender und einen Empfänger, die entweder Nutzer- oder smart contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, sodass sie in den Transaktionsdaten nicht enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für alle, die sich mit Kryptowährungen befassen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Inventarisiere werttragende Komponenten (signers, oracles, bridges, automation), um zu verstehen, wer Mittel bewegen kann und wie.
- Mappe jede Komponente auf relevante MITRE AADAPT tactics, um Privilegieneskalationspfade offenzulegen.
- Übe flash-loan/oracle/credential/cross-chain attack chains, um den Impact zu validieren und ausnutzbare Vorbedingungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering von wallet UIs kann EIP-712 Payloads direkt vor dem Signieren verändern und gültige Signaturen für delegatecall-basierte Proxy-Übernahmen ernten (z. B. slot-0 overwrite von Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige smart-account failure modes umfassen das Umgehen von `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay und fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing, um blinde Flecken in Test-Suiten zu finden:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen proof circuit verwendet, um eine Behauptung zu belegen, lernt der Verifier nur, dass das **guest program wie geschrieben ausgeführt wurde**. Wenn der guest **unsafe deserialization**, **undefined behavior** oder **missing semantic constraints** enthält, kann ein bösartiger Prover einen proof erzeugen, der verifiziert wird, während die **public metrics oder die behauptete invariant falsch** sind.

### Unsafe deserialization innerhalb von proof guests

- Behandle private witness/circuit bytes als **nicht vertrauenswürdige attacker input**, auch wenn sie durch den proof verborgen sind.
- Vermeide das Deserialisieren mit ungeprüften Helfern wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits out-of-band validiert wurden.
- Enum discriminants, relative pointers, lengths und indexes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder den Speicherzugriff beeinflussen.

Praktisches Audit-Muster:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Wenn ein Feld wie `op.kind` ein enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachfolgende `match` auf diesem Wert verdächtig.

### Jump-table / UB counter bypass

Wenn Rust ein großes `match` in eine **jump table** umsetzt, kann ein ungültiger enum discriminant **undefined control flow** erzeugen. Ein gefährliches Muster ist:

1. Ein `match` aktualisiert **security-critical counters/constraints**.
2. Ein zweites `match` führt die **eigentliche instruction semantics** aus.
3. Ein out-of-range discriminant indexiert hinter die erste jump table hinaus und landet in Code, der mit der zweiten verknüpft ist.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Accounting-Pfad wird übersprungen. In einer zkVM kann das Proofs fälschen, die unmögliche Metriken melden, etwa weniger gates, weniger teure Operationen oder andere falsifizierte begrenzte Ressourcen.

Review-Checklist:

- Suche nach attacker-controlled enums, die aus witness/private input deserialisiert werden.
- Prüfe wiederholte `match`-Anweisungen über dasselbe opcode/kind-Feld.
- Betrachte `unsafe` + unchecked deserialization + große opcode dispatches als Hochrisiko-Kombination.
- Reverse-engineere bei Bedarf das erzeugte Binary; das jump-table layout kann wichtiger sein als der Source.

### Fehlende semantische Constraints in reversiblen/spezialisierten Interpretern

Validiere nicht nur die memory safety; validiere auch die **semantischen Regeln**, die der proof erzwingen soll.

Für reversible/quantum-like instruction sets stelle sicher, dass Operanden, die verschieden sein müssen, tatsächlich auf verschieden constrained werden. Eine Toffoli/CCX-like operation implementiert als:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
wird unsicher, wenn der Gast nicht ablehnt:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In diesem Fall kollabiert der Übergang zu:
```text
q = q ^ (q & q) = 0
```
This creates a **deterministic reset primitive**, bricht Annahmen über die Reversibilität und ermöglicht billigere, nicht beabsichtigte Berechnungen. In Proof systems, die Ressourcennutzung attestieren, kann dies Angreifern erlauben, funktionale Checks zu erfüllen und dabei das Cost model zu umgehen, von dem der Verifier glaubt, dass es durchgesetzt wird.

### Was in ZK systems zu testen ist

- Fuzz alle guest parser mit fehlerhaften witness/private-input Encodings.
- Prüfe Enum-Bereichsvalidierung vor dem Opcode dispatch.
- Füge semantische Checks für operand aliasing und andere ungültige instruction forms hinzu.
- Vergleiche gemeldete/public counters mit einer unabhängigen reference implementation.
- Denke daran, dass ein gültiger proof trotzdem die **falsche Aussage** beweisen kann, wenn das guest program fehlerhaft ist.

## DeFi/AMM Exploitation

Wenn du praktische Exploitation von DEXes und AMMs untersuchst (Uniswap v4 hooks, rounding/precision abuse, flash‑loan verstärkte threshold‑crossing swaps), schau dir an:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset weighted pools, die virtual balances cachen und vergiftet werden können, wenn `supply == 0`, studiere:

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
