# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und so die Ausführung von Vereinbarungen ohne Vermittler automatisieren.
- **Dezentrale Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Front-End sowie ein transparentes, überprüfbares Back-End.
- **Tokens & Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
- **Utility Tokens** gewähren Zugriff auf Dienste, und **Security Tokens** kennzeichnen den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Autoritäten.
- **DEX** und **DAOs** stehen für Decentralized Exchange Platforms beziehungsweise Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** beruht bei der Transaktionsüberprüfung auf Rechenleistung.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, wodurch der Energieverbrauch im Vergleich zu PoW gesenkt wird.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Guthaben zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, sodass nur der Besitzer des privaten Schlüssels Übertragungen initiieren kann.<sup>[[2]](#references)</sup>

#### Schlüsselkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen zur Autorisierung einer Transaktion.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **inputs** (Quelle der Guthaben), **outputs** (Ziel), **fees** (an Miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden und nur der endgültige Zustand an die Blockchain übertragen wird.

## Datenschutzbedenken bei Bitcoin

Privacy attacks wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Benutzern verschleiern.

## Anonymes Erwerben von Bitcoins

Zu den Methoden gehören Bargeschäfte, Mining und die Verwendung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Nachverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt und so für mehr Datenschutz sorgt.

# Datenschutzangriffe auf Bitcoin

# Zusammenfassung der Datenschutzangriffe auf Bitcoin

In der Welt von Bitcoin sind der Datenschutz von Transaktionen und die Anonymität der Benutzer häufige Anliegen. Hier ist eine vereinfachte Übersicht über mehrere verbreitete Methoden, mit denen Angreifer den Bitcoin-Datenschutz gefährden können.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Es ist aufgrund der damit verbundenen Komplexität allgemein selten, dass Inputs verschiedener Benutzer in einer einzigen Transaktion kombiniert werden. Daher wird häufig angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO oder **Unspent Transaction Output** muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch der Datenschutz beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder die Verwendung mehrerer Adressen dabei helfen, den Besitz zu verschleiern.

## **Social Networks & Forums Exposure**

Benutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden und dadurch potenzielle Verbindungen zwischen Benutzern auf Grundlage des Geldflusses offenlegen.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu vermuten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs dazu führt, dass der Change-Output größer als jeder einzelne Input ist, kann dies die Heuristik verwirren.

## **Erzwungene Adresswiederverwendung**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits verwendeten, leeren Adressen empfangen wurden, um diesen privacy leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Change finden wahrscheinlich zwischen zwei Adressen statt, die demselben Benutzer gehören.
- **Runde Zahlen:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei der nicht-runde Output wahrscheinlich der Change ist.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Transaktionserstellung auf. Dadurch können Analysten die verwendete Software und möglicherweise die Change-Adresse identifizieren.
- **Korrelationen von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder Beträgen kann Transaktionen rückverfolgbar machen.

## **Traffic Analysis**

Durch die Überwachung des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke möglicherweise mit IP-Adressen verknüpfen und dadurch die Privatsphäre der Benutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Fähigkeit zur Überwachung von Transaktionen verbessert wird.

## Mehr

Eine umfassende Liste von privacy attacks und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen:** Bitcoin gegen Bargeld erwerben.
- **Bargeldalternativen:** Geschenkkarten kaufen und diese online gegen Bitcoin eintauschen.
- **Mining:** Die privateste Methode, Bitcoins zu verdienen, ist Mining, insbesondere wenn es allein durchgeführt wird, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl:** Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, Bitcoin anonym zu erwerben, obwohl dies illegal und nicht empfehlenswert ist.

## Mixing Services

Durch die Nutzung eines Mixing Service kann ein Benutzer **Bitcoins senden** und **andere Bitcoins im Gegenzug erhalten**, wodurch die Rückverfolgung des ursprünglichen Besitzers erschwert wird. Dies erfordert jedoch Vertrauen in den Service, dass er keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Optionen gehören Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Benutzer zu einer einzigen zusammen und erschwert dadurch den Versuch, Inputs den Outputs zuzuordnen. Trotz seiner Effektivität können Transaktionen mit einzigartigen Input- und Output-Größen möglicherweise weiterhin zurückverfolgt werden.

Beispieltransaktionen, bei denen CoinJoin verwendet worden sein könnte, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen ähnlichen Service für Ethereum findest du unter [Tornado Cash](https://tornado.cash), der Transaktionen mit Geldern von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die charakteristischen gleichen Outputs von CoinJoin. Dadurch ist sie äußerst schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik ungültig machen, die von Organisationen zur Transaktionsüberwachung verwendet wird.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die obige könnten PayJoin sein, wodurch die Privatsphäre verbessert wird und sie dennoch nicht von standardmäßigen Bitcoin-Transaktionen zu unterscheiden sind.

**Die Nutzung von PayJoin könnte traditionelle Überwachungsmethoden erheblich beeinträchtigen** und stellt damit eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre dar.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Privatsphäre und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet eine Full node maximale Privatsphäre. Alle jemals durchgeführten Transaktionen werden lokal gespeichert, wodurch es Angreifern unmöglich wird, zu erkennen, für welche Transaktionen oder Adressen sich der Benutzer interessiert.
- **Client-side block filtering**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt, sodass Wallets relevante Transaktionen identifizieren können, ohne bestimmte Interessen gegenüber Netzwerkbeobachtern offenzulegen. Lightweight-Wallets laden diese Filter herunter und rufen vollständige Blöcke nur ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird die Verwendung von Tor empfohlen, um die IP-Adresse zu verschleiern und die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Verhindern der Wiederverwendung von Adressen**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre beeinträchtigen, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets wirken der Wiederverwendung von Adressen durch ihr Design entgegen.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Privacy-Angriffe vereiteln.
- **Vermeidung von Wechselgeld**: Die Wahl von Transaktionen, die keine Wechselgeld-Outputs erfordern, verbessert die Privatsphäre, indem Methoden zur Erkennung von Wechselgeld gestört werden.
- **Mehrere Wechselgeld-Outputs**: Wenn die Vermeidung von Wechselgeld nicht möglich ist, kann die Erstellung mehrerer Wechselgeld-Outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero adressiert den Bedarf an absoluter Anonymität bei digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den für die Ausführung von Operationen auf Ethereum erforderlichen Rechenaufwand und wird in **gwei** angegeben. Beispielsweise umfasst eine Transaktion mit Kosten von 2.310.000 gwei (oder 0,00231 ETH) ein Gas-Limit und eine Base Fee sowie ein Trinkgeld zur Incentivierung von Minern. Benutzer können eine maximale Gebühr festlegen, um eine Überzahlung zu vermeiden; der überschüssige Betrag wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Ausführen von Transaktionen**

Transaktionen in Ethereum umfassen einen Sender und einen Empfänger, bei denen es sich entweder um Benutzer- oder Smart-Contract-Adressen handeln kann. Sie erfordern eine Gebühr und müssen gemined werden. Zu den wesentlichen Informationen einer Transaktion gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, wodurch sie in den Transaktionsdaten nicht erforderlich ist.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden eine Grundlage für alle, die sich mit Kryptowährungen beschäftigen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Wertehaltige Komponenten (Signer, Oracles, Bridges, Automatisierung) inventarisieren, um zu verstehen, wer Gelder bewegen kann und wie.
- Jede Komponente den relevanten MITRE-AADAPT-Taktiken zuordnen, um Wege zur Privilege Escalation aufzudecken.
- Flash-Loan-/Oracle-/Credential-/Cross-Chain-Angriffsketten proben, um die Auswirkungen zu validieren und ausnutzbare Vorbedingungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signing-Workflows

- Supply-Chain-Tampering von Wallet-UIs kann EIP-712-Payloads unmittelbar vor dem Signieren verändern und gültige Signaturen für Delegatecall-basierte Proxy-Übernahmen abgreifen (z. B. das Überschreiben von Slot 0 von Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige Fehlerzustände von Smart Accounts umfassen das Umgehen der `EntryPoint`-Zugriffskontrolle, nicht signierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und das Abschöpfen von Gebühren durch Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Auffinden von Blindspots in Testsuites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Gästen

Wenn ein Prover eine **zkVM** oder eine anwendungsspezifische Proof-Schaltung verwendet, um eine Behauptung zu attestieren, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Wenn der Guest **unsichere Deserialisierung**, **Undefined Behavior** oder **fehlende semantische Constraints** enthält, kann ein böswilliger Prover einen Proof erzeugen, der verifiziert wird, während die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Gästen

- Private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingaben** behandeln, selbst wenn sie durch den Proof verborgen sind.
- Ihre Deserialisierung mit ungeprüften Helfern wie `rkyv::access_unchecked` vermeiden, sofern die Bytes nicht bereits out-of-band validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und aus nicht vertrauenswürdigen serialisierten Daten geladene Indizes müssen validiert werden, bevor sie den Control Flow oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Wenn ein Feld wie `op.kind` ein enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jeder nachgelagerte `match` über diesen Wert verdächtig.

### Jump-table / UB counter bypass

Wenn Rust einen umfangreichen `match` in eine **jump table** umwandelt, kann ein ungültiger enum discriminant zu **undefined control flow** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Constraints**.
2. Ein zweiter `match` führt die **eigentliche Instruction-Semantik** aus.
3. Ein out-of-range discriminant indiziert hinter die erste jump table und landet in Code, der mit der zweiten verknüpft ist.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Accounting-Pfad wird übersprungen. In einer zkVM kann dies Proofs fälschen, die unmögliche Metriken melden, etwa weniger Gates, weniger aufwendige Operationen oder andere verfälschte begrenzte Ressourcen.

Review-Checkliste:

- Suche nach attacker-controlled enums, die aus witness/private input deserialisiert werden.
- Untersuche wiederholte `match`-Statements über dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + unchecked deserialization + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf das emittierte Binary; das Layout der jump tables kann wichtiger sein als der Sourcecode.

### Fehlende semantische Constraints in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Memory-Sicherheit, sondern auch die **semantischen Regeln**, deren Durchsetzung der Proof gewährleisten soll.

Bei reversiblen/quantum-artigen Instruction-Sets muss sichergestellt sein, dass Operanden, die distinct sein müssen, tatsächlich durch Constraints als distinct festgelegt sind. Eine Toffoli-/CCX-ähnliche Operation, die wie folgt implementiert ist:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
wird unsicher, wenn der Gast nicht ablehnt:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In diesem Fall reduziert sich der Übergang auf:
```text
q = q ^ (q & q) = 0
```
Das erzeugt ein **deterministisches Reset-Primitiv**, bricht Annahmen zur Reversibilität und ermöglicht kostengünstigere nicht beabsichtigte Berechnungen. In Beweissystemen, die den Ressourcenverbrauch attestieren, kann dies Angreifern erlauben, funktionale Prüfungen zu erfüllen und gleichzeitig das Kostenmodell zu umgehen, dessen Durchsetzung der Verifier annimmt.

### Was in ZK-Systemen getestet werden sollte

- Fuzze alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen.
- Stelle die Validierung des Enum-Bereichs vor dem Opcode Dispatch sicher.
- Füge semantische Prüfungen für Operand-Aliasing und andere ungültige Instruction-Formen hinzu.
- Vergleiche gemeldete/öffentliche Counter mit einer unabhängigen Referenzimplementierung.
- Denke daran, dass ein gültiger Proof trotzdem die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## DeFi/AMM-Exploitation

Wenn du die praktische Ausnutzung von DEXes und AMMs (Uniswap v4 Hooks, Ausnutzung von Rundungs-/Präzisionsfehlern, durch Flash-Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) untersuchst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset-Weighted-Pools, die virtuelle Salden cachen und vergiftet werden können, wenn `supply == 0`, siehe:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Referenzen

- [1] [Proof of Stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key und Private Key erklärt - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signature-Transaktionen? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Wir haben Googles Zero-Knowledge-Proof der Quantenkryptanalyse gebrochen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Schutz elliptischer-Kurven-Kryptowährungen vor Quanten-Schwachstellen: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail-of-Bits-Proof-of-Concept-Repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
