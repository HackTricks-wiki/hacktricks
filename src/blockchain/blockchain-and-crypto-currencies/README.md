# Blockchain und Kryptowährungen

## Grundlegende Konzepte

- **Smart Contracts** sind als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und die Ausführung von Vereinbarungen ohne Vermittler automatisieren.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Front-end sowie ein transparentes, überprüfbares Back-end.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
- **Utility Tokens** gewähren Zugriff auf Dienste, während **Security Tokens** den Besitz von Vermögenswerten anzeigen.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** bezeichnen jeweils Decentralized Exchange Platforms und Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und gemeinsam bestätigte Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** stützt sich bei der Transaktionsüberprüfung auf Rechenleistung.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, wodurch der Energieverbrauch im Vergleich zu PoW reduziert wird.<sup>[[1]](#references)</sup>

## Grundlagen von Bitcoin

### Transaktionen

Bitcoin-Transaktionen umfassen die Übertragung von Guthaben zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des privaten Schlüssels Übertragungen initiieren kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **inputs** (Quelle der Mittel), **outputs** (Ziel), **fees** (an Miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht und nur der endgültige Zustand an die Blockchain übertragen wird.

## Datenschutzbedenken bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Benutzern verschleiern.

## Anonymes Erwerben von Bitcoins

Zu den Methoden gehören Bargeldgeschäfte, Mining und die Verwendung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Nachverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt und so den Datenschutz erhöht.

# Zusammenfassung der Bitcoin-Datenschutzangriffe

In der Welt von Bitcoin sind der Datenschutz von Transaktionen und die Anonymität der Benutzer häufige Anliegen. Hier ist eine vereinfachte Übersicht über mehrere gängige Methoden, durch die Angreifer den Bitcoin-Datenschutz beeinträchtigen können.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Es ist aufgrund der damit verbundenen Komplexität im Allgemeinen selten, dass Inputs verschiedener Benutzer in einer einzelnen Transaktion kombiniert werden. Daher wird häufig angenommen, dass **zwei input addresses in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO oder **Unspent Transaction Output** muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue change address. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch der Datenschutz beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder die Verwendung mehrerer Adressen dazu beitragen, den Besitz zu verschleiern.

## **Social Networks & Forums Exposure**

Benutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden und potenzielle Verbindungen zwischen Benutzern auf Grundlage des Geldflusses offenlegen.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückfließende Wechselgeld ist.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs dazu führt, dass der Change-Output größer ist als jeder einzelne Input, kann dies die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die an bereits verwendete, leere Adressen empfangen wurden, um diesen Privacy leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld erfolgen wahrscheinlich zwischen zwei Adressen, die demselben Benutzer gehören.
- **Runde Zahlen:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt; der nicht-runde Output ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software identifizieren und möglicherweise die Wechselgeldadresse bestimmen.
- **Korrelationen von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann dazu führen, dass Transaktionen nachverfolgt werden können.

## **Traffic Analysis**

Durch die Überwachung des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke potenziell mit IP-Adressen verknüpfen und dadurch die Privatsphäre der Benutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Fähigkeit zur Überwachung von Transaktionen verbessert wird.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin gegen Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und diese online gegen Bitcoin eintauschen.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist Mining, insbesondere wenn es allein durchgeführt wird, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Methode sein, diesen anonym zu erwerben, obwohl dies illegal und nicht empfehlenswert ist.

## Mixing Services

Bei der Verwendung eines Mixing Service kann ein Benutzer **Bitcoins senden** und dafür **andere Bitcoins zurückerhalten**, wodurch die Rückverfolgung des ursprünglichen Besitzers erschwert wird. Dies erfordert jedoch Vertrauen darin, dass der Service keine Logs aufbewahrt und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Optionen gehören Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Benutzer zu einer einzigen zusammen, wodurch der Vorgang für jeden erschwert wird, der versucht, Inputs mit Outputs abzugleichen. Trotz seiner Effektivität können Transaktionen mit einzigartigen Input- und Output-Größen potenziell weiterhin zurückverfolgt werden.

Beispieltransaktionen, bei denen möglicherweise CoinJoin verwendet wurde, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien, beispielsweise einem Kunden und einem Händler, als reguläre Transaktion, ohne das charakteristische Merkmal gleicher Outputs von CoinJoin. Dadurch ist sie äußerst schwer zu erkennen und könnte die von Überwachungsentitäten für Transaktionen verwendete Heuristik des gemeinsamen Input-Eigentums außer Kraft setzen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben genannten könnten PayJoin sein, wodurch die Privatsphäre verbessert wird, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und stellt damit eine vielversprechende Entwicklung im Streben nach transaktionaler Privatsphäre dar.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Privatsphäre und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet eine Full node maximale Privatsphäre. Alle jemals durchgeführten Transaktionen werden lokal gespeichert, wodurch es Angreifern unmöglich gemacht wird, zu erkennen, für welche Transaktionen oder Adressen sich der Benutzer interessiert.
- **Client-side block filtering**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt, sodass Wallets relevante Transaktionen erkennen können, ohne bestimmte Interessen gegenüber Netzwerkbeobachtern offenzulegen. Lightweight-Wallets laden diese Filter herunter und rufen vollständige Blöcke nur ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird die Nutzung von Tor empfohlen, um die IP-Adresse zu verbergen und dadurch die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Vermeidung der Wiederverwendung von Adressen**

Zum Schutz der Privatsphäre ist es entscheidend, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Das Aufteilen einer Zahlung auf mehrere Transaktionen kann den Transaktionsbetrag verschleiern und dadurch Privacy-Angriffe vereiteln.
- **Vermeidung von Wechselgeld**: Die Auswahl von Transaktionen, die keine Wechselgeld-Outputs erfordern, verbessert die Privatsphäre, indem Methoden zur Erkennung von Wechselgeld gestört werden.
- **Mehrere Wechselgeld-Outputs**: Wenn sich Wechselgeld nicht vermeiden lässt, kann die Erzeugung mehrerer Wechselgeld-Outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero wurde entwickelt, um die Privatsphäre von Transaktionen zu priorisieren.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der zur Ausführung von Operationen auf Ethereum erforderlich ist, und wird in **gwei** angegeben. Beispielsweise umfasst eine Transaktion mit Kosten von 2.310.000 gwei (oder 0,00231 ETH) ein Gas-Limit und eine Basisgebühr sowie eine Prioritätsgebühr, um die Aufnahme durch einen Validator zu fördern. Benutzer können eine maximale Gebühr festlegen, um eine Überzahlung zu vermeiden; der Überschuss wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Ausführen von Transaktionen**

Transaktionen in Ethereum umfassen einen Sender und einen Empfänger, bei denen es sich entweder um Benutzer- oder Smart-Contract-Adressen handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Informationen einer Transaktion gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, sodass sie nicht in den Transaktionsdaten enthalten sein muss.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden eine grundlegende Grundlage für alle, die sich mit Kryptowährungen beschäftigen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Bestandsaufnahme der werttragenden Komponenten (Signierer, Oracles, Bridges, Automatisierung), um zu verstehen, wer Gelder bewegen kann und auf welche Weise.
- Zuordnung jeder Komponente zu relevanten MITRE-AADAPT-Taktiken, um Wege zur Privilege Escalation offenzulegen.
- Einübung von Flash-Loan-/Oracle-/Credential-/Cross-Chain-Angriffsketten, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signing-Workflows

- Supply-Chain-Manipulationen an Wallet-UIs können EIP-712-Payloads unmittelbar vor dem Signieren verändern und gültige Signaturen für Delegatecall-basierte Proxy-Übernahmen abgreifen (z. B. das Überschreiben von Slot 0 von Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Zu den häufigen Fehlerzuständen von Smart Accounts gehören das Umgehen der Zugriffskontrolle von `EntryPoint`, nicht signierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und das Abschöpfen von Gebühren durch Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Auffinden von Blindspots in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK-Proof-/zkVM-Guest-Integrität

Wenn ein Prover eine **zkVM** oder eine anwendungsspezifische Proof-Schaltung verwendet, um eine Behauptung zu attestieren, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Wenn der Guest **unsichere Deserialisierung**, **Undefined Behavior** oder **fehlende semantische Constraints** enthält, kann ein böswilliger Prover einen Proof erzeugen, der verifiziert wird, während die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Guests

- Behandle private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifer-Eingaben**, selbst wenn sie durch den Proof verborgen sind.
- Vermeide die Deserialisierung mit ungeprüften Helpern wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits außerhalb dieses Kontexts validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder den Speicherzugriff beeinflussen.

Praktisches Audit-Muster:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Wenn ein Feld wie `op.kind` ein enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` über diesen Wert verdächtig.

### Umgehung von Zählern durch Jump-table / UB

Wenn Rust ein großes `match` in eine **jump table** umwandelt, kann ein ungültiger enum discriminant zu **undefined control flow** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Semantik der Instruktion** aus.
3. Ein out-of-range discriminant indexiert hinter die erste jump table und landet in Code, der mit der zweiten verknüpft ist.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies Beweise fälschen, die unmögliche Metriken melden, etwa weniger Gates, weniger teure Operationen oder andere verfälschte begrenzte Ressourcen.

Checkliste für das Review:

- Suche nach vom Angreifer kontrollierten enums, die aus witness/private input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen über dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + unchecked deserialization + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der jump table kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Memory-Sicherheit, sondern auch die **semantischen Regeln**, deren Durchsetzung der Beweis gewährleisten soll.

Bei reversiblen/quantum-artigen Instruction Sets muss sichergestellt sein, dass Operanden, die verschieden sein müssen, tatsächlich so eingeschränkt werden, dass sie verschieden sind. Eine Toffoli-/CCX-ähnliche Operation, implementiert als:<sup>[[7]](#references)[[8]](#references)</sup>
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
Dies erzeugt ein **deterministisches Reset-Primitiv**, bricht Annahmen zur Reversibilität und ermöglicht günstigere, nicht beabsichtigte Berechnungen. In Proof-Systemen, die die Ressourcennutzung attestieren, kann dies Angreifern ermöglichen, funktionale Prüfungen zu erfüllen und gleichzeitig das Kostenmodell zu umgehen, dessen Durchsetzung der Verifier annimmt.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen fuzzing.
- Die Validierung des Enum-Bereichs vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Instruktionsformen hinzufügen.
- Gemeldete/öffentliche Counter mit einer unabhängigen Referenzimplementierung vergleichen.
- Daran denken, dass ein gültiger Proof dennoch die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## DeFi/AMM-Ausnutzung

Wenn du die praktische Ausnutzung von DEXes und AMMs (Uniswap-v4-Hooks, Ausnutzung von Rundungs- und Präzisionsfehlern, durch Flash-Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) untersuchst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset-Weighted-Pools, die virtuelle Balances cachen und vergiftet werden können, wenn `supply == 0`, siehe:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key und Private Key erklärt - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signature-Transaktionen? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatsphäre - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Wir haben Googles Zero-Knowledge-Proof der Quantenkryptoanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Schutz elliptischer Kurven-Kryptowährungen vor Quanten-Schwachstellen: Ressourcenschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
