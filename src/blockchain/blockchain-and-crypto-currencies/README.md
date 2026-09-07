# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und die Ausführung von Vereinbarungen ohne Vermittler automatisieren.
- **Dezentralisierte Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Front-End sowie ein transparentes, auditierbares Back-End.
- **Tokens & Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
- **Utility Tokens** gewähren Zugriff auf Services, während **Security Tokens** den Besitz von Vermögenswerten kennzeichnen.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** stehen jeweils für Decentralized Exchange Platforms und Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** basiert bei der Transaktionsverifizierung auf Rechenleistung.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, wodurch der Energieverbrauch im Vergleich zu PoW reduziert wird.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen umfassen die Übertragung von Guthaben zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des privaten Schlüssels Übertragungen initiieren kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **inputs** (Quelle der Gelder), **outputs** (Ziel), **fees** (an Miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden und nur der endgültige Zustand an die Blockchain übertragen wird.

## Datenschutzprobleme bei Bitcoin

Privacy attacks wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Benutzern verschleiern.

## Anonyme Beschaffung von Bitcoins

Zu den Methoden gehören Bargeldgeschäfte, Mining und die Verwendung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt und so den Datenschutz erhöht.

# Zusammenfassung der Bitcoin-Datenschutzangriffe

In der Welt von Bitcoin sind der Datenschutz von Transaktionen und die Anonymität der Benutzer häufige Problemfelder. Hier folgt eine vereinfachte Übersicht über verschiedene gängige Methoden, mit denen Angreifer den Bitcoin-Datenschutz beeinträchtigen können.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Es ist aufgrund der damit verbundenen Komplexität generell selten, dass Inputs verschiedener Benutzer in einer einzigen Transaktion kombiniert werden. Daher wird häufig angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO oder **Unspent Transaction Output** muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch der Datenschutz beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Services oder die Verwendung mehrerer Adressen dabei helfen, den Besitz zu verschleiern.

## **Social Networks & Forums Exposure**

Benutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden und dadurch potenzielle Verbindungen zwischen Benutzern auf Grundlage des Geldflusses offenlegen.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückfließende Wechselgeld ist.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs dazu führt, dass der Change-Output größer ist als jeder einzelne Input, kann dies die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an bereits verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, auf bereits verwendeten, leeren Adressen empfangene Coins zu verwenden, um dieses Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld finden wahrscheinlich zwischen zwei Adressen statt, die demselben Benutzer gehören.
- **Runde Beträge:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei der nicht runde Output wahrscheinlich das Wechselgeld ist.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software identifizieren und möglicherweise die Change-Adresse bestimmen.
- **Korrelationen von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Verkehrsanalyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke möglicherweise mit IP-Adressen verknüpfen und dadurch die Privatsphäre der Benutzer beeinträchtigen. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Fähigkeit zur Überwachung von Transaktionen verbessert wird.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Schutzmaßnahmen findest du unter [Bitcoin Privacy im Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und diese online gegen Bitcoin eintauschen.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist Mining, insbesondere wenn es allein durchgeführt wird, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Methode sein, es anonym zu erwerben, allerdings ist dies illegal und wird nicht empfohlen.

## Mixing-Services

Durch die Nutzung eines Mixing-Services kann ein Benutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch die Rückverfolgung des ursprünglichen Besitzers erschwert wird. Dies erfordert jedoch Vertrauen in den Service, keine Logs zu speichern und die Bitcoins tatsächlich zurückzugeben. Zu den alternativen Mixing-Optionen gehören Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Benutzer zu einer einzigen zusammen, wodurch der Versuch erschwert wird, Inputs den Outputs zuzuordnen. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispieltransaktionen, bei denen möglicherweise CoinJoin verwendet wurde, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Abhebungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne das charakteristische Merkmal gleich großer Outputs von CoinJoin. Dadurch ist sie äußerst schwer zu erkennen und könnte die von Stellen zur Transaktionsüberwachung verwendete Heuristik des gemeinsamen Input-Besitzes ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben genannten könnten PayJoin sein und so die Privatsphäre verbessern, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und stellt damit eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre dar.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Privatsphäre und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass es für Angreifer unmöglich ist, zu erkennen, für welche Transaktionen oder Adressen sich der Benutzer interessiert.
- **Client-side block filtering**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt. Dadurch können Wallets relevante Transaktionen identifizieren, ohne gegenüber Netzwerkbeobachtern bestimmte Interessen offenzulegen. Leichtgewichtige Wallets laden diese Filter herunter und rufen vollständige Blöcke nur ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird die Nutzung von Tor empfohlen, um die IP-Adresse zu verschleiern und dadurch die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Vermeidung der Wiederverwendung von Adressen**

Zum Schutz der Privatsphäre ist es entscheidend, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre beeinträchtigen, da dadurch Transaktionen mit derselben Entität verknüpft werden können. Moderne Wallets wirken der Wiederverwendung von Adressen durch ihr Design entgegen.

## **Strategien für die Transaktionsprivatsphäre**

- **Multiple transactions**: Das Aufteilen einer Zahlung auf mehrere Transaktionen kann den Transaktionsbetrag verschleiern und so Privacy-Angriffe vereiteln.
- **Change avoidance**: Die Wahl von Transaktionen, die keine Wechselgeld-Outputs erfordern, verbessert die Privatsphäre, indem Methoden zur Erkennung von Wechselgeld gestört werden.
- **Multiple change outputs**: Wenn die Vermeidung von Wechselgeld nicht möglich ist, kann die Erzeugung mehrerer Wechselgeld-Outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero wurde entwickelt, um die Privatsphäre von Transaktionen zu priorisieren.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den für die Ausführung von Operationen auf Ethereum erforderlichen Rechenaufwand und wird in **gwei** angegeben. Beispielsweise umfasst eine Transaktion, die 2.310.000 gwei (oder 0.00231 ETH) kostet, ein Gas-Limit und eine Basisgebühr sowie eine Prioritätsgebühr, um die Aufnahme durch einen Validator zu incentivieren. Benutzer können eine maximale Gebühr festlegen, um eine Überzahlung zu verhindern; der überschüssige Betrag wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Ausführen von Transaktionen**

Transaktionen auf Ethereum umfassen einen Sender und einen Empfänger, bei denen es sich entweder um Benutzer- oder Smart-Contract-Adressen handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Informationen einer Transaktion gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Bemerkenswerterweise wird die Adresse des Senders aus der Signatur abgeleitet, sodass sie nicht in den Transaktionsdaten enthalten sein muss.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden eine Grundlage für alle, die sich mit Kryptowährungen beschäftigen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Inventarisiere werttragende Komponenten (Signer, Oracles, Bridges, Automatisierung), um zu verstehen, wer Gelder bewegen kann und wie.
- Ordne jede Komponente den relevanten MITRE-AADAPT-Taktiken zu, um Wege zur Privilege Escalation offenzulegen.
- Übe Flash-Loan-/Oracle-/Credential-/Cross-Chain-Angriffsketten, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3 Signing Workflow

- Manipulationen der Supply Chain von Wallet-UIs können EIP-712-Payloads unmittelbar vor dem Signieren verändern und gültige Signaturen für auf `delegatecall` basierende Übernahmen von Proxies abgreifen (z. B. zum Überschreiben von Slot 0 des Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Zu den häufigen Fehlerarten bei Smart Accounts gehören die Umgehung der Zugriffskontrolle von `EntryPoint`, unsignierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay sowie das Abschöpfen von Gebühren durch Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Auffinden von Blind Spots in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / Integrität von zkVM Guests

Wenn ein Prover eine **zkVM** oder eine anwendungsspezifische Proof-Schaltung verwendet, um eine Behauptung zu attestieren, lernt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Wenn der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen** enthält, kann ein bösartiger Prover einen Proof erzeugen, der verifiziert wird, während die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof Guests

- Behandle private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifer-Eingaben**, selbst wenn sie durch den Proof verborgen sind.
- Vermeide die Deserialisierung mit ungeprüften Helfern wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits außerhalb des Systems validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` über diesen Wert verdächtig.

### Jump-table / UB counter bypass

Wenn Rust ein großes `match` in eine **jump table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefined control flow** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **tatsächliche Instruction-Semantik** aus.
3. Ein Discriminant außerhalb des gültigen Bereichs indexiert über die erste jump table hinaus und landet in Code, der mit der zweiten verknüpft ist.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Accounting-Pfad wird übersprungen. In einer zkVM können dadurch Proofs gefälscht werden, die unmögliche Metriken melden, etwa weniger Gates, weniger teure Operationen oder andere verfälschte begrenzte Ressourcen.

Review-Checkliste:

- Suche nach von Angreifern kontrollierten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen über dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + unchecked deserialization + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der jump table kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Validiere nicht nur die Memory-Safety, sondern auch die **semantischen Regeln**, deren Durchsetzung der Proof gewährleisten soll.

Bei reversiblen/quantumähnlichen Instruction Sets muss sichergestellt sein, dass Operanden, die verschieden sein müssen, tatsächlich durch Constraints als verschieden festgelegt sind. Eine Toffoli-/CCX-ähnliche Operation, die implementiert ist als:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
wird unsicher, wenn der Gast dies nicht ablehnt:
```text
op.q_control1 == op.q_control2 == op.q_target
```
In diesem Fall reduziert sich der Übergang auf:
```text
q = q ^ (q & q) = 0
```
Dies erzeugt ein **deterministisches Reset-Primitiv**, bricht Annahmen zur Reversibilität und ermöglicht kostengünstigere, nicht vorgesehene Berechnungen. In Proof-Systemen, die den Ressourcenverbrauch bestätigen, kann dies Angreifern ermöglichen, funktionale Prüfungen zu erfüllen und gleichzeitig das Kostenmodell zu umgehen, von dessen Durchsetzung der Verifier ausgeht.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen fuzzing.
- Eine Enum-Bereichsvalidierung vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Instruktionsformen hinzufügen.
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Daran denken, dass ein gültiger Proof dennoch die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-Exploitation

Wenn du praktische Exploitation von DEXes und AMMs (Uniswap-v4-Hooks, Ausnutzung von Rundungs- und Präzisionsfehlern, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) untersuchst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset-Weighted-Pools, die virtuelle Salden cachen und vergiftet werden können, wenn `supply == 0`, siehe:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake – Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher Schlüssel und privater Schlüssel erklärt – Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signature-Transaktionen? – Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatsphäre – Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Proof der Quantenkryptanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sicherung elliptischer-Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
