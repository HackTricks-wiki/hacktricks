# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und so die Ausführung von Vereinbarungen ohne Vermittler automatisieren.
- **Dezentrale Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
- **Utility Tokens** gewähren Zugriff auf Dienste, während **Security Tokens** den Besitz von Vermögenswerten darstellen.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** stehen für Decentralized Exchange Platforms beziehungsweise Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Überprüfung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, wodurch der Energieverbrauch im Vergleich zu PoW reduziert wird.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Guthaben zwischen Adressen übertragen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des privaten Schlüssels Übertragungen initiieren kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **inputs** (Quelle der Guthaben), **outputs** (Ziel), **fees** (an Miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden und nur der endgültige Zustand an die Blockchain übertragen wird.

## Datenschutzprobleme bei Bitcoin

Privacy attacks wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Benutzern verschleiern.

## Anonymes Erwerben von Bitcoins

Zu den Methoden gehören Bargeldgeschäfte, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Nachverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt und so einen höheren Datenschutz bietet.

# Zusammenfassung der Bitcoin Privacy Attacks

In der Welt von Bitcoin sind der Datenschutz von Transaktionen und die Anonymität der Benutzer häufige Anliegen. Hier ist eine vereinfachte Übersicht über mehrere gängige Methoden, mit denen Angreifer den Bitcoin-Datenschutz kompromittieren können.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

In der Regel werden Inputs verschiedener Benutzer aufgrund der damit verbundenen Komplexität nur selten in einer einzigen Transaktion kombiniert. Daher wird häufig angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, also ein **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch der Datenschutz beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder die Verwendung mehrerer Adressen dazu beitragen, den Besitz zu verschleiern.

## **Social Networks & Forums Exposure**

Benutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden und anhand des Geldflusses potenzielle Verbindungen zwischen Benutzern offenlegen.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs dazu führt, dass der Change-Output größer als jeder einzelne Input ist, kann dies die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits verwendeten, leeren Adressen empfangen wurden, um diesen Privacy-leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Change finden wahrscheinlich zwischen zwei Adressen statt, die demselben Benutzer gehören.
- **Runde Zahlen:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei der nicht-runde Output wahrscheinlich das Change ist.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Transaktionserstellung auf. Dadurch können Analysten die verwendete Software und möglicherweise die Change-Adresse identifizieren.
- **Korrelationen von Betrag und Zeit:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen zurückverfolgbar machen.

## **Traffic-Analyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke möglicherweise mit IP-Adressen verknüpfen und dadurch die Privatsphäre der Benutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, da dies ihre Fähigkeit zur Überwachung von Transaktionen verbessert.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen:** Bitcoin gegen Bargeld erwerben.
- **Bargeldalternativen:** Geschenkkarten kaufen und diese online gegen Bitcoin eintauschen.
- **Mining:** Die privateste Methode, Bitcoins zu verdienen, ist Mining, insbesondere wenn es allein betrieben wird, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl:** Theoretisch könnte der Diebstahl von Bitcoin eine weitere Methode sein, es anonym zu erwerben, obwohl dies illegal und nicht empfehlenswert ist.

## Mixing-Services

Durch die Nutzung eines Mixing-Services kann ein Benutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch die Rückverfolgung des ursprünglichen Besitzers erschwert wird. Dies setzt jedoch voraus, dass dem Service vertraut wird, keine Logs zu speichern und die Bitcoins tatsächlich zurückzugeben. Zu den alternativen Mixing-Optionen gehören Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Benutzer zu einer einzigen zusammen, wodurch der Vorgang für jeden erschwert wird, der versucht, Inputs den Outputs zuzuordnen. Trotz seiner Effektivität können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispieltransaktionen, die möglicherweise CoinJoin verwendet haben, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum smart-contract mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne das charakteristische Merkmal gleich großer Outputs von CoinJoin. Dadurch ist sie äußerst schwer zu erkennen und könnte die bei der Transaktionsüberwachung durch Entitäten verwendete Heuristik des gemeinsamen Input-Besitzes ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die obigen könnten PayJoin sein, wodurch die Privatsphäre verbessert wird, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Der Einsatz von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und stellt damit eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre dar.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Privatsphäre und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full node maximale Privatsphäre. Alle jemals durchgeführten Transaktionen werden lokal gespeichert, wodurch es Angreifern unmöglich wird, festzustellen, für welche Transaktionen oder Adressen sich der Benutzer interessiert.
- **Client-seitige Blockfilterung**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt, sodass Wallets relevante Transaktionen erkennen können, ohne bestimmte Interessen gegenüber Netzwerkbeobachtern offenzulegen. Leichtgewichtige Wallets laden diese Filter herunter und rufen vollständige Blöcke nur ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird die Nutzung von Tor empfohlen, um die IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Vermeidung der Wiederverwendung von Adressen**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets verhindern die Wiederverwendung von Adressen durch ihr Design.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und so Privacy-Angriffe vereiteln.
- **Vermeidung von Wechselgeld**: Die Wahl von Transaktionen, die keine Wechselgeld-Outputs erfordern, verbessert die Privatsphäre, indem Methoden zur Erkennung von Wechselgeld gestört werden.
- **Mehrere Wechselgeld-Outputs**: Wenn die Vermeidung von Wechselgeld nicht möglich ist, kann die Erzeugung mehrerer Wechselgeld-Outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero wurde entwickelt, um die Privatsphäre von Transaktionen zu priorisieren.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der für die Ausführung von Operationen auf Ethereum erforderlich ist, und wird in **gwei** bepreist. Beispielsweise umfasst eine Transaktion, die 2.310.000 gwei (oder 0,00231 ETH) kostet, ein Gas-Limit und eine Grundgebühr sowie eine Prioritätsgebühr, um die Aufnahme durch einen Validator zu fördern. Benutzer können eine maximale Gebühr festlegen, um eine Überzahlung zu verhindern; der Überschuss wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Ausführen von Transaktionen**

Transaktionen in Ethereum umfassen einen Sender und einen Empfänger, bei denen es sich entweder um Benutzer- oder Smart-Contract-Adressen handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Informationen einer Transaktion gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, sodass sie in den Transaktionsdaten nicht erforderlich ist.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden die Grundlage für alle, die sich mit Kryptowährungen beschäftigen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Wertzentriertes Web3 Red Teaming

- Eine Bestandsaufnahme der werttragenden Komponenten (Signer, Oracles, Bridges, Automatisierung), um zu verstehen, wer Gelder bewegen kann und wie.
- Jede Komponente den relevanten MITRE-AADAPT-Taktiken zuordnen, um Wege zur Rechteausweitung offenzulegen.
- Flash-Loan-/Oracle-/Credential-/Cross-Chain-Angriffsketten proben, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signing-Workflows

- Manipulationen der Wallet-UIs in der Supply Chain können EIP-712-Payloads unmittelbar vor dem Signieren verändern und gültige Signaturen für auf delegatecall basierende Proxy-Übernahmen abgreifen (z. B. das Überschreiben von Slot 0 des Safe-masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Zu den häufigen Fehlerarten bei Smart Accounts gehören die Umgehung der Zugriffskontrolle von `EntryPoint`, nicht signierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und das Abschöpfen von Gebühren durch Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Auffinden von Blindstellen in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Gästen

Wenn ein Prover eine **zkVM** oder eine anwendungsspezifische Proof-Schaltung verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Wenn der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen** enthält, kann ein böswilliger Prover einen Proof erzeugen, der verifiziert wird, obwohl die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Gästen

- Behandle private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingabe**, selbst wenn sie durch den Proof verborgen sind.
- Vermeide die Deserialisierung mit ungeprüften Helfern wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits extern validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` über diesen Wert verdächtig.

### Umgehung von Jump-Table-/UB-Zählern

Wenn Rust ein umfangreiches `match` in eine **Jump Table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Constraints**.
2. Ein zweiter `match` führt die **tatsächliche Semantik der Instruktion** aus.
3. Ein Discriminant außerhalb des gültigen Bereichs indiziert hinter die erste Jump Table und landet in Code, der mit der zweiten verknüpft ist.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Accounting-Pfad wird übersprungen. In einer zkVM können dadurch Proofs gefälscht werden, die unmögliche Metriken melden, etwa weniger Gates, weniger kostenintensive Operationen oder andere verfälschte begrenzte Ressourcen.

Review-Checkliste:

- Suche nach vom Angreifer kontrollierten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen über dasselbe Opcode-/Kind-Feld.
- Behandle die Kombination aus `unsafe` + unchecked Deserialization + großem Opcode-Dispatch als besonders risikoreich.
- Reverse-engineere bei Bedarf die erzeugte Binary; das Layout der Jump Table kann wichtiger sein als der Quellcode.

### Fehlende semantische Constraints in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Memory Safety, sondern auch die **semantischen Regeln**, deren Durchsetzung durch den Proof beabsichtigt ist.

Bei reversiblen/quantumähnlichen Instruction Sets muss sichergestellt werden, dass Operanden, die verschieden sein müssen, tatsächlich durch Constraints als verschieden festgelegt sind. Eine Toffoli-/CCX-ähnliche Operation, die implementiert ist als:<sup>[[7]](#references)[[8]](#references)</sup>
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
This erzeugt ein **deterministisches Reset-Primitiv**, wodurch Annahmen zur Reversibilität gebrochen werden und kostengünstigere, nicht beabsichtigte Berechnungen möglich werden. In Proof-Systemen, die den Ressourcenverbrauch attestieren, kann dies Angreifern ermöglichen, funktionale Prüfungen zu erfüllen und dabei das Kostenmodell zu umgehen, von dessen Durchsetzung der Verifier ausgeht.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen fuzzing.
- Enum-Bereichsvalidierung vor dem Opcode-Dispatch erzwingen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Instruction-Formen hinzufügen.
- Gemeldete/öffentliche Counter mit einer unabhängigen Referenzimplementierung vergleichen.
- Daran denken, dass ein gültiger Proof dennoch die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## DeFi/AMM-Exploitation

Wenn du praktische Exploitation von DEXes und AMMs (Uniswap-v4-Hooks, Ausnutzung von Rundungsfehlern und Präzision, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) untersuchst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset-Weighted-Pools, die virtuelle Salden zwischenspeichern und vergiftet werden können, wenn `supply == 0` gilt, siehe:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher und privater Schlüssel erklärt - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signature-Transaktionen? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Wir haben Googles Zero-Knowledge-Proof der Quantenkryptanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Absicherung elliptischer-Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
