# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Dezentrale Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Eigentum repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** stehen für den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** stehen für dezentrale Börsenplattformen beziehungsweise dezentrale autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und abgestimmte Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Überprüfung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten. Dadurch wird im Vergleich zu PoW weniger Energie verbraucht.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Die Transaktionen werden durch digitale Signaturen validiert. So wird sichergestellt, dass nur der Besitzer des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Schlüsselkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Geldquelle), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden und nur der Endzustand an die Blockchain übermittelt wird.

## Datenschutzbedenken bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Benutzern verschleiern.

## Bitcoins anonym erwerben

Zu den Methoden zählen Bargeldgeschäfte, Mining und die Verwendung von Mixers. **CoinJoin** vermischt mehrere Transaktionen, um die Nachverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt und so für mehr Datenschutz sorgt.

# Zusammenfassung der Datenschutzangriffe auf Bitcoin

In der Bitcoin-Welt sind der Datenschutz bei Transaktionen und die Anonymität der Benutzer häufig Anlass zur Sorge. Hier ist eine vereinfachte Übersicht über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin beeinträchtigen können.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Es ist im Allgemeinen selten, dass Inputs verschiedener Benutzer aufgrund der damit verbundenen Komplexität in einer einzigen Transaktion zusammengeführt werden. Daher wird oft angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, also ein **Unspent Transaction Output**, muss bei einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, wird der Rest an eine neue Wechselgeldadresse gesendet. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch dessen Privatsphäre beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder mehrere Adressen dazu beitragen, die Besitzverhältnisse zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Benutzer teilen ihre Bitcoin-Adressen manchmal online. Dadurch lässt sich **die Adresse leicht ihrem Besitzer zuordnen**.

## **Analyse des Transaktionsgraphen**

Transaktionen können als Graphen visualisiert werden und anhand des Geldflusses mögliche Verbindungen zwischen Benutzern offenbaren.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn das Hinzufügen weiterer Inputs dazu führt, dass die Change-Ausgabe größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden und hoffen, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und so die Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die an bereits verwendete, leere Adressen empfangen wurden, um diesen Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Change finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; die nicht runde Ausgabe ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software identifizieren und möglicherweise auch die Change-Adresse ermitteln.
- **Korrelation von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen rückverfolgbar machen.

## **Traffic-Analyse**

Durch die Überwachung des Netzwerk-Traffics können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch sie Transaktionen besser überwachen kann.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und online gegen Bitcoin tauschen.
- **Mining**: Bitcoins lassen sich am privatesten durch Mining verdienen, insbesondere im Alleingang, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, es anonym zu erwerben, auch wenn dies illegal und nicht empfehlenswert ist.

## Mixing-Dienste

Bei der Nutzung eines Mixing-Dienstes kann ein Nutzer **Bitcoins senden** und **andere Bitcoins zurückerhalten**, wodurch es schwierig wird, den ursprünglichen Besitzer nachzuverfolgen. Dafür muss man jedoch darauf vertrauen, dass der Dienst keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Möglichkeiten zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Nutzer zu einer einzigen zusammen und erschwert so die Zuordnung von Inputs zu Outputs. Trotz seiner Wirksamkeit lassen sich Transaktionen mit ungewöhnlichen Input- und Output-Größen möglicherweise weiterhin zurückverfolgen.

Beispiele für Transaktionen, bei denen CoinJoin verwendet worden sein könnte: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Abhebungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt eine Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als gewöhnliche Transaktion, ohne die für CoinJoin typischen gleichen Outputs. Dadurch ist PayJoin äußerst schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik ungültig machen, die von Stellen zur Transaktionsüberwachung verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die obige könnten PayJoin sein und die Privatsphäre verbessern, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Der Einsatz von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und ist damit eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu gewährleisten, ist es entscheidend, Wallets mit der Blockchain zu synchronisieren. Zwei Methoden stechen hervor:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet eine Full Node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass Angreifer nicht erkennen können, für welche Transaktionen oder Adressen sich der Nutzer interessiert.
- **Clientseitige Blockfilterung**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt. So können Wallets relevante Transaktionen identifizieren, ohne Netzwerkbeobachtern konkrete Interessen offenzulegen. Leichtgewichtige Wallets laden diese Filter herunter und rufen vollständige Blöcke nur dann ab, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin über ein Peer-to-Peer-Netzwerk betrieben wird, wird die Nutzung von Tor empfohlen, um die IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen derselben Entität zugeordnet werden. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Durch das Aufteilen einer Zahlung in mehrere Transaktionen lässt sich der Transaktionsbetrag verschleiern und Datenschutzangriffen entgegenwirken.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeldausgaben verbessern die Privatsphäre, da sie Methoden zur Erkennung von Wechselgeld erschweren.
- **Mehrere Wechselgeldausgaben**: Lässt sich Wechselgeld nicht vermeiden, kann die Erzeugung mehrerer Wechselgeldausgaben die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero ist darauf ausgelegt, die Privatsphäre von Transaktionen in den Vordergrund zu stellen.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der für die Ausführung von Vorgängen auf Ethereum erforderlich ist, und wird in **gwei** angegeben. Eine Transaktion, die beispielsweise 2.310.000 gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Basisgebühr sowie eine Prioritätsgebühr, die Validatoren zur Aufnahme der Transaktion anregen soll. Nutzer können eine maximale Gebühr festlegen, um nicht zu viel zu bezahlen; der überschüssige Betrag wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

Transaktionen auf Ethereum umfassen einen Absender und einen Empfänger, bei denen es sich um Adressen von Nutzern oder Smart Contracts handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsdaten gehören der Empfänger, die Signatur des Absenders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Die Adresse des Absenders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden die Grundlage für alle, die Kryptowährungen nutzen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Alle Komponenten, die Werte verwalten (Signer, Oracles, Bridges, Automatisierung), inventarisieren, um zu verstehen, wer Gelder bewegen kann und auf welche Weise.
- Jede Komponente den relevanten MITRE-AADAPT-Taktiken zuordnen, um Privilegienausweitungspfade aufzudecken.
- Flash-Loan-/Oracle-/Credential-/Cross-Chain-Angriffsketten durchspielen, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signierungsablaufs

- Manipulation der Lieferkette von Wallet-UIs kann EIP-712-Payloads unmittelbar vor dem Signieren verändern und so gültige Signaturen für delegatecall-basierte Proxy-Übernahmen abgreifen (z. B. Überschreiben von `masterCopy` in Slot 0 von Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige Fehlerarten bei Smart Accounts umfassen das Umgehen der `EntryPoint`-Zugriffskontrolle, nicht signierte Gasfelder, zustandsbehaftete Validierung, ERC-1271-Replay-Angriffe und Gebührenabfluss durch Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing, um blinde Flecken in Testsuiten aufzudecken:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK Proofs / zkVM Guests

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Proof-Circuit verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Enthält der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover möglicherweise einen gültigen Proof erzeugen, obwohl die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung in Proof Guests

- Private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingabe** behandeln, auch wenn sie durch den Proof verborgen sind.
- Die Deserialisierung mit nicht geprüften Hilfsfunktionen wie `rkyv::access_unchecked` vermeiden, sofern die Bytes nicht bereits auf anderem Weg validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` auf diesem Wert verdächtig.

### Jump-table-/UB-Umgehung

Wenn Rust ein großes `match` in eine **jump table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Semantik der Instruktion** aus.
3. Ein out-of-range Discriminant indiziert über die erste jump table hinaus und landet in Code, der der zweiten zugeordnet ist.

Ergebnis: Die Operation wird trotzdem ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies Beweise fälschen, die unmögliche Metriken ausweisen, etwa weniger Gates, weniger aufwendige Operationen oder andere verfälschte begrenzte Ressourcen.

Checkliste für die Überprüfung:

- Suche nach vom Angreifer kontrollierten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen für dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + ungeprüfte Deserialisierung + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der jump tables kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Beweis durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Instruktionssätzen sicher, dass Operanden, die verschieden sein müssen, auch tatsächlich durch eine Einschränkung verschieden gehalten werden. Eine Toffoli-/CCX-ähnliche Operation, die wie folgt implementiert ist:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

wird unsicher, wenn der Gast Folgendes nicht ablehnt:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In diesem Fall reduziert sich der Übergang auf:

```text
q = q ^ (q & q) = 0
```

Dies schafft eine **deterministische Reset-Primitive**, die Annahmen zur Umkehrbarkeit verletzt und kostengünstigere, nicht vorgesehene Berechnungen ermöglicht. In Proof-Systemen, die den Ressourcenverbrauch bestätigen, können Angreifer dadurch funktionale Prüfungen bestehen und zugleich das Kostenmodell umgehen, dessen Durchsetzung der Verifier annimmt.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Encodings für Witnesses und Private Inputs fuzz testen.
- Vor dem Opcode-Dispatch die Validierung des Enum-Wertebereichs sicherstellen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Instruktionsformen hinzufügen.
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Beachten, dass ein gültiger Proof trotzdem die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi-/AMM-Exploitation

Wenn Sie praktische Exploitation von DEXes und AMMs (Uniswap-v4-Hooks, Ausnutzung von Rundungs- und Präzisionsfehlern, durch Flash Loans verstärkte Swaps, die Schwellenwerte überschreiten) untersuchen, lesen Sie:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Untersuchen Sie bei Multi-Asset-Weighted-Pools, die virtuelle Salden zwischenspeichern und bei denen `supply == 0` eine Poisoning-Attacke ermöglicht:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher Schlüssel und privater Schlüssel erklärt - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signature-Transaktionen? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Wir haben Googles Zero-Knowledge-Proof zur Quantenkryptanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sicherung elliptischer Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
