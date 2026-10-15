# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

Dieses Kapitel behandelt Blockchain-Konzepte und On-Chain-Sicherheit. Bei einem exponierten Bitcoin-Peer beginne mit der [Enumeration des Bitcoin-P2P-Dienstes](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); bei einem Browser-Frontend, einer Wallet-Verbindung oder einem Off-Chain-Backend verwende [DApp-Pentesting](../../pentesting-web/dapps-DecentralizedApplications.md). Informationen zu Datenschutzoperationen bei Kryptowährungen und deren Grenzen findest du im [Kapitel zum Datenschutz bei Kryptowährungen](../../privacy/cryptocurrency-privacy.md).

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die bei Erfüllung bestimmter Bedingungen auf einer Blockchain ausgeführt werden und Vereinbarungen ohne Vermittler automatisieren.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Zusammenhängen einen Wert oder Besitz darstellen.
  - **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** verbriefen den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** stehen jeweils für dezentrale Börsenplattformen und dezentrale autonome Organisationen.

Begriffe zu Spot-Orders, Futures, Leverage und Optionen, die auf Kryptomärkten verwendet werden, findest du unter [Investmentbegriffe](investment-terms.md).

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Transaktionsverifizierung.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, wodurch im Vergleich zu PoW der Energieverbrauch sinkt.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden durch digitale Signaturen validiert, sodass nur der Besitzer des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignature-Transaktionen** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Geldquelle), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden und nur der endgültige Status an die Blockchain übermittelt wird.

## Datenschutzprobleme bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixer** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Zu den Methoden zählen Bargeldgeschäfte, Mining und die Nutzung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgung zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt und so den Datenschutz verbessert.

# Zusammenfassung der Datenschutzangriffe auf Bitcoin

In der Welt von Bitcoin geben der Datenschutz von Transaktionen und die Anonymität der Nutzer häufig Anlass zur Sorge. Hier folgt ein vereinfachter Überblick über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin gefährden können.<sup>[[6]](#references)</sup>

## **Annahme gemeinsamer Input-Besitzverhältnisse**

Da es aufgrund der damit verbundenen Komplexität selten vorkommt, dass Inputs verschiedener Nutzer in einer einzelnen Transaktion zusammengeführt werden, wird häufig **angenommen, dass zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO, also ein **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch dessen Datenschutz gefährdet wird.

### Beispiel

Um dem entgegenzuwirken, können Mixing-Dienste oder die Verwendung mehrerer Adressen helfen, den Besitz zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch es **einfach wird, die Adresse ihrem Besitzer zuzuordnen**.

## **Analyse von Transaktionsgraphen**

Transaktionen lassen sich als Graphen darstellen, die anhand des Geldflusses mögliche Verbindungen zwischen Nutzern offenlegen.

## **Heuristik für unnötige Inputs (Heuristik für optimales Wechselgeld)**

Diese Heuristik analysiert Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn das Hinzufügen weiterer Inputs dazu führt, dass die Change-Ausgabe größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an bereits verwendete Adressen senden und hoffen, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und so Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die an bereits verwendeten, leeren Adressen eingegangen sind, um diesen Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; die Ausgabe mit dem nicht runden Betrag ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Transaktionserstellung auf. So können Analysten die verwendete Software und möglicherweise die Wechselgeldadresse identifizieren.
- **Korrelation von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Traffic-Analyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Das gilt besonders, wenn eine Entität viele Bitcoin-Nodes betreibt und dadurch Transaktionen besser überwachen kann.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Gegenmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und diese online gegen Bitcoin eintauschen.
- **Mining**: Die privateste Möglichkeit, Bitcoins zu verdienen, ist Mining. Besonders privat ist es, allein zu minen, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, es anonym zu erwerben. Er ist jedoch illegal und nicht zu empfehlen.

## Mixing-Dienste

Mit einem Mixing-Dienst kann ein Nutzer **Bitcoins senden** und dafür **andere Bitcoins zurückerhalten**, wodurch sich der ursprüngliche Besitzer nur schwer zurückverfolgen lässt. Dafür muss man jedoch darauf vertrauen, dass der Dienst keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Optionen zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** fasst mehrere Transaktionen verschiedener Nutzer zu einer zusammen und erschwert dadurch die Zuordnung von Inputs zu Outputs. Trotz seiner Effektivität lassen sich Transaktionen mit einzigartigen Input- und Output-Größen möglicherweise weiterhin zurückverfolgen.

Beispiele für Transaktionen, bei denen CoinJoin zum Einsatz gekommen sein könnte: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Abhebungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als gewöhnliche Transaktion, ohne die für CoinJoin charakteristischen gleich hohen Outputs. Dadurch ist PayJoin extrem schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik außer Kraft setzen, die von Überwachungsdiensten für Transaktionen verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die obige könnten PayJoin sein und den Datenschutz verbessern, während sie weiterhin nicht von standardmäßigen Bitcoin-Transaktionen zu unterscheiden sind.

**Der Einsatz von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und ist damit eine vielversprechende Entwicklung beim Streben nach Datenschutz bei Transaktionen.

# Best Practices für Datenschutz bei Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Datenschutz und Sicherheit zu gewährleisten, ist es entscheidend, Wallets mit der Blockchain zu synchronisieren. Zwei Methoden sind besonders hervorzuheben:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full Node maximalen Datenschutz. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass Angreifer nicht erkennen können, für welche Transaktionen oder Adressen sich der Nutzer interessiert.
- **Client-seitige Blockfilterung**: Bei dieser Methode werden für jeden Block der Blockchain Filter erstellt. So können Wallets relevante Transaktionen erkennen, ohne Netzwerkbeobachtern spezifische Interessen offenzulegen. Leichtgewichtige Wallets laden diese Filter herunter und rufen vollständige Blöcke nur dann ab, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, empfiehlt sich die Nutzung von Tor, um die IP-Adresse zu verschleiern und so den Datenschutz bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre beeinträchtigen, indem Transaktionen derselben Entität zugeordnet werden. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für den Datenschutz bei Transaktionen**

- **Mehrere Transaktionen**: Durch die Aufteilung einer Zahlung auf mehrere Transaktionen lässt sich der Transaktionsbetrag verschleiern und Datenschutzangriffen entgegenwirken.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeldausgänge verbessern den Datenschutz, da sie Methoden zur Erkennung von Wechselgeld erschweren.
- **Mehrere Wechselgeldausgänge**: Wenn sich Wechselgeld nicht vermeiden lässt, kann die Erzeugung mehrerer Wechselgeldausgänge den Datenschutz dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero ist darauf ausgelegt, den Datenschutz bei Transaktionen in den Vordergrund zu stellen.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand für die Ausführung von Vorgängen auf Ethereum und wird in **gwei** angegeben. Eine Transaktion, die beispielsweise 2.310.000 gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Grundgebühr sowie eine Prioritätsgebühr, die Validatoren zur Aufnahme der Transaktion anregen soll. Nutzer können eine maximale Gebühr festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen; der Überschuss wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

An Ethereum-Transaktionen sind ein Sender und ein Empfänger beteiligt, bei denen es sich jeweils um eine Nutzer- oder Smart-Contract-Adresse handeln kann. Für Transaktionen ist eine Gebühr erforderlich, und sie müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsdaten gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Die Adresse des Senders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden die Grundlage für alle, die sich mit Kryptowährungen beschäftigen und dabei Datenschutz und Sicherheit priorisieren möchten.

## Wertzentriertes Web3 Red Teaming

- Erfasse Komponenten, die Werte verwalten (Signer, Oracles, Bridges, Automatisierung), um zu verstehen, wer Gelder bewegen kann und wie.
- Ordne jede Komponente den relevanten MITRE-AADAPT-Taktiken zu, um Privilegieneskalationspfade aufzudecken.
- Übe Angriffsketten mit Flash Loans, Oracles, Zugangsdaten und Cross-Chain-Techniken, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signatur-Workflows

- Manipulationen der Supply Chain von Wallet-UIs können EIP-712-Payloads unmittelbar vor der Signatur verändern und so gültige Signaturen für Delegatecall-basierte Proxy-Übernahmen abgreifen (z. B. das Überschreiben von `masterCopy` in Slot 0 einer Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Zu den häufigen Fehlerarten bei Smart Accounts gehören das Umgehen der Zugriffskontrolle von `EntryPoint`, nicht signierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und das Abziehen von Gebühren durch einen Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Aufdecken von blinden Flecken in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Gästen

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Proof-Circuit verwendet, um eine Behauptung zu bestätigen, erfährt der Verifier lediglich, dass das **Gastprogramm wie geschrieben ausgeführt wurde**. Enthält der Gast **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover einen gültigen Proof erzeugen, obwohl die **öffentlichen Messwerte oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung in Proof-Gästen

- Behandle private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingaben**, selbst wenn sie durch den Proof verborgen sind.
- Vermeide ihre Deserialisierung mit ungeprüften Hilfsfunktionen wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits außerhalb des Systems validiert wurden.
- Enum-Discriminants, relative Zeiger, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **Discriminant außerhalb des gültigen Wertebereichs** einschleusen kann, ist jeder nachgelagerte `match` auf diesem Wert verdächtig.

### Umgehung von Countern per Jump-Table / UB

Wenn Rust ein großes `match` in eine **Jump-Table** umwandelt, kann ein ungültiger Enum-Discriminant **undefiniertes Kontrollflussverhalten** verursachen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Counter/Constraints**.
2. Ein zweiter `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein Discriminant außerhalb des gültigen Wertebereichs greift über die erste Jump-Table hinaus und landet bei Code, der mit der zweiten verknüpft ist.

Ergebnis: Die Operation wird trotzdem ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies gefälschte Beweise erzeugen, die unmögliche Metriken wie weniger Gates, weniger aufwendige Operationen oder andere verfälschte begrenzte Ressourcen melden.

Checkliste für die Prüfung:

- Suche nach angreifergesteuerten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Prüfe wiederholte `match`-Anweisungen für dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + ungeprüfte Deserialisierung + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-Engineere bei Bedarf das erzeugte Binary; das Layout der Jump-Table kann wichtiger sein als der Quellcode.

### Fehlende semantische Constraints in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Beweis durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Instruktionssätzen sicher, dass Operanden, die verschieden sein müssen, tatsächlich auf Verschiedenheit beschränkt sind. Eine Toffoli-/CCX-ähnliche Operation, implementiert als:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

wird unsicher, wenn der Gast nicht ablehnt:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In diesem Fall fällt der Übergang zusammen zu:

```text
q = q ^ (q & q) = 0
```

Dies erzeugt eine **deterministische Reset-Primitive**, die Annahmen zur Umkehrbarkeit verletzt und kostengünstigere, nicht beabsichtigte Berechnungen ermöglicht. In Proof-Systemen, die den Ressourcenverbrauch bestätigen, können Angreifer dadurch funktionale Prüfungen bestehen und zugleich das Kostenmodell umgehen, das der Verifizierer durchzusetzen glaubt.

### Unzureichend eingeschränkte Prover-Hinweise und modulare Arithmetik

Werte, die von einem **Advice-/Witness-Stack geladen werden, werden vom Prover kontrolliert**, auch wenn sie als vorberechnete Quotienten, Reste, Inverse oder Hinweise beschrieben werden. Ein Proof belegt nur, dass der Witness die implementierten Constraints erfüllt; er belegt nicht, dass die beabsichtigte Berechnung ausgeführt wurde, wenn diese Constraints eine Typ-, Wertebereichs- oder kanonische Formprüfung auslassen.<sup>[[13]](#references)</sup>

Prüfe bei einer Reduktions- oder euklidischen Divisionsfunktion die vollständige Ganzzahlrelation und nicht nur die abschließende Subtraktion oder Multiplikation. Jedes Limb von `q` und `r` muss auf seine deklarierte Breite beschränkt sein, die Rekonstruktion `x = q * m + r` muss in der vorgesehenen Ganzzahldarstellung gelten, und die kanonische Schranke `0 <= r < m` muss erzwungen werden. Prüfe einen Wert, **bevor** du ihn an eine schmalere `u32`-/`u64`-Instruktion übergibst; eine schmale Operation beweist nicht nachträglich, dass das ursprüngliche Feldelement oder der Wert aus mehreren Limbs den erwarteten Typ hatte.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Der `mod_12289`-Fehler in Miden veranschaulicht das Exploit-Muster: Der Quotient wurde als zweigliedriger 64-Bit-Wert geprüft, aber der über Advice bereitgestellte Restwert erreichte `u32overflowing_sub` ohne gleichwertige Validierung. Ein böswilliger Prover konnte ungültige Quotienten- und Restwerte so aufeinander abstimmen, dass die implementierten Subtraktionsbedingungen weiterhin erfüllt waren, während die Prozedur einen mathematisch falschen Restwert zurückgab. Da dieses Ergebnis in die Falcon-Verifikation einfloss, ließ sich der Soundness-Fehler zu gefälschten Autorisierungssignaturen ausweiten, statt lediglich ein falsches arithmetisches Ergebnis zu erzeugen.<sup>[[13]](#references)</sup>

### Auditing impliziter Stack-Kryptografie-VMs

Stack-Sprachen verbergen Operanden. Daher sollten Anweisungen zunächst in eine IR überführt werden, in der jeder verbrauchte und erzeugte Stack-Wert ein Ausdruck mit Provenienz ist. Eine konservative Analysepipeline kann anschließend Folgendes tun:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Den Callgraph erstellen und die Stack-Effekte der Prozedureingaben und -ausgaben ableiten.
2. Unterstützte Anweisungen symbolisch ausführen und den Kontrollfluss in SSA-/strukturierte Ausdrücke überführen.
3. Abstrakte Fakten wie `Unknown`, `ProvenU32`, `Bool`, Wert-Provenienz und lokale Initialisierung bis zu einem Fixpunkt propagieren.
4. Von Advice abgeleitete Werte markieren, die ohne Sanitizer auf **jedem** eingehenden Pfad typisierte Arithmetik oder Senken für Nicht-Null-Werte erreichen.
5. Deklarierte und abgeleitete Signaturen vergleichen und prüfen, ob jeder Exit die dem Aufrufer gehörenden Stack-Werte erhält.

Eine unbekannte Signatur oder ein nicht unterstütztes Konstrukt ist als **Analyselücke** zu behandeln, nicht als sauberes Ergebnis. Dynamische Aufrufe, nicht Stack-neutrale Schleifen und Verzweigungen mit unterschiedlichen Stack-Effekten können eine zuverlässige Nachverfolgung von Stack-Slots unmöglich machen. Ein sichererer Decompiler weist solche Fälle zurück oder markiert sie, statt plausibel wirkenden, aber falschen Pseudocode auszugeben.<sup>[[10]](#references)[[13]](#references)</sup>

An Kontrollflussverknüpfungen sollte eine Eigenschaft nur dann erhalten bleiben, wenn sie für jeden Vorgänger gilt (zum Beispiel `ProvenU32 join Unknown = Unknown`). Außerdem muss zwischen Konvergenz am Fixpunkt und dem Erreichen eines Iterationslimits unterschieden werden: Nur eine konvergierte, sounde Überapproximation kann rechtfertigen, das Ausbleiben eines Befunds als Beleg dafür zu werten, dass alle dargestellten Ausführungen die Eigenschaft erfüllen.<sup>[[11]](#references)</sup>

### Verborgene Vorbedingungen mit Beweispflichten aufdecken

Bei kleinen Befehlssätzen sollten Prozeduren in ein ausführbares formales VM-Modell übersetzt und sowohl das Ergebnis als auch die vollständige Stack-Transformation bewiesen werden. Der Satz sollte Terminierung, typisierte Eingaben, das erwartete Ausgabepräfix und die Erhaltung des unveränderten Caller-Stacks abdecken. Die Satzformulierung sollte ebenso sorgfältig geprüft werden wie der Beweis: Der Kernel kann einen Beweis für eine versehentlich abgeschwächte Behauptung validieren.<sup>[[12]](#references)[[13]](#references)</sup>

Unerwartete Hypothesen sind nützliche Befunde. Bei der Miden-Prüfung erforderte ein Beweis für eine 64-Bit-Rechtsrotation `shift mod 32 != 0` und deckte damit einen fehlerhaften Randfall für große Eingaben auf, wenn der Shift ein Vielfaches von 32 war. Ein anderer Beweis ergab, dass `wrapping_mul` für 256-Bit-Werte dem Aufrufer gehörende Stack-Werte verwarf. Der entdeckte Randfall sollte zu den Tests hinzugefügt und anschließend die Implementierung korrigiert oder die öffentliche Vorbedingung bewusst verschärft werden, statt die zusätzliche Annahme stillschweigend zu akzeptieren.<sup>[[12]](#references)[[13]](#references)</sup>

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen fuzz testen.
- Die Validierung des Enum-Wertebereichs vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen für Operand-Aliasing und andere ungültige Anweisungsformen hinzufügen.
- Jede Advice-/Witness-Quelle bis zu jeder typisierten arithmetischen Senke nachverfolgen und auf jedem Pfad eine Validierung verlangen.<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetische Hilfsfunktionen mit nicht-kanonischen Limbs, Restwerten außerhalb des gültigen Bereichs und Shift-Anzahlen an den Grenzen testen.<sup>[[12]](#references)[[13]](#references)</sup>
- Bei jeder Rückgabe die Stack-Höhe und die Erhaltung der Werte unterhalb der deklarierten Prozedurargumente sicherstellen.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Daran denken, dass ein gültiger Beweis trotzdem die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi-/AMM-Exploitation

Wenn du praktische Exploitation von DEXes und AMMs untersuchst (Uniswap-v4-Hooks, Missbrauch von Rundung/Präzision, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten), sieh dir Folgendes an:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für gewichtete Pools mit mehreren Assets, die virtuelle Salden zwischenspeichern und bei `supply == 0` vergiftet werden können, lies:

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
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Beweis für Quantenkryptanalyse gebrochen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Absicherung von Elliptische-Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architektur des MASM-Decompilers](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Statische MASM-Analyse-Engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean-Modell und Korrektheitsbeweise](https://github.com/trailofbits/masm-lean)
- [13] [Auditing im Zeitalter von (ausreichend guter) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
