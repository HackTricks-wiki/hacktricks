# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, sobald bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Dezentralisierte Anwendungen (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** verbriefen den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** stehen für dezentrale Börsenplattformen bzw. dezentralisierte autonome Organisationen.

Die Begriffe für Spot-Orders, Futures, Leverage und Optionen auf Kryptomärkten findest du unter [Investment Terms](investment-terms.md).

## Konsensmechanismen

Konsensmechanismen gewährleisten die sichere und einvernehmliche Validierung von Transaktionen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Verifizierung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten. Dadurch wird der Energieverbrauch im Vergleich zu PoW gesenkt.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden durch digitale Signaturen validiert, sodass nur der Besitzer des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptbestandteile:

- **Multisignatur-Transaktionen** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Quelle der Gelder), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Scripts** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden. Nur der endgültige Zustand wird an die Blockchain übertragen.

## Datenschutzprobleme bei Bitcoin

Datenschutzangriffe wie die **Annahme gemeinsamer Input-Besitzverhältnisse** und die **Erkennung von Wechselgeldadressen anhand von UTXOs** nutzen Transaktionsmuster aus. Methoden wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Zu den Methoden gehören Bargeldgeschäfte, Mining und die Nutzung von Mixers. **CoinJoin** vermischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren. **PayJoin** tarnt CoinJoins als normale Transaktionen und erhöht so den Datenschutz.

# Zusammenfassung der Datenschutzangriffe auf Bitcoin

In der Bitcoin-Welt geben der Datenschutz bei Transaktionen und die Anonymität der Nutzer oft Anlass zur Sorge. Hier ist ein vereinfachter Überblick über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin beeinträchtigen können.<sup>[[6]](#references)</sup>

## **Annahme gemeinsamer Input-Besitzverhältnisse**

Es kommt generell selten vor, dass Inputs verschiedener Nutzer aufgrund der damit verbundenen Komplexität in einer einzelnen Transaktion zusammengeführt werden. Daher wird oft **angenommen, dass zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO, also ein **Unspent Transaction Output**, muss bei einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch dessen Datenschutz beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder die Verwendung mehrerer Adressen helfen, den Besitz zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer teilen ihre Bitcoin-Adressen manchmal online. Dadurch lässt sich **die Adresse leicht ihrem Besitzer zuordnen**.

## **Analyse des Transaktionsgraphen**

Transaktionen lassen sich als Graphen visualisieren. Dadurch werden mögliche Verbindungen zwischen Nutzern anhand des Geldflusses sichtbar.

## **Heuristik für unnötige Inputs (Heuristik für optimales Wechselgeld)**

Diese Heuristik analysiert Transaktionen mit mehreren Inputs und Outputs, um zu vermuten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn weitere Inputs hinzugefügt werden, kann die Change-Ausgabe größer sein als jeder einzelne Input, was die Heuristik verwirren kann.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden und hoffen, dass der Empfänger diese in künftigen Transaktionen mit anderen Inputs zusammenführt und so Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die an bereits verwendete, leere Adressen gesendet wurden, um diesen Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Change finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; der nicht runde Output ist wahrscheinlich das Change.
- **Wallet-Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Transaktionserstellung. So können Analysten die verwendete Software und möglicherweise die Change-Adresse identifizieren.
- **Korrelationen zwischen Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Traffic-Analyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke möglicherweise mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Das gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch sie Transaktionen besser überwachen kann.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Schutzmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und online gegen Bitcoin tauschen.
- **Mining**: Bitcoins lassen sich am privatesten durch Mining verdienen, insbesondere allein, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, anonym an Bitcoin zu gelangen, doch er ist illegal und nicht empfehlenswert.

## Mixing-Services

Bei der Nutzung eines Mixing-Service kann ein Nutzer **Bitcoins senden** und dafür **andere Bitcoins zurückerhalten**, wodurch sich der ursprüngliche Besitzer schwerer zurückverfolgen lässt. Dafür muss man jedoch darauf vertrauen, dass der Service keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Möglichkeiten gehören Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Nutzer zu einer einzigen zusammen und erschwert dadurch den Abgleich von Inputs und Outputs. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispiele für Transaktionen, bei denen möglicherweise CoinJoin verwendet wurde, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als gewöhnliche Transaktion, ohne die charakteristischen gleich großen Outputs von CoinJoin. Dadurch ist PayJoin äußerst schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik aushebeln, die von Überwachungsdiensten für Transaktionen verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die obige könnten PayJoin sein und den Datenschutz verbessern, während sie von gewöhnlichen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und ist daher eine vielversprechende Entwicklung im Streben nach Transaktionsdatenschutz.

# Best Practices für den Datenschutz bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Datenschutz und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden sind besonders hervorzuheben:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain bietet ein Full Node maximalen Datenschutz. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass Angreifer nicht erkennen können, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Clientseitige Blockfilterung**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt. So können Wallets relevante Transaktionen identifizieren, ohne Netzwerkbeobachtern ihre konkreten Interessen offenzulegen. Lightweight-Wallets laden diese Filter herunter und rufen vollständige Blöcke nur ab, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, empfiehlt sich die Verwendung von Tor, um die IP-Adresse zu verschleiern und den Datenschutz bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann den Datenschutz beeinträchtigen, indem sie Transaktionen derselben Entität zuordnet. Moderne Wallets verhindern durch ihr Design die Wiederverwendung von Adressen.

## **Strategien für den Transaktionsdatenschutz**

- **Mehrere Transaktionen**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Datenschutzangriffe vereiteln.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeld-Ausgaben verbessern den Datenschutz, da sie Methoden zur Erkennung von Wechselgeld erschweren.
- **Mehrere Wechselgeld-Ausgaben**: Wenn sich Wechselgeld nicht vermeiden lässt, kann die Erstellung mehrerer Wechselgeld-Ausgaben den Datenschutz dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero wurde entwickelt, um den Datenschutz bei Transaktionen in den Vordergrund zu stellen.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand für die Ausführung von Vorgängen auf Ethereum und wird in **gwei** angegeben. Eine Transaktion, die beispielsweise 2.310.000 gwei (oder 0,00231 ETH) kostet, umfasst ein Gas-Limit und eine Basisgebühr sowie eine Prioritätsgebühr, um Validatoren zur Aufnahme der Transaktion zu bewegen. Nutzer können eine maximale Gebühr festlegen, um nicht zu viel zu bezahlen; der überschüssige Betrag wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

An Ethereum-Transaktionen sind ein Sender und ein Empfänger beteiligt, bei denen es sich jeweils um eine Nutzer- oder Smart-Contract-Adresse handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsdaten gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Die Adresse des Senders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden die Grundlage für alle, die Kryptowährungen nutzen und dabei Datenschutz und Sicherheit in den Vordergrund stellen möchten.

## Web3 Red Teaming mit Fokus auf Vermögenswerten

- Erfassen Sie Komponenten, die Vermögenswerte verwalten oder bewegen können (Signer, Oracles, Bridges, Automatisierung), um zu verstehen, wer Gelder bewegen kann und auf welche Weise.
- Ordnen Sie jede Komponente den relevanten MITRE-AADAPT-Taktiken zu, um Wege zur Rechteausweitung aufzudecken.
- Üben Sie Angriffsketten mit Flash Loans, Oracles, Zugangsdaten und Cross-Chain-Komponenten, um die Auswirkungen zu überprüfen und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signatur-Workflows

- Manipulationen an der Lieferkette von Wallet-UIs können EIP-712-Payloads unmittelbar vor dem Signieren verändern und so gültige Signaturen für Übernahmen von Proxys auf Basis von `delegatecall` abgreifen (z. B. das Überschreiben von Slot 0 mit `Safe masterCopy`).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige Fehlerarten bei Smart Accounts sind das Umgehen der Zugriffskontrolle von `EntryPoint`, nicht signierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay-Angriffe und das Abschöpfen von Gebühren durch einen Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Aufdecken von Lücken in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Guests

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Proof-Circuit verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Enthält der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein bösartiger Prover einen gültigen Proof erzeugen, obwohl die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Guests

- Behandeln Sie private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingaben**, selbst wenn sie durch den Proof verborgen sind.
- Vermeiden Sie die Deserialisierung mit ungeprüften Hilfsfunktionen wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits außerhalb des Systems validiert wurden.
- Enum-Discriminants, relative Zeiger, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` auf diesem Wert verdächtig.

### Jump-table-/UB-Umgehung von Zählern

Wenn Rust ein großes `match` in eine **jump table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein out-of-range-Discriminant greift über die erste jump table hinaus und landet in Code, der der zweiten zugeordnet ist.

Ergebnis: Die Operation wird trotzdem ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies gefälschte Beweise erzeugen, die unmögliche Metriken wie weniger Gates, weniger aufwendige Operationen oder andere verfälschte begrenzte Ressourcen melden.

Checkliste für die Überprüfung:

- Suche nach vom Angreifer kontrollierten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen über dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + ungeprüfte Deserialisierung + große Opcode-Dispatches als Hochrisikokombination.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der jump table kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Beweis durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Befehlssätzen sicher, dass Operanden, die verschieden sein müssen, tatsächlich auf Verschiedenheit eingeschränkt sind. Eine Toffoli-/CCX-ähnliche Operation, implementiert als:<sup>[[7]](#references)[[8]](#references)</sup>

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

Dies schafft ein **deterministisches Reset-Primitiv**, das Annahmen zur Umkehrbarkeit bricht und kostengünstigere, nicht vorgesehene Berechnungen ermöglicht. In Beweissystemen, die den Ressourcenverbrauch attestieren, können Angreifer dadurch Funktionsprüfungen bestehen und gleichzeitig das Kostenmodell umgehen, dessen Durchsetzung der Verifier annimmt.

### Unzureichend eingeschränkte Prover-Ratschläge und modulare Arithmetik

Werte, die von einem **Advice-/Witness-Stack geladen werden, werden vom Prover kontrolliert**, selbst wenn sie als vorberechnete Quotienten, Reste, Inverse oder Hinweise beschrieben werden. Ein Beweis stellt nur fest, dass der Witness die implementierten Constraints erfüllt; er belegt nicht, dass die beabsichtigte Berechnung ausgeführt wurde, wenn diese Constraints eine Typ-, Bereichs- oder kanonische Formprüfung auslassen.<sup>[[13]](#references)</sup>

Prüfe bei einer Reduktions- oder euklidischen Divisionshilfe die vollständige ganzzahlige Relation und nicht nur die abschließende Subtraktion oder Multiplikation. Jeder Limb von `q` und `r` muss auf seine deklarierte Breite beschränkt sein, die Rekonstruktion `x = q * m + r` muss in der vorgesehenen ganzzahligen Darstellung gelten und die kanonische Schranke `0 <= r < m` muss durchgesetzt werden. Validiere einen Wert **bevor** du ihn an eine schmalere `u32`-/`u64`-Instruktion übergibst; eine schmale Operation beweist nicht nachträglich, dass das ursprüngliche Feldelement oder der mehrgliedrige Wert den erwarteten Typ hatte.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Der Fehler `mod_12289` in Miden veranschaulicht das Exploit-Muster: Der Quotient wurde als zweigliedriger 64-Bit-Wert geprüft, aber der durch Advice bereitgestellte Rest erreichte `u32overflowing_sub` ohne gleichwertige Validierung. Ein bösartiger Prover konnte ungültige Quotienten- und Restwerte so aufeinander abstimmen, dass die implementierten Subtraktionsbedingungen weiterhin erfüllt waren, während die Prozedur einen mathematisch falschen Rest zurückgab. Da dieses Ergebnis in die Falcon-Verifizierung einfloss, ließ sich der Soundness-Fehler zu gefälschten Autorisierungssignaturen ausweiten, statt lediglich ein falsches arithmetisches Ergebnis zu erzeugen.<sup>[[13]](#references)</sup>

### Implizite Stack-VMs für Kryptografie auditieren

Stack-Sprachen verbergen Operanden. Überführe daher zunächst die Instruktionen in eine IR, in der jeder verbrauchte und erzeugte Stack-Wert als Ausdruck mit Herkunft dargestellt wird. Eine konservative Analysepipeline kann dann:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Den Aufrufgraphen erstellen und die Stack-Effekte der Prozedureingaben und -ausgaben ableiten.
2. Unterstützte Instruktionen symbolisch ausführen und den Kontrollfluss in SSA-/strukturierte Ausdrücke überführen.
3. Abstrakte Fakten wie `Unknown`, `ProvenU32`, `Bool`, die Herkunft von Werten und die Initialisierung lokaler Variablen bis zu einem Fixpunkt weitergeben.
4. Von Advice abgeleitete Werte kennzeichnen, die ohne Sanitizer auf **jedem** eingehenden Pfad typisierte Arithmetik oder Senken für Werte ungleich null erreichen.
5. Deklarierte und abgeleitete Signaturen vergleichen und prüfen, ob jeder Exit die Stack-Werte des Aufrufers erhält.

Behandle eine unbekannte Signatur oder ein nicht unterstütztes Konstrukt als **Analyselücke**, nicht als unbedenkliches Ergebnis. Dynamische Aufrufe, Schleifen, die den Stack nicht unverändert lassen, und Verzweigungen mit unterschiedlichen Stack-Effekten können eine verlässliche Zuordnung von Stack-Slots unmöglich machen. Ein sichererer Decompiler weist solche Fälle zurück oder markiert sie, statt plausibel wirkenden, aber falschen Pseudocode auszugeben.<sup>[[10]](#references)[[13]](#references)</sup>

Behalte an Kontrollflusszusammenführungen eine Eigenschaft nur bei, wenn sie für jeden Vorgänger gilt (zum Beispiel `ProvenU32 join Unknown = Unknown`). Unterscheide außerdem zwischen der Konvergenz zum Fixpunkt und dem Erreichen eines Iterationslimits: Nur eine konvergierte, korrekte Überapproximation rechtfertigt es, das Ausbleiben einer Diagnose als Beleg dafür zu werten, dass alle dargestellten Ausführungen die Eigenschaft erfüllen.<sup>[[11]](#references)</sup>

### Verborgene Vorbedingungen mit Beweispflichten aufdecken

Übersetze Prozeduren bei kleinen Instruktionssätzen in ein ausführbares formales VM-Modell und beweise sowohl das Ergebnis als auch die vollständige Stack-Transformation. Der Satz sollte Terminierung, typisierte Eingaben, das erwartete Ausgabepräfix und den Erhalt des unveränderten Aufrufer-Stacks abdecken. Prüfe die Formulierung des Satzes ebenso sorgfältig wie den Beweis: Der Kernel kann auch einen Beweis für eine versehentlich abgeschwächte Behauptung validieren.<sup>[[12]](#references)[[13]](#references)</sup>

Unerwartete Hypothesen sind wertvolle Befunde. Bei der Miden-Prüfung erforderte ein Beweis für die 64-Bit-Rechtsrotation `shift mod 32 != 0`. Dadurch wurde ein fehlerhafter Randfall für große Eingaben aufgedeckt, wenn der Shift ein Vielfaches von 32 war. Ein anderer Beweis ergab, dass `wrapping_mul` für 256 Bit Stack-Werte des Aufrufers verwarf. Nimm den entdeckten Randfall in die Tests auf und behebe anschließend die Implementierung oder verschärfe bewusst die öffentliche Vorbedingung, statt die zusätzliche Annahme stillschweigend zu akzeptieren.<sup>[[12]](#references)[[13]](#references)</sup>

### Was in ZK-Systemen getestet werden sollte

- Fuzze alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen.
- Stelle sicher, dass Enum-Bereiche vor dem Opcode-Dispatch validiert werden.
- Füge semantische Prüfungen für Operand-Aliasing und andere ungültige Instruktionsformen hinzu.
- Verfolge jede Advice-/Witness-Quelle bis zu jeder Senke für typisierte Arithmetik und verlange Validierung auf jedem Pfad.<sup>[[11]](#references)[[13]](#references)</sup>
- Teste Arithmetik-Helper mit nicht-kanonischen Limbs, Werten außerhalb des zulässigen Restbereichs und Shift-Zählwerten an den Grenzen.<sup>[[12]](#references)[[13]](#references)</sup>
- Stelle bei jeder Rückgabe sicher, dass die Stack-Höhe stimmt und Werte unterhalb der deklarierten Argumente der Prozedur erhalten bleiben.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Vergleiche gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung.
- Denk daran: Ein gültiger Beweis kann trotzdem die **falsche Aussage** beweisen, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi-/AMM-Exploitation

Wenn du praktische Exploits gegen DEXes und AMMs (Uniswap-v4-Hooks, Ausnutzung von Rundungs-/Präzisionsfehlern, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) recherchierst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Untersuche bei Multi-Asset-Weighted-Pools, die virtuelle Salden zwischenspeichern und bei `supply == 0` manipuliert werden können:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake – Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher Schlüssel und privater Schlüssel erklärt – Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signatur-Transaktionen? – Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privatsphäre – Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Beweis für Quanten-Kryptanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sicherung elliptischer Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [MASM-Decompiler-Architektur](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Statische MASM-Analyse-Engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-zu-Lean-Modell und Korrektheitsbeweise](https://github.com/trailofbits/masm-lean)
- [13] [Auditing im Zeitalter von (gut genuger) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
