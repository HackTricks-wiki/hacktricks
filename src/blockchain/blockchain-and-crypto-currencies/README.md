# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, sobald bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Dezentrale Anwendungen (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Front-End sowie ein transparentes, überprüfbares Back-End.
- **Tokens und Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** stehen für den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** stehen für dezentrale Handelsplattformen beziehungsweise dezentrale autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Überprüfung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und verringert den Energieverbrauch im Vergleich zu PoW.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden durch digitale Signaturen validiert, sodass nur der Inhaber des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptbestandteile:

- **Multisignatur-Transaktionen** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Geldquelle), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden und nur der endgültige Status an die Blockchain übertragen wird.

## Datenschutzprobleme bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO-Erkennung von Wechselgeldadressen** nutzen Transaktionsmuster aus. Strategien wie **Mixer** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Zu den Methoden zählen Bargeldgeschäfte, Mining und die Verwendung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt und so den Datenschutz verbessert.

# Zusammenfassung der Bitcoin-Datenschutzangriffe

In der Welt von Bitcoin geben der Datenschutz von Transaktionen und die Anonymität der Nutzer häufig Anlass zur Sorge. Hier folgt ein vereinfachter Überblick über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin gefährden können.<sup>[[6]](#references)</sup>

## **Annahme gemeinsamer Input-Eigentümerschaft**

Da es aufgrund der damit verbundenen Komplexität eher selten vorkommt, dass Inputs verschiedener Nutzer in einer einzigen Transaktion zusammengeführt werden, wird oft angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Eigentümer gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO oder **Unspent Transaction Output** muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch dessen Datenschutz gefährdet wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder mehrere Adressen dabei helfen, die Eigentümerschaft zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer veröffentlichen ihre Bitcoin-Adressen mitunter online, wodurch sich **die Adresse leicht ihrem Eigentümer zuordnen lässt**.

## **Analyse des Transaktionsgraphen**

Transaktionen lassen sich als Graphen visualisieren, die anhand des Geldflusses mögliche Verbindungen zwischen Nutzern aufzeigen.

## **Heuristik für unnötige Inputs (Heuristik für optimales Wechselgeld)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn das Hinzufügen weiterer Inputs dazu führt, dass die Change-Ausgabe größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden und darauf hoffen, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins, die an bereits verwendete, leere Adressen gesendet wurden, erneut zu verwenden, um diesen privacy leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld erfolgen wahrscheinlich zwischen zwei Adressen, die demselben Benutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; die nicht runde Ausgabe ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software und möglicherweise die Wechselgeldadresse identifizieren.
- **Korrelation von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen nachvollziehbar machen.

## **Traffic Analysis**

Durch die Überwachung des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Benutzer gefährden. Das gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Möglichkeiten zur Überwachung von Transaktionen verbessert werden.

## Mehr

Eine umfassende Liste von Datenschutzangriffen und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und online gegen Bitcoin eintauschen.
- **Mining**: Bitcoins lassen sich am privatesten durch Mining verdienen, insbesondere wenn man allein mint, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, anonym an Bitcoin zu gelangen. Er ist jedoch illegal und wird nicht empfohlen.

## Mixing Services

Mit einem Mixing Service kann ein Benutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch sich der ursprüngliche Eigentümer nur schwer zurückverfolgen lässt. Dafür muss man jedoch darauf vertrauen, dass der Service keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Optionen zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Benutzer zu einer einzigen zusammen und erschwert es dadurch, Inputs und Outputs einander zuzuordnen. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Beträgen möglicherweise weiterhin zurückverfolgt werden.

Beispiele für Transaktionen, bei denen CoinJoin zum Einsatz gekommen sein könnte, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Informationen zu einem Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

**PayJoin** (oder P2EP), eine Variante von CoinJoin, tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als gewöhnliche Transaktion, ohne die für CoinJoin charakteristischen identischen Outputs. Dadurch ist PayJoin extrem schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik entkräften, die von Stellen zur Transaktionsüberwachung verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die oben genannten könnten PayJoin sein und so die Privatsphäre verbessern, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und ist damit eine vielversprechende Entwicklung im Streben nach Privatsphäre bei Transaktionen.

# Best Practices für den Datenschutz bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Datenschutz und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden sind besonders hervorzuheben:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet eine Full Node ein Höchstmaß an Datenschutz. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass Angreifer nicht erkennen können, für welche Transaktionen oder Adressen sich der Benutzer interessiert.
- **Clientseitige Blockfilterung**: Bei dieser Methode werden Filter für jeden Block in der Blockchain erstellt. So können Wallets relevante Transaktionen erkennen, ohne Netzwerkbeobachtern ihre konkreten Interessen offenzulegen. Leichtgewichtige Wallets laden diese Filter herunter und rufen vollständige Blöcke nur dann ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, empfiehlt sich die Nutzung von Tor, um die IP-Adresse zu verschleiern und so den Datenschutz bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem sie Transaktionen mit derselben Entität verknüpft. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für den Datenschutz bei Transaktionen**

- **Mehrere Transaktionen**: Durch die Aufteilung einer Zahlung auf mehrere Transaktionen lässt sich der Transaktionsbetrag verschleiern und Datenschutzangriffen entgegenwirken.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeldausgaben verbessern den Datenschutz, da sie Methoden zur Erkennung von Wechselgeld erschweren.
- **Mehrere Wechselgeldausgaben**: Wenn sich Wechselgeld nicht vermeiden lässt, kann die Erstellung mehrerer Wechselgeldausgaben den Datenschutz dennoch verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero ist darauf ausgelegt, dem Datenschutz bei Transaktionen Vorrang einzuräumen.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand für die Ausführung von Vorgängen auf Ethereum und wird in **gwei** angegeben. Eine Transaktion, die beispielsweise 2.310.000 gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Basisgebühr sowie eine Prioritätsgebühr, um Validatoren zur Aufnahme der Transaktion zu bewegen. Benutzer können eine maximale Gebühr festlegen, um eine Überzahlung zu vermeiden; der überschüssige Betrag wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

An Ethereum-Transaktionen sind ein Sender und ein Empfänger beteiligt, bei denen es sich jeweils um eine Benutzer- oder Smart-Contract-Adresse handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsdaten gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Bemerkenswert ist, dass sich die Adresse des Senders aus der Signatur ableiten lässt, sodass sie nicht in den Transaktionsdaten enthalten sein muss.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen sind grundlegend für alle, die sich mit Kryptowährungen beschäftigen und dabei Datenschutz und Sicherheit priorisieren möchten.

## Web3 Red Teaming mit Fokus auf Werte

- Komponenten mit Wertbeständen (Signer, Oracles, Bridges, Automatisierung) erfassen, um zu verstehen, wer Gelder bewegen kann und auf welche Weise.
- Jede Komponente den relevanten MITRE-AADAPT-Taktiken zuordnen, um Pfade zur Rechteausweitung aufzudecken.
- Angriffsketten mit Flash Loans, Oracles, Zugangsdaten und Cross-Chain-Techniken durchspielen, um die Auswirkungen zu prüfen und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signatur-Workflows

- Manipulationen an der Lieferkette von Wallet-UIs können EIP-712-Payloads unmittelbar vor der Signatur verändern und so gültige Signaturen für Übernahmen von Proxys auf Basis von `delegatecall` abgreifen (z. B. durch Überschreiben von `masterCopy` in Slot 0 einer Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige Fehlerquellen bei Smart Accounts sind die Umgehung der Zugriffskontrolle von `EntryPoint`, nicht signierte Gasfelder, zustandsbehaftete Validierung, ERC-1271-Replay-Angriffe und Gebührenabfluss durch Reverts nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicherheit von Smart Contracts

- Mutation Testing, um blinde Flecken in Testsuiten zu finden:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Guests

Wenn ein Prover eine **zkVM** oder eine anwendungsspezifische Proof-Schaltung verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Enthält der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover einen Proof erzeugen, der gültig ist, obwohl die **öffentlichen Kennzahlen oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Guests

- Private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingaben** behandeln, auch wenn sie durch den Proof verborgen sind.
- Sie nicht mit ungeprüften Hilfsfunktionen wie `rkyv::access_unchecked` deserialisieren, es sei denn, die Bytes wurden bereits unabhängig davon validiert.
- Enum-Discriminants, relative Pointer, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

If ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` auf diesem Wert verdächtig.

### Jump-table / UB counter bypass

Wenn Rust ein großes `match` in eine **jump table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Constraints**.
2. Ein zweites `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein out-of-range-Discriminant greift über die erste jump table hinaus und landet in Code, der der zweiten zugeordnet ist.

Ergebnis: Die Operation wird trotzdem ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies gefälschte Proofs erzeugen, die unmögliche Metriken melden, etwa weniger Gates, weniger aufwendige Operationen oder andere falsifizierte begrenzte Ressourcen.

Checkliste für die Überprüfung:

- Suche nach angreifergesteuerten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Prüfe wiederholte `match`-Anweisungen für dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + ungeprüfte Deserialisierung + umfangreiche Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf die erzeugte Binärdatei; das Layout der jump table kann wichtiger sein als der Quellcode.

### Fehlende semantische Constraints in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Proof durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Instruktionssätzen sicher, dass Operanden, die verschieden sein müssen, tatsächlich auf Verschiedenheit beschränkt sind. Eine Toffoli-/CCX-ähnliche Operation, implementiert als:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

wird unsicher, wenn der Gast Folgendes nicht zurückweist:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In diesem Fall reduziert sich der Übergang auf:

```text
q = q ^ (q & q) = 0
```

This erzeugt ein **deterministisches Reset-Primitiv**, das Annahmen zur Umkehrbarkeit verletzt und kostengünstigere, nicht vorgesehene Berechnungen ermöglicht. In Proof-Systemen, die den Ressourcenverbrauch attestieren, können Angreifer so Funktionsprüfungen bestehen und gleichzeitig das Kostenmodell umgehen, dessen Durchsetzung der Verifier annimmt.

### Unzureichend eingeschränkte Prover-Hinweise und modulare Arithmetik

Werte, die von einem **Advice-/Witness-Stack** geladen werden, werden vom Prover kontrolliert, selbst wenn sie als vorberechnete Quotienten, Reste, Inverse oder Hinweise beschrieben werden. Ein Proof belegt nur, dass der Witness die implementierten Constraints erfüllt; er belegt nicht, dass die beabsichtigte Berechnung ausgeführt wurde, wenn diesen Constraints eine Prüfung des Typs, des Wertebereichs oder der kanonischen Form fehlt.<sup>[[13]](#references)</sup>

Bei einer Reduktions- oder euklidischen Divisions-Hilfsfunktion solltest du die vollständige Ganzzahlrelation prüfen, nicht nur die abschließende Subtraktion oder Multiplikation. Jede Limb von `q` und `r` muss auf die deklarierte Breite beschränkt sein, die Rekonstruktion `x = q * m + r` muss in der vorgesehenen Ganzzahldarstellung gelten, und die kanonische Schranke `0 <= r < m` muss erzwungen werden. Prüfe einen Wert, **bevor** du ihn an eine engere `u32`-/`u64`-Instruktion übergibst; eine schmalere Operation beweist nicht nachträglich, dass das ursprüngliche Feldelement oder der mehrgliedrige Wert den erwarteten Typ hatte.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Der `mod_12289`-Fehler in Miden veranschaulicht das Exploit-Muster: Der Quotient wurde als zweigliedriger 64-Bit-Wert geprüft, aber der durch Advice bereitgestellte Rest erreichte `u32overflowing_sub` ohne gleichwertige Validierung. Ein böswilliger Prover konnte ungültige Quotienten- und Restwerte so aufeinander abstimmen, dass die implementierten Subtraktionsbedingungen weiterhin erfüllt waren, während die Prozedur einen nicht-mathematischen Rest zurückgab. Da dieses Ergebnis in die Falcon-Verifizierung einfloss, konnte der Soundness-Fehler zu gefälschten Autorisierungssignaturen eskaliert werden, statt lediglich ein falsches Rechenergebnis zu erzeugen.<sup>[[13]](#references)</sup>

### Implizite Stack-basierte kryptografische VMs auditieren

Stack-Sprachen verbergen Operanden. Überführe deshalb zunächst Anweisungen in eine IR, in der jeder verbrauchte und erzeugte Stack-Wert ein Ausdruck mit Herkunftsinformationen ist. Anschließend kann eine konservative Analysepipeline Folgendes tun:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Den Aufrufgraphen erstellen und die Stack-Effekte für Eingaben und Ausgaben von Prozeduren ableiten.
2. Unterstützte Anweisungen symbolisch ausführen und den Kontrollfluss in SSA-/strukturierte Ausdrücke überführen.
3. Abstrakte Fakten wie `Unknown`, `ProvenU32`, `Bool`, die Herkunft eines Werts und die Initialisierung lokaler Variablen bis zu einem Fixpunkt weitergeben.
4. Von Advice abgeleitete Werte markieren, die ohne Bereinigung auf typisierte Arithmetik oder Senken mit Nichtnull-Anforderung treffen — und zwar, wenn dies auf **jedem** eingehenden Pfad geschieht.
5. Deklarierte und abgeleitete Signaturen vergleichen und sicherstellen, dass jeder Exit die vom Aufrufer bereitgestellten Stack-Werte erhält.

Behandle eine unbekannte Signatur oder ein nicht unterstütztes Konstrukt als **Analyserückstand**, nicht als unbedenkliches Ergebnis. Dynamische Aufrufe, Schleifen, die den Stack-Effekt nicht erhalten, und Verzweigungen mit unterschiedlichen Stack-Effekten können eine zuverlässige Zuordnung von Stack-Slots unmöglich machen. Ein sichererer Decompiler weist diese Fälle zurück oder markiert sie, statt plausiblen, aber falschen Pseudocode auszugeben.<sup>[[10]](#references)[[13]](#references)</sup>

Behalte an Kontrollfluss-Zusammenführungen eine Eigenschaft nur dann bei, wenn sie für jeden Vorgänger gilt (zum Beispiel `ProvenU32 join Unknown = Unknown`). Unterscheide außerdem zwischen der Konvergenz bis zu einem Fixpunkt und dem Erreichen einer Iterationsgrenze: Nur eine konvergierte, sounde Überapproximation kann rechtfertigen, das Fehlen eines Befunds als Beleg dafür zu werten, dass alle dargestellten Ausführungen die Eigenschaft erfüllen.<sup>[[11]](#references)</sup>

### Versteckte Vorbedingungen mithilfe von Beweispflichten aufdecken

Übersetze Prozeduren bei kleinen Befehlssätzen in ein ausführbares formales VM-Modell und beweise sowohl das Ergebnis als auch die vollständige Stack-Transformation. Der Satz sollte Terminierung, typisierte Eingaben, das erwartete Ausgabepräfix und die Erhaltung des unangetasteten Aufrufer-Stacks abdecken. Prüfe die Aussage des Satzes ebenso sorgfältig wie den Beweis: Der Kernel kann auch einen Beweis für eine versehentlich abgeschwächte Behauptung validieren.<sup>[[12]](#references)[[13]](#references)</sup>

Unerwartete Hypothesen sind nützliche Befunde. Bei der Miden-Überprüfung erforderte ein Beweis für eine 64-Bit-Rechtsrotation `shift mod 32 != 0`. Dadurch wurde ein fehlerhafter Randfall für große Eingaben aufgedeckt, bei denen die Verschiebung ein Vielfaches von 32 war. Ein anderer Beweis ergab, dass `wrapping_mul` für 256-Bit-Werte vom Aufrufer bereitgestellte Stack-Werte verwarf. Nimm den entdeckten Randfall in die Tests auf und behebe dann die Implementierung oder verschärfe bewusst die öffentliche Vorbedingung, statt die zusätzliche Annahme stillschweigend zu akzeptieren.<sup>[[12]](#references)[[13]](#references)</sup>

### Was in ZK-Systemen getestet werden sollte

- Alle Parser der Guest-Programme mit fehlerhaften Kodierungen von Witnesses/privaten Eingaben fuzz testen.
- Eine Enum-Bereichsprüfung vor dem Dispatch von Opcodes sicherstellen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Anweisungsformen ergänzen.
- Jede Advice-/Witness-Quelle bis zu jeder Senke für typisierte Arithmetik nachverfolgen und eine Validierung auf jedem Pfad verlangen.<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetische Hilfsfunktionen mit nicht-kanonischen Limbs, außerhalb des gültigen Bereichs liegenden Resten und Randwerten für Shift-Anzahlen testen.<sup>[[12]](#references)[[13]](#references)</sup>
- Bei jeder Rückgabe die Stack-Höhe und den Erhalt der Werte unterhalb der deklarierten Argumente der Prozedur sicherstellen.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Bedenke, dass ein gültiger Beweis trotzdem die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi-/AMM-Exploitation

Wenn du praktische Ausnutzung von DEXes und AMMs (Uniswap-v4-Hooks, Missbrauch von Rundung/Präzision, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) recherchierst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für gewichtete Pools mit mehreren Assets, die virtuelle Salden zwischenspeichern und bei `supply == 0` vergiftet werden können, siehe:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake – Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher und privater Schlüssel erklärt – Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Transaktionen mit mehreren Signaturen? – Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz – Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Beweis für Quantenkryptanalyse gebrochen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Absicherung von Kryptowährungen mit elliptischen Kurven gegen Quantenanfälligkeiten: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architektur des MASM-Decompilers](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Statische MASM-Analyse-Engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-zu-Lean-Modell und Korrektheitsbeweise](https://github.com/trailofbits/masm-lean)
- [13] [Auditing im Zeitalter von (gut genuger) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
