# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

Dieses Kapitel behandelt Blockchain-Konzepte und On-Chain-Sicherheit. Beginne bei einem offengelegten Bitcoin-Peer mit der [Bitcoin P2P service enumeration](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); für ein Browser-Frontend, eine Wallet-Verbindung oder ein Off-Chain-Backend verwende [DApp pentesting](../../pentesting-web/dapps-DecentralizedApplications.md). Informationen zu Datenschutzoperationen im Zusammenhang mit Kryptowährungen und deren Grenzen findest du im [cryptocurrency privacy chapter](../../privacy/cryptocurrency-privacy.md).

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, sobald bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Zwischenhändler.
- **Dezentralisierte Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens und Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, **Security Tokens** verbriefen den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Instanzen.
- **DEX** und **DAOs** stehen für dezentrale Börsenplattformen beziehungsweise dezentrale autonome Organisationen.

Begriffe für Spot-Orders, Futures, Leverage und Optionen auf Kryptomärkten findest du unter [Investment Terms](investment-terms.md). Informationen zum Missbrauch von Funding-Rates in Perpetual-Protokollen findest du unter [Perpetual Funding-Rate Exploitation](perpetual-funding-rate-exploitation.md).

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Verifizierung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und senkt dadurch den Energieverbrauch im Vergleich zu PoW.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden mithilfe digitaler Signaturen validiert, sodass nur der Inhaber des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Geldquelle), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Das Lightning Network soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden. Nur der endgültige Zustand wird an die Blockchain übertragen.

## Datenschutzprobleme bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Methoden wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Zu den Methoden zählen Bargeldtransaktionen, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als gewöhnliche Transaktionen tarnt und so für mehr Datenschutz sorgt.

# Zusammenfassung der Bitcoin-Datenschutzangriffe

In der Welt von Bitcoin geben der Datenschutz von Transaktionen und die Anonymität der Nutzer häufig Anlass zur Sorge. Hier folgt ein vereinfachter Überblick über einige gängige Methoden, mit denen Angreifer den Datenschutz von Bitcoin beeinträchtigen können.<sup>[[6]](#references)</sup>

## **Annahme gemeinsamer Input-Inhaberschaft**

Aufgrund der Komplexität werden Inputs verschiedener Nutzer nur selten in einer einzelnen Transaktion zusammengefasst. Daher wird oft angenommen, dass **zwei Input-Adressen derselben Transaktion demselben Inhaber gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO, also ein **nicht ausgegebener Transaktionsoutput**, muss bei einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, was den Datenschutz beeinträchtigt.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder mehrere Adressen dabei helfen, die Inhaberschaft zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch sich **die Adresse leicht ihrem Inhaber zuordnen lässt**.

## **Analyse von Transaktionsgraphen**

Transaktionen lassen sich als Graphen darstellen. Anhand des Geldflusses werden so mögliche Verbindungen zwischen Nutzern sichtbar.

## **Heuristik für unnötige Inputs (Heuristik für optimales Wechselgeld)**

Diese Heuristik analysiert Transaktionen mit mehreren Inputs und Outputs, um zu schätzen, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn das Hinzufügen weiterer Eingaben dazu führt, dass die Wechselgeld-Ausgabe größer ist als jede einzelne Eingabe, kann dies die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an bereits verwendete Adressen senden und darauf hoffen, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Eingaben zusammenfasst und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die an bereits genutzte, leere Adressen gesendet wurden, um diesen privacy leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; die nicht runde Ausgabe ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software und möglicherweise die Wechselgeldadresse identifizieren.
- **Korrelationen zwischen Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann dazu führen, dass Transaktionen zurückverfolgt werden können.

## **Datenverkehrsanalyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Dies gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Möglichkeiten zur Überwachung von Transaktionen erweitert werden.

## Mehr

Eine umfassende Liste von Datenschutzangriffen und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, anonym Bitcoins zu erhalten

- **Bargeldtransaktionen**: Bitcoin gegen Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und online gegen Bitcoin eintauschen.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist Mining, insbesondere allein, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, es anonym zu erwerben, obwohl dies illegal und nicht empfehlenswert ist.

## Mixing-Dienste

Mit einem Mixing-Dienst kann ein Nutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch es schwierig wird, den ursprünglichen Besitzer zurückzuverfolgen. Dazu muss man dem Dienst jedoch vertrauen, dass er keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Optionen zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Nutzer zu einer einzigen zusammen und erschwert so den Versuch, Eingaben den Ausgaben zuzuordnen. Trotz seiner Effektivität können Transaktionen mit einzigartigen Eingabe- und Ausgabegrößen weiterhin möglicherweise zurückverfolgt werden.

Beispiele für Transaktionen, bei denen möglicherweise CoinJoin verwendet wurde, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die charakteristischen gleich hohen Ausgaben von CoinJoin. Dadurch ist PayJoin extrem schwer zu erkennen und könnte die Heuristik des gemeinsamen Eingentums an Eingaben entkräften, die von Stellen zur Transaktionsüberwachung verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die oben genannten könnten PayJoin sein, die den Datenschutz verbessern und dabei von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich beeinträchtigen** und ist daher eine vielversprechende Entwicklung im Streben nach Datenschutz bei Transaktionen.

# Best Practices für Datenschutz bei Kryptowährungen

## **Techniken zur Wallet-Synchronisierung**

Um Datenschutz und Sicherheit zu gewährleisten, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full Node maximalen Datenschutz. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass Angreifer nicht erkennen können, an welchen Transaktionen oder Adressen der Benutzer interessiert ist.
- **Client-seitige Blockfilterung**: Bei dieser Methode werden Filter für jeden Block in der Blockchain erstellt. So können Wallets relevante Transaktionen erkennen, ohne Netzwerkbeobachtern spezifische Interessen offenzulegen. Lightweight Wallets laden diese Filter herunter und rufen vollständige Blöcke nur dann ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin über ein Peer-to-Peer-Netzwerk betrieben wird, wird die Verwendung von Tor empfohlen, um die IP-Adresse zu verschleiern und den Datenschutz bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann den Datenschutz beeinträchtigen, indem Transaktionen derselben Entität zugeordnet werden. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für den Datenschutz bei Transaktionen**

- **Mehrere Transaktionen**: Wird eine Zahlung auf mehrere Transaktionen aufgeteilt, kann dies den Transaktionsbetrag verschleiern und Datenschutzangriffe vereiteln.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeld-Ausgaben bieten besseren Datenschutz, da sie Methoden zur Erkennung von Wechselgeld stören.
- **Mehrere Wechselgeld-Ausgaben**: Ist es nicht möglich, Wechselgeld zu vermeiden, kann die Erzeugung mehrerer Wechselgeld-Ausgaben den Datenschutz dennoch verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero wurde so konzipiert, dass der Datenschutz bei Transaktionen Vorrang hat.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand für die Ausführung von Vorgängen auf Ethereum und wird in **gwei** angegeben. Eine Transaktion, die beispielsweise 2.310.000 gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Grundgebühr sowie eine Prioritätsgebühr, die Validatoren zur Aufnahme der Transaktion anregen soll. Benutzer können eine maximale Gebühr festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen; der Überschuss wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

Transaktionen auf Ethereum umfassen einen Absender und einen Empfänger, bei denen es sich jeweils um eine Benutzer- oder Smart-Contract-Adresse handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsinformationen gehören der Empfänger, die Signatur des Absenders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Die Adresse des Absenders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden die Grundlage für alle, die Kryptowährungen nutzen und dabei Datenschutz und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Werteführende Komponenten (Signer, Oracles, Bridges, Automatisierung) erfassen, um zu verstehen, wer Gelder bewegen kann und wie.
- Jede Komponente relevanten MITRE-AADAPT-Taktiken zuordnen, um Pfade zur Rechteausweitung aufzudecken.
- Angriffsketten mit Flash Loans, Oracles, Zugangsdaten und Cross-Chain-Aktionen durchspielen, um die Auswirkungen zu überprüfen und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signatur-Workflows

- Supply-Chain-Manipulationen an Wallet-UIs können EIP-712-Payloads unmittelbar vor dem Signieren verändern und so gültige Signaturen für delegatecall-basierte Proxy-Übernahmen abgreifen (z. B. durch Überschreiben von `masterCopy` in Slot 0 von Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Zu den häufigen Fehlerarten bei Smart Accounts gehören das Umgehen der Zugriffskontrolle von `EntryPoint`, unsignierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay-Angriffe und das Abschöpfen von Gebühren durch einen Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Auffinden von Schwachstellen in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Guests

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Proof-Circuit verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Enthält der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover einen gültigen Proof erzeugen, obwohl die **öffentlichen Kennzahlen oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Guests

- Private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingaben** behandeln, auch wenn sie durch den Proof verborgen sind.
- Sie nicht mit ungeprüften Hilfsfunktionen wie `rkyv::access_unchecked` deserialisieren, sofern die Bytes nicht bereits außerhalb des Systems validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` auf diesem Wert verdächtig.

### Jump-Table-/UB-Counter-Bypass

Wenn Rust ein großes `match` in eine **Jump Table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein out-of-range Discriminant greift über die erste Jump Table hinaus und landet in Code, der zur zweiten gehört.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies Beweise fälschen, die unmögliche Kennzahlen melden, etwa weniger Gates, weniger aufwendige Operationen oder andere verfälschte begrenzte Ressourcen.

Prüfliste:

- Suche nach angreiferkontrollierten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen über dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + ungeprüfte Deserialisierung + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der Jump Table kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Beweis durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Instruktionssätzen sicher, dass Operanden, die verschieden sein müssen, tatsächlich auf Verschiedenheit eingeschränkt sind. Eine Toffoli-/CCX-ähnliche Operation, die wie folgt implementiert ist:<sup>[[7]](#references)[[8]](#references)</sup>

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

This erzeugt ein **deterministisches Reset-Primitiv**, das Annahmen zur Umkehrbarkeit verletzt und kostengünstigere, nicht beabsichtigte Berechnungen ermöglicht. In Beweissystemen, die den Ressourcenverbrauch attestieren, können Angreifer dadurch funktionale Prüfungen bestehen und zugleich das Kostenmodell umgehen, dessen Durchsetzung der Verifier annimmt.

### Unzureichend beschränkte Prover-Hinweise und modulare Arithmetik

Werte, die von einem **Advice-/Witness-Stack geladen werden, werden vom Prover kontrolliert**, auch wenn sie als vorberechnete Quotienten, Reste, Inverse oder Hinweise bezeichnet werden. Ein Beweis stellt nur fest, dass der Witness die implementierten Constraints erfüllt; er belegt nicht, dass die beabsichtigte Berechnung ausgeführt wurde, wenn diese Constraints eine Prüfung des Typs, des Wertebereichs oder der kanonischen Form auslassen.<sup>[[13]](#references)</sup>

Bei einem Reduktions- oder euklidischen Divisionshelfer solltest du die vollständige ganzzahlige Relation prüfen, nicht nur die abschließende Subtraktion oder Multiplikation. Jedes Limb von `q` und `r` muss auf seine deklarierte Breite beschränkt sein, die Rekonstruktion `x = q * m + r` muss in der vorgesehenen Ganzzahldarstellung gelten und die kanonische Schranke `0 <= r < m` muss erzwungen werden. Prüfe einen Wert **bevor** du ihn an eine schmalere `u32`-/`u64`-Instruktion übergibst; eine schmale Operation beweist nicht nachträglich, dass das ursprüngliche Feldelement oder der Multi-Limb-Wert den erwarteten Typ hatte.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

Der `mod_12289`-Fehler in Miden veranschaulicht das Exploit-Muster: Der Quotient wurde als zweigliedriger 64-Bit-Wert geprüft, aber der durch Advice bereitgestellte Rest erreichte `u32overflowing_sub` ohne entsprechende Validierung. Ein bösartiger Prover konnte ungültige Quotienten- und Restwerte so aufeinander abstimmen, dass die implementierten Subtraktionsbedingungen weiterhin erfüllt waren, während die Prozedur einen mathematisch falschen Rest zurückgab. Da dieses Ergebnis in die Falcon-Verifizierung einfloss, ließ sich der Soundness-Fehler zu gefälschten Autorisierungssignaturen eskalieren, statt lediglich ein falsches arithmetisches Ergebnis zu erzeugen.<sup>[[13]](#references)</sup>

### Implizite Stack-VMs für Kryptografie auditieren

Stack-Sprachen verbergen Operanden. Überführt daher zunächst die Instruktionen in eine IR, in der jeder verbrauchte und erzeugte Stack-Wert ein Ausdruck mit Herkunftsinformationen ist. Eine konservative Analysepipeline kann dann Folgendes tun:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Den Aufrufgraphen erstellen und die Stack-Effekte für Eingaben und Ausgaben von Prozeduren ableiten.
2. Unterstützte Instruktionen symbolisch ausführen und den Kontrollfluss in SSA-/strukturierte Ausdrücke überführen.
3. Abstrakte Fakten wie `Unknown`, `ProvenU32`, `Bool`, Wert-Herkunft und lokale Initialisierung bis zu einem Fixpunkt propagieren.
4. Von Advice abgeleitete Werte kennzeichnen, die ohne einen Sanitizer auf **jedem** eingehenden Pfad typisierte Arithmetik oder Senken mit Nicht-Null-Bedingung erreichen.
5. Deklarierte und abgeleitete Signaturen vergleichen und prüfen, ob jeder Exit die dem Aufrufer gehörenden Stack-Werte erhält.

Behandelt eine unbekannte Signatur oder ein nicht unterstütztes Konstrukt als **Analyselücke**, nicht als sauberes Ergebnis. Dynamische Aufrufe, Schleifen, die den Stack nicht neutral lassen, und Verzweigungen mit unterschiedlichen Stack-Effekten können eine verlässliche Nachverfolgung der Stack-Slots unmöglich machen. Ein sichererer Decompiler weist solche Fälle zurück oder kennzeichnet sie, statt plausiblen, aber falschen Pseudocode auszugeben.<sup>[[10]](#references)[[13]](#references)</sup>

An Kontrollfluss-Zusammenführungen sollte eine Eigenschaft nur dann erhalten bleiben, wenn sie für jeden Vorgänger gilt (zum Beispiel `ProvenU32 join Unknown = Unknown`). Unterscheidet außerdem die Konvergenz am Fixpunkt davon, dass ein Iterationslimit erreicht wurde: Nur eine konvergierte, sounde Überapproximation rechtfertigt es, das Ausbleiben einer Diagnose als Beleg dafür zu werten, dass alle dargestellten Ausführungen die Eigenschaft erfüllen.<sup>[[11]](#references)</sup>

### Versteckte Vorbedingungen mit Beweispflichten aufdecken

Bei kleinen Instruktionssätzen sollten Prozeduren in ein ausführbares formales VM-Modell übersetzt und sowohl das Ergebnis als auch die vollständige Stack-Transformation bewiesen werden. Der Satz sollte Terminierung, typisierte Eingaben, das erwartete Ausgabepräfix und den Erhalt des unveränderten Aufruferstacks abdecken. Prüft die Aussage des Satzes ebenso sorgfältig wie den Beweis: Der Kernel kann auch einen Beweis für eine versehentlich abgeschwächte Aussage validieren.<sup>[[12]](#references)[[13]](#references)</sup>

Unerwartete Hypothesen sind nützliche Erkenntnisse. Bei der Miden-Prüfung erforderte ein Beweis für eine 64-Bit-Rotation nach rechts `shift mod 32 != 0`. Dadurch wurde ein Fehlerfall für große Eingaben sichtbar, wenn die Verschiebung ein Vielfaches von 32 war. Ein weiterer Beweis ergab, dass `wrapping_mul` für 256 Bit dem Aufrufer gehörende Stack-Werte verwarf. Ergänzt den entdeckten Grenzfall in den Tests und behebt dann die Implementierung oder verschärft bewusst die öffentliche Vorbedingung, statt die zusätzliche Annahme stillschweigend zu akzeptieren.<sup>[[12]](#references)[[13]](#references)</sup>

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Witness-/Private-Input-Kodierungen fuzz testen.
- Die Validierung des Enum-Wertebereichs vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen für Operanden-Aliasing und andere ungültige Instruktionsformen hinzufügen.
- Jede Advice-/Witness-Quelle bis zu jeder Senke für typisierte Arithmetik nachverfolgen und auf jedem Pfad Validierung verlangen.<sup>[[11]](#references)[[13]](#references)</sup>
- Arithmetik-Helper mit nicht kanonischen Limbs, Werten außerhalb des zulässigen Restbereichs und grenzwertigen Shift-Werten testen.<sup>[[12]](#references)[[13]](#references)</sup>
- Bei jeder Rückgabe die Stack-Höhe und den Erhalt der Werte unterhalb der deklarierten Argumente der Prozedur sicherstellen.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Bedenkt, dass ein gültiger Beweis trotzdem die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-Exploitation

Wenn ihr praktische Exploitation von DEXes und AMMs (Uniswap v4 Hooks, Missbrauch von Rundung/Präzision, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten) untersucht, seht euch Folgendes an:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für gewichtete Multi-Asset-Pools, die virtuelle Salden zwischenspeichern und bei `supply == 0` vergiftet werden können, lest:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher Schlüssel und privater Schlüssel erklärt - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Transaktionen mit mehreren Signaturen? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Wir haben Googles Zero-Knowledge-Beweis für Quanten-Kryptanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sicherung von Elliptic-Curve-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Architektur des MASM-Decompilers](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Statische MASM-Analyse-Engine](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [MASM-to-Lean-Modell und Korrektheitsbeweise](https://github.com/trailofbits/masm-lean)
- [13] [Auditing im Zeitalter der (gut genug) KI](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
