# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, sobald bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Dezentralisierte Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens und Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, während **Security Tokens** den Besitz von Vermögenswerten anzeigen.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** stehen jeweils für dezentralisierte Börsenplattformen und dezentrale autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Verifizierung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und verbraucht im Vergleich zu PoW weniger Energie.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Inhaber des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Quelle der Gelder), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden und nur der endgültige Zustand an die Blockchain übertragen wird.

## Datenschutzbedenken bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Nutzern verschleiern.

## Anonyme Beschaffung von Bitcoins

Zu den Methoden gehören Bargeldgeschäfte, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgung zu erschweren, während **PayJoin** CoinJoins als gewöhnliche Transaktionen tarnt und so den Datenschutz verbessert.

# Zusammenfassung der Bitcoin-Datenschutzangriffe

In der Welt von Bitcoin geben der Datenschutz von Transaktionen und die Anonymität der Nutzer häufig Anlass zur Sorge. Hier ist ein vereinfachter Überblick über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin verletzen können.<sup>[[6]](#references)</sup>

## **Annahme gemeinsamer Input-Eigentümerschaft**

Es ist generell selten, dass Inputs verschiedener Nutzer aufgrund der damit verbundenen Komplexität in einer einzelnen Transaktion zusammengeführt werden. Daher wird oft angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO, also ein **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch dessen Datenschutz beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder die Verwendung mehrerer Adressen dabei helfen, die Eigentümerschaft zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch sich **die Adresse leicht ihrem Besitzer zuordnen lässt**.

## **Analyse des Transaktionsgraphen**

Transaktionen lassen sich als Graphen darstellen und können mögliche Verbindungen zwischen Nutzern auf Grundlage des Geldflusses aufzeigen.

## **Heuristik zu unnötigen Inputs (Optimal-Change-Heuristik)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückgegebene Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn weitere Inputs dazu führen, dass die Change-Ausgabe größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an zuvor verwendete Adressen senden und darauf hoffen, dass der Empfänger diese bei künftigen Transaktionen mit anderen Inputs zusammenfasst. Dadurch werden Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins, die an bereits verwendete, leere Adressen gesendet wurden, erneut zu verwenden, um diesen Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; die Ausgabe mit dem nicht runden Betrag ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software und möglicherweise die Wechselgeldadresse identifizieren.
- **Korrelationen von Betrag und Zeitpunkt:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen rückverfolgbar machen.

## **Traffic-Analyse**

Durch die Überwachung des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer beeinträchtigen. Das gilt insbesondere, wenn eine Instanz viele Bitcoin-Nodes betreibt und dadurch Transaktionen besser überwachen kann.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Abwehrmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, anonym Bitcoins zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und diese online gegen Bitcoin eintauschen.
- **Mining**: Bitcoins lassen sich am privatesten durch Mining verdienen, insbesondere beim alleinigen Mining, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, anonym an Bitcoin zu gelangen. Er ist jedoch illegal und nicht empfehlenswert.

## Mixing-Services

Mit einem Mixing-Service kann ein Nutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch sich der ursprüngliche Besitzer schwerer zurückverfolgen lässt. Dafür muss man dem Service jedoch vertrauen, dass er keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Möglichkeiten zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Nutzer zu einer einzigen zusammen. Dadurch wird es für andere schwieriger, Inputs den Outputs zuzuordnen. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispiele für Transaktionen, bei denen CoinJoin zum Einsatz gekommen sein könnte, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt eine Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als gewöhnliche Transaktion, ohne die für CoinJoin charakteristischen gleichen Outputs. Dadurch ist sie extrem schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik ungültig machen, die von Instanzen zur Überwachung von Transaktionen eingesetzt wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die obige könnten PayJoin sein und so die Privatsphäre verbessern, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich beeinträchtigen** und ist damit eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu gewährleisten, ist es entscheidend, Wallets mit der Blockchain zu synchronisieren. Zwei Methoden stechen hervor:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full Node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert. So können Angreifer nicht erkennen, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Clientseitige Blockfilterung**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt, mit denen Wallets relevante Transaktionen erkennen können, ohne ihre spezifischen Interessen gegenüber Netzwerkbeobachtern offenzulegen. Leichtgewichtige Wallets laden diese Filter herunter und rufen vollständige Blöcke nur dann ab, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin über ein Peer-to-Peer-Netzwerk betrieben wird, empfiehlt sich die Verwendung von Tor, um die IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre beeinträchtigen, indem sie Transaktionen derselben Entität zuordnet. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für die Privatsphäre bei Transaktionen**

- **Mehrere Transaktionen**: Eine Zahlung auf mehrere Transaktionen aufzuteilen, kann den Transaktionsbetrag verschleiern und so Angriffe auf die Privatsphäre vereiteln.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeld-Outputs verbessern die Privatsphäre, da sie Methoden zur Erkennung von Wechselgeld erschweren.
- **Mehrere Wechselgeld-Outputs**: Wenn sich Wechselgeld nicht vermeiden lässt, kann die Erstellung mehrerer Wechselgeld-Outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero ist darauf ausgelegt, die Privatsphäre von Transaktionen in den Vordergrund zu stellen.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der für die Ausführung von Vorgängen auf Ethereum erforderlich ist, und wird in **gwei** bepreist. Beispielsweise umfasst eine Transaktion, die 2.310.000 gwei (oder 0,00231 ETH) kostet, ein Gas-Limit und eine Basisgebühr sowie eine Prioritätsgebühr, die Validatoren zur Aufnahme der Transaktion anregt. Nutzer können eine maximale Gebühr festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen; der überschüssige Betrag wird erstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

Transaktionen auf Ethereum umfassen einen Absender und einen Empfänger, bei denen es sich jeweils um Adressen von Nutzern oder Smart Contracts handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsdaten gehören der Empfänger, die Signatur des Absenders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Die Adresse des Absenders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen sind grundlegend für alle, die Kryptowährungen nutzen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Web3 Red Teaming mit Fokus auf Werte

- Bestandsaufnahme werttragender Komponenten (Signer, Oracles, Bridges, Automatisierung), um zu verstehen, wer Gelder bewegen kann und wie.
- Jede Komponente den relevanten MITRE-AADAPT-Taktiken zuordnen, um Privilegienausweitungspfade aufzudecken.
- Flash-Loan-, Oracle-, Credential- und Cross-Chain-Angriffsketten durchspielen, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signatur-Workflows

- Manipulation der Lieferkette von Wallet-UIs kann EIP-712-Payloads unmittelbar vor der Signatur verändern und so gültige Signaturen für Proxy-Übernahmen auf Basis von `delegatecall` abgreifen (z. B. das Überschreiben von `masterCopy` in Slot 0 einer Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Zu den häufigen Fehlerbildern bei Smart Accounts zählen die Umgehung der `EntryPoint`-Zugriffskontrolle, nicht signierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und das Abschöpfen von Gebühren durch einen Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutation Testing zum Aufdecken blinder Flecken in Testsuiten:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Beweisen / zkVM-Gästen

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Beweisschaltkreis verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Gastprogramm wie vorgegeben ausgeführt wurde**. Enthält der Gast **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover einen gültigen Beweis erzeugen, obwohl die **öffentlichen Messwerte oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung in Beweis-Gästen

- Behandle private Witness- bzw. Schaltkreis-Bytes als **nicht vertrauenswürdige Angreifereingaben**, selbst wenn sie durch den Beweis verborgen sind.
- Vermeide ihre Deserialisierung mit nicht geprüften Hilfsfunktionen wie `rkyv::access_unchecked`, sofern die Bytes nicht bereits außerhalb des Systems validiert wurden.
- Enum-Discriminants, relative Zeiger, Längen und Indizes, die aus nicht vertrauenswürdigen serialisierten Daten geladen werden, müssen validiert werden, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` auf diesem Wert verdächtig.

### Jump-Table-/UB-Counter-Bypass

Wenn Rust ein großes `match` in eine **Jump-Table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein out-of-range Discriminant indiziert über die erste Jump-Table hinaus und landet in Code, der zur zweiten gehört.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies gefälschte Proofs erzeugen, die unmögliche Kennzahlen melden, etwa weniger Gates, weniger aufwendige Operationen oder andere verfälschte begrenzte Ressourcen.

Prüfliste:

- Suche nach vom Angreifer kontrollierten Enums, die aus Witness-/Private-Input deserialisiert werden.
- Prüfe wiederholte `match`-Anweisungen für dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + ungeprüfte Deserialisierung + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-Engineere bei Bedarf die erzeugte Binärdatei; das Layout der Jump-Table kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Proof durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Instruktionssätzen sicher, dass Operanden, die verschieden sein müssen, auch tatsächlich als verschieden eingeschränkt sind. Eine Toffoli-/CCX-ähnliche Operation, implementiert als:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

wird unsicher, wenn der Gast nicht ablehnt:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In diesem Fall vereinfacht sich der Übergang zu:

```text
q = q ^ (q & q) = 0
```

Dies erzeugt ein **deterministisches Reset-Primitiv**, das Annahmen zur Umkehrbarkeit aufbricht und kostengünstigere, nicht vorgesehene Berechnungen ermöglicht. In Beweissystemen, die den Ressourcenverbrauch attestieren, können Angreifer dadurch funktionale Prüfungen bestehen und zugleich das Kostenmodell umgehen, dessen Durchsetzung der Verifizierer annimmt.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Encodings von Witnesses und privaten Eingaben fuzz testen.
- Die Enum-Bereichsvalidierung vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen für Operand-Aliasing und andere ungültige Instruktionsformen hinzufügen.
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Beachten, dass ein gültiger Beweis trotzdem die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi-/AMM-Exploitation

Wenn du praktische Exploitation von DEXes und AMMs untersuchst (Uniswap-v4-Hooks, Rundungs-/Präzisionsmissbrauch, durch Flash Loans verstärkte Swaps, die Schwellenwerte überschreiten), lies:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset-gewichtete Pools, die virtuelle Kontostände cachen und vergiftet werden können, wenn `supply == 0`, lies:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake – Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher Schlüssel und privater Schlüssel erklärt – Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signature-Transaktionen? – Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz – Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Beweis für Quantenkryptanalyse besiegt](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Absicherung elliptischer Kurven-Kryptowährungen gegen Quantenbedrohungen: Ressourcenschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
