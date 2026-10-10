# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, sobald bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Dezentralisierte Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend sowie ein transparentes, überprüfbares Backend.
- **Tokens & Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, während **Security Tokens** den Besitz von Vermögenswerten anzeigen.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** stehen für dezentrale Börsenplattformen beziehungsweise dezentrale autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen gewährleisten die sichere und einvernehmliche Validierung von Transaktionen auf der Blockchain:

- **Proof of Work (PoW)** stützt sich bei der Transaktionsverifizierung auf Rechenleistung.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert im Vergleich zu PoW den Energieverbrauch.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden durch digitale Signaturen validiert, sodass nur der Besitzer des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptbestandteile:

- **Multisignatur-Transaktionen** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Geldquellen), **Outputs** (Ziele), **Gebühren** (die an Miner gezahlt werden) und **Skripten** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden und nur der Endzustand an die Blockchain übermittelt wird.

## Datenschutzprobleme bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Methoden wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Nutzern verschleiern.

## Anonyme Beschaffung von Bitcoins

Zu den Methoden zählen Bargeldgeschäfte, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als gewöhnliche Transaktionen tarnt und so den Datenschutz verbessert.

# Zusammenfassung der Datenschutzangriffe auf Bitcoin

In der Welt von Bitcoin sind der Datenschutz bei Transaktionen und die Anonymität der Nutzer häufig Anlass zur Sorge. Hier folgt ein vereinfachter Überblick über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin verletzen können.<sup>[[6]](#references)</sup>

## **Annahme des gemeinsamen Input-Eigentums**

Es ist allgemein ungewöhnlich, dass Inputs verschiedener Nutzer aufgrund der damit verbundenen Komplexität in einer einzigen Transaktion zusammengeführt werden. Daher wird **häufig angenommen, dass zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO, also ein **nicht ausgegebener Transaktionsoutput**, muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch dessen Privatsphäre beeinträchtigt wird.

### Beispiel

Um dies zu verhindern, können Mixing-Dienste oder mehrere Adressen dabei helfen, die Besitzverhältnisse zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer teilen ihre Bitcoin-Adressen manchmal online, wodurch sich **die Adresse leicht ihrem Besitzer zuordnen lässt**.

## **Analyse des Transaktionsgraphen**

Transaktionen lassen sich als Graphen darstellen. Anhand des Geldflusses können so mögliche Verbindungen zwischen Nutzern aufgedeckt werden.

## **Heuristik für unnötige Inputs (Heuristik für optimales Wechselgeld)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückfließende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn zusätzliche Inputs dazu führen, dass die Change-Ausgabe größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an bereits verwendete Adressen senden und hoffen, dass der Empfänger diese in künftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits genutzten, leeren Adressen eingegangen sind, um diesen Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Change finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; die nicht runde Ausgabe ist wahrscheinlich das Change.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Transaktionserstellung auf. Dadurch können Analysten die verwendete Software und möglicherweise die Change-Adresse identifizieren.
- **Korrelation von Beträgen und Zeitpunkten:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Traffic-Analyse**

Durch die Überwachung des Netzwerk-Traffics können Angreifer Transaktionen oder Blöcke möglicherweise mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer beeinträchtigen. Das gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt und dadurch Transaktionen besser überwachen kann.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Schutzmaßnahmen findest du unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und online gegen Bitcoin eintauschen.
- **Mining**: Bitcoins lassen sich am privatesten durch Mining verdienen, insbesondere wenn man allein minet, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte der Diebstahl von Bitcoin eine weitere Möglichkeit sein, anonym an Bitcoin zu gelangen. Er ist jedoch illegal und wird nicht empfohlen.

## Mixing-Dienste

Bei einem Mixing-Dienst kann ein Nutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch sich der ursprüngliche Besitzer schwerer zurückverfolgen lässt. Dafür muss man dem Dienst jedoch vertrauen, dass er keine Logs führt und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Möglichkeiten zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** fasst mehrere Transaktionen verschiedener Nutzer zu einer zusammen und erschwert dadurch den Versuch, Inputs den Outputs zuzuordnen. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispiele für Transaktionen, bei denen CoinJoin zum Einsatz gekommen sein könnte: `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen findest du unter [CoinJoin](https://coinjoin.io/en). Informationen zu einem Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, findest du unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die für CoinJoin charakteristischen gleichen Outputs. Dadurch ist sie äußerst schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik entkräften, die von Stellen zur Transaktionsüberwachung verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die oben genannten könnten PayJoin sein und die Privatsphäre verbessern, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Die Nutzung von PayJoin könnte traditionelle Überwachungsmethoden erheblich beeinträchtigen** und ist daher eine vielversprechende Entwicklung auf dem Weg zu mehr Transaktionsprivatsphäre.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet eine Full Node maximale Privatsphäre. Alle jemals durchgeführten Transaktionen werden lokal gespeichert, sodass Angreifer nicht erkennen können, für welche Transaktionen oder Adressen sich der Nutzer interessiert.
- **Clientseitige Blockfilterung**: Bei dieser Methode werden für jeden Block in der Blockchain Filter erstellt. So können Wallets relevante Transaktionen erkennen, ohne Netzwerkbeobachtern ihre konkreten Interessen offenzulegen. Lightweight-Wallets laden diese Filter herunter und rufen vollständige Blöcke nur dann ab, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin über ein Peer-to-Peer-Netzwerk betrieben wird, empfiehlt sich die Nutzung von Tor, um die IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre beeinträchtigen, indem Transaktionen derselben Entität zugeordnet werden. Moderne Wallets wirken der Wiederverwendung von Adressen durch ihr Design entgegen.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Eine Zahlung auf mehrere Transaktionen aufzuteilen, kann den Transaktionsbetrag verschleiern und so Angriffe auf die Privatsphäre abwehren.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeld-Ausgaben erhöhen die Privatsphäre, da Methoden zur Erkennung von Wechselgeld erschwert werden.
- **Mehrere Wechselgeld-Ausgaben**: Wenn sich Wechselgeld nicht vermeiden lässt, können mehrere Wechselgeld-Ausgaben die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtfeuer der Anonymität**

Monero wurde so konzipiert, dass die Privatsphäre von Transaktionen im Vordergrund steht.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand für die Ausführung von Vorgängen auf Ethereum und wird in **gwei** angegeben. Eine Transaktion, die beispielsweise 2.310.000 gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Grundgebühr sowie eine Prioritätsgebühr, die Validatoren zur Aufnahme der Transaktion anregen soll. Nutzer können eine maximale Gebühr festlegen, um eine Überzahlung zu vermeiden; der Überschuss wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

An Ethereum-Transaktionen sind ein Sender und ein Empfänger beteiligt, bei denen es sich um Nutzer- oder Smart-Contract-Adressen handeln kann. Für sie ist eine Gebühr erforderlich, und sie müssen in einen Block aufgenommen werden. Zu den wesentlichen Informationen einer Transaktion gehören der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Die Adresse des Senders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen sind grundlegend für alle, die Kryptowährungen nutzen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Komponenten, die Werte verwalten (Signer, Oracles, Bridges, Automatisierung), erfassen, um zu verstehen, wer Gelder bewegen kann und wie.
- Jede Komponente den relevanten MITRE-AADAPT-Taktiken zuordnen, um Privilegienausweitungspfade aufzudecken.
- Flash-Loan-/Oracle-/Credential-/Cross-Chain-Angriffsketten erproben, um die Auswirkungen zu überprüfen und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signatur-Workflows

- Manipulation der Supply Chain von Wallet-UIs kann EIP-712-Payloads unmittelbar vor dem Signieren verändern und gültige Signaturen für Proxy-Übernahmen auf Basis von `delegatecall` abgreifen (z. B. Überschreiben von `slot-0` in `Safe masterCopy`).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account-Abstraktion (ERC-4337)

- Zu den häufigen Fehlerzuständen bei Smart Accounts gehören das Umgehen der Zugriffskontrolle von `EntryPoint`, unsignierte Gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und Gebührenabschöpfung durch Revert nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Sicherheit von Smart Contracts

- Mutation Testing, um blinde Flecken in Testsuiten zu finden:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Gästen

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Proof-Circuit verwendet, um eine Behauptung zu bestätigen, erfährt der Verifier lediglich, dass das **Guest-Programm wie geschrieben ausgeführt wurde**. Enthält der Guest **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover einen Proof erzeugen, der verifiziert wird, obwohl die **öffentlichen Messwerte oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung innerhalb von Proof-Gästen

- Private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Eingaben eines Angreifers** behandeln, selbst wenn sie durch den Proof verborgen sind.
- Sie nicht mit ungeprüften Hilfsfunktionen wie `rkyv::access_unchecked` deserialisieren, es sei denn, die Bytes wurden bereits außerhalb des Systems validiert.
- Enum-Discriminants, relative Zeiger, Längen und Indizes aus nicht vertrauenswürdigen serialisierten Daten validieren, bevor sie die Kontrollflusssteuerung oder den Speicherzugriff beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **außerhalb des gültigen Bereichs liegenden Diskriminantenwert** einschleusen kann, ist jedes nachgelagerte `match` auf diesen Wert verdächtig.

### Jump-table / UB-Umgehung von Zählern

Wenn Rust ein großes `match` in eine **Sprungtabelle** umwandelt, kann ein ungültiger Enum-Diskriminantenwert zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein außerhalb des gültigen Bereichs liegender Diskriminantenwert greift über die erste Sprungtabelle hinaus und landet bei Code, der der zweiten zugeordnet ist.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dadurch das Fälschen von Beweisen ermöglicht werden, die unmögliche Metriken melden, etwa weniger Gates, weniger aufwendige Operationen oder andere gefälschte begrenzte Ressourcen.

Prüfliste:

- Suche nach angreifergesteuerten Enums, die aus Witness-/privaten Eingaben deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen für dasselbe Opcode-/Kind-Feld.
- Behandle die Kombination aus `unsafe`, ungeprüfter Deserialisierung und umfangreicher Opcode-Verarbeitung als besonders riskant.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der Sprungtabelle kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Beweis durchsetzen soll.

Stelle bei reversiblen oder quantenähnlichen Befehlssätzen sicher, dass Operanden, die verschieden sein müssen, tatsächlich auf Verschiedenheit geprüft werden. Eine Toffoli-/CCX-ähnliche Operation, die wie folgt implementiert ist:<sup>[[7]](#references)[[8]](#references)</sup>

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

Dies schafft eine **deterministische Reset-Primitive**, die Annahmen zur Umkehrbarkeit verletzt und kostengünstigere, nicht vorgesehene Berechnungen ermöglicht. In Proof-Systemen, die den Ressourcenverbrauch attestieren, können Angreifer dadurch funktionale Prüfungen bestehen und gleichzeitig das Kostenmodell umgehen, dessen Durchsetzung der Verifizierer annimmt.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Encodings für Witnesses/Private Inputs fuzz testen.
- Die Validierung des Enum-Bereichs vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Instruktionsformen hinzufügen.
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Daran denken: Ein gültiger Proof kann trotzdem die **falsche Aussage** beweisen, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM-Exploitation

Wenn du praktische Exploitation von DEXes und AMMs untersuchst (Uniswap-v4-Hooks, Ausnutzung von Rundungs-/Präzisionsfehlern, durch Flash Loans verstärkte Swaps zum Überschreiten von Schwellenwerten), sieh dir Folgendes an:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für Multi-Asset-Weighted-Pools, die virtuelle Salden cachen und bei `supply == 0` vergiftet werden können, lies:

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
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Proof zur Quantenkryptoanalyse geschlagen](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Sicherung elliptischer Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
