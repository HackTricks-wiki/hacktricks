# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind. Sie automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Dezentrale Anwendungen (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Front-End sowie ein transparentes, überprüfbares Back-End.
- **Tokens und Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten einen Wert oder Besitz repräsentieren.
  - **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** stehen für den Besitz von Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** stehen für dezentrale Börsenplattformen beziehungsweise dezentrale autonome Organisationen.

## Konsensmechanismen

Konsensmechanismen gewährleisten sichere und einvernehmliche Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** nutzt Rechenleistung zur Überprüfung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert so den Energieverbrauch im Vergleich zu PoW.<sup>[[1]](#references)</sup>

## Bitcoin-Grundlagen

### Transaktionen

Bei Bitcoin-Transaktionen werden Gelder zwischen Adressen übertragen. Transaktionen werden mithilfe digitaler Signaturen validiert. So wird sichergestellt, dass nur der Besitzer des privaten Schlüssels Überweisungen veranlassen kann.<sup>[[2]](#references)</sup>

#### Hauptkomponenten:

- **Multisignatur-Transaktionen** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.<sup>[[3]](#references)</sup>
- Transaktionen bestehen aus **Inputs** (Geldquelle), **Outputs** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Soll die Skalierbarkeit von Bitcoin verbessern, indem mehrere Transaktionen innerhalb eines Kanals ermöglicht werden und nur der endgültige Status an die Blockchain übertragen wird.

## Datenschutzbedenken bei Bitcoin

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Nutzern verschleiern.

## Anonyme Beschaffung von Bitcoins

Zu den Methoden zählen Bargeldgeschäfte, Mining und die Verwendung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgung zu erschweren. **PayJoin** tarnt CoinJoins als reguläre Transaktionen und sorgt so für mehr Datenschutz.

# Zusammenfassung der Bitcoin-Datenschutzangriffe

In der Welt von Bitcoin sind der Datenschutz bei Transaktionen und die Anonymität der Nutzer häufig Gegenstand von Bedenken. Hier ist eine vereinfachte Übersicht über einige gängige Methoden, mit denen Angreifer den Datenschutz bei Bitcoin gefährden können.<sup>[[6]](#references)</sup>

## **Annahme des gemeinsamen Input-Besitzes**

Es ist generell ungewöhnlich, Inputs verschiedener Nutzer in einer einzelnen Transaktion zusammenzuführen, da dies komplex ist. Daher wird **oft angenommen, dass zwei Input-Adressen derselben Transaktion demselben Besitzer gehören**.

## **Erkennung von UTXO-Wechselgeldadressen**

Ein UTXO, also ein **nicht ausgegebener Transaktions-Output**, muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil davon an eine andere Adresse gesendet, geht der Rest an eine neue Wechselgeldadresse. Beobachter können annehmen, dass diese neue Adresse dem Absender gehört, wodurch der Datenschutz gefährdet wird.

### Beispiel

Um dem entgegenzuwirken, können Mixing-Dienste oder mehrere Adressen dabei helfen, den Besitz zu verschleiern.

## **Offenlegung in sozialen Netzwerken und Foren**

Nutzer veröffentlichen ihre Bitcoin-Adressen manchmal online, wodurch sich die Adresse **leicht ihrem Besitzer zuordnen lässt**.

## **Analyse von Transaktionsgraphen**

Transaktionen lassen sich als Graphen darstellen und können anhand des Geldflusses mögliche Verbindungen zwischen Nutzern aufzeigen.

## **Heuristik für unnötige Inputs (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das an den Absender zurückgehende Wechselgeld ist.

### Beispiel

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Wenn zusätzliche Inputs dazu führen, dass der Change-Output größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an bereits verwendete Adressen senden und hoffen, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die sie auf bereits verwendeten, leeren Adressen erhalten haben, um diesen Privacy-Leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Wechselgeld finden wahrscheinlich zwischen zwei Adressen statt, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet auf eine Zahlung hin; der nicht runde Output ist wahrscheinlich das Wechselgeld.
- **Wallet-Fingerprinting:** Verschiedene Wallets weisen einzigartige Muster bei der Erstellung von Transaktionen auf. Dadurch können Analysten die verwendete Software und möglicherweise die Wechselgeldadresse identifizieren.
- **Korrelation von Beträgen und Zeitpunkten:** Die Offenlegung von Transaktionszeitpunkten oder -beträgen kann Transaktionen nachvollziehbar machen.

## **Traffic Analysis**

Durch die Überwachung des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke potenziell mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Das gilt insbesondere, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Möglichkeiten zur Überwachung von Transaktionen steigen.

## Mehr

Eine umfassende Liste von Privacy-Angriffen und Abwehrmaßnahmen finden Sie unter [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, anonym Bitcoins zu erhalten

- **Bargeldtransaktionen**: Bitcoin mit Bargeld erwerben.
- **Bargeldalternativen**: Geschenkkarten kaufen und online gegen Bitcoin eintauschen.
- **Mining**: Bitcoins lassen sich am privatesten durch Mining verdienen, insbesondere allein, da Mining-Pools möglicherweise die IP-Adresse des Miners kennen. [Informationen zu Mining-Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl**: Theoretisch könnte das Stehlen von Bitcoin eine weitere Möglichkeit sein, es anonym zu erwerben. Es ist jedoch illegal und nicht empfehlenswert.

## Mixing-Dienste

Bei einem Mixing-Dienst kann ein Nutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, wodurch es schwierig wird, den ursprünglichen Besitzer zurückzuverfolgen. Dafür muss man jedoch darauf vertrauen, dass der Dienst keine Logs speichert und die Bitcoins tatsächlich zurückgibt. Zu den alternativen Mixing-Möglichkeiten zählen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** führt mehrere Transaktionen verschiedener Nutzer zu einer zusammen, wodurch es schwieriger wird, Inputs und Outputs einander zuzuordnen. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispiele für Transaktionen, bei denen CoinJoin zum Einsatz gekommen sein könnte, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen finden Sie unter [CoinJoin](https://coinjoin.io/en). Einen Ethereum-Smart-Contract-Mixer, der Einzahlungen von späteren Auszahlungen trennt, finden Sie unter [Tornado Cash](https://tornado.cash).

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die für CoinJoin charakteristischen gleich großen Outputs. Dadurch ist sie extrem schwer zu erkennen und könnte die Common-Input-Ownership-Heuristik außer Kraft setzen, die von Stellen zur Transaktionsüberwachung verwendet wird.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transaktionen wie die oben genannten könnten PayJoin sein und die Privatsphäre verbessern, während sie von standardmäßigen Bitcoin-Transaktionen nicht zu unterscheiden sind.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich beeinträchtigen** und ist damit eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu gewährleisten, ist es entscheidend, Wallets mit der Blockchain zu synchronisieren. Zwei Methoden stechen hervor:

- **Full Node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full Node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, sodass Gegner nicht erkennen können, für welche Transaktionen oder Adressen sich der Benutzer interessiert.
- **Clientseitige Blockfilterung**: Bei dieser Methode werden für jeden Block der Blockchain Filter erstellt. So können Wallets relevante Transaktionen erkennen, ohne Netzwerkbeobachtern bestimmte Interessen offenzulegen. Leichte Wallets laden diese Filter herunter und rufen vollständige Blöcke nur ab, wenn eine Übereinstimmung mit den Adressen des Benutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, empfiehlt sich die Verwendung von Tor, um die IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Wiederverwendung von Adressen verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen derselben Entität zugeordnet werden. Moderne Wallets wirken durch ihr Design der Wiederverwendung von Adressen entgegen.

## **Strategien für Transaktionsprivatsphäre**

- **Mehrere Transaktionen**: Eine Zahlung auf mehrere Transaktionen aufzuteilen kann den Transaktionsbetrag verschleiern und so Angriffe auf die Privatsphäre vereiteln.
- **Wechselgeld vermeiden**: Transaktionen ohne Wechselgeldausgaben verbessern die Privatsphäre, da sie Methoden zur Erkennung von Wechselgeld erschweren.
- **Mehrere Wechselgeldausgaben**: Wenn sich Wechselgeld nicht vermeiden lässt, können mehrere Wechselgeldausgaben die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero ist darauf ausgelegt, die Transaktionsprivatsphäre in den Vordergrund zu stellen.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand für die Ausführung von Vorgängen auf Ethereum und wird in **Gwei** berechnet. Eine Transaktion, die beispielsweise 2.310.000 Gwei (oder 0,00231 ETH) kostet, umfasst ein Gaslimit und eine Basisgebühr sowie eine Prioritätsgebühr, die Validatoren zur Aufnahme der Transaktion anregen soll. Benutzer können eine maximale Gebühr festlegen, damit sie nicht zu viel bezahlen; der Überschuss wird zurückerstattet.<sup>[[5]](#references)</sup>

## **Transaktionen ausführen**

An Ethereum-Transaktionen sind ein Absender und ein Empfänger beteiligt, bei denen es sich um Benutzer- oder Smart-Contract-Adressen handeln kann. Sie erfordern eine Gebühr und müssen in einen Block aufgenommen werden. Zu den wesentlichen Transaktionsdaten gehören der Empfänger, die Signatur des Absenders, der Wert, optionale Daten, das Gaslimit und die Gebühren. Die Adresse des Absenders wird aus der Signatur abgeleitet und muss daher nicht in den Transaktionsdaten enthalten sein.<sup>[[4]](#references)</sup>

Diese Praktiken und Mechanismen bilden die Grundlage für alle, die Kryptowährungen nutzen und dabei Privatsphäre und Sicherheit priorisieren möchten.

## Value-Centric Web3 Red Teaming

- Komponenten, die Werte verwalten (Signer, Oracles, Bridges, Automatisierung), erfassen, um zu verstehen, wer Gelder bewegen kann und wie.
- Jede Komponente relevanten MITRE-AADAPT-Taktiken zuordnen, um Pfade zur Rechteausweitung aufzudecken.
- Angriffsketten mit Flash Loans, Oracles, Zugangsdaten und Cross-Chain-Szenarien durchspielen, um die Auswirkungen zu überprüfen und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signierungsablaufs

- Manipulationen an der Lieferkette von Wallet-UIs können EIP-712-Payloads unmittelbar vor der Signierung verändern und gültige Signaturen für Proxy-Übernahmen auf Basis von `delegatecall` abgreifen (z. B. das Überschreiben von Slot 0 von Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige Fehlkonfigurationen von Smart Accounts sind die Umgehung der Zugriffskontrolle von `EntryPoint`, nicht signierte Gasfelder, zustandsbehaftete Validierung, ERC-1271-Replay-Angriffe und Gebührenverluste durch Reverts nach der Validierung.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart-Contract-Sicherheit

- Mutationstests zum Aufdecken blinder Flecken in Testsuites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integrität von ZK-Proofs / zkVM-Gästen

Wenn ein Prover eine **zkVM** oder einen anwendungsspezifischen Proof-Circuit verwendet, um eine Behauptung zu belegen, erfährt der Verifier lediglich, dass das **Gastprogramm wie geschrieben ausgeführt wurde**. Enthält der Gast **unsichere Deserialisierung**, **undefiniertes Verhalten** oder **fehlende semantische Einschränkungen**, kann ein böswilliger Prover einen gültigen Proof erzeugen, obwohl die **öffentlichen Metriken oder die behauptete Invariante falsch sind**.<sup>[[7]](#references)</sup>

### Unsichere Deserialisierung in Proof-Gästen

- Private Witness-/Circuit-Bytes als **nicht vertrauenswürdige Angreifereingaben** behandeln, selbst wenn sie durch den Proof verborgen sind.
- Sie nicht mit ungeprüften Hilfsfunktionen wie `rkyv::access_unchecked` deserialisieren, sofern die Bytes nicht bereits außerhalb des Systems validiert wurden.
- Enum-Discriminants, relative Pointer, Längen und Indizes aus nicht vertrauenswürdigen serialisierten Daten validieren, bevor sie den Kontrollfluss oder Speicherzugriffe beeinflussen.

Praktisches Audit-Muster:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Wenn ein Feld wie `op.kind` ein Enum ist und ein Angreifer einen **out-of-range discriminant** einschleusen kann, wird jedes nachgelagerte `match` auf diesem Wert verdächtig.

### Umgehung von Zählern durch Jump Tables / UB

Wenn Rust ein großes `match` in eine **Jump Table** umwandelt, kann ein ungültiger Enum-Discriminant zu **undefiniertem Kontrollfluss** führen. Ein gefährliches Muster ist:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ein `match` aktualisiert **sicherheitskritische Zähler/Einschränkungen**.
2. Ein zweites `match` führt die **eigentliche Instruktionssemantik** aus.
3. Ein out-of-range Discriminant greift über die erste Jump Table hinaus und landet in Code, der zur zweiten gehört.

Ergebnis: Die Operation wird weiterhin ausgeführt, aber der Abrechnungspfad wird übersprungen. In einer zkVM kann dies gefälschte Proofs erzeugen, die unmögliche Metriken melden, etwa weniger Gates, weniger aufwendige Operationen oder andere gefälschte begrenzte Ressourcen.

Prüfliste:

- Suche nach attacker-controlled Enums, die aus Witness-/Private-Input deserialisiert werden.
- Untersuche wiederholte `match`-Anweisungen über dasselbe Opcode-/Kind-Feld.
- Behandle `unsafe` + unchecked deserialization + große Opcode-Dispatches als Kombination mit hohem Risiko.
- Reverse-engineere bei Bedarf das erzeugte Binary; das Layout der Jump Tables kann wichtiger sein als der Quellcode.

### Fehlende semantische Einschränkungen in reversiblen/spezialisierten Interpretern

Prüfe nicht nur die Speichersicherheit, sondern auch die **semantischen Regeln**, die der Proof durchsetzen soll.

Stelle bei reversiblen/quantenähnlichen Instruktionssätzen sicher, dass Operanden, die verschieden sein müssen, tatsächlich als verschieden eingeschränkt sind. Eine Toffoli-/CCX-ähnliche Operation, implementiert als:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

wird unsicher, wenn der Gast nicht ablehnt:

```text
op.q_control1 == op.q_control2 == op.q_target
```

In diesem Fall läuft der Übergang auf Folgendes hinaus:

```text
q = q ^ (q & q) = 0
```

This erzeugt ein **deterministisches Reset-Primitiv**, das Annahmen zur Umkehrbarkeit verletzt und günstigere, nicht beabsichtigte Berechnungen ermöglicht. In Beweissystemen, die die Ressourcennutzung attestieren, können Angreifer so funktionale Prüfungen bestehen und zugleich das Kostenmodell umgehen, dessen Durchsetzung der Verifizierer annimmt.

### Was in ZK-Systemen getestet werden sollte

- Alle Guest-Parser mit fehlerhaften Encodings von Witnesses und privaten Eingaben fuzzingtesten.
- Enum-Bereichsvalidierung vor dem Opcode-Dispatch sicherstellen.
- Semantische Prüfungen auf Operand-Aliasing und andere ungültige Instruktionsformen ergänzen.
- Gemeldete/öffentliche Zähler mit einer unabhängigen Referenzimplementierung vergleichen.
- Beachten, dass ein gültiger Beweis dennoch die **falsche Aussage** beweisen kann, wenn das Guest-Programm fehlerhaft ist.

## Zustandsabhängige Autorisierung

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi-/AMM-Exploitation

Wenn du praktische Exploitation von DEXes und AMMs untersuchst (Uniswap v4 Hooks, Rundungs-/Präzisionsmissbrauch, durch Flash Loans verstärkte Swaps, die Schwellenwerte überschreiten), sieh dir Folgendes an:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Bei gewichteten Multi-Asset-Pools, die virtuelle Salden zwischenspeichern und manipuliert werden können, wenn `supply == 0` gilt, lies:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of Stake – Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Öffentlicher Schlüssel und privater Schlüssel erklärt – Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Was sind Multi-Signatur-Transaktionen? – Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transaktionen | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas und Gebühren | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Datenschutz – Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits – Wir haben Googles Zero-Knowledge-Beweis für Quantenkryptanalyse geknackt](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Absicherung elliptischer-Kurven-Kryptowährungen gegen Quanten-Schwachstellen: Ressourcenabschätzungen und Gegenmaßnahmen (gepatchte Version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-Concept-Repository von Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
