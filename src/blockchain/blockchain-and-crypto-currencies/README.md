# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundbegriffe

- **Smart Contracts** werden als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und automatisieren die Vertragsausführung ohne Vermittler.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Front-End sowie ein transparentes, prüfbares Back-End.
- **Tokens & Coins** unterscheiden sich dadurch, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten Wert oder Eigentum repräsentieren.
- **Utility Tokens** gewähren Zugang zu Dienstleistungen, und **Security Tokens** stehen für Eigentum an Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Autoritäten.
- **DEX** und **DAOs** beziehen sich auf Decentralized Exchange Platforms bzw. Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und abgestimmte Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** basiert auf Rechenleistung zur Verifizierung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert im Vergleich zu PoW den Energieverbrauch.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Geldern zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des privaten Schlüssels Überweisungen initiieren kann.

#### Schlüsselelemente:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **inputs** (Quelle der Mittel), **outputs** (Ziel), **fees** (an Miner gezahlte Gebühren) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden und nur der endgültige Zustand an die Blockchain gesendet wird.

## Bitcoin-Datenschutzbedenken

Privacy-Angriffe, wie **Common Input Ownership** und **UTXO Change Address Detection**, nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverbindungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Methoden umfassen Barhandel, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt, um die Privatsphäre zu erhöhen.

# Bitcoin-Datenschutzangriffe

# Zusammenfassung der Bitcoin Privacy Attacks

In der Welt von Bitcoin sind die Privatsphäre von Transaktionen und die Anonymität der Nutzer häufig Anlass zur Sorge. Hier ist ein vereinfachter Überblick über mehrere gängige Methoden, mit denen Angreifer die Bitcoin-Privatsphäre kompromittieren können.

## **Common Input Ownership Assumption**

Es ist generell selten, dass inputs von unterschiedlichen Nutzern in einer einzigen Transaktion kombiniert werden, da dies mit erheblicher Komplexität verbunden ist. Daher wird häufig angenommen, dass **zwei input addresses in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, oder **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil an eine andere Adresse gesendet, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Sender gehört, wodurch die Privatsphäre kompromittiert wird.

### Beispiel

Zur Minderung können Mixing-Services oder die Nutzung mehrerer Adressen helfen, die Eigentümerschaft zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden, wodurch potenzielle Verbindungen zwischen Nutzern basierend auf dem Geldfluss sichtbar werden.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren inputs und outputs, um zu erraten, welcher output die Change ist, die an den Sender zurückgeht.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn durch Hinzufügen weiterer Inputs die Change-Ausgabe größer wird als irgendein einzelner Input, kann das die Heuristik verwirren.

## **Erzwungene Wiederverwendung von Adressen**

Angreifer können kleine Beträge an bereits verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Richtiges Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits genutzten, leeren Adressen empfangen wurden, um dieses Privacy leak zu verhindern.

## **Weitere Blockchain-Analysetechniken**

- **Exakte Zahlungsbeträge:** Transaktionen ohne Change-Ausgabe sind wahrscheinlich zwischen zwei Adressen, die demselben Nutzer gehören.
- **Runde Beträge:** Ein runder Betrag in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei die nicht-runde Ausgabe wahrscheinlich die Change-Ausgabe ist.
- **Wallet-Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, die es Analysten ermöglichen, die verwendete Software zu identifizieren und möglicherweise die Change-Adresse zu ermitteln.
- **Betrags- und Zeitkorrelationen:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen nachvollziehbar machen.

## **Traffic-Analyse**

Durch das Überwachen des Netzwerk-Traffics können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Dies gilt besonders, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Fähigkeit zur Überwachung von Transaktionen erhöht wird.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Wege, Bitcoins anonym zu erhalten

- **Barzahlungen:** Bitcoin durch Bargeld erwerben.
- **Bargeld-Alternativen:** Kauf von Geschenkkarten und deren Online-Umtausch gegen Bitcoin.
- **Mining:** Die privateste Methode, Bitcoins zu verdienen, ist Mining, besonders wenn es allein durchgeführt wird, da mining pools möglicherweise die IP-Adresse des Miners kennen. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diebstahl:** Theoretisch könnte das Stehlen von Bitcoin eine weitere Methode sein, sie anonym zu erwerben, obwohl es illegal und nicht zu empfehlen ist.

## Mixing Services

Durch die Nutzung eines Mixing-Service kann ein Nutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, was die Rückverfolgung des ursprünglichen Besitzers erschwert. Dennoch erfordert dies Vertrauen in den Service, keine Logs zu führen und die Bitcoins tatsächlich zurückzugeben. Alternative Mixing-Optionen umfassen Bitcoin-Casinos.

## CoinJoin

**CoinJoin** fasst mehrere Transaktionen von verschiedenen Nutzern zu einer zusammen und erschwert so das Zuordnen von Inputs zu Outputs. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispiel-Transaktionen, die möglicherweise CoinJoin verwendet haben, umfassen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben gezeigten könnten PayJoin sein, die die Privatsphäre verbessern und gleichzeitig nicht von normalen bitcoin-Transaktionen zu unterscheiden sind.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich stören**, was es zu einer vielversprechenden Entwicklung im Streben nach Transaktionsprivatsphäre macht.

# Beste Praktiken für Privatsphäre in Kryptowährungen

## **Wallet-Synchronisationstechniken**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisation von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, wodurch es für Angreifer unmöglich wird zu identifizieren, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Client-side block filtering**: Diese Methode umfasst das Erstellen von Filtern für jeden Block in der Blockchain, wodurch Wallets relevante Transaktionen identifizieren können, ohne spezifische Interessen gegenüber Netzwerkbeobachtern offenzulegen. Lightweight wallets laden diese Filter herunter und fordern nur dann vollständige Blöcke an, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor zur Anonymität verwenden**

Da Bitcoin in einem Peer-to-Peer-Netzwerk arbeitet, wird empfohlen, Tor zu verwenden, um Ihre IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Vermeidung von Adresswiederverwendung**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets verhindern die Adresswiederverwendung durch ihr Design.

## **Strategien für Transaktionsprivatsphäre**

- **Multiple transactions**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Angriffe auf die Privatsphäre vereiteln.
- **Change avoidance**: Die Wahl von Transaktionen, die keine change outputs erfordern, erhöht die Privatsphäre, da sie Methoden der Change-Erkennung stören.
- **Multiple change outputs**: Wenn die Vermeidung von Change nicht möglich ist, kann das Erzeugen mehrerer change outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero erfüllt das Bedürfnis nach absoluter Anonymität in digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Verständnis von Gas**

Gas misst den Rechenaufwand, der nötig ist, um Operationen auf Ethereum auszuführen und wird in **gwei** bepreist. Zum Beispiel beinhaltet eine Transaktion, die 2,310,000 gwei (oder 0.00231 ETH) kostet, ein gas limit und eine base fee sowie ein tip zur Anreizsetzung für Miner. Nutzer können ein max fee festlegen, um sicherzustellen, dass sie nicht zu viel bezahlen; der Überschuss wird zurückerstattet.

## **Durchführung von Transaktionen**

Transaktionen auf Ethereum beinhalten einen Sender und einen Empfänger, die entweder Benutzer- oder smart contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Senders, der Wert, optionale Daten, gas limit und Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, wodurch sie nicht in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für jeden, der sich mit Kryptowährungen beschäftigen möchte und dabei Privatsphäre und Sicherheit priorisiert.

## Value-Centric Web3 Red Teaming

- Erfasse werttragende Komponenten (signers, oracles, bridges, automation), um zu verstehen, wer Gelder verschieben kann und wie.
- Ordne jede Komponente relevanten MITRE AADAPT-Taktiken zu, um Privilegieneskalationspfade aufzudecken.
- Probiere flash-loan/oracle/credential/cross-chain-Angriffsketten durch, um die Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Kompromittierung des Web3-Signing-Workflows

- Supply-chain-Manipulation von Wallet-UIs kann EIP-712-Payloads direkt vor dem Signieren verändern und gültige Signaturen ernten für delegatecall-basierte Proxy-Übernahmen (z. B. slot-0-Überschreibung der Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation-Testing, um Blindspots in Test-Suiten zu finden:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Referenzen

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM-Exploitation

Wenn Sie die praktische Ausnutzung von DEXes und AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) recherchieren, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für multi-asset weighted pools, die virtuelle Salden cachen und vergiftet werden können, wenn `supply == 0`, studieren Sie:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
