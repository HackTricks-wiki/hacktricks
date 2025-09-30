# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** werden als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und die Ausführung von Vereinbarungen ohne Zwischeninstanzen automatisieren.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend sowie ein transparentes, prüfbares Backend.
- **Tokens & Coins** unterscheiden sich dahingehend, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten Wert oder Eigentum repräsentieren.
- **Utility Tokens** gewähren Zugriff auf Dienste, und **Security Tokens** kennzeichnen Eigentum an Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Autoritäten.
- **DEX** und **DAOs** bezeichnen jeweils Decentralized Exchange Platforms und Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen stellen sichere und abgestimmte Transaktionsvalidierungen auf der Blockchain sicher:

- **Proof of Work (PoW)** beruht auf Rechenleistung zur Verifikation von Transaktionen.
- **Proof of Stake (PoS)** verlangt, dass Validatoren eine bestimmte Menge an Tokens halten, und reduziert im Vergleich zu PoW den Energieverbrauch.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen umfassen das Übertragen von Mitteln zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, womit sichergestellt wird, dass nur der Eigentümer des privaten Schlüssels Überweisungen initiieren kann.

#### Wichtige Komponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **inputs** (Geldquelle), **outputs** (Ziel), **fees** (an Miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden und lediglich der Endzustand an die Blockchain gesendet wird.

## Bedenken zur Bitcoin-Privatsphäre

Privacy-Angriffe, wie **Common Input Ownership** und **UTXO Change Address Detection**, nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Methoden umfassen Barhandel, Mining und die Nutzung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt, um die Privatsphäre weiter zu erhöhen.

# Bitcoin-Privatsphäre-Angriffe

# Zusammenfassung der Bitcoin-Privatsphäre-Angriffe

Im Bitcoin-Umfeld sind die Privatsphäre von Transaktionen und die Anonymität von Nutzern häufig problematisch. Hier eine vereinfachte Übersicht mehrerer gängiger Methoden, mit denen Angreifer die Bitcoin-Privatsphäre gefährden können.

## **Common Input Ownership Assumption**

Es ist allgemein selten, dass Inputs verschiedener Nutzer aufgrund der damit verbundenen Komplexität in einer einzigen Transaktion kombiniert werden. Daher wird oft angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Eigentümer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, also **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wird nur ein Teil an eine andere Adresse gesendet, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Sender gehört, wodurch die Privatsphäre gefährdet wird.

### Beispiel

Zur Abschwächung können Mixing-Services oder die Verwendung mehrerer Adressen helfen, die Eigentumsverhältnisse zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **einfach wird, die Adresse mit ihrem Eigentümer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden und offenbaren potenzielle Verbindungen zwischen Nutzern basierend auf dem Geldfluss.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output die Change ist, die an den Sender zurückgeht.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs das Change-Output größer macht als jeder einzelne Input, kann das die Heuristik verwirren.

## **Erzwungene Adresswiederverwendung**

Angreifer können kleine Beträge an bereits verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits verwendeten, leeren Adressen empfangen wurden, um dieses privacy leak zu verhindern.

## **Weitere Blockchain-Analyse-Techniken**

- **Exact Payment Amounts:** Transaktionen ohne Change sind höchstwahrscheinlich zwischen zwei Adressen, die demselben Nutzer gehören.
- **Round Numbers:** Eine runde Zahl in einer Transaktion deutet auf eine Zahlung hin, wobei der nicht-runde Output vermutlich das Change ist.
- **Wallet Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, die Analysten erlauben, die verwendete Software zu identifizieren und möglicherweise die Change-Adresse zu bestimmen.
- **Amount & Timing Correlations:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen nachvollziehbar machen.

## **Traffic Analysis**

Durch Überwachen des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer beeinträchtigen. Dies gilt besonders, wenn eine Entität viele Bitcoin-Nodes betreibt, was ihre Fähigkeit zur Überwachung von Transaktionen erhöht.

## More

Für eine umfassende Liste von Privacy-Angriffen und -Verteidigungen besuchen Sie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin bar erwerben.
- **Cash Alternatives**: Geschenk­karten kaufen und online gegen Bitcoin tauschen.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist Mining, besonders solo, da Mining-Pools die IP-Adresse des Miners kennen könnten. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretisch könnte das Stehlen von Bitcoin eine weitere Methode sein, sie anonym zu erwerben, es ist jedoch illegal und nicht empfehlenswert.

## Mixing Services

Durch die Nutzung eines Mixing-Services kann ein Nutzer Bitcoins senden und im Gegenzug andere Bitcoins erhalten, was die Rückverfolgung des ursprünglichen Besitzers erschwert. Das setzt jedoch Vertrauen in den Service voraus, keine Logs zu führen und die Bitcoins tatsächlich zurückzugeben. Alternative Mixing-Optionen sind Bitcoin-Casinos.

## CoinJoin

CoinJoin verbindet mehrere Transaktionen unterschiedlicher Nutzer zu einer, was das Zuordnen von Inputs zu Outputs erschwert. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispiel-Transaktionen, die CoinJoin genutzt haben könnten, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Weitere Informationen finden Sie unter [CoinJoin](https://coinjoin.io/en). Für einen ähnlichen Dienst auf Ethereum siehe [Tornado Cash](https://tornado.cash), das Transaktionen mit Mitteln von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, PayJoin (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als reguläre Transaktion, ohne die markanten gleichen Outputs, die für CoinJoin charakteristisch sind. Das macht sie extrem schwer zu erkennen und kann die common-input-ownership heuristic, die von Überwachungsstellen verwendet wird, außer Kraft setzen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben gezeigten könnten PayJoin sein, die die Privatsphäre erhöhen und gleichzeitig nicht von normalen Bitcoin-Transaktionen zu unterscheiden sind.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich stören**, was es zu einer vielversprechenden Entwicklung im Streben nach Transaktions-Privatsphäre macht.

# Best Practices für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisationstechniken**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisation von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, wodurch es für Angreifer unmöglich wird zu identifizieren, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Client-side block filtering**: Diese Methode erzeugt Filter für jeden Block der Blockchain, wodurch Wallets relevante Transaktionen erkennen können, ohne Netzwerkbeobachtern spezifische Interessen preiszugeben. Lightweight wallets laden diese Filter herunter und holen nur dann komplette Blöcke, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität nutzen**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird empfohlen, Tor zu verwenden, um deine IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Adresswiederverwendung verhindern**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Adressen wiederzuverwenden kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets entmutigen die Wiederverwendung von Adressen durch ihr Design.

## **Strategien für Transaktions-Privatsphäre**

- **Multiple transactions**: Eine Zahlung in mehrere Transaktionen aufzuteilen kann den Betrag verschleiern und Angriffe auf die Privatsphäre vereiteln.
- **Change avoidance**: Die Wahl von Transaktionen, die keine Change-Outputs erfordern, erhöht die Privatsphäre, indem Change-Detection-Methoden gestört werden.
- **Multiple change outputs**: Wenn das Vermeiden von Change nicht möglich ist, kann das Erstellen mehrerer Change-Outputs trotzdem die Privatsphäre verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero adressiert das Bedürfnis nach absoluter Anonymität bei digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der zur Ausführung von Operationen auf Ethereum erforderlich ist und wird in **gwei** bepreist. Zum Beispiel umfasst eine Transaktion, die 2.310.000 gwei (oder 0,00231 ETH) kostet, ein Gas-Limit und eine Base Fee sowie ein Tip, um Miner zu incentivieren. Nutzer können eine Max Fee setzen, um sicherzustellen, dass sie nicht zu viel bezahlen; der Überschuss wird zurückerstattet.

## **Transaktionen ausführen**

Transaktionen in Ethereum beinhalten einen Sender und einen Empfänger, die sowohl Benutzer- als auch Smart-Contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das Gas-Limit und die Gebühren. Bemerkenswert ist, dass die Absenderadresse aus der Signatur abgeleitet wird, sodass sie nicht in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für alle, die mit Kryptowährungen interagieren und dabei Privatsphäre und Sicherheit priorisieren.

## Referenzen

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM-Ausnutzung

Wenn du praktische Ausnutzungen von DEXes und AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) recherchierst, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
