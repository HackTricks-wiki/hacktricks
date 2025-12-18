# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Konzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und verfügen über ein benutzerfreundliches Frontend und ein transparentes, prüfbares Backend.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens Wert oder Eigentum in bestimmten Kontexten repräsentieren.
- **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** stehen für Eigentum an Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Behörden an.
- **DEX** und **DAOs** bezeichnen jeweils Decentralized Exchange Platforms und Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und gemeinsame Bestätigung von Transaktionen auf der Blockchain:

- **Proof of Work (PoW)** beruht auf Rechenleistung zur Verifikation von Transaktionen.
- **Proof of Stake (PoS)** verlangt, dass Validatoren eine bestimmte Menge Tokens halten, wodurch der Energieverbrauch im Vergleich zu PoW reduziert wird.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Mitteln zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des privaten Schlüssels Übertragungen initiieren kann.

#### Wichtige Komponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **inputs** (Quelle der Mittel), **outputs** (Ziel), **fees** (an Miner gezahlt) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu erhöhen, indem mehrere Transaktionen innerhalb eines Channels ermöglicht werden, wobei nur der Endzustand in die Blockchain gesendet wird.

## Bitcoin Datenschutzbedenken

Datenschutzangriffe wie **Common Input Ownership** und **UTXO Change Address Detection** nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Transaktionsverknüpfungen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Methoden umfassen Bartransaktionen, Mining und die Nutzung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als reguläre Transaktionen tarnt, um die Privatsphäre zu erhöhen.

# Bitcoin-Privatsphäre-Angriffe

# Zusammenfassung der Bitcoin-Privatsphäre-Angriffe

In der Welt von Bitcoin stehen die Privatsphäre von Transaktionen und die Anonymität von Nutzern häufig im Fokus. Hier eine vereinfachte Übersicht über mehrere gebräuchliche Methoden, mit denen Angreifer die Bitcoin-Privatsphäre gefährden können.

## **Common Input Ownership Assumption**

Es ist generell selten, dass Inputs von verschiedenen Nutzern in einer einzigen Transaktion kombiniert werden, aufgrund der damit verbundenen Komplexität. Daher wird häufig angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, also ein **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Sender gehört, was die Privatsphäre kompromittiert.

### Beispiel

Um dem entgegenzuwirken, können Mixing-Dienste oder die Verwendung mehrerer Adressen helfen, die Zuordnung von Eigentum zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden, wodurch potenzielle Verbindungen zwischen Nutzern anhand des Geldflusses sichtbar werden.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output die Change-Adresse ist, die an den Sender zurückgeht.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs dazu führt, dass die Change-Ausgabe größer wird als irgendein einzelner Input, kann das die Heuristik verwirren.

## **Forced Address Reuse**

Angreifer können kleine Beträge an bereits verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese später mit anderen Inputs in zukünftigen Transaktionen kombiniert und damit Adressen miteinander verknüpft.

### Korrektes Wallet-Verhalten

Wallets sollten vermeiden, Coins zu verwenden, die an bereits genutzte, leere Adressen empfangen wurden, um dieses privacy leak zu verhindern.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaktionen ohne Change sind wahrscheinlich zwischen zwei Adressen des gleichen Nutzers.
- **Round Numbers:** Eine runde Zahl in einer Transaktion deutet auf eine Zahlung hin; die nicht-runde Ausgabe ist wahrscheinlich die Change.
- **Wallet Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, wodurch Analysten die verwendete Software und möglicherweise die Change-Adresse identifizieren können.
- **Amount & Timing Correlations:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen nachvollziehbar machen.

## **Traffic Analysis**

Durch Überwachen des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Dies gilt besonders, wenn eine Entität viele Bitcoin-Nodes betreibt, was ihre Fähigkeit zur Überwachung von Transaktionen erhöht.

## Mehr

Für eine umfassende Liste von Privacy-Angriffen und Gegenmaßnahmen besuchen Sie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Möglichkeiten, Bitcoins anonym zu erhalten

- **Cash Transactions**: Erwerb von bitcoin mit Bargeld.
- **Cash Alternatives**: Kauf von Geschenkkarten und deren Umtausch online gegen bitcoin.
- **Mining**: Die privateste Methode, bitcoins zu gewinnen, ist Mining — besonders Solo-Mining, da Mining-Pools die IP-Adresse des Miners kennen könnten. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretisch könnte das Stehlen von bitcoin eine weitere Methode sein, sie anonym zu erhalten; das ist jedoch illegal und nicht zu empfehlen.

## Mixing Services

Durch die Nutzung eines Mixing-Service kann ein Benutzer bitcoins senden und im Gegenzug andere bitcoins erhalten, was die Rückverfolgung des ursprünglichen Besitzers erschwert. Das erfordert jedoch Vertrauen in den Service, dass er keine Logs führt und die bitcoins tatsächlich zurückgibt. Alternative Mixing-Optionen umfassen Bitcoin-Casinos.

## CoinJoin

CoinJoin fasst Transaktionen mehrerer Nutzer zu einer einzigen zusammen, wodurch das Zuordnen von Inputs zu Outputs deutlich erschwert wird. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen dennoch potenziell zurückverfolgt werden.

Beispiel-Transaktionen, die CoinJoin verwendet haben könnten, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Für mehr Informationen, besuchen Sie [CoinJoin](https://coinjoin.io/en). Für einen ähnlichen Service auf Ethereum siehe [Tornado Cash](https://tornado.cash), das Transaktionen mit Mitteln von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. Kunde und Händler) als normale Transaktion, ohne die charakteristischen gleichen Outputs von CoinJoin. Das macht sie extrem schwer zu erkennen und kann die common-input-ownership heuristic, die von Transaction-Surveillance-Entitäten verwendet wird, ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die obige könnten PayJoin sein, die die Privatsphäre erhöhen und gleichzeitig nicht von standard bitcoin transactions zu unterscheiden sind.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich stören**, wodurch es eine vielversprechende Entwicklung im Streben nach Transaktionsprivatsphäre darstellt.

# Beste Praktiken für Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisation-Techniken**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisation von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain gewährleistet ein Full node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, wodurch es für Angreifer unmöglich wird zu erkennen, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Client-side block filtering**: Bei dieser Methode werden Filter für jeden Block der Blockchain erstellt, sodass Wallets relevante Transaktionen identifizieren können, ohne spezifische Interessen gegenüber Netzwerkbeobachtern offenzulegen. Lightweight wallets laden diese Filter herunter und holen nur dann komplette Blöcke, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Tor für Anonymität**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird empfohlen, Tor zu verwenden, um Ihre IP-Adresse zu verschleiern und die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Vermeidung von Adresswiederverwendung**

Zum Schutz der Privatsphäre ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, da Transaktionen mit derselben Entität verknüpft werden können. Moderne Wallets verhindern durch ihr Design die Wiederverwendung von Adressen.

## **Strategien für Transaktionsprivatsphäre**

- **Multiple transactions**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Transaktionsbetrag verschleiern und Angriffe auf die Privatsphäre vereiteln.
- **Change avoidance**: Die Wahl von Transaktionen, die keine Change-Outputs erfordern, erhöht die Privatsphäre, indem sie Methoden zur Erkennung von Change stört.
- **Multiple change outputs**: Falls die Vermeidung von Change nicht möglich ist, kann das Erzeugen mehrerer Change-Outputs die Privatsphäre verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero geht das Bedürfnis nach absoluter Anonymität bei digitalen Transaktionen an und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Verständnis von Gas**

Gas misst den Rechenaufwand, der zur Ausführung von Operationen auf Ethereum erforderlich ist, und wird in **gwei** bepreist. Zum Beispiel beinhaltet eine Transaktion, die 2.310.000 gwei (oder 0,00231 ETH) kostet, ein Gas-Limit und eine Basisgebühr (base fee), sowie ein Tip als Anreiz für Miner. Nutzer können eine Maximalgebühr setzen, um Überzahlungen zu vermeiden; der überschüssige Betrag wird zurückerstattet.

## **Ausführen von Transaktionen**

Transaktionen auf Ethereum beinhalten einen Sender und einen Empfänger, die entweder Benutzer- oder Smart-Contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Senders, der Wert, optionale Daten, Gas-Limit und Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, sodass sie nicht explizit in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für alle, die sich mit Kryptowährungen beschäftigen und dabei Privatsphäre und Sicherheit priorisieren.

## Wertzentriertes Web3 Red Teaming

- Inventarisiere werttragende Komponenten (signers, oracles, bridges, automation), um zu verstehen, wer Mittel verschieben kann und wie.
- Ordne jede Komponente relevanten MITRE AADAPT-Taktiken zu, um Pfade zur Privilegienerweiterung aufzudecken.
- Probiere flash-loan/oracle/credential/cross-chain Angriffsketten durch, um Auswirkungen zu validieren und ausnutzbare Voraussetzungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutationstests, um blinde Flecken in Test-Suites zu finden:

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

## DeFi/AMM-Ausnutzung

Wenn Sie die praktische Ausnutzung von DEXes und AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) erforschen, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für multi-asset gewichtete Pools, die virtuelle Salden cachen und bei `supply == 0` manipuliert werden können, studieren Sie:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
