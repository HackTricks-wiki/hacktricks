# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundkonzepte

- **Smart Contracts** sind Programme, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und automatisieren die Ausführung von Vereinbarungen ohne Vermittler.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Frontend sowie ein transparentes, prüfbares Backend.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens in bestimmten Kontexten Wert oder Eigentum repräsentieren.
- **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** signalisieren Eigentum an Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Autoritäten.
- **DEX** und **DAOs** stehen für Decentralized Exchange Platforms bzw. Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und abgestimmte Transaktionsvalidierungen auf der Blockchain:

- **Proof of Work (PoW)** beruht auf Rechenleistung zur Verifikation von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert den Energieverbrauch im Vergleich zu PoW.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Mitteln zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Inhaber des privaten Schlüssels Überweisungen initiieren kann.

#### Wichtige Komponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **inputs** (Quelle der Mittel), **outputs** (Ziel), **fees** (an Miner gezahlte Gebühren) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Channels erlaubt werden und nur der finale Zustand an die Blockchain gesendet wird.

## Bitcoin-Privatsphäre-Bedenken

Privacy-Angriffe, wie **Common Input Ownership** und **UTXO Change Address Detection**, nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie die Verknüpfung von Transaktionen zwischen Nutzern verschleiern.

## Bitcoins anonym erwerben

Methoden umfassen Barhandel, Mining und die Nutzung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt, um die Privatsphäre weiter zu erhöhen.

# Bitcoin-Privatsphäre-Angriffe

# Zusammenfassung der Bitcoin-Privatsphäre-Angriffe

In der Welt von Bitcoin sind die Privatsphäre von Transaktionen und die Anonymität von Nutzern häufig problematisch. Hier eine vereinfachte Übersicht über mehrere gängige Methoden, mit denen Angreifer die Bitcoin-Privatsphäre kompromittieren können.

## **Common Input Ownership Assumption**

Es ist allgemein selten, dass Inputs von verschiedenen Nutzern in einer einzigen Transaktion kombiniert werden, da dies mit Komplexität verbunden ist. Daher wird **oft angenommen, dass zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO, oder **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil an eine andere Adresse gesendet wird, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Sender gehört, was die Privatsphäre gefährdet.

### Beispiel

Um dies zu vermindern, können Mixing-Services oder die Verwendung mehrerer Adressen helfen, die Eigentümerschaft zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden, wodurch potenzielle Verbindungen zwischen Nutzern anhand des Geldflusses aufgedeckt werden können.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output die Change ist, die an den Sender zurückgeht.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn das Hinzufügen weiterer Inputs dafür sorgt, dass der Change-Ausgang größer ist als jeder einzelne Input, kann das die Heuristik verwirren.

## **Forced Address Reuse**

Angreifer könnten kleine Beträge an zuvor verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese später mit anderen Inputs kombiniert und so Adressen miteinander verknüpft.

### Correct Wallet Behavior

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits verwendeten, leeren Adressen empfangen wurden, um dieses privacy leak zu verhindern.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaktionen ohne Change sind wahrscheinlich zwischen zwei Adressen, die demselben Nutzer gehören.
- **Round Numbers:** Eine runde Zahl in einer Transaktion deutet auf eine Zahlung hin, wobei der nicht-runde Ausgang wahrscheinlich der Change ist.
- **Wallet Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, wodurch Analysten die verwendete Software und möglicherweise die Change-Adresse identifizieren können.
- **Amount & Timing Correlations:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen rückverfolgbar machen.

## **Traffic Analysis**

Durch Überwachung des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Dies gilt besonders, wenn eine Entität viele Bitcoin-Nodes betreibt, wodurch ihre Fähigkeit zur Überwachung der Transaktionen verstärkt wird.

## More

Für eine umfassende Liste von Privacy-Angriffen und -Abwehrmaßnahmen besuchen Sie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin mit Bargeld erwerben.
- **Cash Alternatives**: Kauf von Geschenkkarten und deren Online-Umtausch in Bitcoin.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist das Mining, besonders wenn es allein betrieben wird, da Mining Pools die IP-Adresse des Miners kennen könnten. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretisch könnte das Stehlen von Bitcoin eine weitere Methode sein, diese anonym zu erhalten, allerdings ist es illegal und nicht empfohlen.

## Mixing Services

Durch die Nutzung eines Mixing-Dienstes kann ein Nutzer **Bitcoins senden** und im Gegenzug **andere Bitcoins erhalten**, was das Zurückverfolgen des ursprünglichen Besitzers erschwert. Dies erfordert jedoch Vertrauen in den Dienst, keine Logs zu führen und die Bitcoins tatsächlich zurückzugeben. Als alternative Mixing-Optionen kommen Bitcoin-Casinos in Frage.

## CoinJoin

**CoinJoin** fasst mehrere Transaktionen verschiedener Nutzer zu einer zusammen, was das Zuordnen von Inputs zu Outputs erschwert. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen dennoch zurückverfolgt werden.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. einem Kunden und einem Händler) als normale Transaktion, ohne die charakteristischen gleichen Outputs, die CoinJoin auszeichnen. Das macht sie extrem schwer zu erkennen und kann die common-input-ownership heuristic, die von Stellen zur Transaktionsüberwachung verwendet wird, ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben gezeigten könnten PayJoin sein, was die Privatsphäre verbessert, während sie von standardmäßigen bitcoin-Transaktionen nicht unterscheidbar bleiben.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich stören**, wodurch es eine vielversprechende Entwicklung bei der Suche nach transaktionaler Privatsphäre darstellt.

# Beste Praktiken für Privatsphäre in Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisation von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain sorgt ein Full node für maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, wodurch es für Angreifer unmöglich ist zu erkennen, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Client-side block filtering**: Diese Methode beinhaltet das Erstellen von Filtern für jeden Block in der Blockchain, sodass Wallets relevante Transaktionen identifizieren können, ohne spezifische Interessen gegenüber Netzwerkteilnehmern preiszugeben. Lightweight wallets laden diese Filter herunter und holen vollständige Blöcke nur, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin in einem Peer-to-Peer-Netzwerk betrieben wird, wird empfohlen, Tor zu verwenden, um die IP-Adresse zu verschleiern und die Privatsphäre bei der Interaktion mit dem Netzwerk zu verbessern.

## **Vermeidung der Wiederverwendung von Adressen**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets entmutigen die Wiederverwendung von Adressen durch ihr Design.

## **Strategien für Transaktions-Privatsphäre**

- **Multiple transactions**: Das Aufteilen einer Zahlung in mehrere Transaktionen kann den Betrag verschleiern und Angriffe auf die Privatsphäre vereiteln.
- **Change avoidance**: Die Wahl von Transaktionen, die keine Change-Outputs erfordern, erhöht die Privatsphäre, indem Change-Detektionsmethoden gestört werden.
- **Multiple change outputs**: Wenn die Vermeidung von Change nicht möglich ist, kann die Erzeugung mehrerer Change-Outputs die Privatsphäre dennoch verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero adressiert das Bedürfnis nach absoluter Anonymität in digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Gas verstehen**

Gas misst den Rechenaufwand, der nötig ist, um Operationen auf Ethereum auszuführen; es wird in **gwei** angegeben. Zum Beispiel umfasst eine Transaktion mit Kosten von 2.310.000 gwei (bzw. 0,00231 ETH) ein gas limit und eine base fee sowie einen tip, um Miner zu incentivieren. Nutzer können eine max fee festlegen, damit sie nicht zu viel zahlen; der Überschuss wird zurückerstattet.

## **Transaktionen ausführen**

Transaktionen auf Ethereum beinhalten einen Sender und einen Empfänger, die entweder Nutzer- oder Smart-Contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion umfassen den Empfänger, die Signatur des Senders, den Wert, optionale Daten, gas limit und Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, wodurch sie nicht explizit in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für alle, die sich mit Kryptowährungen befassen und dabei Privatsphäre und Sicherheit priorisieren.

## Value-Centric Web3 Red Teaming

- Bestandsaufnahme der werttragenden Komponenten (signers, oracles, bridges, automation), um zu verstehen, wer Gelder bewegen kann und wie.
- Ordnen Sie jede Komponente den relevanten MITRE AADAPT-Taktiken zu, um Wege zur Privilegieneskalation aufzudecken.
- Üben Sie flash-loan/oracle/credential/cross-chain Angriffsketten, um die Auswirkungen zu validieren und ausnutzbare Vorbedingungen zu dokumentieren.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain-Manipulation von wallet UIs kann EIP-712-Payloads direkt vor dem Signieren verändern und gültige Signaturen ernten, um delegatecall-basierte Proxy-Übernahmen zu ermöglichen (z. B. slot-0 Überschreibung der Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Häufige Failure-Modes bei smart accounts umfassen das Umgehen der `EntryPoint`-Zugriffssteuerung, unsignierte gas-Felder, zustandsbehaftete Validierung, ERC-1271-Replay und fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing, um Blindspots in Test-Suites zu finden:

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

## DeFi/AMM Exploitation

Wenn Sie die praktische Ausnutzung von DEXes und AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps) recherchieren, siehe:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Für multi-asset weighted pools, die virtuelle Salden cachen und beim `supply == 0` vergiftet werden können, studieren Sie:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
