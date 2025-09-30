# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundkonzepte

- **Smart Contracts** werden als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und automatisieren Ausführungen von Vereinbarungen ohne Zwischeninstanzen.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Frontend sowie ein transparentes, prüfbares Backend.
- **Tokens & Coins** unterscheiden sich dahingehend, dass Coins als digitales Geld dienen, während Tokens Wert oder Eigentum in spezifischen Kontexten repräsentieren.
- **Utility Tokens** gewähren Zugang zu Dienstleistungen, und **Security Tokens** signalisieren Eigentum an Vermögenswerten.
- **DeFi** steht für Decentralized Finance und bietet Finanzdienstleistungen ohne zentrale Autoritäten.
- **DEX** und **DAOs** beziehen sich auf Decentralized Exchange Platforms bzw. Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und einvernehmliche Transaktionsvalidierung in der Blockchain:

- **Proof of Work (PoW)** beruht auf Rechenleistung zur Transaktionsverifikation.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert den Energieverbrauch im Vergleich zu PoW.

## Bitcoin Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten die Übertragung von Mitteln zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Eigentümer des Private Keys Überweisungen initiieren kann.

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **Eingängen** (Quelle der Mittel), **Ausgängen** (Ziel), **Gebühren** (an Miner gezahlt) und **Skripten** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Kanals erlaubt werden und nur der finale Zustand in die Blockchain gesendet wird.

## Bitcoin-Privatsphäre-Bedenken

Privacy-Angriffe, wie **Common Input Ownership** und **UTXO Change Address Detection**, nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** verbessern die Anonymität, indem sie Verbindungen zwischen Transaktionen und Nutzern verschleiern.

## Anonyme Beschaffung von Bitcoins

Methoden umfassen Bartransaktionen, Mining und die Nutzung von Mixern. **CoinJoin** mischt mehrere Transaktionen, um Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt, um die Privatsphäre weiter zu erhöhen.

# Bitcoin-Privatsphäre-Angriffe

# Zusammenfassung der Bitcoin-Privatsphäre-Angriffe

In der Welt von Bitcoin sind die Privatsphäre von Transaktionen und die Anonymität der Nutzer häufig Gegenstand von Bedenken. Hier ist ein vereinfachter Überblick über mehrere gängige Methoden, mit denen Angreifer die Bitcoin-Privatsphäre kompromittieren können.

## **Common Input Ownership Assumption**

Es ist allgemein selten, dass Inputs von verschiedenen Nutzern in einer einzigen Transaktion kombiniert werden, aufgrund der damit verbundenen Komplexität. Daher wird oft angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Eine UTXO, oder **Unspent Transaction Output**, muss in einer Transaktion vollständig ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Sender gehört, wodurch die Privatsphäre kompromittiert wird.

### Beispiel

Um dem entgegenzuwirken, können Mixing-Dienste oder die Verwendung mehrerer Adressen helfen, die Zuordnung zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden, wodurch potenzielle Verbindungen zwischen Nutzern anhand des Geldflusses sichtbar werden.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output das als Wechsel zurück an den Sender gehende Guthaben ist.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Angreifer können kleine Beträge an bereits verwendete Adressen schicken, in der Hoffnung, dass der Empfänger diese später mit anderen Inputs in zukünftigen Transaktionen zusammenführt und dadurch Adressen miteinander verknüpft.

### Correct Wallet Behavior

Wallets sollten vermeiden, Münzen zu verwenden, die auf bereits verwendeten, leeren Adressen empfangen wurden, um dieses privacy leak zu verhindern.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaktionen ohne Change deuten wahrscheinlich auf zwei Adressen desselben Nutzers hin.
- **Round Numbers:** Eine runde Zahl in einer Transaktion deutet darauf hin, dass es sich um eine Zahlung handelt, wobei der nicht-runde Ausgang wahrscheinlich der Change ist.
- **Wallet Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Erstellung von Transaktionen, die Analysten erlauben, die verwendete Software zu identifizieren und möglicherweise die Change-Adresse zu ermitteln.
- **Amount & Timing Correlations:** Die Offenlegung von Transaktionszeiten oder -beträgen kann Transaktionen rückverfolgbar machen.

## **Traffic Analysis**

Durch das Überwachen des Netzwerkverkehrs können Angreifer Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Dies gilt besonders, wenn eine Entität viele Bitcoin-Knoten betreibt, was ihre Fähigkeit zur Überwachung von Transaktionen erhöht.

## More

Für eine umfassende Liste von Privacy-Angriffen und -Abwehrmaßnahmen besuchen Sie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Erwerb von Bitcoin mit Bargeld.
- **Cash Alternatives**: Kauf von Geschenkkarten und deren Tausch online gegen Bitcoin.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist das Mining, besonders wenn solo betrieben, da Mining-Pools die IP-Adresse des Miners kennen können. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretisch könnte auch der Diebstahl von Bitcoin eine anonyme Erwerbsmethode sein, obwohl es illegal und nicht empfohlen ist.

## Mixing Services

Durch die Nutzung eines Mixing-Service kann ein Nutzer **bitcoins senden** und **im Gegenzug andere bitcoins erhalten**, was es schwierig macht, den ursprünglichen Besitzer zu verfolgen. Dennoch erfordert dies Vertrauen in den Service, keine Logs zu führen und die bitcoins tatsächlich zurückzugeben. Alternative Mixing-Optionen sind Bitcoin-Casinos.

## CoinJoin

**CoinJoin** fasst mehrere Transaktionen verschiedener Nutzer zu einer zusammen, was es für jemanden, der versucht, Inputs mit Outputs abzugleichen, erschwert. Trotz seiner Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen dennoch potenziell zurückverfolgt werden.

Beispieltransaktionen, die CoinJoin verwendet haben könnten, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (or P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. Kunde und Händler) als normale Transaktion, ohne die für CoinJoin charakteristischen gleichen Outputs. Dadurch wird die Erkennung extrem erschwert und könnte die common-input-ownership heuristic, die bei der Transaktionsüberwachung angewandt wird, außer Kraft setzen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**Die Nutzung von PayJoin könnte herkömmliche Überwachungsmethoden erheblich stören**, was es zu einer vielversprechenden Entwicklung im Streben nach Transaktionsprivatsphäre macht.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisation von Wallets mit der blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten blockchain gewährleistet ein Full node maximale Privatsphäre. Alle jemals getätigten Transaktionen werden lokal gespeichert, wodurch es für Angreifer unmöglich wird zu identifizieren, an welchen Transaktionen oder Adressen der Nutzer interessiert ist.
- **Client-side block filtering**: Diese Methode erzeugt Filter für jeden Block in der blockchain, sodass Wallets relevante Transaktionen erkennen können, ohne spezifische Interessen gegenüber Netzwerkbeobachtern preiszugeben. Leichte Wallets laden diese Filter herunter und fordern nur dann vollständige Blöcke an, wenn ein Treffer mit den Adressen des Nutzers gefunden wird.

## **Utilizing Tor for Anonymity**

Da Bitcoin auf einem Peer-to-Peer-Netzwerk läuft, wird empfohlen, Tor zu verwenden, um die IP-Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Preventing Address Reuse**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre kompromittieren, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets entmutigen die Adresswiederverwendung durch ihr Design.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Eine Zahlung in mehrere Transaktionen aufzuteilen kann den Transaktionsbetrag verschleiern und Privatsphäre-Angriffe vereiteln.
- **Change avoidance**: Transaktionen zu wählen, die keine Change-Ausgänge erfordern, erhöht die Privatsphäre, indem Change-Detektionsmethoden unterlaufen werden.
- **Multiple change outputs**: Wenn die Vermeidung von Change nicht möglich ist, kann das Erzeugen mehrerer Change-Ausgänge die Privatsphäre dennoch verbessern.

# **Monero: A Beacon of Anonymity**

Monero adressiert das Bedürfnis nach absoluter Anonymität bei digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas misst den Rechenaufwand, der nötig ist, um Operationen auf Ethereum auszuführen, und wird in **gwei** bepreist. Zum Beispiel erfordert eine Transaktion, die 2.310.000 gwei (oder 0,00231 ETH) kostet, ein gas limit und eine base fee sowie einen Tip zur Anreizung der Miner. Nutzer können eine max fee setzen, um sicherzustellen, dass sie nicht zu viel bezahlen; der Überschuss wird zurückerstattet.

## **Executing Transactions**

Transaktionen auf Ethereum beinhalten einen Sender und einen Empfänger, die entweder Nutzer- oder smart contract-Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen in einer Transaktion sind der Empfänger, die Signatur des Senders, der Wert, optionale Daten, das gas limit und die Gebühren. Bemerkenswert ist, dass die Absenderadresse aus der Signatur abgeleitet wird, wodurch sie nicht in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für alle, die sich mit cryptocurrencies beschäftigen möchten und dabei Privatsphäre und Sicherheit priorisieren.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
