# Blockchain und Kryptowährungen

{{#include ../../banners/hacktricks-training.md}}

## Grundbegriffe

- **Smart Contracts** werden als Programme definiert, die auf einer Blockchain ausgeführt werden, wenn bestimmte Bedingungen erfüllt sind, und automatisieren die Ausführung von Vereinbarungen ohne Zwischeninstanzen.
- **Decentralized Applications (dApps)** bauen auf Smart Contracts auf und bieten ein benutzerfreundliches Front-End sowie ein transparentes, prüfbares Back-End.
- **Tokens & Coins** unterscheiden sich darin, dass Coins als digitales Geld dienen, während Tokens Wert oder Eigentum in bestimmten Kontexten repräsentieren.
- **Utility Tokens** gewähren Zugang zu Diensten, und **Security Tokens** stehen für Eigentum an Vermögenswerten.
- **DeFi** steht für Dezentrale Finanzen und bietet Finanzdienstleistungen ohne zentrale Behörden.
- **DEX** und **DAOs** beziehen sich auf dezentrale Exchange-Plattformen bzw. Decentralized Autonomous Organizations.

## Konsensmechanismen

Konsensmechanismen sorgen für sichere und abgestimmte Validierung von Transaktionen in der Blockchain:

- **Proof of Work (PoW)** beruht auf Rechenleistung zur Verifizierung von Transaktionen.
- **Proof of Stake (PoS)** verlangt von Validatoren, eine bestimmte Menge an Tokens zu halten, und reduziert den Energieverbrauch im Vergleich zu PoW.

## Bitcoin-Grundlagen

### Transaktionen

Bitcoin-Transaktionen beinhalten das Übertragen von Mitteln zwischen Adressen. Transaktionen werden durch digitale Signaturen validiert, wodurch sichergestellt wird, dass nur der Besitzer des privaten Schlüssels Überweisungen initiieren kann.

#### Hauptkomponenten:

- **Multisignature Transactions** erfordern mehrere Signaturen, um eine Transaktion zu autorisieren.
- Transaktionen bestehen aus **inputs** (Quellen der Mittel), **outputs** (Ziele), **fees** (an Miner gezahlte Gebühren) und **scripts** (Transaktionsregeln).

### Lightning Network

Zielt darauf ab, die Skalierbarkeit von Bitcoin zu verbessern, indem mehrere Transaktionen innerhalb eines Channels erlaubt werden und nur der finale Zustand zur Blockchain gesendet wird.

## Bitcoin-Privatsphäre-Bedenken

Angriffe auf die Privatsphäre, wie **Common Input Ownership** und **UTXO Change Address Detection**, nutzen Transaktionsmuster aus. Strategien wie **Mixers** und **CoinJoin** erhöhen die Anonymität, indem sie Transaktionsverknüpfungen zwischen Nutzern verschleiern.

## Bitcoin anonym erwerben

Methoden umfassen Bargeldgeschäfte, Mining und die Nutzung von Mixers. **CoinJoin** mischt mehrere Transaktionen, um die Rückverfolgbarkeit zu erschweren, während **PayJoin** CoinJoins als normale Transaktionen tarnt, um die Privatsphäre weiter zu erhöhen.

# Bitcoin Privacy Atacks

# Zusammenfassung der Bitcoin-Privatsphäre-Angriffe

In der Welt von Bitcoin sind die Privatsphäre von Transaktionen und die Anonymität der Nutzer häufig Gegenstand von Bedenken. Hier ist eine vereinfachte Übersicht über mehrere gängige Methoden, mit denen Angreifer die Bitcoin-Privatsphäre kompromittieren können.

## **Common Input Ownership Assumption**

Es ist allgemein selten, dass Inputs von verschiedenen Nutzern in einer einzigen Transaktion kombiniert werden, aufgrund der damit verbundenen Komplexität. Daher wird oft angenommen, dass **zwei Input-Adressen in derselben Transaktion demselben Besitzer gehören**.

## **UTXO Change Address Detection**

Ein UTXO (Unspent Transaction Output) muss vollständig in einer Transaktion ausgegeben werden. Wenn nur ein Teil davon an eine andere Adresse gesendet wird, geht der Rest an eine neue Change-Adresse. Beobachter können annehmen, dass diese neue Adresse dem Sender gehört, was die Privatsphäre kompromittiert.

### Beispiel

Zur Minderung dieses Problems können Mixing-Services oder die Verwendung mehrerer Adressen helfen, die Eigentümerschaft zu verschleiern.

## **Social Networks & Forums Exposure**

Nutzer teilen manchmal ihre Bitcoin-Adressen online, wodurch es **einfach wird, die Adresse mit ihrem Besitzer zu verknüpfen**.

## **Transaction Graph Analysis**

Transaktionen können als Graphen visualisiert werden, wodurch potenzielle Verbindungen zwischen Nutzern basierend auf dem Geldfluss sichtbar werden.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Diese Heuristik basiert auf der Analyse von Transaktionen mit mehreren Inputs und Outputs, um zu erraten, welcher Output die Change ist, die an den Sender zurückgeht.

### Beispiel
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Wenn durch Hinzufügen weiterer Inputs der change output größer wird als jeder einzelne Input, kann das die Heuristik verwirren.

## **Forced Address Reuse**

Angreifer können kleine Beträge an bereits verwendete Adressen senden, in der Hoffnung, dass der Empfänger diese in zukünftigen Transaktionen mit anderen Inputs kombiniert und dadurch Adressen miteinander verknüpft.

### Correct Wallet Behavior

Wallets sollten vermeiden, Coins zu verwenden, die auf bereits verwendeten, leeren Adressen empfangen wurden, um dieses privacy leak zu verhindern.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transaktionen ohne change sind wahrscheinlich Zahlungen zwischen zwei Adressen, die demselben Nutzer gehören.
- **Round Numbers:** Eine runde Zahl in einer Transaktion deutet auf eine Zahlung hin; der nicht-runde Output ist wahrscheinlich der change.
- **Wallet Fingerprinting:** Verschiedene Wallets haben einzigartige Muster bei der Transaktionserstellung, wodurch Analysten die verwendete Software identifizieren und möglicherweise die change address bestimmen können.
- **Amount & Timing Correlations:** Das Offenlegen von Transaktionszeiten oder -beträgen kann Transaktionen nachverfolgbar machen.

## **Traffic Analysis**

Durch Überwachen des Netzwerkverkehrs können Angreifer möglicherweise Transaktionen oder Blöcke mit IP-Adressen verknüpfen und so die Privatsphäre der Nutzer gefährden. Das gilt besonders, wenn eine Entität viele Bitcoin Nodes betreibt, da dies ihre Fähigkeit zur Überwachung von Transaktionen erhöht.

## Mehr

Für eine umfassende Liste von privacy attacks und Gegenmaßnahmen besuchen Sie [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonyme Bitcoin-Transaktionen

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Bitcoin mit Bargeld erwerben.
- **Cash Alternatives**: Gutscheinkarten kaufen und online gegen Bitcoin eintauschen.
- **Mining**: Die privateste Methode, Bitcoins zu verdienen, ist mining, besonders wenn man alleine mined, da mining pools möglicherweise die IP-Adresse des Miners kennen. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretisch könnte auch Diebstahl von Bitcoin eine Methode sein, sie anonym zu erwerben, obwohl das illegal und nicht zu empfehlen ist.

## Mixing Services

Durch die Nutzung eines Mixing-Services kann ein Nutzer **Bitcoins senden** und **andere Bitcoins als Gegenleistung erhalten**, was die Rückverfolgung des ursprünglichen Besitzers erschwert. Das setzt jedoch Vertrauen in den Service voraus, dass er keine Logs führt und die Bitcoins tatsächlich zurückgibt. Alternative Mixing-Optionen umfassen Bitcoin-Casinos.

## CoinJoin

CoinJoin fasst mehrere Transaktionen von verschiedenen Nutzern zu einer zusammen und erschwert so das Zuordnen von Inputs zu Outputs. Trotz der Wirksamkeit können Transaktionen mit einzigartigen Input- und Output-Größen weiterhin potenziell zurückverfolgt werden.

Beispieltransaktionen, die CoinJoin verwendet haben könnten, sind `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` und `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Für mehr Informationen siehe [CoinJoin](https://coinjoin.io/en). Für einen ähnlichen Service auf Ethereum siehe [Tornado Cash](https://tornado.cash), das Transaktionen mit Mitteln von Minern anonymisiert.

## PayJoin

Eine Variante von CoinJoin, **PayJoin** (oder P2EP), tarnt die Transaktion zwischen zwei Parteien (z. B. Kunde und Händler) als normale Transaktion, ohne die für CoinJoin typischen gleichen Outputs. Das macht sie extrem schwer zu erkennen und kann die common-input-ownership heuristic, die von Überwachungsstellen für Transaktionen verwendet wird, ungültig machen.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaktionen wie die oben gezeigten könnten PayJoin sein, wodurch die Privatsphäre erhöht wird, während sie weiterhin nicht von Standard‑bitcoin‑Transaktionen zu unterscheiden sind.

**Der Einsatz von PayJoin könnte traditionelle Überwachungsmethoden erheblich stören**, und stellt damit eine vielversprechende Entwicklung im Streben nach Transaktions‑Privatsphäre dar.

# Beste Praktiken für die Privatsphäre bei Kryptowährungen

## **Wallet-Synchronisierungstechniken**

Um Privatsphäre und Sicherheit zu wahren, ist die Synchronisierung von Wallets mit der Blockchain entscheidend. Zwei Methoden stechen hervor:

- **Full node**: Durch das Herunterladen der gesamten Blockchain stellt ein Full node maximale Privatsphäre sicher. Alle jemals getätigten Transaktionen werden lokal gespeichert, wodurch es für Gegner unmöglich wird, zu identifizieren, welche Transaktionen oder Adressen den Nutzer interessieren.
- **Client-side block filtering**: Bei dieser Methode werden Filter für jeden Block in der Blockchain erstellt, wodurch Wallets relevante Transaktionen identifizieren können, ohne spezifische Interessen gegenüber Netzwerkbeobachtern offenzulegen. Lightweight wallets laden diese Filter herunter und fordern komplette Blöcke nur dann an, wenn eine Übereinstimmung mit den Adressen des Nutzers gefunden wird.

## **Nutzung von Tor für Anonymität**

Da Bitcoin in einem Peer‑to‑Peer‑Netzwerk betrieben wird, wird empfohlen, Tor zu verwenden, um Ihre IP‑Adresse zu verschleiern und so die Privatsphäre bei der Interaktion mit dem Netzwerk zu erhöhen.

## **Vermeidung der Wiederverwendung von Adressen**

Um die Privatsphäre zu schützen, ist es wichtig, für jede Transaktion eine neue Adresse zu verwenden. Die Wiederverwendung von Adressen kann die Privatsphäre gefährden, indem Transaktionen mit derselben Entität verknüpft werden. Moderne Wallets entmutigen die Wiederverwendung von Adressen durch ihr Design.

## **Strategien für Transaktions‑Privatsphäre**

- **Mehrere Transaktionen**: Eine Zahlung in mehrere Transaktionen aufzuteilen kann den Transaktionsbetrag verschleiern und Angriffe auf die Privatsphäre vereiteln.
- **Change‑Vermeidung**: Die Wahl von Transaktionen, die keine Change‑Outputs erfordern, verbessert die Privatsphäre, indem sie Methoden zur Change‑Erkennung stört.
- **Mehrere Change‑Outputs**: Wenn die Vermeidung von Change nicht möglich ist, kann das Erzeugen mehrerer Change‑Outputs die Privatsphäre trotzdem verbessern.

# **Monero: Ein Leuchtturm der Anonymität**

Monero adressiert das Bedürfnis nach absoluter Anonymität bei digitalen Transaktionen und setzt einen hohen Standard für Privatsphäre.

# **Ethereum: Gas und Transaktionen**

## **Verständnis von Gas**

Gas misst den Rechenaufwand zur Ausführung von Operationen auf Ethereum und wird in **gwei** bepreist. Zum Beispiel beinhaltet eine Transaktion, die 2.310.000 gwei (also 0,00231 ETH) kostet, ein Gas‑Limit und eine Base‑Fee sowie ein Tip zur Anreizung der Miner. Nutzer können eine Max‑Fee festlegen, um Überzahlungen zu vermeiden; der Überschuss wird zurückerstattet.

## **Ausführen von Transaktionen**

Transaktionen auf Ethereum beinhalten einen Sender und einen Empfänger, die entweder Benutzer‑ oder Smart‑Contract‑Adressen sein können. Sie erfordern eine Gebühr und müssen gemined werden. Wesentliche Informationen einer Transaktion umfassen den Empfänger, die Signatur des Senders, den Wert, optionale Daten, Gas‑Limit und Gebühren. Bemerkenswert ist, dass die Adresse des Senders aus der Signatur abgeleitet wird, sodass sie nicht explizit in den Transaktionsdaten enthalten sein muss.

Diese Praktiken und Mechanismen sind grundlegend für alle, die mit Kryptowährungen arbeiten möchten und dabei Privatsphäre und Sicherheit priorisieren.

## Smart‑Contract‑Sicherheit

- Mutationstests, um Blindstellen in Test‑Suiten zu finden:

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

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
