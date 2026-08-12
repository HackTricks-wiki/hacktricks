# Investmentbegriffe

{{#include ../banners/hacktricks-training.md}}

## Spot

Beim Spot-Trading wird ein Vermögenswert gegen sofortige Lieferung getauscht. Eine Limit-Order legt die Menge und den Limitpreis fest; sie wird nur ausgeführt, wenn der Markt diesen Preis oder einen besseren Preis erfüllen kann. Eine Market-Order strebt dagegen eine schnelle Ausführung zu den dann verfügbaren besten Preisen an und kann Slippage verursachen.<sup>[[4]](#references)</sup>

Eine Stop-Limit-Order verfügt über einen Stop-Preis, der eine Limit-Order aktiviert. Sie kann den Ausführungspreis begrenzen, garantiert jedoch keine Ausführung, wenn sich der Markt durch das Limit bewegt.<sup>[[4]](#references)</sup>

## Futures

Ein Futures-Kontrakt ist eine standardisierte Vereinbarung zum Kauf oder Verkauf eines bestimmten Rohstoffs oder Finanzinstruments zu einem zukünftigen Zeitpunkt. Beispielsweise könnten sich zwei Parteien auf einen Preis von $70,000 für einen Bitcoin mit einer Abrechnung in sechs Monaten einigen.<sup>[[1]](#references)</sup>

Wenn der Abrechnungspreis $80,000 beträgt, erzielt die Long-Seite im Vergleich zum Vertragspreis von $70,000 einen Gewinn und die Short-Seite einen Verlust. Bei einem Preis von $60,000 ist die Richtung umgekehrt. Tatsächlich börsengehandelte Futures werden zum Marktwert bewertet und normalerweise vor dem Verfall geschlossen oder gerollt; dies ist daher eine vereinfachte Darstellung.<sup>[[2]](#references)</sup>

Produzenten und Verbraucher nutzen Futures, um sich gegen Preisrisiken abzusichern; andere Teilnehmer nutzen sie, um Gewinne zu erzielen oder Liquidität bereitzustellen.<sup>[[1]](#references)</sup>

- Eine **Long-Position** erzielt im Allgemeinen Gewinne, wenn der Kontraktpreis steigt.
- Eine **Short-Position** erzielt im Allgemeinen Gewinne, wenn der Kontraktpreis fällt.<sup>[[2]](#references)</sup>

### Absicherung mit Futures

Wenn ein Fondsmanager erwartet, dass ein Portfolio fällt, könnte er einen ausreichend korrelierten Aktienindex-Futures-Kontrakt shorten. Gewinne aus der Short-Absicherung können einen Teil der Portfolioverluste ausgleichen; das Basisrisiko bedeutet, dass der Ausgleich selten exakt ist. Ein Bitcoin-Future würde ein Bitcoin-Exposure absichern, nicht automatisch ein Aktienportfolio.

Wenn der abgesicherte Markt fällt, kann die Short-Futures-Position an Wert gewinnen, während die Bestände an Wert verlieren. Wenn er steigt, können die Bestände an Wert gewinnen, während die Absicherung Verluste verursacht. Hedging reduziert ausgewählte Risiken, anstatt einen garantierten Gewinn zu erzeugen.<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual-Kontrakte sind Derivate ohne festes Ablaufdatum. Krypto-Handelsplätze verwenden üblicherweise regelmäßige Funding-Zahlungen, um ihren Preis nahe am zugrunde liegenden Spot-Preis zu halten; die Bedingungen unterscheiden sich je nach Handelsplatz.<sup>[[3]](#references)</sup>

Gewinn und Verlust ändern sich, wenn sich der Mark-Preis bewegt. Eine Preisbewegung von 1 % führt vor Gebühren und Funding zu einer ungefähr 1%igen Bewegung des Nominalwerts der Position, aber Leverage kann daraus einen deutlich größeren Prozentsatz des hinterlegten Collaterals machen.

### Futures mit Leverage

**Leverage** ermöglicht es einem Trader, mit einer geringeren Margin-Einlage eine größere Nominalposition zu kontrollieren. Verluste sind nicht immer auf die anfängliche Margin begrenzt: Liquidation, Gaps, Gebühren und die Regeln des Handelsplatzes können zusätzliche Verluste verursachen.<sup>[[3]](#references)</sup>

Beispielsweise kontrollieren $100 Margin bei 50x Leverage eine Position von $5,000. Werden Gebühren, Funding und Liquidationsmechanismen ignoriert, erzeugt eine günstige Bewegung von 1 % einen Gewinn von $50 (50 % der anfänglichen Margin), während eine ungünstige Bewegung von 1 % einen Verlust von $50 verursacht. Eine ungünstige Bewegung von 2 % entspricht $100, obwohl ein Handelsplatz die Position normalerweise liquidiert, bevor die gesamte Margin aufgebraucht ist.

Leverage verstärkt sowohl Gewinne als auch Verluste und macht eine Liquidation bereits nach einer vergleichsweise kleinen ungünstigen Bewegung möglich.

## Unterschiede zwischen Futures und Optionen

Der Käufer einer Option erhält ein Recht, nicht jedoch eine Verpflichtung, die Option gemäß den Vertragsbedingungen auszuüben. Der Stillhalter der Option hat die entsprechende Verpflichtung, wenn der Käufer die Option ausübt. Der Käufer zahlt dem Stillhalter für dieses Recht eine Prämie.<sup>[[4]](#references)</sup>

### 1. **Verpflichtung vs. Recht:**

* **Futures:** Wenn du einen Futures-Kontrakt kaufst oder verkaufst, gehst du eine **verbindliche Vereinbarung** ein, einen Vermögenswert an einem zukünftigen Datum zu einem bestimmten Preis zu kaufen oder zu verkaufen. Sowohl der Käufer als auch der Verkäufer sind **verpflichtet**, den Vertrag bei Ablauf zu erfüllen (sofern der Vertrag nicht vorher geschlossen wird).
* **Optionen:** Bei Optionen hast du das **Recht, aber nicht die Verpflichtung**, einen Vermögenswert zu einem bestimmten Preis vor oder an einem bestimmten Ablaufdatum zu kaufen (im Fall einer **Call-Option**) oder zu verkaufen (im Fall einer **Put-Option**). Der **Käufer** hat die Möglichkeit, die Option auszuüben, während der **Verkäufer** verpflichtet ist, den Handel zu erfüllen, wenn der Käufer die Option ausüben möchte.

### 2. **Risiko:**

* **Futures:** Beide Seiten können erhebliche Verluste erleiden. Ob der Verlust mathematisch unbegrenzt ist, hängt von der Position und dem zugrunde liegenden Vermögenswert ab: Eine Short-Position kann theoretisch unbegrenzte Verluste verursachen, während eine Long-Position nicht mehr als den Nominalwert verlieren kann, wenn der zugrunde liegende Vermögenswert nicht unter null fallen kann.
* **Optionen:** Ein Käufer, der keine weitere Option schreibt, riskiert im Allgemeinen die gezahlte Prämie. Ein Stillhalter eines ungedeckten Calls kann theoretisch unbegrenzte Verluste erleiden; andere Strategien zum Schreiben von Optionen weisen unterschiedliche begrenzte oder unbegrenzte Risikoprofile auf.

### 3. **Kosten:**

* **Futures:** Es gibt keine Vorauszahlung über die zum Halten der Position erforderliche Margin hinaus, da Käufer und Verkäufer gleichermaßen verpflichtet sind, den Handel abzuschließen.
* **Optionen:** Der Käufer muss für das Recht, die Option auszuüben, im Voraus eine **Optionsprämie** zahlen. Diese Prämie stellt im Wesentlichen die Kosten der Option dar.

### 4. **Gewinnpotenzial:**

* **Futures:** Der Gewinn oder Verlust basiert auf der Differenz zwischen dem Marktpreis bei Ablauf und dem im Vertrag vereinbarten Preis.
* **Optionen:** Der Käufer erzielt einen Gewinn, wenn sich der Markt über den Strike-Preis hinaus und um mehr als die gezahlte Prämie in eine günstige Richtung bewegt. Der Verkäufer erzielt einen Gewinn, indem er die Prämie behält, wenn die Option nicht ausgeübt wird.

## References

- [1] [CFTC - Der wirtschaftliche Zweck von Futures-Märkten](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Grundlagen des Futures-Marktes](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Die Risiken des Handels mit virtuellen Währungen verstehen](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC-Glossar - Option, Prämie und Ausübung](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
