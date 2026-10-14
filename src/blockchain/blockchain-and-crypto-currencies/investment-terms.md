# Anlagebegriffe

{{#include ../../banners/hacktricks-training.md}}

## Spotmarkt

Beim Spot-Handel wird ein Vermögenswert zur sofortigen Lieferung getauscht. Eine Limit-Order legt Menge und Limitpreis fest. Sie wird nur ausgeführt, wenn der Markt diesen Preis oder einen besseren erfüllen kann. Eine Market-Order zielt stattdessen auf eine sofortige Ausführung zu den besten gerade verfügbaren Preisen ab und kann Slippage verursachen.<sup>[[4]](#references)</sup>

Eine Stop-Limit-Order hat einen Stoppreis, der eine Limit-Order aktiviert. Sie kann den Ausführungspreis begrenzen, garantiert aber keine Ausführung, wenn sich der Markt über das Limit hinweg bewegt.<sup>[[4]](#references)</sup>

## Futures

Ein Futures-Kontrakt ist eine standardisierte Vereinbarung, eine bestimmte Ware oder ein Finanzinstrument zu einem zukünftigen Zeitpunkt zu kaufen oder zu verkaufen. Beispielsweise könnten zwei Parteien einen Preis von 70.000 $ für einen Bitcoin mit Abrechnung in sechs Monaten vereinbaren.<sup>[[1]](#references)</sup>

Beträgt der Abrechnungspreis 80.000 $, erzielt die Long-Seite im Vergleich zum Kontraktpreis von 70.000 $ einen Gewinn und die Short-Seite einen Verlust. Bei einem Preis von 60.000 $ ist es umgekehrt. Tatsächlich börsengehandelte Futures werden täglich bewertet und in der Regel vor Ablauf geschlossen oder gerollt; dies ist daher eine vereinfachte Darstellung.<sup>[[2]](#references)</sup>

Produzenten und Verbraucher nutzen Futures zur Absicherung gegen Preisrisiken; andere Marktteilnehmer nutzen sie, um Gewinne anzustreben oder Liquidität bereitzustellen.<sup>[[1]](#references)</sup>

- Eine **Long-Position** profitiert in der Regel von einem steigenden Kontraktpreis.
- Eine **Short-Position** profitiert in der Regel von einem fallenden Kontraktpreis.<sup>[[2]](#references)</sup>

### Absicherung mit Futures

Wenn ein Fondsmanager mit einem fallenden Portfolio rechnet, könnte er einen ausreichend stark korrelierten Aktienindex-Futures-Kontrakt leerverkaufen. Gewinne aus der Short-Absicherung können einen Teil der Portfolioverluste ausgleichen; aufgrund des Basisrisikos ist dieser Ausgleich selten exakt. Ein Bitcoin-Future würde ein Bitcoin-Engagement absichern, nicht automatisch ein Aktienportfolio.

Fällt der abgesicherte Markt, kann die Short-Futures-Position an Wert gewinnen, während die Bestände an Wert verlieren. Steigt der Markt, können die Bestände an Wert gewinnen, während die Absicherung Verluste verursacht. Eine Absicherung reduziert bestimmte Risiken, statt einen garantierten Gewinn zu erzielen.<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual-Kontrakte sind Derivate ohne festes Ablaufdatum. Krypto-Handelsplätze verwenden häufig regelmäßige Funding-Zahlungen, um ihren Preis nahe am zugrunde liegenden Spotpreis zu halten; die Bedingungen unterscheiden sich je nach Handelsplatz.<sup>[[3]](#references)</sup>

Gewinn und Verlust ändern sich mit der Bewegung des Mark-Preises. Eine Preisbewegung von 1 % bewirkt vor Gebühren und Funding eine ungefähre Veränderung von 1 % des Nominalwerts der Position. Durch den Einsatz von Hebel kann dies jedoch einen deutlich größeren prozentualen Anteil des hinterlegten Sicherheitenbetrags ausmachen.

### Futures mit Hebel

**Hebel** ermöglicht es einem Trader, mit einer geringeren Margin eine größere Position mit höherem Nominalwert zu kontrollieren. Verluste sind nicht immer auf die anfängliche Margin beschränkt: Liquidation, Kurslücken, Gebühren und die Regeln des Handelsplatzes können zusätzliche Verluste verursachen.<sup>[[3]](#references)</sup>

Beispielsweise kontrollieren 100 $ Margin bei einem Hebel von 50x eine Position von 5.000 $. Ohne Berücksichtigung von Gebühren, Funding und Liquidationsmechanismen führt eine günstige Kursbewegung von 1 % zu einem Gewinn von 50 $ (50 % der anfänglichen Margin), während eine ungünstige Bewegung von 1 % einen Verlust von 50 $ verursacht. Eine ungünstige Bewegung von 2 % entspricht 100 $, wobei ein Handelsplatz die Position normalerweise liquidiert, bevor die gesamte Margin aufgebraucht ist.

Hebel verstärkt sowohl Gewinne als auch Verluste und ermöglicht eine Liquidation bereits nach einer vergleichsweise kleinen ungünstigen Kursbewegung.

## Unterschiede zwischen Futures und Optionen

Ein Käufer einer Option erhält gemäß den Vertragsbedingungen ein Recht, aber keine Verpflichtung zur Ausübung. Der Optionsverkäufer hat die entsprechende Verpflichtung, falls der Käufer die Option ausübt. Der Käufer zahlt dem Verkäufer für dieses Recht eine Prämie.<sup>[[4]](#references)</sup>

### 1. **Verpflichtung oder Recht:**

* **Futures:** Wenn du einen Futures-Kontrakt kaufst oder verkaufst, gehst du eine **verbindliche Vereinbarung** ein, einen Vermögenswert an einem zukünftigen Datum zu einem bestimmten Preis zu kaufen oder zu verkaufen. Sowohl der Käufer als auch der Verkäufer sind **verpflichtet**, den Vertrag bei Ablauf zu erfüllen (sofern der Kontrakt nicht zuvor geschlossen wird).
* **Optionen:** Bei Optionen hast du das **Recht, aber nicht die Verpflichtung**, einen Vermögenswert zu einem bestimmten Preis vor oder an einem bestimmten Ablaufdatum zu kaufen (bei einer **Call-Option**) oder zu verkaufen (bei einer **Put-Option**). Der **Käufer** hat die Wahl, die Option auszuüben; der **Verkäufer** muss den Handel erfüllen, wenn der Käufer sich für die Ausübung entscheidet.

### 2. **Risiko:**

* **Futures:** Beide Seiten können erhebliche Verluste erleiden. Ob Verluste mathematisch unbegrenzt sind, hängt von der Position und dem zugrunde liegenden Vermögenswert ab: Eine Short-Position kann theoretisch unbegrenzte Verluste verursachen, während eine Long-Position nicht mehr als den Nominalwert verlieren kann, sofern der zugrunde liegende Vermögenswert nicht unter null fallen kann.
* **Optionen:** Ein Käufer, der nicht zugleich eine andere Option verkauft, riskiert in der Regel die gezahlte Prämie. Ein ungedeckter Call-Verkäufer kann theoretisch unbegrenzte Verluste erleiden; andere Optionsverkaufsstrategien haben unterschiedliche begrenzte oder unbegrenzte Risikoprofile.

### 3. **Kosten:**

* **Futures:** Abgesehen von der erforderlichen Margin für das Halten der Position fallen keine Vorabkosten an, da sowohl Käufer als auch Verkäufer verpflichtet sind, den Handel abzuschließen.
* **Optionen:** Der Käufer muss vorab eine **Optionsprämie** für das Recht zur Ausübung der Option zahlen. Diese Prämie ist im Wesentlichen der Preis der Option.

### 4. **Gewinnpotenzial:**

* **Futures:** Der Gewinn oder Verlust basiert auf der Differenz zwischen dem Marktpreis bei Ablauf und dem im Kontrakt vereinbarten Preis.
* **Optionen:** Der Käufer erzielt einen Gewinn, wenn sich der Markt günstig über den Ausübungspreis hinaus bewegt und die Bewegung größer ist als die gezahlte Prämie. Der Verkäufer erzielt einen Gewinn, wenn er die Prämie behalten kann, weil die Option nicht ausgeübt wird.

## References

- [1] [CFTC - Der wirtschaftliche Zweck von Futures-Märkten](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Grundlagen des Futures-Markts](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Risiken des Handels mit virtuellen Währungen verstehen](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC-Glossar - Option, Prämie und Ausübung](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
