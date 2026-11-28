# Investmentbegriffe

{{#include ../../banners/hacktricks-training.md}}

## Spot

Beim Spot-Trading wird ein Vermögenswert gegen sofortige Lieferung getauscht. Eine Limit-Order legt die Menge und den Limitpreis fest; sie wird nur ausgeführt, wenn der Markt diesen Preis oder einen besseren erfüllen kann. Eine Market-Order zielt dagegen auf eine sofortige Ausführung zu den dann besten verfügbaren Preisen ab und kann Slippage verursachen.<sup>[[4]](#references)</sup>

Eine Stop-Limit-Order hat einen Stop-Preis, der eine Limit-Order aktiviert. Sie kann den Ausführungspreis begrenzen, garantiert aber keine Ausführung, wenn sich der Markt über den Limitpreis hinausbewegt.<sup>[[4]](#references)</sup>

## Futures

Ein Futures-Kontrakt ist eine standardisierte Vereinbarung, eine bestimmte Ware oder ein bestimmtes Finanzinstrument zu einem zukünftigen Zeitpunkt zu kaufen oder zu verkaufen. Beispielsweise könnten zwei Parteien einen Preis von 70.000 $ für einen Bitcoin mit Abrechnung in sechs Monaten vereinbaren.<sup>[[1]](#references)</sup>

Liegt der Abrechnungspreis bei 80.000 $, gewinnt die Long-Seite und die Short-Seite verliert gegenüber dem Kontraktpreis von 70.000 $. Bei 60.000 $ kehrt sich die Richtung um. Tatsächlich börsengehandelte Futures werden zum Marktwert bewertet und normalerweise vor Ablauf geschlossen oder gerollt; dies ist daher eine vereinfachte Veranschaulichung.<sup>[[2]](#references)</sup>

Produzenten und Verbraucher nutzen Futures zur Absicherung von Preisrisiken; andere Marktteilnehmer nutzen sie, um Gewinne anzustreben oder Liquidität bereitzustellen.<sup>[[1]](#references)</sup>

- Eine **Long-Position** profitiert im Allgemeinen, wenn der Kontraktpreis steigt.
- Eine **Short-Position** profitiert im Allgemeinen, wenn der Kontraktpreis fällt.<sup>[[2]](#references)</sup>

### Absicherung mit Futures

Wenn ein Fondsmanager erwartet, dass ein Portfolio an Wert verliert, könnte er einen ausreichend stark korrelierten Aktienindex-Futures-Kontrakt leerverkaufen. Gewinne aus der Short-Absicherung können einen Teil der Portfolioverluste ausgleichen; aufgrund des Basisrisikos ist der Ausgleich selten exakt. Ein Bitcoin-Future würde ein Bitcoin-Engagement absichern, nicht automatisch ein Aktienportfolio.

Fällt der abgesicherte Markt, kann die Short-Futures-Position an Wert gewinnen, während die Bestände an Wert verlieren. Steigt er, können die Bestände an Wert gewinnen, während die Absicherung Verluste verursacht. Eine Absicherung reduziert bestimmte Risiken, statt einen garantierten Gewinn zu erzielen.<sup>[[1]](#references)</sup>

### Perpetual Futures

Perpetual-Kontrakte sind Derivate ohne festes Ablaufdatum. Krypto-Handelsplattformen verwenden häufig regelmäßige Funding-Zahlungen, um ihren Preis nahe am zugrunde liegenden Spotpreis zu halten; die Bedingungen unterscheiden sich je nach Plattform.<sup>[[3]](#references)</sup>

Tests auf Missbrauch von Funding Rates bei On-Chain-Perpetual-Protokollen finden Sie unter [Ausnutzung von Perpetual-Funding-Rates](perpetual-funding-rate-exploitation.md).

Gewinn und Verlust ändern sich mit dem Markpreis. Eine Preisbewegung von 1 % führt vor Gebühren und Funding zu einer Bewegung von ungefähr 1 % des Nominalwerts der Position. Durch den Hebel kann dies jedoch einen deutlich größeren prozentualen Anteil der hinterlegten Sicherheit ausmachen.

### Futures mit Hebel

**Hebel** ermöglicht es einem Trader, mit einer geringeren Sicherheitsleistung eine größere Position mit höherem Nominalwert zu kontrollieren. Verluste sind nicht immer auf die anfängliche Sicherheitsleistung beschränkt: Liquidation, Kurslücken, Gebühren und die Regeln der Handelsplattform können zusätzliche Verluste verursachen.<sup>[[3]](#references)</sup>

Beispielsweise kontrollieren 100 $ Sicherheitsleistung bei einem Hebel von 50x eine Position von 5.000 $. Gebühren, Funding und Liquidationsmechanismen außer Acht gelassen, führt eine günstige Kursbewegung von 1 % zu einem Gewinn von 50 $ (50 % der anfänglichen Sicherheitsleistung), während eine ungünstige Kursbewegung von 1 % einen Verlust von 50 $ verursacht. Eine ungünstige Bewegung von 2 % entspricht 100 $, allerdings wird eine Handelsplattform die Position normalerweise liquidieren, bevor die gesamte Sicherheitsleistung aufgebraucht ist.

Ein Hebel verstärkt sowohl Gewinne als auch Verluste und ermöglicht eine Liquidation bereits nach einer vergleichsweise kleinen ungünstigen Kursbewegung.

## Unterschiede zwischen Futures und Optionen

Ein Optionskäufer erhält das Recht, aber nicht die Pflicht, die Option gemäß den Vertragsbedingungen auszuüben. Der Optionsverkäufer hat die entsprechende Verpflichtung, falls der Käufer die Option ausübt. Der Käufer zahlt dem Verkäufer für dieses Recht eine Prämie.<sup>[[4]](#references)</sup>

### 1. **Verpflichtung vs. Recht:**

* **Futures:** Wenn Sie einen Futures-Kontrakt kaufen oder verkaufen, gehen Sie eine **verbindliche Vereinbarung** ein, einen Vermögenswert an einem zukünftigen Datum zu einem bestimmten Preis zu kaufen oder zu verkaufen. Sowohl Käufer als auch Verkäufer sind **verpflichtet**, den Vertrag bei Fälligkeit zu erfüllen, sofern der Vertrag nicht vorher geschlossen wird.
* **Optionen:** Bei Optionen haben Sie das **Recht, aber nicht die Pflicht**, einen Vermögenswert zu einem bestimmten Preis vor oder an einem bestimmten Ablaufdatum zu kaufen (bei einer **Call-Option**) oder zu verkaufen (bei einer **Put-Option**). Der **Käufer** kann die Option ausüben, während der **Verkäufer** verpflichtet ist, den Handel abzuwickeln, wenn der Käufer sich für die Ausübung entscheidet.

### 2. **Risiko:**

* **Futures:** Beide Seiten können erhebliche Verluste erleiden. Ob der Verlust mathematisch unbegrenzt ist, hängt von der Position und dem zugrunde liegenden Vermögenswert ab: Bei einer Short-Position kann der theoretische Verlust unbegrenzt sein, während eine Long-Position nicht mehr als den Nominalwert verlieren kann, wenn der zugrunde liegende Vermögenswert nicht unter null fallen kann.
* **Optionen:** Ein Käufer, der nicht zugleich eine andere Option verkauft, riskiert im Allgemeinen die gezahlte Prämie. Bei einem ungedeckten Call-Verkauf kann der Verlust theoretisch unbegrenzt sein; andere Optionsverkaufsstrategien haben unterschiedliche begrenzte oder unbegrenzte Risikoprofile.

### 3. **Kosten:**

* **Futures:** Abgesehen von der erforderlichen Sicherheitsleistung für das Halten der Position fallen keine Vorauszahlungen an, da sowohl Käufer als auch Verkäufer verpflichtet sind, den Handel abzuschließen.
* **Optionen:** Der Käufer muss für das Recht, die Option auszuüben, vorab eine **Optionsprämie** zahlen. Diese Prämie ist im Wesentlichen der Preis der Option.

### 4. **Gewinnpotenzial:**

* **Futures:** Der Gewinn oder Verlust ergibt sich aus der Differenz zwischen dem Marktpreis bei Fälligkeit und dem im Vertrag vereinbarten Preis.
* **Optionen:** Der Käufer erzielt einen Gewinn, wenn sich der Marktpreis über den Ausübungspreis hinaus und um mehr als die gezahlte Prämie zu seinen Gunsten bewegt. Der Verkäufer erzielt einen Gewinn, wenn er die Prämie behält, weil die Option nicht ausgeübt wird.

## References

- [1] [CFTC – Der wirtschaftliche Zweck von Futures-Märkten](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC – Grundlagen des Futures-Marktes](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC – Die Risiken des Handels mit virtuellen Währungen verstehen](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [CFTC-Glossar – Option, Prämie und Ausübung](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
