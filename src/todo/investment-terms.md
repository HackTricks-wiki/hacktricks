# Investment Terms

## Spot

Dies ist die grundlegendste Art des Handels. Sie können **den Betrag des Vermögenswerts und den Preis** angeben, zu dem Sie kaufen oder verkaufen möchten, und wann immer dieser Preis erreicht wird, wird die Transaktion durchgeführt.

In der Regel können Sie auch den **aktuellen Marktpreis** verwenden, um die Transaktion so schnell wie möglich zum aktuellen Preis durchzuführen.

**Stop Loss - Limit**: Sie können auch den Betrag und den Preis der Vermögenswerte angeben, die Sie kaufen oder verkaufen möchten, und gleichzeitig einen niedrigeren Preis angeben, um zu kaufen oder zu verkaufen, falls dieser erreicht wird (um Verluste zu stoppen).

## Futures

Ein Future ist ein Vertrag, bei dem sich 2 Parteien darauf einigen, **etwas in der Zukunft zu einem festen Preis zu erwerben**. Zum Beispiel, um 1 Bitcoin in 6 Monaten für 70.000$ zu verkaufen.

Offensichtlich verliert die Verkäuferseite Geld, wenn der Bitcoin-Wert in 6 Monaten 80.000$ beträgt, und die Käuferseite verdient. Wenn der Bitcoin-Wert in 6 Monaten 60.000$ beträgt, passiert das Gegenteil.

Dies ist jedoch interessant für Unternehmen, die ein Produkt herstellen und die Sicherheit benötigen, dass sie es zu einem Preis verkaufen können, um die Kosten zu decken. Oder Unternehmen, die feste Preise in der Zukunft für etwas sichern möchten, selbst wenn diese höher sind.

Obwohl dies an Börsen normalerweise verwendet wird, um einen Gewinn zu erzielen.

* Beachten Sie, dass eine "Long-Position" bedeutet, dass jemand darauf wettet, dass ein Preis steigen wird.
* Während eine "Short-Position" bedeutet, dass jemand darauf wettet, dass ein Preis fallen wird.

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Wenn ein Fondsmanager befürchtet, dass einige Aktien fallen werden, könnte er eine Short-Position über einige Vermögenswerte wie Bitcoins oder S&P 500-Futures-Kontrakte eingehen. Dies wäre ähnlich wie der Kauf oder das Halten von Vermögenswerten und das Erstellen eines Vertrags, um diese zu einem späteren Zeitpunkt zu einem höheren Preis zu verkaufen.&#x20;

Falls der Preis fällt, wird der Fondsmanager Gewinne erzielen, weil er die Vermögenswerte zu einem höheren Preis verkauft. Wenn der Preis der Vermögenswerte steigt, wird der Manager diesen Vorteil nicht erzielen, aber er wird seine Vermögenswerte dennoch behalten.

### Perpetual Futures

**Dies sind "Futures", die unbegrenzt dauern** (ohne ein Enddatum des Vertrags). Es ist sehr üblich, sie beispielsweise in Krypto-Börsen zu finden, wo Sie basierend auf dem Preis von Kryptos in Futures ein- und aussteigen können.

Beachten Sie, dass in diesen Fällen die Gewinne und Verluste in Echtzeit erfolgen können. Wenn der Preis um 1% steigt, gewinnen Sie 1%, wenn der Preis um 1% sinkt, verlieren Sie es.

### Futures with Leverage

**Leverage** ermöglicht es Ihnen, eine größere Position auf dem Markt mit einem kleineren Geldbetrag zu kontrollieren. Es ermöglicht Ihnen im Grunde, "viel mehr Geld zu setzen, als Sie haben", wobei Sie nur das Geld riskieren, das Sie tatsächlich haben.

Wenn Sie beispielsweise eine Future-Position im BTC/USDT mit 100$ und einem 50-fachen Hebel eröffnen, bedeutet dies, dass Sie bei einem Anstieg des Preises um 1% 1x50 = 50% Ihrer ursprünglichen Investition (50$) gewinnen würden. Und daher hätten Sie 150$.\
Wenn der Preis jedoch um 1% sinkt, verlieren Sie 50% Ihres Kapitals (59$ in diesem Fall). Und wenn der Preis um 2% sinkt, verlieren Sie Ihre gesamte Wette (2x50 = 100%).

Daher ermöglicht es das Leverage, die Höhe des Geldes, das Sie setzen, zu kontrollieren, während die Gewinne und Verluste erhöht werden.

## Differences Futures & Options

Der Hauptunterschied zwischen Futures und Optionen besteht darin, dass der Vertrag für den Käufer optional ist: Er kann entscheiden, ob er ihn ausführen möchte oder nicht (normalerweise wird er dies nur tun, wenn er davon profitiert). Der Verkäufer muss verkaufen, wenn der Käufer die Option nutzen möchte.\
Der Käufer zahlt jedoch eine Gebühr an den Verkäufer für die Eröffnung der Option (so dass der Verkäufer, der anscheinend mehr Risiko trägt, beginnt, etwas Geld zu verdienen).

### 1. **Obligation vs. Recht:**

* **Futures:** Wenn Sie einen Futures-Vertrag kaufen oder verkaufen, treten Sie in eine **verbindliche Vereinbarung** ein, um einen Vermögenswert zu einem bestimmten Preis an einem zukünftigen Datum zu kaufen oder zu verkaufen. Sowohl der Käufer als auch der Verkäufer sind **verpflichtet**, den Vertrag bei Fälligkeit zu erfüllen (es sei denn, der Vertrag wird vorher geschlossen).
* **Optionen:** Bei Optionen haben Sie das **Recht, aber nicht die Verpflichtung**, einen Vermögenswert zu einem bestimmten Preis vor oder zu einem bestimmten Fälligkeitsdatum zu kaufen (im Falle einer **Call-Option**) oder zu verkaufen (im Falle einer **Put-Option**). Der **Käufer** hat die Option zur Ausführung, während der **Verkäufer** verpflichtet ist, den Handel zu erfüllen, wenn der Käufer sich entscheidet, die Option auszuüben.

### 2. **Risiko:**

* **Futures:** Sowohl der Käufer als auch der Verkäufer tragen **unbegrenztes Risiko**, da sie verpflichtet sind, den Vertrag zu erfüllen. Das Risiko ist die Differenz zwischen dem vereinbarten Preis und dem Marktpreis am Fälligkeitstag.
* **Optionen:** Das Risiko des Käufers ist auf die **Prämie** beschränkt, die zum Kauf der Option gezahlt wurde. Wenn sich der Markt nicht zugunsten des Optionsinhabers bewegt, kann er die Option einfach verfallen lassen. Der **Verkäufer** (Schreiber) der Option hat jedoch ein unbegrenztes Risiko, wenn sich der Markt erheblich gegen ihn bewegt.

### 3. **Kosten:**

* **Futures:** Es gibt keine Vorauszahlung über die Margin hinaus, die erforderlich ist, um die Position zu halten, da sowohl der Käufer als auch der Verkäufer verpflichtet sind, den Handel abzuschließen.
* **Optionen:** Der Käufer muss eine **Optionsprämie** im Voraus zahlen, um das Recht zur Ausübung der Option zu erhalten. Diese Prämie ist im Wesentlichen die Kosten der Option.

### 4. **Gewinnpotenzial:**

* **Futures:** Der Gewinn oder Verlust basiert auf der Differenz zwischen dem Marktpreis bei Fälligkeit und dem im Vertrag vereinbarten Preis.
* **Optionen:** Der Käufer profitiert, wenn sich der Markt über den Ausübungspreis hinaus mehr als die gezahlte Prämie bewegt. Der Verkäufer profitiert, indem er die Prämie behält, wenn die Option nicht ausgeübt wird.
