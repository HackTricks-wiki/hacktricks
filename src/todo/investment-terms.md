# Investmentbegriffe

{{#include ../banners/hacktricks-training.md}}

## Spot

Dies ist die grundlegendste Möglichkeit, Trading zu betreiben. Sie können den **Betrag des Assets und den Preis angeben**, zu dem Sie kaufen oder verkaufen möchten. Sobald dieser Preis erreicht wird, wird die Transaktion ausgeführt.

Normalerweise können Sie auch den **aktuellen Marktpreis** verwenden, um die Transaktion so schnell wie möglich zum aktuellen Preis durchzuführen.

**Stop Loss - Limit**: Sie können außerdem den Betrag und den Preis der zu kaufenden oder zu verkaufenden Assets angeben und gleichzeitig einen niedrigeren Preis festlegen, zu dem gekauft oder verkauft werden soll, falls dieser erreicht wird (um Verluste zu begrenzen).

## Futures

Ein Future ist ein Vertrag, bei dem sich 2 Parteien darauf einigen, **etwas in der Zukunft zu einem festen Preis zu erwerben**. Zum Beispiel 1 Bitcoin in 6 Monaten für 70.000 $ zu verkaufen.

Wenn der Wert von Bitcoin nach 6 Monaten bei 80.000 $ liegt, verliert die verkaufende Partei Geld und die kaufende Partei verdient es. Wenn der Wert von Bitcoin nach 6 Monaten bei 60.000 $ liegt, passiert das Gegenteil.

Dies ist beispielsweise für Unternehmen interessant, die ein Produkt herstellen und sicherstellen müssen, dass sie es zu einem Preis verkaufen können, der ihre Kosten deckt. Es ist auch für Unternehmen interessant, die sich für die Zukunft feste Preise für etwas sichern möchten, selbst wenn diese höher sind.

An Börsen wird dies jedoch normalerweise verwendet, um Gewinne zu erzielen.

* Beachten Sie, dass eine "Long position" bedeutet, dass jemand darauf setzt, dass ein Preis steigen wird
* Eine "short position" bedeutet dagegen, dass jemand darauf setzt, dass ein Preis fallen wird

### Hedging With Futures <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Wenn ein Fondsmanager befürchtet, dass einige Aktien fallen werden, kann er eine Short-Position auf bestimmte Assets wie Bitcoin oder S\&P-500-Futures-Kontrakte eingehen. Dies wäre vergleichbar damit, einige Assets zu kaufen oder zu besitzen und einen Vertrag über deren Verkauf zu einem späteren Zeitpunkt zu einem höheren Preis abzuschließen.

Falls der Preis fällt, erzielt der Fondsmanager Gewinne, weil er die Assets zu einem höheren Preis verkaufen wird. Wenn der Preis der Assets steigt, erzielt der Manager diesen Gewinn nicht, behält aber weiterhin seine Assets.

### Perpetual Futures

**Dies sind "Futures", die unbegrenzt lange laufen** (ohne Enddatum des Vertrags). Sie sind beispielsweise an Krypto-Börsen sehr verbreitet, an denen Sie auf Grundlage des Kryptopreises in Futures ein- und aussteigen können.

Beachten Sie, dass Gewinne und Verluste in diesen Fällen in Echtzeit entstehen können: Wenn der Preis um 1 % steigt, gewinnen Sie 1 %, und wenn der Preis um 1 % fällt, verlieren Sie diesen Betrag.

### Futures with Leverage

**Leverage** ermöglicht es Ihnen, mit einem geringeren Geldbetrag eine größere Position am Markt zu kontrollieren. Dadurch können Sie im Grunde mit deutlich mehr Geld "wetten", als Sie besitzen, wobei Sie nur das Geld riskieren, das Sie tatsächlich haben.

Wenn Sie beispielsweise eine Future-Position für BTC/USDT mit 100 $ und einem 50-fachen Leverage eröffnen, bedeutet dies: Steigt der Preis um 1 %, gewinnen Sie 1 x 50 = 50 % Ihrer ursprünglichen Investition (50 $). Damit verfügen Sie über 150 $.\
Sinkt der Preis dagegen um 1 %, verlieren Sie 50 % Ihrer Mittel (in diesem Fall 50 $). Wenn der Preis um 2 % sinkt, verlieren Sie Ihren gesamten Einsatz (2 x 50 = 100 %).

Leverage ermöglicht es daher, den eingesetzten Geldbetrag zu kontrollieren und gleichzeitig Gewinne und Verluste zu vervielfachen.

## Unterschiede zwischen Futures & Optionen

Der Hauptunterschied zwischen Futures und Optionen besteht darin, dass der Vertrag für den Käufer optional ist: Er kann entscheiden, ob er ihn ausführt oder nicht (normalerweise wird er dies nur tun, wenn es für ihn profitabel ist). Der Verkäufer muss verkaufen, wenn der Käufer die Option ausüben möchte.\
Der Käufer zahlt dem Verkäufer jedoch eine Gebühr für die Eröffnung der Option (der Verkäufer, der scheinbar ein höheres Risiko übernimmt, beginnt dadurch mit der Erzielung von Einnahmen).

### 1. **Verpflichtung vs. Recht:**

* **Futures:** Wenn Sie einen Future-Kontrakt kaufen oder verkaufen, gehen Sie eine **verbindliche Vereinbarung** ein, ein Asset an einem zukünftigen Datum zu einem bestimmten Preis zu kaufen oder zu verkaufen. Sowohl der Käufer als auch der Verkäufer sind **verpflichtet**, den Vertrag bei Ablauf zu erfüllen (sofern der Vertrag nicht vorher geschlossen wird).
* **Optionen:** Bei Optionen haben Sie das **Recht, aber nicht die Verpflichtung**, ein Asset zu einem bestimmten Preis vor oder an einem bestimmten Ablaufdatum zu kaufen (bei einer **Call-Option**) oder zu verkaufen (bei einer **Put-Option**). Der **Käufer** kann entscheiden, ob er die Option ausübt, während der **Verkäufer** verpflichtet ist, den Handel auszuführen, wenn der Käufer die Option ausüben möchte.

### 2. **Risiko:**

* **Futures:** Sowohl der Käufer als auch der Verkäufer tragen ein **unbegrenztes Risiko**, da sie zur Erfüllung des Vertrags verpflichtet sind. Das Risiko entspricht der Differenz zwischen dem vereinbarten Preis und dem Marktpreis am Ablaufdatum.
* **Optionen:** Das Risiko des Käufers ist auf die für den Kauf der Option gezahlte **Prämie** begrenzt. Wenn sich der Markt nicht zugunsten des Optionsinhabers bewegt, kann dieser die Option einfach auslaufen lassen. Der **Verkäufer** (Stillhalter) der Option trägt jedoch ein unbegrenztes Risiko, wenn sich der Markt deutlich gegen ihn bewegt.

### 3. **Kosten:**

* **Futures:** Es gibt keine Vorabkosten außer der Margin, die zum Halten der Position erforderlich ist, da Käufer und Verkäufer beide verpflichtet sind, den Handel abzuschließen.
* **Optionen:** Der Käufer muss im Voraus eine **Optionsprämie** für das Recht zur Ausübung der Option zahlen. Diese Prämie stellt im Wesentlichen die Kosten der Option dar.

### 4. **Gewinnpotenzial:**

* **Futures:** Der Gewinn oder Verlust basiert auf der Differenz zwischen dem Marktpreis bei Ablauf und dem im Vertrag vereinbarten Preis.
* **Optionen:** Der Käufer erzielt einen Gewinn, wenn sich der Markt über den Strike-Preis hinaus und um mehr als die gezahlte Prämie zu seinen Gunsten bewegt. Der Verkäufer erzielt einen Gewinn, indem er die Prämie behält, wenn die Option nicht ausgeübt wird.

{{#include ../banners/hacktricks-training.md}}
