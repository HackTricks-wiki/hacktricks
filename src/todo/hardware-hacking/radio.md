# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)ist ein kostenloser digitaler Signalanalysator für GNU/Linux und macOS, der dafür entwickelt wurde, Informationen aus unbekannten Funksignalen zu extrahieren. Er unterstützt über SoapySDR eine Vielzahl von SDR-Geräten und ermöglicht die einstellbare Demodulation von FSK-, PSK- und ASK-Signalen, das Decodieren analoger Videos, die Analyse burstartiger Signale sowie das Abhören analoger Sprachkanäle (alles in Echtzeit).<sup>[[1]](#references)</sup>

### Grundlegende Konfiguration

Nach der Installation gibt es einige Dinge, deren Konfiguration du in Betracht ziehen solltest.\
In den Einstellungen (der zweite Tab-Button) kannst du das **SDR-Gerät** auswählen oder **eine Datei auswählen**, die gelesen werden soll, sowie die zu syntonisierende Frequenz und die Sample-Rate festlegen (empfohlen werden bis zu 2.56 Msps, sofern dein PC dies unterstützt).

![SigDigger-Einstellungen mit Optionen für SDR-Gerät, Eingabedatei, Frequenz und Sample-Rate](<../../images/image (245).png>)

Im GUI-Verhalten wird empfohlen, einige Optionen zu aktivieren, sofern dein PC dies unterstützt:

![SigDigger - Grundlegende Konfiguration: Im GUI-Verhalten wird empfohlen, einige Optionen zu aktivieren, sofern dein PC dies unterstützt](<../../images/image (472).png>)

> [!TIP]
> Wenn du feststellst, dass dein PC nichts aufnimmt, versuche, OpenGL zu deaktivieren und die Sample-Rate zu verringern.

### Verwendung

- Um **einen Signalabschnitt aufzunehmen und zu analysieren**, halte den Button "Push to capture" so lange gedrückt, wie nötig.

![Grundlegende Konfiguration - Verwendung: Um einen Signalabschnitt aufzunehmen und zu analysieren, halte den Button "Push to capture" so lange gedrückt, wie nötig](<../../images/image (960).png>)

- Der **Tuner** von SigDigger hilft dabei, **bessere Signale aufzunehmen** (kann sie aber auch verschlechtern). Beginne idealerweise mit 0 und **erhöhe den Wert**, bis das eingeführte **Rauschen** größer ist als die benötigte **Signalverbesserung**.

![SigDigger-Tuner-Steuerung zur Verbesserung des aufgenommenen Funksignals](<../../images/image (1099).png>)

### Mit einem Funkkanal synchronisieren

Synchronisiere [**SigDigger** ](https://github.com/BatchDrake/SigDigger)mit dem Kanal, den du abhören möchtest, konfiguriere die Option "Baseband audio preview", stelle die Bandbreite so ein, dass alle gesendeten Informationen erfasst werden, und setze anschließend den Tuner auf den Pegel, bevor das Rauschen deutlich zunimmt:<sup>[[1]](#references)</sup>

![SigDigger mit synchronisiertem Funkkanal, Baseband-Audio-Vorschau und konfigurierter Bandbreite](<../../images/image (585).png>)

## Interessante Tricks

- Wenn ein Gerät Informationsbursts sendet, ist der **erste Teil normalerweise ein Präambel**. Du musst dir daher **keine Sorgen machen**, wenn du dort **keine Informationen findest** oder **einige Fehler** auftreten.
- In Informationsframes solltest du normalerweise **verschiedene, gut aneinander ausgerichtete Frames finden**:

![Mit einem Funkkanal synchronisieren - Interessante Tricks: In Informationsframes solltest du normalerweise verschiedene, gut aneinander ausgerichtete Frames finden](<../../images/image (1076).png>)

![Mit einem Funkkanal synchronisieren - Interessante Tricks: In Informationsframes solltest du normalerweise verschiedene, gut aneinander ausgerichtete Frames finden](<../../images/image (597).png>)

- **Nachdem du die Bits wiederhergestellt hast, musst du sie möglicherweise auf irgendeine Weise verarbeiten**. Bei der Manchester-Codierung entspricht beispielsweise ein Anstieg+Abfall einer 1 oder 0, während ein Abfall+Anstieg dem jeweils anderen Wert entspricht. Daher bilden Paare aus 1 und 0 (Anstiege und Abfälle) eine echte 1 oder 0.
- Auch wenn ein Signal Manchester-Codierung verwendet (es ist unmöglich, mehr als zwei 0en oder 1en hintereinander zu finden), kannst du **in der Präambel mehrere aufeinanderfolgende 1en oder 0en finden**!

### Modulationstyp mit IQ ermitteln

Es gibt drei Möglichkeiten, Informationen in Signalen zu speichern: durch Modulation der **Amplitude**, **Frequenz** oder **Phase**.\
Wenn du ein Signal untersuchst, gibt es verschiedene Möglichkeiten herauszufinden, welche Methode zum Speichern der Informationen verwendet wird (weiter unten findest du weitere Möglichkeiten). Eine gute Methode ist jedoch die Untersuchung des IQ-Diagramms.

![SigDigger-IQ-Diagramm zur Ermittlung, ob ein Signal Amplituden-, Frequenz- oder Phasenmodulation verwendet](<../../images/image (788).png>)

- **AM erkennen**: Wenn im IQ-Diagramm beispielsweise **2 Kreise** erscheinen (wahrscheinlich einer bei 0 und der andere bei einer anderen Amplitude), könnte dies bedeuten, dass es sich um ein AM-Signal handelt. Im IQ-Diagramm entspricht der Abstand zwischen 0 und dem Kreis der Amplitude des Signals. Daher lassen sich verschiedene verwendete Amplituden leicht visualisieren.
- **PM erkennen**: Wie im vorherigen Bild bedeutet das Finden kleiner, nicht miteinander verbundener Kreise wahrscheinlich, dass Phasenmodulation verwendet wird. Im IQ-Diagramm entspricht der Winkel zwischen dem Punkt und 0,0 der Phase des Signals. Das bedeutet, dass 4 verschiedene Phasen verwendet werden.
- Beachte, dass du keine klar voneinander getrennten Phasen sehen wirst, wenn die Information darin verborgen ist, dass eine Phase geändert wird, und nicht in der Phase selbst.
- **FM erkennen**: IQ enthält kein Feld zur Identifikation von Frequenzen (der Abstand zum Mittelpunkt entspricht der Amplitude und der Winkel der Phase).\
Um FM zu identifizieren, solltest du in diesem Diagramm daher **im Wesentlichen nur einen Kreis sehen**.\
Außerdem wird eine andere Frequenz im IQ-Diagramm durch eine **Beschleunigung der Geschwindigkeit entlang des Kreises** dargestellt (wenn das IQ-Diagramm in SysDigger beim Auswählen des Signals gefüllt wird, kann eine Beschleunigung oder Richtungsänderung im erzeugten Kreis bedeuten, dass es sich um FM handelt):

## AM-Beispiel

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM ermitteln

#### Die Hüllkurve untersuchen

Bei der Untersuchung von AM-Informationen mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger)und alleiniger Betrachtung der **Hüllkurve** kannst du verschiedene deutliche Amplitudenpegel erkennen. Das verwendete Signal sendet Informationspulse in AM. So sieht ein Puls aus:<sup>[[1]](#references)</sup>

![SigDigger-AM-Signalhüllkurve mit klaren Pulsamplitudenpegeln](<../../images/image (590).png>)

So sieht ein Teil des Symbols mit der Wellenform aus:

![AM ermitteln - Die Hüllkurve untersuchen: So sieht ein Teil des Symbols mit der Wellenform aus](<../../images/image (734).png>)

#### Das Histogramm untersuchen

Du kannst das **gesamte Signal auswählen**, in dem sich Informationen befinden, den Modus **Amplitude** und **Selection** auswählen und auf **Histogram.** klicken. Du kannst beobachten, dass nur 2 klare Pegel vorhanden sind.

![SigDigger-Amplitudenhistogramm mit zwei klaren Pegeln für das ausgewählte AM-Signal](<../../images/image (264).png>)

Wenn du in diesem AM-Signal beispielsweise statt Amplitude die Frequenz auswählst, findest du nur 1 Frequenz (es ist nicht möglich, dass in der Frequenz modulierte Informationen nur 1 Frequenz verwenden).

![SigDigger-Frequenzhistogramm für das AM-Signal mit einer Frequenz](<../../images/image (732).png>)

Wenn du viele Frequenzen findest, handelt es sich möglicherweise nicht um FM. Wahrscheinlich wurde die Signalfrequenz lediglich durch den Kanal verändert.

#### Mit IQ

In diesem Beispiel siehst du einen **großen Kreis**, aber auch **viele Punkte im Zentrum**.

![Das Histogramm untersuchen - Mit IQ: In diesem Beispiel siehst du einen großen Kreis, aber auch viele Punkte im Zentrum](<../../images/image (222).png>)

### Symbolrate ermitteln

#### Mit einem Symbol

Wähle das kleinste Symbol aus, das du finden kannst (so kannst du sicher sein, dass es nur 1 ist), und überprüfe "Selection freq". In diesem Fall wären es 1.013 kHz (also 1 kHz).

![Symbolrate ermitteln - Mit einem Symbol: Wähle das kleinste Symbol aus, das du finden kannst, und überprüfe "Selection freq". In diesem Fall wären es 1.013 kHz (also 1 kHz)](<../../images/image (78).png>)

#### Mit einer Symbolgruppe

Du kannst auch die Anzahl der Symbole angeben, die du auswählen möchtest. SigDigger berechnet dann die Frequenz eines Symbols (je mehr Symbole ausgewählt werden, desto besser ist das Ergebnis wahrscheinlich). In diesem Szenario habe ich 10 Symbole ausgewählt und die "Selection freq" beträgt 1.004 kHz:

![Berechnung der Symbolrate in SigDigger anhand einer ausgewählten Gruppe von zehn Symbolen](<../../images/image (1008).png>)

### Bits ermitteln

Nachdem festgestellt wurde, dass es sich um ein **AM-moduliertes** Signal handelt und die **Symbolrate** bekannt ist (sowie in diesem Fall bekannt ist, dass ein Anstieg 1 und ein Abfall 0 bedeutet), ist es sehr einfach, die im Signal codierten **Bits zu ermitteln**. Wähle dazu das Signal mit den Informationen aus, konfiguriere Sampling und Entscheidung und drücke auf Sample (stelle sicher, dass **Amplitude** ausgewählt, die ermittelte **Symbolrate** konfiguriert und **Gadner clock recovery** ausgewählt ist):

![SigDigger-Panel zum Ermitteln von Bits mit konfiguriertem AM-Sampling, Symbolrate und Gardner-Clock-Recovery](<../../images/image (965).png>)

- **Sync to selection intervals** bedeutet, dass die Symbolrate verwendet wird, die du zuvor zur Ermittlung der Symbolrate ausgewählt hast.
- **Manual** bedeutet, dass die angegebene Symbolrate verwendet wird.
- Unter **Fixed interval selection** gibst du die Anzahl der auszuwählenden Intervalle an; daraus wird die Symbolrate berechnet.
- **Gadner clock recovery** ist normalerweise die beste Option. Du musst jedoch weiterhin eine ungefähre Symbolrate angeben.

Nach dem Drücken von Sample erscheint Folgendes:

![Mit einer Symbolgruppe - Bits ermitteln: Nach dem Drücken von Sample erscheint Folgendes](<../../images/image (644).png>)

Damit SigDigger versteht, **wo der Bereich** des Information tragenden Pegels liegt, musst du auf den **unteren Pegel** klicken und die Maustaste bis zum höchsten Pegel gedrückt halten:

![Auswahl des Pegelbereichs in SigDigger vom niedrigeren zum höheren Amplitudenpegel](<../../images/image (439).png>)

Wenn es beispielsweise **4 verschiedene Amplitudenpegel** gegeben hätte, müsstest du **Bits per symbol auf 2** setzen und vom niedrigsten bis zum höchsten Pegel auswählen.

Durch **Erhöhen** des **Zooms** und **Ändern der Row size** kannst du schließlich die Bits sehen (du kannst alle auswählen und kopieren, um alle Bits zu erhalten):

![Mit einer Symbolgruppe - Bits ermitteln: Durch Erhöhen des Zooms und Ändern der Zeilengröße kannst du schließlich die Bits sehen](<../../images/image (276).png>)

Wenn das Signal mehr als 1 Bit pro Symbol enthält (beispielsweise 2), kann SigDigger **nicht erkennen, welches Symbol** 00, 01, 10 oder 11 ist. Daher verwendet es verschiedene **Graustufen**, um jedes Symbol darzustellen (beim Kopieren der Bits verwendet es **Zahlen von 0 bis 3**, die du verarbeiten musst).

Verwende außerdem **Codierungen** wie **Manchester**: Anstieg+Abfall kann **1 oder 0** bedeuten, und Abfall+Anstieg kann ebenfalls 1 oder 0 bedeuten. In diesen Fällen musst du die ermittelten Anstiege (1) und Abfälle (0) **verarbeiten**, um die Paare 01 oder 10 durch 0 oder 1 zu ersetzen.

## FM-Beispiel

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM ermitteln

#### Frequenzen und Wellenform untersuchen

Beispiel eines Signals, das Informationen in FM moduliert sendet:

![FM ermitteln - Frequenzen und Wellenform untersuchen: Beispiel eines Signals, das Informationen in FM moduliert sendet](<../../images/image (725).png>)

Im vorherigen Bild kannst du gut erkennen, dass **2 Frequenzen verwendet werden**. Wenn du jedoch die **Wellenform** betrachtest, kannst du die **2 verschiedenen Frequenzen möglicherweise nicht korrekt identifizieren**:

![SigDigger-FM-Wellenform, bei der die beiden Frequenzen nur schwer direkt zu unterscheiden sind](<../../images/image (717).png>)

Das liegt daran, dass ich das Signal auf beiden Frequenzen aufnehme. Daher ist die eine Frequenz ungefähr das Negativ der anderen:

![SigDigger-FM-Aufnahme, die die beiden Frequenzen als ungefähr entgegengesetzte Werte zeigt](<../../images/image (942).png>)

Wenn die synchronisierte Frequenz **näher an einer Frequenz als an der anderen liegt**, kannst du die 2 verschiedenen Frequenzen leicht erkennen:

![FM ermitteln - Frequenzen und Wellenform untersuchen: Wenn die synchronisierte Frequenz näher an einer Frequenz als an der anderen liegt, kannst du die 2 verschiedenen Frequenzen leicht erkennen](<../../images/image (422).png>)

![FM ermitteln - Frequenzen und Wellenform untersuchen: Wenn die synchronisierte Frequenz näher an einer Frequenz als an der anderen liegt, kannst du die 2 verschiedenen Frequenzen leicht erkennen](<../../images/image (488).png>)

#### Das Histogramm untersuchen

Wenn du das Frequenzhistogramm des Signals mit Informationen untersuchst, kannst du leicht 2 verschiedene Signale erkennen:

![Frequenzen und Wellenform untersuchen - Das Histogramm untersuchen: Wenn du das Frequenzhistogramm des Signals mit Informationen untersuchst, kannst du leicht 2 verschiedene Signale erkennen](<../../images/image (871).png>)

Wenn du in diesem Fall das **Amplitudenhistogramm** überprüfst, findest du **nur eine Amplitude**. Daher **kann es sich nicht um AM handeln** (wenn du viele Amplituden findest, könnte dies daran liegen, dass das Signal entlang des Kanals an Leistung verloren hat):

![SigDigger-Amplitudenhistogramm für ein FM-Signal mit einem einzigen Amplitudenpegel](<../../images/image (817).png>)

Dies wäre das Phasenhistogramm, das sehr deutlich macht, dass das Signal nicht phasenmoduliert ist:

![Frequenzen und Wellenform untersuchen - Das Histogramm untersuchen: Dies wäre das Phasenhistogramm, das sehr deutlich macht, dass das Signal nicht phasenmoduliert ist](<../../images/image (996).png>)

#### Mit IQ

IQ enthält kein Feld zur Identifikation von Frequenzen (der Abstand zum Mittelpunkt entspricht der Amplitude und der Winkel der Phase).\
Um FM zu identifizieren, solltest du in diesem Diagramm daher **im Wesentlichen nur einen Kreis sehen**.\
Außerdem wird eine andere Frequenz im IQ-Diagramm durch eine **Beschleunigung der Geschwindigkeit entlang des Kreises** dargestellt (wenn das IQ-Diagramm in SysDigger beim Auswählen des Signals gefüllt wird, kann eine Beschleunigung oder Richtungsänderung im erzeugten Kreis bedeuten, dass es sich um FM handelt):

![SigDigger-IQ-Diagramm, in dem FM als Geschwindigkeitsänderungen entlang des Kreises erscheint](<../../images/image (81).png>)

### Symbolrate ermitteln

Du kannst **dieselbe Technik wie im AM-Beispiel** verwenden, um die Symbolrate zu ermitteln, sobald du die Frequenzen gefunden hast, die die Symbole übertragen.

### Bits ermitteln

Du kannst **dieselbe Technik wie im AM-Beispiel** verwenden, um die Bits zu ermitteln, sobald du **festgestellt hast, dass das Signal frequenzmoduliert ist**, und die **Symbolrate** kennst.

## Referenzen

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
