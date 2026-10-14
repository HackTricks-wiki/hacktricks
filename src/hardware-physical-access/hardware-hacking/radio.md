# Funk

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) ist ein kostenloser digitaler Signalanalysator für GNU/Linux und macOS, der dafür entwickelt wurde, Informationen aus unbekannten Funksignalen zu extrahieren. Er unterstützt SDR-Geräte über SoapySDR und bietet Echtzeit-Demodulations- und Analysewerkzeuge für FSK, PSK, ASK, analoges Video, burstartige Signale und analoge Sprachkanäle.<sup>[[1]](#references)</sup>

### Grundkonfiguration

Nach der Installation gibt es einige Einstellungen, die du konfigurieren kannst.\
Wähle in den Einstellungen (die Schaltfläche des zweiten Tabs) ein **SDR-Gerät** oder eine Eingabedatei, die abzustimmende Frequenz und die Abtastrate aus. Eine Rate von bis zu 2.56 Msps kann praktikabel sein, sofern der Host sie unterstützt.

![SigDigger-Einstellungen mit Optionen für SDR-Gerät, Eingabedatei, Frequenz und Abtastrate](<../../images/image (245).png>)

In den GUI-Einstellungen wird empfohlen, einige Optionen zu aktivieren, sofern dein PC sie unterstützt:

![SigDigger – Grundkonfiguration: In den GUI-Einstellungen wird empfohlen, einige Optionen zu aktivieren, sofern dein PC sie unterstützt](<../../images/image (472).png>)

> [!TIP]
> Wenn dein PC offenbar nichts aufzeichnet, versuche, OpenGL zu deaktivieren und die Abtastrate zu verringern.

### Verwendung

- Um **ein Signal eine Zeit lang aufzuzeichnen und zu analysieren**, halte einfach die Schaltfläche „Push to capture“ so lange gedrückt, wie nötig.

![Grundkonfiguration – Verwendung: Um ein Signal eine Zeit lang aufzuzeichnen und zu analysieren, halte einfach die Schaltfläche „Push to capture“ so lange gedrückt, wie nötig](<../../images/image (960).png>)

- Mit dem **Tuner** von SigDigger kannst du **Signale besser aufzeichnen** (sie aber auch verschlechtern). Beginne idealerweise bei 0 und **erhöhe den Wert**, bis das eingeführte **Rauschen** stärker ist als die gewünschte **Verbesserung des Signals**.

![SigDigger-Tuner zur Verbesserung des aufgezeichneten Funksignals eingestellt](<../../images/image (1099).png>)

### Mit einem Funkkanal synchronisieren

Synchronisiere dich mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger) auf dem Kanal, den du abhören möchtest, konfiguriere die Option „Baseband audio preview“, stelle die Bandbreite so ein, dass alle gesendeten Informationen erfasst werden, und setze dann den Tuner auf den Wert direkt vor dem Punkt, an dem das Rauschen deutlich zunimmt:<sup>[[1]](#references)</sup>

![Mit einem Funkkanal synchronisiertes SigDigger mit konfigurierter Baseband-Audio-Vorschau und Bandbreite](<../../images/image (585).png>)

## Interessante Tricks

- Wenn ein Gerät Informationen in Bursts sendet, ist der **erste Teil normalerweise eine Präambel**. Du musst dir also **keine Sorgen machen**, wenn du dort **keine Informationen findest** oder **Fehler auftreten**.
- In Informationsframes solltest du normalerweise **verschiedene, gut aufeinander ausgerichtete Frames finden**:

![Mit einem Funkkanal synchronisieren – Interessante Tricks: In Informationsframes solltest du normalerweise verschiedene, gut aufeinander ausgerichtete Frames finden](<../../images/image (1076).png>)

![Mit einem Funkkanal synchronisieren – Interessante Tricks: In Informationsframes solltest du normalerweise verschiedene, gut aufeinander ausgerichtete Frames finden](<../../images/image (597).png>)

- **Nachdem du die Pegelübergänge wiederhergestellt hast, musst du sie möglicherweise decodieren.** Bei Manchester-Codierung steht eine Übergangsrichtung für `0` und die entgegengesetzte Richtung für `1`; die genaue Polarität hängt von der verwendeten Konvention ab.
- Eine Präambel kann eine Folge gleicher abgetasteter Pegel enthalten, selbst wenn die Nutzdaten Manchester-codiert sind. Bestimme deshalb vor dem Decodieren die Frame-Grenze.

### Modulationsart anhand von IQ ermitteln

Es gibt drei Möglichkeiten, Informationen in Signalen zu speichern: durch Modulation der **Amplitude**, **Frequenz** oder **Phase**.\
Wenn du ein Signal untersuchst, gibt es verschiedene Möglichkeiten herauszufinden, welche Methode zur Speicherung der Informationen verwendet wird (weitere Möglichkeiten findest du unten). Eine gute Methode ist, das IQ-Diagramm zu prüfen.

![SigDigger-IQ-Diagramm zur Bestimmung, ob ein Signal Amplituden-, Frequenz- oder Phasenmodulation verwendet](<../../images/image (788).png>)

- **AM erkennen**: Wenn im IQ-Diagramm beispielsweise **zwei Kreise** erscheinen (wahrscheinlich einer bei 0 und der andere bei einer anderen Amplitude), könnte es sich um ein AM-Signal handeln. Im IQ-Diagramm entspricht der Abstand zwischen 0 und dem Kreis der Amplitude des Signals. So lassen sich unterschiedliche verwendete Amplituden einfach erkennen.
- **PM erkennen**: Wie im vorherigen Bild deutet das Vorhandensein kleiner, voneinander unabhängiger Kreise wahrscheinlich auf Phasenmodulation hin. Im IQ-Diagramm entspricht der Winkel zwischen dem Punkt und dem Ursprung (0,0) der Phase des Signals. Das bedeutet, dass vier verschiedene Phasen verwendet werden.
  - Beachte, dass du unterschiedliche Phasen nicht klar voneinander unterscheiden kannst, wenn die Information darin steckt, dass sich eine Phase ändert, und nicht in der Phase selbst.
- **FM erkennen**: IQ enthält kein Feld zum Erkennen von Frequenzen (der Abstand zum Mittelpunkt entspricht der Amplitude, der Winkel der Phase).\
  Um FM zu erkennen, solltest du in diesem Diagramm daher **im Wesentlichen nur einen Kreis sehen**.\
  Außerdem verändert eine Frequenzverschiebung die Rotationsgeschwindigkeit um den IQ-Kreis. Eine Änderung der Rotationsgeschwindigkeit oder -richtung kann in SigDigger daher auf FM hindeuten.

## AM-Beispiel

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM ermitteln

#### Die Hüllkurve prüfen

Bei der Untersuchung von AM-Daten mit [**SigDigger**](https://github.com/BatchDrake/SigDigger) kann die Signal-**Hüllkurve** unterschiedliche Amplitudenpegel sichtbar machen. Das Beispiels信号 sendet Informationen als amplitudenmodulierte Impulse; ein Impuls sieht so aus:<sup>[[1]](#references)</sup>

![SigDigger-AM-Signalhüllkurve mit deutlich erkennbaren Impulsamplitudenpegeln](<../../images/image (590).png>)

So sieht ein Teil des Symbols zusammen mit der Wellenform aus:

![AM ermitteln – Die Hüllkurve prüfen: So sieht ein Teil des Symbols zusammen mit der Wellenform aus](<../../images/image (734).png>)

#### Das Histogramm prüfen

Du kannst **das gesamte Signal auswählen**, in dem sich Informationen befinden, den Modus **Amplitude** und **Selection** auswählen und auf **Histogram** klicken. Dabei sind nur zwei deutliche Pegel zu erkennen.

![SigDigger-Amplitudenhistogramm mit zwei deutlichen Pegeln für das ausgewählte AM-Signal](<../../images/image (264).png>)

Wenn du in diesem AM-Signal beispielsweise statt Amplitude die Frequenz auswählst, findest du nur eine Frequenz (es ist unwahrscheinlich, dass Informationen durch Frequenzmodulation mit nur einer Frequenz übertragen werden).

![SigDigger-Frequenzhistogramm des AM-Signals mit einer Frequenz](<../../images/image (732).png>)

Wenn du viele Frequenzen findest, handelt es sich wahrscheinlich nicht um FM. Vermutlich wurde die Signalfrequenz durch den Kanal verändert.

#### Mit IQ

In diesem Beispiel siehst du einen **großen Kreis**, aber auch **viele Punkte in der Mitte**.

![Das Histogramm prüfen – Mit IQ: In diesem Beispiel siehst du einen großen Kreis, aber auch viele Punkte in der Mitte](<../../images/image (222).png>)

### Symbolrate ermitteln

#### Mit einem Symbol

Wähle das kleinste Intervall aus, das eindeutig ein Symbol enthält, und prüfe **Selection freq**. In diesem Beispiel beträgt sie 1.013 kHz, also ungefähr 1 kHz.

![Symbolrate ermitteln – Mit einem Symbol: Wähle das kleinste Intervall aus, das eindeutig ein Symbol enthält, und prüfe „Selection freq“. In diesem Beispiel beträgt sie 1.013 kHz (also 1 kHz).](<../../images/image (78).png>)

#### Mit einer Gruppe von Symbolen

Du kannst auch die Anzahl der Symbole angeben, die du auswählen möchtest. SigDigger berechnet dann die Frequenz eines Symbols (je mehr Symbole ausgewählt werden, desto besser ist das Ergebnis wahrscheinlich). In diesem Beispiel habe ich 10 Symbole ausgewählt und „Selection freq“ beträgt 1.004 kHz:

![Berechnung der Symbolrate in SigDigger anhand einer ausgewählten Gruppe von zehn Symbolen](<../../images/image (1008).png>)

### Bits ermitteln

Nachdem du AM identifiziert und die **Symbolrate** geschätzt hast, wähle den Signalbereich aus, konfiguriere die Amplitudenabtastung und die Entscheidungsschwellen, wähle **Gardner clock recovery** und drücke **Sample**:

![SigDigger-Fenster „Get Bits“, konfiguriert für AM-Abtastung, Symbolrate und Gardner-Taktrückgewinnung](<../../images/image (965).png>)

- **Sync to selection intervals** bedeutet, dass die Symbolrate verwendet wird, wenn du zuvor Intervalle zur Ermittlung der Symbolrate ausgewählt hast.
- **Manual** bedeutet, dass die angegebene Symbolrate verwendet wird.
- Unter **Fixed interval selection** gibst du die Anzahl der auszuwählenden Intervalle an. Daraus wird die Symbolrate berechnet.
- **Gardner clock recovery** ist eine hilfreiche Standardeinstellung, benötigt aber eine ungefähre Symbolrate.

Nach dem Drücken von „Sample“ wird Folgendes angezeigt:

![Mit einer Gruppe von Symbolen – Bits ermitteln: Nach dem Drücken von „Sample“ wird Folgendes angezeigt](<../../images/image (644).png>)

Damit SigDigger den **Bereich** des informationsführenden Pegels erkennt, klicke auf den **niedrigeren Pegel** und halte die Maustaste gedrückt, bis du den höchsten Pegel erreichst:

![Auswahl des Pegelbereichs in SigDigger vom niedrigeren zum höheren Amplitudenpegel](<../../images/image (439).png>)

Wenn es beispielsweise **vier verschiedene Amplitudenpegel** gäbe, müsstest du **Bits per symbol auf 2** einstellen und den Bereich vom niedrigsten bis zum höchsten Pegel auswählen.

Wenn du schließlich den **Zoom erhöhst** und die **Zeilengröße änderst**, kannst du die Bits sehen (du kannst alle auswählen und kopieren, um alle Bits zu erhalten):

![Mit einer Gruppe von Symbolen – Bits ermitteln: Wenn du schließlich den Zoom erhöhst und die Zeilengröße änderst, kannst du die Bits sehen (du kannst alle auswählen und kopieren, um alle Bits zu erhalten)](<../../images/image (276).png>)

Wenn das Signal mehr als ein Bit pro Symbol hat (zum Beispiel 2), kann SigDigger **nicht erkennen, welches Symbol** 00, 01, 10 oder 11 ist. Deshalb verwendet es unterschiedliche **Graustufen**, um die einzelnen Symbole darzustellen (beim Kopieren der Bits verwendet es **Zahlen von 0 bis 3**, die du entsprechend verarbeiten musst).

Wandle bei Leitungscodierungen wie **Manchester** jedes gültige Übergangspaar (`01` oder `10`) gemäß der vom Protokoll verwendeten Konvention in ein Datenbit um.

## FM-Beispiel

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM ermitteln

#### Frequenzen und Wellenform prüfen

Beispiel für ein Signal, das Informationen per FM sendet:

![FM ermitteln – Frequenzen und Wellenform prüfen: Beispiel für ein Signal, das Informationen per FM sendet](<../../images/image (725).png>)

Das Spektrum zeigt deutlich **zwei Frequenzen**, auch wenn sie in der Zeitbereichswellenform schwer zu unterscheiden sein können:

![SigDigger-FM-Wellenform, in der die beiden Frequenzen schwer direkt zu unterscheiden sind](<../../images/image (717).png>)

Das liegt daran, dass die Aufzeichnung zwischen beiden Frequenzen zentriert ist und ihre Frequenzverschiebungen daher ungefähr entgegengesetzt sind:

![SigDigger-FM-Aufzeichnung mit den beiden Frequenzen als ungefähr entgegengesetzte Abweichungen](<../../images/image (942).png>)

Wenn die synchronisierte Frequenz **näher an einer der beiden Frequenzen liegt**, kannst du die beiden unterschiedlichen Frequenzen leicht erkennen:

![FM ermitteln – Frequenzen und Wellenform prüfen: Wenn die synchronisierte Frequenz näher an einer der beiden Frequenzen liegt, kannst du die beiden unterschiedlichen Frequenzen leicht erkennen](<../../images/image (422).png>)

![FM ermitteln – Frequenzen und Wellenform prüfen: Wenn die synchronisierte Frequenz näher an einer der beiden Frequenzen liegt, kannst du die beiden unterschiedlichen Frequenzen leicht erkennen](<../../images/image (488).png>)

#### Das Histogramm prüfen

Wenn du das Frequenzhistogramm des Signals mit den Informationen prüfst, kannst du leicht zwei unterschiedliche Signale erkennen:

![Frequenzen und Wellenform prüfen – Das Histogramm prüfen: Wenn du das Frequenzhistogramm des Signals mit den Informationen prüfst, kannst du leicht zwei unterschiedliche Signale erkennen](<../../images/image (871).png>)

Wenn du in diesem Fall das **Amplitudenhistogramm** prüfst, findest du **nur eine Amplitude**. Es **kann also keine AM sein** (wenn du viele Amplituden findest, könnte das daran liegen, dass das Signal während der Übertragung im Kanal an Leistung verloren hat):

![SigDigger-Amplitudenhistogramm eines FM-Signals mit einem einzigen Amplitudenpegel](<../../images/image (817).png>)

Das folgende Phasenhistogramm macht deutlich, dass das Signal nicht phasenmoduliert ist:

![Frequenzen und Wellenform prüfen – Das Histogramm prüfen: Das folgende Phasenhistogramm macht deutlich, dass das Signal nicht phasenmoduliert ist](<../../images/image (996).png>)

#### Mit IQ

IQ enthält kein Feld zum Erkennen von Frequenzen (der Abstand zum Mittelpunkt entspricht der Amplitude, der Winkel der Phase).\
Um FM zu erkennen, solltest du in diesem Diagramm daher **im Wesentlichen nur einen Kreis sehen**.\
Außerdem verändert eine Frequenzverschiebung die Rotationsgeschwindigkeit um den IQ-Kreis. Eine Änderung der Rotationsgeschwindigkeit oder -richtung kann in SigDigger daher auf FM hindeuten:

![SigDigger-IQ-Diagramm, in dem FM als Änderung der Rotationsgeschwindigkeit um den Kreis erscheint](<../../images/image (81).png>)

### Symbolrate ermitteln

Du kannst **dieselbe Methode wie im AM-Beispiel** verwenden, um die Symbolrate zu ermitteln, sobald du die Frequenzen gefunden hast, die die Symbole übertragen.

### Bits ermitteln

Du kannst **dieselbe Methode wie im AM-Beispiel** verwenden, um die Bits zu ermitteln, sobald du **festgestellt hast, dass das Signal frequenzmoduliert ist**, und die **Symbolrate** kennst.

## References

- [1] [SigDigger – Kostenloser digitaler Signalanalysator für GNU/Linux und macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
