# Radio

{{#include ../../banners/hacktricks-training.md}}

Für protokollspezifische Arbeiten nach der Signalerkennung siehe [RFID/NFC, Sub-GHz, Infrarot, BLE- und LoRaWAN-Tests](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) ist ein kostenloser Digitalsignalanalysator für GNU/Linux und macOS, der dafür entwickelt wurde, Informationen aus unbekannten Funksignalen zu extrahieren. Das Tool unterstützt SDR-Geräte über SoapySDR und bietet Echtzeit-Demodulations- und Analysewerkzeuge für FSK, PSK, ASK, analoges Video, burstartige Signale und analoge Sprachkanäle.<sup>[[1]](#references)</sup>

### Grundlegende Konfiguration

Nach der Installation gibt es einige Dinge, die du konfigurieren kannst.\
Wähle in den Einstellungen (zweiter Tab-Button) ein **SDR-Gerät** oder eine Eingabedatei, die abzustimmende Frequenz und die Abtastrate aus. Eine Rate von bis zu 2.56 Msps kann praktikabel sein, wenn der Host sie unterstützt.

![SigDigger-Einstellungen mit Optionen für SDR-Gerät, Eingabedatei, Frequenz und Abtastrate](<../../images/image (245).png>)

Es empfiehlt sich, in den GUI-Einstellungen einige Optionen zu aktivieren, sofern dein PC sie unterstützt:

![SigDigger – Grundlegende Konfiguration: Es empfiehlt sich, in den GUI-Einstellungen einige Optionen zu aktivieren, sofern dein PC sie unterstützt](<../../images/image (472).png>)

> [!TIP]
> Wenn dein PC nichts aufzuzeichnen scheint, versuche, OpenGL zu deaktivieren und die Abtastrate zu senken.

### Verwendung

- Um **einen Signalabschnitt aufzuzeichnen und zu analysieren**, halte den Button „Push to capture“ so lange gedrückt wie nötig.

![Grundlegende Konfiguration – Verwendung: Um einen Signalabschnitt aufzuzeichnen und zu analysieren, halte den Button „Push to capture“ so lange gedrückt wie nötig](<../../images/image (960).png>)

- Der **Tuner** von SigDigger hilft dabei, **Signale besser aufzuzeichnen** (kann sie aber auch verschlechtern). Beginne idealerweise bei 0 und **erhöhe den Wert**, bis das **hinzugefügte Rauschen** größer ist als die **gewünschte Signalverbesserung**.

![SigDigger-Tuner, angepasst zur Verbesserung des aufgezeichneten Funksignals](<../../images/image (1099).png>)

### Mit einem Funkkanal synchronisieren

Synchronisiere mit [**SigDigger** ](https://github.com/BatchDrake/SigDigger)den Kanal, den du abhören möchtest. Konfiguriere die Option „Baseband audio preview“ und die Bandbreite, damit alle gesendeten Informationen erfasst werden. Stelle anschließend den Tuner auf den Wert ein, bevor das Rauschen deutlich zunimmt:<sup>[[1]](#references)</sup>

![Mit SigDigger synchronisierter Funkkanal mit konfigurierter Baseband-Audio-Vorschau und Bandbreite](<../../images/image (585).png>)

## Interessante Tricks

- Wenn ein Gerät Informationsbursts sendet, ist der **erste Teil meist eine Präambel**. Du musst dir also **keine Sorgen** machen, wenn du dort **keine Informationen findest oder Fehler auftreten**.
- In Informationsframes solltest du normalerweise **verschiedene, gut zueinander ausgerichtete Frames finden**:

![Mit einem Funkkanal synchronisieren – Interessante Tricks: In Informationsframes solltest du normalerweise verschiedene, gut zueinander ausgerichtete Frames finden](<../../images/image (1076).png>)

![Mit einem Funkkanal synchronisieren – Interessante Tricks: In Informationsframes solltest du normalerweise verschiedene, gut zueinander ausgerichtete Frames finden](<../../images/image (597).png>)

- **Nachdem du die Pegelübergänge ermittelt hast, musst du sie möglicherweise dekodieren.** Bei Manchester-Codierung steht eine Übergangsrichtung für `0` und die entgegengesetzte für `1`; die genaue Polarität hängt von der verwendeten Konvention ab.
- Eine Präambel kann eine Folge desselben abgetasteten Pegels enthalten, auch wenn die Nutzdaten Manchester-codiert sind. Ermittle daher die Frame-Grenze, bevor du dekodierst.

### Modulationstyp anhand von IQ erkennen

Es gibt drei Möglichkeiten, Informationen in Signalen zu speichern: durch Modulation der **Amplitude**, **Frequenz** oder **Phase**.\
Wenn du ein Signal untersuchst, gibt es verschiedene Möglichkeiten herauszufinden, welche Methode verwendet wird (weitere Möglichkeiten folgen unten). Eine gute Methode ist jedoch, das IQ-Diagramm zu überprüfen.

![SigDigger-IQ-Diagramm zur Erkennung, ob ein Signal Amplituden-, Frequenz- oder Phasenmodulation verwendet](<../../images/image (788).png>)

- **AM erkennen**: Wenn im IQ-Diagramm beispielsweise **zwei Kreise** erscheinen (wahrscheinlich einer bei 0 und der andere bei einer anderen Amplitude), könnte es sich um ein AM-Signal handeln. Im IQ-Diagramm entspricht der Abstand zwischen 0 und dem Kreis der Amplitude des Signals. Daher lassen sich verschiedene verwendete Amplituden leicht erkennen.
- **PM erkennen**: Wie im vorherigen Bild können kleine, nicht miteinander verbundene Kreise auf Phasenmodulation hindeuten. Im IQ-Diagramm entspricht der Winkel zwischen dem Punkt und dem Ursprung (0,0) der Phase des Signals. Das bedeutet, dass vier verschiedene Phasen verwendet werden.
  - Wenn die Information darin steckt, dass eine Phase geändert wird, und nicht in der Phase selbst, sind die verschiedenen Phasen möglicherweise nicht klar voneinander zu unterscheiden.
- **FM erkennen**: IQ bietet kein Feld zur Anzeige von Frequenzen (der Abstand zum Mittelpunkt steht für die Amplitude, der Winkel für die Phase).\
  Daher solltest du bei FM in diesem Diagramm **im Wesentlichen nur einen Kreis sehen**.\
  Außerdem ändert ein Frequenzversatz die Rotationsgeschwindigkeit um den IQ-Kreis. In SigDigger kann eine Änderung der Rotationsgeschwindigkeit oder -richtung daher auf FM hindeuten.

## AM-Beispiel

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM erkennen

#### Die Hüllkurve überprüfen

Bei der Untersuchung von AM-Daten mit [**SigDigger**](https://github.com/BatchDrake/SigDigger) kann die **Hüllkurve** verschiedene Amplitudenpegel erkennen lassen. Das Beispielspe signalisiert Informationen in Form von amplitudenmodulierten Impulsen; ein Impuls sieht folgendermaßen aus:<sup>[[1]](#references)</sup>

![AM-Signalhüllkurve in SigDigger mit klar erkennbaren Impulsamplituden](<../../images/image (590).png>)

So sieht ein Teil des Symbols mit der Wellenform aus:

![AM erkennen – Die Hüllkurve überprüfen: So sieht ein Teil des Symbols mit der Wellenform aus](<../../images/image (734).png>)

#### Das Histogramm überprüfen

Du kannst **das gesamte Signal auswählen**, in dem sich Informationen befinden, den Modus **Amplitude** und **Selection** auswählen und auf **Histogram** klicken. Du kannst sehen, dass nur zwei klare Pegel vorhanden sind.

![SigDigger-Amplitudenhistogramm mit zwei klaren Pegeln für das ausgewählte AM-Signal](<../../images/image (264).png>)

Wenn du bei diesem AM-Signal beispielsweise statt Amplitude die Frequenz auswählst, findest du nur eine Frequenz (Informationen können nicht frequenzmoduliert sein, wenn nur eine Frequenz verwendet wird).

![SigDigger-Frequenzhistogramm für das AM-Signal mit einer Frequenz](<../../images/image (732).png>)

Wenn du viele Frequenzen findest, ist das Signal möglicherweise nicht FM. Wahrscheinlich wurde die Signalfrequenz lediglich durch den Kanal verändert.

#### Mit IQ

In diesem Beispiel siehst du einen **großen Kreis**, aber auch **viele Punkte in der Mitte**.

![Das Histogramm überprüfen – Mit IQ: In diesem Beispiel siehst du einen großen Kreis, aber auch viele Punkte in der Mitte](<../../images/image (222).png>)

### Die Symbolrate ermitteln

#### Mit einem Symbol

Wähle das kleinste Intervall aus, das eindeutig ein Symbol enthält, und überprüfe **Selection freq**. In diesem Beispiel sind es 1.013 kHz, also ungefähr 1 kHz.

![Die Symbolrate ermitteln – Mit einem Symbol: Wähle das kleinste Symbol aus, das du finden kannst (damit du sicher bist, dass es nur eines ist), und überprüfe „Selection freq“. In diesem Fall wären es 1.013 kHz (also 1 kHz).](<../../images/image (78).png>)

#### Mit einer Gruppe von Symbolen

Du kannst auch die Anzahl der Symbole angeben, die du auswählen möchtest. SigDigger berechnet dann die Frequenz eines Symbols (je mehr Symbole ausgewählt werden, desto besser ist das Ergebnis wahrscheinlich). In diesem Beispiel habe ich 10 Symbole ausgewählt und die „Selection freq“ beträgt 1.004 kHz:

![Berechnung der Symbolrate in SigDigger anhand einer ausgewählten Gruppe von zehn Symbolen](<../../images/image (1008).png>)

### Bits ermitteln

Nachdem du AM erkannt und die **Symbolrate** geschätzt hast, wähle den Signalbereich aus, konfiguriere die Amplitudenabtastung und die Entscheidungsschwellen, wähle **Gardner clock recovery** und klicke auf **Sample**:

![SigDigger-Panel „Get Bits“, konfiguriert für AM-Abtastung, Symbolrate und Gardner-Taktrückgewinnung](<../../images/image (965).png>)

- **Sync to selection intervals** bedeutet, dass die Symbolrate verwendet wird, wenn du zuvor Intervalle ausgewählt hast, um sie zu ermitteln.
- **Manual** bedeutet, dass die angegebene Symbolrate verwendet wird.
- Unter **Fixed interval selection** gibst du die Anzahl der auszuwählenden Intervalle an. Daraus wird die Symbolrate berechnet.
- **Gardner clock recovery** ist eine nützliche Standardeinstellung, benötigt aber weiterhin eine ungefähre Symbolrate.

Nach dem Klicken auf „Sample“ erscheint Folgendes:

![Mit einer Gruppe von Symbolen – Bits ermitteln: Nach dem Klicken auf „Sample“ erscheint Folgendes](<../../images/image (644).png>)

Damit SigDigger erkennt, **welcher Pegelbereich** die Informationen enthält, klicke auf den **niedrigeren Pegel** und ziehe bis zum höchsten Pegel:

![Auswahl des Pegelbereichs in SigDigger vom niedrigeren zum höheren Amplitudenpegel](<../../images/image (439).png>)

Bei **vier verschiedenen Amplitudenpegeln** müsstest du beispielsweise **Bits per symbol auf 2** setzen und den Bereich vom niedrigsten bis zum höchsten Pegel auswählen.

Wenn du schließlich den **Zoom erhöhst** und die **Zeilengröße änderst**, kannst du die Bits sehen (du kannst alle auswählen und kopieren, um alle Bits zu erhalten):

![Mit einer Gruppe von Symbolen – Bits ermitteln: Wenn du schließlich den Zoom erhöhst und die Zeilengröße änderst, kannst du die Bits sehen (du kannst alle auswählen und kopieren, um alle Bits zu erhalten)](<../../images/image (276).png>)

Wenn das Signal mehr als ein Bit pro Symbol hat (zum Beispiel zwei), kann SigDigger **nicht wissen, welches Symbol** 00, 01, 10 oder 11 ist. Daher verwendet es unterschiedliche **Graustufen**, um die einzelnen Symbole darzustellen (beim Kopieren der Bits werden **Zahlen von 0 bis 3** verwendet, die du entsprechend verarbeiten musst).

Wandle bei Leitungscodierungen wie **Manchester** jedes gültige Übergangspaar (`01` oder `10`) gemäß der verwendeten Protokollkonvention in ein Datenbit um.

## FM-Beispiel

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM erkennen

#### Frequenzen und Wellenform überprüfen

Beispiel eines Signals, das Informationen per FM sendet:

![FM erkennen – Frequenzen und Wellenform überprüfen: Beispiel eines Signals, das Informationen per FM sendet](<../../images/image (725).png>)

Das Spektrum zeigt deutlich **zwei Frequenzen**, auch wenn sie in der Wellenform im Zeitbereich schwer zu unterscheiden sein können:

![FM-Wellenform in SigDigger, bei der die beiden Frequenzen nicht ohne Weiteres zu unterscheiden sind](<../../images/image (717).png>)

Das liegt daran, dass die Aufzeichnung zwischen den beiden Frequenzen zentriert ist. Daher sind ihre Frequenzversätze ungefähr entgegengesetzt:

![FM-Aufzeichnung in SigDigger mit den beiden Frequenzen als ungefähr entgegengesetzten Versätzen](<../../images/image (942).png>)

Wenn die Synchronisationsfrequenz **näher an einer der beiden Frequenzen** liegt, kannst du die zwei Frequenzen leicht erkennen:

![FM erkennen – Frequenzen und Wellenform überprüfen: Wenn die Synchronisationsfrequenz näher an einer der beiden Frequenzen liegt, kannst du die zwei Frequenzen leicht erkennen](<../../images/image (422).png>)

![FM erkennen – Frequenzen und Wellenform überprüfen: Wenn die Synchronisationsfrequenz näher an einer der beiden Frequenzen liegt, kannst du die zwei Frequenzen leicht erkennen](<../../images/image (488).png>)

#### Das Histogramm überprüfen

Im Frequenzhistogramm des Signals mit den Informationen kannst du leicht zwei verschiedene Signale erkennen:

![Frequenzen und Wellenform überprüfen – Histogramm überprüfen: Im Frequenzhistogramm des Signals mit den Informationen kannst du leicht zwei verschiedene Signale erkennen](<../../images/image (871).png>)

Wenn du in diesem Fall das **Amplitudenhistogramm** überprüfst, findest du **nur eine Amplitude**. Daher **kann es sich nicht um AM handeln** (wenn du viele Amplituden findest, könnte das daran liegen, dass das Signal im Kanal an Leistung verloren hat):

![SigDigger-Amplitudenhistogramm eines FM-Signals mit nur einem Amplitudenpegel](<../../images/image (817).png>)

Das hier ist das Phasenhistogramm (das deutlich zeigt, dass das Signal nicht phasenmoduliert ist):

![Frequenzen und Wellenform überprüfen – Histogramm überprüfen: Das hier ist das Phasenhistogramm (das deutlich zeigt, dass das Signal nicht phasenmoduliert ist)](<../../images/image (996).png>)

#### Mit IQ

IQ bietet kein Feld zur Anzeige von Frequenzen (der Abstand zum Mittelpunkt steht für die Amplitude, der Winkel für die Phase).\
Daher solltest du bei FM in diesem Diagramm **im Wesentlichen nur einen Kreis sehen**.\
Außerdem ändert ein Frequenzversatz die Rotationsgeschwindigkeit um den IQ-Kreis. In SigDigger kann eine Änderung der Rotationsgeschwindigkeit oder -richtung daher auf FM hindeuten:

![SigDigger-IQ-Diagramm, in dem sich FM als Änderungen der Rotationsgeschwindigkeit um den Kreis zeigt](<../../images/image (81).png>)

### Die Symbolrate ermitteln

Mit der **gleichen Methode wie im AM-Beispiel** kannst du die Symbolrate ermitteln, sobald du die Frequenzen gefunden hast, die die Symbole übertragen.

### Bits ermitteln

Mit der **gleichen Methode wie im AM-Beispiel** kannst du die Bits ermitteln, sobald du herausgefunden hast, dass das Signal **frequenzmoduliert ist**, und die **Symbolrate** bestimmt hast.

## References

- [1] [SigDigger – Kostenloser Digitalsignalanalysator für GNU/Linux und macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
