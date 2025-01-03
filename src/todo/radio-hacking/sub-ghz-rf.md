# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garagentore

Garagentoröffner arbeiten typischerweise im Frequenzbereich von 300-190 MHz, wobei die häufigsten Frequenzen 300 MHz, 310 MHz, 315 MHz und 390 MHz sind. Dieser Frequenzbereich wird häufig für Garagentoröffner verwendet, da er weniger überfüllt ist als andere Frequenzbänder und weniger wahrscheinlich Störungen durch andere Geräte erfährt.

## Autotüren

Die meisten Autoschlüssel-Fobs arbeiten entweder auf **315 MHz oder 433 MHz**. Dies sind beides Funkfrequenzen, die in verschiedenen Anwendungen verwendet werden. Der Hauptunterschied zwischen den beiden Frequenzen besteht darin, dass 433 MHz eine größere Reichweite hat als 315 MHz. Das bedeutet, dass 433 MHz besser für Anwendungen geeignet ist, die eine größere Reichweite erfordern, wie z.B. die Fernbedienung ohne Schlüssel.\
In Europa wird häufig 433,92 MHz verwendet, in den USA und Japan ist es 315 MHz.

## **Brute-Force-Angriff**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Wenn man anstelle von fünfmaligem Senden jedes Codes (so gesendet, um sicherzustellen, dass der Empfänger ihn erhält) nur einmal sendet, wird die Zeit auf 6 Minuten reduziert:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Und wenn man die **2 ms Wartezeit** zwischen den Signalen **entfernt**, kann man die Zeit auf **3 Minuten reduzieren.**

Darüber hinaus kann durch die Verwendung der De Bruijn-Sequenz (eine Methode zur Reduzierung der Anzahl der benötigten Bits, um alle potenziellen binären Zahlen zu brute-forcen) diese **Zeit auf nur 8 Sekunden reduziert werden**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Ein Beispiel für diesen Angriff wurde in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) implementiert.

Die Anforderung eines **Präambels wird die De Bruijn-Sequenz**-Optimierung vermeiden und **rollende Codes werden diesen Angriff verhindern** (vorausgesetzt, der Code ist lang genug, um nicht brute-forcable zu sein).

## Sub-GHz-Angriff

Um diese Signale mit Flipper Zero anzugreifen, überprüfen Sie:

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rollende Codeschutz

Automatische Garagentoröffner verwenden typischerweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Funksignal (RF)** an den Garagentoröffner, der den Motor aktiviert, um das Tor zu öffnen oder zu schließen.

Es ist möglich, dass jemand ein Gerät namens Code Grabber verwendet, um das RF-Signal abzufangen und für später zu speichern. Dies wird als **Wiedergabeangriff** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **rollendes Code**-System bekannt ist.

Das **RF-Signal wird typischerweise mit einem rollenden Code übertragen**, was bedeutet, dass sich der Code bei jeder Verwendung ändert. Dies macht es **schwierig**, dass jemand das Signal **abfängt** und es **verwendet**, um **unbefugten** Zugang zur Garage zu erhalten.

In einem rollenden Code-System haben die Fernbedienung und der Garagentoröffner einen **gemeinsamen Algorithmus**, der bei jeder Verwendung der Fernbedienung **einen neuen Code generiert**. Der Garagentoröffner reagiert nur auf den **richtigen Code**, was es viel schwieriger macht, unbefugten Zugang zur Garage zu erhalten, nur indem man einen Code abfängt.

### **Missing Link-Angriff**

Im Grunde hört man auf den Knopf und **fängt das Signal ab, während die Fernbedienung außerhalb der Reichweite** des Geräts (zum Beispiel des Autos oder der Garage) ist. Dann bewegt man sich zum Gerät und **verwendet den abgefangenen Code, um es zu öffnen**.

### Vollständiger Link-Jamming-Angriff

Ein Angreifer könnte das Signal in der Nähe des Fahrzeugs oder des Empfängers **stören**, sodass der **Empfänger den Code nicht tatsächlich „hören“ kann**, und sobald das passiert, kann man einfach den Code **abfangen und wiedergeben**, wenn man das Stören gestoppt hat.

Das Opfer wird irgendwann die **Schlüssel verwenden, um das Auto abzuschließen**, aber dann wird der Angriff **genug „Tür schließen“-Codes aufgezeichnet haben**, die hoffentlich erneut gesendet werden können, um die Tür zu öffnen (ein **Frequenzwechsel könnte erforderlich sein**, da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf beide Befehle in unterschiedlichen Frequenzen hören).

> [!WARNING]
> **Jamming funktioniert**, aber es ist auffällig, denn wenn die **Person, die das Auto abschließt, einfach die Türen testet**, um sicherzustellen, dass sie abgeschlossen sind, würde sie bemerken, dass das Auto nicht abgeschlossen ist. Außerdem, wenn sie sich solcher Angriffe bewusst sind, könnten sie sogar hören, dass die Türen nie das **Geräusch** des Abschließens gemacht haben oder die **Lichter** des Autos nie geflackert haben, als sie den „Abschließen“-Knopf drückten.

### **Code-Grabbing-Angriff (auch bekannt als „RollJam“)**
 
Dies ist eine **stealth Jamming-Technik**. Der Angreifer wird das Signal stören, sodass, wenn das Opfer versucht, die Tür abzuschließen, es nicht funktioniert, aber der Angreifer wird **diesen Code aufzeichnen**. Dann wird das Opfer **versuchen, das Auto erneut abzuschließen**, indem es den Knopf drückt, und das Auto wird **diesen zweiten Code aufzeichnen**.\
Sofort danach kann der **Angreifer den ersten Code senden** und das **Auto wird abschließen** (das Opfer wird denken, dass der zweite Druck es geschlossen hat). Dann wird der Angreifer in der Lage sein, den **zweiten gestohlenen Code zu senden, um** das Auto zu öffnen (vorausgesetzt, dass ein **„Auto schließen“-Code auch verwendet werden kann, um es zu öffnen**). Ein Frequenzwechsel könnte erforderlich sein (da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf beide Befehle in unterschiedlichen Frequenzen hören).

Der Angreifer kann **den Empfänger des Autos stören und nicht seinen eigenen Empfänger**, denn wenn der Empfänger des Autos beispielsweise in einem 1 MHz-Breitband lauscht, wird der Angreifer nicht die genaue Frequenz stören, die von der Fernbedienung verwendet wird, sondern **eine nahe Frequenz in diesem Spektrum**, während der **Empfänger des Angreifers in einem kleineren Bereich lauscht**, wo er das Signal der Fernbedienung **ohne das Störsignal** hören kann.

> [!WARNING]
> Andere in den Spezifikationen gesehene Implementierungen zeigen, dass der **rollende Code ein Teil** des gesamten gesendeten Codes ist. Das heißt, der gesendete Code ist ein **24-Bit-Schlüssel**, wobei die ersten **12 der rollende Code** sind, die **zweiten 8 der Befehl** (wie abschließen oder aufschließen) und die letzten 4 die **Prüfziffer** sind. Fahrzeuge, die diesen Typ implementieren, sind auch natürlich anfällig, da der Angreifer lediglich das Segment des rollenden Codes ersetzen muss, um **jeden rollenden Code auf beiden Frequenzen verwenden zu können**.

> [!CAUTION]
> Beachten Sie, dass, wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten sendet, der erste und der zweite Code ungültig werden.

### Alarmton-Jamming-Angriff

Tests gegen ein nachgerüstetes rollendes Codesystem, das in einem Auto installiert ist, **aktivierten das Alarmsystem** und die Wegfahrsperre sofort, als **der gleiche Code zweimal gesendet wurde**, was eine einzigartige **Denial-of-Service**-Möglichkeit bot. Ironischerweise bestand die Möglichkeit, den **Alarm** und die Wegfahrsperre zu **deaktivieren**, darin, die **Fernbedienung** zu **drücken**, was einem Angreifer die Möglichkeit gab, **fortlaufend DoS-Angriffe durchzuführen**. Oder man könnte diesen Angriff mit dem **vorherigen kombinieren, um mehr Codes zu erhalten**, da das Opfer den Angriff so schnell wie möglich stoppen möchte.

## Referenzen

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
