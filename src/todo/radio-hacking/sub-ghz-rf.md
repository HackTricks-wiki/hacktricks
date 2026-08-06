# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garagentore

Garagentoröffner arbeiten typischerweise in einem Frequenzbereich von 300 bis 190 MHz, wobei 300 MHz, 310 MHz, 315 MHz und 390 MHz die häufigsten Frequenzen sind. Dieser Frequenzbereich wird häufig für Garagentoröffner verwendet, da er weniger ausgelastet ist als andere Frequenzbänder und dadurch weniger wahrscheinlich von Interferenzen durch andere Geräte betroffen ist.

## Autotüren

Die meisten Autoschlüssel-Fernbedienungen arbeiten entweder auf **315 MHz oder 433 MHz**. Beides sind Radiofrequenzen, die in einer Vielzahl verschiedener Anwendungen verwendet werden. Der Hauptunterschied zwischen den beiden Frequenzen besteht darin, dass 433 MHz eine größere Reichweite als 315 MHz haben. Das bedeutet, dass 433 MHz besser für Anwendungen geeignet sind, die eine größere Reichweite erfordern, beispielsweise Remote Keyless Entry.\
In Europa werden üblicherweise 433,92 MHz verwendet, in den USA und Japan 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Wenn stattdessen jeder Code fünfmal gesendet wird (er wird auf diese Weise gesendet, um sicherzustellen, dass der Empfänger ihn erhält), kann er einfach einmal gesendet werden, wodurch sich die Zeit auf 6 Minuten reduziert:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

und wenn du die **2 ms Wartezeit** zwischen den Signalen **entfernst**, kannst du die **Zeit auf 3 Minuten reduzieren.**

Durch die Verwendung der De-Bruijn-Sequenz (eine Methode, um die Anzahl der Bits zu reduzieren, die zum Senden aller möglichen Binärzahlen für einen Bruteforce benötigt werden) wird diese **Zeit auf nur 8 Sekunden reduziert**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Ein Beispiel für diesen Angriff wurde in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) implementiert.

Ein **Preamble ist erforderlich, um die De-Bruijn-Sequenz**-Optimierung zu verhindern, und **Rolling Codes verhindern diesen Angriff** (vorausgesetzt, der Code ist lang genug, um nicht bruteforcebar zu sein).

## Sub-GHz Attack

Um diese Signale mit dem Flipper Zero anzugreifen, siehe:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatische Garagentoröffner verwenden typischerweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Radiofrequenzsignal (RF-Signal)** an den Garagentoröffner, der den Motor zum Öffnen oder Schließen des Tors aktiviert.

Es ist möglich, dass jemand ein als Code Grabber bekanntes Gerät verwendet, um das RF-Signal abzufangen und für eine spätere Verwendung aufzuzeichnen. Dies wird als **Replay-Angriff** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **Rolling-Code**-System bekannt ist.

Das **RF-Signal wird typischerweise unter Verwendung eines Rolling Codes übertragen**, was bedeutet, dass sich der Code bei jeder Verwendung ändert. Dadurch wird es für jemanden **schwierig**, das Signal **abzufangen** und es zu verwenden, um sich **unbefugten** Zugang zum Garagentor zu verschaffen.

In einem Rolling-Code-System verfügen die Fernbedienung und der Garagentoröffner über einen **gemeinsamen Algorithmus**, der jedes Mal, wenn die Fernbedienung verwendet wird, einen neuen Code **generiert**. Der Garagentoröffner reagiert nur auf den **korrekten Code**, wodurch es für jemanden deutlich schwieriger wird, sich unbefugten Zugang zum Garagentor zu verschaffen, indem er einfach einen Code aufzeichnet.

### **Missing Link Attack**

Grundsätzlich wartet man auf das Drücken der Taste und **fängt das Signal ab, während sich die Fernbedienung außerhalb der Reichweite** des Geräts (beispielsweise des Autos oder Garagentors) befindet. Anschließend bewegt man sich zum Gerät und **verwendet den aufgezeichneten Code, um es zu öffnen**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Ein Angreifer könnte das Signal in der Nähe des Fahrzeugs oder Empfänge**r stören**, sodass der **Empfänger den Code tatsächlich nicht „hören“ kann**. Sobald dies geschieht, kann der Angreifer den Code einfach **aufzeichnen und wiedergeben**, sobald die Störung beendet wurde.<sup>[[2]](#references)</sup>

Das Opfer wird irgendwann die **Schlüssel verwenden, um das Auto zu verriegeln**, aber der Angriff hat dann **genügend „Tür-schließen“-Codes** aufgezeichnet, die hoffentlich erneut gesendet werden können, um die Tür zu öffnen (möglicherweise ist **ein Frequenzwechsel erforderlich**, da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf unterschiedlichen Frequenzen auf beide Befehle hören).

> [!WARNING]
> **Jamming funktioniert**, ist jedoch auffällig: Wenn die **Person, die das Auto abschließt, einfach die Türen testet**, um sicherzustellen, dass sie verriegelt sind, würde sie feststellen, dass das Auto entriegelt ist. Wenn sie sich außerdem solcher Angriffe bewusst wäre, könnte sie sogar bemerken, dass die Türen beim Drücken der „Verriegeln“-Taste nie das **Verriegelungsgeräusch** erzeugt haben oder die **Lichter** des Autos nie aufgeblinkt haben.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dies ist eine **unauffälligere Jamming-Technik**. Der Angreifer stört das Signal, sodass das Verriegeln der Tür nicht funktioniert, wenn das Opfer es versucht, aber der Angreifer **zeichnet diesen Code auf**. Anschließend **versucht das Opfer erneut, das Auto zu verriegeln**, indem es die Taste drückt, und das Auto **zeichnet diesen zweiten Code auf**.<sup>[[2]](#references)[[4]](#references)</sup>\
Unmittelbar danach kann der **Angreifer den ersten Code senden**, und das **Auto wird verriegelt** (das Opfer wird denken, dass der zweite Tastendruck das Auto verriegelt hat). Anschließend kann der Angreifer den **zweiten gestohlenen Code senden, um das Auto zu öffnen** (vorausgesetzt, dass ein **„Auto schließen“-Code auch zum Öffnen verwendet werden kann**). Möglicherweise ist ein Frequenzwechsel erforderlich (da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf unterschiedlichen Frequenzen auf beide Befehle hören).

Der Angreifer kann **den Autoempfänger stören und nicht seinen eigenen Empfänger**, denn wenn der Autoempfänger beispielsweise einen 1-MHz-Breitbandbereich überwacht, wird der Angreifer nicht die exakte, von der Fernbedienung verwendete Frequenz **stören**, sondern **eine nahegelegene Frequenz in diesem Spektrum**, während der **Empfänger des Angreifers einen kleineren Bereich überwacht**, in dem er das Signal der Fernbedienung **ohne das Störsignal empfangen kann**.

> [!WARNING]
> Andere in Spezifikationen beschriebene Implementierungen zeigen, dass der **Rolling Code nur einen Teil** des insgesamt gesendeten Codes darstellt. Der gesendete Code ist beispielsweise ein **24-Bit-Schlüssel**, bei dem die ersten **12 Bit der Rolling Code**, die **nächsten 8 Bit der Befehl** (beispielsweise „Verriegeln“ oder „Entriegeln“) und die letzten 4 Bit die **Prüfsumme** sind. Fahrzeuge, die diesen Typ implementieren, sind ebenfalls grundsätzlich anfällig, da der Angreifer lediglich das Rolling-Code-Segment ersetzen muss, um **beliebige Rolling Codes auf beiden Frequenzen verwenden** zu können.

> [!CAUTION]
> Beachte, dass der erste und zweite Code ungültig werden, wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten Code sendet.

### Alarm Sounding Jamming Attack

Bei Tests mit einem nachgerüsteten Rolling-Code-System in einem Auto **aktivierte das unmittelbare zweimalige Senden desselben Codes** den Alarm und die Wegfahrsperre, wodurch sich eine einzigartige Möglichkeit für einen **Denial of Service** ergab. Ironischerweise bestand die Methode zum **Deaktivieren des Alarms** und der Wegfahrsperre darin, die **Fernbedienung zu drücken**, wodurch ein Angreifer in die Lage versetzt wurde, kontinuierlich **DoS-Angriffe durchzuführen**. Alternativ kann dieser Angriff mit dem **vorherigen Angriff kombiniert werden**, um weitere Codes zu erhalten, da das Opfer den Angriff so schnell wie möglich beenden möchte.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
