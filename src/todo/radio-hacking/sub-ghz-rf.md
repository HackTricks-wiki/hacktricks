# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garagentore

Fernbedienungen für Garagentore verwenden mehrere regions- und produktspezifische Sub-GHz-Zuweisungen. Frequenzen wie 300, 310, 315, 390 und 433,92 MHz kommen vor, aber es gibt kein universelles Garagentorband von „300–190 MHz“. Identifiziere das Etikett des Ziels, die regulatorische Region und das beobachtete Signal, bevor du sendest.<sup>[[1]](#references)</sup>

## Autotüren

Viele Autoschlüssel verwenden **315 MHz oder 433,92 MHz**, wobei regionale Vorschriften und das Fahrzeugdesign die Auswahl beeinflussen. Die Frequenz allein macht 433 MHz nicht reichweitenstärker als 315 MHz: Sendeleistung, Antenneneffizienz, Modulation, Empfängerempfindlichkeit, Ausbreitung und lokale Vorschriften spielen alle eine Rolle. In Europa werden üblicherweise 433,92 MHz verwendet, während 315 MHz in Nordamerika und Japan verbreitet sind.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Im demonstrierten Fixed-Code-System reduziert das einmalige Senden jedes Codes anstelle von fünf Wiederholungen die geschätzte Zeit auf sechs Minuten:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Das Entfernen der 2-ms-Wartezeit zwischen den Signalen reduziert diese Demonstration auf ungefähr drei Minuten.

Die Verwendung einer De-Bruijn-Sequenz zur Überlappung von Bit-String-Kandidaten reduziert den demonstrierten Angriff auf ungefähr acht Sekunden, wenn der Empfänger die kontinuierliche Sequenz ohne erforderliche Präambel oder Frame-Reset akzeptiert.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementiert diesen Angriff gegen kompatible Fixed-Code-Systeme.<sup>[[5]](#references)</sup>

Das Erfordernis **einer Präambel verhindert die Optimierung durch die De-Bruijn-Sequenz**, und **Rolling Codes verhindern diesen Angriff** (vorausgesetzt, der Code ist lang genug, um nicht brute-forcebar zu sein).

## Sub-GHz Attack

Um diese Signale mit Flipper Zero anzugreifen, siehe:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Schutz durch Rolling Codes

Automatische Garagentoröffner verwenden typischerweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Radiofrequenzsignal (RF-Signal)** an den Garagentoröffner, der den Motor zum Öffnen oder Schließen des Tors aktiviert.

Jemand kann ein als Code Grabber bezeichnetes Gerät verwenden, um das RF-Signal abzufangen und zur späteren Verwendung aufzuzeichnen. Dies wird als **Replay-Angriff** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **Rolling-Code**-System bekannt ist.

Das **RF-Signal wird typischerweise unter Verwendung eines Rolling Codes übertragen**, was bedeutet, dass sich der Code bei jeder Verwendung ändert. Dadurch wird es für jemanden **schwierig**, das Signal **abzufangen** und es zu **verwenden**, um **unbefugten** Zugang zur Garage zu erlangen.

In einem Rolling-Code-System verfügen die Fernbedienung und der Garagentoröffner über einen **gemeinsamen Algorithmus**, der jedes Mal, wenn die Fernbedienung verwendet wird, einen **neuen Code generiert**. Der Garagentoröffner reagiert nur auf den **korrekten Code**, wodurch es deutlich schwieriger wird, allein durch das Aufzeichnen eines Codes unbefugten Zugang zur Garage zu erlangen.

### **Missing Link Attack**

Grundsätzlich wartet man auf das Drücken der Taste und **fängt das Signal ab, während sich die Fernbedienung außerhalb der Reichweite** des Geräts (beispielsweise des Autos oder der Garage) befindet. Anschließend begibt man sich zum Gerät und **verwendet den aufgezeichneten Code, um es zu öffnen**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Vorsätzliche RF-Störungen sind in vielen Rechtsordnungen illegal und können sicherheitsrelevante Systeme beeinträchtigen. Führe Jamming-Tests nur in einem abgeschirmten, autorisierten Labor und unter Einhaltung der geltenden Funkvorschriften durch.<sup>[[6]](#references)</sup>

Ein Angreifer könnte **das Signal in der Nähe des Fahrzeugs oder Empfängers jammen**, sodass der Empfänger den Code nicht decodieren kann, die blockierte Übertragung separat aufzeichnen, das Jamming beenden und anschließend den aufgezeichneten Code erneut senden.<sup>[[2]](#references)</sup>

Das Opfer wird irgendwann **die Schlüssel zum Verriegeln des Autos verwenden**, aber der Angriff hat dann **genügend „Tür-schließen“-Codes aufgezeichnet**, die hoffentlich erneut gesendet werden könnten, um die Tür zu öffnen (möglicherweise ist ein **Frequenzwechsel erforderlich**, da einige Autos dieselben Codes zum Öffnen und Schließen verwenden, aber auf unterschiedlichen Frequenzen auf beide Befehle hören).

> [!WARNING]
> **Jamming funktioniert**, ist jedoch auffällig: Wenn die **Person, die das Auto verriegelt, einfach die Türen testet**, um sicherzustellen, dass sie verriegelt sind, würde sie bemerken, dass das Auto nicht verriegelt ist. Wenn sie außerdem von solchen Angriffen wüsste, könnte sie sogar daran erkennen, dass die Türen beim Drücken der „Verriegeln“-Taste nie das **Verriegelungsgeräusch** erzeugt haben oder die **Lichter des Autos** nie aufgeblinkt haben.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dies ist eine **unauffälligere Jamming-Technik**. Der Angreifer jammt das Signal, sodass das Verriegeln der Tür beim Versuch des Opfers nicht funktioniert, und **zeichnet diesen Code auf**. Danach **versucht das Opfer erneut, das Auto zu verriegeln**, indem es die Taste drückt, und das Auto **zeichnet diesen zweiten Code auf**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Unmittelbar danach kann der **Angreifer den ersten Code senden**, und das **Auto wird verriegelt** (das Opfer wird denken, dass der zweite Tastendruck das Auto verriegelt hat). Anschließend kann der Angreifer den **zweiten gestohlenen Code senden, um das Auto zu öffnen** (vorausgesetzt, ein **„Auto-schließen“-Code kann auch zum Öffnen verwendet werden**). Möglicherweise ist ein Frequenzwechsel erforderlich (da einige Autos dieselben Codes zum Öffnen und Schließen verwenden, aber auf unterschiedlichen Frequenzen auf beide Befehle hören).

Eine RollJam-Implementierung nutzt die Empfängerbandbreite aus: Der Jammer sendet nahe genug am Träger der Fernbedienung, um den breiteren Empfänger des Fahrzeugs unempfindlich zu machen, während der schmalere Empfänger des Angreifers auf die Fernbedienung zentriert bleibt und sie weiterhin aufzeichnen kann. Der genaue Offset und die Bandbreite hängen von der Zielhardware ab.<sup>[[2]](#references)</sup>

> [!WARNING]
> Andere in Spezifikationen beobachtete Implementierungen zeigen, dass der **Rolling Code nur einen Teil** des insgesamt gesendeten Codes darstellt. Der gesendete Code ist beispielsweise ein **24-Bit-Schlüssel**, bei dem die ersten **12 Bit der Rolling Code**, die nächsten **8 Bit der Befehl** (etwa Verriegeln oder Entriegeln) und die letzten 4 Bit die **Prüfsumme** sind. Fahrzeuge, die diesen Typ implementieren, sind ebenfalls grundsätzlich anfällig, da der Angreifer lediglich das Rolling-Code-Segment ersetzen muss, um **jeden Rolling Code auf beiden Frequenzen verwenden** zu können.

> [!CAUTION]
> Beachte, dass der erste und zweite Code ungültig werden, wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten Code sendet.

### Alarm Sounding Jamming Attack

Bei Tests gegen ein nachgerüstetes Rolling-Code-System in einem Auto **aktivierte das unmittelbare zweimalige Senden desselben Codes** den Alarm und die Wegfahrsperre, wodurch sich eine einzigartige **Denial-of-Service**-Möglichkeit ergab. Ironischerweise bestand die Möglichkeit, den **Alarm** und die Wegfahrsperre zu **deaktivieren**, darin, die **Fernbedienung zu drücken**, wodurch ein Angreifer fortlaufend **DoS-Angriffe** durchführen konnte. Alternativ kann dieser Angriff mit dem **vorherigen kombiniert werden, um weitere Codes zu erhalten**, da das Opfer den Angriff so schnell wie möglich beenden möchte.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero-Dokumentation - regionale Sub-GHz-Frequenzen](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling-Code-Systeme umgehen - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Wie man ein Auto hackt - RollJam-Reproduktion mit YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame-Quellcode](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Durchsetzung gegen Jammer](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
