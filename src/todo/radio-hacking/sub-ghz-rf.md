# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garagentore

Garagentoröffner arbeiten typischerweise in einem Frequenzbereich von 300-190 MHz, wobei 300 MHz, 310 MHz, 315 MHz und 390 MHz die häufigsten Frequenzen sind. Dieser Frequenzbereich wird häufig für Garagentoröffner verwendet, da er weniger ausgelastet ist als andere Frequenzbänder und seltener Interferenzen durch andere Geräte auftreten.

## Autotüren

Die meisten Autoschlüssel-Funksender arbeiten entweder mit **315 MHz oder 433 MHz**. Beide sind Radiofrequenzen und werden in verschiedenen Anwendungen eingesetzt. Der Hauptunterschied zwischen den beiden Frequenzen besteht darin, dass 433 MHz eine größere Reichweite als 315 MHz haben. Das bedeutet, dass 433 MHz besser für Anwendungen geeignet sind, die eine größere Reichweite erfordern, beispielsweise Remote Keyless Entry.\
In Europa werden üblicherweise 433,92 MHz verwendet, in den USA und Japan 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Wenn stattdessen jeder Code fünfmal gesendet wird (so wird er gesendet, um sicherzustellen, dass der Empfänger ihn erhält), und man ihn nur einmal sendet, reduziert sich die Zeit auf 6 Minuten:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Wenn man außerdem die **2 ms Wartezeit** zwischen den Signalen **entfernt**, kann man die **Zeit auf 3 Minuten reduzieren.**

Durch die Verwendung der De-Bruijn-Sequenz (eine Methode, um die Anzahl der benötigten Bits zu reduzieren, die zum Senden aller potenziellen Binärzahlen für einen Brute-Force-Angriff erforderlich sind) wird diese **Zeit auf nur 8 Sekunden reduziert**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Ein Beispiel für diesen Angriff wurde in [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup> implementiert.

Ein **Präambel erforderlich zu machen, verhindert** die Optimierung durch die De-Bruijn-Sequenz, und **Rolling Codes verhindern diesen Angriff** (vorausgesetzt, der Code ist lang genug, um nicht per Brute-Force ermittelt werden zu können).

## Sub-GHz Attack

Um diese Signale mit Flipper Zero anzugreifen, siehe:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatische Garagentoröffner verwenden typischerweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Radiofrequenz-(RF-)Signal** an den Garagentoröffner, der den Motor zum Öffnen oder Schließen des Tors aktiviert.

Es ist möglich, dass jemand ein als Code Grabber bezeichnetes Gerät verwendet, um das RF-Signal abzufangen und für eine spätere Verwendung aufzuzeichnen. Dies wird als **Replay Attack** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, die als **Rolling-Code**-System bekannt ist.

Das **RF-Signal wird typischerweise mithilfe eines Rolling Codes übertragen**, was bedeutet, dass sich der Code bei jeder Verwendung ändert. Dadurch wird es für jemanden **schwierig**, das Signal **abzufangen** und es zu verwenden, um sich **unautorisierten** Zugang zum Garagentor zu verschaffen.

In einem Rolling-Code-System verfügen die Fernbedienung und der Garagentoröffner über einen **gemeinsamen Algorithmus**, der bei jeder Verwendung der Fernbedienung einen **neuen Code erzeugt**. Der Garagentoröffner reagiert nur auf den **korrekten Code**, wodurch es deutlich schwieriger wird, sich allein durch das Aufzeichnen eines Codes unautorisierten Zugang zum Garagentor zu verschaffen.

### **Missing Link Attack**

Grundsätzlich wartet man auf das Drücken der Taste und **zeichnet das Signal auf, während sich die Fernbedienung außerhalb der Reichweite** des Geräts (beispielsweise des Autos oder Garagentors) befindet. Anschließend begibt man sich zum Gerät und **verwendet den aufgezeichneten Code, um es zu öffnen**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Ein Angreifer könnte das Signal in der Nähe des Fahrzeugs oder des Empfänge**rs stören**, sodass der **Empfänger den Code tatsächlich nicht „hören“ kann**. Sobald dies geschieht, kann man den Code einfach **aufzeichnen und wiedergeben**, wenn man das Jamming beendet hat.

Das Opfer wird irgendwann die **Schlüssel verwenden, um das Auto zu verriegeln**, aber der Angreifer hat dann **genügend „Tür-schließen“-Codes aufgezeichnet**, die hoffentlich erneut gesendet werden können, um die Tür zu öffnen (möglicherweise ist ein **Frequenzwechsel erforderlich**, da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf unterschiedlichen Frequenzen auf beide Befehle hören).

> [!WARNING]
> **Jamming funktioniert**, ist aber auffällig: Wenn die **Person, die das Auto verriegelt, einfach die Türen testet**, um sicherzustellen, dass sie verriegelt sind, würde sie feststellen, dass das Auto entriegelt ist. Wenn sie außerdem von solchen Angriffen wüsste, könnte sie sogar bemerken, dass die Türen beim Drücken der „Verriegeln“-Taste nie das **Verriegelungsgeräusch** erzeugt haben oder dass die **Lichter des Autos** nie aufleuchteten.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dies ist eine **unauffälligere Jamming-Technik**. Der Angreifer wird das Signal stören, sodass das Verriegeln der Tür nicht funktioniert, wenn das Opfer es versucht, und der Angreifer wird diesen Code **aufzeichnen**. Anschließend wird das Opfer erneut versuchen, das Auto zu verriegeln, indem es die Taste drückt, und das Auto wird **diesen zweiten Code aufzeichnen**.\
Unmittelbar danach kann der **Angreifer den ersten Code senden**, und das **Auto wird verriegelt** (das Opfer wird denken, dass der zweite Tastendruck das Auto verriegelt hat). Anschließend kann der Angreifer den **zweiten gestohlenen Code senden, um das Auto zu öffnen** (vorausgesetzt, dass ein **„Auto-schließen“-Code auch zum Öffnen verwendet werden kann**). Möglicherweise ist ein Frequenzwechsel erforderlich (da es Autos gibt, die dieselben Codes zum Öffnen und Schließen verwenden, aber auf unterschiedlichen Frequenzen auf beide Befehle hören).<sup>[[3]](#references)[[2]](#references)</sup>

Der Angreifer kann **den Autoempfänger stören, nicht jedoch seinen eigenen Empfänger**, da der Angreifer bei einem Autoempfänger, der beispielsweise eine 1-MHz-Bandbreite überwacht, nicht die exakte vom Sender verwendete Frequenz **stört**, sondern **eine nahegelegene Frequenz in diesem Spektrum**, während der **Empfänger des Angreifers einen kleineren Bereich überwacht**, in dem er das Signal der Fernbedienung **ohne das Jamming-Signal** empfangen kann.

> [!WARNING]
> Andere in Spezifikationen beobachtete Implementierungen zeigen, dass der **Rolling Code nur einen Teil** des insgesamt gesendeten Codes darstellt. Der gesendete Code ist beispielsweise ein **24-Bit-Schlüssel**, bei dem die ersten **12 Bit der Rolling Code**, die nächsten **8 Bit der Befehl** (beispielsweise „Verriegeln“ oder „Entriegeln“) und die letzten 4 Bit die **Prüfsumme** sind. Fahrzeuge mit diesem Typ sind ebenfalls grundsätzlich anfällig, da der Angreifer lediglich das Segment mit dem Rolling Code ersetzen muss, um **beliebige Rolling Codes auf beiden Frequenzen verwenden zu können**.

> [!CAUTION]
> Beachte, dass der erste und zweite Code ungültig werden, wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten Code sendet.

### Alarm Sounding Jamming Attack

Bei Tests gegen ein nachgerüstetes Rolling-Code-System in einem Auto **aktivierte das unmittelbare zweimalige Senden desselben Codes** den Alarm und die Wegfahrsperre, wodurch sich eine einzigartige Möglichkeit für einen **Denial of Service** ergab. Ironischerweise konnte der Alarm und die Wegfahrsperre durch **Drücken** der **Fernbedienung** deaktiviert werden, wodurch ein Angreifer in die Lage versetzt wurde, fortlaufend **DoS-Angriffe durchzuführen**. Alternativ kann dieser Angriff mit dem **vorherigen kombiniert werden, um weitere Codes zu erhalten**, da das Opfer den Angriff möglichst schnell beenden möchte.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
