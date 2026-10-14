# Sub-GHz-RF

{{#include ../../banners/hacktricks-training.md}}

## Garagentore

Fernbedienungen für Garagentore nutzen je nach Region und Produkt unterschiedliche Sub-GHz-Frequenzbereiche. Frequenzen wie 300, 310, 315, 390 und 433,92 MHz kommen vor, aber es gibt keinen universellen Garagentor-Frequenzbereich von „300–190 MHz“. Ermittle das Label des Ziels, die geltende Regulierungsregion und das beobachtete Signal, bevor du sendest.<sup>[[1]](#references)</sup>

## Autotüren

Viele Autoschlüssel verwenden **315 MHz oder 433,92 MHz**. Welche Frequenz gewählt wird, hängt von regionalen Vorschriften und dem Fahrzeugdesign ab. Allein die Frequenz macht 433 MHz nicht reichweitenstärker als 315 MHz: Sendeleistung, Antenneneffizienz, Modulation, Empfängerempfindlichkeit, Ausbreitung und lokale Vorschriften spielen ebenfalls eine Rolle. In Europa werden häufig 433,92 MHz verwendet, während 315 MHz in Nordamerika und Japan verbreitet sind.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Beim demonstrierten Fixed-Code-System wird die geschätzte Zeit auf sechs Minuten verkürzt, wenn jeder Code statt fünfmal nur einmal gesendet wird:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Wenn die Wartezeit von 2 ms zwischen den Signalen entfällt, dauert diese Demonstration etwa drei Minuten.

Mit einer De-Bruijn-Sequenz lassen sich überlappende Kandidaten-Bitfolgen nutzen. Dadurch verkürzt sich der demonstrierte Angriff auf etwa acht Sekunden, sofern der Empfänger die fortlaufende Sequenz ohne erforderliche Präambel oder Frame-Reset akzeptiert.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementiert diesen Angriff gegen kompatible Fixed-Code-Systeme.<sup>[[5]](#references)</sup>

Eine erforderliche **Präambel verhindert die Optimierung mit der De-Bruijn-Sequenz**, und **Rolling Codes verhindern diesen Angriff** (sofern der Code lang genug ist, um nicht per Brute Force knackbar zu sein).

## Sub-GHz Attack

Informationen zu Angriffen auf diese Signale mit Flipper Zero findest du hier:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Schutz durch Rolling Codes

Automatische Garagentoröffner verwenden üblicherweise eine drahtlose Fernbedienung, um das Garagentor zu öffnen und zu schließen. Die Fernbedienung **sendet ein Hochfrequenzsignal (RF)** an den Garagentoröffner, der den Motor zum Öffnen oder Schließen des Tors aktiviert.

Mit einem sogenannten Code-Grabber kann jemand das RF-Signal abfangen und für eine spätere Verwendung aufzeichnen. Dies wird als **replay attack** bezeichnet. Um diese Art von Angriff zu verhindern, verwenden viele moderne Garagentoröffner eine sicherere Verschlüsselungsmethode, das **Rolling-Code-System**.

Das **RF-Signal wird üblicherweise mit einem Rolling Code übertragen**. Das bedeutet, dass sich der Code bei jeder Verwendung ändert. Dadurch wird es **schwieriger**, das Signal **abzufangen** und **zu verwenden**, um sich **unbefugt** Zugang zur Garage zu verschaffen.

Bei einem Rolling-Code-System verwenden die Fernbedienung und der Garagentoröffner einen **gemeinsamen Algorithmus**, der bei jeder Verwendung der Fernbedienung **einen neuen Code generiert**. Der Garagentoröffner reagiert nur auf den **korrekten Code**. Dadurch wird es deutlich schwieriger, sich allein durch das Aufzeichnen eines Codes unbefugt Zugang zur Garage zu verschaffen.

### **Missing Link Attack**

Im Grunde hörst du auf das Tastensignal und **zeichnest es auf, während sich die Fernbedienung außerhalb der Reichweite** des Geräts befindet (zum Beispiel des Autos oder Garagentors). Anschließend gehst du zum Gerät und **verwendest den aufgezeichneten Code, um es zu öffnen**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Absichtliche RF-Störungen sind in vielen Rechtsgebieten illegal und können sicherheitsrelevante Systeme beeinträchtigen. Führe Jamming-Tests nur in einem abgeschirmten, autorisierten Labor und gemäß den geltenden Funkvorschriften durch.<sup>[[6]](#references)</sup>

Ein Angreifer könnte **das Signal in der Nähe des Fahrzeugs oder Empfängers stören**, sodass der Empfänger den Code nicht dekodieren kann. Gleichzeitig könnte er die blockierte Übertragung separat aufzeichnen, das Jamming beenden und anschließend den aufgezeichneten Code erneut senden.<sup>[[2]](#references)</sup>

Das Opfer wird irgendwann **die Schlüssel zum Verriegeln des Autos verwenden**. Der Angriff hat dann jedoch **genug „Tür schließen“-Codes aufgezeichnet**, die hoffentlich erneut gesendet werden können, um die Tür zu öffnen (möglicherweise ist ein **Frequenzwechsel erforderlich**, da manche Autos dieselben Codes zum Öffnen und Schließen verwenden, die beiden Befehle aber auf unterschiedlichen Frequenzen empfangen).

> [!WARNING]
> **Jamming funktioniert**, ist aber erkennbar: Wenn die **Person, die das Auto verriegelt, einfach die Türen überprüft**, um sicherzustellen, dass sie verschlossen sind, bemerkt sie, dass das Auto unverschlossen ist. Außerdem könnte jemand, der von solchen Angriffen weiß, darauf achten, dass die Türen beim Drücken der Verriegelungstaste kein Verriegelungs**geräusch** von sich geben oder die **Lichter** des Autos nicht blinken.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Dies ist eine **unauffälligere Jamming-Technik**. Der Angreifer stört das Signal, sodass das Verriegeln der Tür durch das Opfer fehlschlägt, zeichnet diesen Code aber **auf**. Daraufhin **versucht das Opfer erneut, das Auto zu verriegeln**, indem es die Taste drückt, und das Auto **zeichnet diesen zweiten Code auf**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Unmittelbar danach kann der **Angreifer den ersten Code senden**, woraufhin sich das **Auto verriegelt** (das Opfer glaubt, dass der zweite Tastendruck das Auto verriegelt hat). Anschließend kann der Angreifer den **zweiten gestohlenen Code senden, um das Auto zu öffnen** (vorausgesetzt, ein **„Auto schließen“-Code kann auch zum Öffnen verwendet werden**). Möglicherweise ist ein Frequenzwechsel erforderlich (da manche Autos dieselben Codes zum Öffnen und Schließen verwenden, die beiden Befehle aber auf unterschiedlichen Frequenzen empfangen).

Eine RollJam-Implementierung nutzt die Empfängerbandbreite aus: Der Jammer sendet auf einer Frequenz, die nahe genug an der Trägerfrequenz der Fernbedienung liegt, um den breitbandigeren Empfänger des Fahrzeugs unempfindlich zu machen. Der schmalbandigere Empfänger des Angreifers bleibt dabei auf die Fernbedienung abgestimmt und kann das Signal weiterhin aufzeichnen. Der genaue Frequenzversatz und die Bandbreite hängen von der Zielhardware ab.<sup>[[2]](#references)</sup>

> [!WARNING]
> Andere in Spezifikationen beschriebene Implementierungen zeigen, dass der **Rolling Code nur einen Teil des gesamten gesendeten Codes** ausmacht. Der gesendete Code besteht beispielsweise aus einem **24-Bit-Schlüssel**, dessen erste **12 Bits der Rolling Code**, dessen **nächste 8 Bits der Befehl** (etwa Verriegeln oder Entriegeln) und dessen letzte 4 Bits die **Prüfsumme** sind. Fahrzeuge mit dieser Art von Implementierung sind ebenfalls anfällig: Der Angreifer muss lediglich das Rolling-Code-Segment ersetzen, um **jeden Rolling Code auf beiden Frequenzen verwenden zu können**.

> [!CAUTION]
> Beachte: Wenn das Opfer einen dritten Code sendet, während der Angreifer den ersten sendet, werden der erste und der zweite Code ungültig.

### Alarm Sounding Jamming Attack

Bei Tests mit einem nachgerüsteten Rolling-Code-System in einem Auto **aktivierte das zweimalige Senden desselben Codes** sofort den Alarm und die Wegfahrsperre. Dadurch entstand eine besondere Möglichkeit für einen **Denial-of-Service-Angriff**. Ironischerweise ließ sich der Alarm und die Wegfahrsperre durch Drücken der **Fernbedienung** **deaktivieren**, sodass ein Angreifer den DoS-Angriff **fortlaufend ausführen** konnte. Alternativ lässt sich dieser Angriff mit dem **vorherigen kombinieren, um mehr Codes zu erhalten**, da das Opfer den Angriff so schnell wie möglich beenden möchte.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper-Zero-Dokumentation – regionale Sub-GHz-Frequenzen](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling-Code-Systeme umgehen – Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar – DEF CON 23: Fahr, als hättest du es gehackt (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Wie man ein Auto hackt – RollJam-Nachbildung mit YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame-Quellcode](https://github.com/samyk/opensesame)
- [6] [FCC-Durchsetzungsmitteilung – Durchsetzung von Jammer-Vorschriften](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
