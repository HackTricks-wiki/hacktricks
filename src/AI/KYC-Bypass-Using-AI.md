# KYC-Umgehung mit AI

{{#include ../banners/hacktricks-training.md}}

Generative Modelle können verwendet werden, um **browserbasierte KYC-, Altersverifizierungs- und biometrische Liveness-Workflows zu umgehen**. Die Schwachstelle liegt häufig **nicht** im Transport oder beim Cloud-Liveness-Provider, sondern an der **Vertrauensgrenze der Kamera**: Ein Desktop-Browser vertraut normalerweise jedem Gerät, das `getUserMedia()` als Webcam bereitstellt.

## Praktische Angriffskette

1. **Challenge-konforme Medien generieren** mit einem Video-to-Video-Modell anhand eines Quellakteurs und eines Referenzbilds des Opfers.
2. **Den gefälschten Stream vor dem Signieren oder Upload injizieren**, beispielsweise über eine mit `v4l2loopback` erstellte virtuelle Kamera unter Linux, die von OBS oder FFmpeg gespeist wird.
3. Den Browser und das Vendor-SDK (WebRTC, AWS usw.) die **vom Angreifer kontrollierten Frames erfassen, signieren und hochladen lassen, als stammten sie von einer echten Webcam**.

Dies ist bei Assessments wichtig, da signierte WebSocket-Chunks oder proprietäres SDK-Framing **Manipulationen auf Netzwerkebene** unpraktikabel machen können, während **Injektionen auf Kameraebene** weiterhin funktionieren.

## Besonders wertvolle Testansätze

- **Akzeptanz virtueller Webcams**: Wenn der Ablauf über einen Desktop-Browser funktioniert, sollte getestet werden, ob OBS, `v4l2loopback` oder virtuelle Kameras des Anbieters als normale Peripheriegeräte akzeptiert werden.
- **Umleitung der Kamera-API auf Mobilgeräten**: Native mobile Abläufe können weiterhin anfällig sein, wenn Frida Kamera-APIs hookt und Sensorpuffer durch Frames aus einer MP4-Datei oder einer emulatorbasierten virtuellen Kamera ersetzt.
- **Abschwächung von Constraints**: Seiten, die eine exakte `deviceId`, `frameRate`, `width`, `height` oder `facingMode` verlangen, können manchmal durch Monkeypatching von `navigator.mediaDevices.getUserMedia` und das Ersetzen strikter Constraints durch breitere Bereiche umgangen werden.
- **Generierung in niedriger Qualität mit anschließendem Post-Processing**: Das günstigste Video generieren, das das Modell zuverlässig rendern kann, und anschließend FFmpeg-Upscaling oder Frame-Interpolation verwenden, um die Anforderungen der Aufnahme zu erfüllen.
- **Vorhersehbare aktive Challenges**: Wiederholte Sequenzen mit Kopfbewegungen oder Lichtblitzen sind es wert, aufgezeichnet und über einen generativen Workflow wiedergegeben zu werden.
- **Schwache Replay-Erkennung**: Einfache Szenenveränderungen wie Zuschnitt- oder Positionsverschiebungen, Änderungen an Overlays oder geringfügige Bewegungen können ausreichen, wenn die Anti-Replay-Logik nur oberflächliche Frame-Ähnlichkeiten prüft.

## Unterschiede beim Vertrauen zwischen Mobilgeräten und Desktop

Native mobile Apps können die Kosten für den Angreifer erhöhen durch:

- **Attestation von Sensoren oder Secure Elements** für Kamerapuffer;
- **Execution-Integrity-Signale** wie **Play Integrity** oder **App Attest**;
- **Bewegungskorrelation** zwischen Video und Telemetriedaten des Beschleunigungssensors oder Gyroskops.

Desktop-Web-Abläufe verfügen normalerweise über keine gleichwertige Vertrauenskette für Kameras und sind daher im Allgemeinen der Weg des geringsten Widerstands.

## Hinweise für die defensive Prüfung

Bei der Überprüfung einer KYC- oder Liveness-Integration sollte festgestellt werden, ob sie:

- einen **Fallback für Desktop-Browser** bei einem Workflow zulässt, der ursprünglich nur für mobile Aufnahmen als Bedrohungsmodell betrachtet wurde;
- sich hauptsächlich auf **algorithmische Liveness** ohne starke menschliche Eskalation bei verdächtigen Sitzungen stützt;
- **stabile oder vorhersehbare Challenges** verwendet, die vorab aufgezeichnet und in eine Generierungspipeline eingespeist werden können;
- **Monkeypatching von `getUserMedia`**, virtuelle Kameras, inkonsistente Browser-Hardwaretelemetrie oder fehlende Geräte-Attestation erkennt.

## Referenzen

- [Synacktiv - KYC: Umgehung der Altersverifizierung mit generativen Videomodellen](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
