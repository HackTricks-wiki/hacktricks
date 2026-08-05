# KYC Bypass mit AI

{{#include ../banners/hacktricks-training.md}}

Generative Modelle können verwendet werden, um **browserbasierte KYC-, Altersverifizierungs- und biometrische Liveness-Workflows zu umgehen**. Die Schwachstelle liegt häufig **nicht** im Transport oder beim Cloud-Liveness-Provider, sondern an der **Vertrauensgrenze der Kamera**: Ein Desktop-Browser vertraut normalerweise jedem Gerät, das `getUserMedia()` als Webcam bereitstellt.<sup>[[1]](#references)</sup>

## Praktische Angriffskette

1. **Challenge-konforme Medien generieren** mit einem Video-to-Video-Modell, einem Quell-Actor und einem Referenzbild des Opfers.
2. **Den gefälschten Stream vor dem Signieren oder Upload injizieren**, beispielsweise über eine mit `v4l2loopback` erstellte virtuelle Linux-Kamera, die von OBS oder FFmpeg gespeist wird.
3. Den Browser und das Vendor-SDK (WebRTC, AWS usw.) die **vom Angreifer kontrollierten Frames so erfassen, signieren und hochladen lassen, als kämen sie von einer echten Webcam**.

Dies ist bei Assessments wichtig, da signierte WebSocket-Chunks oder proprietäres SDK-Framing **Manipulationen auf Netzwerkebene** unpraktikabel machen können, während **Injektionen auf Kameraebene** weiterhin funktionieren.<sup>[[1]](#references)</sup>

## Besonders wertvolle Testansätze

- **Akzeptanz virtueller Webcams**: Wenn der Flow über einen Desktop-Browser funktioniert, teste, ob OBS, `v4l2loopback` oder virtuelle Kameras von Anbietern als normale Peripheriegeräte akzeptiert werden.
- **Umleitung der Kamera-API auf Mobilgeräten**: Native mobile Flows können weiterhin anfällig sein, wenn Frida Kamera-APIs hookt und Sensorpuffer durch Frames aus einer MP4-Datei oder einer emulatorgestützten virtuellen Kamera ersetzt.
- **Abschwächung von Constraints**: Seiten, die eine exakte `deviceId`, `frameRate`, `width`, `height` oder `facingMode` verlangen, können manchmal durch Monkeypatching von `navigator.mediaDevices.getUserMedia` und das Ersetzen strenger Constraints durch größere Bereiche umgangen werden.
- **Generierung mit niedriger Qualität plus Post-Processing**: Generiere das günstigste Video, das das Modell zuverlässig rendern kann, und verwende anschließend FFmpeg-Upscaling oder Frame-Interpolation, um die Anforderungen an die Aufnahme zu erfüllen.
- **Vorhersehbare aktive Challenges**: Wiederholte Sequenzen mit Kopfbewegungen oder Lichtblitzen sind es wert, aufgezeichnet und über einen generativen Workflow wiedergegeben zu werden.
- **Schwache Replay-Erkennung**: Einfache Szenenänderungen, etwa Crop- oder Positionsverschiebungen, Änderungen von Overlays oder leichte Bewegungen, können ausreichen, wenn die Anti-Replay-Logik nur oberflächliche Frame-Ähnlichkeiten prüft.<sup>[[1]](#references)</sup>

## Unterschiede beim Vertrauen zwischen Mobile und Desktop

Native mobile Apps können die Kosten für Angreifer erhöhen durch:

- **Attestation von Sensoren oder Secure Elements** für Kamerapuffer;
- **Signale zur Integrität der Ausführung**, etwa **Play Integrity** oder **App Attest**;
- **Bewegungskorrelation** zwischen Video und Telemetriedaten von Beschleunigungssensor oder Gyroskop.

Desktop-Webflows fehlt normalerweise eine gleichwertige Vertrauenskette für Kameras, weshalb sie im Allgemeinen den einfachsten Angriffsweg darstellen.<sup>[[1]](#references)</sup>

## Hinweise zur Prüfung von Schutzmaßnahmen

Bei der Prüfung einer KYC- oder Liveness-Integration sollte verifiziert werden, ob sie:

- einen **Fallback über einen Desktop-Browser** für einen Workflow erlaubt, der nur für mobile Aufnahmen als Bedrohungsmodell erstellt wurde;
- sich hauptsächlich auf **algorithmische Liveness** ohne starke menschliche Eskalation bei verdächtigen Sessions stützt;
- **stabile oder vorhersehbare Challenges** verwendet, die vorab aufgezeichnet und in eine Generierungspipeline eingespeist werden können;
- **Monkeypatching von `getUserMedia`**, virtuelle Kameras, inkonsistente Browser-Hardwaretelemetrie oder eine fehlende Geräte-Attestation erkennt.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
