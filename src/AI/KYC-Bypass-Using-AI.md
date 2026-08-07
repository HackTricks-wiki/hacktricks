# KYC-Bypass mit AI

{{#include ../banners/hacktricks-training.md}}

Generative Modelle können verwendet werden, um **browserbasierte KYC-, Altersverifikations- und biometrische Liveness-Workflows zu umgehen**. Die Schwachstelle liegt oft **nicht im Transport oder beim Cloud-Liveness-Provider, sondern an der Vertrauensgrenze der Kamera**: Ein Desktop-Browser vertraut normalerweise jedem Gerät, das `getUserMedia()` als Webcam bereitstellt.<sup>[[1]](#references)</sup>

## Praktische Angriffskette

1. **Challenge-konforme Medien generieren** mit einem Video-to-Video-Modell, einer Ausgangsperson und einem Referenzbild des Opfers.<sup>[[1]](#references)</sup>
2. **Den gefälschten Stream vor dem Signieren oder Upload injizieren**, beispielsweise über eine mit `v4l2loopback` erstellte virtuelle Linux-Kamera, die von OBS oder FFmpeg gespeist wird.<sup>[[3]](#references)</sup>
3. Den Browser und das Vendor-SDK (WebRTC, AWS usw.) die **vom Angreifer kontrollierten Frames erfassen, signieren und hochladen lassen, als stammten sie von einer echten Webcam**.<sup>[[2]](#references)</sup>

Dies ist bei Assessments wichtig, da signierte WebSocket-Chunks oder proprietäres SDK-Framing **Manipulationen auf Netzwerkebene** unpraktikabel machen können, während **Injection auf Kameraebene** weiterhin funktioniert.<sup>[[1]](#references)</sup>

## Besonders wertvolle Testansätze

- **Akzeptanz virtueller Webcams**: Wenn der Flow über einen Desktop-Browser funktioniert, sollte getestet werden, ob OBS, `v4l2loopback` oder virtuelle Kameras von Anbietern als normale Peripheriegeräte akzeptiert werden.<sup>[[1]](#references)</sup>
- **Umleitung der Camera API auf Mobilgeräten**: Native Mobile-Flows können weiterhin anfällig sein, wenn Frida Camera APIs hookt und Sensorpuffer durch Frames aus einer MP4-Datei oder einer emulatorgestützten virtuellen Kamera ersetzt.
- **Abschwächung von Constraints**: Seiten, die eine exakte `deviceId`, `frameRate`, `width`, `height` oder `facingMode` verlangen, können manchmal durch Monkeypatching von `navigator.mediaDevices.getUserMedia` und das Ersetzen strikter Constraints durch breitere Bereiche umgangen werden.<sup>[[4]](#references)</sup>
- **Generierung mit niedriger Qualität plus Post-Processing**: Das günstigste Video generieren, das das Modell zuverlässig rendern kann, und anschließend FFmpeg-Upscaling oder Frame-Interpolation verwenden, um die Anforderungen der Aufnahme zu erfüllen.
- **Vorhersehbare aktive Challenges**: Wiederholte Sequenzen mit Kopfbewegungen oder Lichtblitzen sind es wert, aufgezeichnet und über einen generativen Workflow wiedergegeben zu werden.
- **Schwache Replay-Erkennung**: Einfache Szenenveränderungen wie Crop- oder Positionsverschiebungen, Overlay-Änderungen oder leichte Bewegungen können ausreichen, wenn die Anti-Replay-Logik nur oberflächliche Frame-Ähnlichkeiten prüft.<sup>[[1]](#references)</sup>

## Unterschiede beim Vertrauen zwischen Mobile und Desktop

Native Mobile-Apps können die Kosten für den Angreifer erhöhen durch:<sup>[[1]](#references)</sup>

- **Attestation von Sensoren oder Secure Elements** für Kamerapuffer;
- **Execution-Integrity-Signale** wie **Play Integrity** oder **App Attest**;
- **Bewegungskorrelation** zwischen Video und Telemetriedaten von Beschleunigungssensor oder Gyroskop.

Desktop-Web-Flows verfügen normalerweise über keine gleichwertige Chain of Trust für Kameras und sind daher im Allgemeinen der Weg des geringsten Widerstands.<sup>[[1]](#references)</sup>

## Hinweise zur Defensive Review

Bei der Prüfung einer KYC- oder Liveness-Integration sollte verifiziert werden, ob sie:<sup>[[1]](#references)</sup>

- einen **Fallback für Desktop-Browser** bei einem Workflow zulässt, der ausschließlich für Mobile-Aufnahmen threat-modeled wurde;
- sich hauptsächlich auf **algorithmische Liveness** ohne starke menschliche Eskalation bei verdächtigen Sessions stützt;
- **stabile oder vorhersehbare Challenges** verwendet, die vorab aufgezeichnet und in eine Generierungspipeline eingespeist werden können;
- **`getUserMedia`-Monkeypatching**, virtuelle Kameras, inkonsistente Browser-Hardware-Telemetrie oder fehlende Device Attestation erkennt.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
