# KYC-Umgehung mit AI

{{#include ../banners/hacktricks-training.md}}

Generative Modelle können verwendet werden, um **browserbasierte KYC-, Altersverifizierungs- und biometrische Liveness-Workflows zu umgehen**. Die Schwachstelle liegt häufig **nicht** beim Transport oder beim Cloud-Liveness-Provider, sondern an der **Vertrauensgrenze der Kamera**: Ein Desktop-Browser vertraut normalerweise jedem Gerät, das `getUserMedia()` als Webcam bereitstellt.<sup>[[1]](#references)</sup>

## Praktische Angriffskette

1. **Challenge-konforme Medien generieren** mit einem Video-to-Video-Modell, einem Quell-Actor und einem Referenzbild des Opfers.<sup>[[1]](#references)</sup>
2. **Den gefälschten Stream vor dem Signieren oder Upload einschleusen**, beispielsweise über eine mit `v4l2loopback` erstellte virtuelle Linux-Kamera, die von OBS oder FFmpeg gespeist wird.<sup>[[3]](#references)</sup>
3. Den Browser und das Vendor-SDK (WebRTC, AWS usw.) die **vom Angreifer kontrollierten Frames erfassen, signieren und hochladen lassen, als ob sie von einer echten Webcam stammen würden**.<sup>[[2]](#references)</sup>

Dies ist bei Assessments wichtig, da signierte WebSocket-Chunks oder proprietäres SDK-Framing **Manipulationen auf Netzwerkebene** unpraktikabel machen können, während **Einschleusungen auf Kameraebene** weiterhin funktionieren.<sup>[[1]](#references)</sup>

## Besonders wertvolle Testansätze

- **Akzeptanz virtueller Webcams**: Wenn der Flow über einen Desktop-Browser funktioniert, testen, ob OBS, `v4l2loopback` oder virtuelle Kameras von Anbietern als normale Peripheriegeräte akzeptiert werden.<sup>[[1]](#references)</sup>
- **Umleitung der Camera API auf Mobilgeräten**: Native Flows können weiterhin anfällig sein, wenn Runtime-Instrumentierung wie Frida Camera APIs hookt und Sensorpuffer durch Frames aus einer MP4-Datei oder einer emulatorgestützten virtuellen Kamera ersetzt. Dies erfordert Kontrolle über die Client-Ausführungsumgebung und sollte gemeinsam mit Root-/Jailbreak- und Application-Integrity-Signalen bewertet werden.<sup>[[1]](#references)</sup>
- **Abschwächung von Constraints**: Seiten, die eine exakte `deviceId`, `frameRate`, `width`, `height` oder `facingMode` verlangen, können manchmal durch Monkeypatching von `navigator.mediaDevices.getUserMedia` und das Ersetzen strikter Constraints durch breitere Bereiche umgangen werden.<sup>[[4]](#references)</sup>
- **Generierung mit niedriger Qualität plus Post-Processing**: Testen, ob kostengünstig generiertes Video mit FFmpeg ausreichend hochskaliert oder per Frame-Interpolation verarbeitet werden kann, um die Capture-Constraints zu erfüllen.<sup>[[1]](#references)</sup>
- **Vorhersehbare aktive Challenges**: Wiederholte Sequenzen mit Kopfbewegungen oder Lichtblitzen sollten aufgezeichnet und über einen generativen Workflow wiedergegeben werden.
- **Schwache Replay-Erkennung**: Einfache Szenenveränderungen wie Änderungen von Ausschnitt oder Position, Overlay-Änderungen oder leichte Bewegungen können ausreichen, wenn die Anti-Replay-Logik nur oberflächliche Frame-Ähnlichkeiten prüft.<sup>[[1]](#references)</sup>

## Unterschiede beim Vertrauen zwischen Mobile und Desktop

Native Mobile-Apps können die Kosten für den Angreifer erhöhen durch:<sup>[[1]](#references)</sup>

- **hardwaregestützte Provenance- oder Attestation-Signale**, einschließlich durch ein Secure Element unterstützter Nachweise, sofern Plattform und Capture-Stack diese tatsächlich bereitstellen;
- **Execution-Integrity-Signale** wie **Play Integrity** oder **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **Bewegungskorrelation** zwischen Video und Telemetriedaten von Accelerometer oder Gyroskop.

Desktop-Web-Flows verfügen normalerweise nicht über eine gleichwertige Vertrauenskette für Kameras und sind daher im Allgemeinen der Weg des geringsten Widerstands.<sup>[[1]](#references)</sup>

## Hinweise zur Defensive Review

Bei der Überprüfung einer KYC- oder Liveness-Integration sollte verifiziert werden, ob sie:<sup>[[1]](#references)</sup>

- einen **Fallback auf einen Desktop-Browser** für einen Workflow zulässt, der nur für mobile Aufnahmen als Bedrohungsmodell betrachtet wurde;
- sich größtenteils auf **algorithmische Liveness** ohne starke menschliche Eskalation für verdächtige Sessions stützt;
- **stabile oder vorhersehbare Challenges** verwendet, die vorab aufgezeichnet und in eine Generierungspipeline eingespeist werden können;
- **Monkeypatching von `getUserMedia`**, virtuelle Kameras, inkonsistente Browser-Hardwaretelemetrie oder fehlende Device-Attestation erkennt.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Umgehung der Altersverifizierung mit generativen Videomodellen](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
