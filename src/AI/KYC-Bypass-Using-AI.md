# Bypass de KYC usando AI

{{#include ../banners/hacktricks-training.md}}

Los modelos generativos pueden utilizarse para **bypassear flujos de KYC, verificación de edad y liveness biométrico basados en navegador**. El punto débil a menudo **no es el transporte ni el proveedor cloud de liveness**, sino el **límite de confianza de la cámara**: un navegador de escritorio normalmente confía en cualquier dispositivo que `getUserMedia()` exponga como webcam.<sup>[[1]](#references)</sup>

## Cadena práctica de ataque

1. **Generar contenido multimedia que cumpla los desafíos** con un modelo de video-to-video a partir de un actor de origen y una imagen de referencia de la víctima.<sup>[[1]](#references)</sup>
2. **Inyectar el stream falsificado antes de la firma o la subida**, por ejemplo mediante una cámara virtual de Linux creada con `v4l2loopback` y alimentada por OBS o FFmpeg.<sup>[[3]](#references)</sup>
3. Permitir que el navegador y el SDK del proveedor (WebRTC, AWS, etc.) **capturen, firmen y suban los frames controlados por el atacante como si procedieran de una webcam real**.<sup>[[2]](#references)</sup>

Esto es importante durante los assessments porque los chunks de WebSocket firmados o el framing propietario del SDK pueden hacer que la **manipulación en la capa de red** resulte poco práctica, mientras que la **inyección en la capa de cámara** sigue funcionando.<sup>[[1]](#references)</sup>

## Ángulos de testing de alto valor

- **Aceptación de webcams virtuales**: si el flujo funciona desde un navegador de escritorio, comprobar si OBS, `v4l2loopback` o las cámaras virtuales del proveedor se aceptan como periféricos normales.<sup>[[1]](#references)</sup>
- **Redirección de la API de cámara en móviles**: los flujos nativos pueden seguir siendo vulnerables cuando la instrumentación en runtime, como Frida, hace hooks sobre las APIs de cámara y reemplaza los buffers del sensor por frames de un archivo MP4 o de una cámara virtual respaldada por un emulador. Esto requiere control sobre el entorno de ejecución del cliente y debe evaluarse junto con las señales de root/jailbreak e integridad de la aplicación.<sup>[[1]](#references)</sup>
- **Relajación de restricciones**: las páginas que requieren valores exactos de `deviceId`, `frameRate`, `width`, `height` o `facingMode` a veces pueden bypassarse haciendo monkeypatching de `navigator.mediaDevices.getUserMedia` y reemplazando las restricciones estrictas por rangos más amplios.<sup>[[4]](#references)</sup>
- **Generación de baja calidad con postprocesado**: comprobar si un video generado de bajo coste puede ampliarse o someterse a interpolación de frames con FFmpeg lo suficiente para cumplir las restricciones de captura.<sup>[[1]](#references)</sup>
- **Desafíos activos predecibles**: vale la pena grabar y reproducir mediante un flujo generativo las secuencias repetidas de movimientos de cabeza o destellos de luz.
- **Detección de replay débil**: perturbaciones simples de la escena, como cambios de recorte o posición, cambios en overlays o movimientos ligeros, pueden ser suficientes cuando la lógica anti-replay solo comprueba una similitud superficial entre frames.<sup>[[1]](#references)</sup>

## Diferencias de confianza entre móviles y escritorio

Las aplicaciones móviles nativas pueden aumentar el coste del atacante mediante:<sup>[[1]](#references)</sup>

- **señales de procedencia o attestation respaldadas por hardware**, incluida la evidencia respaldada por Secure Element cuando la plataforma y el stack de captura realmente la exponen;
- señales de **integridad de ejecución**, como **Play Integrity** o **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **correlación de movimiento** entre el video y la telemetría del acelerómetro o giroscopio.

Los flujos web de escritorio normalmente carecen de una cadena de confianza de cámara equivalente, por lo que generalmente son el camino de menor resistencia.<sup>[[1]](#references)</sup>

## Notas para la revisión defensiva

Al revisar una integración de KYC o liveness, verificar si:<sup>[[1]](#references)</sup>

- permite un **fallback mediante navegador de escritorio** para un flujo cuyo threat model solo contemplaba la captura móvil;
- depende principalmente de **liveness algorítmico** sin una escalación humana sólida para sesiones sospechosas;
- utiliza **desafíos estables o predecibles** que pueden pregrabarse e introducirse en un pipeline de generación;
- detecta el **monkeypatching de `getUserMedia`**, las cámaras virtuales, una telemetría de hardware del navegador incoherente o la ausencia de attestation del dispositivo.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass de la verificación de edad usando modelos generativos de video](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — API Play Integrity](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
