# KYC Bypass Usando IA

{{#include ../banners/hacktricks-training.md}}

Los modelos generativos pueden utilizarse para **bypassear flujos de KYC, verificación de edad y liveness biométrico basados en navegador**. El punto débil a menudo **no es el transporte ni el proveedor cloud de liveness**, sino el **límite de confianza de la cámara**: un navegador de escritorio normalmente confía en cualquier dispositivo que `getUserMedia()` exponga como webcam.<sup>[[1]](#references)</sup>

## Cadena de ataque práctica

1. **Generar contenido multimedia que cumpla los desafíos** con un modelo de video-to-video a partir de un actor de origen y una imagen de referencia de la víctima.
2. **Inyectar el stream falsificado antes de firmarlo o subirlo**, por ejemplo mediante una cámara virtual de Linux creada con `v4l2loopback` y alimentada por OBS o FFmpeg.
3. Permitir que el navegador y el SDK del proveedor (WebRTC, AWS, etc.) **capturen, firmen y suban los frames controlados por el atacante como si procedieran de una webcam real**.

Esto es importante durante los assessments porque los chunks de WebSocket firmados o el framing propietario del SDK pueden hacer que la **manipulación en la capa de red** sea poco práctica, mientras que la **inyección en la capa de cámara** siga funcionando.<sup>[[1]](#references)</sup>

## Vectores de testing de alto valor

- **Aceptación de webcams virtuales**: si el flujo funciona desde un navegador de escritorio, comprobar si OBS, `v4l2loopback` o las cámaras virtuales del proveedor se aceptan como periféricos normales.
- **Redirección de la API de cámara en móviles**: los flujos móviles nativos aún pueden ser vulnerables cuando Frida intercepta las APIs de cámara y reemplaza los buffers del sensor con frames procedentes de un MP4 o de una cámara virtual respaldada por un emulador.
- **Relajación de restricciones**: las páginas que requieren un `deviceId`, `frameRate`, `width`, `height` o `facingMode` exactos a veces pueden bypassarse modificando `navigator.mediaDevices.getUserMedia` mediante monkeypatching y reemplazando las restricciones estrictas por rangos más amplios.
- **Generación de baja calidad más postprocesamiento**: generar el video más barato que el modelo pueda renderizar de forma fiable y utilizar después upscaling de FFmpeg o interpolación de frames para cumplir los requisitos de captura.
- **Desafíos activos predecibles**: merece la pena grabar y reproducir mediante un flujo generativo las secuencias repetitivas de movimientos de cabeza o destellos de luz.
- **Detección de replay débil**: perturbaciones simples de la escena, como recortes o cambios de posición, modificaciones de overlays o un movimiento leve, pueden ser suficientes cuando la lógica anti-replay solo comprueba una similitud superficial entre frames.<sup>[[1]](#references)</sup>

## Diferencias de confianza entre móviles y escritorio

Las aplicaciones móviles nativas pueden aumentar el coste del atacante mediante:

- **attestation del sensor o del Secure Element** para los buffers de la cámara;
- señales de **integridad de ejecución**, como **Play Integrity** o **App Attest**;
- **correlación de movimiento** entre el video y la telemetría del acelerómetro o giroscopio.

Los flujos web de escritorio normalmente carecen de una cadena de confianza equivalente para la cámara, por lo que generalmente son el camino de menor resistencia.<sup>[[1]](#references)</sup>

## Notas para la revisión defensiva

Al revisar una integración de KYC o liveness, verificar si:

- permite un **fallback mediante navegador de escritorio** para un flujo cuyo modelado de amenazas solo contemplaba la captura móvil;
- depende principalmente del **liveness algorítmico** sin una escalada humana sólida para las sesiones sospechosas;
- utiliza **desafíos estables o predecibles** que puedan pregrabarse e introducirse en un pipeline de generación;
- detecta el **monkeypatching de `getUserMedia`**, las cámaras virtuales, la telemetría de hardware inconsistente del navegador o la ausencia de attestation del dispositivo.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Synacktiv - Bypass de la verificación de edad mediante modelos generativos de video](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
