# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Los modelos generativos pueden utilizarse para **bypassear flujos de KYC basados en navegador, verificación de edad y liveness biométrico**. El punto débil a menudo **no es el transporte ni el proveedor cloud de liveness**, sino el **límite de confianza de la cámara**: un navegador de escritorio normalmente confía en cualquier dispositivo que `getUserMedia()` exponga como webcam.

## Cadena de ataque práctica

1. **Generar contenido multimedia que cumpla los desafíos** con un modelo de video a video a partir de un actor de origen y una imagen de referencia de la víctima.
2. **Inyectar el stream falsificado antes de firmarlo o subirlo**, por ejemplo mediante una cámara virtual de Linux creada con `v4l2loopback` y alimentada por OBS o FFmpeg.
3. Permitir que el navegador y el SDK del proveedor (WebRTC, AWS, etc.) **capturen, firmen y suban los frames controlados por el atacante como si procedieran de una webcam real**.

Esto es importante durante los assessments porque los chunks de WebSocket firmados o el framing propietario del SDK pueden hacer que la **manipulación en la capa de red** sea poco práctica, mientras que la **inyección en la capa de cámara** sigue funcionando.

## Enfoques de testing de alto valor

- **Aceptación de webcams virtuales**: si el flujo funciona desde un navegador de escritorio, comprobar si OBS, `v4l2loopback` o las cámaras virtuales del proveedor se aceptan como periféricos normales.
- **Redirección de la API de cámara en mobile**: los flujos nativos mobile pueden seguir siendo vulnerables cuando Frida hookea las APIs de cámara y reemplaza los buffers del sensor con frames de un MP4 o de una cámara virtual respaldada por un emulador.
- **Relajación de constraints**: las páginas que requieren un `deviceId`, `frameRate`, `width`, `height` o `facingMode` exactos a veces pueden bypasssearse haciendo monkeypatch de `navigator.mediaDevices.getUserMedia` y reemplazando los constraints estrictos por rangos más amplios.
- **Generación de baja calidad más postprocesado**: generar el video más barato que el modelo pueda renderizar de forma fiable y utilizar después upscaling de FFmpeg o interpolación de frames para cumplir los requisitos de captura.
- **Desafíos activos predecibles**: vale la pena grabar y reproducir mediante un workflow generativo las secuencias repetitivas de movimiento de cabeza o destellos de luz.
- **Detección de replay débil**: perturbaciones simples de la escena, como recortes o desplazamientos de posición, cambios en overlays o movimientos leves, pueden ser suficientes cuando la lógica anti-replay solo comprueba la similitud superficial entre frames.

## Diferencias de confianza entre mobile y desktop

Las aplicaciones nativas mobile pueden aumentar el coste del atacante mediante:

- **attestation del sensor o del Secure Element** para los buffers de cámara;
- señales de **integridad de ejecución**, como **Play Integrity** o **App Attest**;
- **correlación de movimiento** entre el video y la telemetría del acelerómetro o del giroscopio.

Los flujos web de escritorio normalmente carecen de una cadena de confianza de cámara equivalente, por lo que generalmente son el camino de menor resistencia.

## Notas para la revisión defensiva

Al revisar una integración de KYC o liveness, comprobar si:

- permite un **fallback mediante navegador de escritorio** para un workflow cuyo threat model solo contemplaba la captura mobile;
- depende principalmente del **liveness algorítmico** sin una escalada humana sólida para sesiones sospechosas;
- utiliza **desafíos estables o predecibles** que pueden grabarse previamente e introducirse en un pipeline de generación;
- detecta **monkeypatching de `getUserMedia`**, cámaras virtuales, telemetría de hardware del navegador incoherente o ausencia de attestation del dispositivo.

## Referencias

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
