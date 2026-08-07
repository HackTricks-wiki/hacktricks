# Bypass de KYC usando AI

{{#include ../banners/hacktricks-training.md}}

Los modelos generativos pueden utilizarse para **bypassear flujos de KYC basados en navegador, verificación de edad y liveness biométrico**. El punto débil a menudo **no es el transporte ni el proveedor de liveness en la nube**, sino el **límite de confianza de la cámara**: un navegador de escritorio normalmente confía en cualquier dispositivo que `getUserMedia()` exponga como webcam.<sup>[[1]](#references)</sup>

## Cadena de ataque práctica

1. **Generar contenido multimedia que cumpla los desafíos** con un modelo video-to-video a partir de un actor de origen y una imagen de referencia de la víctima.<sup>[[1]](#references)</sup>
2. **Inyectar el flujo falsificado antes de firmarlo o subirlo**, por ejemplo mediante una cámara virtual de Linux creada con `v4l2loopback` y alimentada por OBS o FFmpeg.<sup>[[3]](#references)</sup>
3. Dejar que el navegador y el SDK del proveedor (WebRTC, AWS, etc.) **capturen, firmen y suban los fotogramas controlados por el atacante como si procedieran de una webcam real**.<sup>[[2]](#references)</sup>

Esto es importante durante las evaluaciones porque los fragmentos de WebSocket firmados o el framing propietario del SDK pueden hacer que la **manipulación de la capa de red** resulte poco práctica, mientras que la **inyección en la capa de cámara** sigue funcionando.<sup>[[1]](#references)</sup>

## Enfoques de alto valor para las pruebas

- **Aceptación de webcams virtuales**: si el flujo funciona desde un navegador de escritorio, comprobar si OBS, `v4l2loopback` o las cámaras virtuales del proveedor se aceptan como periféricos normales.<sup>[[1]](#references)</sup>
- **Redirección de la API de cámara en móviles**: los flujos móviles nativos aún pueden ser vulnerables cuando Frida realiza hooks sobre las APIs de cámara y reemplaza los buffers del sensor con fotogramas de un MP4 o de una cámara virtual respaldada por un emulador.
- **Relajación de restricciones**: las páginas que requieren un `deviceId`, `frameRate`, `width`, `height` o `facingMode` exactos a veces pueden bypassarse haciendo monkeypatching de `navigator.mediaDevices.getUserMedia` y reemplazando las restricciones estrictas por rangos más amplios.<sup>[[4]](#references)</sup>
- **Generación de baja calidad más postprocesamiento**: generar el vídeo más económico que el modelo pueda renderizar de forma fiable y después utilizar upscaling de FFmpeg o interpolación de fotogramas para cumplir los requisitos de captura.
- **Desafíos activos predecibles**: merece la pena grabar y reproducir mediante un flujo generativo las secuencias repetidas de movimientos de cabeza o destellos de luz.
- **Detección de replay débil**: perturbaciones simples de la escena, como cambios de recorte o posición, modificaciones de overlays o movimientos leves, pueden ser suficientes cuando la lógica anti-replay solo comprueba la similitud superficial entre fotogramas.<sup>[[1]](#references)</sup>

## Diferencias de confianza entre móviles y escritorios

Las aplicaciones móviles nativas pueden aumentar el coste del atacante mediante:<sup>[[1]](#references)</sup>

- **attestation del sensor o del Secure Element** para los buffers de la cámara;
- señales de **integridad de ejecución**, como **Play Integrity** o **App Attest**;
- **correlación de movimiento** entre el vídeo y la telemetría del acelerómetro o giroscopio.

Los flujos web de escritorio normalmente carecen de una cadena de confianza equivalente para la cámara, por lo que generalmente representan el camino de menor resistencia.<sup>[[1]](#references)</sup>

## Notas para la revisión defensiva

Al revisar una integración de KYC o liveness, verificar si:<sup>[[1]](#references)</sup>

- permite un **fallback en navegador de escritorio** para un flujo cuyo modelo de amenazas solo contemplaba la captura móvil;
- depende principalmente del **liveness algorítmico** sin una escalada humana sólida para las sesiones sospechosas;
- utiliza **desafíos estables o predecibles** que pueden grabarse previamente e introducirse en un pipeline de generación;
- detecta el **monkeypatching de `getUserMedia`**, las cámaras virtuales, la telemetría de hardware incoherente del navegador o la ausencia de attestation del dispositivo.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypass de la verificación de edad mediante modelos generativos de vídeo](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
