# Ataques de canal lateral mediante recibos de entrega en mensajeros E2EE

{{#include ../banners/hacktricks-training.md}}

Los recibos de entrega son obligatorios en los mensajeros modernos con cifrado de extremo a extremo (E2EE), porque los clientes necesitan saber cuándo se descifró un ciphertext para poder descartar el estado del ratchet y las claves efímeras. El servidor reenvía blobs opacos, por lo que los reconocimientos del dispositivo (dobles marcas de verificación) son emitidos por el destinatario después de un descifrado correcto. Medir el tiempo de ida y vuelta (RTT) entre una acción activada por el atacante y el recibo de entrega correspondiente expone un canal temporal de alta resolución que filtra el estado del dispositivo y la presencia online, y que puede abusarse para realizar un DoS encubierto. Las implementaciones "client-fanout" multidispositivo amplifican la filtración porque cada dispositivo registrado descifra la sonda y devuelve su propio recibo.<sup>[[1]](#references)</sup>

## Fuentes de recibos de entrega frente a señales visibles para el usuario

Elige tipos de mensajes que siempre emitan un recibo de entrega, pero que no muestren artefactos en la UI de la víctima. La siguiente tabla resume el comportamiento confirmado empíricamente:<sup>[[1]](#references)</sup>

| Messenger | Acción | Recibo de entrega | Notificación para la víctima | Notas |
|-----------|--------|------------------|------------------------------|-------|
| **WhatsApp** | Mensaje de texto | ● | ● | Siempre genera ruido → solo es útil para inicializar el estado. |
| | Reacción | ● | ◐ (solo al reaccionar al mensaje de la víctima) | Las autoreacciones y eliminaciones permanecen silenciosas. |
| | Edición | ● | Push silencioso dependiente de la plataforma | Ventana de edición ≈20 min; sigue recibiendo ACK después de expirar. |
| | Eliminar para todos | ● | ○ | La UI permite ~60 h, pero los paquetes posteriores siguen recibiendo ACK. |
| **Signal** | Mensaje de texto | ● | ● | Las mismas limitaciones que WhatsApp. |
| | Reacción | ● | ◐ | Las autoreacciones son invisibles para la víctima. |
| | Edición/Eliminación | ● | ○ | El servidor aplica una ventana de ~48 h y permite hasta 10 ediciones, pero los paquetes tardíos siguen recibiendo ACK. |
| **Threema** | Mensaje de texto | ● | ● | Los recibos multidispositivo se agregan, por lo que solo un RTT por sonda se hace visible. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de la UI dependiente de la plataforma se indica en línea. Desactiva los recibos de lectura si es necesario, pero los recibos de entrega no pueden desactivarse en WhatsApp ni Signal.<sup>[[1]](#references)</sup>

## Objetivos y modelos del atacante

* **G1 – Fingerprinting de dispositivos:** Contar cuántos recibos llegan por sonda, agrupar los RTT para inferir el sistema operativo/cliente (Android frente a iOS o desktop) y observar las transiciones online/offline.
* **G2 – Monitorización del comportamiento:** Tratar la serie de RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e inferir si la pantalla está encendida/apagada, si la aplicación está en primer plano/segundo plano, horarios de desplazamiento al trabajo frente a horas laborales, etc.
* **G3 – Agotamiento de recursos:** Mantener activas las radios/CPU de todos los dispositivos de la víctima mediante el envío de sondas silenciosas interminables, agotando la batería y los datos y degradando la calidad de VoIP/RTC.<sup>[[1]](#references)</sup>

Dos actores de amenaza bastan para describir la superficie de abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de autoreacciones, eliminaciones de reacciones o ediciones/eliminaciones repetidas vinculadas a IDs de mensajes existentes.
2. **Spooky stranger:** registra una cuenta desechable y envía reacciones que hacen referencia a IDs de mensajes que nunca existieron en la conversación local; WhatsApp y Signal aun así los descifran y reconocen, aunque la UI descarte el cambio de estado, por lo que no se requiere una conversación previa.

## Tooling para acceso al protocolo en bruto

Utiliza clientes que expongan el protocolo E2EE subyacente para poder crear paquetes fuera de las restricciones de la UI, especificar `message_id`s arbitrarios y registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo de WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientado a dispositivos móviles) permiten emitir frames `ReactionMessage`, `ProtocolMessage` (edición/eliminación) y `Receipt` en bruto, manteniendo sincronizado el estado del double-ratchet.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli), combinado con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java), expone todos los tipos de mensajes mediante CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> La sintaxis actual de `signal-cli` utiliza `sendReaction RECIPIENT --target-author --target-timestamp`; mantén `receive` o `daemon` en ejecución para que los recibos de entrega se recopilen realmente.<sup>[[6]](#references)</sup> Ejemplo de alternancia de autoreacción:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** El código fuente del cliente Android documenta cómo se consolidan los recibos de entrega antes de salir del dispositivo, lo que explica por qué el canal lateral tiene un ancho de banda insignificante en este caso.<sup>[[1]](#references)</sup>
* **PoCs turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) incluye backends para WhatsApp/Signal, utiliza por defecto sondas silenciosas de eliminación y etiqueta `active` frente a `standby` con un umbral de mediana móvil (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) es una CLI más ligera y centrada en WhatsApp, con `--delay`, `--concurrent`, exportadores CSV/Prometheus y salida compatible con Grafana.<sup>[[8]](#references)</sup> Trata ambas herramientas como ayudas de reconocimiento y no como referencias del protocolo; la conclusión importante es lo poco código que se necesita una vez que existe acceso al cliente en bruto.

Cuando no haya tooling personalizado disponible, aún puedes activar acciones silenciosas desde WhatsApp Web o Signal Desktop y esnifar el canal websocket/WebRTC cifrado, pero las API en bruto eliminan las demoras de la UI y permiten operaciones no válidas.

## Creepy companion: bucle de muestreo silencioso

1. Elige cualquier mensaje histórico que hayas escrito en el chat para que la víctima nunca vea cambiar los globos de "reacción".
2. Alterna entre un emoji visible y un payload de reacción vacío (codificado como `""` en los protobufs de WhatsApp o como `--remove` en signal-cli). Cada transmisión genera un ACK del dispositivo aunque no haya ningún cambio visible en la UI de la víctima.
3. Registra el momento de envío y la llegada de cada recibo de entrega. Un bucle de 1 Hz como el siguiente proporciona indefinidamente trazas de RTT por dispositivo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceptan actualizaciones ilimitadas de reacciones, el atacante nunca necesita publicar contenido nuevo en el chat ni preocuparse por las ventanas de edición.<sup>[[1]](#references)</sup>

## Spooky stranger: sondeo de números de teléfono arbitrarios

1. Registra una cuenta nueva de WhatsApp/Signal y obtiene las claves de identidad públicas del número objetivo (se hace automáticamente durante la configuración de la sesión).
2. Crea un paquete de reacción/edición/eliminación que haga referencia a un `message_id` aleatorio que ninguna de las partes haya visto (WhatsApp acepta GUIDs arbitrarios en `key.id`; Signal utiliza timestamps en milisegundos).
3. Envía el paquete aunque no exista ningún hilo. Los dispositivos de la víctima lo descifran, no encuentran el mensaje base, descartan el cambio de estado, pero aun así reconocen el ciphertext entrante y envían recibos del dispositivo al atacante.
4. Repite continuamente para crear series de RTT sin aparecer nunca en la lista de chats de la víctima.<sup>[[1]](#references)</sup>

Si primero necesitas descubrir qué números están registrados o quieres preparar inventarios de dispositivos a escala, encadena esto con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) en lugar de adivinar manualmente rangos E.164 aleatorios.

Los trabajos publicados sobre contact-discovery mostraron por qué esto es importante desde el punto de vista operativo: con tablas precisas de prefijos telefónicos y recursos modestos, los investigadores pudieron consultar aproximadamente el `10%` de los números móviles de EE. UU. en WhatsApp y el `100%` en Signal antes de pasar al sondeo dirigido.<sup>[[11]](#references)</sup> En la práctica, filtrar primero las cuentas activas mantiene el presupuesto de sondas silenciosas centrado en números que realmente descifrarán los paquetes.

Las versiones recientes de WhatsApp también exponen `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trátalo como un limitador de rendimiento, no como una solución: principalmente dificulta el flooding sostenido realizado solo por desconocidos y es irrelevante cuando ya eres un contacto conocido.

## Reciclaje de ediciones y eliminaciones como triggers encubiertos

* **Eliminaciones repetidas:** Después de que un mensaje se haya eliminado para todos una vez, los paquetes de eliminación posteriores que hagan referencia al mismo `message_id` no tienen efecto en la UI, pero cada dispositivo sigue descifrándolos y reconociéndolos.
* **Operaciones fuera de ventana:** WhatsApp aplica ventanas de ~60 h para eliminar y ~20 min para editar desde la UI; Signal aplica ~48 h. Los mensajes de protocolo creados fuera de estas ventanas se ignoran silenciosamente en el dispositivo de la víctima, pero los recibos se transmiten, por lo que los atacantes pueden sondear indefinidamente mucho después de que haya terminado la conversación.
* **Payloads no válidos:** Los cuerpos de edición malformados o las eliminaciones que hacen referencia a mensajes ya purgados provocan el mismo comportamiento: descifrado más recibo, sin artefactos visibles para el usuario.<sup>[[1]](#references)</sup>

## Amplificación y fingerprinting multidispositivo

* Cada dispositivo asociado (teléfono, aplicación de escritorio o companion del navegador) descifra la sonda de forma independiente y devuelve su propio ACK. Contar los recibos por sonda revela el número exacto de dispositivos.
* Si un dispositivo está offline, su recibo se pone en cola y se emite al reconectarse. Por tanto, las brechas filtran los ciclos online/offline e incluso los horarios de desplazamiento (por ejemplo, los recibos del desktop se detienen durante los viajes).
* Las distribuciones de RTT varían según la plataforma debido a la gestión de energía del sistema operativo y a los wakeups del push. Agrupa los RTT (por ejemplo, mediante k-means sobre características de mediana/varianza) para etiquetar un “terminal Android", “terminal iOS", “desktop Electron", etc.
* Como el remitente debe recuperar el inventario de claves del destinatario antes de cifrar, el atacante también puede observar cuándo se emparejan dispositivos nuevos; un aumento repentino en el número de dispositivos o un nuevo grupo de RTT es un indicador sólido.<sup>[[1]](#references)</sup>

## Cadencia de muestreo, colas y recibos acumulados

* **Tolerancia de WhatsApp a ráfagas:** Las mediciones publicadas informaron que WhatsApp aceptaba ráfagas de reacciones silenciosas a una velocidad de una sonda cada `50 ms` sin una cola evidente en el servidor. Esto resulta útil para ráfagas cortas de calibración, para contar dispositivos rápidamente o para acelerar un drain attack.
* **Queueing prolongado en Signal:** Signal toleraba ráfagas cortas, pero comenzó a poner en cola el tráfico sostenido de varias sondas por segundo. Para una monitorización de larga duración, mantén la cadencia alrededor de `1 Hz` (o inferior), de modo que cada recibo siga reflejando el estado actual del dispositivo en lugar de vaciar una cola acumulada.
* **Artefactos de reconexión:** Cuando un dispositivo vuelve a estar online, algunos clientes agrupan o vacían rápidamente varios recibos retrasados. Trata esas ráfagas de recibos como un marcador de transición de estado y no como muestras de RTT independientes; de lo contrario, tu clustering o clasificador `active` frente a `idle` se ajustará demasiado al ruido de reconexión.<sup>[[1]](#references)</sup>

## Inferencia de comportamiento a partir de trazas de RTT

1. Muestrea a ≥1 Hz para capturar los efectos de scheduling del sistema operativo. Con WhatsApp en iOS, los RTT <1 s se correlacionan estrechamente con la pantalla encendida/en primer plano, mientras que los RTT >1 s se correlacionan con la limitación en pantalla apagada/segundo plano.
2. Construye clasificadores sencillos (thresholding o k-means de dos grupos) que etiqueten cada RTT como "active" o "idle". Agrupa las etiquetas en rachas para obtener horarios de sueño, desplazamientos, horas de trabajo o los periodos en que el companion de escritorio está activo.
3. Correlaciona sondas simultáneas hacia todos los dispositivos para observar cuándo los usuarios cambian del móvil al desktop, cuándo los companions se desconectan y si la aplicación está limitada por push o por un socket persistente.
4. En redes reales, evita un único umbral fijo de `1 s`. Inicializa cada dispositivo con una breve ventana de calentamiento y mantén una línea base móvil (por ejemplo, `threshold = 0.9 * median RTT`) para que las variaciones de Wi-Fi/red celular no inutilicen tu clasificador.<sup>[[1]](#references)</sup>

## Inferencia de ubicación a partir del RTT de entrega

El mismo primitive temporal puede reutilizarse para inferir dónde está el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar con distribuciones de RTT de ubicaciones conocidas permite que un atacante clasifique posteriormente la ubicación de la víctima utilizando únicamente las confirmaciones de entrega:<sup>[[2]](#references)</sup>

* Crea una línea base para el mismo objetivo mientras se encuentra en varios lugares conocidos (casa, oficina, campus, país A frente a país B, etc.).
* Para cada ubicación, recopila muchos RTT de mensajes normales y extrae características sencillas como mediana, varianza o intervalos de percentiles.
* Durante el ataque real, compara la nueva serie de sondas con los grupos entrenados. El artículo informa que incluso pueden separarse con frecuencia ubicaciones de una misma ciudad, con una precisión `>80%` en un escenario de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el entorno del remitente y realiza las sondas bajo condiciones de red similares, porque la ruta medida incluye la red de acceso del destinatario, la latencia de wake-up y la infraestructura del messenger.<sup>[[2]](#references)</sup>

A diferencia de los ataques silenciosos de reacción/edición/eliminación anteriores, la inferencia de ubicación no requiere IDs de mensajes no válidos ni paquetes sigilosos que cambien el estado. Los mensajes normales con confirmaciones de entrega normales son suficientes, por lo que la contrapartida es un menor sigilo, pero una aplicabilidad más amplia entre messengers.

## Agotamiento sigiloso de recursos

Como cada sonda silenciosa debe descifrarse y reconocerse, el envío continuo de alternancias de reacciones, ediciones no válidas o paquetes de eliminación para todos crea un DoS en la capa de aplicación:<sup>[[1]](#references)</sup>

* Obliga a la radio/módem a transmitir/recibir cada segundo → provoca un consumo de batería apreciable, especialmente en terminales inactivos.
* Genera tráfico ascendente/descendente no medido que consume los planes de datos móviles mientras se mezcla con el ruido TLS/WebSocket.
* Ocupa los hilos de criptografía e introduce jitter en funciones sensibles a la latencia (VoIP, videollamadas), aunque el usuario nunca vea notificaciones.
* En WhatsApp, las reacciones no válidas aceptan muchos más datos de lo que sugiere un emoji normal: mediciones publicadas encontraron una aceptación en el servidor de hasta aproximadamente `1 MB` por reacción.
* Las reacciones sobredimensionadas dejan de producir recibos de entrega fiables cuando el cuerpo supera aproximadamente `30 bytes`, pero siguen reenviándose y procesándose antes de descartarse. Mantén los cuerpos de las reacciones pequeños cuando necesites ACKs; auméntalos solo cuando el objetivo sea el drain puro o el transporte unidireccional encubierto.
* Las mediciones públicas alcanzaron aproximadamente `3.7 MB/s` (`~13.3 GB/h`) de tráfico de la víctima en este modo.

## Referencias

- [1] [Careless Whisper: Explotación de recibos de entrega silenciosos para monitorizar usuarios en mensajeros instantáneos móviles](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracción de ubicaciones de usuarios a partir de mensajeros instantáneos móviles](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [página man de signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Cómo bloquear grandes volúmenes de mensajes desconocidos | Centro de ayuda de WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Todos los números son de EE. UU.: abuso a gran escala de Contact Discovery en mensajeros móviles](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
