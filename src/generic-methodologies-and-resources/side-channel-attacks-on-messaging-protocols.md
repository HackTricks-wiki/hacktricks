# Ataques de canal lateral de recibos de entrega en messengers E2EE

{{#include ../banners/hacktricks-training.md}}

Los recibos de entrega son obligatorios en los messengers modernos de cifrado de extremo a extremo (E2EE) porque los clientes necesitan saber cuándo un ciphertext fue descifrado para poder descartar el estado de ratcheting y las claves efímeras. El servidor reenvía blobs opacos, así que los acuses de recibo del dispositivo (doble check) son emitidos por el destinatario después del descifrado exitoso. Medir el tiempo de ida y vuelta (RTT) entre una acción provocada por el atacante y el correspondiente recibo de entrega expone un canal de temporización de alta resolución que leak estado del dispositivo, presencia online y puede abusarse para DoS encubierto. Las implementaciones multi-device de "client-fanout" amplifican la leak porque cada dispositivo registrado descifra la prueba y devuelve su propio recibo.

## Fuentes de recibos de entrega vs. señales visibles para el usuario

Elige tipos de mensaje que siempre emitan un recibo de entrega pero no muestren artefactos de UI en la víctima. La tabla de abajo resume el comportamiento confirmado empíricamente:

| Messenger | Acción | Recibo de entrega | Notificación a la víctima | Notas |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Siempre ruidoso → solo útil para arrancar el estado. |
| | Reaction | ● | ◐ (solo si reaccionando al mensaje de la víctima) | Las auto-reactions y eliminaciones permanecen silenciosas. |
| | Edit | ● | Silent push dependiente de la plataforma | Ventana de edición ≈20 min; sigue ack’d después de expirar. |
| | Delete for everyone | ● | ○ | La UI permite ~60 h, pero los paquetes posteriores siguen ack’d. |
| **Signal** | Text message | ● | ● | Las mismas limitaciones que WhatsApp. |
| | Reaction | ● | ◐ | Las auto-reactions son invisibles para la víctima. |
| | Edit/Delete | ● | ○ | El servidor aplica una ventana de ~48 h, permite hasta 10 edits, pero los paquetes tardíos siguen ack’d. |
| **Threema** | Text message | ● | ● | Los recibos multi-device se agregan, así que solo se vuelve visible un RTT por prueba. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de UI dependiente de la plataforma se indica en línea. Desactiva los read receipts si hace falta, pero los recibos de entrega no pueden desactivarse en WhatsApp o Signal.

## Objetivos y modelos del atacante

* **G1 – Device fingerprinting:** Cuenta cuántos recibos llegan por prueba, agrupa RTTs para inferir OS/client (Android vs iOS vs desktop) y observa transiciones online/offline.
* **G2 – Monitorización conductual:** Trata la serie de RTT de alta frecuencia (≈1 Hz es estable) como una time-series e infiere pantalla encendida/apagada, app en foreground/background, horarios de desplazamiento vs trabajo, etc.
* **G3 – Agotamiento de recursos:** Mantén despiertos radios/CPUs de cada dispositivo víctima enviando silent probes sin fin, drenando batería/datos y degradando la calidad de VoIP/RTC.

Dos actores de amenaza son suficientes para describir la superficie de abuso:

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de self-reactions, eliminación de reactions o edits/deletes repetidos vinculados a IDs de mensajes existentes.
2. **Spooky stranger:** registra una cuenta desechable y envía reactions que referencian IDs de mensajes que nunca existieron en la conversación local; WhatsApp y Signal aún así los descifran y los reconocen aunque la UI descarte el cambio de estado, así que no se requiere conversación previa.

## Tooling para acceso raw al protocolo

Depende de clientes que expongan el protocolo E2EE subyacente para que puedas crear paquetes fuera de las restricciones de UI, especificar `message_id`s arbitrarios y registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo de WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) te permiten emitir frames raw `ReactionMessage`, `ProtocolMessage` (edit/delete) y `Receipt` mientras mantienes sincronizado el estado de double-ratchet.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expone cada tipo de mensaje vía CLI/API. La sintaxis actual de `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantén `receive` o `daemon` ejecutándose para que los recibos de entrega se recojan realmente. Ejemplo de toggle de auto-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** La fuente del cliente Android documenta cómo los recibos de entrega se consolidan antes de salir del dispositivo, explicando por qué el canal lateral tiene ancho de banda negligible ahí.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) incluye backends de WhatsApp/Signal, usa por defecto silent delete probes, y etiqueta `active` vs `standby` con un umbral de rolling-median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) es un CLI más ligero centrado en WhatsApp con `--delay`, `--concurrent`, exportadores CSV/Prometheus y salida amigable para Grafana. Trata ambos como ayudantes de reconnaissance más que como referencias del protocolo; la conclusión importante es lo poco código que hace falta una vez que existe acceso raw al cliente.

Cuando no hay tooling personalizado disponible, aún puedes provocar acciones silenciosas desde WhatsApp Web o Signal Desktop y sniffar el canal websocket/WebRTC cifrado, pero las APIs raw eliminan retrasos de UI y permiten operaciones inválidas.

## Creepy companion: silent sampling loop

1. Elige cualquier mensaje histórico que tú hayas escrito en el chat para que la víctima nunca vea cambiar los globos de "reaction".
2. Alterna entre un emoji visible y un payload de reaction vacío (codificado como `""` en protobufs de WhatsApp o `--remove` en signal-cli). Cada transmisión genera un ack del dispositivo pese a no haber delta de UI para la víctima.
3. Marca con timestamp la hora de envío y cada llegada de recibo de entrega. Un loop de 1 Hz como el siguiente da trazas de RTT por dispositivo de forma indefinida:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceptan actualizaciones de reaction ilimitadas, el atacante nunca necesita publicar contenido nuevo en el chat ni preocuparse por las ventanas de edición.

## Spooky stranger: probing arbitrary phone numbers

1. Registra una cuenta nueva de WhatsApp/Signal y obtén las public identity keys para el número objetivo (se hace automáticamente durante la configuración de sesión).
2. Crea un paquete de reaction/edit/delete que referencie un `message_id` aleatorio nunca visto por ninguna de las partes (WhatsApp acepta GUIDs arbitrarios `key.id`; Signal usa timestamps en milisegundos).
3. Envía el paquete aunque no exista ningún thread. Los dispositivos de la víctima lo descifran, no encuentran el mensaje base, descartan el cambio de estado, pero aun así reconocen el ciphertext entrante, devolviendo recibos de dispositivo al atacante.
4. Repite continuamente para construir series de RTT sin aparecer nunca en la lista de chats de la víctima.

Si primero necesitas descubrir qué números están registrados o quieres pre-seed device inventories a escala, encadena esto con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) en lugar de adivinar rangos E.164 aleatorios a mano.

El trabajo publicado sobre contact-discovery mostró por qué esto importa operativamente: con tablas de prefijos telefónicos precisas y recursos modestos, los investigadores pudieron consultar aproximadamente `10%` de los números móviles de US en WhatsApp y `100%` en Signal antes de pasar a probing dirigido. En la práctica, filtrar primero las cuentas vivas mantiene tu presupuesto de silent-probe centrado en números que realmente descifrarán paquetes.

Las compilaciones recientes de WhatsApp también exponen `Settings -> Privacy -> Advanced -> Block unknown account messages`. Trátalo como un limitador de throughput, no como una solución: perjudica sobre todo el flooding sostenido solo con strangers y es irrelevante una vez que ya eres un contacto conocido.

## Reutilizar edits y deletes como triggers encubiertos

* **Repeated deletes:** Después de que un mensaje se elimina-for-everyone una vez, los paquetes de delete posteriores que referencian el mismo `message_id` no tienen efecto de UI, pero cada dispositivo aún los descifra y reconoce.
* **Out-of-window operations:** WhatsApp aplica en la UI ventanas de ~60 h para delete / ~20 min para edit; Signal aplica ~48 h. Los mensajes de protocolo construidos fuera de esas ventanas se ignoran silenciosamente en el dispositivo de la víctima, pero los recibos se transmiten, así que los atacantes pueden hacer probing indefinidamente mucho después de que la conversación terminara.
* **Invalid payloads:** Cuerpos de edit malformados o deletes que referencian mensajes ya purgados provocan el mismo comportamiento: descifrado más recibo, cero artefactos visibles para el usuario.

## Amplificación multi-device y fingerprinting

* Cada dispositivo asociado (teléfono, app de desktop, companion browser) descifra la prueba de forma independiente y devuelve su propio ack. Contar recibos por prueba revela el número exacto de dispositivos.
* Si un dispositivo está offline, su recibo queda en cola y se emite al reconectarse. Por tanto, los huecos leak ciclos online/offline e incluso horarios de desplazamiento (por ejemplo, los recibos del desktop se detienen durante el viaje).
* Las distribuciones de RTT difieren por plataforma debido al power management del SO y a los push wakeups. Agrupa RTTs (por ejemplo, k-means sobre features de mediana/varianza) para etiquetar “Android handset", “iOS handset", “Electron desktop", etc.
* Como el emisor debe recuperar el inventario de claves del destinatario antes de cifrar, el atacante también puede observar cuándo se emparejan nuevos dispositivos; un aumento repentino en el número de dispositivos o un nuevo cluster de RTT es un indicador fuerte.

## Cadencia de muestreo, queueing y recibos apilados

* **WhatsApp burst tolerance:** Medidas publicadas reportaron que WhatsApp aceptó bursts de silent-reaction tan rápido como una prueba cada `50 ms` sin queueing obvio del lado del servidor. Eso es útil para ráfagas cortas de calibración, conteo rápido de dispositivos o para acelerar rápidamente un ataque de drenaje.
* **Signal long-run queueing:** Signal toleró ráfagas cortas pero empezó a hacer queueing con tráfico sostenido de varios probes por segundo. Para monitorización de larga duración, mantén la cadencia alrededor de `1 Hz` (o menos) para que cada recibo siga reflejando el estado actual del dispositivo en lugar de vaciar backlog.
* **Reconnect artefacts:** Cuando un dispositivo vuelve online, algunos clientes agrupan o vacían rápidamente múltiples recibos retrasados. Trata esos bursts de recibos como un marcador de transición de estado y no como muestras RTT independientes, o tu clustering / clasificador `active` vs `idle` sobreajustará el ruido de reconexión.

## Inferencia de comportamiento a partir de trazas RTT

1. Muestrea a ≥1 Hz para capturar efectos de scheduling del SO. Con WhatsApp en iOS, RTTs <1 s correlacionan fuertemente con pantalla encendida/foreground, y >1 s con pantalla apagada/throttling en background.
2. Construye clasificadores simples (thresholding o k-means de dos clusters) que etiqueten cada RTT como "active" o "idle". Agrega las etiquetas en rachas para derivar horas de sueño, desplazamientos, horas de trabajo o cuándo el companion de desktop está activo.
3. Correlaciona probes simultáneas hacia cada dispositivo para ver cuándo los usuarios cambian de mobile a desktop, cuándo los companions se desconectan y si la app está limitada por rate limit de push vs socket persistente.
4. En redes reales, evita un único threshold hardcoded de `1 s`. Haz bootstrap de cada dispositivo con una ventana corta de warm-up y mantén una baseline móvil (por ejemplo, `threshold = 0.9 * median RTT`) para que el drift de Wi-Fi/celular no destruya tu clasificador.

## Inferencia de ubicación a partir de delivery RTT

El mismo primitive de temporización puede reutilizarse para inferir dónde está el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar sobre distribuciones de RTT para ubicaciones conocidas del receptor permite a un atacante clasificar después la ubicación de la víctima solo a partir de delivery confirmations:

* Construye una baseline para el mismo objetivo mientras está en varios lugares conocidos (casa, oficina, campus, country A vs country B, etc.).
* Para cada ubicación, recopila muchos RTT normales de mensajes y extrae features simples como mediana, varianza o buckets de percentiles.
* Durante el ataque real, compara la nueva serie de probes con los clusters entrenados. El paper reporta que incluso ubicaciones dentro de la misma ciudad a menudo pueden separarse, con una precisión de `>80%` en un escenario de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el entorno del emisor y hace probes bajo condiciones de red similares, porque la ruta medida incluye la red de acceso del destinatario, la latencia de wake-up y la infraestructura del messenger.

A diferencia de los ataques silenciosos de reaction/edit/delete anteriores, la inferencia de ubicación no requiere message IDs inválidos ni paquetes stealthy que cambien estado. Basta con mensajes normales con confirmaciones de entrega normales, así que el tradeoff es menor stealth pero mayor aplicabilidad entre messengers.

## Agotamiento de recursos sigiloso

Como cada silent probe debe descifrarse y reconocerse, enviar continuamente toggles de reaction, edits inválidos o paquetes de delete-for-everyone crea un DoS a nivel de aplicación:

* Fuerza al radio/módem a transmitir/recibir cada segundo → drenaje de batería notable, especialmente en handsets inactivos.
* Genera tráfico upstream/downstream no medido que consume planes de datos móviles mientras se mezcla con ruido TLS/WebSocket.
* Ocupa hilos criptográficos e introduce jitter en funciones sensibles a latencia (VoIP, videollamadas) aunque el usuario nunca vea notificaciones.
* En WhatsApp, las reactions inválidas aceptan muchos más datos de lo que sugiere un emoji normal: medidas publicadas encontraron aceptación del lado del servidor de hasta aproximadamente `1 MB` por reaction.
* Las reactions sobredimensionadas dejan de producir recibos de entrega fiables una vez que el body crece más allá de aproximadamente `30 bytes`, pero aun así se reenvían y procesan antes de ser descartadas. Mantén los cuerpos de reaction pequeños cuando necesites ACKs; inflalos solo cuando el objetivo sea drenaje puro o transporte encubierto unidireccional.
* Las medidas públicas alcanzaron alrededor de `3.7 MB/s` (`~13.3 GB/h`) de tráfico de la víctima en este modo.

## Referencias

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
