# Ataques de canal lateral por Delivery Receipt en mensajeros E2EE

{{#include ../banners/hacktricks-training.md}}

Los delivery receipts son obligatorios en los mensajeros modernos de cifrado de extremo a extremo (E2EE) porque los clientes necesitan saber cuándo un ciphertext fue descifrado para poder descartar el estado de ratcheting y las claves efímeras. El servidor reenvía blobs opacos, así que los acknowledgements de dispositivo (doble checkmark) son emitidos por el destinatario después de un descifrado exitoso. Medir el round-trip time (RTT) entre una acción provocada por el atacante y el correspondiente delivery receipt expone un canal de temporización de alta resolución que filtra el estado del dispositivo, la presencia online y puede ser abusado para DoS encubierto. Los despliegues multi-device de "client-fanout" amplifican la filtración porque cada dispositivo registrado descifra la prueba y devuelve su propio receipt.

## Fuentes de delivery receipt vs. señales visibles para el usuario

Elige tipos de mensaje que siempre emitan un delivery receipt pero no muestren artefactos de UI en la víctima. La tabla de abajo resume el comportamiento confirmado empíricamente:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Siempre ruidoso → solo útil para arrancar el estado. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Las self-reactions y las removals permanecen en silencio. |
| | Edit | ● | Silent push dependiente de la plataforma | Ventana de edición ≈20 min; aun así se ack’d después de expirar. |
| | Delete for everyone | ● | ○ | La UI permite ~60 h, pero paquetes posteriores siguen ack’d. |
| **Signal** | Text message | ● | ● | Las mismas limitaciones que WhatsApp. |
| | Reaction | ● | ◐ | Las self-reactions son invisibles para la víctima. |
| | Edit/Delete | ● | ○ | El servidor aplica una ventana de ~48 h, permite hasta 10 ediciones, pero paquetes tardíos siguen ack’d. |
| **Threema** | Text message | ● | ● | Los receipts multi-device se agregan, así que solo se hace visible un RTT por prueba. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de UI dependiente de la plataforma se indica inline. Desactiva los read receipts si es necesario, pero los delivery receipts no se pueden apagar en WhatsApp o Signal.

## Objetivos y modelos del atacante

* **G1 – Device fingerprinting:** Cuenta cuántos receipts llegan por prueba, agrupa RTTs para inferir OS/cliente (Android vs iOS vs desktop) y observa transiciones online/offline.
* **G2 – Supervisión comportamental:** Trata la serie RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e infiere pantalla encendida/apagada, app en foreground/background, horas de desplazamiento vs trabajo, etc.
* **G3 – Agotamiento de recursos:** Mantén radios/CPUs de cada dispositivo víctima despiertos enviando silent probes interminables, drenando batería/datos y degradando la calidad de VoIP/RTC.

Dos actores de amenaza bastan para describir la superficie de abuso:

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de self-reactions, removal de reacciones o ediciones/borrados repetidos ligados a IDs de mensajes existentes.
2. **Spooky stranger:** registra una cuenta burner y envía reacciones referenciando message IDs que nunca existieron en la conversación local; WhatsApp y Signal aun así los descifran y los reconocen aunque la UI descarte el cambio de estado, así que no se requiere conversación previa.

## Tooling para acceso bruto al protocolo

Apóyate en clientes que expongan el protocolo E2EE subyacente para poder crear paquetes fuera de las restricciones de la UI, especificar `message_id`s arbitrarios y registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) permiten emitir `ReactionMessage`, `ProtocolMessage` (edit/delete) y tramas `Receipt` sin perder la sincronización del estado double-ratchet.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expone cada tipo de mensaje vía CLI/API. La sintaxis actual de `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; deja `receive` o `daemon` ejecutándose para que los delivery receipts se recojan de verdad. Ejemplo de toggle de self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** La fuente del cliente Android documenta cómo se consolidan los delivery receipts antes de salir del dispositivo, explicando por qué el side channel tiene un ancho de banda despreciable allí.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) incluye backends de WhatsApp/Signal, usa por defecto silent delete probes y etiqueta `active` vs `standby` con un umbral de rolling-median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) es un CLI más ligero centrado en WhatsApp con `--delay`, `--concurrent`, exportadores CSV/Prometheus y salida compatible con Grafana. Trata ambos como ayudantes de reconnaissance y no como referencias de protocolo; la conclusión importante es lo poco código que hace falta una vez existe acceso bruto al cliente.

Cuando no haya tooling personalizado disponible, aún puedes disparar acciones silenciosas desde WhatsApp Web o Signal Desktop y sniffar el canal websocket/WebRTC cifrado, pero las APIs brutas eliminan retrasos de UI y permiten operaciones inválidas.

## Creepy companion: bucle de muestreo silencioso

1. Elige cualquier mensaje histórico que tú hayas escrito en el chat para que la víctima nunca vea cambiar los globos de "reaction".
2. Alterna entre un emoji visible y un payload de reacción vacío (codificado como `""` en los protobufs de WhatsApp o `--remove` en signal-cli). Cada transmisión produce un ack de dispositivo pese a no haber delta de UI para la víctima.
3. Toma el timestamp de envío y de cada llegada de delivery receipt. Un bucle de 1 Hz como el siguiente da trazas RTT por dispositivo indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceptan actualizaciones de reacción ilimitadas, el atacante nunca necesita publicar contenido nuevo en el chat ni preocuparse por las ventanas de edición.

## Spooky stranger: sondeo de números de teléfono arbitrarios

1. Registra una cuenta nueva de WhatsApp/Signal y obtiene las public identity keys para el número objetivo (hecho automáticamente durante la configuración de la sesión).
2. Construye un paquete de reaction/edit/delete que referencie un `message_id` aleatorio nunca visto por ninguna de las partes (WhatsApp acepta GUID `key.id` arbitrarios; Signal usa timestamps en milisegundos).
3. Envía el paquete aunque no exista ningún thread. Los dispositivos de la víctima lo descifran, no logran encontrar el mensaje base, descartan el cambio de estado, pero aun así reconocen el ciphertext entrante, enviando delivery receipts de vuelta al atacante.
4. Repite continuamente para construir series RTT sin aparecer nunca en la lista de chats de la víctima.

Si primero necesitas descubrir qué números están registrados o quieres pre-sembrar inventarios de dispositivos a escala, encadena esto con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) en lugar de adivinar a mano rangos E.164 aleatorios.

Las compilaciones recientes de WhatsApp también exponen `Settings -> Privacy -> Advanced -> Block unknown account messages`. Trátalo como un limitador de throughput, no como una solución: principalmente perjudica flooding sostenido solo de strangers y es irrelevante una vez ya eres un contacto conocido.

## Reutilizar edits y deletes como triggers encubiertos

* **Repeated deletes:** Después de que un mensaje se borra-for-everyone una vez, paquetes delete posteriores que referencian el mismo `message_id` no tienen efecto de UI, pero cada dispositivo aun así los descifra y los reconoce.
* **Out-of-window operations:** WhatsApp aplica ventanas de borrado de ~60 h / edición de ~20 min en la UI; Signal aplica ~48 h. Los mensajes de protocolo construidos fuera de estas ventanas se ignoran silenciosamente en el dispositivo víctima, pero los receipts se transmiten, así que los atacantes pueden sondear indefinidamente mucho después de que la conversación terminara.
* **Invalid payloads:** Cuerpos de edición malformados o deletes que referencian mensajes ya purgados provocan el mismo comportamiento: descifrado más receipt, cero artefactos visibles para el usuario.

## Amplificación multi-device y fingerprinting

* Cada dispositivo asociado (teléfono, app desktop, browser companion) descifra la prueba de forma independiente y devuelve su propio ack. Contar receipts por prueba revela el número exacto de dispositivos.
* Si un dispositivo está offline, su receipt se encola y se emite al reconectarse. Por tanto, los huecos filtran ciclos online/offline e incluso horarios de desplazamiento (por ejemplo, los receipts del desktop se detienen durante los viajes).
* Las distribuciones RTT difieren por plataforma debido a la gestión de energía del OS y a los wakeups push. Agrupa los RTT (por ejemplo, k-means sobre features de mediana/varianza) para etiquetar “Android handset", “iOS handset", “Electron desktop", etc.
* Como el remitente debe recuperar el inventario de claves del destinatario antes de cifrar, el atacante también puede observar cuándo se emparejan nuevos dispositivos; un aumento repentino en el número de dispositivos o un nuevo cluster RTT es un indicador fuerte.

## Inferencia de comportamiento a partir de trazas RTT

1. Muestrea a ≥1 Hz para capturar efectos de scheduling del OS. Con WhatsApp en iOS, RTTs <1 s se correlacionan fuertemente con pantalla encendida/foreground, y >1 s con pantalla apagada/background throttling.
2. Construye clasificadores simples (thresholding o k-means de dos clusters) que etiqueten cada RTT como "active" o "idle". Agrega las etiquetas en streaks para derivar horas de dormir, trayectos, horas de trabajo o cuándo el companion desktop está activo.
3. Correlaciona sondas simultáneas hacia cada dispositivo para ver cuándo los usuarios cambian de móvil a desktop, cuándo los companions pasan a offline y si la app está limitada por rate limit de push o por socket persistente.
4. En redes reales, evita un único umbral fijo de `1 s`. Arranca cada dispositivo con una pequeña ventana de warm-up y mantiene una baseline móvil (por ejemplo, `threshold = 0.9 * median RTT`) para que el drift Wi-Fi/celular no derrumbe tu clasificador.

## Inferencia de ubicación a partir de delivery RTT

El mismo primitive de temporización puede reutilizarse para inferir dónde está el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar sobre distribuciones RTT para ubicaciones conocidas del receptor permite que un atacante clasifique después la ubicación de la víctima solo a partir de las delivery confirmations:

* Construye una baseline para el mismo objetivo mientras está en varios lugares conocidos (casa, oficina, campus, país A vs país B, etc.).
* Para cada ubicación, recopila muchos RTT normales de mensajes y extrae features simples como mediana, varianza o buckets de percentiles.
* Durante el ataque real, compara la nueva serie de pruebas contra los clusters entrenados. El paper informa que incluso ubicaciones dentro de la misma ciudad a menudo pueden separarse, con una precisión `>80%` en un escenario de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el entorno del remitente y sondea bajo condiciones de red similares, porque la ruta medida incluye la red de acceso del receptor, la latencia de wake-up y la infraestructura del mensajero.

A diferencia de los ataques silenciosos de reaction/edit/delete anteriores, la inferencia de ubicación no requiere message IDs inválidos ni paquetes sigilosos que cambian estado. Mensajes normales con delivery confirmations normales bastan, así que la desventaja es menor stealth pero mayor aplicabilidad entre mensajeros.

## Agotamiento de recursos sigiloso

Como cada silent probe debe descifrarse y reconocerse, enviar continuamente toggles de reacción, edits inválidos o paquetes delete-for-everyone crea un DoS a nivel de aplicación:

* Obliga a la radio/módem a transmitir/recibir cada segundo → drenaje notable de batería, especialmente en handsets inactivos.
* Genera tráfico upstream/downstream sin medición que consume planes de datos móviles mientras se mezcla con ruido TLS/WebSocket.
* Ocupa hilos criptográficos e introduce jitter en funciones sensibles a la latencia (VoIP, videollamadas) aunque el usuario nunca vea notificaciones.
* En WhatsApp, las reacciones inválidas aceptan mucha más data de la que sugiere un emoji normal: mediciones publicadas encontraron aceptación del lado del servidor de hasta aproximadamente `1 MB` por reacción.
* Las reacciones sobredimensionadas dejan de producir delivery receipts fiables una vez que el cuerpo crece por encima de aproximadamente `30 bytes`, pero aun así se reenvían y procesan antes de descartarse. Mantén pequeños los cuerpos de reacción cuando necesites ACKs; inflalos solo cuando el objetivo sea puro drain o transporte unidireccional encubierto.
* Mediciones públicas alcanzaron alrededor de `3.7 MB/s` (`~13.3 GB/h`) de tráfico de la víctima en este modo.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
