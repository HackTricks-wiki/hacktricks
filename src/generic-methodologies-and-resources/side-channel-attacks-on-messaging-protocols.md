# Ataques de canal lateral de Delivery Receipt en mensajeros E2EE

{{#include ../banners/hacktricks-training.md}}

Los delivery receipts son obligatorios en los mensajeros modernos de cifrado de extremo a extremo (E2EE) porque los clientes necesitan saber cuándo se descifró un ciphertext para poder descartar el estado de ratcheting y las ephemeral keys. El servidor reenvía blobs opacos, así que las confirmaciones del dispositivo (doble checkmark) las emite el destinatario después de un descifrado exitoso. Medir el round-trip time (RTT) entre una acción provocada por el atacante y el delivery receipt correspondiente expone un canal de temporización de alta resolución que leakea el estado del dispositivo, la presencia online y puede abusarse para DoS encubierto. Los despliegues multi-device de "client-fanout" amplifican el leak porque cada dispositivo registrado descifra la probe y devuelve su propio receipt.

## Delivery receipt sources vs. user-visible signals

Elige tipos de mensaje que siempre emitan un delivery receipt pero no muestren artefactos UI en la víctima. La tabla de abajo resume el comportamiento confirmado empíricamente:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Siempre ruidoso → solo útil para arrancar estado. |
| | Reaction | ● | ◐ (solo si se reacciona al mensaje de la víctima) | Las self-reactions y removals permanecen silenciosas. |
| | Edit | ● | Push silencioso dependiente de la plataforma | La ventana de edición ≈20 min; aún se ack’d después del vencimiento. |
| | Delete for everyone | ● | ○ | La UI permite ~60 h, pero los paquetes posteriores aún se ack’d. |
| **Signal** | Text message | ● | ● | Las mismas limitaciones que WhatsApp. |
| | Reaction | ● | ◐ | Las self-reactions son invisibles para la víctima. |
| | Edit/Delete | ● | ○ | El servidor impone una ventana de ~48 h, permite hasta 10 edits, pero los paquetes tardíos aún se ack’d. |
| **Threema** | Text message | ● | ● | Los delivery receipts multi-device se agregan, así que solo se hace visible un RTT por probe. |

Leyenda: ● = always, ◐ = conditional, ○ = never. El comportamiento UI dependiente de la plataforma se indica en línea. Desactiva los read receipts si hace falta, pero los delivery receipts no se pueden desactivar en WhatsApp o Signal.

## Objetivos y modelos del atacante

* **G1 – Device fingerprinting:** Cuenta cuántos receipts llegan por probe, agrupa los RTT para inferir OS/client (Android vs iOS vs desktop), y observa transiciones online/offline.
* **G2 – Behavioural monitoring:** Trata la serie de RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e infiere pantalla encendida/apagada, app en foreground/background, horarios de desplazamiento vs trabajo, etc.
* **G3 – Resource exhaustion:** Mantén las radios/CPUs de cada dispositivo de la víctima despiertas enviando silent probes sin fin, drenando batería/datos y degradando la calidad de VoIP/RTC.

Dos actores de amenaza bastan para describir la superficie de abuso:

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de self-reactions, reaction removals o edits/deletes repetidos vinculados a IDs de mensaje existentes.
2. **Spooky stranger:** registra una cuenta burner y envía reactions que referencian IDs de mensaje que nunca existieron en la conversación local; WhatsApp y Signal aún así los descifran y los acknowledge aunque la UI descarte el cambio de estado, así que no se requiere conversación previa.

## Tooling para acceso raw al protocolo

Depende de clientes que expongan el protocolo E2EE subyacente para que puedas crear paquetes fuera de las restricciones de la UI, especificar `message_id`s arbitrarios y registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo de WhatsApp Web) o [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) te permiten emitir frames raw `ReactionMessage`, `ProtocolMessage` (edit/delete) y `Receipt` manteniendo el estado double-ratchet sincronizado.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expone cada tipo de mensaje vía CLI/API. Ejemplo de toggle de self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** El código fuente del cliente Android documenta cómo se consolidan los delivery receipts antes de salir del dispositivo, explicando por qué el side channel allí tiene ancho de banda despreciable.
* **Turnkey PoCs:** proyectos públicos como `device-activity-tracker` y `careless-whisper-python` ya automatizan silent delete/reaction probes y la clasificación de RTT. Trátalos como ayudantes de reconocimiento listos para usar más que como referencias de protocolo; la parte interesante es que confirman que el ataque es operativamente simple una vez existe acceso raw al cliente.

Cuando no haya tooling personalizado disponible, aún puedes disparar acciones silenciosas desde WhatsApp Web o Signal Desktop y esnifar el canal websocket/WebRTC cifrado, pero las APIs raw eliminan retrasos de UI y permiten operaciones inválidas.

## Creepy companion: silent sampling loop

1. Elige cualquier mensaje histórico que hayas escrito en el chat para que la víctima nunca vea cambiar los globos de "reaction".
2. Alterna entre un emoji visible y un payload de reacción vacío (codificado como `""` en protobufs de WhatsApp o `--remove` en signal-cli). Cada transmisión genera un device ack pese a no haber delta en la UI para la víctima.
3. Marca el send time y la llegada de cada delivery receipt. Un loop de 1 Hz como el siguiente da trazas de RTT por dispositivo indefinidamente:
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

1. Registra una cuenta nueva de WhatsApp/Signal y obtén las public identity keys para el número objetivo (se hace automáticamente durante la configuración de la sesión).
2. Construye un paquete de reaction/edit/delete que referencie un `message_id` aleatorio nunca visto por ninguna de las partes (WhatsApp acepta GUIDs arbitrarios `key.id`; Signal usa timestamps en milisegundos).
3. Envía el paquete aunque no exista ningún thread. Los dispositivos de la víctima lo descifran, fallan al hacer match con el base message, descartan el cambio de estado, pero aun así acknowledge el ciphertext entrante, devolviendo device receipts al atacante.
4. Repite continuamente para construir series de RTT sin aparecer nunca en la lista de chats de la víctima.

## Reutilizar edits y deletes como triggers encubiertos

* **Repeated deletes:** Después de que un mensaje se borra-for-everyone una vez, los siguientes paquetes delete que referencian el mismo `message_id` no tienen efecto en la UI, pero cada dispositivo aún los descifra y los acknowledge.
* **Out-of-window operations:** WhatsApp aplica ventanas de ~60 h para delete / ~20 min para edit en la UI; Signal aplica ~48 h. Los mensajes de protocolo construidos fuera de estas ventanas se ignoran silenciosamente en el dispositivo de la víctima, pero los receipts se transmiten, así que los atacantes pueden sondear indefinidamente mucho después de que la conversación haya terminado.
* **Invalid payloads:** cuerpos de edit malformados o deletes que referencian mensajes ya purgados provocan el mismo comportamiento—descifrado más receipt, cero artefactos visibles para el usuario.

## Multi-device amplification & fingerprinting

* Cada dispositivo asociado (teléfono, app de escritorio, companion del browser) descifra la probe de forma independiente y devuelve su propio ack. Contar receipts por probe revela el número exacto de dispositivos.
* Si un dispositivo está offline, su receipt se encola y se emite al reconectarse. Por tanto, los huecos leakean ciclos online/offline e incluso horarios de desplazamiento (por ejemplo, los receipts del desktop se detienen durante el viaje).
* Las distribuciones de RTT difieren por plataforma debido a la gestión de energía del OS y a los wakeups de push. Agrupa los RTT (por ejemplo, k-means sobre features de mediana/varianza) para etiquetar “Android handset", “iOS handset", “Electron desktop", etc.
* Como el emisor debe recuperar el inventario de keys del destinatario antes de cifrar, el atacante también puede observar cuándo se emparejan nuevos dispositivos; un aumento repentino en el número de dispositivos o un nuevo cluster de RTT es un indicador fuerte.

## Behaviour inference from RTT traces

1. Muestrea a ≥1 Hz para capturar los efectos de scheduling del OS. Con WhatsApp en iOS, RTT <1 s se correlaciona fuertemente con pantalla encendida/foreground, RTT >1 s con throttling de pantalla apagada/background.
2. Construye clasificadores simples (thresholding o two-cluster k-means) que etiqueten cada RTT como "active" o "idle". Agrega las etiquetas en rachas para derivar horas de dormir, desplazamientos, horario laboral o cuándo el companion de escritorio está activo.
3. Correlaciona probes simultáneas hacia cada dispositivo para ver cuándo los usuarios cambian de mobile a desktop, cuándo los companions se desconectan y si la app está limitada por rate limiting de push o por socket persistente.

## Location inference from delivery RTT

El mismo primitive de temporización puede reutilizarse para inferir dónde está el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar con distribuciones de RTT para ubicaciones conocidas del receptor permite a un atacante clasificar más tarde la ubicación de la víctima solo a partir de delivery confirmations:

* Construye una línea base para el mismo objetivo mientras está en varios lugares conocidos (home, office, campus, country A vs country B, etc.).
* Para cada ubicación, recopila muchos RTT de mensajes normales y extrae features simples como mediana, varianza o percentiles.
* Durante el ataque real, compara la nueva serie de probe con los clusters entrenados. El paper informa que incluso ubicaciones dentro de la misma ciudad a menudo pueden separarse, con exactitud `>80%` en una configuración de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el sender environment y sondea bajo condiciones de red similares, porque el path medido incluye la red de acceso del destinatario, la latencia de wake-up y la infraestructura del messenger.

A diferencia de los silent reaction/edit/delete attacks de arriba, la inferencia de ubicación no requiere IDs de mensaje inválidos ni paquetes sigilosos que cambian estado. Bastan mensajes normales con delivery confirmations normales, así que el tradeoff es menor stealth pero mayor aplicabilidad entre mensajeros.

## Stealthy resource exhaustion

Como cada silent probe debe ser descifrada y acknowledge, enviar continuamente toggles de reaction, edits inválidos o paquetes delete-for-everyone crea un DoS a nivel de aplicación:

* Fuerza a la radio/modem a transmitir/recibir cada segundo → drenaje notable de batería, especialmente en handsets inactivos.
* Genera tráfico upstream/downstream no medido que consume planes de datos móviles mientras se mezcla con ruido TLS/WebSocket.
* Ocupa hilos criptográficos e introduce jitter en features sensibles a latencia (VoIP, videollamadas) aunque el usuario nunca vea notificaciones.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
