# Ataques por canal lateral de recibos de entrega en mensajería E2EE

{{#include ../banners/hacktricks-training.md}}

Los recibos de entrega son obligatorios en los mensajeros modernos con end-to-end encryption (E2EE) porque los clientes necesitan saber cuándo se ha desencriptado un ciphertext para poder descartar el ratcheting state y las claves efímeras. El servidor reenvía blobs opacos, por lo que los acknowledgements de dispositivo (double checkmarks) son emitidos por el destinatario tras una desencriptación satisfactoria. Medir el round-trip time (RTT) entre una acción provocada por el atacante y el correspondiente recibo de entrega expone un canal de temporización de alta resolución que leaks el estado del dispositivo, la presencia en línea, y puede abusarse para un DoS encubierto. Las desplegables multi-dispositivo "client-fanout" amplifican la fuga porque cada dispositivo registrado desencripta la sonda y devuelve su propio recibo.

## Fuentes de recibos de entrega vs señales visibles por el usuario

Elige tipos de mensaje que siempre emitan un recibo de entrega pero que no muestren artefactos en la UI de la víctima. La tabla abajo resume el comportamiento confirmado empíricamente:

| Messenger | Acción | Recibo de entrega | Notificación a la víctima | Notas |
|-----------|--------|------------------|---------------------------|-------|
| **WhatsApp** | Mensaje de texto | ● | ● | Siempre ruidoso → útil solo para arrancar el estado. |
| | Reacción | ● | ◐ (solo si reaccionando a un mensaje de la víctima) | Self-reactions y removals permanecen silenciosos. |
| | Editar | ● | Push silencioso dependiente de la plataforma | Ventana de edición ≈20 min; todavía ack’d después del vencimiento. |
| | Eliminar para todos | ● | ○ | La UI permite ~60 h, pero paquetes posteriores siguen siendo ack’d. |
| **Signal** | Mensaje de texto | ● | ● | Mismas limitaciones que WhatsApp. |
| | Reacción | ● | ◐ | Self-reactions invisibles para la víctima. |
| | Editar/Eliminar | ● | ○ | El servidor aplica ~48 h, permite hasta 10 ediciones, pero paquetes tardíos siguen siendo ack’d. |
| **Threema** | Mensaje de texto | ● | ● | Los recibos multi-dispositivo son agregados, así que solo un RTT por sonda se vuelve visible. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de la UI dependiente de la plataforma se anota en línea. Desactiva read receipts si es necesario, pero los recibos de entrega no pueden desactivarse en WhatsApp o Signal.

## Attacker goals and models

* **G1 – Device fingerprinting:** Contar cuántos recibos llegan por sonda, agrupar RTTs para inferir OS/client (Android vs iOS vs desktop), y observar transiciones online/offline del dispositivo.
* **G2 – Behavioural monitoring:** Tratar la serie de RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e inferir pantalla encendida/apagada, app en foreground/background, horas de traslado vs trabajo, etc.
* **G3 – Resource exhaustion:** Mantener las radios/CPUs de cada dispositivo víctima despiertas enviando sondas silenciosas sin fin, agotando batería/datos y degradando la calidad de VoIP/RTC.

Dos actores de amenaza son suficientes para describir la superficie de abuso:

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de self-reactions, eliminación de reacciones, o ediciones/eliminaciones repetidas atadas a message IDs existentes.
2. **Spooky stranger:** registra una cuenta burner y envía reacciones que referencian message IDs que nunca existieron en la conversación local; WhatsApp y Signal aún las desencriptan y las reconocen aunque la UI descarte el cambio de estado, así que no se requiere conversación previa.

## Tooling for raw protocol access

Confía en clientes que expongan el protocolo E2EE subyacente para que puedas construir paquetes fuera de las restricciones de la UI, especificar `message_id`s arbitrarios y registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) o [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) te permiten emitir `ReactionMessage`, `ProtocolMessage` (edit/delete) y frames `Receipt` en bruto mientras mantienes el double-ratchet state sincronizado.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado con [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expone cada tipo de mensaje vía CLI/API. Ejemplo de toggle de self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** El código fuente del cliente Android documenta cómo los recibos de entrega se consolidan antes de salir del dispositivo, explicando por qué el canal lateral tiene ancho de banda despreciable allí.

Cuando no haya tooling personalizado, aún puedes activar acciones silenciosas desde WhatsApp Web o Signal Desktop y sniffear el websocket/WebRTC cifrado, pero las APIs en bruto eliminan retardos de la UI y permiten operaciones inválidas.

## Creepy companion: bucle de muestreo silencioso

1. Escoge cualquier mensaje histórico que hayas enviado en el chat para que la víctima nunca vea cambios en los "globos" de reacción.
2. Alterna entre un emoji visible y una carga de reacción vacía (codificada como `""` en protobufs de WhatsApp o `--remove` en signal-cli). Cada transmisión produce un ack de dispositivo a pesar de no haber delta en la UI para la víctima.
3. Registra el timestamp de envío y de cada llegada de recibo de entrega. Un bucle a 1 Hz como el siguiente da trazas de RTT por dispositivo indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Porque WhatsApp/Signal aceptan actualizaciones ilimitadas de reacción, el atacante nunca necesita publicar contenido nuevo en el chat ni preocuparse por ventanas de edición.

## Spooky stranger: sondeando números de teléfono arbitrarios

1. Registra una cuenta nueva en WhatsApp/Signal y obtén las public identity keys para el número objetivo (se hace automáticamente durante el setup de sesión).
2. Construye un paquete de reaction/edit/delete que referencie un `message_id` aleatorio nunca visto por ninguna de las partes (WhatsApp acepta GUIDs arbitrarios en `key.id`; Signal usa timestamps en milisegundos).
3. Envía el paquete aunque no exista hilo. Los dispositivos de la víctima lo desencriptan, no logran emparejarlo con el mensaje base, descartan el cambio de estado, pero aún reconocen el ciphertext entrante y envían receipts de dispositivo de vuelta al atacante.
4. Repite continuamente para construir series de RTT sin aparecer jamás en la lista de chats de la víctima.

## Reciclar ediciones y eliminaciones como triggers encubiertos

* **Eliminaciones repetidas:** Tras eliminar un mensaje para todos una vez, paquetes de delete adicionales que referencien el mismo `message_id` no tienen efecto en la UI pero cada dispositivo aún los desencripta y los reconoce.
* **Operaciones fuera de ventana:** WhatsApp aplica ~60 h para delete / ~20 min para edit en la UI; Signal aplica ~48 h. Mensajes de protocolo creados fuera de estas ventanas son ignorados silenciosamente en el dispositivo de la víctima pero se transmiten receipts, así que los atacantes pueden sondear indefinidamente mucho después de que la conversación haya terminado.
* **Payloads inválidos:** Cuerpos de edición malformados o eliminaciones que referencian mensajes ya purgados provocan el mismo comportamiento—desencriptado más receipt, cero artefactos visibles al usuario.

## Amplificación multi-dispositivo y fingerprinting

* Cada dispositivo asociado (teléfono, app de escritorio, companion en navegador) desencripta la sonda de forma independiente y devuelve su propio ack. Contar recibos por sonda revela el número exacto de dispositivos.
* Si un dispositivo está offline, su recibo se encola y se emite al reconectar. Por tanto, los huecos filtran ciclos online/offline e incluso horarios de desplazamiento (por ejemplo, los recibos del escritorio paran durante viajes).
* Las distribuciones de RTT difieren por plataforma debido a la gestión de energía del OS y wakeups push. Agrupa RTTs (por ejemplo, k-means sobre características median/varianza) para etiquetar “Android handset", “iOS handset", “Electron desktop", etc.
* Porque el remitente debe recuperar el inventory de llaves del destinatario antes de cifrar, el atacante también puede observar cuando se emparejan nuevos dispositivos; un aumento repentino en el conteo de dispositivos o un nuevo cluster de RTT es un indicador fuerte.

## Inferencia de comportamiento a partir de trazas RTT

1. Muestrea a ≥1 Hz para capturar efectos de scheduling del OS. Con WhatsApp en iOS, RTTs <1 s se correlacionan fuertemente con pantalla encendida/foreground, >1 s con throttling por pantalla apagada/background.
2. Construye clasificadores simples (thresholding o k-means de dos clusters) que etiqueten cada RTT como "active" o "idle". Agrega etiquetas en rachas para derivar horarios de sueño, desplazamientos, horas de trabajo, o cuándo el companion de escritorio está activo.
3. Correlaciona sondas simultáneas hacia cada dispositivo para ver cuándo los usuarios cambian de móvil a escritorio, cuándo los companions se desconectan, y si la app está rate limited por push vs socket persistente.

## Agotamiento de recursos sigiloso

Porque cada sonda silenciosa debe desencriptarse y reconocerse, enviar continuamente toggles de reacción, ediciones inválidas, o paquetes de delete-for-everyone crea un DoS a nivel de aplicación:

* Fuerza la radio/modem a transmitir/recibir cada segundo → notable desgaste de batería, especialmente en handsets en reposo.
* Genera tráfico upstream/downstream que consume planes de datos móviles mientras se mezcla en el ruido TLS/WebSocket.
* Ocupa hilos de crypto e introduce jitter en funciones sensibles a latencia (VoIP, video calls) aunque el usuario nunca vea notificaciones.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
