# Side-Channel Attacks de Delivery Receipts en Messengers E2EE

Los delivery receipts son obligatorios en los messengers modernos con cifrado end-to-end (E2EE), porque los clientes necesitan saber cuándo se descifró un ciphertext para poder descartar el estado del ratchet y las claves efímeras. El servidor reenvía blobs opacos, por lo que los acknowledgements del dispositivo (dobles marcas de verificación) los emite el destinatario después de descifrar correctamente. Medir el round-trip time (RTT) entre una acción activada por el atacante y el delivery receipt correspondiente expone un canal temporal de alta resolución que hace leak del estado del dispositivo y de la presencia online, y que puede abusarse para realizar DoS encubierto. Las implementaciones multidispositivo de tipo "client-fanout" amplifican el leak porque cada dispositivo registrado descifra el probe y devuelve su propio receipt.<sup>[[1]](#references)</sup>

## Fuentes de delivery receipts frente a señales visibles para el usuario

Elige tipos de mensajes que siempre emitan un delivery receipt, pero que no muestren artefactos en la UI de la víctima. La siguiente tabla resume el comportamiento confirmado empíricamente:<sup>[[1]](#references)</sup>

| Messenger | Acción | Delivery receipt | Notificación de la víctima | Notas |
|-----------|--------|------------------|----------------------------|-------|
| **WhatsApp** | Mensaje de texto | ● | ● | Siempre genera ruido → solo es útil para iniciar el estado. |
| | Reacción | ● | ◐ (solo al reaccionar al mensaje de la víctima) | Las autorreacciones y eliminaciones permanecen silenciosas. |
| | Edición | ● | Push silencioso dependiente de la plataforma | Ventana de edición ≈20 min; sigue generando ack después de expirar. |
| | Eliminar para todos | ● | ○ | La UI permite ~60 h, pero los paquetes posteriores siguen generando ack. |
| **Signal** | Mensaje de texto | ● | ● | Las mismas limitaciones que WhatsApp. |
| | Reacción | ● | ◐ | Las autorreacciones son invisibles para la víctima. |
| | Editar/Eliminar | ● | ○ | El servidor aplica una ventana de ~48 h y permite hasta 10 ediciones, pero los paquetes tardíos siguen generando ack. |
| **Threema** | Mensaje de texto | ● | ● | Los receipts multidispositivo se agregan, por lo que solo un RTT por probe se hace visible. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de la UI dependiente de la plataforma se indica en línea. Desactiva los read receipts si es necesario, pero los delivery receipts no pueden desactivarse en WhatsApp ni Signal.<sup>[[1]](#references)</sup>

## Objetivos y modelos del atacante

* **G1 – Fingerprinting de dispositivos:** Cuenta cuántos receipts llegan por probe, agrupa los RTT para inferir el OS/cliente (Android frente a iOS frente a desktop) y observa las transiciones online/offline.
* **G2 – Monitorización de comportamiento:** Trata la serie de RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e infiere si la pantalla está encendida/apagada, si la app está en foreground/background, los horarios de desplazamiento frente a trabajo, etc.
* **G3 – Agotamiento de recursos:** Mantiene activadas las radios/CPUs de todos los dispositivos de la víctima enviando probes silenciosos interminables, agotando batería/datos y degradando la calidad de las videollamadas.<sup>[[1]](#references)</sup>

Dos threat actors bastan para describir la superficie de abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de autorreacciones, eliminaciones de reacciones o ediciones/eliminaciones repetidas vinculadas a IDs de mensajes existentes.
2. **Spooky stranger:** registra una cuenta desechable y envía reacciones que hacen referencia a IDs de mensajes que nunca existieron en la conversación local; WhatsApp y Signal aun así los descifran y reconocen, aunque la UI descarta el cambio de estado, por lo que no se requiere una conversación previa.

## Tooling para acceso al protocolo raw

Utiliza clientes que expongan suficiente información del protocolo E2EE subyacente para crear paquetes compatibles fuera de las limitaciones de la UI y registrar timestamps precisos; los IDs de mensajes arbitrarios requieren comprobar cada implementación:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidispositivo de WhatsApp Web) documenta el envío y la recepción de delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (API no oficial de Web y mobile en Java/Kotlin) documenta operaciones de mensajes como reaccionar, editar y eliminar. Utiliza sus APIs documentadas en lugar de asumir que cada frame interno está expuesto.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) expone interfaces CLI, JSON-RPC y D-Bus, mientras que [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) es una biblioteca Java para comunicarse con Signal.<sup>[[5]](#references)[[7]](#references)</sup> La sintaxis actual de `signal-cli` utiliza `sendReaction RECIPIENT --target-author --target-timestamp`; mantén `receive` o `daemon` en ejecución para que las actualizaciones del protocolo sigan procesándose.<sup>[[6]](#references)</sup> Ejemplo de toggle de autorreacción:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Las mediciones del artículo Careless Whisper descubrieron que los delivery receipts se sincronizan entre dispositivos, por lo que solo se expone un receipt por mensaje incluso en una configuración multidispositivo.<sup>[[1]](#references)</sup>
* **PoCs turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) incluye backends para WhatsApp/Signal, utiliza por defecto probes de eliminación silenciosa y etiqueta `active` frente a `standby` con un umbral de mediana móvil (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) es una CLI más ligera centrada en WhatsApp, con `--delay`, `--concurrent`, exporters CSV/Prometheus y salida compatible con Grafana.<sup>[[9]](#references)</sup> Trata ambas como herramientas auxiliares de reconnaissance, no como referencias del protocolo; la conclusión importante es lo poco código que se necesita una vez que existe acceso al cliente raw.

Cuando no haya tooling personalizado, los clientes oficiales o las developer tools del navegador aún pueden activar acciones silenciosas y exponer el timing del tráfico cifrado; las APIs raw eliminan los retrasos de la UI y permiten operaciones inválidas.<sup>[[1]](#references)</sup>

## Creepy companion: loop de muestreo silencioso

1. Elige cualquier mensaje histórico que hayas escrito en el chat para que la víctima nunca vea cambiar los globos de "reacción".
2. Alterna entre un emoji visible y un payload de reacción vacío (codificado como `""` en los protobufs de WhatsApp o como `--remove` en signal-cli). Cada transmisión produce un ack del dispositivo pese a que no existe ningún cambio visible en la UI de la víctima.
3. Registra el momento de envío y la llegada de cada delivery receipt. Un loop de 1 Hz como el siguiente proporciona indefinidamente trazas de RTT por dispositivo:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceptan actualizaciones ilimitadas de reacciones, el atacante nunca necesita publicar contenido nuevo en el chat ni preocuparse por las ventanas de edición.<sup>[[1]](#references)</sup>

## Spooky stranger: probing de números de teléfono arbitrarios

1. Registra una cuenta nueva de WhatsApp/Signal y obtiene las claves de identidad públicas del número objetivo (se realiza automáticamente durante la configuración de la sesión).
2. Crea un paquete de reacción que haga referencia a un `message_id` aleatorio que ninguna de las partes haya visto; el artículo informa de que tanto WhatsApp como Signal aceptan dichas reacciones y siguen generando delivery receipts.<sup>[[1]](#references)</sup>
3. Envía el paquete aunque no exista ningún thread. Los dispositivos de la víctima lo descifran, no encuentran el mensaje base, descartan el cambio de estado, pero aun así reconocen el ciphertext entrante y envían los receipts del dispositivo de vuelta al atacante.
4. Repite continuamente para crear series de RTT sin una conversación previa ni una notificación visible.<sup>[[1]](#references)</sup>

Si primero necesitas descubrir qué números están registrados o quieres preparar inventarios de dispositivos a escala, encadena esto con [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) en lugar de adivinar manualmente rangos E.164 aleatorios.

Los trabajos publicados sobre contact-discovery mostraron por qué esto es importante operativamente: con tablas precisas de prefijos telefónicos y recursos modestos, los investigadores pudieron consultar aproximadamente el `10%` de los números móviles de EE. UU. en WhatsApp y el `100%` en Signal antes de pasar al probing dirigido.<sup>[[11]](#references)</sup> En la práctica, filtrar primero las cuentas activas mantiene el presupuesto de silent probes centrado en números que realmente descifrarán los paquetes.

Las versiones recientes de WhatsApp también exponen `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trátalo como un limitador de throughput: la documentación del tracker indica que WhatsApp bloquea los mensajes de alto volumen procedentes de cuentas desconocidas, pero no revela el umbral, por lo que no evita completamente las reacciones de probing.<sup>[[8]](#references)</sup>

## Reciclaje de ediciones y eliminaciones como triggers encubiertos

* **Eliminaciones repetidas:** Después de eliminar un mensaje para todos una vez, los paquetes de eliminación posteriores que hagan referencia al mismo `message_id` no producen ningún efecto en la UI, pero todos los dispositivos siguen descifrándolos y reconociéndolos.
* **Operaciones fuera de ventana:** WhatsApp aplica ventanas de ~60 h para eliminar y ~20 min para editar en la UI; Signal aplica ~48 h. Los mensajes de protocolo creados fuera de estas ventanas se ignoran silenciosamente en el dispositivo de la víctima, pero los receipts se transmiten, por lo que los atacantes pueden hacer probing indefinidamente mucho después de que terminara la conversación.
* **Payloads inválidos:** El artículo informa de que los mensajes inválidos aún pueden reconocerse; el comportamiento exacto para cuerpos malformados o IDs purgados depende de la implementación, por lo que debe probarse antes de confiar en ello.<sup>[[1]](#references)</sup>

## Amplificación multidispositivo y fingerprinting

* En WhatsApp y Signal, cada dispositivo asociado (teléfono, app de escritorio, companion del navegador) descifra el probe de forma independiente y devuelve su propio ack. Contar los receipts por probe revela el número exacto de dispositivos.<sup>[[1]](#references)</sup>
* Si un dispositivo está offline, su receipt se pone en cola y se emite al reconectarse. Por tanto, los intervalos hacen leak de los ciclos online/offline e incluso de los horarios de desplazamiento (por ejemplo, los receipts del desktop dejan de llegar durante los viajes).
* Las distribuciones de RTT difieren según la plataforma y el entorno, porque el OS, el modelo, el cliente y las condiciones de red afectan al timing. Agrupa los RTT (por ejemplo, aplicando k-means sobre características de mediana/varianza) para etiquetar “Android handset”, “iOS handset”, “Electron desktop”, etc.
* Como el sender debe recuperar el inventario de claves del destinatario antes de cifrar, el atacante también puede observar cuándo se emparejan nuevos dispositivos; un aumento repentino del número de dispositivos o un nuevo cluster de RTT es un indicador sólido.<sup>[[1]](#references)</sup>

## Cadencia de muestreo, queueing y receipts acumulados

* **Tolerancia de WhatsApp a bursts:** Las mediciones publicadas informaron de que WhatsApp aceptaba bursts de reacciones silenciosas de hasta un probe cada `50 ms` sin queueing evidente en el servidor. Esto resulta útil para bursts cortos de calibración, conteo rápido de dispositivos o para acelerar rápidamente un drain attack.
* **Queueing prolongado en Signal:** Signal toleraba bursts cortos, pero comenzó a poner en cola el tráfico sostenido de varios probes por segundo. Para monitorización de larga duración, mantén la cadencia alrededor de `1 Hz` (o inferior), de modo que cada receipt siga reflejando el estado actual del dispositivo en lugar de vaciar una cola acumulada.
* **Artefactos de reconexión:** Cuando un dispositivo vuelve a estar online, algunos clientes agrupan o vacían rápidamente varios receipts retrasados. Trata esos bursts de receipts como un marcador de transición de estado y no como muestras de RTT independientes; de lo contrario, tu clustering o clasificador `active` frente a `idle` se ajustará en exceso al ruido de reconexión.<sup>[[1]](#references)</sup>

## Inferencia de comportamiento a partir de trazas de RTT

1. Muestrea a ≥1 Hz para capturar los efectos de scheduling del OS. Con WhatsApp en iOS, los RTT <1 s se correlacionan fuertemente con la pantalla encendida/foreground, mientras que los RTT >1 s se relacionan con throttling de pantalla apagada/background.
2. Construye clasificadores simples (thresholding o k-means de dos clusters) que etiqueten cada RTT como "active" o "idle". Agrega las etiquetas en rachas para obtener horarios de sueño, desplazamientos, horas de trabajo o cuándo está activo el companion de escritorio.
3. Correlaciona probes simultáneos dirigidos a cada dispositivo para observar cuándo los usuarios cambian del móvil al desktop, cuándo los companions se desconectan y si la app está limitada por rate limiting de push frente a un socket persistente.
4. En redes reales, evita un umbral único de `1 s` codificado de forma rígida. Inicializa cada dispositivo con una breve ventana de warm-up y conserva una baseline móvil (por ejemplo, la PoC device-activity-tracker utiliza `threshold = 0.9 * median RTT`) para que las variaciones de Wi-Fi/celular no inutilicen tu clasificador.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferencia de ubicación a partir del RTT de delivery

El mismo primitive temporal puede reutilizarse para inferir dónde está el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar con distribuciones de RTT de ubicaciones conocidas permite al atacante clasificar posteriormente la ubicación de la víctima solo a partir de las confirmaciones de delivery:<sup>[[2]](#references)</sup>

* Crea una baseline para el mismo objetivo mientras se encuentra en varios lugares conocidos (casa, oficina, campus, país A frente a país B, etc.).
* Para cada ubicación, recopila muchos RTT de mensajes normales y extrae características simples como mediana, varianza o buckets de percentiles.
* Durante el ataque real, compara la nueva serie de probes con los clusters entrenados. El artículo informa de que incluso pueden separarse a menudo ubicaciones dentro de la misma ciudad, con una precisión `>80%` en una configuración de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el entorno del sender y hace probing bajo condiciones de red similares, porque la ruta medida incluye la red de acceso del destinatario, la latencia de activación y la infraestructura del messenger.<sup>[[2]](#references)</sup>

A diferencia de los ataques silenciosos de reacciones/ediciones/eliminaciones anteriores, la inferencia de ubicación no requiere IDs de mensajes inválidos ni paquetes sigilosos que cambien el estado. Los mensajes normales con confirmaciones de delivery normales son suficientes, por lo que el coste es un menor sigilo, pero una aplicabilidad más amplia entre messengers.

## Agotamiento sigiloso de recursos

Como cada probe silencioso debe descifrarse y reconocerse, el envío continuo de toggles de reacciones, ediciones inválidas o paquetes de eliminación para todos crea un DoS en la capa de aplicación:<sup>[[1]](#references)</sup>

* Obliga a la radio/módem a transmitir/recibir cada segundo → provoca un consumo de batería apreciable, especialmente en handsets inactivos.
* Genera tráfico upstream/downstream que consume los planes de datos móviles y puede competir con funciones sensibles a la latencia, como las videollamadas.<sup>[[1]](#references)</sup>
* Los payloads inválidos añaden trabajo de procesamiento, pero el artículo informa de que la criptografía en sí representa una parte insignificante del coste de batería.<sup>[[1]](#references)</sup>
* En WhatsApp, las reacciones inválidas aceptan muchos más datos de lo que sugiere un emoji normal: las mediciones publicadas encontraron una aceptación por parte del servidor de hasta aproximadamente `1 MB` por reacción.
* Las reacciones sobredimensionadas dejan de producir delivery receipts fiables cuando el cuerpo supera aproximadamente los `30 bytes`, pero siguen reenviándose y procesándose antes de descartarse. Mantén pequeños los cuerpos de las reacciones cuando necesites ACKs; inflalos solo cuando el objetivo sea el drain puro o un transporte unidireccional encubierto.
* Las mediciones públicas alcanzaron aproximadamente `3.7 MB/s` (`~13.3 GB/h`) de tráfico de la víctima en este modo.

## References

- [1] [Careless Whisper: Explotación de Silent Delivery Receipts para Monitorizar Usuarios en Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracción de Ubicaciones de Usuarios a Partir de Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Página de manual de signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Cómo bloquear grandes volúmenes de mensajes desconocidos | Centro de ayuda de WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Todos los números son de EE. UU.: Abuso a gran escala del Contact Discovery en Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
