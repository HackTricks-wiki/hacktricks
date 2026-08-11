# Ataques de canal lateral mediante confirmaciones de entrega en Messengers E2EE

{{#include ../banners/hacktricks-training.md}}

Las confirmaciones de entrega son obligatorias en los Messengers modernos con cifrado de extremo a extremo (E2EE), porque los clientes necesitan saber cuándo se descifró un ciphertext para poder descartar el estado de ratcheting y las claves efímeras. El servidor reenvía blobs opacos, por lo que los acuses de recibo de los dispositivos (dobles marcas de verificación) son emitidos por el destinatario después de un descifrado correcto. Medir el tiempo de ida y vuelta (RTT) entre una acción activada por el atacante y la confirmación de entrega correspondiente expone un canal temporal de alta resolución que filtra el estado del dispositivo y la presencia online, y que puede abusarse para realizar DoS encubierto. Las implementaciones "client-fanout" multidispositivo amplifican el leak porque cada dispositivo registrado descifra la sonda y devuelve su propia confirmación.<sup>[[1]](#references)</sup>

## Fuentes de confirmaciones de entrega frente a señales visibles para el usuario

Elige tipos de mensajes que siempre emitan una confirmación de entrega, pero que no muestren elementos en la UI de la víctima. La siguiente tabla resume el comportamiento confirmado empíricamente:<sup>[[1]](#references)</sup>

| Messenger | Acción | Confirmación de entrega | Notificación para la víctima | Notas |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Mensaje de texto | ● | ● | Siempre genera ruido → solo es útil para inicializar el estado. |
| | Reacción | ● | ◐ (solo al reaccionar al mensaje de la víctima) | Las autorreacciones y las eliminaciones permanecen silenciosas. |
| | Edición | ● | Push silencioso dependiente de la plataforma | Ventana de edición ≈20 min; sigue confirmándose después de expirar. |
| | Eliminar para todos | ● | ○ | La UI permite ~60 h, pero los paquetes posteriores siguen confirmándose. |
| **Signal** | Mensaje de texto | ● | ● | Las mismas limitaciones que WhatsApp. |
| | Reacción | ● | ◐ | Las autorreacciones son invisibles para la víctima. |
| | Edición/Eliminación | ● | ○ | El servidor aplica una ventana de ~48 h y permite hasta 10 ediciones, pero los paquetes tardíos siguen confirmándose. |
| **Threema** | Mensaje de texto | ● | ● | Las confirmaciones multidispositivo se agregan, por lo que solo se hace visible un RTT por sonda. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de la UI dependiente de la plataforma se indica en línea. Desactiva las confirmaciones de lectura si es necesario, pero las confirmaciones de entrega no pueden desactivarse en WhatsApp ni Signal.<sup>[[1]](#references)</sup>

## Objetivos y modelos del atacante

* **G1 – Fingerprinting de dispositivos:** Cuenta cuántas confirmaciones llegan por sonda, agrupa los RTT para inferir el sistema operativo/cliente (Android frente a iOS o desktop) y observa las transiciones online/offline.
* **G2 – Monitorización del comportamiento:** Trata la serie de RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e infiere si la pantalla está encendida o apagada, si la app está en foreground o background, horas de desplazamiento frente a horas laborales, etc.
* **G3 – Agotamiento de recursos:** Mantén activas las radios/CPU de todos los dispositivos de la víctima enviando sondas silenciosas interminables, agotando batería/datos y degradando la calidad de las videollamadas.<sup>[[1]](#references)</sup>

Dos actores de amenaza bastan para describir la superficie de abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** ya comparte un chat con la víctima y abusa de autorreacciones, eliminaciones de reacciones o ediciones/eliminaciones repetidas asociadas a IDs de mensajes existentes.
2. **Spooky stranger:** registra una cuenta desechable y envía reacciones que hacen referencia a IDs de mensajes que nunca existieron en la conversación local; WhatsApp y Signal aun así los descifran y confirman aunque la UI descarte el cambio de estado, por lo que no se requiere una conversación previa.

## Tooling para acceder al protocolo sin procesar

Usa clientes que expongan suficiente del protocolo E2EE subyacente para crear paquetes compatibles fuera de las restricciones de la UI y registrar timestamps precisos; los IDs de mensajes arbitrarios requieren comprobar cada implementación:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidispositivo de WhatsApp Web) documenta el envío y la recepción de confirmaciones de entrega; [Cobalt](https://github.com/Auties00/Cobalt) (API no oficial de Web y mobile para Java/Kotlin) documenta operaciones de mensajes como reaccionar, editar y eliminar. Usa sus APIs documentadas en lugar de asumir que todos los frames internos están expuestos.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) expone interfaces CLI, JSON-RPC y D-Bus, mientras que [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) es una biblioteca Java para comunicarse con Signal.<sup>[[5]](#references)[[7]](#references)</sup> La sintaxis actual de `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantén `receive` o `daemon` ejecutándose para que las actualizaciones del protocolo continúen procesándose.<sup>[[6]](#references)</sup> Ejemplo de alternancia de autorreacción:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Las mediciones del artículo Careless Whisper descubrieron que las confirmaciones de entrega se sincronizan entre dispositivos, por lo que solo se expone una confirmación por mensaje incluso en una configuración multidispositivo.<sup>[[1]](#references)</sup>
* **PoCs turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) incluye backends de WhatsApp/Signal, usa sondas de eliminación silenciosa por defecto y etiqueta `active` frente a `standby` con un umbral de mediana móvil (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) es una CLI más ligera centrada primero en WhatsApp, con `--delay`, `--concurrent`, exportadores CSV/Prometheus y salida compatible con Grafana.<sup>[[9]](#references)</sup> Trata ambas como herramientas auxiliares de reconnaissance, no como referencias del protocolo; la conclusión importante es lo poco código que se necesita una vez que existe acceso al cliente sin procesar.

Cuando no haya tooling personalizado disponible, los clientes oficiales o las herramientas de desarrollo del navegador todavía pueden activar acciones silenciosas y exponer la temporización del tráfico cifrado; las APIs sin procesar eliminan los retrasos de la UI y permiten operaciones inválidas.<sup>[[1]](#references)</sup>

## Creepy companion: bucle de muestreo silencioso

1. Elige cualquier mensaje histórico que hayas enviado en el chat para que la víctima nunca vea cambiar los globos de "reacción".
2. Alterna entre un emoji visible y un payload de reacción vacío (codificado como `""` en los protobufs de WhatsApp o como `--remove` en signal-cli). Cada transmisión produce un ack del dispositivo aunque no haya ningún cambio visible en la UI de la víctima.
3. Registra el momento de envío y la llegada de cada confirmación de entrega. Un bucle de 1 Hz como el siguiente proporciona indefinidamente trazas de RTT por dispositivo:
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

1. Registra una cuenta nueva de WhatsApp/Signal y obtiene las claves de identidad públicas del número objetivo (se realiza automáticamente durante la configuración de la sesión).
2. Crea un paquete de reacción que haga referencia a un `message_id` aleatorio que ninguna de las partes haya visto; el artículo informa de que WhatsApp y Signal aceptan dichas reacciones y aun así generan confirmaciones de entrega.<sup>[[1]](#references)</sup>
3. Envía el paquete aunque no exista ningún hilo. Los dispositivos de la víctima lo descifran, no consiguen asociarlo con el mensaje base, descartan el cambio de estado, pero aun así confirman el ciphertext entrante y envían las confirmaciones del dispositivo al atacante.
4. Repite continuamente para crear series de RTT sin una conversación previa ni una notificación visible.<sup>[[1]](#references)</sup>

Si primero necesitas descubrir qué números están registrados o quieres preparar inventarios de dispositivos a escala, encadena esto con [oráculos de descubrimiento de contactos / registro](../pentesting-web/registration-vulnerabilities.md) en lugar de adivinar manualmente rangos E.164 aleatorios.

Los trabajos publicados sobre descubrimiento de contactos mostraron por qué esto es importante operativamente: con tablas precisas de prefijos telefónicos y recursos modestos, los investigadores pudieron consultar aproximadamente el `10%` de los números móviles de EE. UU. en WhatsApp y el `100%` en Signal antes de pasar al sondeo dirigido.<sup>[[11]](#references)</sup> En la práctica, filtrar primero las cuentas activas mantiene el presupuesto de sondas silenciosas centrado en números que realmente descifrarán los paquetes.

Las versiones recientes de WhatsApp también exponen `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trátalo como un limitador de rendimiento: la documentación del tracker indica que WhatsApp bloquea los mensajes de gran volumen procedentes de cuentas desconocidas, pero no revela el umbral, por lo que no impide completamente las reacciones de sondeo.<sup>[[8]](#references)</sup>

## Reutilización de ediciones y eliminaciones como triggers encubiertos

* **Eliminaciones repetidas:** Después de que un mensaje se elimine para todos una vez, los paquetes de eliminación posteriores que hagan referencia al mismo `message_id` no tienen efecto en la UI, pero cada dispositivo sigue descifrándolos y confirmándolos.
* **Operaciones fuera de ventana:** WhatsApp aplica ventanas de ~60 h para eliminar y ~20 min para editar en la UI; Signal aplica ~48 h. Los mensajes de protocolo creados fuera de estas ventanas se ignoran silenciosamente en el dispositivo de la víctima, pero las confirmaciones se transmiten, por lo que los atacantes pueden sondear indefinidamente mucho después de que haya terminado la conversación.
* **Payloads inválidos:** El artículo informa de que los mensajes inválidos todavía pueden confirmarse; el comportamiento exacto para cuerpos malformados o IDs eliminados depende de la implementación, así que pruébalo antes de depender de ello.<sup>[[1]](#references)</sup>

## Amplificación multidispositivo y fingerprinting

* En WhatsApp y Signal, cada dispositivo asociado (teléfono, app de desktop, companion del navegador) descifra la sonda de forma independiente y devuelve su propio ack. Contar las confirmaciones por sonda revela el número exacto de dispositivos.<sup>[[1]](#references)</sup>
* Si un dispositivo está offline, su confirmación queda en cola y se emite al reconectarse. Por tanto, las interrupciones filtran los ciclos online/offline e incluso los horarios de desplazamiento (por ejemplo, las confirmaciones del desktop se detienen durante los viajes).
* Las distribuciones de RTT difieren según la plataforma y el entorno porque el sistema operativo, el modelo, el cliente y las condiciones de red afectan a la temporización. Agrupa los RTT (por ejemplo, mediante k-means sobre características de mediana/varianza) para etiquetar “terminal Android", “terminal iOS", “desktop Electron", etc.
* Como el emisor debe recuperar el inventario de claves del destinatario antes de cifrar, el atacante también puede observar cuándo se emparejan dispositivos nuevos; un aumento repentino del número de dispositivos o un nuevo cluster de RTT es un indicador sólido.<sup>[[1]](#references)</sup>

## Cadencia de muestreo, colas y confirmaciones acumuladas

* **Tolerancia de WhatsApp a bursts:** Las mediciones publicadas informaron de que WhatsApp aceptaba bursts de reacciones silenciosas de hasta una sonda cada `50 ms` sin una cola evidente en el servidor. Esto resulta útil para bursts de calibración cortos, conteos rápidos de dispositivos o para acelerar rápidamente un ataque de agotamiento.
* **Colas prolongadas en Signal:** Signal toleraba bursts cortos, pero comenzó a poner en cola el tráfico sostenido de varias sondas por segundo. Para monitorización de larga duración, mantén la cadencia alrededor de `1 Hz` (o inferior) para que cada confirmación siga reflejando el estado actual del dispositivo en lugar de vaciar una cola acumulada.
* **Artefactos de reconexión:** Cuando un dispositivo vuelve a estar online, algunos clientes agrupan o vacían rápidamente varias confirmaciones retrasadas. Trata esos bursts de confirmaciones como un marcador de transición de estado y no como muestras de RTT independientes; de lo contrario, tu clustering o clasificador `active` frente a `idle` se ajustará en exceso al ruido de reconexión.<sup>[[1]](#references)</sup>

## Inferencia de comportamiento a partir de trazas de RTT

1. Muestrea a ≥1 Hz para capturar los efectos de planificación del sistema operativo. Con WhatsApp en iOS, los RTT <1 s se correlacionan fuertemente con la pantalla encendida/foreground, mientras que los >1 s se correlacionan con la pantalla apagada/background y la limitación en segundo plano.
2. Crea clasificadores simples (basados en umbrales o k-means de dos clusters) que etiqueten cada RTT como "active" o "idle". Agrega las etiquetas en rachas para deducir horas de sueño, desplazamientos, horas laborales o cuándo está activo el companion de desktop.
3. Correlaciona sondas simultáneas dirigidas a cada dispositivo para observar cuándo los usuarios cambian del móvil al desktop, cuándo los companions se desconectan y si la app está limitada por push o por un socket persistente.
4. En redes reales, evita un único umbral fijo de `1 s`. Inicializa cada dispositivo con una breve ventana de calentamiento y conserva una línea base móvil (por ejemplo, la PoC device-activity-tracker usa `threshold = 0.9 * median RTT`) para que las variaciones de Wi-Fi/celular no inutilicen tu clasificador.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferencia de ubicación a partir del RTT de entrega

La misma primitiva temporal puede reutilizarse para inferir dónde se encuentra el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar con distribuciones de RTT de ubicaciones conocidas permite al atacante clasificar posteriormente la ubicación de la víctima usando únicamente las confirmaciones de entrega:<sup>[[2]](#references)</sup>

* Crea una línea base para el mismo objetivo mientras se encuentra en varios lugares conocidos (casa, oficina, campus, país A frente a país B, etc.).
* Para cada ubicación, recopila muchos RTT de mensajes normales y extrae características simples como la mediana, la varianza o intervalos percentiles.
* Durante el ataque real, compara la nueva serie de sondas con los clusters entrenados. El artículo informa de que incluso pueden separarse a menudo ubicaciones dentro de la misma ciudad, con una precisión de `>80%` en un escenario de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el entorno del emisor y realiza las sondas bajo condiciones de red similares, porque la ruta medida incluye la red de acceso del destinatario, la latencia de activación y la infraestructura del Messenger.<sup>[[2]](#references)</sup>

A diferencia de los ataques silenciosos de reacción/edición/eliminación anteriores, la inferencia de ubicación no requiere IDs de mensajes inválidos ni paquetes sigilosos que cambien el estado. Los mensajes normales con confirmaciones de entrega normales son suficientes, por lo que la contrapartida es un menor sigilo, pero una aplicabilidad más amplia entre Messengers.

## Agotamiento sigiloso de recursos

Como cada sonda silenciosa debe descifrarse y confirmarse, el envío continuo de alternancias de reacciones, ediciones inválidas o paquetes de eliminación para todos crea un DoS en la capa de aplicación:<sup>[[1]](#references)</sup>

* Obliga a la radio/módem a transmitir/recibir cada segundo → provoca un consumo de batería apreciable, especialmente en terminales inactivos.
* Genera tráfico ascendente/descendente que consume planes de datos móviles y puede competir con funciones sensibles a la latencia, como las videollamadas.<sup>[[1]](#references)</sup>
* Los payloads inválidos añaden trabajo de procesamiento, pero el artículo informa de que la criptografía en sí representa una parte insignificante del coste de batería.<sup>[[1]](#references)</sup>
* En WhatsApp, las reacciones inválidas aceptan muchos más datos de lo que sugiere un emoji normal: las mediciones publicadas encontraron una aceptación por parte del servidor de hasta aproximadamente `1 MB` por reacción.
* Las reacciones sobredimensionadas dejan de producir confirmaciones de entrega fiables cuando el cuerpo supera aproximadamente los `30 bytes`, pero todavía se reenvían y procesan antes de descartarse. Mantén pequeños los cuerpos de las reacciones cuando necesites ACKs; amplíalos solo cuando el objetivo sea agotar recursos o realizar un transporte unidireccional encubierto.
* Las mediciones públicas alcanzaron aproximadamente `3.7 MB/s` (`~13.3 GB/h`) de tráfico de la víctima en este modo.

## References

- [1] [Careless Whisper: Explotación de confirmaciones de entrega silenciosas para monitorizar usuarios en Messengers instantáneos móviles](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracción de ubicaciones de usuarios a partir de Messengers instantáneos móviles](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Página man de signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Cómo bloquear grandes volúmenes de mensajes desconocidos | Centro de ayuda de WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Todos los números son de EE. UU.: abuso a gran escala del descubrimiento de contactos en Messengers móviles](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
