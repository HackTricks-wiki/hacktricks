# Ataques de canal lateral mediante recibos de entrega en mensajeros E2EE

{{#include ../banners/hacktricks-training.md}}

Los recibos de entrega son obligatorios en los mensajeros modernos con cifrado de extremo a extremo (E2EE), porque los clientes necesitan saber cuándo se descifró un texto cifrado para poder descartar el estado de ratcheting y las claves efímeras. El servidor reenvía blobs opacos, por lo que el destinatario emite confirmaciones del dispositivo (dobles marcas de verificación) tras descifrar correctamente. Medir el tiempo de ida y vuelta (RTT) entre una acción iniciada por el atacante y el recibo de entrega correspondiente expone un canal temporal de alta resolución que hace leak del estado del dispositivo y de la presencia en línea, y que puede usarse para un DoS encubierto. Las implementaciones multidispositivo de tipo "client-fanout" amplifican el leak, porque cada dispositivo registrado descifra la sonda y devuelve su propio recibo.<sup>[[1]](#references)</sup>

## Fuentes de recibos de entrega frente a señales visibles para el usuario

Elige tipos de mensaje que siempre generen un recibo de entrega, pero que no dejen rastros visibles en la interfaz de la víctima. La siguiente tabla resume el comportamiento confirmado empíricamente:<sup>[[1]](#references)</sup>

| Mensajero | Acción | Recibo de entrega | Notificación a la víctima | Notas |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Mensaje de texto | ● | ● | Siempre genera ruido → solo sirve para establecer el estado inicial. |
| | Reacción | ● | ◐ (solo si se reacciona a un mensaje de la víctima) | Las reacciones propias y las eliminaciones pasan inadvertidas. |
| | Edición | ● | Push silencioso, según la plataforma | La ventana de edición es de ≈20 min; aun así, se confirma después de que expire. |
| | Eliminar para todos | ● | ○ | La interfaz permite hacerlo durante ~60 h, pero los paquetes posteriores siguen recibiendo confirmación. |
| **Signal** | Mensaje de texto | ● | ● | Las mismas limitaciones que en WhatsApp. |
| | Reacción | ● | ◐ | Las reacciones propias son invisibles para la víctima. |
| | Editar/Eliminar | ● | ○ | El servidor impone una ventana de ~48 h y permite hasta 10 ediciones, pero los paquetes tardíos siguen recibiendo confirmación. |
| **Threema** | Mensaje de texto | ● | ● | Los recibos multidispositivo se agregan, así que solo se ve un RTT por sonda. |

Leyenda: ● = siempre, ◐ = condicional, ○ = nunca. El comportamiento de la interfaz, según la plataforma, se indica en línea. Si es necesario, desactiva los recibos de lectura, pero los recibos de entrega no se pueden desactivar en WhatsApp ni en Signal.<sup>[[1]](#references)</sup>

## Objetivos y modelos del atacante

* **G1 – Fingerprinting de dispositivos:** Cuenta cuántos recibos llegan por sonda, agrupa los RTT para inferir el sistema operativo o cliente (Android frente a iOS o escritorio) y observa las transiciones entre conexión y desconexión.
* **G2 – Monitorización del comportamiento:** Trata la serie de RTT de alta frecuencia (≈1 Hz es estable) como una serie temporal e infiere si la pantalla está encendida o apagada, si la aplicación está en primer o segundo plano, los horarios de desplazamiento al trabajo frente a las horas de trabajo, etc.
* **G3 – Agotamiento de recursos:** Mantiene despiertas las radios y CPU de todos los dispositivos de la víctima mediante el envío de sondas silenciosas interminables, agotando la batería y los datos y degradando la calidad de las videollamadas.<sup>[[1]](#references)</sup>

Dos tipos de atacantes bastan para describir la superficie de abuso:<sup>[[1]](#references)</sup>

1. **Acompañante espeluznante:** ya comparte un chat con la víctima y abusa de las reacciones propias, de la eliminación de reacciones o de ediciones/eliminaciones repetidas vinculadas a IDs de mensajes existentes.
2. **Desconocido siniestro:** registra una cuenta desechable y envía reacciones que hacen referencia a IDs de mensajes que nunca existieron en la conversación local; WhatsApp y Signal los descifran y confirman igualmente, aunque la interfaz descarte el cambio de estado, por lo que no hace falta una conversación previa.

## Herramientas para acceder al protocolo en bruto

Usa clientes que expongan suficiente información del protocolo E2EE subyacente para crear paquetes compatibles fuera de las limitaciones de la interfaz y registrar marcas de tiempo precisas; para usar IDs de mensaje arbitrarios, hay que comprobar cada implementación:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidispositivo de WhatsApp Web) documenta el envío y la recepción de recibos de entrega; [Cobalt](https://github.com/Auties00/Cobalt) (API no oficial de Java/Kotlin para Web y móvil) documenta operaciones de mensajes como reaccionar, editar y eliminar. Usa sus APIs documentadas en lugar de asumir que exponen todos los frames internos.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) expone interfaces CLI, JSON-RPC y D-Bus, mientras que [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) es una biblioteca Java para comunicarse con Signal.<sup>[[5]](#references)[[7]](#references)</sup> La sintaxis actual de `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantén `receive` o `daemon` en ejecución para que se sigan procesando las actualizaciones del protocolo.<sup>[[6]](#references)</sup> Ejemplo de alternancia de una reacción propia:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Las mediciones del artículo Careless Whisper descubrieron que los recibos de entrega se sincronizan entre dispositivos, por lo que solo se expone un recibo por mensaje incluso en una configuración multidispositivo.<sup>[[1]](#references)</sup>
* **PoCs listas para usar:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) incluye backends para WhatsApp/Signal, usa por defecto sondas de eliminación silenciosas y etiqueta `active` frente a `standby` con un umbral de mediana móvil (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) es una CLI más ligera, centrada en WhatsApp, con `--delay`, `--concurrent`, exportadores CSV/Prometheus y resultados compatibles con Grafana.<sup>[[9]](#references)</sup> Considera ambas herramientas auxiliares de reconocimiento, no referencias de protocolo; lo importante es lo poco que se necesita programar cuando ya se tiene acceso al cliente en bruto.

Cuando no se dispone de herramientas personalizadas, los clientes oficiales o las herramientas de desarrollador del navegador aún pueden activar acciones silenciosas y exponer los tiempos del tráfico cifrado; las API en bruto eliminan las demoras de la interfaz y permiten operaciones no válidas.<sup>[[1]](#references)</sup>

## Compañero siniestro: bucle de muestreo silencioso

1. Elige cualquier mensaje histórico que hayas enviado en el chat para que la víctima nunca vea cambiar las burbujas de «reacción».
2. Alterna entre un emoji visible y una carga útil de reacción vacía (codificada como `""` en los protobufs de WhatsApp o como `--remove` en signal-cli). Cada transmisión genera un acuse de recibo del dispositivo pese a que no hay ningún cambio en la interfaz para la víctima.
3. Registra la hora de envío y la llegada de cada recibo de entrega. Un bucle de 1 Hz como el siguiente proporciona trazas RTT por dispositivo de forma indefinida:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Como WhatsApp/Signal aceptan actualizaciones de reacciones ilimitadas, el atacante nunca necesita publicar contenido nuevo en el chat ni preocuparse por las ventanas de edición.<sup>[[1]](#references)</sup>

## Extraño misterioso: sondeo de números de teléfono arbitrarios

1. Registra una cuenta nueva de WhatsApp/Signal y obtén las claves de identidad públicas del número objetivo (se hace automáticamente durante la configuración de la sesión).
2. Crea un paquete de reacción que haga referencia a un `message_id` aleatorio que ninguna de las partes haya visto; el artículo informa que tanto WhatsApp como Signal aceptan esas reacciones y aun así generan confirmaciones de entrega.<sup>[[1]](#references)</sup>
3. Envía el paquete aunque no exista ningún hilo. Los dispositivos de la víctima lo descifran, no encuentran el mensaje base, descartan el cambio de estado, pero aun así confirman la recepción del texto cifrado entrante y envían confirmaciones del dispositivo al atacante.
4. Repite el proceso continuamente para crear series de RTT sin una conversación previa ni notificaciones visibles.<sup>[[1]](#references)</sup>

Si primero necesitas descubrir qué números están registrados o quieres recopilar inventarios de dispositivos a escala, combina esto con [oráculos de descubrimiento de contactos / registro](../pentesting-web/registration-vulnerabilities.md) en lugar de adivinar rangos E.164 aleatorios manualmente.

Los trabajos publicados sobre descubrimiento de contactos mostraron por qué esto es importante en la práctica: con tablas precisas de prefijos telefónicos y recursos modestos, los investigadores pudieron consultar aproximadamente el `10%` de los números móviles de EE. UU. en WhatsApp y el `100%` en Signal antes de pasar al sondeo dirigido.<sup>[[11]](#references)</sup> En la práctica, filtrar primero las cuentas activas permite concentrar el presupuesto de sondeos silenciosos en números que realmente descifrarán los paquetes.

Las versiones recientes de WhatsApp también incluyen `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Considéralo un limitador de volumen: la documentación del tracker indica que WhatsApp bloquea los mensajes de alto volumen de cuentas desconocidas, pero no revela el umbral, así que no impide por completo las reacciones de sondeo.<sup>[[8]](#references)</sup>

## Reutilización de ediciones y eliminaciones como disparadores encubiertos

* **Eliminaciones repetidas:** Después de eliminar un mensaje para todos una vez, los paquetes de eliminación posteriores que hagan referencia al mismo `message_id` no tienen ningún efecto en la interfaz, pero todos los dispositivos los descifran y confirman.
* **Operaciones fuera de plazo:** WhatsApp aplica ventanas de ~60 h para eliminar y ~20 min para editar desde la interfaz; Signal aplica una de ~48 h. Los mensajes de protocolo creados fuera de estas ventanas se ignoran silenciosamente en el dispositivo de la víctima, pero se envían confirmaciones, por lo que los atacantes pueden sondear indefinidamente mucho después de que termine la conversación.
* **Payloads no válidos:** El artículo informa que los mensajes no válidos pueden recibir confirmación; el comportamiento exacto ante cuerpos malformados o IDs purgados depende de la implementación, así que haz pruebas antes de confiar en ello.<sup>[[1]](#references)</sup>

## Amplificación y fingerprinting multidispositivo

* En WhatsApp y Signal, cada dispositivo asociado (teléfono, app de escritorio, navegador vinculado) descifra el sondeo de forma independiente y devuelve su propia confirmación. Contar las confirmaciones por sondeo revela el número exacto de dispositivos.<sup>[[1]](#references)</sup>
* Si un dispositivo está desconectado, su confirmación queda en cola y se envía al reconectarse. Por tanto, los intervalos revelan los ciclos de conexión y desconexión e incluso los horarios de desplazamiento (por ejemplo, las confirmaciones del escritorio se interrumpen durante los viajes).
* Las distribuciones de RTT varían según la plataforma y el entorno, porque el sistema operativo, el modelo, el cliente y las condiciones de red afectan al tiempo. Agrupa los RTT (por ejemplo, con k-means sobre características de mediana/varianza) para etiquetarlos como “teléfono Android”, “teléfono iOS”, “escritorio Electron”, etc.
* Como el remitente debe obtener el inventario de claves del destinatario antes de cifrar, el atacante también puede observar cuándo se vinculan dispositivos nuevos; un aumento repentino del número de dispositivos o un nuevo grupo de RTT es un indicador claro.<sup>[[1]](#references)</sup>

**Fingerprint a partir de confirmaciones en cola:** Envía varios sondeos con IDs de mensaje distintos mientras el dispositivo objetivo está desconectado. Cuando se reconecte, relaciona los IDs con las confirmaciones de entrega recibidas y comprueba si llegan por separado o agrupados en una sola confirmación, y si los IDs agrupados conservan o invierten el orden de envío. En los clientes probados, WhatsApp para Android/iOS devolvió confirmaciones de entrega separadas, mientras que Web, Windows y macOS las agrupaban; macOS invertía el orden de los elementos agrupados. Signal Desktop agrupaba las confirmaciones, a diferencia de sus clientes móviles. Esto permite clasificar un cliente que se reconecta incluso cuando las distribuciones de RTT se solapan. No confundas las confirmaciones de entrega con las confirmaciones de lectura, cuyas reglas de agrupamiento son distintas.<sup>[[1]](#references)</sup>

Para un sondeo independiente de WhatsApp que lee las **recargas de prekeys del lado del servidor** sin entregar mensajes, consulta [Canal lateral de agotamiento y recarga de paquetes de prekeys de WhatsApp](whatsapp-prekey-bundle-side-channel.md).

## Frecuencia de muestreo, colas y confirmaciones agrupadas

* **Tolerancia de WhatsApp a ráfagas:** Las mediciones publicadas informaron que WhatsApp aceptaba ráfagas de reacciones silenciosas de hasta un sondeo cada `50 ms` sin una cola evidente del lado del servidor. Esto resulta útil para ráfagas breves de calibración, para contar dispositivos rápidamente o para aumentar con rapidez la intensidad de un ataque de agotamiento.
* **Colas prolongadas en Signal:** Signal toleraba ráfagas breves, pero empezaba a poner en cola el tráfico sostenido de varios sondeos por segundo. Para la monitorización prolongada, mantén la frecuencia alrededor de `1 Hz` (o menos), de modo que cada confirmación siga reflejando el estado actual del dispositivo y no el vaciado de una cola acumulada.
* **Artefactos de reconexión:** Cuando un dispositivo vuelve a conectarse, algunos clientes agrupan o envían rápidamente varias confirmaciones retrasadas. Trata esas ráfagas de confirmaciones como un marcador de cambio de estado y no como muestras de RTT independientes, o tu agrupamiento / clasificador de `active` frente a `idle` se ajustará en exceso al ruido de la reconexión.<sup>[[1]](#references)</sup>

## Inferencia de comportamiento a partir de trazas de RTT

1. Muestrea a ≥1 Hz para capturar los efectos de la planificación del sistema operativo. En WhatsApp para iOS, los RTT de <1 s se correlacionan estrechamente con la pantalla encendida/la app en primer plano, y los de >1 s con la pantalla apagada/la limitación en segundo plano.
2. Crea clasificadores sencillos (basados en umbrales o con k-means de dos grupos) que etiqueten cada RTT como “active” o “idle”. Agrupa las etiquetas en secuencias para deducir horarios de sueño, desplazamientos, horas de trabajo o cuándo está activo el cliente de escritorio vinculado.
3. Correlaciona los sondeos simultáneos dirigidos a cada dispositivo para saber cuándo los usuarios pasan del móvil al escritorio, cuándo se desconectan los dispositivos vinculados y si la app está limitada por push o por un socket persistente.
4. En redes reales, evita un único umbral fijo de `1 s`. Inicializa cada dispositivo con una breve ventana de calentamiento y mantén una referencia móvil (por ejemplo, el PoC device-activity-tracker usa `threshold = 0.9 * median RTT`) para que las variaciones entre Wi-Fi y redes móviles no degraden el clasificador.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferencia de ubicación a partir del RTT de entrega

El mismo mecanismo de temporización puede reutilizarse para inferir dónde está el destinatario, no solo si está activo. El trabajo `Hope of Delivery` mostró que entrenar con distribuciones de RTT de ubicaciones conocidas del receptor permite que un atacante clasifique posteriormente la ubicación de la víctima basándose únicamente en las confirmaciones de entrega:<sup>[[2]](#references)</sup>

* Crea una referencia para el mismo objetivo mientras se encuentra en varios lugares conocidos (casa, oficina, campus, país A frente a país B, etc.).
* Para cada ubicación, recopila muchos RTT de mensajes normales y extrae características sencillas, como la mediana, la varianza o intervalos de percentiles.
* Durante el ataque real, compara la nueva serie de sondeos con los grupos entrenados. El artículo informa que a menudo se pueden distinguir incluso ubicaciones dentro de la misma ciudad, con una precisión de `>80%` en un escenario de 3 ubicaciones.
* Esto funciona mejor cuando el atacante controla el entorno del remitente y realiza los sondeos en condiciones de red similares, porque la ruta medida incluye la red de acceso del destinatario, la latencia de activación y la infraestructura del servicio de mensajería.<sup>[[2]](#references)</sup>

A diferencia de los ataques silenciosos de reacción/edición/eliminación anteriores, la inferencia de ubicación no requiere IDs de mensaje no válidos ni paquetes encubiertos que cambien el estado. Bastan mensajes normales con confirmaciones de entrega estándar, así que el compromiso es un menor sigilo, pero una aplicabilidad más amplia entre servicios de mensajería.

## Agotamiento sigiloso de recursos

Como cada sondeo silencioso debe descifrarse y recibir confirmación, enviar continuamente alternancias de reacciones, ediciones no válidas o paquetes de eliminación para todos provoca un DoS en la capa de aplicación:<sup>[[1]](#references)</sup>

* Obliga a la radio/módem a transmitir y recibir cada segundo → provoca un consumo de batería perceptible, especialmente en teléfonos inactivos.
* Genera tráfico ascendente/descendente que consume los planes de datos móviles y puede competir con funciones sensibles a la latencia, como las videollamadas.<sup>[[1]](#references)</sup>
* Los payloads no válidos de gran tamaño añaden trabajo de procesamiento, pero el artículo informa que la criptografía en sí representa una parte insignificante del consumo de batería.<sup>[[1]](#references)</sup>
* En WhatsApp, las reacciones no válidas aceptan muchos más datos de lo que sugiere un emoji normal: las mediciones publicadas encontraron una aceptación del lado del servidor de hasta aproximadamente `1 MB` por reacción.
* Las reacciones de gran tamaño dejan de producir confirmaciones de entrega fiables cuando el cuerpo supera aproximadamente los `30 bytes`, pero aun así se reenvían y procesan antes de descartarse. Mantén pequeños los cuerpos de las reacciones cuando necesites ACK; auméntalos solo cuando el objetivo sea agotar recursos o realizar un transporte encubierto unidireccional.
* Las mediciones públicas alcanzaron unos `3.7 MB/s` (`~13.3 GB/h`) de tráfico en el dispositivo de la víctima en este modo.



## References

- [1] [Susurro descuidado: explotación de confirmaciones de entrega silenciosas para monitorizar a usuarios en servicios de mensajería instantánea móvil](https://arxiv.org/html/2411.11194v4)
- [2] [Esperanza de entrega: extracción de ubicaciones de usuarios a partir de servicios de mensajería instantánea móvil](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [página man de signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Cómo bloquear grandes volúmenes de mensajes de números desconocidos | Centro de ayuda de WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Todos los números son de EE. UU.: abuso a gran escala del descubrimiento de contactos en servicios de mensajería móvil](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
