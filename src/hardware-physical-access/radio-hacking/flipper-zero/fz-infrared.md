# FZ - Infrarrojo

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para más información sobre cómo funciona el infrarrojo, consulta:


{{#ref}}
../infrared.md
{{#endref}}

## Receptor de señal IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero usa un receptor IR demodulador para capturar señales de controles remotos infrarrojos comunes. Algunos teléfonos, incluidos ciertos modelos de Xiaomi, incorporan un transmisor IR, pero la mayoría no puede recibir ni decodificar señales de controles remotos.<sup>[[1]](#references)</sup>

El **receptor infrarrojo** de Flipper es bastante sensible. Incluso puedes **captar la señal** mientras estás **en algún punto entre** el control remoto y el televisor. No es necesario apuntar el control remoto directamente al puerto IR de Flipper. Esto resulta útil cuando alguien cambia de canal cerca del televisor y tanto tú como Flipper están a cierta distancia.

La decodificación del protocolo se realiza mediante software. Los protocolos reconocidos se pueden guardar como comandos decodificados; los protocolos no compatibles se pueden capturar y reproducir como datos de temporización sin procesar, dentro de los límites de frecuencia portadora y temporización del hardware.<sup>[[1]](#references)</sup>

## Acciones

### Controles remotos universales

El modo de control remoto universal de Flipper Zero recorre los comandos conocidos de su base de datos infrarroja para televisores, equipos de audio, proyectores y aires acondicionados compatibles. No se garantiza que controle todos los dispositivos y solo debe usarse con equipos que sean tuyos o que tengas autorización para probar.<sup>[[1]](#references)</sup>

Basta con pulsar el botón de encendido en el modo de control remoto universal para que Flipper envíe **secuencialmente comandos de «Apagar»** para todos los televisores que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando el televisor recibe la señal, responde y se apaga.

Este tipo de fuerza bruta lleva tiempo. Cuanto mayor sea el diccionario, más tardará en completarse. Es imposible saber qué señal reconoció exactamente el televisor, ya que este no proporciona ninguna respuesta.

### Aprender un nuevo control remoto

Flipper Zero puede **capturar una señal infrarroja**. Si reconoce el protocolo y el comando, almacena una representación decodificada; de lo contrario, puede guardar los datos de temporización sin procesar para reproducirlos más adelante.<sup>[[1]](#references)</sup>

## References

- [1] [Tomar el control de televisores con el puerto infrarrojo de Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
