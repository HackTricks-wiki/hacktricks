# FZ - Infrarrojos

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para obtener más información sobre cómo funciona el infrarrojo, consulta:


{{#ref}}
../infrared.md
{{#endref}}

## Receptor de señales IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero utiliza un receptor IR demodulador para capturar señales de mandos a distancia IR comunes. Algunos teléfonos, incluidos ciertos modelos Xiaomi, incorporan un transmisor IR, pero la mayoría no puede recibir ni decodificar señales de mandos a distancia.<sup>[[1]](#references)</sup>

El **receptor infrarrojo de Flipper es bastante sensible**. Incluso puedes **captar la señal** mientras te encuentras **en algún punto entre** el mando y el televisor. No es necesario apuntar directamente el mando al puerto IR de Flipper. Esto resulta útil cuando alguien cambia de canal mientras está cerca del televisor y tanto tú como Flipper os encontráis a cierta distancia.

La decodificación del protocolo se realiza mediante software. Los protocolos reconocidos pueden almacenarse como comandos decodificados; los protocolos no compatibles pueden capturarse y reproducirse como datos de temporización sin procesar, dentro de los límites de frecuencia de portadora y temporización del hardware.<sup>[[1]](#references)</sup>

## Acciones

### Mandos universales

El modo de mando universal de Flipper Zero recorre comandos conocidos de su base de datos infrarroja para televisores, equipos de audio, proyectores y aires acondicionados compatibles. No se garantiza que controle todos los dispositivos y solo debe utilizarse con equipos que poseas o para los que tengas autorización para realizar pruebas.<sup>[[1]](#references)</sup>

Basta con pulsar el botón de encendido en el modo de mando universal para que Flipper **envíe secuencialmente comandos de "Apagar"** de todos los televisores que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando el televisor recibe su señal, reaccionará y se apagará.

Este brute-force requiere tiempo. Cuanto mayor sea el diccionario, más tardará en finalizar. Es imposible saber qué señal reconoció exactamente el televisor, ya que no proporciona ningún feedback.

### Aprender un mando nuevo

Flipper Zero puede **capturar una señal infrarroja**. Si reconoce el protocolo y el comando, almacena una representación decodificada; de lo contrario, puede almacenar los datos de temporización sin procesar para reproducirlos posteriormente.<sup>[[1]](#references)</sup>

## References

- [1] [Tomar el control de televisores con el puerto infrarrojo de Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
