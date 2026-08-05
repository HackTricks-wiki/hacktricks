# FZ - Infrarrojo

{{#include ../../../banners/hacktricks-training.md}}

## Introducción <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para obtener más información sobre cómo funciona el infrarrojo, consulta:


{{#ref}}
../infrared.md
{{#endref}}

## Receptor de señal IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utiliza un receptor de señal IR digital TSOP, que **permite interceptar señales de mandos a distancia IR**. Hay algunos **smartphones**, como Xiaomi, que también tienen un puerto IR, pero ten en cuenta que **la mayoría solo pueden transmitir** señales y **no pueden recibirlas**.<sup>[[1]](#references)</sup>

El **receptor** infrarrojo de Flipper es **bastante sensible**. Incluso puedes **capturar la señal** mientras permaneces **en algún punto entre** el mando y la TV. No es necesario apuntar directamente el mando al puerto IR de Flipper. Esto resulta útil cuando alguien cambia de canal mientras está cerca de la TV y tanto tú como Flipper estáis a cierta distancia.

Como la **decodificación de la señal infrarroja** ocurre en el lado del **software**, Flipper Zero potencialmente admite la **recepción y transmisión de cualquier código de mando IR**. En el caso de protocolos **desconocidos** que no se puedan reconocer, **graba y reproduce** la señal raw exactamente como se recibió.<sup>[[1]](#references)</sup>

## Acciones

### Mandos universales

Flipper Zero puede utilizarse como un **mando universal para controlar cualquier TV, aire acondicionado o centro multimedia**. En este modo, Flipper **hace bruteforce** de todos los **códigos conocidos** de todos los fabricantes compatibles **según el diccionario de la tarjeta SD**. No necesitas elegir un mando específico para apagar la TV de un restaurante.<sup>[[1]](#references)</sup>

Basta con pulsar el botón de encendido en el modo Universal Remote y Flipper enviará **secuencialmente los comandos "Power Off"** de todas las TV que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando la TV recibe su señal, reaccionará y se apagará.

Este brute-force lleva tiempo. Cuanto mayor sea el diccionario, más tardará en terminar. Es imposible saber qué señal reconoció exactamente la TV, ya que no hay feedback de la TV.

### Aprender un nuevo mando

Es posible **capturar una señal infrarroja** con Flipper Zero. Si **encuentra la señal en la base de datos**, Flipper **sabrá automáticamente qué dispositivo es** y te permitirá interactuar con él.\
Si no la encuentra, Flipper puede **almacenar** la **señal** y permitirá **reproducirla**.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
