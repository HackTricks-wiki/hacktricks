# FZ - Infrarrojo

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para más información sobre cómo funciona el infrarrojo, consulta:

{{#ref}}
../infrared.md
{{#endref}}

## Receptor de Señal IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utiliza un receptor de señal IR digital TSOP, que **permite interceptar señales de controles remotos IR**. Hay algunos **smartphones** como Xiaomi, que también tienen un puerto IR, pero ten en cuenta que **la mayoría de ellos solo pueden transmitir** señales y son **incapaces de recibirlas**.

El **receptor infrarrojo de Flipper es bastante sensible**. Incluso puedes **captar la señal** mientras te mantienes **en algún lugar entre** el control remoto y el televisor. No es necesario apuntar el control remoto directamente al puerto IR de Flipper. Esto es útil cuando alguien está cambiando de canal mientras está cerca del televisor, y tanto tú como Flipper están a cierta distancia.

Como la **decodificación de la señal infrarroja** ocurre del lado del **software**, Flipper Zero potencialmente soporta la **recepción y transmisión de cualquier código de control remoto IR**. En el caso de protocolos **desconocidos** que no se pueden reconocer, **graba y reproduce** la señal en bruto exactamente como se recibió.

## Acciones

### Controles Remotos Universales

Flipper Zero puede ser utilizado como un **control remoto universal para controlar cualquier televisor, aire acondicionado o centro de medios**. En este modo, Flipper **realiza un ataque de fuerza bruta** a todos los **códigos conocidos** de todos los fabricantes soportados **según el diccionario de la tarjeta SD**. No necesitas elegir un control remoto particular para apagar un televisor en un restaurante.

Basta con presionar el botón de encendido en el modo de Control Remoto Universal, y Flipper **enviará secuencialmente comandos de "Apagar"** de todos los televisores que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando el televisor recibe su señal, reaccionará y se apagará.

Tal ataque de fuerza bruta toma tiempo. Cuanto más grande sea el diccionario, más tiempo tomará terminar. Es imposible averiguar qué señal exactamente reconoció el televisor, ya que no hay retroalimentación del televisor.

### Aprender Nuevo Control Remoto

Es posible **capturar una señal infrarroja** con Flipper Zero. Si **encuentra la señal en la base de datos**, Flipper automáticamente **sabrà qué dispositivo es** y te permitirá interactuar con él.\
Si no lo encuentra, Flipper puede **almacenar** la **señal** y te permitirá **reproducirla**.

## Referencias

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
