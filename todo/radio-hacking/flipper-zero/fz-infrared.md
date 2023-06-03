# FZ - Infrarrojo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para obtener más información sobre cómo funciona el infrarrojo, consulte:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Receptor de señal IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utiliza un receptor de señal IR digital TSOP, que **permite interceptar señales de controles remotos IR**. Hay algunos **teléfonos inteligentes** como Xiaomi, que también tienen un puerto IR, pero tenga en cuenta que **la mayoría de ellos solo pueden transmitir** señales y son **incapaces de recibirlas**.

El receptor infrarrojo de Flipper es bastante sensible. Incluso puede **captar la señal** mientras se encuentra **en algún lugar intermedio** entre el control remoto y el televisor. No es necesario apuntar el control remoto directamente al puerto IR de Flipper. Esto es útil cuando alguien está cambiando de canal mientras está parado cerca del televisor, y tanto usted como Flipper están a cierta distancia.

Como la **decodificación de la señal infrarroja** ocurre en el **lado del software**, Flipper Zero potencialmente admite la **recepción y transmisión de cualquier código de control remoto IR**. En el caso de **protocolos desconocidos** que no se pudieron reconocer, Flipper graba y reproduce la señal cruda exactamente como se recibió.

## Acciones

### Controles remotos universales

Flipper Zero se puede utilizar como un **control remoto universal para controlar cualquier televisor, aire acondicionado o centro multimedia**. En este modo, Flipper **fuerza bruta** todos los **códigos conocidos** de todos los fabricantes compatibles **según el diccionario de la tarjeta SD**. No es necesario elegir un control remoto en particular para apagar un televisor de un restaurante.

Es suficiente con presionar el botón de encendido en el modo de control remoto universal, y Flipper enviará **secuencialmente comandos de "Apagar"** de todos los televisores que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando el televisor recibe su señal, reaccionará y se apagará.

Esta fuerza bruta lleva tiempo. Cuanto más grande sea el diccionario, más tiempo tardará en finalizar. Es imposible saber qué señal exactamente reconoció el televisor ya que no hay retroalimentación del televisor.

### Aprender un nuevo control remoto

Es posible **capturar una señal infrarroja** con Flipper Zero. Si **encuentra la señal en la base de datos**, Flipper automáticamente **sabrá qué dispositivo es** y te permitirá interactuar con él.\
Si no lo hace, Flipper puede **almacenar** la **señal** y te permitirá **reproducirla**.

## Referencias

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
