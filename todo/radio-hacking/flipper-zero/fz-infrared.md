# FZ - Infrarrojo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para obtener más información sobre cómo funciona el infrarrojo, consulta:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Receptor de Señal IR en Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper utiliza un receptor de señal IR digital TSOP, que **permite interceptar señales de controles remotos IR**. Algunos **teléfonos inteligentes** como Xiaomi, también tienen un puerto IR, pero ten en cuenta que **la mayoría de ellos solo pueden transmitir** señales y son **incapaces de recibirlas**.

El receptor infrarrojo de Flipper es bastante sensible. Incluso puedes **captar la señal** estando **en algún lugar intermedio** entre el control remoto y el televisor. No es necesario apuntar el control remoto directamente al puerto IR de Flipper. Esto es útil cuando alguien está cambiando de canal mientras está cerca del televisor, y tanto tú como Flipper están a cierta distancia.

Como la **decodificación de la señal infrarroja** ocurre en el **lado del software**, Flipper Zero potencialmente admite la **recepción y transmisión de cualquier código de control remoto IR**. En el caso de **protocolos desconocidos** que no se pueden reconocer, **registra y reproduce** la señal cruda exactamente como se recibió.

## Acciones

### Controles Remotos Universales

Flipper Zero se puede utilizar como un **control remoto universal para controlar cualquier televisor, aire acondicionado o centro multimedia**. En este modo, Flipper **realiza un ataque de fuerza bruta** con todos los **códigos conocidos** de todos los fabricantes admitidos **según el diccionario de la tarjeta SD**. No es necesario elegir un control remoto en particular para apagar un televisor de un restaurante.

Basta con presionar el botón de encendido en el modo de Control Remoto Universal, y Flipper **enviará secuencialmente comandos de "Apagar"** de todos los televisores que conoce: Sony, Samsung, Panasonic... y así sucesivamente. Cuando el televisor recibe su señal, reaccionará y se apagará.

Este ataque de fuerza bruta lleva tiempo. Cuanto más grande sea el diccionario, más tiempo llevará terminar. Es imposible saber qué señal reconoció exactamente el televisor, ya que no hay retroalimentación del televisor.

### Aprender un Nuevo Control Remoto

Es posible **capturar una señal infrarroja** con Flipper Zero. Si **encuentra la señal en la base de datos**, Flipper automáticamente **sabrá qué dispositivo es** y te permitirá interactuar con él.\
Si no la encuentra, Flipper puede **almacenar** la **señal** y te permitirá **reproducirla**.

## Referencias

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
