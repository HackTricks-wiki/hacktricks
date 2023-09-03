# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en toda tu pila tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introducción <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero puede **recibir y transmitir frecuencias de radio en el rango de 300-928 MHz** con su módulo incorporado, que puede leer, guardar y emular controles remotos. Estos controles se utilizan para la interacción con puertas, barreras, cerraduras de radio, interruptores de control remoto, timbres inalámbricos, luces inteligentes y más. Flipper Zero puede ayudarte a aprender si tu seguridad está comprometida.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero tiene un módulo sub-1 GHz incorporado basado en un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) y una antena de radio (el alcance máximo es de 50 metros). Tanto el chip CC1101 como la antena están diseñados para operar en frecuencias en las bandas de 300-348 MHz, 387-464 MHz y 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Analizador de frecuencia

{% hint style="info" %}
Cómo encontrar qué frecuencia está utilizando el control remoto
{% endhint %}

Al analizar, Flipper Zero está escaneando la intensidad de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una intensidad de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar la frecuencia del control remoto, sigue estos pasos:

1. Coloca el control remoto muy cerca del lado izquierdo de Flipper Zero.
2. Ve a **Menú principal** **→ Sub-GHz**.
3. Selecciona **Analizador de frecuencia**, luego presiona y mantén presionado el botón del control remoto que deseas analizar.
4. Revisa el valor de la frecuencia en la pantalla.

### Leer

{% hint style="info" %}
Encuentra información sobre la frecuencia utilizada (también otra forma de encontrar qué frecuencia se utiliza)
{% endhint %}

La opción **Leer** **escucha en la frecuencia configurada** en la modulación indicada: 433.92 AM de forma predeterminada. Si **se encuentra algo** al leer, se muestra información en la pantalla. Esta información se puede utilizar para replicar la señal en el futuro.

Mientras se utiliza Leer, es posible presionar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Puedes establecer **cualquier frecuencia que te interese**, sin embargo, si no estás seguro de qué frecuencia podría ser la utilizada por el control remoto que tienes, **activa el Hopping (salto de frecuencia) a ON** (desactivado de forma predeterminada) y presiona el botón varias veces hasta que Flipper lo capture y te proporcione la información que necesitas para establecer la frecuencia.

{% hint style="danger" %}
Cambiar entre frecuencias lleva tiempo, por lo tanto, las señales transmitidas en el momento del cambio pueden perderse. Para una mejor recepción de la señal, establece una frecuencia fija determinada por el Analizador de frecuencia.
{% endhint %}

### Leer en bruto

{% hint style="info" %}
Roba (y reproduce) una señal en la frecuencia configurada
{% endhint %}

La opción **Leer en bruto** **registra las señales** enviadas en la frecuencia de escucha. Esto se puede utilizar para **robar** una señal y **repetirla**.

De forma predeterminada, **Leer en bruto también está en 433.92 en AM650**, pero si con la opción Leer encontraste que la señal que te interesa está en una **frecuencia/modulación diferente, también puedes modificarla** presionando el botón izquierdo (mientras estás dentro de la opción Leer en bruto).
### Fuerza Bruta

Si conoces el protocolo utilizado, por ejemplo, por la puerta del garaje, es posible **generar todos los códigos y enviarlos con el Flipper Zero**. Este es un ejemplo que admite los tipos comunes de garajes: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Agregar Manualmente

{% hint style="info" %}
Agregar señales desde una lista configurada de protocolos
{% endhint %}

#### Lista de [protocolos compatibles](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (funciona con la mayoría de los sistemas de códigos estáticos) | 433.92 | Estático |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Estático |
| Nice Flo 24bit\_433                                             | 433.92 | Estático |
| CAME 12bit\_433                                                 | 433.92 | Estático |
| CAME 24bit\_433                                                 | 433.92 | Estático |
| Linear\_300                                                     | 300.00 | Estático |
| CAME TWEE                                                       | 433.92 | Estático |
| Gate TX\_433                                                    | 433.92 | Estático |
| DoorHan\_315                                                    | 315.00 | Dinámico |
| DoorHan\_433                                                    | 433.92 | Dinámico |
| LiftMaster\_315                                                 | 315.00 | Dinámico |
| LiftMaster\_390                                                 | 390.00 | Dinámico |
| Security+2.0\_310                                               | 310.00 | Dinámico |
| Security+2.0\_315                                               | 315.00 | Dinámico |
| Security+2.0\_390                                               | 390.00 | Dinámico |

### Vendedores Sub-GHz compatibles

Ver la lista en [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frecuencias compatibles por región

Ver la lista en [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Prueba

{% hint style="info" %}
Obtener dBms de las frecuencias guardadas
{% endhint %}

## Referencia

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra las vulnerabilidades que más importan para que puedas solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos de amenazas proactivas, encuentra problemas en toda tu infraestructura tecnológica, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
