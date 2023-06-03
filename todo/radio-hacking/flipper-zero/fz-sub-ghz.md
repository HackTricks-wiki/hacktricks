# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Comparte tus trucos de hacking enviando PR a los repositorios** [**hacktricks**](https://github.com/carlospolop/hacktricks) **y** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero puede **recibir y transmitir frecuencias de radio en el rango de 300-928 MHz** con su módulo incorporado, que puede leer, guardar y emular controles remotos. Estos controles se utilizan para la interacción con puertas, barreras, cerraduras de radio, interruptores de control remoto, timbres inalámbricos, luces inteligentes y más. Flipper Zero puede ayudarte a aprender si tu seguridad está comprometida.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero tiene un módulo sub-1 GHz incorporado basado en un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) y una antena de radio (el alcance máximo es de 50 metros). Tanto el chip CC1101 como la antena están diseñados para operar en frecuencias en las bandas de 300-348 MHz, 387-464 MHz y 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Analizador de frecuencia

{% hint style="info" %}
Cómo encontrar qué frecuencia está utilizando el control remoto
{% endhint %}

Al analizar, Flipper Zero está escaneando la fuerza de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una fuerza de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar la frecuencia del control remoto, haz lo siguiente:

1. Coloca el control remoto muy cerca de la izquierda de Flipper Zero.
2. Ve a **Menú principal → Sub-GHz**.
3. Selecciona **Analizador de frecuencia**, luego presiona y mantén presionado el botón del control remoto que deseas analizar.
4. Revisa el valor de la frecuencia en la pantalla.

### Leer

{% hint style="info" %}
Encuentra información sobre la frecuencia utilizada (también otra forma de encontrar qué frecuencia se utiliza)
{% endhint %}

La opción **Leer** **escucha en la frecuencia configurada** en la modulación indicada: 433,92 AM por defecto. Si **se encuentra algo** al leer, se muestra **información** en la pantalla. Esta información se puede utilizar para replicar la señal en el futuro.

Mientras se utiliza Leer, es posible presionar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Puedes establecer **cualquier frecuencia que te interese**, sin embargo, si **no estás seguro de qué frecuencia** podría ser la utilizada por el control remoto que tienes, **activa Hopping** (desactivado por defecto) y presiona el botón varias veces hasta que Flipper lo capture y te dé la información que necesitas para establecer la frecuencia.

{% hint style="danger" %}
Cambiar entre frecuencias lleva algún tiempo, por lo tanto, las señales transmitidas en el momento del cambio pueden perderse. Para una mejor recepción de la señal, establece una frecuencia fija determinada por el Analizador de frecuencia.
{% endhint %}

### Leer en bruto

{% hint style="info" %}
Robar (y reproducir) una señal en la frecuencia configurada
{% endhint %}

La opción **Leer en bruto** **registra señales** enviadas en la frecuencia de escucha. Esto se puede utilizar para **robar** una señal y **repetirla**.

Por defecto, **Leer en
