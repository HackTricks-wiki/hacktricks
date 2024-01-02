# FZ - Sub-GHz

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Introducción <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero puede **recibir y transmitir frecuencias de radio en el rango de 300-928 MHz** con su módulo incorporado, que puede leer, guardar y emular controles remotos. Estos controles se utilizan para interactuar con puertas, barreras, cerraduras de radio, interruptores de control remoto, timbres inalámbricos, luces inteligentes y más. Flipper Zero puede ayudarte a aprender si tu seguridad está comprometida.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero tiene un módulo sub-1 GHz incorporado basado en un [chip CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) y una antena de radio (el alcance máximo es de 50 metros). Tanto el chip CC1101 como la antena están diseñados para operar en frecuencias en las bandas de 300-348 MHz, 387-464 MHz y 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Analizador de Frecuencia

{% hint style="info" %}
Cómo encontrar qué frecuencia está utilizando el control remoto
{% endhint %}

Al analizar, Flipper Zero está escaneando la fuerza de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una fuerza de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar la frecuencia del control remoto, haz lo siguiente:

1. Coloca el control remoto muy cerca de la izquierda de Flipper Zero.
2. Ve al **Menú Principal** **→ Sub-GHz**.
3. Selecciona **Analizador de Frecuencia**, luego presiona y mantén presionado el botón del control remoto que quieres analizar.
4. Revisa el valor de la frecuencia en la pantalla.

### Leer

{% hint style="info" %}
Encuentra información sobre la frecuencia utilizada (también otra forma de encontrar qué frecuencia se usa)
{% endhint %}

La opción **Leer** **escucha en la frecuencia configurada** en la modulación indicada: 433.92 AM por defecto. Si **se encuentra algo** al leer, **se da información** en la pantalla. Esta información podría usarse para replicar la señal en el futuro.

Mientras se usa Leer, es posible presionar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Puedes configurar **cualquiera que te interese**, sin embargo, si **no estás seguro de qué frecuencia** podría ser la utilizada por el control remoto que tienes, **activa Hopping en ON** (desactivado por defecto), y presiona el botón varias veces hasta que Flipper lo capture y te dé la información que necesitas para configurar la frecuencia.

{% hint style="danger" %}
Cambiar entre frecuencias lleva algo de tiempo, por lo tanto, las señales transmitidas en el momento del cambio pueden perderse. Para una mejor recepción de la señal, configura una frecuencia fija determinada por el Analizador de Frecuencia.
{% endhint %}

### **Leer Raw**

{% hint style="info" %}
Robar (y reproducir) una señal en la frecuencia configurada
{% endhint %}

La opción **Leer Raw** **registra señales** enviadas en la frecuencia de escucha. Esto se puede usar para **robar** una señal y **repetirla**.

Por defecto **Leer Raw también está en 433.92 en AM650**, pero si con la opción Leer encontraste que la señal que te interesa está en una **frecuencia/modulación diferente, también puedes modificar eso** presionando a la izquierda (mientras estás dentro de la opción Leer Raw).

### Fuerza Bruta

Si conoces el protocolo utilizado por ejemplo por la puerta del garaje, es posible **generar todos los códigos y enviarlos con el Flipper Zero.** Este es un ejemplo que soporta tipos comunes generales de garajes: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Añadir Manualmente

{% hint style="info" %}
Añadir señales de una lista configurada de protocolos
{% endhint %}

#### Lista de [protocolos soportados](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (funciona con la mayoría de los sistemas de código estático) | 433.92 | Estático  |
| -------------------------------------------------------------------------- | ------ | --------- |
| Nice Flo 12bit\_433                                                        | 433.92 | Estático  |
| Nice Flo 24bit\_433                                                        | 433.92 | Estático  |
| CAME 12bit\_433                                                            | 433.92 | Estático  |
| CAME 24bit\_433                                                            | 433.92 | Estático  |
| Linear\_300                                                                | 300.00 | Estático  |
| CAME TWEE                                                                  | 433.92 | Estático  |
| Gate TX\_433                                                               | 433.92 | Estático  |
| DoorHan\_315                                                               | 315.00 | Dinámico  |
| DoorHan\_433                                                               | 433.92 | Dinámico  |
| LiftMaster\_315                                                            | 315.00 | Dinámico  |
| LiftMaster\_390                                                            | 390.00 | Dinámico  |
| Security+2.0\_310                                                          | 310.00 | Dinámico  |
| Security+2.0\_315                                                          | 315.00 | Dinámico  |
| Security+2.0\_390                                                          | 390.00 | Dinámico  |

### Vendedores Sub-GHz soportados

Revisa la lista en [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frecuencias Soportadas por Región

Revisa la lista en [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Prueba

{% hint style="info" %}
Obtener dBms de las frecuencias guardadas
{% endhint %}

## Referencia

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Encuentra vulnerabilidades que importan más para poder solucionarlas más rápido. Intruder rastrea tu superficie de ataque, realiza escaneos proactivos de amenazas, encuentra problemas en todo tu stack tecnológico, desde APIs hasta aplicaciones web y sistemas en la nube. [**Pruébalo gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) hoy.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
