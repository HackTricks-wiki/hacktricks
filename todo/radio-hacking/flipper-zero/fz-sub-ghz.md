# FZ - Sub-GHz

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Introducción <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero puede **recibir y transmitir frecuencias de radio en el rango de 300-928 MHz** con su módulo incorporado, que puede leer, guardar y emular controles remotos. Estos controles se utilizan para la interacción con puertas, barreras, cerraduras de radio, interruptores de control remoto, timbres inalámbricos, luces inteligentes y más. Flipper Zero puede ayudarte a descubrir si tu seguridad está comprometida.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Hardware Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero tiene un módulo sub-1 GHz incorporado basado en un [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿chip CC1101 y una antena de radio (el alcance máximo es de 50 metros). Tanto el chip CC1101 como la antena están diseñados para operar en frecuencias en las bandas de 300-348 MHz, 387-464 MHz y 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Acciones

### Analizador de Frecuencia

{% hint style="info" %}
Cómo encontrar qué frecuencia está utilizando el control remoto
{% endhint %}

Al analizar, Flipper Zero está escaneando la fuerza de las señales (RSSI) en todas las frecuencias disponibles en la configuración de frecuencia. Flipper Zero muestra la frecuencia con el valor RSSI más alto, con una fuerza de señal superior a -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Para determinar la frecuencia del control remoto, sigue estos pasos:

1. Coloca el control remoto muy cerca a la izquierda de Flipper Zero.
2. Ve a **Menú Principal** **→ Sub-GHz**.
3. Selecciona **Analizador de Frecuencia**, luego presiona y mantén presionado el botón en el control remoto que deseas analizar.
4. Revisa el valor de la frecuencia en la pantalla.

### Leer

{% hint style="info" %}
Encuentra información sobre la frecuencia utilizada (también otra forma de encontrar qué frecuencia se está utilizando)
{% endhint %}

La opción **Leer** **escucha en la frecuencia configurada** en la modulación indicada: 433.92 AM por defecto. Si **encuentra algo** al leer, se muestra **información** en la pantalla. Esta información puede ser utilizada para replicar la señal en el futuro.

Mientras se está utilizando Leer, es posible presionar el **botón izquierdo** y **configurarlo**.\
En este momento tiene **4 modulaciones** (AM270, AM650, FM328 y FM476), y **varias frecuencias relevantes** almacenadas:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Puedes establecer **cualquier frecuencia que te interese**, sin embargo, si **no estás seguro de qué frecuencia** podría ser la utilizada por el control remoto que tienes, **activa el Hopping** (Desactivado por defecto), y presiona el botón varias veces hasta que Flipper la capture y te proporcione la información necesaria para configurar la frecuencia.

{% hint style="danger" %}
Cambiar entre frecuencias lleva algo de tiempo, por lo tanto, las señales transmitidas en el momento del cambio pueden perderse. Para una mejor recepción de la señal, establece una frecuencia fija determinada por el Analizador de Frecuencia.
{% endhint %}

### **Leer en Bruto**

{% hint style="info" %}
Roba (y reproduce) una señal en la frecuencia configurada
{% endhint %}

La opción **Leer en Bruto** **registra las señales** enviadas en la frecuencia de escucha. Esto se puede utilizar para **robar** una señal y **repetirla**.

Por defecto, **Leer en Bruto también está en 433.92 en AM650**, pero si con la opción Leer encontraste que la señal que te interesa está en una **frecuencia/modulación diferente, también puedes modificarla** presionando a la izquierda (mientras estás dentro de la opción Leer en Bruto).

### Fuerza Bruta

Si conoces el protocolo utilizado, por ejemplo, por la puerta del garaje, es posible **generar todos los códigos y enviarlos con el Flipper Zero**. Este es un ejemplo que admite tipos comunes generales de garajes: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Agregar Manualmente

{% hint style="info" %}
Agrega señales de una lista configurada de protocolos
{% endhint %}

#### Lista de [protocolos admitidos](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (funciona con la mayoría de sistemas de códigos estáticos) | 433.92 | Estático |
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
### Fabricantes compatibles con Sub-GHz

Consulte la lista en [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frecuencias admitidas por región

Consulte la lista en [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Prueba

{% hint style="info" %}
Obtener dBm de las frecuencias guardadas
{% endhint %}

## Referencia

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**oficial mercancía de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
