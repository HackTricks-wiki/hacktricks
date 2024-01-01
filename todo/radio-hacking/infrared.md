# Infrarrojo

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo funciona el Infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda del IR es de **0.7 a 1000 micrones**. Los controles remotos domésticos utilizan una señal IR para la transmisión de datos y operan en el rango de longitud de onda de 0.75..1.4 micrones. Un microcontrolador en el control remoto hace que un LED infrarrojo parpadee con una frecuencia específica, convirtiendo la señal digital en una señal IR.

Para recibir señales IR se utiliza un **fotoreceptor**. Este **convierte la luz IR en pulsos de voltaje**, que ya son **señales digitales**. Por lo general, hay un **filtro de luz oscura dentro del receptor**, que permite **solo el paso de la longitud de onda deseada** y elimina el ruido.

### Variedad de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos IR difieren en 3 factores:

* codificación de bits
* estructura de datos
* frecuencia portadora — a menudo en el rango de 36..38 kHz

#### Formas de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificación por Distancia de Pulso**

Los bits se codifican modulando la duración del espacio entre pulsos. La anchura del pulso en sí es constante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Codificación por Anchura de Pulso**

Los bits se codifican mediante la modulación de la anchura del pulso. La anchura del espacio después de la ráfaga de pulsos es constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codificación de Fase**

También se conoce como codificación Manchester. El valor lógico se define por la polaridad de la transición entre la ráfaga de pulsos y el espacio. "Espacio a ráfaga de pulso" denota lógica "0", "ráfaga de pulso a espacio" denota lógica "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinación de los anteriores y otras exóticas**

{% hint style="info" %}
Hay protocolos IR que **intentan ser universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Desafortunadamente, el más famoso **no significa el más común**. En mi entorno, solo encontré dos controles remotos NEC y ninguno RC5.

Los fabricantes adoran usar sus propios protocolos IR únicos, incluso dentro de la misma gama de dispositivos (por ejemplo, cajas de TV). Por lo tanto, los controles remotos de diferentes compañías y a veces de diferentes modelos de la misma compañía, no pueden trabajar con otros dispositivos del mismo tipo.
{% endhint %}

### Explorando una señal IR

La forma más fiable de ver cómo es la señal IR de un control remoto es usar un osciloscopio. No demodula ni invierte la señal recibida, simplemente se muestra "tal cual". Esto es útil para pruebas y depuración. Mostraré la señal esperada en el ejemplo del protocolo IR NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Por lo general, hay un preámbulo al principio de un paquete codificado. Esto permite al receptor determinar el nivel de ganancia y el fondo. También hay protocolos sin preámbulo, por ejemplo, Sharp.

Luego se transmite la información. La estructura, el preámbulo y el método de codificación de bits están determinados por el protocolo específico.

El **protocolo IR NEC** contiene un comando corto y un código de repetición, que se envía mientras se presiona el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando NEC**, además del preámbulo, consta de un byte de dirección y un byte de número de comando, por el cual el dispositivo entiende qué se debe realizar. Los bytes de dirección y número de comando se duplican con valores inversos, para verificar la integridad de la transmisión. Hay un bit de parada adicional al final del comando.

El **código de repetición** tiene un "1" después del preámbulo, que es un bit de parada.

Para **lógica "0" y "1"** NEC utiliza Codificación por Distancia de Pulso: primero, se transmite una ráfaga de pulsos después de la cual hay una pausa, su longitud establece el valor del bit.

### Aire Acondicionado

A diferencia de otros controles remotos, **los aires acondicionados no transmiten solo el código del botón presionado**. También **transmiten toda la información** cuando se presiona un botón para asegurar que la **máquina de aire acondicionado y el control remoto estén sincronizados**.\
Esto evitará que una máquina configurada a 20ºC aumente a 21ºC con un control remoto, y luego cuando se use otro control remoto, que todavía tiene la temperatura a 20ºC, se use para aumentar más la temperatura, la "aumentará" a 21ºC (y no a 22ºC pensando que está en 21ºC).

### Ataques

Puedes atacar Infrarrojo con Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referencias

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
