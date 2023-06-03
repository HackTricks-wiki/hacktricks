# Infrarrojo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo funciona el infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda del infrarrojo es de **0,7 a 1000 micrones**. Los mandos a distancia utilizan una señal de infrarrojos para la transmisión de datos y operan en el rango de longitud de onda de 0,75 a 1,4 micrones. Un microcontrolador en el mando hace que un LED infrarrojo parpadee con una frecuencia específica, convirtiendo la señal digital en una señal de infrarrojos.

Para recibir señales de infrarrojos se utiliza un **fotoreceptor**. Este **convierte la luz infrarroja en pulsos de voltaje**, que ya son **señales digitales**. Por lo general, hay un **filtro de luz oscura dentro del receptor**, que permite pasar **sólo la longitud de onda deseada** y elimina el ruido.

### Variedad de protocolos de infrarrojos <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos de infrarrojos difieren en 3 factores:

* codificación de bits
* estructura de datos
* frecuencia portadora - a menudo en el rango de 36 a 38 kHz

#### Formas de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificación de distancia de pulso**

Los bits se codifican mediante la modulación de la duración del espacio entre pulsos. El ancho del pulso en sí es constante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Codificación de ancho de pulso**

Los bits se codifican mediante la modulación del ancho del pulso. El ancho del espacio después del estallido de pulso es constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codificación de fase**

También se conoce como codificación de Manchester. El valor lógico se define por la polaridad de la transición entre el estallido de pulso y el espacio. "Espacio a estallido de pulso" denota la lógica "0", "estallido de pulso a espacio" denota la lógica "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinación de los anteriores y otros exóticos**

{% hint style="info" %}
Hay protocolos de infrarrojos que **intentan ser universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Desafortunadamente, lo más famoso **no significa lo más común**. En mi entorno, me encontré con sólo dos mandos NEC y ninguno de RC5.

A los fabricantes les encanta utilizar sus propios protocolos de infrarrojos únicos, incluso dentro del mismo rango de dispositivos (por ejemplo, cajas de TV). Por lo tanto, los mandos a distancia de diferentes empresas y, a veces, de diferentes modelos de la misma empresa, no pueden funcionar con otros dispositivos del mismo tipo.
{% endhint %}

### Explorando una señal de infrarrojos

La forma más fiable de ver cómo se ve la señal de infrarrojos del mando a distancia es utilizar un osciloscopio. No demodula ni invierte la señal recibida, sólo se muestra "tal cual". Esto es útil para pruebas y depuración. Mostraré la señal esperada en el ejemplo del protocolo NEC de infrarrojos.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Por lo general, hay un preámbulo al principio de un paquete codificado. Esto permite al receptor determinar el nivel de ganancia y el fondo. También hay protocolos sin preámbulo, por ejemplo, Sharp.

A continuación se transmite la información. La estructura, el preámbulo y el método de codificación de bits son determinados por el protocolo específico.

El **protocolo NEC de infrarrojos** contiene un comando corto y un código de repetición, que se envía mientras se presiona el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando NEC**, además del preámbulo, consta de un byte de dirección y un byte de número de comando, por el cual el dispositivo entiende lo que debe hacerse. Los bytes de dirección y número de comando se duplican con valores inversos, para comprobar la integridad de la transmisión. Hay un bit de parada adicional al final del comando.

El **código de repetición** tiene un "1" después del preámbulo, que es un bit de parada.

Para la lógica "0" y "1", NEC utiliza la codificación de distancia de pulso: primero se transmite un estallido de pulso, después del cual hay una pausa, cuya longitud establece el valor del bit.

### Acondicionadores de aire

A diferencia de otros mandos a distancia, **los acondicionadores de aire no transmiten sólo el código del botón pulsado**. También **transmiten toda la información** cuando se pulsa un botón para asegurarse de que la **máquina de aire acondicionado y el mando a distancia estén sincronizados**.\
Esto
