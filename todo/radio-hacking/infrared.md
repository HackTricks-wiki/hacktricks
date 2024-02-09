# Cómo funciona el Infrarrojo <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**La luz infrarroja es invisible para los humanos**. La longitud de onda del IR va desde **0.7 hasta 1000 micrones**. Los controles remotos utilizan una señal IR para la transmisión de datos y operan en el rango de longitud de onda de 0.75 a 1.4 micrones. Un microcontrolador en el control remoto hace que un LED infrarrojo parpadee con una frecuencia específica, convirtiendo la señal digital en una señal IR.

Para recibir señales IR se utiliza un **fotorreceptor**. Este **convierte la luz IR en pulsos de voltaje**, que ya son **señales digitales**. Por lo general, hay un **filtro de luz oscura dentro del receptor**, que permite que **solo pase la longitud de onda deseada** y elimina el ruido.

### Variedad de Protocolos IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Los protocolos IR difieren en 3 factores:

* codificación de bits
* estructura de datos
* frecuencia portadora, a menudo en el rango de 36 a 38 kHz

#### Formas de codificación de bits <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Codificación de Distancia de Pulso**

Los bits se codifican modulando la duración del espacio entre pulsos. El ancho del pulso en sí es constante.

**2. Codificación de Ancho de Pulso**

Los bits se codifican mediante la modulación del ancho del pulso. El ancho del espacio después del estallido del pulso es constante.

**3. Codificación de Fase**

También conocida como codificación Manchester. El valor lógico se define por la polaridad de la transición entre el estallido del pulso y el espacio. "Espacio a estallido de pulso" denota lógica "0", "estallido de pulso a espacio" denota lógica "1".

**4. Combinación de los anteriores y otros exóticos**

{% hint style="info" %}
Existen protocolos IR que **intentan volverse universales** para varios tipos de dispositivos. Los más famosos son RC5 y NEC. Desafortunadamente, los más famosos **no significan los más comunes**. En mi entorno, solo me encontré con dos controles remotos NEC y ninguno de RC5.

A los fabricantes les encanta utilizar sus propios protocolos IR únicos, incluso dentro del mismo rango de dispositivos (por ejemplo, cajas de TV). Por lo tanto, los controles remotos de diferentes empresas y a veces de diferentes modelos de la misma empresa, no pueden funcionar con otros dispositivos del mismo tipo.
{% endhint %}

### Explorando una señal IR

La forma más confiable de ver cómo se ve la señal IR del control remoto es utilizando un osciloscopio. No demodula ni invierte la señal recibida, simplemente la muestra "tal cual". Esto es útil para pruebas y depuración. Mostraré la señal esperada en el ejemplo del protocolo IR NEC.

Por lo general, hay un preámbulo al principio de un paquete codificado. Esto permite al receptor determinar el nivel de ganancia y el fondo. También hay protocolos sin preámbulo, por ejemplo, Sharp.

Luego se transmite la información. La estructura, el preámbulo y el método de codificación de bits son determinados por el protocolo específico.

El protocolo IR **NEC** contiene un comando corto y un código de repetición, que se envía mientras se presiona el botón. Tanto el comando como el código de repetición tienen el mismo preámbulo al principio.

El **comando NEC**, además del preámbulo, consta de un byte de dirección y un byte de número de comando, mediante los cuales el dispositivo comprende qué debe realizarse. Los bytes de dirección y número de comando se duplican con valores inversos, para verificar la integridad de la transmisión. Hay un bit de parada adicional al final del comando.

El **código de repetición** tiene un "1" después del preámbulo, que es un bit de parada.

Para la lógica "0" y "1", NEC utiliza la Codificación de Distancia de Pulso: primero se transmite un estallido de pulso, después hay una pausa, cuya longitud establece el valor del bit.

### Aire Acondicionado

A diferencia de otros controles remotos, **los aires acondicionados no transmiten solo el código del botón presionado**. También **transmiten toda la información** cuando se presiona un botón para asegurar que la **máquina de aire acondicionado y el control remoto estén sincronizados**.\
Esto evitará que una máquina configurada a 20ºC se aumente a 21ºC con un control remoto, y luego cuando se use otro control remoto, que aún tiene la temperatura como 20ºC, para aumentar más la temperatura, la "aumentará" a 21ºC (y no a 22ºC pensando que está en 21ºC).

### Ataques

Puedes atacar el Infrarrojo con Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referencias

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
