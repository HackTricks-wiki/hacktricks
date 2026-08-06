# RF Sub-GHz

{{#include ../../banners/hacktricks-training.md}}

## Puertas de garaje

Los abridores de puertas de garaje suelen operar en el rango de frecuencias de 190-300 MHz, siendo las frecuencias más comunes 300 MHz, 310 MHz, 315 MHz y 390 MHz. Este rango de frecuencias se utiliza habitualmente para los abridores de puertas de garaje porque está menos saturado que otras bandas de frecuencia y es menos probable que experimente interferencias de otros dispositivos.

## Puertas de vehículos

La mayoría de los mandos de los vehículos operan a **315 MHz o 433 MHz**. Ambas son radiofrecuencias y se utilizan en una variedad de aplicaciones diferentes. La principal diferencia entre ambas frecuencias es que 433 MHz tiene un alcance mayor que 315 MHz. Esto significa que 433 MHz es mejor para aplicaciones que requieren un alcance mayor, como la entrada remota sin llave.\
En Europa se utiliza habitualmente 433,92 MHz, mientras que en EE. UU. y Japón se utilizan 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Si, en lugar de enviar cada código 5 veces (se envía así para asegurarse de que el receptor lo recibe), se envía solo una vez, el tiempo se reduce a 6 minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

y si **se elimina el periodo de espera de 2 ms** entre señales, se puede **reducir el tiempo a 3 minutos.**

Además, mediante el uso de la De Bruijn Sequence (una forma de reducir el número de bits necesarios para enviar todos los posibles números binarios mediante fuerza bruta), este **tiempo se reduce a solo 8 segundos**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un ejemplo de este ataque se implementó en [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

La necesidad de un **preamble evitará la optimización de la De Bruijn Sequence**, y los **rolling codes impedirán este ataque** (suponiendo que el código sea lo bastante largo como para que no se pueda aplicar fuerza bruta).

## Sub-GHz Attack

Para atacar estas señales con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protección mediante Rolling Codes

Los abridores automáticos de puertas de garaje suelen utilizar un mando inalámbrico para abrir y cerrar la puerta. El mando **envía una señal de radiofrecuencia (RF)** al abridor de la puerta de garaje, que activa el motor para abrir o cerrar la puerta.

Es posible que alguien utilice un dispositivo conocido como code grabber para interceptar la señal RF y grabarla para usarla posteriormente. Esto se conoce como **replay attack**. Para prevenir este tipo de ataque, muchos abridores modernos de puertas de garaje utilizan un método de cifrado más seguro conocido como sistema de **rolling code**.

La **señal RF se transmite normalmente mediante un rolling code**, lo que significa que el código cambia con cada uso. Esto dificulta que alguien pueda **interceptar** la señal y **utilizarla** para obtener acceso **no autorizado** al garaje.

En un sistema de rolling code, el mando y el abridor de la puerta de garaje tienen un **algoritmo compartido** que **genera un código nuevo** cada vez que se utiliza el mando. El abridor de la puerta de garaje solo responderá al **código correcto**, lo que dificulta mucho que alguien obtenga acceso no autorizado al garaje simplemente capturando un código.

### **Missing Link Attack**

Básicamente, se escucha cuándo se pulsa el botón y se **captura la señal mientras el mando está fuera del alcance** del dispositivo (por ejemplo, del vehículo o del garaje). Después, uno se desplaza hasta el dispositivo y **utiliza el código capturado para abrirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Un atacante podría **bloquear la señal cerca del vehículo o del receiv**er para que el **receptor no pueda realmente «escuchar» el código** y, cuando esto esté ocurriendo, simplemente puede **capturar y reproducir** el código cuando deje de bloquear la señal.<sup>[[2]](#references)</sup>

En algún momento, la víctima utilizará las **llaves para cerrar el vehículo**, pero para entonces el ataque habrá **grabado suficientes códigos de «cerrar puerta»** que, con suerte, se podrán reenviar para abrir la puerta (podría ser necesario **cambiar de frecuencia**, ya que hay vehículos que utilizan los mismos códigos para abrir y cerrar, pero escuchan ambos comandos en frecuencias diferentes).

> [!WARNING]
> **El jamming funciona**, pero es detectable: si la **persona que cierra el vehículo simplemente comprueba las puertas** para asegurarse de que están cerradas, notaría que el vehículo sigue abierto. Además, si conociera este tipo de ataques, podría incluso darse cuenta de que las puertas nunca emitieron el **sonido** de cierre ni las **luces** del vehículo parpadearon al pulsar el botón de «cerrar».

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Esta es una técnica de **jamming más sigilosa**. El atacante bloqueará la señal, de modo que cuando la víctima intente cerrar la puerta no funcionará, pero el atacante **grabará este código**. Después, la víctima **intentará cerrar el vehículo de nuevo** pulsando el botón, y el vehículo **grabará este segundo código**.<sup>[[2]](#references)[[4]](#references)</sup>\
Inmediatamente después, el **atacante puede enviar el primer código** y el **vehículo se cerrará** (la víctima pensará que el segundo intento lo cerró). Entonces, el atacante podrá **enviar el segundo código robado para abrir** el vehículo (suponiendo que un **código de «cerrar vehículo» también pueda utilizarse para abrirlo**). Podría ser necesario cambiar de frecuencia (ya que hay vehículos que utilizan los mismos códigos para abrir y cerrar, pero escuchan ambos comandos en frecuencias diferentes).

El atacante puede **bloquear el receptor del vehículo, pero no su propio receptor**, porque si el receptor del vehículo está escuchando, por ejemplo, en un ancho de banda de 1 MHz, el atacante no **bloqueará** la frecuencia exacta utilizada por el mando, sino **una cercana dentro de ese espectro**, mientras que el receptor del atacante estará escuchando en un rango menor, donde podrá escuchar la señal del mando **sin la señal de jamming**.

> [!WARNING]
> Otras implementaciones observadas en especificaciones muestran que el **rolling code es solo una parte** del código total enviado. Es decir, el código enviado es una **clave de 24 bits**, donde los primeros **12 son el rolling code**, los siguientes **8 son el comando** (como cerrar o abrir) y los últimos 4 son el **checksum**. Los vehículos que implementan este tipo también son susceptibles de forma natural, ya que el atacante solo necesita reemplazar el segmento del rolling code para poder **utilizar cualquier rolling code en ambas frecuencias**.

> [!CAUTION]
> Ten en cuenta que si la víctima envía un tercer código mientras el atacante está enviando el primero, el primer y el segundo código quedarán invalidados.

### Alarm Sounding Jamming Attack

Al probar un sistema de rolling code instalado posteriormente en un vehículo, **enviar el mismo código dos veces** activó inmediatamente la **alarma** y el inmovilizador, lo que proporcionó una oportunidad única de **denial of service**. Irónicamente, la forma de **desactivar la alarma** y el inmovilizador consistía en **pulsar** el **mando**, lo que proporcionaba al atacante la capacidad de **realizar continuamente un ataque DoS**. También se puede combinar este ataque con el **anterior para obtener más códigos**, ya que la víctima querrá detener el ataque lo antes posible.<sup>[[2]](#references)</sup>

## Referencias

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
