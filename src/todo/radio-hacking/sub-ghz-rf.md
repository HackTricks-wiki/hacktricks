# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Puertas de Garaje

Los abridores de puertas de garaje suelen operar en frecuencias en el rango de 300-190 MHz, siendo las frecuencias más comunes 300 MHz, 310 MHz, 315 MHz y 390 MHz. Este rango de frecuencia se utiliza comúnmente para abridores de puertas de garaje porque está menos congestionado que otras bandas de frecuencia y es menos probable que experimente interferencias de otros dispositivos.

## Puertas de Automóviles

La mayoría de los llaveros de automóviles operan en **315 MHz o 433 MHz**. Estas son ambas frecuencias de radio, y se utilizan en una variedad de aplicaciones diferentes. La principal diferencia entre las dos frecuencias es que 433 MHz tiene un rango más largo que 315 MHz. Esto significa que 433 MHz es mejor para aplicaciones que requieren un rango más largo, como el acceso remoto sin llave.\
En Europa, 433.92MHz se utiliza comúnmente y en EE. UU. y Japón es 315MHz.

## **Ataque de Fuerza Bruta**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Si en lugar de enviar cada código 5 veces (enviado así para asegurarse de que el receptor lo reciba) se envía solo una vez, el tiempo se reduce a 6 minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

y si **elimina el período de espera de 2 ms** entre señales, puede **reducir el tiempo a 3 minutos.**

Además, al usar la Secuencia de De Bruijn (una forma de reducir el número de bits necesarios para enviar todos los números binarios potenciales para la fuerza bruta), este **tiempo se reduce a solo 8 segundos**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Un ejemplo de este ataque fue implementado en [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requerir **un preámbulo evitará la optimización de la Secuencia de De Bruijn** y **los códigos rodantes evitarán este ataque** (suponiendo que el código sea lo suficientemente largo como para no ser susceptible a la fuerza bruta).

## Ataque Sub-GHz

Para atacar estas señales con Flipper Zero, consulte:

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protección de Códigos Rodantes

Los abridores automáticos de puertas de garaje suelen utilizar un control remoto inalámbrico para abrir y cerrar la puerta del garaje. El control remoto **envía una señal de frecuencia de radio (RF)** al abridor de la puerta del garaje, que activa el motor para abrir o cerrar la puerta.

Es posible que alguien use un dispositivo conocido como un code grabber para interceptar la señal RF y grabarla para su uso posterior. Esto se conoce como un **ataque de repetición**. Para prevenir este tipo de ataque, muchos abridores de puertas de garaje modernos utilizan un método de cifrado más seguro conocido como un sistema de **código rodante**.

La **señal RF se transmite típicamente utilizando un código rodante**, lo que significa que el código cambia con cada uso. Esto hace que sea **difícil** para alguien **interceptar** la señal y **utilizarla** para obtener acceso **no autorizado** al garaje.

En un sistema de código rodante, el control remoto y el abridor de la puerta del garaje tienen un **algoritmo compartido** que **genera un nuevo código** cada vez que se utiliza el control remoto. El abridor de la puerta del garaje solo responderá al **código correcto**, lo que dificulta mucho que alguien obtenga acceso no autorizado al garaje solo capturando un código.

### **Ataque de Enlace Perdido**

Básicamente, escuchas el botón y **capturas la señal mientras el control remoto está fuera del alcance** del dispositivo (digamos el automóvil o el garaje). Luego te mueves hacia el dispositivo y **utilizas el código capturado para abrirlo**.

### Ataque de Jamming de Enlace Completo

Un atacante podría **interferir la señal cerca del vehículo o receptor** para que el **receptor no pueda realmente 'escuchar' el código**, y una vez que eso esté sucediendo, puedes simplemente **capturar y reproducir** el código cuando hayas dejado de interferir.

La víctima en algún momento usará las **llaves para cerrar el automóvil**, pero luego el ataque habrá **grabado suficientes códigos de "cerrar puerta"** que, con suerte, podrían ser reenviados para abrir la puerta (puede ser **necesario un cambio de frecuencia** ya que hay automóviles que utilizan los mismos códigos para abrir y cerrar pero escuchan ambos comandos en diferentes frecuencias).

> [!WARNING]
> **La interferencia funciona**, pero es notable, ya que si la **persona que cierra el automóvil simplemente prueba las puertas** para asegurarse de que están cerradas, notaría que el automóvil está desbloqueado. Además, si estuvieran al tanto de tales ataques, incluso podrían escuchar el hecho de que las puertas nunca hicieron el **sonido** de bloqueo o que las **luces** del automóvil nunca parpadearon cuando presionaron el botón de 'bloquear'.

### **Ataque de Captura de Código (también conocido como 'RollJam')**

Esta es una técnica de **interferencia más sigilosa**. El atacante interferirá la señal, de modo que cuando la víctima intente cerrar la puerta, no funcione, pero el atacante **grabará este código**. Luego, la víctima **intenta cerrar el automóvil nuevamente** presionando el botón y el automóvil **grabará este segundo código**.\
Instantáneamente después de esto, el **atacante puede enviar el primer código** y el **automóvil se cerrará** (la víctima pensará que la segunda presión lo cerró). Luego, el atacante podrá **enviar el segundo código robado para abrir** el automóvil (suponiendo que un **código de "cerrar automóvil" también se puede usar para abrirlo**). Puede ser necesario un cambio de frecuencia (ya que hay automóviles que utilizan los mismos códigos para abrir y cerrar pero escuchan ambos comandos en diferentes frecuencias).

El atacante puede **interferir el receptor del automóvil y no su receptor** porque si el receptor del automóvil está escuchando, por ejemplo, en un ancho de banda de 1MHz, el atacante no **interferirá** la frecuencia exacta utilizada por el control remoto, sino **una cercana en ese espectro**, mientras que el **receptor del atacante estará escuchando en un rango más pequeño** donde puede escuchar la señal del control remoto **sin la señal de interferencia**.

> [!WARNING]
> Otras implementaciones vistas en especificaciones muestran que el **código rodante es una porción** del código total enviado. Es decir, el código enviado es una **clave de 24 bits** donde los primeros **12 son el código rodante**, los **8 segundos son el comando** (como bloquear o desbloquear) y los últimos 4 son el **checksum**. Los vehículos que implementan este tipo también son naturalmente susceptibles, ya que el atacante solo necesita reemplazar el segmento del código rodante para poder **usar cualquier código rodante en ambas frecuencias**.

> [!CAUTION]
> Tenga en cuenta que si la víctima envía un tercer código mientras el atacante está enviando el primero, el primer y segundo código serán invalidados.

### Ataque de Jamming de Sonido de Alarma

Al probar un sistema de código rodante de posventa instalado en un automóvil, **enviar el mismo código dos veces** inmediatamente **activó la alarma** y el inmovilizador, proporcionando una única oportunidad de **denegación de servicio**. Irónicamente, el medio para **desactivar la alarma** y el inmovilizador era **presionar** el **control remoto**, proporcionando al atacante la capacidad de **realizar continuamente un ataque de DoS**. O mezclar este ataque con el **anterior para obtener más códigos**, ya que la víctima querría detener el ataque lo antes posible.

## Referencias

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
