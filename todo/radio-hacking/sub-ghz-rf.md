# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Puertas de Garaje

Los abridores de puertas de garaje suelen operar en frecuencias en el rango de 300-190 MHz, siendo las frecuencias más comunes 300 MHz, 310 MHz, 315 MHz y 390 MHz. Este rango de frecuencia se utiliza comúnmente para los abridores de puertas de garaje porque está menos congestionado que otras bandas de frecuencia y es menos probable que experimente interferencias de otros dispositivos.

## Puertas de Coche

La mayoría de los mandos a distancia de los coches funcionan en **315 MHz o 433 MHz**. Estas son frecuencias de radio y se utilizan en una variedad de aplicaciones diferentes. La principal diferencia entre las dos frecuencias es que 433 MHz tiene un alcance más largo que 315 MHz. Esto significa que 433 MHz es mejor para aplicaciones que requieren un alcance más largo, como la entrada sin llave remota.\
En Europa se utiliza comúnmente 433.92 MHz y en Estados Unidos y Japón es 315 MHz.

## **Ataque de Fuerza Bruta**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Si en lugar de enviar cada código 5 veces (enviado de esta manera para asegurarse de que el receptor lo reciba), solo se envía una vez, el tiempo se reduce a 6 minutos:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

y si **se elimina el período de espera de 2 ms** entre las señales, se puede **reducir el tiempo a 3 minutos**.

Además, utilizando la Secuencia de De Bruijn (una forma de reducir el número de bits necesarios para enviar todos los números binarios potenciales para el ataque de fuerza bruta), este **tiempo se reduce a solo 8 segundos**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Un ejemplo de este ataque se implementó en [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requerir **un preámbulo evitará la optimización de la Secuencia de De Bruijn** y los **códigos rodantes evitarán este ataque** (suponiendo que el código sea lo suficientemente largo como para no poder ser atacado por fuerza bruta).

## Ataque Sub-GHz

Para atacar estas señales con Flipper Zero, consulta:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protección de Códigos Rodantes

Los abridores automáticos de puertas de garaje suelen utilizar un control remoto inalámbrico para abrir y cerrar la puerta del garaje. El control remoto **envía una señal de radiofrecuencia (RF)** al abridor de la puerta del garaje, que activa el motor para abrir o cerrar la puerta.

Es posible que alguien utilice un dispositivo conocido como un capturador de códigos para interceptar la señal de RF y grabarla para su uso posterior. Esto se conoce como un **ataque de reproducción**. Para evitar este tipo de ataque, muchos abridores modernos de puertas de garaje utilizan un método de cifrado más seguro conocido como un sistema de **código rodante**.

La **señal de RF se transmite típicamente utilizando un código rodante**, lo que significa que el código cambia con cada uso. Esto hace que sea **difícil** para alguien **interceptar** la señal y **usarla** para obtener acceso **no autorizado** al garaje.

En un sistema de código rodante, el control remoto y el abridor de la puerta del garaje tienen un **algoritmo compartido** que **genera un nuevo código** cada vez que se utiliza el control remoto. El abridor de la puerta del garaje solo responderá al **código correcto**, lo que dificulta mucho que alguien obtenga acceso no autorizado al garaje simplemente capturando un código.

### **Ataque de Enlace Perdido**

Básicamente, escuchas el botón y **capturas la señal mientras el control remoto está fuera del alcance** del dispositivo (por ejemplo, el coche o el garaje). Luego te acercas al dispositivo y **utilizas el código capturado para abrirlo**.

### Ataque de Jamming de Enlace Completo

Un atacante podría **interferir con la señal cerca del vehículo o del receptor** para que el **receptor no pueda "escuchar" el código**, y una vez que eso suceda, simplemente puedes **capturar y reproducir** el código cuando hayas dejado de interferir.

En algún momento, la víctima usará las **llaves para cerrar el coche**, pero luego el ataque habrá **registrado suficientes códigos de "cerrar puerta"** que esperanzadamente podrían ser reenviados para abrir la puerta (podría ser necesario un **cambio de frecuencia** ya que hay coches que utilizan los mismos códigos para abrir y cerrar, pero escuchan ambos comandos en diferentes frecuencias).

{% hint style="warning" %}
El **interferir funciona**, pero es notable, ya que si la **persona que cierra el coche simplemente prueba las puertas** para asegurarse de que están cerradas, se dará cuenta de que el coche está desbloqueado. Además, si estuvieran al tanto de tales ataques, incluso podrían escuchar el hecho de que las puertas nunca hicieron el **sonido** de bloqueo o las **luces** del coche nunca parpadearon cuando presionaron el botón de "bloqueo".
{% endhint %}
### **Ataque de Captura de Código (también conocido como 'RollJam')**

Este es una técnica de **interferencia sigilosa**. El atacante interferirá la señal, de modo que cuando la víctima intente cerrar la puerta, no funcionará, pero el atacante **grabará este código**. Luego, la víctima **intentará cerrar el auto nuevamente** presionando el botón y el auto **grabará este segundo código**.\
Inmediatamente después, el **atacante puede enviar el primer código** y el **auto se cerrará** (la víctima pensará que el segundo intento lo cerró). Luego, el atacante podrá **enviar el segundo código robado para abrir** el auto (suponiendo que un **código de "cerrar auto" también se pueda usar para abrirlo**). Es posible que se necesite un cambio de frecuencia (ya que hay autos que usan los mismos códigos para abrir y cerrar, pero escuchan ambos comandos en diferentes frecuencias).

El atacante puede **interferir el receptor del auto y no su propio receptor** porque si el receptor del auto está escuchando, por ejemplo, en un ancho de banda de 1 MHz, el atacante no **interferirá** la frecuencia exacta utilizada por el control remoto, sino **una cercana en ese espectro**, mientras que el **receptor del atacante estará escuchando en un rango más pequeño** donde puede captar la señal del control remoto **sin la señal de interferencia**.

{% hint style="warning" %}
Otras implementaciones vistas en especificaciones muestran que el **código rodante es una parte** del código total enviado. Es decir, el código enviado es una **clave de 24 bits** donde los primeros **12 son el código rodante**, los siguientes 8 son el **comando** (como bloquear o desbloquear) y los últimos 4 son el **checksum**. Los vehículos que implementan este tipo también son naturalmente susceptibles, ya que el atacante solo necesita reemplazar el segmento del código rodante para poder **usar cualquier código rodante en ambas frecuencias**.
{% endhint %}

{% hint style="danger" %}
Tenga en cuenta que si la víctima envía un tercer código mientras el atacante está enviando el primero, el primer y segundo código serán invalidados.
{% endhint %}

### Ataque de Interferencia con Sonido de Alarma

Probando contra un sistema de código rodante de posventa instalado en un auto, **enviar el mismo código dos veces** activó inmediatamente la alarma y el inmovilizador, proporcionando una oportunidad única de **denegación de servicio**. Irónicamente, la forma de **desactivar la alarma** y el inmovilizador era **presionar** el **control remoto**, lo que brinda al atacante la capacidad de **realizar continuamente un ataque de denegación de servicio**. O combinar este ataque con el **anterior para obtener más códigos**, ya que la víctima querría detener el ataque lo antes posible.

## Referencias

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
