# RF Sub-GHz

<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en GitHub.

</details>

## Puertas de Garaje

Los abridores de puertas de garaje suelen operar en frecuencias en el rango de 300-190 MHz, con las frecuencias más comunes siendo 300 MHz, 310 MHz, 315 MHz y 390 MHz. Este rango de frecuencia se utiliza comúnmente para los abridores de puertas de garaje porque está menos congestionado que otras bandas de frecuencia y es menos probable que experimente interferencias de otros dispositivos.

## Puertas de Coche

La mayoría de los mandos a distancia de coches operan en **315 MHz o 433 MHz**. Estas son frecuencias de radio que se utilizan en una variedad de aplicaciones diferentes. La principal diferencia entre las dos frecuencias es que 433 MHz tiene un alcance mayor que 315 MHz. Esto significa que 433 MHz es mejor para aplicaciones que requieren un alcance mayor, como la entrada sin llave remota.\
En Europa se utiliza comúnmente 433.92 MHz y en EE. UU. y Japón es el 315 MHz.

## **Ataque de Fuerza Bruta**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

Si en lugar de enviar cada código 5 veces (enviado de esta manera para asegurarse de que el receptor lo reciba) solo se envía una vez, el tiempo se reduce a 6 minutos:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

y si **se elimina el período de espera de 2 ms** entre las señales, se puede **reducir el tiempo a 3 minutos**.

Además, al utilizar la Secuencia de De Bruijn (una forma de reducir el número de bits necesarios para enviar todos los números binarios potenciales para la fuerza bruta) este **tiempo se reduce a solo 8 segundos**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

Un ejemplo de este ataque fue implementado en [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requerir **un preámbulo evitará la optimización de la Secuencia de De Bruijn** y los **códigos rodantes evitarán este ataque** (suponiendo que el código sea lo suficientemente largo como para no ser fuerza bruta).

## Ataque Sub-GHz

Para atacar estas señales con Flipper Zero, verifica:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protección de Códigos Rodantes

Los abridores automáticos de puertas de garaje suelen utilizar un control remoto inalámbrico para abrir y cerrar la puerta de garaje. El control remoto **envía una señal de radiofrecuencia (RF)** al abridor de la puerta de garaje, que activa el motor para abrir o cerrar la puerta.

Es posible que alguien use un dispositivo conocido como un capturador de códigos para interceptar la señal de RF y grabarla para su uso posterior. Esto se conoce como un **ataque de repetición**. Para evitar este tipo de ataque, muchos abridores modernos de puertas de garaje utilizan un método de cifrado más seguro conocido como un sistema de **código rodante**.

La **señal de RF se transmite típicamente utilizando un código rodante**, lo que significa que el código cambia con cada uso. Esto hace que sea **difícil** para alguien **interceptar** la señal y **usarla** para obtener **acceso no autorizado** al garaje.

En un sistema de código rodante, el control remoto y el abridor de la puerta de garaje tienen un **algoritmo compartido** que **genera un nuevo código** cada vez que se utiliza el control remoto. El abridor de la puerta de garaje solo responderá al **código correcto**, lo que hace mucho más difícil para alguien obtener acceso no autorizado al garaje simplemente capturando un código.

### **Ataque de Enlace Perdido**

Básicamente, escuchas el botón y **capturas la señal mientras el control remoto está fuera del alcance** del dispositivo (como el coche o el garaje). Luego te mueves al dispositivo y **utilizas el código capturado para abrirlo**.

### Ataque de Jamming de Enlace Completo

Un atacante podría **interferir la señal cerca del vehículo o del receptor** para que el **receptor no pueda 'escuchar' el código**, y una vez que eso sucede, simplemente puedes **capturar y reproducir** el código cuando hayas dejado de interferir.

En algún momento, la víctima usará las **llaves para cerrar el coche**, pero luego el ataque habrá **grabado suficientes códigos de "cerrar puerta"** que esperanzadamente podrían ser reenviados para abrir la puerta (podría ser necesaria una **cambio de frecuencia** ya que hay coches que usan los mismos códigos para abrir y cerrar pero escuchan ambos comandos en diferentes frecuencias).

{% hint style="warning" %}
**El Jamming funciona**, pero es notable, ya que si la **persona que cierra el coche simplemente prueba las puertas** para asegurarse de que estén cerradas, notaría que el coche está desbloqueado. Además, si estuviera al tanto de tales ataques, incluso podría escuchar el hecho de que las puertas nunca emitieron el sonido de cierre o que las **luces** del coche nunca parpadearon cuando presionó el botón de ‘cerrar’.
{% endhint %}

### **Ataque de Captura de Código (también conocido como ‘RollJam’)**

Esta es una técnica de Jamming más **sigilosa**. El atacante interferirá la señal, por lo que cuando la víctima intente cerrar la puerta, no funcionará, pero el atacante **grabará este código**. Luego, la víctima **intentará cerrar el coche nuevamente** presionando el botón y el coche **grabará este segundo código**.\
Inmediatamente después, el **atacante puede enviar el primer código** y el **coche se cerrará** (la víctima pensará que el segundo botón lo cerró). Luego, el atacante podrá **enviar el segundo código robado para abrir** el coche (suponiendo que un **código de "cerrar coche" también se pueda usar para abrirlo**). Podría ser necesaria una cambio de frecuencia (ya que hay coches que usan los mismos códigos para abrir y cerrar pero escuchan ambos comandos en diferentes frecuencias).

El atacante puede **interferir el receptor del coche y no su receptor** porque si el receptor del coche está escuchando, por ejemplo, en un ancho de banda de 1 MHz, el atacante no **interferirá** la frecuencia exacta utilizada por el control remoto, sino **una cercana en ese espectro** mientras que el **receptor del atacante estará escuchando en un rango más pequeño** donde puede escuchar la señal del control remoto **sin la señal de interferencia**.

{% hint style="warning" %}
Otras implementaciones vistas en especificaciones muestran que el **código rodante es una parte** del código total enviado. Es decir, el código enviado es una **clave de 24 bits** donde los primeros **12 son el código rodante**, los **segundos 8 son el comando** (como cerrar o abrir) y los últimos 4 son el **checksum**. Los vehículos que implementan este tipo también son naturalmente susceptibles, ya que el atacante simplemente necesita reemplazar el segmento de código rodante para poder **usar cualquier código rodante en ambas frecuencias**.
{% endhint %}

{% hint style="danger" %}
Ten en cuenta que si la víctima envía un tercer código mientras el atacante envía el primero, el primer y segundo código serán invalidados.
{% endhint %}
### Ataque de interferencia de alarma sonora

Al probar contra un sistema de código rodante de posventa instalado en un automóvil, **enviar el mismo código dos veces** inmediatamente **activaba la alarma** y el inmovilizador proporcionando una oportunidad única de **denegación de servicio**. Irónicamente, el medio para **desactivar la alarma** y el inmovilizador era **presionar** el **control remoto**, brindando a un atacante la capacidad de **realizar continuamente un ataque de denegación de servicio**. O combinar este ataque con el **anterior para obtener más códigos** ya que la víctima querría detener el ataque lo antes posible.

## Referencias

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
