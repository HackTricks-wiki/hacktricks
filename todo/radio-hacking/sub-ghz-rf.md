# RF Sub-GHz

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Puertas de Garaje

Los abridores de puertas de garaje típicamente operan en rangos de frecuencia de 300-190 MHz, siendo las frecuencias más comunes 300 MHz, 310 MHz, 315 MHz y 390 MHz. Este rango de frecuencia se utiliza comúnmente para abridores de puertas de garaje porque está menos saturado que otras bandas de frecuencia y es menos probable que experimente interferencias de otros dispositivos.

## Puertas de Coches

La mayoría de los mandos a distancia de coches operan en **315 MHz o 433 MHz**. Ambas son frecuencias de radio y se utilizan en una variedad de aplicaciones diferentes. La principal diferencia entre las dos frecuencias es que 433 MHz tiene un alcance más largo que 315 MHz. Esto significa que 433 MHz es mejor para aplicaciones que requieren un mayor alcance, como la entrada sin llave a distancia.\
En Europa se utiliza comúnmente 433.92MHz y en EE.UU. y Japón es 315MHz.

## **Ataque de Fuerza Bruta**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Si en lugar de enviar cada código 5 veces (se envía así para asegurarse de que el receptor lo reciba) se envía solo una vez, el tiempo se reduce a 6 minutos:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

y si **eliminas el periodo de espera de 2 ms** entre señales puedes **reducir el tiempo a 3 minutos.**

Además, utilizando la Secuencia de De Bruijn (una forma de reducir el número de bits necesarios para enviar todos los números binarios posibles para fuerza bruta) este **tiempo se reduce a solo 8 segundos**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Ejemplo de este ataque fue implementado en [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requerir **un preámbulo evitará la optimización de la Secuencia de De Bruijn** y **los códigos rodantes evitarán este ataque** (suponiendo que el código sea lo suficientemente largo como para no ser vulnerado por fuerza bruta).

## Ataque RF Sub-GHz

Para atacar estas señales con Flipper Zero revisa:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protección de Códigos Rodantes

Los abridores automáticos de puertas de garaje típicamente usan un control remoto inalámbrico para abrir y cerrar la puerta del garaje. El control remoto **envía una señal de frecuencia de radio (RF)** al abridor de la puerta del garaje, que activa el motor para abrir o cerrar la puerta.

Es posible que alguien utilice un dispositivo conocido como capturador de códigos para interceptar la señal RF y grabarla para su uso posterior. Esto se conoce como un **ataque de repetición**. Para prevenir este tipo de ataque, muchos abridores modernos de puertas de garaje utilizan un método de encriptación más seguro conocido como sistema de **códigos rodantes**.

La **señal RF se transmite típicamente usando un código rodante**, lo que significa que el código cambia con cada uso. Esto hace que sea **difícil** para alguien **interceptar** la señal y **usarla** para obtener acceso **no autorizado** al garaje.

En un sistema de códigos rodantes, el control remoto y el abridor de la puerta del garaje tienen un **algoritmo compartido** que **genera un nuevo código** cada vez que se utiliza el mando. El abridor de la puerta del garaje solo responderá al **código correcto**, lo que hace que sea mucho más difícil para alguien obtener acceso no autorizado al garaje simplemente capturando un código.

### **Ataque de Enlace Perdido**

Básicamente, escuchas el botón y **capturas la señal mientras el mando está fuera del alcance** del dispositivo (digamos el coche o el garaje). Luego te mueves al dispositivo y **usas el código capturado para abrirlo**.

### Ataque de Interferencia de Enlace Completo

Un atacante podría **interferir la señal cerca del vehículo o receptor** para que el **receptor no pueda 'escuchar' el código**, y una vez que eso suceda, simplemente puedes **capturar y repetir** el código cuando hayas dejado de interferir.

La víctima en algún momento usará las **llaves para cerrar el coche**, pero entonces el ataque habrá **grabado suficientes códigos de "cerrar puerta"** que esperanzadamente podrían ser reenviados para abrir la puerta (un **cambio de frecuencia podría ser necesario** ya que hay coches que usan los mismos códigos para abrir y cerrar pero escuchan ambos comandos en diferentes frecuencias).

{% hint style="warning" %}
**La interferencia funciona**, pero es notable ya que si la **persona que cierra el coche simplemente prueba las puertas** para asegurarse de que están cerradas notaría el coche desbloqueado. Además, si estuvieran conscientes de tales ataques podrían incluso escuchar el hecho de que las puertas nunca hicieron el sonido de **cierre** o las **luces** del coche nunca parpadearon cuando presionaron el botón de 'cerrar'.
{% endhint %}

### **Ataque de Captura de Código (también conocido como 'RollJam')**

Esta es una técnica de interferencia más **sigilosa**. El atacante interferirá la señal, así que cuando la víctima intente cerrar la puerta no funcionará, pero el atacante **grabará este código**. Luego, la víctima intentará **cerrar el coche de nuevo** presionando el botón y el coche **grabará este segundo código**.\
Inmediatamente después de esto el **atacante puede enviar el primer código** y el **coche se cerrará** (la víctima pensará que el segundo presionado lo cerró). Entonces, el atacante podrá **enviar el segundo código robado para abrir** el coche (suponiendo que un **código de "cerrar coche" también se pueda usar para abrirlo**). Podría ser necesario un cambio de frecuencia (ya que hay coches que usan los mismos códigos para abrir y cerrar pero escuchan ambos comandos en diferentes frecuencias).

El atacante puede **interferir el receptor del coche y no su receptor** porque si el receptor del coche está escuchando por ejemplo un ancho de banda de 1MHz, el atacante no **interferirá** la frecuencia exacta utilizada por el mando sino **una cercana en ese espectro** mientras el **receptor del atacante estará escuchando en un rango más pequeño** donde puede escuchar la señal del mando **sin la señal de interferencia**.

{% hint style="warning" %}
Otras implementaciones vistas en especificaciones muestran que el **código rodante es una porción** del código total enviado. Es decir, el código enviado es una **llave de 24 bits** donde los primeros **12 son el código rodante**, los **siguientes 8 son el comando** (como cerrar o abrir) y los últimos 4 son el **checksum**. Los vehículos que implementan este tipo también son susceptibles naturalmente ya que el atacante simplemente necesita reemplazar el segmento del código rodante para poder **usar cualquier código rodante en ambas frecuencias**.
{% endhint %}

{% hint style="danger" %}
Nota que si la víctima envía un tercer código mientras el atacante está enviando el primero, el primer y segundo código serán invalidados.
{% endhint %}

### Ataque de Interferencia con Alarma Sonando

Probando contra un sistema de códigos rodantes de posventa instalado en un coche, **enviar el mismo código dos veces** inmediatamente **activó la alarma** e inmovilizador proporcionando una oportunidad única de **denegación de servicio**. Irónicamente, el medio para **desactivar la alarma** e inmovilizador era **presionar** el **mando a distancia**, proporcionando a un atacante la capacidad de **realizar continuamente un ataque de DoS**. O mezclar este ataque con el **anterior para obtener más códigos** ya que la víctima querría detener el ataque lo antes posible.

## Referencias

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
