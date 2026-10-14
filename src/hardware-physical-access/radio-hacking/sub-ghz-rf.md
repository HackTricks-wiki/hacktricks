# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Puertas de garaje

Los mandos de puertas de garaje utilizan asignaciones de sub-GHz específicas de cada región y producto. Se encuentran frecuencias como 300, 310, 315, 390 y 433,92 MHz, pero no existe una banda universal de “300–190 MHz” para puertas de garaje. Identifica la etiqueta del objetivo, la región regulatoria y la señal observada antes de transmitir.<sup>[[1]](#references)</sup>

## Puertas de coches

Muchos mandos de llaves de coche utilizan **315 MHz o 433,92 MHz**; la elección depende de las normativas regionales y del diseño del vehículo. La frecuencia por sí sola no hace que 433 MHz tenga más alcance que 315 MHz: también influyen la potencia de transmisión, la eficiencia de la antena, la modulación, la sensibilidad del receptor, la propagación y la normativa local. En Europa se suelen utilizar 433,92 MHz, mientras que 315 MHz es común en Norteamérica y Japón.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

En el sistema de código fijo mostrado, enviar cada código una vez en lugar de cinco reduce el tiempo estimado a seis minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Eliminar la espera de 2 ms entre señales reduce esa demostración a aproximadamente tres minutos.

El uso de una secuencia de De Bruijn para superponer cadenas de bits candidatas reduce el ataque mostrado a aproximadamente ocho segundos, siempre que el receptor acepte la secuencia continua sin requerir un preámbulo ni un reinicio de trama.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementa este ataque contra sistemas compatibles de código fijo.<sup>[[5]](#references)</sup>

Exigir **un preámbulo evita** la optimización de la **secuencia de De Bruijn**, y los **rolling codes impiden este ataque** (suponiendo que el código sea lo bastante largo como para que no se pueda descifrar por fuerza bruta).

## Ataque Sub-GHz

Para atacar estas señales con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Protección mediante Rolling Codes

Los sistemas automáticos de apertura de puertas de garaje suelen utilizar un mando inalámbrico para abrir y cerrar la puerta. El mando **envía una señal de radiofrecuencia (RF)** al sistema de apertura, que activa el motor para abrir o cerrar la puerta.

Alguien podría utilizar un dispositivo conocido como code grabber para interceptar la señal RF y grabarla para usarla más tarde. Esto se conoce como **replay attack**. Para evitar este tipo de ataque, muchos sistemas modernos de apertura de puertas de garaje utilizan un método de cifrado más seguro conocido como sistema de **rolling code**.

La **señal RF suele transmitirse mediante un rolling code**, lo que significa que el código cambia en cada uso. Esto dificulta que alguien pueda **interceptar** la señal y **utilizarla** para obtener **acceso no autorizado** al garaje.

En un sistema de rolling code, el mando y el sistema de apertura de la puerta de garaje tienen un **algoritmo compartido** que **genera un código nuevo** cada vez que se utiliza el mando. El sistema de apertura solo responde al **código correcto**, lo que dificulta mucho que alguien obtenga acceso no autorizado al garaje simplemente capturando un código.

### **Missing Link Attack**

Básicamente, se escucha la pulsación del botón y se **captura la señal mientras el mando está fuera del alcance** del dispositivo (por ejemplo, el coche o el garaje). Después, uno se acerca al dispositivo y **utiliza el código capturado para abrirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> La interferencia RF intencionada es ilegal en muchas jurisdicciones y puede afectar a sistemas relevantes para la seguridad. Realiza pruebas de jamming únicamente en un laboratorio blindado y autorizado, cumpliendo la normativa de radio aplicable.<sup>[[6]](#references)</sup>

Un atacante podría **interferir la señal cerca del vehículo o del receptor** para impedir que el receptor descodifique el código, capturar por separado la transmisión bloqueada, detener la interferencia y, después, reproducir el código capturado.<sup>[[2]](#references)</sup>

En algún momento, la víctima utilizará las **llaves para cerrar el coche**, pero para entonces el ataque habrá **grabado suficientes códigos de “cerrar puerta”** que, con suerte, podrían retransmitirse para abrir la puerta (quizá sea necesario **cambiar de frecuencia**, ya que algunos coches usan los mismos códigos para abrir y cerrar, pero escuchan cada comando en una frecuencia distinta).

> [!WARNING]
> **El jamming funciona**, pero es fácil de notar: si la **persona que cierra el coche simplemente comprueba las puertas** para asegurarse de que están cerradas, se dará cuenta de que el coche está abierto. Además, si conoce este tipo de ataques, podría incluso notar que las puertas no hicieron el **sonido** de cierre o que las **luces** del coche no parpadearon al pulsar el botón de “cerrar”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Esta es una técnica de **jamming más sigilosa**. El atacante interferirá la señal para que, cuando la víctima intente cerrar la puerta, el cierre no funcione, pero el atacante **grabará ese código**. Después, la víctima **volverá a intentar cerrar el coche** pulsando el botón, y el coche **grabará este segundo código**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Inmediatamente después, el **atacante puede enviar el primer código** y el **coche se cerrará** (la víctima creerá que se cerró al pulsar el botón por segunda vez). Entonces, el atacante podrá **enviar el segundo código robado para abrir** el coche (suponiendo que un código de **“cerrar el coche” también pueda usarse para abrirlo**). Quizá sea necesario cambiar de frecuencia (ya que algunos coches usan los mismos códigos para abrir y cerrar, pero escuchan cada comando en una frecuencia distinta).

Una implementación de RollJam aprovecha el ancho de banda del receptor: el jammer transmite lo bastante cerca de la portadora del mando como para insensibilizar el receptor, de mayor ancho de banda, del vehículo, mientras que el receptor más estrecho del atacante permanece centrado en la señal del mando y aún puede grabarla. El desplazamiento exacto y el ancho de banda dependen del hardware objetivo.<sup>[[2]](#references)</sup>

> [!WARNING]
> Otras implementaciones descritas en especificaciones muestran que el **rolling code constituye una parte** del código total enviado. Es decir, el código enviado es una **clave de 24 bits**, donde los primeros **12 bits son el rolling code**, los **siguientes 8 son el comando** (como cerrar o abrir) y los últimos 4 son la **suma de comprobación**. Los vehículos que implementan este tipo de sistema también son vulnerables por diseño, ya que el atacante solo necesita reemplazar el segmento del rolling code para poder **usar cualquier rolling code en ambas frecuencias**.

> [!CAUTION]
> Ten en cuenta que, si la víctima envía un tercer código mientras el atacante está enviando el primero, el primer y el segundo código quedarán invalidados.

### Alarm Sounding Jamming Attack

En una prueba contra un sistema de rolling code de posventa instalado en un coche, **enviar el mismo código dos veces** activó inmediatamente la alarma y el inmovilizador, lo que ofreció una oportunidad única de **denegación de servicio**. Irónicamente, para **desactivar la alarma** y el inmovilizador había que **pulsar** el **mando**, lo que permitía al atacante **repetir continuamente el ataque de DoS**. También se puede combinar este ataque con el **anterior para obtener más códigos**, ya que la víctima querrá detener el ataque cuanto antes.<sup>[[2]](#references)</sup>

## References

- [1] [Documentación de Flipper Zero: frecuencias Sub-GHz regionales](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Cómo eludir sistemas de Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Conduce como si lo hubieras hackeado (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Cómo hackear un coche: recreación de RollJam con YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Código fuente de OpenSesame](https://github.com/samyk/opensesame)
- [6] [Aviso de cumplimiento de la FCC: aplicación de la normativa sobre jammers](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
