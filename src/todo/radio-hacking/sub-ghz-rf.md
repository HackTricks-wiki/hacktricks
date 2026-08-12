# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Puertas de garaje

Los mandos a distancia de las puertas de garaje utilizan varias asignaciones sub-GHz específicas de cada región y producto. Se encuentran frecuencias como 300, 310, 315, 390 y 433.92 MHz, pero no existe una banda universal de puertas de garaje de “300–190 MHz”. Identifica la etiqueta del objetivo, la región regulatoria y la señal observada antes de transmitir.<sup>[[1]](#references)</sup>

## Puertas de vehículos

Muchos mandos de vehículos utilizan **315 MHz o 433.92 MHz**, y las normativas regionales y el diseño del vehículo influyen en la elección. La frecuencia por sí sola no hace que 433 MHz tenga más alcance que 315 MHz: la potencia de transmisión, la eficiencia de la antena, la modulación, la sensibilidad del receptor, la propagación y las normativas locales también son importantes. En Europa se utiliza habitualmente 433.92 MHz, mientras que 315 MHz es común en Norteamérica y Japón.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

En el sistema de código fijo mostrado, enviar cada código una vez en lugar de cinco reduce el tiempo estimado a seis minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Eliminar la espera de 2 ms entre señales reduce esa demostración a aproximadamente tres minutos.

El uso de una secuencia de De Bruijn para solapar cadenas de bits candidatas reduce el ataque mostrado a aproximadamente ocho segundos cuando el receptor acepta la secuencia continua sin un preámbulo obligatorio ni un reinicio de trama.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementa este ataque contra sistemas de código fijo compatibles.<sup>[[5]](#references)</sup>

Requerir **un preámbulo evitará la optimización de la De Bruijn Sequence** y **los rolling codes impedirán este ataque** (suponiendo que el código sea lo suficientemente largo como para no ser susceptible de bruteforce).

## Sub-GHz Attack

Para atacar estas señales con Flipper Zero, consulta:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Los abridores automáticos de puertas de garaje suelen utilizar un mando inalámbrico para abrir y cerrar la puerta. El mando **envía una señal de radiofrecuencia (RF)** al abridor de la puerta de garaje, que activa el motor para abrirla o cerrarla.

Es posible que alguien utilice un dispositivo conocido como code grabber para interceptar la señal RF y grabarla para usarla posteriormente. Esto se conoce como **replay attack**. Para evitar este tipo de ataque, muchos abridores modernos de puertas de garaje utilizan un método de cifrado más seguro conocido como sistema de **rolling code**.

La **señal RF normalmente se transmite mediante un rolling code**, lo que significa que el código cambia con cada uso. Esto dificulta que alguien pueda **interceptar** la señal y **utilizarla** para obtener acceso **no autorizado** al garaje.

En un sistema de rolling code, el mando y el abridor de la puerta de garaje tienen un **algoritmo compartido** que **genera un código nuevo** cada vez que se utiliza el mando. El abridor de la puerta de garaje solo responderá al **código correcto**, lo que dificulta mucho que alguien obtenga acceso no autorizado al garaje simplemente capturando un código.

### **Missing Link Attack**

Básicamente, escuchas la pulsación del botón y **capturas la señal mientras el mando está fuera del alcance** del dispositivo (por ejemplo, el vehículo o el garaje). Después te desplazas hasta el dispositivo y **utilizas el código capturado para abrirlo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> La interferencia RF intencionada es ilegal en muchas jurisdicciones y puede interrumpir sistemas relevantes para la seguridad. Realiza pruebas de jamming únicamente en un laboratorio autorizado y apantallado, y conforme a la normativa de radio aplicable.<sup>[[6]](#references)</sup>

Un atacante podría **bloquear la señal cerca del vehículo o del receptor** para que el receptor no pueda decodificar el código, capturar por separado la transmisión bloqueada, detener el jamming y después reproducir el código capturado.<sup>[[2]](#references)</sup>

En algún momento, la víctima utilizará las **llaves para cerrar el vehículo**, pero para entonces el ataque habrá **grabado suficientes códigos de "cerrar puerta"** que, con suerte, podrían reenviarse para abrir la puerta (podría ser necesario **cambiar de frecuencia**, ya que hay vehículos que utilizan los mismos códigos para abrir y cerrar, pero escuchan ambos comandos en frecuencias diferentes).

> [!WARNING]
> **El jamming funciona**, pero es perceptible: si la **persona que cierra el vehículo simplemente comprueba las puertas** para asegurarse de que están cerradas, notaría que el vehículo sigue abierto. Además, si conociera este tipo de ataques, podría incluso darse cuenta de que las puertas nunca produjeron el **sonido** de cierre o de que las **luces del vehículo** nunca parpadearon al pulsar el botón de ‘cerrar’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Esta es una técnica de **jamming más sigilosa**. El atacante bloqueará la señal, de modo que cuando la víctima intente cerrar la puerta no funcionará, pero el atacante **grabará este código**. Después, la víctima **intentará cerrar el vehículo de nuevo** pulsando el botón y el vehículo **grabará este segundo código**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Inmediatamente después, el **atacante puede enviar el primer código** y el **vehículo se cerrará** (la víctima pensará que el segundo intento lo cerró). Entonces, el atacante podrá **enviar el segundo código robado para abrir** el vehículo (suponiendo que un código de **"cerrar vehículo" también pueda utilizarse para abrirlo**). Puede ser necesario cambiar de frecuencia (ya que hay vehículos que utilizan los mismos códigos para abrir y cerrar, pero escuchan ambos comandos en frecuencias diferentes).

Una implementación de RollJam aprovecha el ancho de banda del receptor: el jammer transmite lo suficientemente cerca de la portadora del mando como para desensibilizar el receptor más amplio del vehículo, mientras que el receptor más estrecho del atacante permanece centrado en el mando y todavía puede grabar su señal. El desplazamiento exacto y el ancho de banda dependen del hardware objetivo.<sup>[[2]](#references)</sup>

> [!WARNING]
> Otras implementaciones observadas en especificaciones muestran que el **rolling code es una parte** del código total enviado. Es decir, el código enviado es una **clave de 24 bits**, donde los primeros **12 son el rolling code**, los siguientes **8 son el comando** (como cerrar o abrir) y los últimos 4 son la **suma de comprobación**. Los vehículos que implementan este tipo también son naturalmente susceptibles, ya que el atacante solo necesita reemplazar el segmento del rolling code para poder **utilizar cualquier rolling code en ambas frecuencias**.

> [!CAUTION]
> Ten en cuenta que, si la víctima envía un tercer código mientras el atacante está enviando el primero, el primer y el segundo código quedarán invalidados.

### Alarm Sounding Jamming Attack

Al realizar pruebas contra un sistema de rolling code instalado posteriormente en un vehículo, **enviar el mismo código dos veces** **activó inmediatamente la alarma** y el inmovilizador, proporcionando una oportunidad única de **denial of service**. Irónicamente, el método para **desactivar la alarma** y el inmovilizador consistía en **pulsar** el **mando**, lo que proporcionaba al atacante la capacidad de **realizar continuamente un ataque DoS**. También se puede combinar este ataque con el **anterior para obtener más códigos**, ya que la víctima querrá detener el ataque lo antes posible.<sup>[[2]](#references)</sup>

## References

- [1] [Documentación de Flipper Zero - frecuencias Sub-GHz regionales](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Elusión de sistemas Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Cómo hackear un vehículo - recreación de RollJam con YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Código fuente de OpenSesame](https://github.com/samyk/opensesame)
- [6] [Aviso de cumplimiento de la FCC - aplicación contra los jammers](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
