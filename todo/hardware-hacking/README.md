<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop).
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


#

# JTAG

JTAG permite realizar un escaneo de límites. El escaneo de límites analiza ciertos circuitos, incluyendo celdas de escaneo de límites y registros para cada pin.

El estándar JTAG define **comandos específicos para realizar escaneos de límites**, incluyendo los siguientes:

* **BYPASS** permite probar un chip específico sin la sobrecarga de pasar por otros chips.
* **SAMPLE/PRELOAD** toma una muestra de los datos que entran y salen del dispositivo cuando está en su modo de funcionamiento normal.
* **EXTEST** establece y lee estados de pines.

También puede admitir otros comandos como:

* **IDCODE** para identificar un dispositivo
* **INTEST** para la prueba interna del dispositivo

Puedes encontrarte con estas instrucciones cuando uses una herramienta como el JTAGulator.

## El Puerto de Acceso de Prueba

Los escaneos de límites incluyen pruebas del puerto de cuatro cables **Test Access Port (TAP)**, un puerto de propósito general que proporciona **acceso a las funciones de soporte de prueba JTAG** incorporadas en un componente. TAP utiliza las siguientes cinco señales:

* Entrada de reloj de prueba (**TCK**) El TCK es el **reloj** que define con qué frecuencia el controlador TAP realizará una sola acción (en otras palabras, saltar al siguiente estado en la máquina de estados).
* Entrada de selección de modo de prueba (**TMS**) TMS controla la **máquina de estados finitos**. En cada latido del reloj, el controlador TAP JTAG del dispositivo verifica el voltaje en el pin TMS. Si el voltaje está por debajo de un cierto umbral, la señal se considera baja e interpretada como 0, mientras que si el voltaje está por encima de un cierto umbral, la señal se considera alta e interpretada como 1.
* Entrada de datos de prueba (**TDI**) TDI es el pin que envía **datos al chip a través de las celdas de escaneo**. Cada proveedor es responsable de definir el protocolo de comunicación sobre este pin, porque JTAG no lo define.
* Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
* Entrada de reinicio de prueba (**TRST**) El TRST opcional reinicia la máquina de estados finitos **a un estado conocido como bueno**. Alternativamente, si el TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, invoca un reinicio, de la misma manera que lo haría el pin TRST, por lo que TRST es opcional.

A veces podrás encontrar esos pines marcados en la PCB. En otras ocasiones podrías necesitar **encontrarlos**.

## Identificación de pines JTAG

La forma más rápida pero más costosa de detectar puertos JTAG es utilizando el **JTAGulator**, un dispositivo creado específicamente para este propósito (aunque también puede **detectar configuraciones de pines UART**).

Tiene **24 canales** que puedes conectar a los pines de las placas. Luego realiza un **ataque BF** de todas las combinaciones posibles enviando comandos de escaneo de límites **IDCODE** y **BYPASS**. Si recibe una respuesta, muestra el canal correspondiente a cada señal JTAG.

Una forma más barata pero mucho más lenta de identificar las configuraciones de pines JTAG es utilizando [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Usando **JTAGenum**, primero **definirías los pines del dispositivo de sondeo** que usarás para la enumeración. Tendrías que referenciar el diagrama de pines del dispositivo y luego conectar estos pines con los puntos de prueba en tu dispositivo objetivo.

Una **tercera forma** de identificar pines JTAG es **inspeccionando la PCB** en busca de una de las configuraciones de pines. En algunos casos, las PCB podrían proporcionar convenientemente la **interfaz Tag-Connect**, lo que es una clara indicación de que la placa también tiene un conector JTAG. Puedes ver cómo es esa interfaz en [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Además, inspeccionar las **hojas de datos de los chipsets en la PCB** podría revelar diagramas de pines que apuntan a interfaces JTAG.

# SDW

SWD es un protocolo específico de ARM diseñado para la depuración.

La interfaz SWD requiere **dos pines**: una señal bidireccional **SWDIO**, que es el equivalente a los pines **TDI y TDO de JTAG y un reloj**, y **SWCLK**, que es el equivalente de **TCK** en JTAG. Muchos dispositivos admiten el **Serial Wire or JTAG Debug Port (SWJ-DP)**, una interfaz combinada de JTAG y SWD que te permite conectar ya sea una sonda SWD o JTAG al objetivo.


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop).
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
