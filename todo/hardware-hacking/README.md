# Hackeo de Hardware

<details>

<summary><strong>Aprende hackeo de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hackeo enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## JTAG

JTAG permite realizar un escaneo de límites. El escaneo de límites analiza ciertos circuitos, incluidas las celdas de escaneo de límites integradas y los registros de cada pin.

El estándar JTAG define **comandos específicos para realizar escaneos de límites**, que incluyen los siguientes:

* **BYPASS** te permite probar un chip específico sin la sobrecarga de pasar por otros chips.
* **SAMPLE/PRELOAD** toma una muestra de los datos que entran y salen del dispositivo cuando está en su modo de funcionamiento normal.
* **EXTEST** establece y lee estados de pines.

También puede admitir otros comandos como:

* **IDCODE** para identificar un dispositivo
* **INTEST** para la prueba interna del dispositivo

Puedes encontrarte con estas instrucciones al usar una herramienta como el JTAGulator.

### El Puerto de Acceso a Pruebas

Los escaneos de límites incluyen pruebas de los cuatro cables del **Puerto de Acceso a Pruebas (TAP)**, un puerto de propósito general que proporciona **acceso a las funciones de soporte de pruebas JTAG** incorporadas en un componente. TAP utiliza las siguientes cinco señales:

* Entrada de reloj de prueba (**TCK**) El TCK es el **reloj** que define con qué frecuencia el controlador TAP tomará una sola acción (en otras palabras, saltará al siguiente estado en la máquina de estados).
* Selección de modo de prueba (**TMS**) de entrada TMS controla la **máquina de estados finitos**. En cada pulso del reloj, el controlador TAP JTAG del dispositivo verifica el voltaje en el pin TMS. Si el voltaje está por debajo de cierto umbral, la señal se considera baja e interpretada como 0, mientras que si el voltaje está por encima de cierto umbral, la señal se considera alta e interpretada como 1.
* Entrada de datos de prueba (**TDI**) TDI es el pin que envía **datos al chip a través de las celdas de escaneo**. Cada fabricante es responsable de definir el protocolo de comunicación sobre este pin, porque JTAG no lo define.
* Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
* Restablecimiento de prueba (**TRST**) de entrada El TRST opcional restablece la máquina de estados finitos **a un estado conocido bueno**. Alternativamente, si el TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, invoca un restablecimiento, de la misma manera que lo haría el pin TRST, razón por la cual TRST es opcional.

A veces podrás encontrar esos pines marcados en la PCB. En otras ocasiones es posible que necesites **encontrarlos**.

### Identificación de pines JTAG

La forma más rápida pero más costosa de detectar puertos JTAG es utilizando el **JTAGulator**, un dispositivo creado específicamente para este propósito (aunque también puede **detectar disposiciones de pines UART**).

Tiene **24 canales** a los que puedes conectar los pines de las placas. Luego realiza un **ataque BF** de todas las combinaciones posibles enviando comandos de escaneo de límites **IDCODE** y **BYPASS**. Si recibe una respuesta, muestra el canal correspondiente a cada señal JTAG.

Una forma más barata pero mucho más lenta de identificar disposiciones de pines JTAG es utilizando el [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Usando **JTAGenum**, primero **definirías los pines del dispositivo de prueba** que usarás para la enumeración. Deberás hacer referencia al diagrama de disposición de pines del dispositivo y luego conectar estos pines con los puntos de prueba en tu dispositivo objetivo.

Una **tercera forma** de identificar pines JTAG es **inspeccionando la PCB** en busca de una de las disposiciones de pines. En algunos casos, las PCB pueden proporcionar convenientemente la **interfaz Tag-Connect**, que es una clara indicación de que la placa tiene un conector JTAG también. Puedes ver cómo es esa interfaz en [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Además, inspeccionar las **hojas de datos de los conjuntos de chips en la PCB** podría revelar diagramas de disposición de pines que apunten a interfaces JTAG.

## SDW

SWD es un protocolo específico de ARM diseñado para la depuración.

La interfaz SWD requiere **dos pines**: una señal bidireccional **SWDIO**, que es el equivalente de los pines **TDI y TDO de JTAG y un reloj**, y **SWCLK**, que es el equivalente de **TCK** en JTAG. Muchos dispositivos admiten el **Puerto de Depuración de Serie o JTAG (SWJ-DP)**, una interfaz combinada de JTAG y SWD que te permite conectar tanto una sonda SWD como JTAG al objetivo.

<details>

<summary><strong>Aprende hackeo de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hackeo enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
