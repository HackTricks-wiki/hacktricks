<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


#

# JTAG

JTAG permite realizar un escaneo de límites. El escaneo de límites analiza ciertos circuitos, incluyendo celdas y registros de escaneo de límites integrados para cada pin.

El estándar JTAG define **comandos específicos para realizar escaneos de límites**, incluyendo los siguientes:

* **BYPASS** permite probar un chip específico sin la sobrecarga de pasar por otros chips.
* **SAMPLE/PRELOAD** toma una muestra de los datos que entran y salen del dispositivo cuando está en su modo de funcionamiento normal.
* **EXTEST** establece y lee los estados de los pines.

También puede admitir otros comandos como:

* **IDCODE** para identificar un dispositivo
* **INTEST** para la prueba interna del dispositivo

Es posible que se encuentre con estas instrucciones cuando se utiliza una herramienta como el JTAGulator.

## El puerto de acceso de prueba

Los escaneos de límites incluyen pruebas de los cuatro cables del **Puerto de Acceso de Prueba (TAP)**, un puerto de propósito general que proporciona **acceso al soporte de prueba JTAG** incorporado en un componente. TAP utiliza las siguientes cinco señales:

* Entrada de reloj de prueba (**TCK**) El TCK es el **reloj** que define con qué frecuencia el controlador TAP tomará una sola acción (en otras palabras, saltará al siguiente estado en la máquina de estados).
* Selección de modo de prueba (**TMS**) entrada TMS controla la **máquina de estados finitos**. En cada golpe del reloj, el controlador TAP JTAG del dispositivo verifica el voltaje en el pin TMS. Si el voltaje está por debajo de cierto umbral, la señal se considera baja e interpretada como 0, mientras que si el voltaje está por encima de cierto umbral, la señal se considera alta e interpretada como 1.
* Entrada de datos de prueba (**TDI**) TDI es el pin que envía **datos al chip a través de las celdas de escaneo**. Cada proveedor es responsable de definir el protocolo de comunicación sobre este pin, porque JTAG no lo define.
* Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
* Restablecimiento de prueba (**TRST**) entrada El TRST opcional restablece la máquina de estados finitos **a un estado conocido bueno**. Alternativamente, si el TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, invoca un restablecimiento, de la misma manera que lo haría el pin TRST, por lo que TRST es opcional.

A veces se podrán encontrar esos pines marcados en la PCB. En otras ocasiones, puede que necesite **encontrarlos**.

## Identificación de pines JTAG

La forma más rápida pero más cara de detectar puertos JTAG es mediante el uso del **JTAGulator**, un dispositivo creado específicamente para este propósito (aunque también puede **detectar los pinouts UART**).

Tiene **24 canales** a los que se pueden conectar los pines de las placas. Luego realiza un **ataque BF** de todas las combinaciones posibles enviando comandos de escaneo de límites **IDCODE** y **BYPASS**. Si recibe una respuesta, muestra el canal correspondiente a cada señal JTAG.

Una forma más barata pero mucho más lenta de identificar los pinouts JTAG es mediante el uso de [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Usando **JTAGenum**, primero **definiría los pines de la sonda** del dispositivo que utilizará para la enumeración. Tendría que hacer referencia al diagrama de asignación de pines del dispositivo y luego conectar estos pines con los puntos de prueba en su dispositivo objetivo.

Una **tercera forma** de identificar los pines JTAG es **inspeccionando la PCB** en busca de uno de los pinouts. En algunos casos, las PCB pueden proporcionar convenientemente la **interfaz Tag-Connect**, que es una clara indicación de que la placa tiene un conector JTAG. Puede ver cómo se ve esa interfaz en [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Además, la inspección de las **hojas de datos de los conjuntos de chips en la PCB** puede revelar diagramas de asignación de pines que apuntan a interfaces JTAG.

# SDW

SWD es un protocolo específico de ARM diseñado para la depuración.

La interfaz SWD requiere **dos pines**: una señal bidireccional **SWDIO**, que es el equivalente de los pines **TDI y TDO de JTAG y un reloj**, y **SWCLK**, que es el equivalente de **TCK en JTAG**. Muchos dispositivos admiten el **Puerto de depuración de serie o JTAG (SWJ-DP)**, una interfaz combinada JTAG y SWD que le permite conectar una sonda SWD o JTAG al objetivo.
