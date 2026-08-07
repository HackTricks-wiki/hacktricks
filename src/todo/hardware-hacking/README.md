# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG permite realizar un boundary scan. El boundary scan analiza determinados circuitos, incluidas las celdas de boundary scan integradas y los registros de cada pin.

El estándar JTAG define **comandos específicos para realizar boundary scans**, incluidos los siguientes:

- **BYPASS** permite probar un chip específico sin la sobrecarga de pasar por otros chips.
- **SAMPLE/PRELOAD** toma una muestra de los datos que entran y salen del dispositivo cuando se encuentra en su modo de funcionamiento normal.
- **EXTEST** establece y lee los estados de los pines.

También puede admitir otros comandos, como:

- **IDCODE** para identificar un dispositivo
- **INTEST** para realizar pruebas internas del dispositivo

Puedes encontrarte con estas instrucciones al utilizar una herramienta como JTAGulator.

### El Test Access Port

Los boundary scans incluyen pruebas del **Test Access Port (TAP)** de cuatro cables, un puerto de propósito general que proporciona **acceso a las funciones de soporte de pruebas JTAG** integradas en un componente. TAP utiliza las siguientes cinco señales:

- Entrada de reloj de prueba (**TCK**) TCK es el **reloj** que define con qué frecuencia el controlador TAP realizará una acción individual (en otras palabras, saltará al siguiente estado de la máquina de estados).
- Entrada de selección del modo de prueba (**TMS**) TMS controla la **máquina de estados finitos**. En cada ciclo del reloj, el controlador JTAG TAP del dispositivo comprueba el voltaje del pin TMS. Si el voltaje está por debajo de cierto umbral, la señal se considera baja y se interpreta como 0, mientras que, si el voltaje está por encima de cierto umbral, la señal se considera alta y se interpreta como 1.
- **Test data input (**TDI**)** TDI es el pin que envía **datos al chip a través de las celdas de scan**. Cada fabricante es responsable de definir el protocolo de comunicación a través de este pin, porque JTAG no lo define.
- **Test data output (**TDO**)** TDO es el pin que envía **datos fuera del chip**.
- Entrada de reset de prueba (**TRST**) La entrada opcional TRST restablece la máquina de estados finitos **a un estado conocido y funcional**. Como alternativa, si TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, se invoca un reset, igual que haría el pin TRST, por lo que TRST es opcional.

A veces podrás encontrar esos pines marcados en la PCB. En otras ocasiones, tendrás que **encontrarlos**.

### Identificación de pines JTAG

La forma más rápida, pero más cara, de detectar puertos JTAG es utilizar **JTAGulator**, un dispositivo creado específicamente para este propósito (aunque **también puede detectar pinouts UART**).

Dispone de **24 canales** que puedes conectar a los pines de la placa. Después realiza un **ataque BF** con todas las combinaciones posibles, enviando comandos de boundary scan **IDCODE** y **BYPASS**. Si recibe una respuesta, muestra el canal correspondiente a cada señal JTAG.

Una forma más barata, pero mucho más lenta, de identificar pinouts JTAG es utilizar [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Al utilizar **JTAGenum**, primero tendrías que **definir los pines del dispositivo de sondeo** que utilizarás para la enumeración. Tendrías que consultar el diagrama de pinout del dispositivo y, después, conectar estos pines con los puntos de prueba del dispositivo objetivo.

Una **tercera forma** de identificar pines JTAG es **inspeccionar la PCB** en busca de uno de los pinouts. En algunos casos, las PCB pueden proporcionar convenientemente la **interfaz Tag-Connect**, lo que indica claramente que la placa también tiene un conector JTAG. Puedes ver el aspecto de esa interfaz en [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Además, inspeccionar las **hojas de datos de los chipsets de la PCB** podría revelar diagramas de pinout que señalen interfaces JTAG.

## SDW

SWD es un protocolo específico de ARM diseñado para la depuración.

La interfaz SWD requiere **dos pines**: una señal **SWDIO** bidireccional, que es el equivalente de los **pines TDI y TDO de JTAG y de un reloj**, y **SWCLK**, que es el equivalente de **TCK** en JTAG. Muchos dispositivos admiten el **Serial Wire or JTAG Debug Port (SWJ-DP)**, una interfaz combinada JTAG y SWD que permite conectar una sonda SWD o JTAG al objetivo.

{{#include ../../banners/hacktricks-training.md}}
