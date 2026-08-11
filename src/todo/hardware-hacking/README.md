# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) permite realizar pruebas de boundary-scan mediante celdas situadas alrededor de los pines de I/O de un dispositivo. Muchos procesadores también exponen funciones de debug específicas del fabricante a través del mismo Test Access Port (TAP); el boundary scan y el debugging de la CPU son usos relacionados de JTAG, no sinónimos.<sup>[[1]](#references)</sup>

El estándar JTAG define **comandos específicos para realizar boundary scans**, incluidos los siguientes:

- **BYPASS** selecciona un registro de bypass de un bit para que se pueda acceder a otros dispositivos de una cadena de scan con una sobrecarga mínima.
- **SAMPLE/PRELOAD** captura los valores de los pines durante el funcionamiento normal y puede precargar el registro de boundary-scan antes de otra instrucción.
- **EXTEST** establece y lee los estados de los pines.

También puede admitir otros comandos, como:

- **IDCODE** para identificar un dispositivo
- **INTEST** para las pruebas internas del dispositivo

Puedes encontrarte con estas instrucciones al utilizar una herramienta como JTAGulator.

### The Test Access Port

El **Test Access Port (TAP)** proporciona acceso a la lógica de pruebas JTAG de un componente. Se requieren cuatro señales y `TRST` es opcional:<sup>[[1]](#references)</sup>

- Entrada de reloj de prueba (**TCK**) TCK es el **reloj** que define con qué frecuencia el controlador TAP realizará una acción individual (en otras palabras, saltará al siguiente estado de la máquina de estados).
- Entrada de selección del modo de prueba (**TMS**) TMS controla la **máquina de estados finitos**. En cada ciclo del reloj, el controlador JTAG TAP del dispositivo comprueba el voltaje del pin TMS. Si el voltaje está por debajo de cierto umbral, la señal se considera baja y se interpreta como 0, mientras que si está por encima de cierto umbral, se considera alta y se interpreta como 1.
- Entrada de datos de prueba (**TDI**) desplaza instrucciones o datos de prueba en serie al registro TAP seleccionado. IEEE 1149.1 define el comportamiento de transferencia del TAP, mientras que los fabricantes definen instrucciones opcionales y registros de debug.
- Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
- Entrada de reset de prueba (**TRST**) La entrada opcional TRST restablece la máquina de estados finitos **a un estado conocido y seguro**. Como alternativa, si TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, se ejecuta un reset, de la misma manera que lo haría el pin TRST, por lo que TRST es opcional.

A veces podrás encontrar esos pines marcados en la PCB. En otras ocasiones tendrás que **encontrarlos**.

### Identifying JTAG pins

Una opción rápida y diseñada específicamente para detectar puertos JTAG, aunque comparativamente cara, es **JTAGulator**, que también puede identificar pinouts de UART.<sup>[[2]](#references)</sup>

Dispone de **24 canales** que se pueden conectar a puntos de prueba de la placa. Enumera combinaciones candidatas de pines mediante scans **IDCODE** y **BYPASS**, e informa de los canales correspondientes a las señales JTAG detectadas.

Una forma más barata, pero mucho más lenta, de identificar pinouts JTAG consiste en utilizar [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Con **JTAGenum**, primero define los pines del microcontrolador de sondeo utilizados para la enumeración. Consulta su pinout y conecta esos pines a puntos de prueba candidatos de la placa objetivo.<sup>[[3]](#references)</sup>

Una **tercera forma** de identificar los pines JTAG consiste en **inspeccionar la PCB** en busca de un footprint conocido. Algunas placas exponen un footprint **Tag-Connect**, aunque Tag-Connect es un sistema de conectores que puede transportar JTAG, SWD, UART u otra interfaz; por sí solo, no demuestra que los pines sean JTAG. Las hojas de datos de los componentes y las mediciones de continuidad pueden identificar entonces las señales reales.<sup>[[5]](#references)</sup>

## SDW

SWD es la interfaz de debug de dos pines y basada en paquetes de Arm.<sup>[[4]](#references)</sup>

La interfaz utiliza **SWDIO** bidireccional para los datos y **SWCLK** para el reloj. Muchos dispositivos implementan un **Serial Wire/JTAG Debug Port (SWJ-DP)** que permite seleccionar entre SWD y JTAG en pines compartidos.<sup>[[4]](#references)</sup>

## References

- [1] [Grupo de trabajo IEEE 1149.1 — JTAG y boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentación de JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumeración de pines JTAG en Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de debug con pocos pines para sistemas con múltiples dispositivos](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints para cables de debug y programación](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
