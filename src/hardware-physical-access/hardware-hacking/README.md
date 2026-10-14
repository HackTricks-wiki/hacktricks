# Hacking de hardware

{{#include ../../banners/hacktricks-training.md}}

Para un dispositivo al que tienes acceso físico, empieza por las interfaces expuestas por su placa o sus señales: [consolas seriales UART](uart.md), [acceso de depuración JTAG/SWD](jtag.md), buses [I²C](i2c.md) y [flash SPI](spi.md). El [análisis de canales laterales](side_channel_analysis.md) y la [inyección de fallos](fault_injection_attacks.md) abordan distintas tareas de medición y glitching; el [análisis de señales de radio](radio.md) cubre un punto de entrada inalámbrico. Antes de conectar herramientas, comprueba los niveles eléctricos del objetivo y las limitaciones indicadas en el capítulo correspondiente.

## JTAG

JTAG (IEEE 1149.1) permite realizar pruebas de boundary scan mediante celdas situadas alrededor de los pines de E/S de un dispositivo. Muchos procesadores también exponen funciones de depuración específicas del fabricante a través del mismo Test Access Port (TAP); el boundary scan y la depuración de CPU son usos relacionados de JTAG, no sinónimos.<sup>[[1]](#references)</sup>

El estándar JTAG define **comandos específicos para realizar boundary scans**, entre ellos:

- **BYPASS** selecciona un registro de bypass de un bit para poder acceder a otros dispositivos de una cadena de escaneo con una sobrecarga mínima.
- **SAMPLE/PRELOAD** captura los valores de los pines durante el funcionamiento normal y puede precargar el registro de boundary scan antes de otra instrucción.
- **EXTEST** establece y lee los estados de los pines.

También puede admitir otros comandos, como:

- **IDCODE** para identificar un dispositivo
- **INTEST** para probar internamente el dispositivo

Es posible que encuentres estas instrucciones al usar una herramienta como JTAGulator.

### El Test Access Port

El **Test Access Port (TAP)** proporciona acceso a la lógica de prueba JTAG de un componente. Se necesitan cuatro señales y `TRST` es opcional:<sup>[[1]](#references)</sup>

- Entrada de reloj de prueba (**TCK**) TCK es el **reloj** que determina con qué frecuencia el controlador TAP realizará una acción (en otras palabras, pasará al siguiente estado de la máquina de estados).
- Entrada de selección del modo de prueba (**TMS**) TMS controla la **máquina de estados finitos**. En cada ciclo del reloj, el controlador JTAG TAP del dispositivo comprueba el voltaje del pin TMS. Si el voltaje está por debajo de cierto umbral, la señal se considera baja y se interpreta como 0; si está por encima de cierto umbral, se considera alta y se interpreta como 1.
- Entrada de datos de prueba (**TDI**) desplaza instrucciones seriales o datos de prueba al registro TAP seleccionado. IEEE 1149.1 define el comportamiento de transferencia del TAP, mientras que los fabricantes definen instrucciones opcionales y registros de depuración.
- Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
- Entrada de reinicio de prueba (**TRST**) El TRST opcional reinicia la máquina de estados finitos **a un estado conocido y válido**. Como alternativa, si TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, se activa un reinicio, igual que con el pin TRST; por eso TRST es opcional.

A veces podrás encontrar esos pines señalados en la PCB. En otras ocasiones quizá tengas que **localizarlos**.

### Identificación de pines JTAG

Una opción rápida, diseñada específicamente para detectar puertos JTAG, aunque comparativamente cara, es **JTAGulator**, que también puede identificar la disposición de pines UART.<sup>[[2]](#references)</sup>

Tiene **24 canales** que pueden conectarse a puntos de prueba de la placa. Enumera combinaciones de pines candidatas mediante escaneos **IDCODE** y **BYPASS**, e informa de los canales correspondientes a las señales JTAG detectadas.

Una forma más barata, pero mucho más lenta, de identificar la disposición de pines JTAG es usar [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Con **JTAGenum**, primero define los pines del microcontrolador de sondeo que se usarán para la enumeración. Consulta su disposición de pines y luego conecta esos pines a puntos de prueba candidatos de la placa objetivo.<sup>[[3]](#references)</sup>

Una **tercera forma** de identificar pines JTAG es **inspeccionar la PCB** en busca de un footprint conocido. Algunas placas exponen un footprint **Tag-Connect**, aunque Tag-Connect es un sistema de conectores que puede transportar JTAG, SWD, UART u otra interfaz; por sí solo, no demuestra que los pines sean JTAG. Las hojas de datos de los componentes y las mediciones de continuidad pueden ayudar a identificar las señales reales.<sup>[[5]](#references)</sup>

## SDW

SWD es la interfaz de depuración de dos pines y basada en paquetes de Arm.<sup>[[4]](#references)</sup>

La interfaz usa **SWDIO** bidireccional para los datos y **SWCLK** para el reloj. Muchos dispositivos implementan un **Serial Wire/JTAG Debug Port (SWJ-DP)** que permite elegir entre SWD y JTAG en pines compartidos.<sup>[[4]](#references)</sup>

## References

- [1] [Grupo de trabajo IEEE 1149.1 — JTAG y boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentación de JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeración de pines JTAG con Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de depuración de bajo número de pines para sistemas con varios dispositivos](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints para cables de depuración y programación](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
