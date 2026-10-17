# Hackeo de hardware

{{#include ../../banners/hacktricks-training.md}}

Para un dispositivo al que se tiene acceso físico, empieza por las interfaces expuestas por su placa o señales: [consolas serie UART](uart.md), [acceso de depuración JTAG/SWD](jtag.md), [trazado de instrucciones CoreSight](arm-coresight-instruction-tracing.md), buses [I²C](i2c.md) y de [memoria flash SPI](spi.md). El [análisis de canal lateral](side_channel_analysis.md) y la [inyección de fallos](fault_injection_attacks.md) se ocupan de otras tareas de medición y glitching; el [análisis de señales de radio](radio.md) cubre un punto de entrada inalámbrico. Para procedimientos específicos del objetivo relacionados con RFID/NFC, sub-GHz, infrarrojos, BLE, LoRaWAN e iButton, consulta [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Antes de conectar herramientas, comprueba los niveles eléctricos del objetivo y las limitaciones indicadas en el capítulo correspondiente.

## JTAG

JTAG (IEEE 1149.1) permite realizar pruebas de escaneo de límites mediante celdas colocadas alrededor de los pines de E/S de un dispositivo. Muchos procesadores también exponen funciones de depuración específicas del proveedor a través del mismo puerto de acceso de prueba (TAP); el escaneo de límites y la depuración de la CPU son usos relacionados de JTAG, pero no son sinónimos.<sup>[[1]](#references)</sup>

El estándar JTAG define **comandos específicos para realizar escaneos de límites**, entre ellos:

- **BYPASS** selecciona un registro de bypass de un bit para poder acceder a otros dispositivos de una cadena de escaneo con una sobrecarga mínima.
- **SAMPLE/PRELOAD** captura los valores de los pines durante el funcionamiento normal y puede precargar el registro de escaneo de límites antes de otra instrucción.
- **EXTEST** establece y lee los estados de los pines.

También puede admitir otros comandos, como:

- **IDCODE** para identificar un dispositivo
- **INTEST** para probar internamente el dispositivo

Es posible que encuentres estas instrucciones al usar una herramienta como JTAGulator.

### El puerto de acceso de prueba

El **puerto de acceso de prueba (TAP)** permite acceder a la lógica de prueba JTAG de un componente. Se requieren cuatro señales y `TRST` es opcional:<sup>[[1]](#references)</sup>

- Entrada de reloj de prueba (**TCK**) TCK es el **reloj** que determina con qué frecuencia el controlador TAP realizará una acción (es decir, pasará al siguiente estado de la máquina de estados).
- Entrada de selección del modo de prueba (**TMS**) TMS controla la **máquina de estados finitos**. En cada ciclo del reloj, el controlador TAP JTAG del dispositivo comprueba el voltaje en el pin TMS. Si el voltaje está por debajo de cierto umbral, la señal se considera baja y se interpreta como 0; si está por encima de cierto umbral, se considera alta y se interpreta como 1.
- Entrada de datos de prueba (**TDI**) desplaza instrucciones o datos de prueba en serie al registro TAP seleccionado. IEEE 1149.1 define el comportamiento de transferencia del TAP, mientras que los proveedores definen las instrucciones opcionales y los registros de depuración.
- Salida de datos de prueba (**TDO**) TDO es el pin que envía **datos fuera del chip**.
- Entrada de reinicio de prueba (**TRST**) El TRST opcional reinicia la máquina de estados finitos **a un estado conocido y válido**. Como alternativa, si TMS se mantiene en 1 durante cinco ciclos de reloj consecutivos, se activa un reinicio igual que con el pin TRST, por lo que TRST es opcional.

A veces podrás encontrar esos pines marcados en la PCB. En otras ocasiones, tendrás que **identificarlos**.

### Identificación de pines JTAG

Una opción rápida y diseñada específicamente para detectar puertos JTAG —aunque comparativamente cara— es **JTAGulator**, que también puede identificar distribuciones de pines UART.<sup>[[2]](#references)</sup>

Cuenta con **24 canales** que se pueden conectar a puntos de prueba de la placa. Enumera posibles combinaciones de pines mediante escaneos **IDCODE** y **BYPASS**, e informa de los canales que corresponden a las señales JTAG detectadas.

Una forma más económica, pero mucho más lenta, de identificar distribuciones de pines JTAG es usar [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) cargado en un microcontrolador compatible con Arduino.

Con **JTAGenum**, primero define los pines del microcontrolador de sondeo que se usarán para la enumeración. Consulta su distribución de pines y luego conecta esos pines a los puntos de prueba candidatos de la placa objetivo.<sup>[[3]](#references)</sup>

Una **tercera forma** de identificar pines JTAG es **inspeccionar la PCB** para buscar una huella conocida. Algunas placas exponen una huella **Tag-Connect**, aunque Tag-Connect es un sistema de conexión que puede transportar JTAG, SWD, UART u otra interfaz; por sí sola, no demuestra que los pines sean JTAG. Las hojas de datos de los componentes y las mediciones de continuidad pueden ayudar a identificar las señales reales.<sup>[[5]](#references)</sup>

## SDW

SWD es la interfaz de depuración de dos pines y basada en paquetes de Arm.<sup>[[4]](#references)</sup>

La interfaz utiliza **SWDIO** bidireccional para los datos y **SWCLK** para el reloj. Muchos dispositivos implementan un **puerto de depuración Serial Wire/JTAG (SWJ-DP)** que permite seleccionar entre SWD y JTAG en pines compartidos.<sup>[[4]](#references)</sup>

## References

- [1] [Grupo de trabajo IEEE 1149.1 — JTAG y escaneo de límites](https://sagroups.ieee.org/1149/1/)
- [2] [Documentación de JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumeración de pines JTAG con Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de depuración con pocos pines para sistemas multidispositivo](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Huellas para cables de depuración y programación](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
