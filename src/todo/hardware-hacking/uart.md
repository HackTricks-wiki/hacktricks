# UART

{{#include ../../banners/hacktricks-training.md}}

## Información básica

UART es una interfaz serie asíncrona que transfiere un flujo de bits enmarcado sin un reloj compartido. No confundas UART de nivel lógico con RS-232: RS-232 utiliza niveles de voltaje diferentes, a menudo negativos, y requiere un transceptor.<sup>[[1]](#references)[[3]](#references)</sup>

Por lo general, la línea se mantiene alta (en un valor lógico 1) mientras UART está en estado inactivo. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (en un valor lógico 0). A continuación, el transmisor envía de cinco a ocho bits de datos que contienen el mensaje real, seguidos de un bit de paridad opcional y uno o dos bits de parada (con un valor lógico 1), según la configuración. El bit de paridad, utilizado para la comprobación de errores, rara vez se ve en la práctica. El bit de parada (o bits) señala el final de la transmisión.

La configuración más común es 8N1: ocho bits de datos, sin paridad y un bit de parada. UART envía primero el bit de datos menos significativo, por lo que ASCII `C` (`0x43`) se transmite como: inicio `0`; datos `1, 1, 0, 0, 0, 0, 1, 0`; parada `1`.<sup>[[1]](#references)</sup>

![UART: La configuración más común se denomina 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en un UART 8N1](<../../images/image (764).png>)

Herramientas de hardware para comunicarse con UART:

- Adaptador USB a serie
- Adaptadores con los chips CP2102 o PL2303
- Herramienta multipropósito como: Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificación de puertos UART

Un header de depuración típico expone **TX**, **RX** y **GND**; también puede exponer un pin **Vcc/Vref**, reset o pines de control de flujo. Vcc no es una señal UART y normalmente solo debe utilizarse como referencia de voltaje, no conectarse como fuente de alimentación, a menos que se conozcan el esquema de la placa y los requisitos de corriente.<sup>[[2]](#references)[[3]](#references)</sup>

Comienza con el dispositivo **apagado** y desconectado:

- Identifica **GND** en modo de continuidad con respecto a un plano de tierra conocido, el blindaje de un conector o la tierra de la fuente de alimentación. Nunca utilices el modo de continuidad/resistencia en una placa encendida.
- Cambia al modo de voltaje DC antes de encender el objetivo. Mide los pines candidatos con respecto a tierra para identificar el voltaje lógico. Un nivel estable puede ser Vcc/Vref; no asumas que es seguro conectarlo.
- Observa los candidatos con un analizador lógico u osciloscopio durante el arranque. **TX** normalmente permanece en alto en reposo y muestra ráfagas de datos enmarcados. Un multímetro puede mostrar una fluctuación media, pero no puede validar el framing ni la velocidad en baudios.
- **RX** puede permanecer inactivo y no puede identificarse de forma segura simplemente porque esté junto a TX. Traza la PCB, consulta la hoja de datos del SoC o utiliza un analizador de alta impedancia antes de activarlo.

Intercambiar TX y RX normalmente no produce comunicación; confundir la alimentación, la tierra o los niveles de señal puede dañar permanentemente el objetivo o el adaptador. Conecta primero la tierra y comienza en modo de **solo recepción** (TX del objetivo a RX del adaptador).

Los fabricantes pueden omitir el header, dejar sin poblar las resistencias en serie, desactivar la consola en el firmware o exponer únicamente TX. Traza los test pads y footprints de resistencias cercanos hasta el SoC y añade una conexión temporal de alta impedancia solo después de confirmar el nivel eléctrico. La presencia de una garantía no implica que deba existir un UART accesible.

### Identificación de la velocidad en baudios de UART

La forma más sencilla de identificar la velocidad en baudios correcta es observar la **salida del pin TX e intentar leer los datos**. Si los datos que recibes no son legibles, cambia a la siguiente velocidad en baudios posible hasta que los datos se vuelvan legibles. Puedes utilizar un adaptador USB a serie o un dispositivo multipropósito como Bus Pirate para hacerlo, junto con un helper script, como [baudrate.py](https://github.com/devttys0/baudrate/). Las velocidades en baudios más comunes son 9600, 38400, 19200, 57600 y 115200.

> [!CAUTION]
> Es importante tener en cuenta que en este protocolo debes conectar el TX de un dispositivo al RX del otro.

## Adaptador UART a TTY CP210X

Los bridges USB-to-UART CP210x aparecen en muchas placas de prototipado y adaptadores económicos. Los módulos comunes exponen pines de alimentación junto con GND, RXD y TXD, pero sus headers y niveles de E/S varían. Confirma el voltaje real a partir del diseño de la placa o de la hoja de datos. Normalmente, conecta solo GND, RX del adaptador a TX del objetivo y, después de validar la recepción únicamente, TX del adaptador a RX del objetivo. No conectes el pin de alimentación de 5 V/3.3 V del adaptador a menos que quieras alimentar intencionadamente un objetivo que sepas que lo tolera.<sup>[[3]](#references)</sup>

En caso de que el adaptador no sea detectado, asegúrate de que los drivers de CP210X estén instalados en el sistema host. Una vez detectado y conectado el adaptador, pueden utilizarse herramientas como picocom, minicom o screen.

Para enumerar los dispositivos conectados a sistemas Linux/MacOS:
```
ls /dev/
```
Para interactuar básicamente con la interfaz UART, utiliza el siguiente comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Para minicom, usa el siguiente comando para configurarlo:
```
minicom -s
```
Configura los ajustes, como la velocidad en baudios y el nombre del dispositivo, en la opción `Serial port setup`.

Después de la configuración, ejecuta `minicom` para abrir la consola UART.

## UART mediante Arduino UNO R3 (placas con chip Atmel 328p extraíble)

En caso de que no haya adaptadores UART Serial a USB disponibles, se puede utilizar Arduino UNO R3 con un quick hack. Como Arduino UNO R3 suele estar disponible en cualquier lugar, esto puede ahorrar mucho tiempo.

Arduino UNO R3 tiene un adaptador USB a Serial integrado en la propia placa. Para obtener una conexión UART, simplemente extrae el microcontrolador Atmel 328p de la placa. Este hack funciona en las variantes de Arduino UNO R3 que tienen el Atmel 328p sin soldar en la placa (se utiliza la versión SMD). Conecta el pin RX de Arduino (Digital Pin 0) al pin TX de la interfaz UART y el pin TX de Arduino (Digital Pin 1) al pin RX de la interfaz UART.

Utiliza el **Serial Monitor** del Arduino IDE o un terminal dedicado con la velocidad en baudios objetivo. Las señales Serial clásicas del Uno R3 utilizan lógica de 5 V, así que usa un level shifter o un divisor antes de conectarlas a un objetivo de 3,3 V o de menor voltaje.

## Bus Pirate

La siguiente transcripción utiliza la interfaz de firmware legacy de Bus Pirate para monitorizar la salida UART. Las versiones más recientes del firmware de Bus Pirate utilizan comandos como `m uart`, `{`/`}`, `monitor` o `bridge`; consulta la documentación de la versión instalada.<sup>[[2]](#references)</sup>
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Volcado del firmware con la consola UART

Una consola UART proporciona acceso en tiempo de ejecución a los registros de arranque y, en ocasiones, a un shell del bootloader o del sistema operativo. Incluso una consola de solo lectura revela mapas de memoria, controladores flash, argumentos de arranque, diseños de particiones y versiones del firmware. El firmware puede residir en SPI NOR/NAND, eMMC u otro dispositivo; por lo general, no se ejecuta desde una EEPROM, y los archivos escritos en un sistema de archivos persistente montado no necesariamente desaparecen al reiniciar.

Existen varias vías de adquisición, y la sección sobre SPI cubre las lecturas directas desde la memoria flash externa. La adquisición asistida por consola puede ser menos invasiva cuando el bootloader ya proporciona un comando de lectura seguro, pero cualquier interrupción del arranque o comando de flash puede afectar a la disponibilidad, por lo que se debe registrar el estado original y evitar operaciones de escritura/borrado.

El volcado de firmware asistido por consola suele comenzar interrumpiendo un bootloader. Muchos dispositivos Linux embebidos utilizan **Das U-Boot**, pero otros emplean bootloaders propietarios o deshabilitan la consola interactiva.

Para comprobar si existe un bootloader interactivo, conecta la línea de recepción UART y el terminal mientras el objetivo está apagado, inicia el registro y enciéndelo. Sigue el aviso de autoboot mostrado; según la compilación, la interrupción puede requerir una tecla, una secuencia corta o estar completamente deshabilitada.

Si la interrupción tiene éxito, utiliza `help`, `printenv` y comandos de reconocimiento de solo lectura para comprender el diseño de memoria y almacenamiento de ese fabricante antes de acceder a las direcciones.

En U-Boot, `md` muestra la **memoria direccionable**, no automáticamente “la EEPROM”. Primero utiliza comandos específicos de la placa, como `mtd list`, `sf probe`, `mmc info`, `part list`, las variables de entorno y los registros de arranque, para identificar la dirección mapeada correcta o cargar una región flash en la RAM. A continuación, muestra un rango conocido byte a byte:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Registra la salida serie antes de comenzar. La salida de `md.b` contiene direcciones y una columna ASCII, por lo que es una representación textual y no una imagen ROM sin procesar.

Elimina las columnas de direcciones y ASCII, concatena únicamente los campos de bytes hexadecimales y decodifícalos a binario (por ejemplo, con `xxd -r -p`). Verifica el número de bytes esperado y registra un hash antes del análisis:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk identifica entonces firmas conocidas en el binario reconstruido. Una lectura directa de la flash mediante la interfaz SPI/eMMC/NAND adecuada suele ser más rápida y menos propensa a errores cuando la consola no puede transferir datos de forma fiable.

U-Boot puede desactivar la interrupción, requerir una secuencia de teclas específica del proveedor o bloquear los comandos de memoria/flash. Sigue el aviso de autoboot y el registro de arranque en lugar de transmitir caracteres a ciegas. Si no se puede interrumpir la consola, conserva el registro de arranque y utiliza un método de adquisición de firmware no invasivo.

## References

- [1] [Manual de referencia de la familia Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentación de Bus Pirate - modo UART y límites eléctricos](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - hoja de datos del CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentación de U-Boot - comando `md` para mostrar memoria](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
