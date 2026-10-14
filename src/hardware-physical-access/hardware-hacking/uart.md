# UART

{{#include ../../banners/hacktricks-training.md}}

## Información básica

UART es una interfaz serial asíncrona que transfiere un flujo de bits enmarcado sin un reloj compartido. No confundas UART de nivel lógico con RS-232: RS-232 usa niveles de voltaje distintos, a menudo negativos, y requiere un transceptor.<sup>[[1]](#references)[[3]](#references)</sup>

Por lo general, la línea se mantiene alta (en el valor lógico 1) mientras UART está en estado inactivo. Luego, para indicar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (en el valor lógico 0). A continuación, el transmisor envía de cinco a ocho bits de datos que contienen el mensaje, seguidos de un bit de paridad opcional y uno o dos bits de parada (con valor lógico 1), según la configuración. El bit de paridad, que se usa para comprobar errores, rara vez se ve en la práctica. El bit o los bits de parada indican el final de la transmisión.

La configuración más común es 8N1: ocho bits de datos, sin paridad y un bit de parada. UART envía primero el bit de datos menos significativo, por lo que el carácter ASCII `C` (`0x43`) se transmite así: inicio `0`; datos `1, 1, 0, 0, 0, 0, 1, 0`; parada `1`.<sup>[[1]](#references)</sup>

![UART: We call the most common configuration 8N1: eight data bits, no parity, and one stop bit. For example, if we wanted to send the character C, or 0x43 in ASCII, in an 8N1 UART](<../../images/image (764).png>)

Herramientas de hardware para comunicarse mediante UART:

- Adaptador USB a serial
- Adaptadores con chips CP2102 o PL2303
- Herramienta multipropósito como Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificación de puertos UART

Un header de depuración típico expone **TX**, **RX** y **GND**; también puede exponer un pin **Vcc/Vref**, de reinicio o de control de flujo. Vcc no es una señal UART y normalmente solo debe usarse como referencia de voltaje, no conectarse como fuente de alimentación, a menos que se conozcan el esquema de la placa y los requisitos de corriente.<sup>[[2]](#references)[[3]](#references)</sup>

Empieza con el dispositivo **apagado** y desconectado:

- Identifica **GND** en modo de continuidad, comparándolo con un plano de tierra conocido, el blindaje del conector o la tierra de alimentación. Nunca uses el modo de continuidad/resistencia con una placa encendida.
- Cambia al modo de voltaje de CC antes de encender el dispositivo objetivo. Mide los pines candidatos con respecto a tierra para identificar el voltaje lógico. Un riel estable puede ser Vcc/Vref; no des por hecho que es seguro conectarlo.
- Observa los pines candidatos con un analizador lógico o un osciloscopio durante el arranque. **TX** suele estar inactivo en nivel alto y mostrar ráfagas de datos enmarcados. Un multímetro puede mostrar fluctuaciones promedio, pero no puede validar el encuadre ni la velocidad en baudios.
- **RX** puede permanecer inactivo y no se puede identificar de forma segura solo porque esté junto a TX. Sigue las pistas de la PCB, consulta la hoja de datos del SoC o usa un analizador de alta impedancia antes de aplicarle señales.

Intercambiar TX y RX normalmente no produce comunicación; confundir la alimentación, la tierra o los niveles de señal puede dañar permanentemente el dispositivo objetivo o el adaptador. Conecta primero la tierra y empieza **solo en modo de recepción** (TX del dispositivo objetivo a RX del adaptador).

Los fabricantes pueden omitir el header, dejar sin montar las resistencias en serie, desactivar la consola en el firmware o exponer solo TX. Sigue las pistas de los puntos de prueba cercanos y las huellas de resistencias hasta el SoC, y añade una conexión temporal de alta impedancia solo después de confirmar el nivel eléctrico. La existencia de una garantía no implica que necesariamente haya una UART accesible.

### Identificación de la velocidad en baudios de UART

La forma más sencilla de identificar la velocidad en baudios correcta es observar la salida del pin **TX** e intentar leer los datos. Si los datos recibidos no son legibles, cambia a la siguiente velocidad en baudios posible hasta que lo sean. Puedes usar un adaptador USB a serial o un dispositivo multipropósito como Bus Pirate, junto con un script auxiliar como [baudrate.py](https://github.com/devttys0/baudrate/). Las velocidades en baudios más comunes son 9600, 38400, 19200, 57600 y 115200.

> [!CAUTION]
> ¡Es importante tener en cuenta que, en este protocolo, debes conectar el TX de un dispositivo al RX del otro!

## Adaptador CP210X UART a TTY

Los puentes USB a UART CP210x aparecen en muchas placas de prototipado y adaptadores económicos. Los módulos comunes exponen pines de alimentación junto con GND, RXD y TXD, pero los headers y los niveles de E/S varían. Confirma el voltaje real según el diseño de la placa o la hoja de datos. Normalmente, conecta solo GND y RX del adaptador a TX del dispositivo objetivo; después de validar la recepción, conecta TX del adaptador a RX del dispositivo objetivo. No conectes el pin de alimentación de 5 V/3,3 V del adaptador, salvo que quieras alimentar intencionalmente un dispositivo objetivo que sepas que admite ese voltaje.<sup>[[3]](#references)</sup>

Si no se detecta el adaptador, asegúrate de que los controladores CP210X estén instalados en el sistema anfitrión. Una vez detectado y conectado el adaptador, puedes usar herramientas como picocom, minicom o screen.

Para listar los dispositivos conectados a sistemas Linux/MacOS:

```
ls /dev/
```

Para interactuar de forma básica con la interfaz UART, usa el siguiente comando:

```
picocom /dev/<adapter> --baud <baudrate>
```

Para minicom, usa el siguiente comando para configurarlo:

```
minicom -s
```

Configura ajustes como la velocidad en baudios y el nombre del dispositivo en la opción `Serial port setup`.

Después de la configuración, ejecuta `minicom` para abrir la consola UART.

## UART mediante Arduino UNO R3 (placas con chip Atmel 328p extraíble)

Si no hay adaptadores UART Serial a USB disponibles, se puede usar Arduino UNO R3 con un hack rápido. Como Arduino UNO R3 suele estar disponible en cualquier lugar, esto puede ahorrar mucho tiempo.

Arduino UNO R3 tiene un adaptador USB a Serial integrado en la propia placa. Para obtener una conexión UART, basta con retirar el microcontrolador Atmel 328p de la placa. Este hack funciona con las variantes de Arduino UNO R3 que tienen el Atmel 328p sin soldar a la placa (se usa la versión SMD). Conecta el pin RX de Arduino (Digital Pin 0) al pin TX de la interfaz UART, y el pin TX de Arduino (Digital Pin 1) al pin RX de la interfaz UART.

Usa el **Serial Monitor** del Arduino IDE o un terminal dedicado configurado con la velocidad en baudios del objetivo. Las señales seriales de los Uno R3 clásicos usan lógica de 5 V, así que utiliza un conversor de nivel o un divisor antes de conectarlas a un objetivo de 3,3 V o de menor voltaje.

## Bus Pirate

La siguiente transcripción usa la interfaz del firmware heredado de Bus Pirate para monitorizar la salida UART. Las versiones más recientes del firmware de Bus Pirate usan comandos como `m uart`, `{`/`}`, `monitor` o `bridge`; consulta la documentación de la versión instalada.<sup>[[2]](#references)</sup>

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

## Volcado de firmware con la consola UART

Una consola UART proporciona acceso en tiempo de ejecución a los registros de arranque y, en ocasiones, a un shell del bootloader o del sistema operativo. Incluso una consola de solo lectura revela mapas de memoria, controladores flash, argumentos de arranque, diseños de particiones y versiones del firmware. El firmware puede estar en SPI NOR/NAND, eMMC u otro dispositivo; por lo general, no se ejecuta desde una EEPROM, y los archivos escritos en un sistema de archivos persistente montado no necesariamente desaparecen al reiniciar.

Hay varias formas de adquirir el firmware; la sección sobre SPI explica las lecturas directas desde la memoria flash externa. La adquisición asistida por consola puede ser menos invasiva si el bootloader ya ofrece un comando de lectura seguro, pero interrumpir el arranque o ejecutar comandos de flash puede afectar la disponibilidad, así que registra el estado original y evita las operaciones de escritura y borrado.

El volcado de firmware asistido por consola suele comenzar interrumpiendo un bootloader. Muchos dispositivos Linux integrados usan **Das U-Boot**, pero otros utilizan bootloaders propietarios o desactivan la consola interactiva.

Para comprobar si hay un bootloader interactivo, conecta la ruta de recepción UART y el terminal mientras el objetivo está apagado, inicia el registro y enciéndelo. Sigue el aviso de autoboot que aparezca; según la compilación, para interrumpirlo puede ser necesario pulsar una tecla, usar una secuencia breve o, si está desactivado, no será posible.

Si logras interrumpir el arranque, usa `help`, `printenv` y comandos de reconocimiento de solo lectura para comprender la disposición de memoria y almacenamiento de ese fabricante antes de acceder a las direcciones.

En U-Boot, `md` muestra **memoria direccionable**, no automáticamente «la EEPROM». Primero, usa comandos específicos de la placa, como `mtd list`, `sf probe`, `mmc info`, `part list`, las variables de entorno y los registros de arranque para identificar la dirección mapeada correcta o cargar una región de flash en la RAM. Luego, muestra un rango conocido byte por byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Registra la salida serial antes de empezar. La salida de `md.b` contiene direcciones y una columna ASCII, por lo que es una representación textual, no una imagen ROM sin procesar.

Elimina las columnas de direcciones y ASCII, concatena solo los campos de bytes hexadecimales y decodifícalos a binario (por ejemplo, con `xxd -r -p`). Verifica que el número de bytes sea el esperado y registra un hash antes del análisis:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifica las firmas conocidas en el binario reconstruido. Una lectura directa de la flash a través de la interfaz SPI/eMMC/NAND adecuada suele ser más rápida y menos propensa a errores cuando la consola no puede transferir datos de forma fiable.

U-Boot puede desactivar la interrupción, requerir una secuencia de teclas específica del proveedor o bloquear los comandos de memoria/flash. Sigue el aviso de autoboot y el registro de arranque en lugar de transmitir caracteres a ciegas. Si no se puede interrumpir la consola, conserva el registro de arranque y recurre a un método no invasivo para adquirir el firmware.

## References

- [1] [Manual de referencia de la familia Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentación de Bus Pirate - modo UART y límites eléctricos](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - hoja de datos del CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentación de U-Boot - comando `md` para mostrar memoria](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
