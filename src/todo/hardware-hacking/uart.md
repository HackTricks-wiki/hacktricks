# UART

{{#include ../../banners/hacktricks-training.md}}

## Información básica

UART es un protocolo serial, lo que significa que transfiere datos entre componentes un bit a la vez. En contraste, los protocolos de comunicación paralela transmiten datos simultáneamente a través de múltiples canales. Entre los protocolos seriales comunes se incluyen RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express y USB.

Generalmente, la línea se mantiene alta (con un valor lógico de 1) mientras UART está en estado inactivo. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (con un valor lógico de 0). A continuación, el transmisor envía entre cinco y ocho bits de datos que contienen el mensaje real, seguidos de un bit de paridad opcional y uno o dos bits de parada (con un valor lógico de 1), dependiendo de la configuración. El bit de paridad, utilizado para la comprobación de errores, rara vez se observa en la práctica. El bit o los bits de parada indican el final de la transmisión.

La configuración más común se denomina 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en una configuración UART 8N1, enviaríamos los siguientes bits: 0 (el bit de inicio); 0, 1, 0, 0, 0, 0, 1, 1 (el valor de 0x43 en binario); y 0 (el bit de parada).

![UART: La configuración más común se denomina 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en una configuración UART 8N1](<../../images/image (764).png>)

Herramientas de hardware para comunicarse con UART:

- Adaptador USB a serial
- Adaptadores con los chips CP2102 o PL2303
- Herramienta multipropósito como: Bus Pirate, Adafruit FT232H, Shikra o Attify Badge

### Identificación de los puertos UART

UART tiene 4 puertos: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) y **GND** (Ground). Es posible que encuentres 4 puertos con las letras **`TX`** y **`RX`** **escritas** en la PCB. Pero si no hay ninguna indicación, quizá tengas que localizarlos por tu cuenta utilizando un **multímetro** o un **analizador lógico**.

Con un **multímetro** y el dispositivo apagado:

- Para identificar el pin **GND**, utiliza el modo **Continuity Test**, coloca la sonda negra en tierra y prueba con la roja hasta que escuches un sonido del multímetro. Se pueden encontrar varios pines GND en la PCB, por lo que es posible que hayas encontrado o no el correspondiente a UART.
- Para identificar el **puerto VCC**, selecciona el modo de voltaje **DC** y configúralo a 20 V. Coloca la sonda negra en tierra y la roja en el pin. Enciende el dispositivo. Si el multímetro mide un voltaje constante de 3.3 V o 5 V, has encontrado el pin Vcc. Si obtienes otros voltajes, vuelve a intentarlo con otros puertos.
- Para identificar el **puerto TX**, selecciona el modo de voltaje **DC** hasta 20 V, coloca la sonda negra en tierra y la roja en el pin, y enciende el dispositivo. Si observas que el voltaje fluctúa durante unos segundos y después se estabiliza en el valor de Vcc, probablemente hayas encontrado el puerto TX. Esto ocurre porque, al encenderse, envía algunos datos de depuración.
- El **puerto RX** sería el más cercano a los otros 3; presenta la menor fluctuación de voltaje y el valor general más bajo de todos los pines UART.

Puedes confundir los puertos TX y RX y no ocurrirá nada, pero si confundes GND y VCC podrías quemar el circuito.

En algunos dispositivos objetivo, el fabricante deshabilita el puerto UART desactivando RX o TX, o incluso ambos. En ese caso, puede ser útil seguir las conexiones en la placa de circuito y encontrar algún punto de breakout. Una pista importante para confirmar que no se detecta UART y que el circuito está interrumpido es comprobar la garantía del dispositivo. Si el dispositivo se ha enviado con garantía, el fabricante deja algunas interfaces de depuración (en este caso, UART) y, por lo tanto, debe haber desconectado UART y volvería a conectarlo durante la depuración. Estos pines de breakout se pueden conectar mediante soldadura o cables jumper.

### Identificación del Baud Rate de UART

La forma más sencilla de identificar el baud rate correcto es observar la salida del **pin TX e intentar leer los datos**. Si los datos que recibes no son legibles, cambia al siguiente baud rate posible hasta que los datos sean legibles. Puedes utilizar un adaptador USB a serial o un dispositivo multipropósito como Bus Pirate para hacerlo, junto con un script auxiliar, como [baudrate.py](https://github.com/devttys0/baudrate/). Los baud rates más comunes son 9600, 38400, 19200, 57600 y 115200.

> [!CAUTION]
> Es importante tener en cuenta que en este protocolo debes conectar el TX de un dispositivo al RX del otro.

## Adaptador CP210X UART a TTY

El chip CP210X se utiliza en muchas placas de prototipado, como NodeMCU (con esp8266), para la comunicación serial. Estos adaptadores son relativamente económicos y se pueden utilizar para conectarse a la interfaz UART del objetivo. El dispositivo tiene 5 pines: 5V, GND, RXD, TXD y 3.3V. Asegúrate de conectar el voltaje compatible con el objetivo para evitar daños. Finalmente, conecta el pin RXD del adaptador al TXD del objetivo y el pin TXD del adaptador al RXD del objetivo.

Si el adaptador no se detecta, asegúrate de que los drivers de CP210X estén instalados en el sistema host. Una vez detectado y conectado el adaptador, se pueden utilizar herramientas como picocom, minicom o screen.

Para enumerar los dispositivos conectados a sistemas Linux/MacOS:
```
ls /dev/
```
Para la interacción básica con la interfaz UART, utiliza el siguiente comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Para minicom, usa el siguiente comando para configurarlo:
```
minicom -s
```
Configura los ajustes, como el baudrate y el nombre del dispositivo, en la opción `Serial port setup`.

Después de la configuración, usa el comando `minicom` para iniciar la UART Console.

## UART mediante Arduino UNO R3 (placas con chip Atmel 328p extraíble)

En caso de que no haya adaptadores UART Serial to USB disponibles, se puede usar Arduino UNO R3 con un quick hack. Como Arduino UNO R3 suele estar disponible en cualquier lugar, esto puede ahorrar mucho tiempo.

Arduino UNO R3 tiene un adaptador USB to Serial integrado en la propia placa. Para obtener una conexión UART, simplemente extrae el chip microcontrolador Atmel 328p de la placa. Este hack funciona en las variantes de Arduino UNO R3 que tienen el Atmel 328p sin soldar en la placa (en ellas se utiliza la versión SMD). Conecta el pin RX de Arduino (Digital Pin 0) al pin TX de la UART Interface y el pin TX de Arduino (Digital Pin 1) al pin RX de la UART interface.

Finalmente, se recomienda usar Arduino IDE para obtener la Serial Console. En la sección `tools` del menú, selecciona la opción `Serial Console` y establece el baud rate según la UART interface.

## Bus Pirate

En este escenario vamos a sniffear la comunicación UART del Arduino, que está enviando todos los prints del programa al Serial Monitor.
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
## Volcado de Firmware con UART Console

UART Console proporciona una excelente forma de trabajar con el firmware subyacente en el entorno de ejecución. Sin embargo, cuando el acceso a UART Console es de solo lectura, puede introducir muchas limitaciones. En muchos dispositivos embebidos, el firmware se almacena en EEPROMs y se ejecuta en procesadores que tienen memoria volátil. Por ello, el firmware se mantiene como solo lectura, ya que el firmware original durante la fabricación se encuentra dentro de la propia EEPROM y cualquier archivo nuevo se perdería debido a la memoria volátil. Por tanto, volcar el firmware es una tarea valiosa al trabajar con firmwares embebidos.

Hay muchas formas de hacerlo, y la sección SPI cubre métodos para extraer el firmware directamente de la EEPROM con diversos dispositivos. Aunque se recomienda intentar primero volcar el firmware con UART, ya que hacerlo con dispositivos físicos e interacciones externas puede ser arriesgado.

Volcar el firmware desde UART Console requiere obtener primero acceso a los bootloaders. Muchos proveedores populares utilizan uboot (Universal Bootloader) como bootloader para cargar Linux. Por tanto, es necesario obtener acceso a uboot.

Para obtener acceso al bootloader, conecta el puerto UART al ordenador utilizando cualquiera de las herramientas de Serial Console y mantén desconectada la fuente de alimentación del dispositivo. Cuando la configuración esté lista, pulsa la tecla Enter y mantenla presionada. Finalmente, conecta la fuente de alimentación al dispositivo y deja que arranque.

Esto interrumpirá la carga de uboot y mostrará un menú. Se recomienda comprender los comandos de uboot y utilizar el menú de ayuda para listarlos. Este podría ser el comando `help`. Dado que los distintos proveedores utilizan configuraciones diferentes, es necesario comprender cada una de ellas por separado.

Normalmente, el comando para volcar el firmware es:
```
md
```
que significa "volcado de memoria". Esto volcará la memoria (contenido de la EEPROM) en la pantalla. Se recomienda registrar la salida de la Consola serie antes de iniciar el procedimiento para capturar el volcado de memoria.

Por último, simplemente elimina todos los datos innecesarios del archivo de registro, guarda el archivo como `filename.rom` y utiliza binwalk para extraer el contenido:
```
binwalk -e <filename.rom>
```
Esto mostrará los posibles contenidos de la EEPROM según las firmas encontradas en el archivo hex.

Sin embargo, es necesario tener en cuenta que no siempre significa que uboot esté desbloqueado, aunque se esté utilizando. Si la tecla Enter no hace nada, comprueba otras teclas, como la tecla Espacio, etc. Si el bootloader está bloqueado y no se puede interrumpir, este método no funcionará. Para comprobar si uboot es el bootloader del dispositivo, revisa la salida en la consola UART mientras el dispositivo arranca. Es posible que mencione uboot durante el arranque.

{{#include ../../banners/hacktricks-training.md}}
