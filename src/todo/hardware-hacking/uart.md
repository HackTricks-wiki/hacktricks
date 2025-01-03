# UART

{{#include ../../banners/hacktricks-training.md}}

## Información Básica

UART es un protocolo serial, lo que significa que transfiere datos entre componentes un bit a la vez. En contraste, los protocolos de comunicación paralela transmiten datos simultáneamente a través de múltiples canales. Los protocolos seriales comunes incluyen RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express y USB.

Generalmente, la línea se mantiene alta (en un valor lógico de 1) mientras UART está en estado de inactividad. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (en un valor lógico de 0). A continuación, el transmisor envía de cinco a ocho bits de datos que contienen el mensaje real, seguidos de un bit de paridad opcional y uno o dos bits de parada (con un valor lógico de 1), dependiendo de la configuración. El bit de paridad, utilizado para la verificación de errores, rara vez se ve en la práctica. El bit (o bits) de parada indican el final de la transmisión.

Llamamos a la configuración más común 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en una configuración UART 8N1, enviaríamos los siguientes bits: 0 (el bit de inicio); 0, 1, 0, 0, 0, 0, 1, 1 (el valor de 0x43 en binario), y 0 (el bit de parada).

![](<../../images/image (764).png>)

Herramientas de hardware para comunicarse con UART:

- Adaptador USB a serie
- Adaptadores con los chips CP2102 o PL2303
- Herramienta multipropósito como: Bus Pirate, el Adafruit FT232H, el Shikra o el Attify Badge

### Identificación de Puertos UART

UART tiene 4 puertos: **TX**(Transmitir), **RX**(Recibir), **Vcc**(Voltaje) y **GND**(Tierra). Podrías encontrar 4 puertos con las letras **`TX`** y **`RX`** **escritas** en el PCB. Pero si no hay indicación, es posible que necesites intentar encontrarlos tú mismo usando un **multímetro** o un **analizador lógico**.

Con un **multímetro** y el dispositivo apagado:

- Para identificar el pin **GND**, usa el modo de **Prueba de Continuidad**, coloca el cable negro en tierra y prueba con el rojo hasta que escuches un sonido del multímetro. Se pueden encontrar varios pines GND en el PCB, por lo que podrías haber encontrado o no el que pertenece a UART.
- Para identificar el **puerto VCC**, configura el **modo de voltaje DC** y ajústalo a 20 V de voltaje. Probeta negra en tierra y probeta roja en el pin. Enciende el dispositivo. Si el multímetro mide un voltaje constante de 3.3 V o 5 V, has encontrado el pin Vcc. Si obtienes otros voltajes, vuelve a intentarlo con otros puertos.
- Para identificar el **puerto TX**, configura el **modo de voltaje DC** hasta 20 V de voltaje, probeta negra en tierra y probeta roja en el pin, y enciende el dispositivo. Si encuentras que el voltaje fluctúa durante unos segundos y luego se estabiliza en el valor de Vcc, es muy probable que hayas encontrado el puerto TX. Esto se debe a que al encender, envía algunos datos de depuración.
- El **puerto RX** sería el más cercano a los otros 3, tiene la fluctuación de voltaje más baja y el valor general más bajo de todos los pines UART.

Puedes confundir los puertos TX y RX y no pasaría nada, pero si confundes el puerto GND y el VCC podrías dañar el circuito.

En algunos dispositivos objetivo, el puerto UART está deshabilitado por el fabricante al deshabilitar RX o TX o incluso ambos. En ese caso, puede ser útil rastrear las conexiones en la placa de circuito y encontrar algún punto de salida. Una fuerte pista sobre la confirmación de la no detección de UART y la ruptura del circuito es verificar la garantía del dispositivo. Si el dispositivo ha sido enviado con alguna garantía, el fabricante deja algunas interfaces de depuración (en este caso, UART) y, por lo tanto, debe haber desconectado el UART y lo volvería a conectar mientras depura. Estos pines de salida se pueden conectar soldando o usando cables de puente.

### Identificación de la Tasa de Baud de UART

La forma más fácil de identificar la tasa de baud correcta es observar la **salida del pin TX y tratar de leer los datos**. Si los datos que recibes no son legibles, cambia a la siguiente tasa de baud posible hasta que los datos se vuelvan legibles. Puedes usar un adaptador USB a serie o un dispositivo multipropósito como Bus Pirate para hacer esto, junto con un script auxiliar, como [baudrate.py](https://github.com/devttys0/baudrate/). Las tasas de baud más comunes son 9600, 38400, 19200, 57600 y 115200.

> [!CAUTION]
> ¡Es importante notar que en este protocolo necesitas conectar el TX de un dispositivo al RX del otro!

## Adaptador CP210X UART a TTY

El chip CP210X se utiliza en muchas placas de prototipado como NodeMCU (con esp8266) para comunicación serial. Estos adaptadores son relativamente económicos y se pueden usar para conectarse a la interfaz UART del objetivo. El dispositivo tiene 5 pines: 5V, GND, RXD, TXD, 3.3V. Asegúrate de conectar el voltaje según lo soportado por el objetivo para evitar daños. Finalmente, conecta el pin RXD del adaptador al TXD del objetivo y el pin TXD del adaptador al RXD del objetivo.

En caso de que el adaptador no sea detectado, asegúrate de que los controladores CP210X estén instalados en el sistema host. Una vez que el adaptador sea detectado y conectado, se pueden usar herramientas como picocom, minicom o screen.

Para listar los dispositivos conectados a sistemas Linux/MacOS:
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
Configura los ajustes como la velocidad en baudios y el nombre del dispositivo en la opción `Serial port setup`.

Después de la configuración, usa el comando `minicom` para iniciar la Consola UART.

## UART a través de Arduino UNO R3 (Placas de chip Atmel 328p removibles)

En caso de que no estén disponibles adaptadores de UART Serial a USB, se puede usar Arduino UNO R3 con un hack rápido. Dado que Arduino UNO R3 suele estar disponible en cualquier lugar, esto puede ahorrar mucho tiempo.

Arduino UNO R3 tiene un adaptador USB a Serial integrado en la placa. Para obtener conexión UART, simplemente desconecta el chip microcontrolador Atmel 328p de la placa. Este hack funciona en variantes de Arduino UNO R3 que tienen el Atmel 328p no soldado en la placa (se utiliza la versión SMD). Conecta el pin RX de Arduino (Pin Digital 0) al pin TX de la interfaz UART y el pin TX de Arduino (Pin Digital 1) al pin RX de la interfaz UART.

Finalmente, se recomienda usar Arduino IDE para obtener la Consola Serial. En la sección `tools` del menú, selecciona la opción `Serial Console` y establece la velocidad en baudios según la interfaz UART.

## Bus Pirate

En este escenario, vamos a espiar la comunicación UART del Arduino que está enviando todas las impresiones del programa al Monitor Serial.
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
## Volcado de Firmware con Consola UART

La Consola UART proporciona una excelente manera de trabajar con el firmware subyacente en un entorno de ejecución. Pero cuando el acceso a la Consola UART es de solo lectura, puede introducir muchas limitaciones. En muchos dispositivos embebidos, el firmware se almacena en EEPROM y se ejecuta en procesadores que tienen memoria volátil. Por lo tanto, el firmware se mantiene en solo lectura ya que el firmware original durante la fabricación está dentro de la EEPROM misma y cualquier archivo nuevo se perdería debido a la memoria volátil. Por lo tanto, volcar firmware es un esfuerzo valioso al trabajar con firmwares embebidos.

Hay muchas maneras de hacer esto y la sección de SPI cubre métodos para extraer firmware directamente de la EEPROM con varios dispositivos. Sin embargo, se recomienda primero intentar volcar el firmware con UART, ya que volcar firmware con dispositivos físicos e interacciones externas puede ser arriesgado.

Volcar firmware desde la Consola UART requiere primero obtener acceso a los bootloaders. Muchos proveedores populares utilizan uboot (Universal Bootloader) como su bootloader para cargar Linux. Por lo tanto, obtener acceso a uboot es necesario.

Para obtener acceso al bootloader, conecta el puerto UART a la computadora y utiliza cualquiera de las herramientas de Consola Serial y mantén desconectada la fuente de alimentación del dispositivo. Una vez que la configuración esté lista, presiona la tecla Enter y mantenla presionada. Finalmente, conecta la fuente de alimentación al dispositivo y déjalo arrancar.

Hacer esto interrumpirá la carga de uboot y proporcionará un menú. Se recomienda entender los comandos de uboot y usar el menú de ayuda para listarlos. Este podría ser el comando `help`. Dado que diferentes proveedores utilizan diferentes configuraciones, es necesario entender cada una de ellas por separado.

Por lo general, el comando para volcar el firmware es:
```
md
```
que significa "volcado de memoria". Esto volcará la memoria (contenido de EEPROM) en la pantalla. Se recomienda registrar la salida de la Consola Serial antes de comenzar el procedimiento para capturar el volcado de memoria.

Finalmente, simplemente elimina todos los datos innecesarios del archivo de registro y guarda el archivo como `filename.rom` y usa binwalk para extraer los contenidos:
```
binwalk -e <filename.rom>
```
Esto enumerará los posibles contenidos de la EEPROM según las firmas encontradas en el archivo hex.

Sin embargo, es necesario señalar que no siempre es el caso que el uboot esté desbloqueado, incluso si se está utilizando. Si la tecla Enter no hace nada, verifica diferentes teclas como la tecla Espacio, etc. Si el bootloader está bloqueado y no se interrumpe, este método no funcionará. Para verificar si uboot es el bootloader del dispositivo, revisa la salida en la Consola UART mientras se inicia el dispositivo. Puede mencionar uboot durante el arranque.

{{#include ../../banners/hacktricks-training.md}}
