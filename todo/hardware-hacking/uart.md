# UART

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares de robo**.

El objetivo principal de WhiteIntel es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}

---

## Información Básica

UART es un protocolo serial, lo que significa que transfiere datos entre componentes un bit a la vez. En contraste, los protocolos de comunicación paralela transmiten datos simultáneamente a través de múltiples canales. Los protocolos seriales comunes incluyen RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express y USB.

Generalmente, la línea se mantiene alta (en un valor lógico 1) mientras UART está en estado inactivo. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (en un valor lógico 0). A continuación, el transmisor envía cinco a ocho bits de datos que contienen el mensaje real, seguido de un bit de paridad opcional y uno o dos bits de parada (con un valor lógico 1), dependiendo de la configuración. El bit de paridad, utilizado para la verificación de errores, rara vez se ve en la práctica. El bit de parada (o bits) señala el final de la transmisión.

Llamamos a la configuración más común 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en una configuración UART 8N1, enviaríamos los siguientes bits: 0 (el bit de inicio); 0, 1, 0, 0, 0, 0, 1, 1 (el valor de 0x43 en binario) y 0 (el bit de parada).

![](<../../.gitbook/assets/image (761).png>)

Herramientas de hardware para comunicarse con UART:

* Adaptador USB a serie
* Adaptadores con los chips CP2102 o PL2303
* Herramientas multipropósito como: Bus Pirate, el Adafruit FT232H, el Shikra o el Attify Badge

### Identificación de Puertos UART

UART tiene 4 puertos: **TX** (Transmitir), **RX** (Recibir), **Vcc** (Voltaje) y **GND** (Tierra). Es posible que puedas encontrar 4 puertos con las letras **`TX`** y **`RX`** **escritas** en la PCB. Pero si no hay indicación, es posible que necesites intentar encontrarlos tú mismo usando un **multímetro** o un **analizador lógico**.

Con un **multímetro** y el dispositivo apagado:

* Para identificar el pin **GND** usa el modo de **Prueba de continuidad**, coloca el cable de retorno en tierra y prueba con el cable rojo hasta que escuches un sonido del multímetro. Varios pines GND pueden encontrarse en la PCB, por lo que es posible que hayas encontrado o no el que pertenece a UART.
* Para identificar el puerto **VCC**, configura el modo de **voltaje DC** y ajústalo a 20 V de voltaje. Sonda negra en tierra y sonda roja en el pin. Enciende el dispositivo. Si el multímetro mide un voltaje constante de 3.3 V o 5 V, has encontrado el pin Vcc. Si obtienes otros voltajes, prueba con otros puertos.
* Para identificar el puerto **TX**, modo de **voltaje DC** hasta 20 V de voltaje, sonda negra en tierra y sonda roja en el pin, y enciende el dispositivo. Si encuentras que el voltaje fluctúa durante unos segundos y luego se estabiliza en el valor de Vcc, es probable que hayas encontrado el puerto TX. Esto se debe a que al encenderlo, envía algunos datos de depuración.
* El puerto **RX** sería el más cercano a los otros 3, tiene la menor fluctuación de voltaje y el valor más bajo en general de todos los pines UART.

Puedes confundir los puertos TX y RX y no pasaría nada, pero si confundes el GND y el puerto VCC podrías dañar el circuito.

En algunos dispositivos objetivo, el puerto UART está deshabilitado por el fabricante al desactivar RX o TX o incluso ambos. En ese caso, puede ser útil rastrear las conexiones en la placa de circuito e encontrar algún punto de ruptura. Una pista sólida para confirmar la no detección de UART y la ruptura del circuito es verificar la garantía del dispositivo. Si el dispositivo se ha enviado con alguna garantía, el fabricante deja algunas interfaces de depuración (en este caso, UART) y, por lo tanto, debe haber desconectado el UART y lo volvería a conectar mientras depura. Estos pines de ruptura se pueden conectar soldando o con cables puente.

### Identificación de la Velocidad de Baudios UART

La forma más fácil de identificar la velocidad de baudios correcta es observar la **salida del pin TX y tratar de leer los datos**. Si los datos que recibes no son legibles, cambia a la siguiente velocidad de baudios posible hasta que los datos sean legibles. Puedes usar un adaptador USB a serie o un dispositivo multipropósito como Bus Pirate para hacer esto, junto con un script de ayuda, como [baudrate.py](https://github.com/devttys0/baudrate/). Las velocidades de baudios más comunes son 9600, 38400, 19200, 57600 y 115200.

{% hint style="danger" %}
¡Es importante tener en cuenta que en este protocolo necesitas conectar el TX de un dispositivo al RX del otro!
{% endhint %}

## Adaptador UART a TTY CP210X

El Chip CP210X se utiliza en muchas placas de prototipado como NodeMCU (con esp8266) para Comunicación Serial. Estos adaptadores son relativamente económicos y se pueden utilizar para conectarse a la interfaz UART del objetivo. El dispositivo tiene 5 pines: 5V, GND, RXD, TXD, 3.3V. Asegúrate de conectar el voltaje compatible con el objetivo para evitar cualquier daño. Finalmente, conecta el pin RXD del Adaptador al TXD del objetivo y el pin TXD del Adaptador al RXD del objetivo.

En caso de que el adaptador no sea detectado, asegúrate de que los controladores CP210X estén instalados en el sistema anfitrión. Una vez que el adaptador esté detectado y conectado, se pueden utilizar herramientas como picocom, minicom o screen.

Para listar los dispositivos conectados a sistemas Linux/MacOS:
```
ls /dev/
```
Para la interacción básica con la interfaz UART, utiliza el siguiente comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Para minicom, utiliza el siguiente comando para configurarlo:
```
minicom -s
```
Configura los ajustes como la velocidad de baudios y el nombre del dispositivo en la opción `Configuración del puerto serie`.

Después de la configuración, utiliza el comando `minicom` para iniciar la Consola UART.

## UART a través de Arduino UNO R3 (Placas de Chip Atmel 328p Removibles)

En caso de que los adaptadores UART Serial a USB no estén disponibles, se puede utilizar Arduino UNO R3 con un hack rápido. Dado que Arduino UNO R3 suele estar disponible en cualquier lugar, esto puede ahorrar mucho tiempo.

Arduino UNO R3 tiene un adaptador USB a serie integrado en la placa. Para obtener la conexión UART, simplemente desenchufa el chip microcontrolador Atmel 328p de la placa. Este hack funciona en las variantes de Arduino UNO R3 que no tienen el Atmel 328p soldado en la placa (se utiliza la versión SMD en ella). Conecta el pin RX de Arduino (Pin Digital 0) al pin TX de la interfaz UART y el pin TX de Arduino (Pin Digital 1) al pin RX de la interfaz UART.

Finalmente, se recomienda utilizar Arduino IDE para obtener la Consola Serie. En la sección `herramientas` en el menú, selecciona la opción `Consola Serie` y establece la velocidad de baudios según la interfaz UART.

## Bus Pirate

En este escenario vamos a espiar la comunicación UART del Arduino que está enviando todas las impresiones del programa al Monitor Serie.
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

La Consola UART proporciona una excelente manera de trabajar con el firmware subyacente en el entorno de ejecución. Sin embargo, cuando el acceso a la Consola UART es de solo lectura, puede introducir muchas limitaciones. En muchos dispositivos integrados, el firmware se almacena en EEPROM y se ejecuta en procesadores que tienen memoria volátil. Por lo tanto, el firmware se mantiene en solo lectura, ya que el firmware original durante la fabricación está dentro de la EEPROM misma y cualquier archivo nuevo se perdería debido a la memoria volátil. Por lo tanto, el volcado de firmware es un esfuerzo valioso al trabajar con firmwares integrados.

Hay muchas formas de hacer esto y la sección SPI cubre métodos para extraer firmware directamente de la EEPROM con varios dispositivos. Aunque se recomienda intentar primero volcar el firmware con UART, ya que volcar el firmware con dispositivos físicos e interacciones externas puede ser arriesgado.

Volcar firmware desde la Consola UART requiere primero obtener acceso a los cargadores de arranque. Muchos proveedores populares utilizan <b>uboot</b> (Universal Bootloader) como su cargador de arranque para cargar Linux. Por lo tanto, es necesario obtener acceso a <b>uboot</b>.

Para acceder al cargador de arranque, conecta el puerto UART a la computadora y utiliza cualquiera de las herramientas de Consola Serie y mantén la fuente de alimentación del dispositivo desconectada. Una vez que la configuración esté lista, presiona la tecla Enter y mantenla presionada. Finalmente, conecta la fuente de alimentación al dispositivo y déjalo arrancar.

Al hacer esto, se interrumpirá <b>uboot</b> al cargar y proporcionará un menú. Se recomienda comprender los comandos de <b>uboot</b> y utilizar el menú de ayuda para listarlos. Este podría ser el comando `help`. Dado que diferentes proveedores utilizan diferentes configuraciones, es necesario comprender cada una de ellas por separado.

Por lo general, el comando para volcar el firmware es:
```
md
```
que significa "volcado de memoria". Esto volcará la memoria (contenido de EEPROM) en la pantalla. Se recomienda registrar la salida de la Consola Serial antes de comenzar el procedimiento para capturar el volcado de memoria.

Finalmente, simplemente elimine todos los datos innecesarios del archivo de registro y guárdelo como `nombrearchivo.rom` y use binwalk para extraer el contenido:
```
binwalk -e <filename.rom>
```
Esto listará los posibles contenidos de la EEPROM según las firmas encontradas en el archivo hexadecimal.

Aunque es necesario tener en cuenta que no siempre es el caso de que el <b>uboot</b> esté desbloqueado incluso si se está utilizando. Si la tecla Enter no hace nada, verifique diferentes teclas como la tecla Espacio, etc. Si el cargador de arranque está bloqueado y no se interrumpe, este método no funcionaría. Para verificar si <b>uboot</b> es el cargador de arranque para el dispositivo, verifique la salida en la Consola UART mientras se inicia el dispositivo. Podría mencionar <b>uboot</b> durante el arranque.


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) es un motor de búsqueda alimentado por la **dark web** que ofrece funcionalidades **gratuitas** para verificar si una empresa o sus clientes han sido **comprometidos** por **malwares ladrones**.

Su objetivo principal es combatir los secuestros de cuentas y los ataques de ransomware resultantes de malwares que roban información.

Puedes visitar su sitio web y probar su motor de forma **gratuita** en:

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>Aprende a hackear AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
