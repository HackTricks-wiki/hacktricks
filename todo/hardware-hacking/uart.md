<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al grupo de** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Información Básica

UART es un protocolo serie, lo que significa que transfiere datos entre componentes un bit a la vez. En contraste, los protocolos de comunicación paralela transmiten datos simultáneamente a través de múltiples canales. Protocolos seriales comunes incluyen RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express y USB.

Generalmente, la línea se mantiene alta (con un valor lógico de 1) mientras UART está en estado de reposo. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (con un valor lógico de 0). A continuación, el transmisor envía de cinco a ocho bits de datos que contienen el mensaje real, seguido de un bit de paridad opcional y uno o dos bits de parada (con un valor lógico de 1), dependiendo de la configuración. El bit de paridad, utilizado para la comprobación de errores, rara vez se ve en la práctica. El bit de parada (o bits) señala el fin de la transmisión.

Llamamos a la configuración más común 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en una configuración UART 8N1, enviaríamos los siguientes bits: 0 (el bit de inicio); 0, 1, 0, 0, 0, 0, 1, 1 (el valor de 0x43 en binario), y 1 (el bit de parada).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Herramientas de hardware para comunicarse con UART:

* Adaptador USB-a-serial
* Adaptadores con los chips CP2102 o PL2303
* Herramienta multipropósito como: Bus Pirate, el Adafruit FT232H, el Shikra o el Attify Badge

## Identificación de Puertos UART

UART tiene 4 puertos: **TX** (Transmitir), **RX** (Recibir), **Vcc** (Voltaje) y **GND** (Tierra). Podrías ser capaz de encontrar 4 puertos con las letras **`TX`** y **`RX`** **escritas** en la PCB. Pero si no hay indicación, podrías necesitar intentar encontrarlos tú mismo usando un **multímetro** o un **analizador lógico**.

Con un **multímetro** y el dispositivo apagado:

* Para identificar el pin **GND** usa el modo **Prueba de Continuidad**, coloca el cable negro en tierra y prueba con el rojo hasta que escuches un sonido del multímetro. Varios pines GND pueden encontrarse en la PCB, así que podrías haber encontrado o no el que pertenece a UART.
* Para identificar el puerto **VCC**, configura el modo de **voltaje DC** y ajústalo a 20 V de voltaje. Sonda negra en tierra y sonda roja en el pin. Enciende el dispositivo. Si el multímetro mide un voltaje constante de 3.3 V o 5 V, has encontrado el pin Vcc. Si obtienes otros voltajes, reintenta con otros puertos.
* Para identificar el puerto **TX**, modo de **voltaje DC** hasta 20 V de voltaje, sonda negra en tierra y sonda roja en el pin, y enciende el dispositivo. Si encuentras que el voltaje fluctúa por unos segundos y luego se estabiliza en el valor de Vcc, lo más probable es que hayas encontrado el puerto TX. Esto se debe a que al encender, envía algunos datos de depuración.
* El puerto **RX** sería el más cercano a los otros 3, tiene la fluctuación de voltaje más baja y el valor general más bajo de todos los pines UART.

Puedes confundir los puertos TX y RX y no pasaría nada, pero si confundes los puertos GND y VCC podrías quemar el circuito.

Con un analizador lógico:

## Identificación de la Tasa de Baudios UART

La forma más fácil de identificar la tasa de baudios correcta es mirar la salida del pin **TX e intentar leer los datos**. Si los datos que recibes no son legibles, cambia a la siguiente tasa de baudios posible hasta que los datos se vuelvan legibles. Puedes usar un adaptador USB-a-serial o un dispositivo multipropósito como Bus Pirate para hacer esto, junto con un script de ayuda, como [baudrate.py](https://github.com/devttys0/baudrate/). Las tasas de baudios más comunes son 9600, 38400, 19200, 57600 y 115200.

{% hint style="danger" %}
Es importante notar que en este protocolo necesitas conectar el TX de un dispositivo al RX del otro.
{% endhint %}

# Bus Pirate

En este escenario vamos a espiar la comunicación UART del Arduino que está enviando todas las impresiones del programa al Monitor Serial.
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
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue**me en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
