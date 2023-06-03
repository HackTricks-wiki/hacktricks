# Información Básica

UART es un protocolo serial, lo que significa que transfiere datos entre componentes un bit a la vez. En contraste, los protocolos de comunicación paralelos transmiten datos simultáneamente a través de múltiples canales. Los protocolos seriales comunes incluyen RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express y USB.

Generalmente, la línea se mantiene alta (en un valor lógico 1) mientras UART está en estado inactivo. Luego, para señalar el inicio de una transferencia de datos, el transmisor envía un bit de inicio al receptor, durante el cual la señal se mantiene baja (en un valor lógico 0). A continuación, el transmisor envía de cinco a ocho bits de datos que contienen el mensaje real, seguido de un bit de paridad opcional y uno o dos bits de parada (con un valor lógico 1), dependiendo de la configuración. El bit de paridad, utilizado para la comprobación de errores, rara vez se ve en la práctica. El bit de parada (o bits) indica el final de la transmisión.

Llamamos a la configuración más común 8N1: ocho bits de datos, sin paridad y un bit de parada. Por ejemplo, si quisiéramos enviar el carácter C, o 0x43 en ASCII, en una configuración UART 8N1, enviaríamos los siguientes bits: 0 (el bit de inicio); 0, 1, 0, 0, 0, 0, 1, 1 (el valor de 0x43 en binario) y 0 (el bit de parada).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Herramientas de hardware para comunicarse con UART:

* Adaptador USB a serie
* Adaptadores con los chips CP2102 o PL2303
* Herramienta multipropósito como: Bus Pirate, el Adafruit FT232H, el Shikra o el Attify Badge

## Identificación de los puertos UART

UART tiene 4 puertos: **TX** (Transmitir), **RX** (Recibir), **Vcc** (Voltaje) y **GND** (Tierra). Es posible que pueda encontrar 4 puertos con las letras **`TX`** y **`RX`** **escritas** en la PCB. Pero si no hay indicación, es posible que deba intentar encontrarlos usted mismo usando un **multímetro** o un **analizador lógico**.

Con un **multímetro** y el dispositivo apagado:

* Para identificar el pin **GND** use el modo de **Prueba de continuidad**, coloque el cable negro en tierra y pruebe con el rojo hasta que escuche un sonido del multímetro. Varios pines GND se pueden encontrar en la PCB, por lo que es posible que haya encontrado o no el que pertenece a UART.
* Para identificar el puerto **VCC**, configure el modo de **voltaje DC** y ajústelo a 20 V de voltaje. Sonda negra en tierra y sonda roja en el pin. Encienda el dispositivo. Si el multímetro mide un voltaje constante de 3,3 V o 5 V, ha encontrado el pin Vcc. Si obtiene otros voltajes, vuelva a intentarlo con otros puertos.
* Para identificar el puerto **TX**, modo de **voltaje DC** hasta 20 V de voltaje, sonda negra en tierra y sonda roja en el pin, y encienda el dispositivo. Si encuentra que el voltaje fluctúa durante unos segundos y luego se estabiliza en el valor Vcc, es probable que haya encontrado el puerto TX. Esto se debe a que al encenderlo, envía algunos datos de depuración.
* El **puerto RX** sería el más cercano a los otros 3, tiene la fluctuación de voltaje más baja y el valor general más bajo de todos los pines UART.

Puede confundir los puertos TX y RX y no sucederá nada, pero si confunde el puerto GND y el puerto VCC, podría dañar el circuito.

Con un analizador lógico:

## Identificación de la velocidad de baudios UART

La forma más fácil de identificar la velocidad de baudios correcta es mirar la **salida del pin TX y tratar de leer los datos**. Si los datos que recibe no son legibles, cambie a la siguiente velocidad de baudios posible hasta que los datos sean legibles. Puede usar un adaptador USB a serie o un dispositivo multipropósito como Bus Pirate para hacer esto, emparejado con un script de ayuda, como [baudrate.py](https://github.com/devttys0/baudrate/). Las velocidades de baudios más comunes son 9600, 38400, 19200, 57600 y 115200.

{% hint style="danger" %}
¡Es importante tener en cuenta que en este protocolo necesita conectar el TX de un dispositivo al RX del otro!
{% endhint %}

# Bus Pirate

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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
