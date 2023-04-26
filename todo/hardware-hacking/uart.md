

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Basic Information

UART is a serial protocol, which means it transfers data between components one bit at a time. In contrast, parallel communication protocols transmit data simultaneously through multiple channels. Common serial protocols include RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, and USB.

Generally, the line is held high (at a logical 1 value) while UART is in the idle state. Then, to signal the start of a data transfer, the transmitter sends a start bit to the receiver, during which the signal is held low (at a logical 0 value). Next, the transmitter sends five to eight data bits containing the actual message, followed by an optional parity bit and one or two stop bits (with a logical 1 value), depending on the configuration. The parity bit, used for error checking, is rarely seen in practice. The stop bit (or bits) signify the end of transmission.

We call the most common configuration 8N1: eight data bits, no parity, and one stop bit. For example, if we wanted to send the character C, or 0x43 in ASCII, in an 8N1 UART configuration, we would send the following bits: 0 (the start bit); 0, 1, 0, 0, 0, 0, 1, 1 (the value of 0x43 in binary), and 0 (the stop bit).

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

Hardware tools to communicate with UART:

* USB-to-serial adapter
* Adapters with the CP2102 or PL2303 chips
* Multipurpose tool such as: Bus Pirate, the Adafruit FT232H, the Shikra, or the Attify Badge

## Identifying UART Ports

UART has 4 ports: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage), and **GND**(Ground). You might be able to find 4 ports with the **`TX`** and **`RX`** letters **written** in the PCB. But if there is no indication, you might need to try to find them yourself using a **multimeter** or a **logic analyzer**.

With a **multimeter** and the device powered off:

* To identify the **GND** pin use the **Continuity Test** mode, place the back lead into ground and test with the red one until you hear a sound from the multimeter. Several GND pins can be found the PCB, so you might have found or not the one belonging to UART.
* To identify the **VCC port**, set the **DC voltage mode** and set it up to 20 V of voltage. Black probe on ground and red probe on the pin. Power on the device. If the multimeter measures a constant voltage of either 3.3 V or 5 V, you’ve found the Vcc pin. If you get other voltages, retry with other ports.
* To identify the **TX** **port**, **DC voltage mode** up to 20 V of voltage, black probe on ground, and red probe on the pin, and power on the device. If you find the voltage fluctuates for a few seconds and then stabilizes at the Vcc value, you’ve most likely found the TX port. This is because when powering on, it sends some debug data.
* The **RX port** would be the closest one to the other 3, it has the lowest voltage fluctuation and lowest overall value of all the UART pins.

You can confuse the TX and RX ports and nothing would happen, but if you confuses the GND and the VCC port you might fry the circuit.

With a logic analyzer:

## Identifying the UART Baud Rate

The easiest way to identify the correct baud rate is to look at the **TX pin’s output and try to read the data**. If the data you receive isn’t readable, switch to the next possible baud rate until the data becomes readable. You can use a USB-to-serial adapter or a multipurpose device like Bus Pirate to do this, paired with a helper script, such as [baudrate.py](https://github.com/devttys0/baudrate/). The most common baud rates are 9600, 38400, 19200, 57600, and 115200.

{% hint style="danger" %}
It's important to note that in this protocol you need to connect the TX of one device to the RX of the other!
{% endhint %}

# Bus Pirate

In this scenario we are going to sniff the UART communication of the Arduino that is sending all the prints of the program to the Serial Monitor.

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

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


