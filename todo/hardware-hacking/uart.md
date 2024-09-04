# UART

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Basic Information

UART is a serial protocol, which means it transfers data between components one bit at a time. In contrast, parallel communication protocols transmit data simultaneously through multiple channels. Common serial protocols include RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, and USB.

Generally, the line is held high (at a logical 1 value) while UART is in the idle state. Then, to signal the start of a data transfer, the transmitter sends a start bit to the receiver, during which the signal is held low (at a logical 0 value). Next, the transmitter sends five to eight data bits containing the actual message, followed by an optional parity bit and one or two stop bits (with a logical 1 value), depending on the configuration. The parity bit, used for error checking, is rarely seen in practice. The stop bit (or bits) signify the end of transmission.

We call the most common configuration 8N1: eight data bits, no parity, and one stop bit. For example, if we wanted to send the character C, or 0x43 in ASCII, in an 8N1 UART configuration, we would send the following bits: 0 (the start bit); 0, 1, 0, 0, 0, 0, 1, 1 (the value of 0x43 in binary), and 0 (the stop bit).

![](<../../.gitbook/assets/image (764).png>)

Hardware tools to communicate with UART:

* USB-to-serial adapter
* Adapters with the CP2102 or PL2303 chips
* Multipurpose tool such as: Bus Pirate, the Adafruit FT232H, the Shikra, or the Attify Badge

### Identifying UART Ports

UART has 4 ports: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage), and **GND**(Ground). You might be able to find 4 ports with the **`TX`** and **`RX`** letters **written** in the PCB. But if there is no indication, you might need to try to find them yourself using a **multimeter** or a **logic analyzer**.

With a **multimeter** and the device powered off:

* To identify the **GND** pin use the **Continuity Test** mode, place the back lead into ground and test with the red one until you hear a sound from the multimeter. Several GND pins can be found the PCB, so you might have found or not the one belonging to UART.
* To identify the **VCC port**, set the **DC voltage mode** and set it up to 20 V of voltage. Black probe on ground and red probe on the pin. Power on the device. If the multimeter measures a constant voltage of either 3.3 V or 5 V, you’ve found the Vcc pin. If you get other voltages, retry with other ports.
* To identify the **TX** **port**, **DC voltage mode** up to 20 V of voltage, black probe on ground, and red probe on the pin, and power on the device. If you find the voltage fluctuates for a few seconds and then stabilizes at the Vcc value, you’ve most likely found the TX port. This is because when powering on, it sends some debug data.
* The **RX port** would be the closest one to the other 3, it has the lowest voltage fluctuation and lowest overall value of all the UART pins.

You can confuse the TX and RX ports and nothing would happen, but if you confuses the GND and the VCC port you might fry the circuit.

In some target devices, the UART port is disabled by the manufacturer by disabling RX or TX or even both. In that case, it can be helpful to trace down the connections in the circuit board and finding some breakout point. A strong hint about confirming no detection of UART and breaking of the circuit is to check the device warranty. If the device has been shipped with some warranty, the manufacturer leaves some debug interfaces (in this case, UART) and hence, must have disconnected the UART and would attach it again while debugging. These breakout pins can be connected by soldering or jumper wires.

### Identifying the UART Baud Rate

The easiest way to identify the correct baud rate is to look at the **TX pin’s output and try to read the data**. If the data you receive isn’t readable, switch to the next possible baud rate until the data becomes readable. You can use a USB-to-serial adapter or a multipurpose device like Bus Pirate to do this, paired with a helper script, such as [baudrate.py](https://github.com/devttys0/baudrate/). The most common baud rates are 9600, 38400, 19200, 57600, and 115200.

{% hint style="danger" %}
It's important to note that in this protocol you need to connect the TX of one device to the RX of the other!
{% endhint %}

## CP210X UART to TTY Adapter

The CP210X Chip is used in a lot of prototyping boards like NodeMCU (with esp8266) for Serial Communication. These adapters are relatively inexpensive and can be used to connect to the UART interface of the target. The device has 5 pins: 5V, GND, RXD, TXD, 3.3V. Make sure to connect the voltage as supported by the target to avoid any damage. Finally connect the RXD pin of the Adapter to TXD of the target and TXD pin of the Adapter to RXD of the target.

Incase the adapter is not detected, make sure that the CP210X drivers are installed in the host system. Once the adapter is detected and connected, tools like picocom, minicom or screen can be used.

To list the devices connected to Linux/MacOS systems:

```
ls /dev/
```

For basic interaction with the UART interface, use the following command:

```
picocom /dev/<adapter> --baud <baudrate>
```

For minicom, use the following command to configure it:

```
minicom -s
```

Configure the settings such as baudrate and device name in the `Serial port setup` option.

After configuration, use the command `minicom` to start get the UART Console.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Incase UART Serial to USB adapters are not available, Arduino UNO R3 can be used with a quick hack. Since Arduino UNO R3 is usually available anywhere, this can save a lot of time.

Arduino UNO R3 has a USB to Serial adapter built on the board itself. To get UART connection, just plug out the Atmel 328p microcontroller chip from the board. This hack works on Arduino UNO R3 variants having the Atmel 328p not soldered on the board (SMD version is used in it). Connect the RX pin of Arduino (Digital Pin 0) to the TX pin of the UART Interface and TX pin of the Arduino (Digital Pin 1) to the RX pin of the UART interface.

Finally, it is recommended to use Arduino IDE to get the Serial Console. In the `tools` section in the menu, select `Serial Console` option and set the baud rate as per the UART interface.

## Bus Pirate

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

## Dumping Firmware with UART Console

UART Console provides a great way to work with the underlying firmware in runtime environment. But when the UART Console access is read-only, it might introduce a lot of constrains. In many embedded devices, the firmware is stored in EEPROMs and executed in processors that have volatile memory. Hence, the firmware is kept read-only since the original firmware during manufacturing is inside the EEPROM itself and any new files would get lost due to volatile memory. Hence, dumping firmware is a valuable effort while working with embedded firmwares.

There are a lot of ways to do this and the SPI section covers methods to extract firmware directly from the EEPROM with various devices. Although, it is recommended to first try dumping firmware with UART since dumping firmware with physical devices and external interactions can be risky.

Dumping firmware from UART Console requires first getting access to bootloaders. Many popular vendors make use of uboot (Universal Bootloader) as their bootloader to load Linux. Hence, getting access to uboot is necessary.

To get access to boot bootloader, connect the UART port to the computer and use any of the Serial Console tools and keep the power supply to the device disconnected. Once the setup is ready, press the Enter Key and hold it. Finally, connect the power supply to the device and let it boot.

Doing this will interrupt uboot from loading and will provide a menu. It is recommended to understand uboot commands and using help menu to list them. This might be `help` command. Since different vendors use different configurations, it is necessary to understand each of them seperately.

Usually, the command to dump the firmware is:

```
md
```

which stands for "memory dump". This will dump the memory (EEPROM Content) on the screen. It is recommended to log the Serial Console output before starting the proceedure to capture the memory dump.

Finally, just strip out all the unnecessary data from the log file and store the file as `filename.rom` and use binwalk to extract the contents:

```
binwalk -e <filename.rom>
```

This will list the possible contents from the EEPROM as per the signatures found in the hex file.

Although, it is necessary to note that it's not always the case that the uboot is unlocked even if it is being used. If the Enter Key doesn't do anything, check for different keys like Space Key, etc. If the bootloader is locked and does not get interrupted, this method would not work. To check if uboot is the bootloader for the device, check the output on the UART Console while booting of the device. It might mention uboot while booting.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
