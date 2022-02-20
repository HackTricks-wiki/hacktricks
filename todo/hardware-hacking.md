# Hardware Hacking

## UART

UART is a serial protocol, which means it transfers data between components one bit at a time. In contrast, parallel communication protocols transmit data simultaneously through multiple channels. Common serial protocols include RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, and USB.

Generally, the line is held high (at a logical 1 value) while UART is in the idle state. Then, to signal the start of a data transfer, the transmitter sends a start bit to the receiver, during which the signal is held low (at a logical 0 value). Next, the transmitter sends five to eight data bits containing the actual message, followed by an optional parity bit and one or two stop bits (with a logical 1 value), depending on the configuration. The parity bit, used for error checking, is rarely seen in practice. The stop bit (or bits) signify the end of transmission.

We call the most common configuration 8N1: eight data bits, no parity, and one stop bit. For example, if we wanted to send the character C, or 0x43 in ASCII, in an 8N1 UART configuration, we would send the following bits: 0 (the start bit); 0, 1, 0, 0, 0, 0, 1, 1 (the value of 0x43 in binary), and 0 (the stop bit).

![](<../.gitbook/assets/image (648).png>)

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

With a logic analyzer:

### Identifying the UART Baud Rate

The easiest way to identify the correct baud rate is to look at the **TX pin’s output and try to read the data**. If the data you receive isn’t readable, switch to the next possible baud rate until the data becomes readable. You can use a USB-to-serial adapter or a multipurpose device like Bus Pirate to do this, paired with a helper script, such as [baudrate.py](https://github.com/devttys0/baudrate/). The most common baud rates are 9600, 38400, 19200, 57600, and 115200.

## JTAG

JTAG allows to perform a boundary scan. The boundary scan analyzes certain circuitry, including embedded boundary-scan cells and registers for each pin.

The JTAG standard defines **specific commands for conducting boundary scans**, including the following:

* **BYPASS** allows you to test a specific chip without the overhead of passing through other chips.
* **SAMPLE/PRELOAD** takes a sample of the data entering and leaving the device when it’s in its normal functioning mode.
* **EXTEST** sets and reads pin states.

It can also support other commands such as:

* **IDCODE** for identifying a device
* **INTEST** for the internal testing of the device

You might come across these instructions when you use a tool like the JTAGulator.

### The Test Access Port

Boundary scans include tests of the four-wire **Test Access Port (TAP)**, a general-purpose port that provides **access to the JTAG test support** functions built into a component. TAP uses the following five signals:

* Test clock input (**TCK**) The TCK is the **clock** that defines how often the TAP controller will take a single action (in other words, jump to the next state in the state machine).
* Test mode select (**TMS**) input TMS controls the **finite state machine**. On each beat of the clock, the device’s JTAG TAP controller checks the voltage on the TMS pin. If the voltage is below a certain threshold, the signal is considered low and interpreted as 0, whereas if the voltage is above a certain threshold, the signal is considered high and interpreted as 1.
* Test data input (**TDI**) TDI is the pin that sends **data into the chip through the scan cells**. Each vendor is responsible for defining the communication protocol over this pin, because JTAG doesn’t define this.
* Test data output (**TDO**) TDO is the pin that sends **data out of the chip**.
* Test reset (**TRST**) input The optional TRST resets the finite state machine **to a known good state**. Alternatively, if the TMS is held at 1 for five consecutive clock cycles, it invokes a reset, the same way the TRST pin would, which is why TRST is optional.

Sometimes you will be able to find those pins marked in the PCB. In other occasions you might need to **find them**.&#x20;

### Identifying JTAG pins

The fastest but most expensive way to detect JTAG ports is by using the **JTAGulator**, a device created specifically for this purpose (although it can **also detect UART pinouts**).

It has **24 channels** you can connect to the boards pins. Then it performs a **BF attack** of all the possible combinations sending **IDCODE** and **BYPASS** boundary scan commands. If it receives a response, it displays the channel corresponding to each JTAG signal

A cheaper but much slower way of identifying JTAG pinouts is by using the [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) **** loaded on an Arduino-compatible microcontroller.

Using **JTAGenum**, you’d first **define the pins of the probing** device that you’ll use for the enumeration.You’d have to reference the device’s pinout diagram, and then connect these pins with the test points on your target device.

A **third way** to identify JTAG pins is by **inspecting the PCB** for one of the pinouts. In some cases, PCBs might conveniently provide the **Tag-Connect interface**, which is a clear indication that the board has a JTAG connector, too. You can see what that interface looks like at [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Additionally, inspecting the **datasheets of the chipsets on the PCB** might reveal pinout diagrams that point to JTAG interfaces.

## SDW

SWD is an ARM-specific protocol designed for debugging.

The SWD interface requires **two pins**: a bidirectional **SWDIO** signal, which is the equivalent of JTAG’s **TDI and TDO pins and a clock**, and **SWCLK**, which is the equivalent of **TCK** in JTAG. Many devices support the **Serial Wire or JTAG Debug Port (SWJ-DP)**, a combined JTAG and SWD interface that enables you to connect either a SWD or JTAG probe to the target.
