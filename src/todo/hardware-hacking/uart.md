# UART

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

UART is an asynchronous serial interface that transfers a framed stream of bits without a shared clock. Do not confuse logic-level UART with RS-232: RS-232 uses different, often negative, voltage levels and requires a transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Generally, the line is held high (at a logical 1 value) while UART is in the idle state. Then, to signal the start of a data transfer, the transmitter sends a start bit to the receiver, during which the signal is held low (at a logical 0 value). Next, the transmitter sends five to eight data bits containing the actual message, followed by an optional parity bit and one or two stop bits (with a logical 1 value), depending on the configuration. The parity bit, used for error checking, is rarely seen in practice. The stop bit (or bits) signify the end of transmission.

The most common configuration is 8N1: eight data bits, no parity, and one stop bit. UART sends the least-significant data bit first, so ASCII `C` (`0x43`) is transmitted as: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: We call the most common configuration 8N1: eight data bits, no parity, and one stop bit. For example, if we wanted to send the character C, or 0x43 in ASCII, in an 8N1 UART](<../../images/image (764).png>)

Hardware tools to communicate with UART:

- USB-to-serial adapter
- Adapters with the CP2102 or PL2303 chips
- Multipurpose tool such as: Bus Pirate, the Adafruit FT232H, the Shikra, or the Attify Badge

### Identifying UART Ports

A typical debug header exposes **TX**, **RX**, and **GND**; it may also expose a **Vcc/Vref** pin, reset, or flow-control pins. Vcc is not a UART signal and should normally be used only as a voltage reference—not connected as a power source—unless the board's schematic and current requirements are known.<sup>[[2]](#references)[[3]](#references)</sup>

Start with the device **powered off** and disconnected:

- Identify **GND** in continuity mode against a known ground plane, connector shield, or supply ground. Never use continuity/resistance mode on a powered board.
- Switch to DC-voltage mode before powering the target. Measure candidate pins relative to ground to identify the logic voltage. A steady rail may be Vcc/Vref; do not assume it is safe to connect.
- Observe candidates with a logic analyzer or oscilloscope during boot. **TX** commonly idles high and shows bursts of framed data. A multimeter may show an average fluctuation but cannot validate framing or baud rate.
- **RX** may remain idle and cannot be identified safely merely because it is adjacent to TX. Trace the PCB, consult the SoC datasheet, or use a high-impedance analyzer before driving it.

Swapping TX and RX normally produces no communication; confusing power, ground, or signal levels can permanently damage the target or adapter. Connect ground first and begin **receive-only** (target TX to adapter RX).

Manufacturers may omit the header, leave series resistors unpopulated, disable the console in firmware, or expose only TX. Trace nearby test pads and resistor footprints to the SoC and add a temporary high-impedance connection only after confirming the electrical level. The presence of a warranty does not imply that an accessible UART must exist.

### Identifying the UART Baud Rate

The easiest way to identify the correct baud rate is to look at the **TX pin’s output and try to read the data**. If the data you receive isn’t readable, switch to the next possible baud rate until the data becomes readable. You can use a USB-to-serial adapter or a multipurpose device like Bus Pirate to do this, paired with a helper script, such as [baudrate.py](https://github.com/devttys0/baudrate/). The most common baud rates are 9600, 38400, 19200, 57600, and 115200.

> [!CAUTION]
> It's important to note that in this protocol you need to connect the TX of one device to the RX of the other!

## CP210X UART to TTY Adapter

CP210x USB-to-UART bridges appear on many prototyping boards and inexpensive adapters. Common modules expose supply pins alongside GND, RXD, and TXD, but their headers and I/O levels vary. Confirm the actual voltage from the board design or data sheet. Usually connect only GND, adapter RX to target TX, and—after receive-only validation—adapter TX to target RX. Do not connect the adapter's 5 V/3.3 V supply pin unless intentionally powering a target known to tolerate it.<sup>[[3]](#references)</sup>

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

After configuration, run `minicom` to open the UART console.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Incase UART Serial to USB adapters are not available, Arduino UNO R3 can be used with a quick hack. Since Arduino UNO R3 is usually available anywhere, this can save a lot of time.

Arduino UNO R3 has a USB to Serial adapter built on the board itself. To get UART connection, just plug out the Atmel 328p microcontroller chip from the board. This hack works on Arduino UNO R3 variants having the Atmel 328p not soldered on the board (SMD version is used in it). Connect the RX pin of Arduino (Digital Pin 0) to the TX pin of the UART Interface and TX pin of the Arduino (Digital Pin 1) to the RX pin of the UART interface.

Use the Arduino IDE **Serial Monitor** or a dedicated terminal at the target baud rate. Classic Uno R3 serial signals are 5 V logic, so use a level shifter or divider before connecting them to a 3.3 V or lower-voltage target.

## Bus Pirate

The following transcript uses the legacy Bus Pirate firmware interface to monitor UART output. Newer Bus Pirate firmware uses commands such as `m uart`, `{`/`}`, `monitor`, or `bridge`; consult the documentation for the installed version.<sup>[[2]](#references)</sup>

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

A UART console provides runtime access to boot logs and, sometimes, a bootloader or operating-system shell. A read-only console still reveals memory maps, flash drivers, boot arguments, partition layouts, and firmware versions. Firmware may live in SPI NOR/NAND, eMMC, or another device; it is not generally executed from an EEPROM, and files written to a mounted persistent filesystem do not necessarily disappear on reboot.

There are several acquisition paths, and the SPI section covers direct reads from external flash. Console-assisted acquisition can be less invasive when the bootloader already provides a safe read command, but any boot interruption or flash command can affect availability, so record the original state and avoid write/erase operations.

Console-assisted firmware dumping often begins by interrupting a bootloader. Many embedded Linux devices use **Das U-Boot**, but others use proprietary bootloaders or disable the interactive console.

To test for an interactive bootloader, connect the UART receive path and terminal while the target is unpowered, start logging, and power it on. Follow the displayed autoboot prompt; depending on the build, interruption may require a key, a short sequence, or may be disabled entirely.

If interruption succeeds, use `help`, `printenv`, and read-only discovery commands to understand that vendor's memory and storage layout before accessing addresses.

In U-Boot, `md` displays **addressable memory**, not automatically “the EEPROM.” First use board-specific commands such as `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables, and boot logs to identify the correct mapped address or load a flash region into RAM. Then display a known range byte-by-byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Log the serial output before starting. The `md.b` output contains addresses and an ASCII column, so it is a textual representation rather than a raw ROM image.

Strip the address and ASCII columns, concatenate only the hexadecimal byte fields, and decode them to binary (for example with `xxd -r -p`). Verify the expected byte count and record a hash before analysis:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk then identifies known signatures in the reconstructed binary. A direct flash read through the appropriate SPI/eMMC/NAND interface is usually faster and less error-prone when the console cannot transfer data reliably.

U-Boot may disable interruption, require a vendor-specific key sequence, or lock memory/flash commands. Follow the autoboot prompt and boot log rather than blindly transmitting characters. If the console cannot be interrupted, retain the boot log and move to a non-invasive firmware acquisition path.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)

{{#include ../../banners/hacktricks-training.md}}
