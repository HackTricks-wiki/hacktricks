# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Verifieer die teikenspanning, pen-uitleg, pull-up-konfigurasie en gemeenskaplike grond voordat jy ’n Bus Pirate koppel. Moenie die Bus Pirate se kragtoevoer op ’n lewendige, teikengevoede bus aktiveer bloot om dit te sniff nie; twee kragtoevoere kan meeding en hardeware beskadig. Die transkripsie hieronder is ’n toestelspesifieke Bus Pirate v3/community-firmware-voorbeeld, nie ’n universele bedradingsresep nie.<sup>[[1]](#references)[[2]](#references)</sup>

Om te toets of ’n Bus Pirate werk, koppel +5V aan VPU en 3.3V aan ADC, kry toegang tot die bus pirate (byvoorbeeld met Tera Term) en gebruik die bevel `~`:
```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```
Soos jy in die vorige command line kan sien, het dit aangedui dat dit 0 foute gevind het. Dit is baie nuttig om te weet dat dit werk nadat jy dit gekoop het of nadat jy ’n firmware geflits het.

Om met die bus pirate te koppel, kan jy die dokumentasie volg:

![Gebruik command - Druk spasie: Om met die bus pirate te koppel, kan jy die dokumentasie volg](<../../images/image (484).png>)

In hierdie geval is die teiken ’n 24C256-familie-I²C EEPROM. Bevestig die presiese agtervoegsel/datasheet, want die ondersteunde toevoerspanning verskil volgens die onderdeel.<sup>[[3]](#references)</sup>

![Gebruik command - Druk spasie: In hierdie geval gaan ek aan ’n EPROM koppel: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Om met bus pirate te kommunikeer, het ek Tera Term gebruik, gekoppel aan die pirate bus COM-poort met Setup --> Serial Port --> Speed op 115200.\
In die volgende kommunikasie kan jy sien hoe om die bus pirate voor te berei om met I2C te kommunikeer, asook hoe om na die geheue te skryf en daaruit te lees (Kommentaar verskyn met “#”; moenie verwag dat daardie deel in die kommunikasie sal verskyn nie):
```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
1. Software
2. Hardware

# Select Software mode
(1)>1
Set speed:
1. ~5kHz
2. ~50kHz
3. ~100kHz
4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
0.Macro menu
1.7bit address search
2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```
### Sniffer

In hierdie scenario gaan ons die I2C-kommunikasie tussen die arduino en die vorige EPROM sniff; jy hoef net met albei toestelle te kommunikeer en dan die bus pirate aan die SCL-, SDA- en GND-penne te koppel:

![Lees 20B vanaf adres 0x69 wat vooraf gekonfigureer is - Sniffer: In hierdie scenario gaan ons die I2C-kommunikasie tussen die arduino en die vorige EPROM sniff; jy hoef net...](<../../images/image (166).png>)
```bash
I2C>m
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

(1)>4
I2C mode:
1. Software
2. Hardware

(1)>1
Set speed:
1. ~5kHz
2. ~50kHz
3. ~100kHz
4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```
## References

- [1] [Bus Pirate-dokumentasie — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus-spesifikasie en gebruikershandleiding](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C-seriële EEPROM-datablad](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
{{#include ../../banners/hacktricks-training.md}}
