

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


# Basic Information

SPI (Serial Peripheral Interface) is an Synchronous Serial Communication Protocol used in embedded systems for short distance communication between ICs (Integrated Circuits). SPI Communication Protocol makes use of the master-slave architecture which is orchastrated by the Clock and Chip Select Signal. A master-slave architecture consists of a master (usually a microprocessor) that manages external peripherals like EEPROM, sensors, control devices, etc. which are considered to be the slaves. 

Multiple slaves can be connected to a master but slaves can't communicate with each other. Slaves are administrated by two pins, clock and chip select. As SPI is an synchronous communication protocol, the input and output pins follow the clock signals. The chip select is used by the master to select a slave and interact with it. When the chip select is high, the slave device is not selected whereas when it's low, the chip has been selected and the master would be interacting with the slave. 

The MOSI (Master Out, Slave In) and MISO (Master In, Slave Out) are responsible for data sending and recieving data. Data is sent to the slave device through the MOSI pin while the chip select is held low. The input data contains instructions, memory addresses or data as per the datasheet of the slave device vendor. Upon a valid input, the MISO pin is responsible for transmitting data to the master. The output data is sent exactly at the next clock cycle after the input ends. The MISO pins transmits data till the data is fully transmitter or the master sets the chip select pin high (in that case, the slave would stop transmitting and master would not listen after that clock cycle). 

# Dump Flash

## Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Note that even if the PINOUT of the Pirate Bus indicates pins for **MOSI** and **MISO** to connect to SPI however some SPIs may indicate pins as DI and DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648) (1) (1).png>)

In Windows or Linux you can use the program [**`flashrom`**](https://www.flashrom.org/Flashrom) to dump the content of the flash memory running something like:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


