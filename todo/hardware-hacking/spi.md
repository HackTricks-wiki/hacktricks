# SPI

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

SPI (Serial Peripheral Interface) is an Synchronous Serial Communication Protocol used in embedded systems for short distance communication between ICs (Integrated Circuits). SPI Communication Protocol makes use of the master-slave architecture which is orchastrated by the Clock and Chip Select Signal. A master-slave architecture consists of a master (usually a microprocessor) that manages external peripherals like EEPROM, sensors, control devices, etc. which are considered to be the slaves.

Multiple slaves can be connected to a master but slaves can't communicate with each other. Slaves are administrated by two pins, clock and chip select. As SPI is an synchronous communication protocol, the input and output pins follow the clock signals. The chip select is used by the master to select a slave and interact with it. When the chip select is high, the slave device is not selected whereas when it's low, the chip has been selected and the master would be interacting with the slave.

The MOSI (Master Out, Slave In) and MISO (Master In, Slave Out) are responsible for data sending and recieving data. Data is sent to the slave device through the MOSI pin while the chip select is held low. The input data contains instructions, memory addresses or data as per the datasheet of the slave device vendor. Upon a valid input, the MISO pin is responsible for transmitting data to the master. The output data is sent exactly at the next clock cycle after the input ends. The MISO pins transmits data till the data is fully transmitter or the master sets the chip select pin high (in that case, the slave would stop transmitting and master would not listen after that clock cycle).

## Dumping Firmware from EEPROMs

Dumping firmware can be useful for analysing the firmware and finding vulnerabilities in them. Often times, the firmware is not available on the internet or is irrelevant due to variations of factors like model number, version, etc. Hence, extracting the firmware directly from the physical device can be helpful to be specific while hunting for threats.

Getting Serial Console can be helpful, but often times it happens that the files are read-only. This constrains the analysis due to various reasons. For example, a tools that are required to send and recieve packages would not be there in the firmware. So extracting the binaries to reverse engineer them is not feasible. Hence, having the whole firmware dumped on the system and extracting the binaries for analysis can be very helpful.

Also, during red reaming and getting physical access to devices, dumping the firmware can help on modifying the files or injecting malicious files and then reflashing them into the memory which could be helpful to implant a backdoor into the device. Hence, there are numerous possibilities that can be unlocked with firmware dumping.

### CH341A EEPROM Programmer and Reader

This device is an inexpensive tool for dumping firmwares from EEPROMs and also reflashing them with firmware files. This has been a popular choice for working with computer BIOS chips (which are just EEPROMs). This device connects over USB and needs minimal tools to get started. Also, it usually gets the task done quickly, so can be helpful in physical device access too.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Connect the EEPROM memory with the CH341a Programmer and plug the device into the computer. Incase the device is not getting detected, try installing drivers into the computer. Also, make sure that the EEPROM is connected in proper orientation (usually, place the VCC Pin in reverse orientation to the USB connector) or else, the software would not be able to detect the chip. Refer to the diagram if required:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Finally, use softwares like flashrom, G-Flash (GUI), etc. for dumping the firmware. G-Flash is a minimal GUI tool is fast and detects the EEPROM automatically. This can be helpful in the firmware needs to be extracted quickly, without much tinkering with the documentation.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

After dumping the firmware, the analysis can be done on the binary files. Tools like strings, hexdump, xxd, binwalk, etc. can be used to extract a lot of information about the firmware as well as the whole file system too.

To extract the contents from the firmware, binwalk can be used. Binwalk analyses for hex signatures and identifies the files in the binary file and is capabale of extracting them.

```
binwalk -e <filename>  
```

The can be .bin or .rom as per the tools and configurations used.

{% hint style="danger" %}
Note that firmware extraction is a delicate process and requires a lot of patience. Any mishandling can potentially corrupt the firmware or even erase it completely and make the device unusable. It is recommended to study the specific device before attempting to extract the firmware.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Note that even if the PINOUT of the Pirate Bus indicates pins for **MOSI** and **MISO** to connect to SPI however some SPIs may indicate pins as DI and DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

In Windows or Linux you can use the program [**`flashrom`**](https://www.flashrom.org/Flashrom) to dump the content of the flash memory running something like:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

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
