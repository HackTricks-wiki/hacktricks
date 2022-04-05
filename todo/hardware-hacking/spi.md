# SPI

## Basic Information

## Dump Flash

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (201).png>)

Note that even if the PINOUT of the Pirate Bus indicates pins for **MOSI** and **MISO** to connect to SPI however some SPIs may indicate pins as DI and DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (648).png>)

In Windows or Linux you can use the program [**`flashrom`**](https://www.flashrom.org/Flashrom)  to dump the content of the flash memory running something like:

```bash
# In this command we are indicating:
## -VV Verbose
## -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
## -p <programmer> In this case how to contact th chip via the Bus Pirate
## -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
