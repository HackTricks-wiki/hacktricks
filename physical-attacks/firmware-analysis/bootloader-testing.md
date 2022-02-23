# Bootloader testing

Copied from [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

When modifying device start up and bootloaders such as U-boot, attempt the following:

* Attempt to access the bootloaders interpreter shell by pressing "0", space or other identified “magic codes” during boot.
* Modify configurations to execute a shell command such as adding '`init=/bin/sh`' at the end of boot arguments
  * `#printenv`
  * `#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3`
  * `mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 int=/bin/sh`
  * `#saveenv`
  * `#boot`
* Setup a tftp server to load images over the network locally from your workstation. Ensure the device has network access.
  * `#setenv ipaddr 192.168.2.2 #local IP of the device`
  * `#setenv serverip 192.168.2.1 #tftp server IP`
  * `#saveenv`
  * `#reset`
  * `#ping 192.168.2.1 #check if network access is available`
  * `#tftp ${loadaddr} uImage-3.6.35 #loadaddr takes two arguments: the address to load the file into and the filename of the image on the TFTP server`
* Use `ubootwrite.py` to write the uboot-image and push a modified firmware to gain root
* Check for enabled debug features such as:
  * verbose logging
  * loading arbitrary kernels
  * booting from untrusted sources
* \*Use caution: Connect one pin to ground, watch device boot up sequence, before the kernel decompresses, short/connect the grounded pin to a data pin (DO) on an SPI flash chip
* \*Use caution: Connect one pin to ground, watch device boot up sequence, before the kernel decompresses, short/connect the grounded pin to pins 8 and 9 of the NAND flash chip at the moment U-boot decompresses the UBI image
  * \*Review the NAND flash chip’s datasheet prior to shorting pins
* Configure a rogue DHCP server with malicious parameters as input for a device to ingest during a PXE boot
  * Use Metasploit’s (MSF) DHCP auxiliary server and modify the ‘`FILENAME`’ parameter with command injection commands such as `‘a";/bin/sh;#’` to test input validation for device startup procedures.

\*Hardware security testing
