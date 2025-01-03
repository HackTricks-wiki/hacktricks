{{#include ../../banners/hacktricks-training.md}}

Die volgende stappe word aanbeveel om toestel opstartkonfigurasies en bootloaders soos U-boot te wysig:

1. **Toegang tot Bootloader se Interpreter Shell**:

- Gedurende opstart, druk "0", spasie, of ander geïdentifiseerde "magiese kodes" om toegang te verkry tot die bootloader se interpreter shell.

2. **Wysig Boot Argumente**:

- Voer die volgende opdragte uit om '`init=/bin/sh`' by die boot argumente te voeg, wat die uitvoering van 'n shell opdrag toelaat:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Stel TFTP Bediening in**:

- Konfigureer 'n TFTP bediener om beelde oor 'n plaaslike netwerk te laai:
%%%
#setenv ipaddr 192.168.2.2 #lokale IP van die toestel
#setenv serverip 192.168.2.1 #TFTP bediener IP
#saveenv
#reset
#ping 192.168.2.1 #kontroleer netwerktoegang
#tftp ${loadaddr} uImage-3.6.35 #loadaddr neem die adres om die lêer in te laai en die lêernaam van die beeld op die TFTP bediener
%%%

4. **Gebruik `ubootwrite.py`**:

- Gebruik `ubootwrite.py` om die U-boot beeld te skryf en 'n gewysigde firmware te druk om worteltoegang te verkry.

5. **Kontroleer Debug Kenmerke**:

- Verifieer of debug kenmerke soos gedetailleerde logging, laai van arbitrêre kerne, of opstart vanaf onbetroubare bronne geaktiveer is.

6. **Versigtigheid met Hardeware Interferensie**:

- Wees versigtig wanneer jy een pen aan grond verbind en met SPI of NAND flash skywe interaksie het tydens die toestel se opstartvolgorde, veral voordat die kern ontspan. Raadpleeg die NAND flash skyf se datasheet voordat jy penne kortsluit.

7. **Stel Rogue DHCP Bediening in**:
- Stel 'n rogue DHCP bediener op met kwaadwillige parameters vir 'n toestel om in te neem tydens 'n PXE opstart. Gebruik gereedskap soos Metasploit se (MSF) DHCP bystandbediener. Wysig die 'FILENAME' parameter met opdraginvoegopdragte soos `'a";/bin/sh;#'` om invoervalidasie vir toestel opstart prosedures te toets.

**Let wel**: Die stappe wat fisiese interaksie met toestel penne behels (\*gemerk met asterisks) moet met uiterste versigtigheid benader word om te voorkom dat die toestel beskadig word.

## Verwysings

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
