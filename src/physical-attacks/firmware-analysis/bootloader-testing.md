{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um die Startkonfigurationen von Geräten und Bootloadern wie U-boot zu ändern:

1. **Zugriff auf die Interpreter-Shell des Bootloaders**:

- Drücken Sie während des Bootvorgangs "0", die Leertaste oder andere identifizierte "magische Codes", um auf die Interpreter-Shell des Bootloaders zuzugreifen.

2. **Boot-Argumente ändern**:

- Führen Sie die folgenden Befehle aus, um '`init=/bin/sh`' zu den Boot-Argumenten hinzuzufügen, was die Ausführung eines Shell-Befehls ermöglicht:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **TFTP-Server einrichten**:

- Konfigurieren Sie einen TFTP-Server, um Bilder über ein lokales Netzwerk zu laden:
%%%
#setenv ipaddr 192.168.2.2 #lokale IP des Geräts
#setenv serverip 192.168.2.1 #IP des TFTP-Servers
#saveenv
#reset
#ping 192.168.2.1 #Netzwerkzugang überprüfen
#tftp ${loadaddr} uImage-3.6.35 #loadaddr nimmt die Adresse, in die die Datei geladen werden soll, und den Dateinamen des Bildes auf dem TFTP-Server
%%%

4. **`ubootwrite.py` verwenden**:

- Verwenden Sie `ubootwrite.py`, um das U-boot-Bild zu schreiben und eine modifizierte Firmware zu pushen, um Root-Zugriff zu erhalten.

5. **Debug-Funktionen überprüfen**:

- Überprüfen Sie, ob Debug-Funktionen wie ausführliches Logging, Laden beliebiger Kernel oder Booten von nicht vertrauenswürdigen Quellen aktiviert sind.

6. **Vorsicht bei Hardware-Interferenzen**:

- Seien Sie vorsichtig, wenn Sie einen Pin mit Masse verbinden und mit SPI- oder NAND-Flash-Chips während des Bootvorgangs des Geräts interagieren, insbesondere bevor der Kernel dekomprimiert. Konsultieren Sie das Datenblatt des NAND-Flash-Chips, bevor Sie Pins kurzschließen.

7. **Rogue DHCP-Server konfigurieren**:
- Richten Sie einen Rogue-DHCP-Server mit bösartigen Parametern ein, die ein Gerät während eines PXE-Boots aufnehmen soll. Verwenden Sie Tools wie den DHCP-Hilfsserver von Metasploit (MSF). Ändern Sie den 'FILENAME'-Parameter mit Befehlsinjektionsbefehlen wie `'a";/bin/sh;#'`, um die Eingabevalidierung für die Startverfahren des Geräts zu testen.

**Hinweis**: Die Schritte, die physische Interaktionen mit den Pins des Geräts (\*mit Sternchen markiert) beinhalten, sollten mit äußerster Vorsicht angegangen werden, um Schäden am Gerät zu vermeiden.

## Referenzen

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

{{#include ../../banners/hacktricks-training.md}}
