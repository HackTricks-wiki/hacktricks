# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

На цій сторінці описано практичний злам secure-boot на кількох платформах MediaTek шляхом використання прогалини у перевірці, коли конфігурація bootloader пристрою (seccfg) має стан "unlocked". Ця вразливість дає змогу запустити пропатчений bl2_ext на ARM EL3, щоб вимкнути подальшу перевірку підписів, зруйнувати chain of trust і дозволити довільне завантаження непідписаних TEE/GZ/LK/Kernel.<sup>[[1]](#references)</sup>

> Увага: patching на ранньому етапі boot може назавжди перетворити пристрій на "цеглину", якщо offsets вказано неправильно. Завжди зберігайте повні dumps і надійний спосіб recovery.

## Вразливий boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: Коли seccfg має стан unlocked, Preloader може пропустити перевірку bl2_ext. Preloader все одно переходить до bl2_ext на EL3, тому crafted bl2_ext може надалі завантажувати неперевірені компоненти.

Ключова межа довіри:
- bl2_ext виконується на EL3 і відповідає за перевірку TEE, GenieZone, LK/AEE та kernel. Якщо сам bl2_ext не автентифікований, решту chain of trust можна тривіально bypass.<sup>[[1]](#references)</sup>

## Root cause

На вразливих пристроях Preloader не забезпечує authentication розділу bl2_ext, коли seccfg вказує на стан "unlocked". Це дає змогу прошити контрольований attacker-ом bl2_ext, який виконується на EL3.

Усередині bl2_ext функцію policy перевірки можна пропатчити, щоб вона безумовно повідомляла, що перевірка не потрібна (або завжди завершується успішно), змушуючи boot chain приймати непідписані TEE/GZ/LK/Kernel images. Оскільки цей patch виконується на EL3, він ефективний навіть тоді, коли downstream-компоненти реалізують власні перевірки.<sup>[[1]](#references)</sup>

## Practical exploit chain

1. Отримати bootloader partitions (Preloader, bl2_ext, LK/AEE тощо) через OTA/firmware packages, EDL/DA readback або hardware dumping.
2. Визначити verification routine у bl2_ext і пропатчити її так, щоб вона завжди пропускала або приймала verification.
3. Прошити modified bl2_ext за допомогою fastboot, DA або подібних maintenance channels, які все ще дозволені на unlocked-пристроях.
4. Перезавантажити пристрій; Preloader переходить до пропатченого bl2_ext на EL3, після чого він завантажує непідписані downstream images (patched TEE/GZ/LK/Kernel) і вимикає signature enforcement.<sup>[[1]](#references)</sup>

Якщо пристрій налаштовано як locked (seccfg locked), очікується, що Preloader перевірятиме bl2_ext. У такій конфігурації ця атака не спрацює, якщо інша вразливість не дозволяє завантажити непідписаний bl2_ext.

## Triage (expdb boot logs)

- Dump-ніть boot/expdb logs навколо моменту завантаження bl2_ext. Якщо `img_auth_required = 0`, а час certificate verification становить приблизно 0 мс, найімовірніше, verification пропущено.<sup>[[1]](#references)</sup>

Приклад фрагмента log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Деякі пристрої пропускають перевірку bl2_ext навіть у заблокованому стані; шляхи вторинного bootloader lk2 також демонстрували таку саму вразливість. Якщо post-OTA Preloader записує в лог `img_auth_required = 1` для bl2_ext у розблокованому стані, enforcement, імовірно, було відновлено.<sup>[[1]](#references)[[2]](#references)</sup>

## Розташування логіки верифікації

- Відповідна перевірка зазвичай міститься всередині образу bl2_ext у функціях із назвами на кшталт `verify_img` або `sec_img_auth`.
- Пропатчена версія змушує функцію повертати успіх або повністю обходити виклик верифікації.<sup>[[1]](#references)</sup>

Приклад підходу до patch (концептуально):
- Знайдіть функцію, яка викликає `sec_img_auth` для образів TEE, GZ, LK і kernel.
- Замініть її тіло на stub, який одразу повертає успіх, або перезапишіть умовний branch, що обробляє помилку верифікації.

Переконайтеся, що patch зберігає налаштування stack/frame і повертає очікувані коди стану для caller'ів.<sup>[[1]](#references)</sup>

## Робочий процес Fenrir PoC (Nothing/CMF)

Fenrir — це reference toolkit для patching цієї проблеми (Nothing Phone (2a) повністю підтримується; CMF Phone 1 — частково).<sup>[[1]](#references)</sup> Загалом:
- Розмістіть образ bootloader пристрою як `bin/<device>.bin`.
- Створіть patched image, який вимикає політику верифікації bl2_ext.
- Прошийте отриманий payload (fastboot helper надається).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Використовуйте інший канал прошивання, якщо fastboot недоступний.

## Нотатки щодо патчингу EL3

- bl2_ext виконується в ARM EL3. Збої на цьому етапі можуть заблокувати пристрій до повторного прошивання через EDL/DA або test points.
- Використовуйте специфічне для плати логування/UART, щоб перевірити шлях виконання та діагностувати збої.
- Створюйте резервні копії всіх розділів, які змінюються, і спочатку тестуйте на апаратному забезпеченні, яке не шкода втратити.<sup>[[1]](#references)</sup>

## Наслідки

- Виконання коду в EL3 після Preloader і повний обхід chain-of-trust для решти шляху завантаження.
- Можливість завантажувати непідписані TEE/GZ/LK/Kernel, обходячи очікування secure/verified boot і забезпечуючи persistent compromise.<sup>[[1]](#references)</sup>

## Примітки щодо пристроїв

- Підтримку підтверджено: Nothing Phone (2a) (Pacman)
- Відомо, що працює (неповна підтримка): CMF Phone 1 (Tetris)
- Спостереження: за повідомленнями, Vivo X80 Pro не перевіряв bl2_ext навіть у locked-стані<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) повторно ввімкнув перевірку bl2_ext; fenrir `pacman-v2.0` відновлює bypass, поєднуючи beta Preloader із patched LK<sup>[[3]](#references)</sup>
- Огляди індустрії вказують на додаткових vendor-ів, що використовують lk2 і постачають ту саму логічну вразливість, тож очікуйте подальшого перетину між MTK-релізами 2024–2025 років.<sup>[[2]](#references)[[4]](#references)</sup>

## Зчитування MTK DA та маніпуляції з seccfg за допомогою Penumbra

Penumbra — це Rust crate/CLI/TUI, який автоматизує взаємодію з MTK preloader/bootrom через USB для операцій у DA-mode. Маючи physical access до вразливого handset (DA extensions дозволені), він може виявити MTK USB-порт, завантажити Download Agent (DA) blob і виконувати privileged-команди, такі як перемикання seccfg lock та зчитування розділів.<sup>[[5]](#references)</sup>

- **Налаштування environment/driver**: У Linux встановіть `libudev`, додайте користувача до групи `dialout` і створіть udev rules або запускайте через `sudo`, якщо device node недоступний. Підтримка Windows ненадійна; іноді все працює лише після заміни MTK driver на WinUSB за допомогою Zadig (відповідно до guidance проєкту).
- **Workflow**: Зчитайте DA payload (наприклад, `std::fs::read("../DA_penangf.bin")`), опитуйте MTK-порт за допомогою `find_mtk_port()` і створіть session через `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Після завершення `init()`, яке виконує handshake і збирає інформацію про пристрій, перевірте protections через bitfields `dev_info.target_config()` (bit 0 встановлено → SBC enabled). Увійдіть у DA mode і спробуйте `set_seccfg_lock_state(LockFlag::Unlock)` — це спрацює лише за умови, що пристрій приймає extensions. Розділи можна зберегти через `read_partition("lk_a", &mut progress_cb, &mut writer)` для offline analysis або patching.
- **Вплив на security**: Успішне seccfg unlocking повторно відкриває шляхи прошивання для unsigned boot images, уможливлюючи persistent compromises, такі як описаний вище EL3 patching bl2_ext. Зчитування розділів надає firmware artifacts для reverse engineering і створення modified images.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Посилання

- [1] [Fenrir – MediaTek bl2_ext secure-boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – опубліковано PoC exploit для вразливості виконання коду в Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Реліз Fenrir pacman-v2.0 (пакет обходу NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC ламає secure boot на Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – інструментарій MTK DA для flash/readback і seccfg](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
