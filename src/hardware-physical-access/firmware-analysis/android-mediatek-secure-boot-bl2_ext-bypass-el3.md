# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка документує практичний secure-boot break на кількох платформах MediaTek, який використовує прогалину в перевірці, коли конфігурація завантажувача пристрою (seccfg) встановлена як "unlocked". Вразливість дозволяє запускати змінений bl2_ext на ARM EL3, щоб відключити перевірку підписів на наступних етапах, зруйнувати ланцюг довіри і дозволити завантаження довільних unsigned TEE/GZ/LK/Kernel образів.

> Увага: Патчинг на ранньому етапі завантаження може назавжди вивести пристрій з ладу, якщо зсуви (offsets) неправильні. Завжди зберігайте повні дампи і надійний шлях відновлення.

## Affected boot flow (MediaTek)

- Нормальний шлях: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Вразливий шлях: Коли seccfg встановлено в unlocked, Preloader може пропустити перевірку bl2_ext. Preloader все одно передає керування bl2_ext на EL3, тож спеціально створений bl2_ext може надалі завантажувати неперевірені компоненти.

Ключовий кордон довіри:
- bl2_ext виконується на EL3 і відповідає за верифікацію TEE, GenieZone, LK/AEE і kernel. Якщо сам bl2_ext не автентифікований, решту ланцюга довіри можна тривіально обійти.

## Root cause

На уразливих пристроях Preloader не примушує автентифікацію розділу bl2_ext, коли seccfg вказує стан "unlocked". Це дозволяє прошити bl2_ext під контролем атакуючого, який виконується на EL3.

Всередині bl2_ext функцію політики верифікації можна пропатчити так, щоб вона безумовно повертала, що верифікація не потрібна (або завжди успішна), змушуючи ланцюг завантаження приймати unsigned образи TEE/GZ/LK/Kernel. Оскільки цей патч виконується на EL3, він ефективний навіть якщо нижележачі компоненти реалізують власні перевірки.

## Practical exploit chain

1. Отримати розділи завантажувача (Preloader, bl2_ext, LK/AEE тощо) через OTA/firmware packages, EDL/DA readback або апаратне дампування.
2. Знайти рутину перевірки bl2_ext і пропатчити її так, щоб вона завжди пропускала/приймала перевірку.
3. Прошити змінений bl2_ext через fastboot, DA або подібні сервісні канали, які ще дозволені на unlocked пристроях.
4. Перезавантажити; Preloader передає керування пропатченому bl2_ext на EL3, який потім завантажує unsigned нижележачі образи (запатчені TEE/GZ/LK/Kernel) і відключає примусове перевіряння підписів.

Якщо пристрій налаштовано як locked (seccfg locked), очікується, що Preloader перевірятиме bl2_ext. У такій конфігурації ця атака не вдасться, якщо інша вразливість не дозволяє завантажити unsigned bl2_ext.

## Triage (expdb boot logs)

- Зберіть дампи boot/expdb логів навколо завантаження bl2_ext. Якщо `img_auth_required = 0` і час перевірки сертифіката ~0 ms, ймовірно перевірка пропускається.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Деякі пристрої пропускають перевірку bl2_ext навіть коли заблоковані; шляхи вторинного завантажувача lk2 показали ту ж прогалину. Якщо post-OTA Preloader реєструє `img_auth_required = 1` для bl2_ext під час розблокованості, ймовірно, примусове застосування перевірки було відновлено.

## Місця розташування логіки перевірки

- Відповідна перевірка зазвичай розміщена всередині образу bl2_ext у функціях з іменами, подібними до `verify_img` або `sec_img_auth`.
- У запатченій версії функцію змушують повертати успіх або повністю обходять виклик перевірки.

Приклад підходу до патчу (концептуально):
- Знайдіть функцію, яка викликає `sec_img_auth` для образів TEE, GZ, LK та kernel images.
- Замініть її тіло на stub, який негайно повертає успіх, або перезапишіть умовну гілку, що обробляє помилку перевірки.

Переконайтеся, що патч зберігає налаштування стеку/фрейму та повертає очікувані коди стану викликам.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir — це референсний інструментарій для патчингу цієї проблеми (Nothing Phone (2a) повністю підтримується; CMF Phone 1 частково). Загалом:
- Розмістіть образ bootloader пристрою як `bin/<device>.bin`.
- Зберіть запатчений образ, який відключає політику перевірки bl2_ext.
- Запишіть отриманий payload (надається fastboot helper).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use another flashing channel if fastboot is unavailable.

## Примітки щодо патчування EL3

- bl2_ext виконується в ARM EL3. Збої тут можуть вивести пристрій з ладу до повторної прошивки через EDL/DA або тестові точки.
- Використовуйте специфічне для плати логування/UART, щоб підтвердити шлях виконання та діагностувати збої.
- Зберігайте резервні копії всіх розділів, що змінюються, і спочатку тестуйте на тестовому обладнанні.

## Наслідки

- Виконання коду в EL3 після Preloader призводить до повного руйнування ланцюга довіри для решти шляху завантаження.
- Можливість завантажувати непідписані TEE/GZ/LK/Kernel, обходячи очікування secure/verified boot і дозволяючи стійке скомпрометування.

## Нотатки щодо пристроїв

- Підтверджено підтримується: Nothing Phone (2a) (Pacman)
- Відомо працює (неповна підтримка): CMF Phone 1 (Tetris)
- Спостерігалося: за повідомленнями, Vivo X80 Pro не перевіряв bl2_ext навіть при заблокованому стані
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) знову ввімкнув перевірку bl2_ext; fenrir `pacman-v2.0` відновлює обхід, комбінуючи бета-Preloader із запатченим LK
- Огляд індустрії підкреслює, що додаткові виробники на базі lk2 постачають ту саму логічну помилку, тож очікуйте подальшого перекриття в релізах MTK 2024–2025 років.

## MTK DA readback і маніпуляції seccfg за допомогою Penumbra

Penumbra — це Rust crate/CLI/TUI, який автоматизує взаємодію з MTK preloader/bootrom по USB для операцій у DA-mode. За наявності фізичного доступу до вразливого телефону (якщо дозволені DA extensions), він може виявити MTK USB-порт, завантажити Download Agent (DA) blob та виконувати привілейовані команди, такі як зміну seccfg lock та partition readback.

- **Налаштування середовища/драйверів**: На Linux встановіть `libudev`, додайте користувача до групи `dialout` і створіть udev-правила або запускайте з `sudo`, якщо вузол пристрою недоступний. Підтримка Windows ненадійна; іноді працює лише після заміни MTK-драйвера на WinUSB через Zadig (згідно з рекомендаціями проєкту).
- **Робочий процес**: Прочитайте DA-пейлоуд (наприклад, `std::fs::read("../DA_penangf.bin")`), опитуйте MTK-порт за допомогою `find_mtk_port()`, і збудуйте сесію за допомогою `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Після того як `init()` завершить рукостискання та збере інформацію про пристрій, перевірте захисти через бітові поля `dev_info.target_config()` (bit 0 встановлений → SBC увімкнено). Увійдіть у DA mode і спробуйте `set_seccfg_lock_state(LockFlag::Unlock)` — це вдасться лише якщо пристрій приймає extensions. Розділи можна здампити за допомогою `read_partition("lk_a", &mut progress_cb, &mut writer)` для офлайн-аналізу або патчингу.
- **Вплив на безпеку**: Успішне розблокування seccfg знову відкриває шляхи прошивки для непідписаних образів завантаження, дозволяючи стійкі компрометації, як описане вище патчування bl2_ext у EL3. Читання розділів надає артефакти прошивки для реверс-інжинірингу та створення змінених образів.

<details>
<summary>Rust DA сесія + розблокування seccfg + дамп розділів (Penumbra)</summary>
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

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
