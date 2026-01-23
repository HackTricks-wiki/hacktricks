# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка документує практичний злам secure-boot на кількох платформах MediaTek шляхом використання прогалини в перевірці, коли конфігурація завантажувача пристрою (seccfg) встановлена в "unlocked". Помилка дозволяє запускати модифікований bl2_ext на ARM EL3 для відключення подальшої перевірки підписів, руйнуючи ланцюжок довіри та даючи змогу завантажувати довільні непідписані TEE/GZ/LK/Kernel.

> Увага: патчинг на ранньому етапі завантаження може назавжди вивести пристрої з ладу, якщо зсуви неправильні. Завжди зберігайте повні дампи та надійний шлях для відновлення.

## Уразливий потік завантаження (MediaTek)

- Нормальний шлях: BootROM → Preloader → bl2_ext (EL3, перевірено) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Уразливий шлях: коли seccfg встановлений у unlocked, Preloader може пропустити перевірку bl2_ext. Preloader все ще передає керування bl2_ext на EL3, тому спеціально створений bl2_ext може завантажувати неперевірені компоненти далі.

Ключова межа довіри:
- bl2_ext виконується на EL3 і відповідає за перевірку TEE, GenieZone, LK/AEE та ядра. Якщо сам bl2_ext не автентифікований, решту ланцюжка довіри тривіально обходять.

## Корінна причина

На уразливих пристроях Preloader не примушує автентифікацію розділу bl2_ext, коли seccfg вказує стан "unlocked". Це дозволяє прошити керований атакуючим bl2_ext, який виконується на EL3.

Всередині bl2_ext функцію політики перевірки можна запатчити так, щоб вона безумовно повідомляла, що перевірка не потрібна. Мінімальний концептуальний патч:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
З цією зміною всі наступні образи (TEE, GZ, LK/AEE, Kernel) приймаються без криптографічних перевірок при завантаженні пропатченим bl2_ext, що працює на EL3.

## Як проводити тріаж цілі (expdb логи)

Зробіть дамп/перегляньте boot-логи (наприклад, expdb) навколо завантаження bl2_ext. Якщо img_auth_required = 0 і час перевірки сертифіката ~0 ms, примусове застосування ймовірно вимкнено і пристрій уразливий.

Приклад уривка логу:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Примітка: повідомляється, що деякі пристрої пропускають перевірку bl2_ext навіть при заблокованому bootloader, що посилює вплив.

Пристрої, які постачаються з lk2 secondary bootloader, також спостерігались з тією ж логічною прогалиною, тому отримайте expdb логи для розділів bl2_ext та lk2, щоб підтвердити, чи якийсь із шляхів застосовує підписи, перш ніж намагатися портувати.

Якщо post-OTA Preloader зараз логить img_auth_required = 1 для bl2_ext навіть коли seccfg розблоковано, швидше за все вендор закрив прогалину — див. примітки про OTA persistence нижче.

## Практичний робочий процес експлуатації (Fenrir PoC)

Fenrir — референсний exploit/patching toolkit для цього класу проблем. Він підтримує Nothing Phone (2a) (Pacman) і відомо, що працює (неповністю підтримується) на CMF Phone 1 (Tetris). Портування на інші моделі вимагає reverse engineering специфічного для пристрою bl2_ext.

Загальний процес:
- Отримайте образ bootloader пристрою для вашого цільового codename і помістіть його як `bin/<device>.bin`
- Зберіть patched image, що відключає політику верифікації bl2_ext
- Запишіть отриманий payload на пристрій (скрипт-помічник передбачає використання fastboot)

Команди:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Якщо fastboot недоступний, потрібно використовувати відповідний альтернативний метод прошивки для вашої платформи.

### OTA-patched firmware: як зберегти bypass (NothingOS 4, кінець 2025)

Nothing запатчила Preloader у стабільному OTA NothingOS 4 від листопада 2025 року (build BP2A.250605.031.A3), щоб примусово застосувати перевірку bl2_ext навіть коли seccfg розблоковано. Fenrir `pacman-v2.0` знову працює шляхом змішування уразливого Preloader з NOS 4 beta та стабільного LK payload:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important:
- Flash the provided Preloader **only** to the matching device/slot; a wrong preloader is an instant hard brick.
- Check expdb after flashing; img_auth_required should drop back to 0 for bl2_ext, confirming that the vulnerable Preloader is executing before your patched LK.
- If future OTAs patch both Preloader and LK, keep a local copy of a vulnerable Preloader to re‑introduce the gap.

### Build automation & payload debugging

- `build.sh` now auto-downloads and exports the Arm GNU Toolchain 14.2 (aarch64-none-elf) the first time you run it, so you do not have to juggle cross-compilers manually.
- Export `DEBUG=1` before invoking `build.sh` to compile payloads with verbose serial prints, which greatly helps when you are blind-patching EL3 code paths.
- Successful builds drop both `lk.patched` and `<device>-fenrir.bin`; the latter already has the payload injected and is what you should flash/boot-test.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Payload staging patterns (EL3)

Fenrir splits its instrumentation into three compile-time stages: stage1 runs before `platform_init()`, stage2 runs before LK signals fastboot entry, and stage3 executes immediately before LK loads Linux. Each device header under `payload/devices/` provides the addresses for these hooks plus fastboot helper symbols, so keep those offsets synchronized with your target build.

Stage2 is a convenient location to register arbitrary `fastboot oem` verbs:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 демонструє, як тимчасово змінювати page-table attributes, щоб патчити immutable strings, такі як Android’s “Orange State” warning, без потреби у downstream kernel access:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Оскільки stage1 запускається перед platform bring-up, це правильне місце для виклику OEM power/reset primitives або вставлення додаткового логування цілісності перед тим, як verified boot chain буде зруйновано.

## Поради щодо портування

- Reverse engineer the device-specific bl2_ext щоб визначити логіку політики верифікації (наприклад, sec_get_vfy_policy).
- Ідентифікуйте місце повернення політики або гілку прийняття рішення й пропатчіть її на «перевірка не потрібна» (return 0 / unconditional allow).
- Тримайте offsets повністю специфічними для пристрою та прошивки; не повторно використовуйте адреси між варіантами.
- Перевіряйте на sacrificial unit спочатку. Підготуйте план відновлення (наприклад, EDL/BootROM loader/SoC-specific download mode) перед тим, як прошивати.
- Пристрої, що використовують lk2 secondary bootloader або повідомляють “img_auth_required = 0” для bl2_ext навіть коли заблоковані, слід розглядати як вразливі реалізації цього класу багів; Vivo X80 Pro вже спостерігався з пропуском верифікації незважаючи на заявлений стан блокування.
- Коли OTA починає вимагати підписи bl2_ext (img_auth_required = 1) у розблокованому стані, перевірте, чи можна прошити старіший Preloader (часто доступний у beta OTA), щоб знову відкрити пролом, а потім повторно запустити fenrir з оновленими offsets для нового LK.

## Вплив на безпеку

- EL3 code execution після Preloader і повний крах chain-of-trust для решти шляху завантаження.
- Можливість завантажити unsigned TEE/GZ/LK/Kernel, обходячи очікування secure/verified boot і забезпечуючи персистентне скомпрометування.

## Примітки щодо пристроїв

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
