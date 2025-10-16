# MediaTek bl2_ext — обхід Secure-Boot (виконання коду на EL3)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка документує практичний злам Secure-Boot на кількох платформах MediaTek шляхом зловживання прогалиною перевірки, коли конфігурація завантажувача пристрою (seccfg) встановлена в стан «unlocked». Уразливість дозволяє запускати змінений bl2_ext на ARM EL3 для відключення подальшої перевірки підписів, що руйнує ланцюг довіри та дає змогу завантажувати довільні непідписані TEE/GZ/LK/Kernel.

> Увага: Патчинг на ранній стадії завантаження може назавжди вивести пристрій з ладу, якщо офсети неправильні. Завжди зберігайте повні дампи та надійний шлях відновлення.

## Схема завантаження (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Ключова межа довіри:
- bl2_ext виконується на EL3 і відповідає за верифікацію TEE, GenieZone, LK/AEE та ядра. Якщо сам bl2_ext не автентифікований, решта ланцюга легко обходиться.

## Причина

На вразливих пристроях Preloader не примушує автентифікацію розділу bl2_ext, коли seccfg вказує стан «unlocked». Це дозволяє прошити bl2_ext, контрольований атакуючим, який запускається на EL3.

Всередині bl2_ext функція політики верифікації може бути пропатчена так, щоб безумовно повертати, що верифікація не потрібна. Мінімальний концептуальний патч:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
З цією зміною всі наступні образи (TEE, GZ, LK/AEE, Kernel) приймаються без криптографічних перевірок під час завантаження патченим bl2_ext, що працює на EL3.

## Як провести тріаж цілі (expdb logs)

Створіть дамп/перегляньте журнали завантаження (наприклад, expdb) навколо завантаження bl2_ext. Якщо img_auth_required = 0 і час перевірки сертифіката ≈ 0 ms, ймовірно, що перевірки вимкнені і пристрій є вразливим.

Приклад уривку журналу:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Примітка: За повідомленнями, деякі пристрої пропускають перевірку bl2_ext навіть при заблокованому bootloader, що посилює наслідки.

## Practical exploitation workflow (Fenrir PoC)

Fenrir — еталонний exploit/patching toolkit для цього класу проблем. Підтримує Nothing Phone (2a) (Pacman) і відомо, що працює (неповністю підтримується) на CMF Phone 1 (Tetris). Портування на інші моделі вимагає reverse engineering специфічного для пристрою bl2_ext.

Загальна послідовність:
- Отримайте bootloader image пристрою для вашого цільового codename і помістіть його в bin/<device>.bin
- Зберіть patched image, який відключає політику перевірки bl2_ext
- Flash отриманий payload на пристрій (helper script передбачає використання fastboot)

Команди:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Реєструвати користувацькі команди fastboot
- Керувати/перевизначати режим завантаження
- Динамічно викликати вбудовані функції bootloader під час виконання
- Підробляти “lock state” як заблокований, будучи фактично розблокованим, щоб пройти більш жорсткі перевірки цілісності (в деяких середовищах все ще можуть вимагатися коригування vbmeta/AVB)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Виконайте реверс-інженерію bl2_ext, специфічного для пристрою, щоб знайти логіку політики верифікації (наприклад, sec_get_vfy_policy).
- Визначте місце повернення політики або гілку прийняття рішення та пропатчіть її у “no verification required” (return 0 / unconditional allow).
- Тримайте офсети повністю специфічними для пристрою та прошивки; не повторно використовуйте адреси між варіантами.
- Спочатку перевірте на тестовому пристрої. Підготуйте план відновлення (наприклад, EDL/BootROM loader/SoC-specific download mode) перед прошиванням.

## Security impact

- Виконання коду на EL3 після Preloader і повний колапс ланцюжка довіри для решти шляху завантаження.
- Можливість завантажити unsigned TEE/GZ/LK/Kernel, обходячи очікування secure/verified boot і дозволяючи персистентне скомпрометування.

## Detection and hardening ideas

- Забезпечте, щоб Preloader перевіряв bl2_ext незалежно від стану seccfg.
- Примусово застосовуйте результати аутентифікації та збирайте аудиторні докази (timings > 0 ms, жорсткі помилки при невідповідності).
- Lock-state spoofing має бути зроблено неефективним для attestation (зв’язати lock state з рішеннями перевірки AVB/vbmeta та fuse-backed state).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
