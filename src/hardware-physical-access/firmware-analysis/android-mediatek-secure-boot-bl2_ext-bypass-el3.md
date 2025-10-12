# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка документує практичний прорив Secure-Boot на кількох платформах MediaTek через використання прогалини в перевірці, коли конфігурація bootloader (seccfg) встановлена в "unlocked". Уразливість дозволяє запускати змінений bl2_ext на ARM EL3 для відключення подальшої перевірки підписів, що призводить до руйнування ланцюга довіри та дозволяє завантажувати довільні неподписані TEE/GZ/LK/Kernel.

> Увага: патчинг на ранньому етапі завантаження може назавжди вивести пристрої з ладу, якщо офсети неправильні. Завжди зберігайте повні дампи та надійний шлях відновлення.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Key trust boundary:
- bl2_ext executes at EL3 and is responsible for verifying TEE, GenieZone, LK/AEE and the kernel. If bl2_ext itself is not authenticated, the rest of the chain is trivially bypassed.

## Root cause

On affected devices, the Preloader does not enforce authentication of the bl2_ext partition when seccfg indicates an "unlocked" state. This allows flashing an attacker-controlled bl2_ext that runs at EL3.

Inside bl2_ext, the verification policy function can be patched to unconditionally report that verification is not required. A minimal conceptual patch is:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
З цією зміною всі наступні образи (TEE, GZ, LK/AEE, Kernel) приймаються без криптографічних перевірок при завантаженні патченою bl2_ext, що працює на EL3.

## Як провести тріаж цілі (expdb logs)

Зробіть дамп/перегляньте логи завантаження (наприклад, expdb) навколо моменту завантаження bl2_ext. Якщо img_auth_required = 0 і час перевірки сертифіката ~0 ms, то, ймовірно, примусова перевірка вимкнена і пристрій вразливий.

Приклад уривку журналу:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Примітка: повідомляють, що деякі пристрої пропускають перевірку bl2_ext навіть при заблокованому bootloader, що посилює масштаб наслідків.

## Практичний робочий процес експлуатації (Fenrir PoC)

Fenrir — це референсний набір інструментів для експлойтів/патчів цього класу проблем. Він підтримує Nothing Phone (2a) (Pacman) і, як відомо, працює (неповністю підтримується) на CMF Phone 1 (Tetris). Портування на інші моделі потребує зворотного інжинірингу специфічного для пристрою bl2_ext.

Загальний процес:
- Отримайте образ bootloader для вашого цільового кодового імені пристрою та помістіть його як bin/<device>.bin
- Побудуйте патчений образ, який вимикає політику перевірки bl2_ext
- Запишіть отриманий payload на пристрій (скрипт-помічник припускає використання fastboot)

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
- Реєструвати власні fastboot команди
- Керувати/перевизначати режим завантаження
- Динамічно викликати вбудовані функції bootloader'а під час виконання
- Фальсифікувати lock state як 'locked', хоча фактично 'unlocked', щоб пройти більш суворі перевірки цілісності (в деяких середовищах все ще можуть знадобитися налаштування vbmeta/AVB)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Reverse engineer the device-specific bl2_ext to locate verification policy logic (e.g., sec_get_vfy_policy).
- Identify the policy return site or decision branch and patch it to “no verification required” (return 0 / unconditional allow).
- Keep offsets fully device- and firmware-specific; do not reuse addresses between variants.
- Validate on a sacrificial unit first. Prepare a recovery plan (e.g., EDL/BootROM loader/SoC-specific download mode) before you flash.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Detection and hardening ideas

- Ensure Preloader verifies bl2_ext regardless of seccfg state.
- Enforce authentication results and gather audit evidence (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing should be made ineffective for attestation (tie lock state to AVB/vbmeta verification decisions and fuse-backed state).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
