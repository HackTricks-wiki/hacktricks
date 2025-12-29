# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка описує практичний secure-boot break на кількох платформах MediaTek шляхом використання прогалини в перевірці, коли конфігурація завантажувача пристрою (seccfg) встановлена в стан "unlocked". Уразливість дозволяє виконати змінений bl2_ext на ARM EL3, щоб відключити подальшу перевірку підписів, зруйнувати ланцюг довіри і дозволити завантаження довільних непідписаних TEE/GZ/LK/Kernel.

> Caution: Early-boot patching can permanently brick devices if offsets are wrong. Always keep full dumps and a reliable recovery path.

## Уразливий потік завантаження (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Ключова межа довіри:
- bl2_ext виконується на EL3 і відповідає за перевірку TEE, GenieZone, LK/AEE та kernel. Якщо сам bl2_ext не автентифікований, решта ланцюга довіри тривіально обходиться.

## Корінна причина

На уразливих пристроях Preloader не примушує автентифікацію розділу bl2_ext, коли seccfg вказує стан "unlocked". Це дозволяє прошивати bl2_ext, контрольований зловмисником, який запускається на EL3.

Всередині bl2_ext функцію політики валідації можна підправити так, щоб вона безумовно повідомляла, що валідація не потрібна. Мінімальний концептуальний патч виглядає так:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
З цією зміною всі подальші образи (TEE, GZ, LK/AEE, Kernel) приймаються без криптографічних перевірок при завантаженні виправленим bl2_ext, що виконується на EL3.

## Як провести триаж цілі (expdb logs)

Зробіть дамп/проінспектуйте boot logs (e.g., expdb) навколо завантаження bl2_ext. Якщо img_auth_required = 0 і час перевірки сертифіката ~0 ms, швидше за все enforcement вимкнено і пристрій exploitable.

Приклад уривка логу:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Примітка: повідомляється, що деякі пристрої пропускають перевірку bl2_ext навіть за наявності locked bootloader, що посилює наслідки.

Пристрої, які постачаються з lk2 secondary bootloader, спостерігалися з тією ж логічною прогалиною; тому збережіть expdb logs для розділів bl2_ext і lk2, щоб підтвердити, чи якийсь із шляхів перевіряє підписи перед тим, як ви спробуєте портування.

## Практичний робочий процес експлуатації (Fenrir PoC)

Fenrir — еталонний exploit/patching toolkit для цього класу проблем. Він підтримує Nothing Phone (2a) (Pacman) і відомо працює (неповністю підтримується) на CMF Phone 1 (Tetris). Портування на інші моделі вимагає reverse engineering специфічного для пристрою bl2_ext.

High-level process:
- Отримайте образ bootloader пристрою для цільового codename і розмістіть його як `bin/<device>.bin`
- Зберіть запатчений образ, який відключає політику верифікації bl2_ext
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Якщо fastboot недоступний, ви маєте використати відповідний альтернативний метод прошивки для вашої платформи.

### Автоматизація збірки та налагодження payload

- `build.sh` тепер автоматично завантажує та експортує Arm GNU Toolchain 14.2 (aarch64-none-elf) при першому запуску, тож вам не потрібно вручну управляти крос‑компіляторами.
- Експортуйте `DEBUG=1` перед викликом `build.sh`, щоб компілювати payloads з verbose serial prints, що значно допомагає при blind-patching EL3 code paths.
- Успішні збірки створюють обидва файли `lk.patched` та `<device>-fenrir.bin`; останній вже має payload injected і саме його слід flash/boot-test.

## Можливості runtime payload (EL3)

Патчений bl2_ext payload може:
- Реєструвати власні fastboot команди
- Керувати/перевизначати boot mode
- Динамічно викликати вбудовані функції bootloader під час runtime
- Підроблювати “lock state” як locked при фактичному unlocked, щоб пройти посилені перевірки цілісності (в деяких середовищах все ще можуть знадобитися корекції vbmeta/AVB)

Обмеження: Нинішні PoCs вказують, що runtime memory modification може спричиняти fault через обмеження MMU; payloads загалом уникають live memory writes, поки це не буде вирішено.

## Шаблони розгортання payload (EL3)

Fenrir розбиває свою інструментацію на три compile-time стадії: stage1 виконується перед `platform_init()`, stage2 виконується перед тим як LK сигналізує про вхід у fastboot, а stage3 виконується безпосередньо перед тим, як LK завантажує Linux. Кожен заголовок пристрою в `payload/devices/` надає адреси для цих hooks та допоміжних fastboot символів, тож синхронізуйте ці offsets з вашою цільовою збіркою.

Stage2 — зручне місце для реєстрації довільних `fastboot oem` verbs:
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
Stage3 демонструє, як тимчасово змінювати атрибути таблиць сторінок, щоб пропатчити незмінні рядки, такі як Android’s “Orange State” warning, без необхідності доступу до downstream kernel:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Оскільки stage1 запускається до platform bring-up, це підходяще місце для виклику OEM power/reset primitives або для вставки додаткового логування цілісності перед тим, як verified boot chain буде зруйновано.

## Поради щодо портування

- Зробіть реверс-інжиніринг device-specific bl2_ext, щоб знайти логіку політики верифікації (наприклад, sec_get_vfy_policy).
- Визначте місце повернення політики або гілку рішення й запатчте її на “no verification required” (return 0 / unconditional allow).
- Тримайте offsets повністю специфічними для пристрою та прошивки; не повторно використовуйте адреси між варіантами.
- Спочатку валідуйте на sacrificial unit. Підготуйте план відновлення (наприклад, EDL/BootROM loader/SoC-specific download mode) перед прошивкою.
- Пристрої, що використовують lk2 secondary bootloader або які повідомляють “img_auth_required = 0” для bl2_ext навіть у заблокованому стані, слід вважати вразливими екземплярами цього класу багів; Vivo X80 Pro вже спостерігався з пропуском верифікації незважаючи на звіт про lock state.
- Порівняйте expdb logs у заблокованому й розблокованому станах — якщо certificate timing стрибає з 0 ms до ненульового значення після повторного блокування, ймовірно ви запатчили правильну точку рішення, але все ще потрібно підсилити lock-state spoofing, щоб приховати модифікацію.

## Вплив на безпеку

- EL3 code execution після Preloader і повний крах chain-of-trust для решти шляху завантаження.
- Можливість завантажити unsigned TEE/GZ/LK/Kernel, обходячи secure/verified boot очікування та забезпечивши персистентне скомпрометування.

## Примітки щодо пристроїв

- Підтверджено підтримується: Nothing Phone (2a) (Pacman)
- Відомо працездатні (часткова підтримка): CMF Phone 1 (Tetris)
- Спостерігалося: Vivo X80 Pro, ймовірно, не перевіряв bl2_ext навіть у заблокованому стані
- Огляди галузі виділяють додаткових постачальників на базі lk2, що постачають ту саму логічну помилку, тож очікуйте подальше перекриття в релізах MTK 2024–2025 років.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
