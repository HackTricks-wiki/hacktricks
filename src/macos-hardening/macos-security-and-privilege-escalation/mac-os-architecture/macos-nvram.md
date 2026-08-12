# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

**NVRAM** (Non-Volatile Random-Access Memory) зберігає дані firmware і стан раннього завантаження поза межами звичайної файлової системи macOS. Вплив на security залежить як від змінної, так і від архітектури завантаження:

| Змінна | Призначення / значення для security |
|---|---|
| `boot-args` | Аргументи, що передаються kernel. Debug- або security-reducing-аргументи фільтруються, якщо boot policy не дозволяє їх. |
| `csr-active-config` | SIP bitmask на Intel Mac. На Apple silicon еквівалентна policy зберігається в `LocalPolicy` для кожного тому, а не безпосередньо довіряється цій змінній. |
| `efi-boot-device` / `efi-boot-device-data` | Ціль завантаження Intel EFI. |
| `boot-volume` | Стан вибору boot volume на Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Приклади звичайних persistent settings. |

Важливо розрізняти **дані, збережені в NVRAM**, і **security policy, прийняту boot chain**. На Apple silicon Secure Enclave підписує `LocalPolicy` для кожної групи boot volume; nonce, що зберігається в Secure Storage Component, забезпечує захист від повторного відтворення. Отже, зміна властивості NVRAM із подібною назвою сама по собі не переписує прийняту boot policy.<sup>[[1]](#references)[[4]](#references)</sup>

## Доступ до NVRAM із User Space

### Зчитування та збір базових даних
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
Не класифікуйте кожен незнайомий ключ як шкідливий. Апаратне забезпечення, recoveryOS, оновлення, Find My та помилки завантаження створюють змінні, що залежать від моделі й версії. Порівнюйте отримані дані з попереднім baseline від **того самого Mac**, а неочікувані бінарні blobs, змінену конфігурацію завантаження або аргументи, що знижують рівень безпеки, розглядайте як напрямки для перевірки, а не як доказ компрометації.

### Запис до NVRAM

Root може створювати або змінювати багато звичайних змінних, але захищені змінні додатково залежать від namespace змінної, SIP, правил kernel для конкретної змінної та restricted Apple entitlements. Тому успішне виконання `sudo` для нешкідливого custom key **не** доводить, що процес може змінювати `boot-args`, SIP або змінні system-region.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Уникайте `nvram -c` під час тестування: вона запитує видалення всіх змінних, доступних для видалення, і може змінити поведінку завантаження/відновлення. Деякі змінні доступні лише ядру, захищені entitlement, приховані під час читання або можуть бути видалені лише під час скидання NVRAM.

## Entitlements NVRAM і `CS_NVRAM_UNRESTRICTED`

Під час exec XNU зіставляє `com.apple.rootless.restricted-nvram-variables.heritable` із прапорцем процесу **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Це не еквівалентно звичайній перевірці ефективного UID 0. Також існують вужчі приватні entitlements для окремих змінних або операцій.

Перевіряйте entitlements, а не покладайтеся на загальний рядок прапорців, який виводить `codesign`:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Під час аудиту привілейованого helper відстежуйте **фактичну ідентичність клієнта та шлях запиту**. Помилка confused-deputy у service з відповідними entitlement може бути кориснішою за прямий виклик `nvram`, але доступна змінна/операція все одно може бути обмежена XNU.

## Стан Intel SIP проти `LocalPolicy` на Apple Silicon

### Intel: `csr-active-config`

На Intel `csr-active-config` кодує винятки `CSR_ALLOW_*`. Позиції бітів, що найчастіше мають значення:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Перевірте ефективне налаштування за допомогою `csrutil status`; необроблений вивід `nvram` може використовувати байти з percent-кодуванням у little-endian форматі. Див. [macOS SIP](../macos-security-protections/macos-sip.md), щоб дізнатися про захист і наслідки bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: перевірка прийнятої політики завантаження

На Apple silicon `sip0` у підписаному Secure Enclave файлі `LocalPolicy` містить біти політики SIP, які раніше зберігалися в NVRAM. Інші відповідні поля політики: `sip1` (дозволити помилку перевірки root-хешу SSV), `sip2` (не блокувати пам’ять ядра за допомогою CTRR) і `sip3` (вимкнути allowlist `boot-args` в iBoot). Ці поля можна змінювати лише з пов’язаного One True recoveryOS (1TR); увімкнення `sip3` також потребує переходу до Permissive Security.<sup>[[4]](#references)</sup>

Під час перерахування використовуйте лише операції відображення:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Не використовуйте параметри `bputil`, що змінюють політику, під час аудиту. Звичайна компрометація macOS не повинна дозволяти непомітно ввімкнути наведені вище поля: шлях downgrade навмисно вимагає фізичного доступу до пов'язаного 1TR і автентифікації власника.<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` як підсилювач після компрометації

Аргументи на кшталт параметрів налагодження ядра, `kcsuffix=development` або `amfi_get_out_of_my_way=1` можуть послабити подальші етапи завантаження, але лише якщо платформа їх приймає. На Apple silicon у режимах Full або Reduced Security iBoot фільтрує аргументи, що знижують рівень безпеки; необмежені аргументи вимагають описаного вище downgrade політики `sip3`. На Intel обмеження NVRAM, що встановлюється SIP, аналогічно не дозволяє вважати root shell автоматичним контролем над `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Дивіться [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) і [kernel debugging](macos-kernel-extensions.md), а не припускайте, що історичний аргумент поводиться однаково в кожному випуску macOS.

### Виконання `rc.trampoline` на основі NVRAM

Нещодавні дослідження задокументували конкретний компонент, що використовує дані NVRAM: платформний binary Apple `/System/Library/CoreServices/rc.trampoline`. Коли launchd бачить boot argument `rc.trampoline=1`, це boot task зчитує властивість `apple-trusted-trampoline` з `IODeviceTree:/options`, записує її в тимчасовий executable file, запускає його в призупиненому стані, перевіряє його code-signing state, від’єднує його, а потім відновлює його виконання. Boot task блокує launchd, доки дочірній процес не завершиться.<sup>[[5]](#references)</sup>

Це **persistence primitive після downgrade, а не SIP bypass**. Продемонстрований шлях вимагав вимкненого SIP, щоб boot task запустився, а `boot-args` можна було встановити. Дослідження також виявило приблизне обмеження розміру значення у 390 КБ. Його цінність полягає в тому, що executable bytes можуть зберігатися поза звичайною файловою системою та матеріалізуватися під час boot після того, як attacker уже отримав необхідне security downgrade.<sup>[[5]](#references)</sup>

Шукайте обидва необхідні артефакти та подію launchd:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Довільні користувацькі змінні NVRAM в іншому випадку є лише **сховищем**: вони нічого не виконують, якщо їх не використовує прошивка, компонент завантаження Apple або окремий механізм persistence. Це розрізнення запобігає перебільшенню значення такого маркера, як `nvram attacker-config=...`, до виконання коду прошивки.

## Скрипт Enumeration

<details>
<summary>Аудит NVRAM і політики завантаження Apple silicon</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Посібник з безпеки платформи Apple — процес завантаження](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Оновлення безпеки Apple — CVE, пов’язані з NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — безпека Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Безпека платформи Apple — вміст файлу LocalPolicy для Mac з Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — Persistence через NVRAM за допомогою apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
