# Уразливості ядра macOS

{{#include ../../../banners/hacktricks-training.md}}

Сучасна експлуатація ядра macOS полягає не стільки в тому, щоб «завантажити тривіальний unsigned kext і отримати ring-0», скільки у зловживанні **Mach/MIG parsers**, **IOKit user clients**, **data-only races усередині XNU** і **specially entitled daemons**, які все ще можуть повторно відкрити attack surface ядра. Для реверсингу конкретних інтерфейсів також перегляньте сторінки про [**IOKit**](macos-iokit.md) і [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces, які досі мають значення

- **Mach/MIG handlers** у системних daemons і kernel-facing services: malformed descriptors, out-of-line (OOL) data та stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods і wrapper libraries/daemons, які приховують реальний call graph.
- **XNU data-only primitives**: races навколо credentials, SMR-protected pointers, read-only zones та інші місця, де corruption змінює policy, не забезпечуючи спочатку контроль над RIP/PC.
- **Third-party / auxiliary kernel code**: legacy kexts трапляються рідше, але enterprise fleets, системи Apple Silicon зі зниженим рівнем безпеки та vendor `.fs` / helper bundles і далі створюють цінні kernel-adjacent paths.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) кілька bugs в OTA/update-chain об’єднано для досягнення компрометації ядра шляхом зловживання software update pipeline і можливостями, пов’язаними з rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: ланцюжок обходу захисту ядра, використаний у реальних атаках (CVE-2024-23225 & CVE-2024-23296)

[**Березневі security releases macOS 2024 року**](https://support.apple.com/en-us/120895) від Apple виправили дві проблеми, які **активно експлуатувалися**:

- **CVE-2024-23225 – Kernel**: memory-corruption bug, за якої attacker з arbitrary kernel read/write міг обійти kernel memory protections.
- **CVE-2024-23296 – RTKit**: друга memory-corruption bug із таким самим public impact statement.

Публічних деталей щодо першопричини досі мало, але ця пара нагадує, що сучасні exploit chains Apple часто потребують **не лише «самого» kernel R/W**: post-exploitation проти memory protections, coprocessor-adjacent code або secondary trust boundaries часто є етапом, на якому реальний chain стабілізується.

Швидкий triage патчів:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + race під час роботи з read-only credentials (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) Joseph Ravichandran — дуже хороший сучасний приклад для XNU, оскільки це **не** classic buffer overflow:

- `proc_ro.p_ucred` — це **SMR-protected pointer**, що зберігається в **read-only** об'єкті `proc_ro`.
- Записувачі повинні оновлювати цей pointer **атомарно**.
- `kauth_cred_proc_update()` використовувала `zalloc_ro_mut(...)` для зміни `p_ucred`; на x86_64 цей шлях зрештою викликає `memcpy` / `rep movsb`, тому конкурентний reader може побачити **torn pointer**.
- Bug перетворюється на **data-only privilege escalation**: якщо пошкоджений credential pointer вказує на інший дійсний credential object, поточний thread може успадкувати більш привілейований стан, не отримуючи спочатку очевидного control-flow hijack.

Мінімальний trigger pattern:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Корисна audit-евристика: щоразу, коли kernel path поєднує **SMR readers**, **read-only zone mutation** і **credential або task metadata**, перевіряйте, що оновлення використовують atomic `zalloc_ro_mut_*` variants, а не copy-based helpers.

---

## 2024-2025: SIP bypass, який повторно відкриває шляхи завантаження kernel (CVE-2024-44243)

Microsoft показала, що `storagekitd` можна було використати для **bypass SIP**, після чого third-party kernel code знову ставав релевантним на машинах, які інакше виглядали б як "post-kext". Ключова ідея:

1. Розмістити або перезаписати шкідливий `.fs` bundle у `/Library/Filesystems`.
2. Запустити `storagekitd` через Disk Utility або `diskutil`.
3. Дозволити daemon із відповідними entitlement-ами запускати bundle executables **без належного зниження привілеїв / перевірки path**.
4. Використати отриманий SIP bypass для зміни захищеного file-system state і, у демонстрації Microsoft, перевизначити kernel extension exclusion list.

Для kernel researchers важливий висновок полягає в тому, що **kernel attack surface може бути повторно відкритий через userland management daemons**, навіть коли пряме завантаження third-party kext значно обмежене.

Корисний triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing і workflow дослідження

Якщо ви активно шукаєте цей клас багів, нещодавні публічні дослідження вказують у тому самому напрямку:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) досі є одним із найкращих орієнтирів для дослідження kernel в епоху Apple Silicon. Він використовує **static binary rewriting** для відновлення coverage, вимикає **entitlement-gated** шляхи під час тестування та визначає структуру інтерфейсів за userspace-обгортками.
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) від Project Zero демонструє дуже практичний workflow для **rebasing kext / fileset у userspace**, завдяки чому код із великою кількістю парсерів можна fuzz-ити на значно вищій швидкості перед відтворенням на пристрої.
- Для цілей із великою кількістю Mach створюйте harness навколо **реальних структур повідомлень і state machine із кількома викликами**, а не лише окремих selector blob. Недавні дослідження CoreAudio/Mach від Project Zero та доповіді на конференціях, такі як **Fuzzing at Mach Speed**, показують, чому stateful послідовності повідомлень продовжують давати результати.

Короткі локальні команди, які ви насправді часто використовуватимете:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Шпаргалка зі швидкого перерахування
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Посилання

* Joseph Ravichandran. «TRAVERTINE: CVE-2025-24118.» https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. «Аналіз CVE-2024-44243, обходу macOS System Integrity Protection через kernel extensions.» https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
