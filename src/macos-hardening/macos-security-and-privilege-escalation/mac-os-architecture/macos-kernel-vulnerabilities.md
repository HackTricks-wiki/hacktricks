# Вразливості ядра macOS

{{#include ../../../banners/hacktricks-training.md}}

Сучасна експлуатація ядра macOS полягає не стільки в тому, щоб «завантажити тривіальний unsigned kext і отримати ring-0», скільки у зловживанні **Mach/MIG-парсерами**, **IOKit user clients**, **data-only race-умовами всередині XNU** та **спеціально привілейованими демонами**, які все ще можуть повторно відкрити поверхню атаки ядра. Для реверсингу конкретних інтерфейсів також перегляньте сторінки про [**IOKit**](macos-iokit.md) і [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Поверхні атаки, які все ще мають значення

- **Обробники Mach/MIG** у системних демонах і сервісах, що взаємодіють із ядром: некоректно сформовані дескриптори, дані поза смугою (OOL) і stateful-послідовності з кількох повідомлень.
- **IOKit user clients**: парсинг, специфічний для selector, методи, доступ до яких обмежений entitlement, а також wrapper-бібліотеки/демони, що приховують реальний call graph.
- **Data-only primitives XNU**: race-умови навколо credentials, вказівників, захищених SMR, read-only zones та інших місць, де пошкодження змінює політику без попереднього отримання контролю над RIP/PC.
- **Сторонній / допоміжний код ядра**: legacy kexts трапляються рідше, але корпоративні середовища, системи Apple Silicon зі зниженим рівнем безпеки та сторонні `.fs` / helper bundles усе ще створюють цінні шляхи, суміжні з ядром.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) кілька помилок в OTA/update-chain об'єднано для отримання компрометації ядра через зловживання pipeline оновлення ПЗ і можливостями, пов'язаними з rootless.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: ланцюжок обходу захисту ядра, використаний у реальних атаках (CVE-2024-23225 та CVE-2024-23296)

У [**березневих security releases macOS 2024 року**](https://support.apple.com/en-us/120895) Apple виправила дві проблеми, які **активно експлуатувалися**:

- **CVE-2024-23225 – Kernel**: помилка пошкодження пам'яті, за якої зловмисник із довільним kernel read/write міг обійти захист пам'яті ядра.
- **CVE-2024-23296 – RTKit**: друга помилка пошкодження пам'яті з таким самим публічним описом впливу.

Загальнодоступних деталей першопричини досі мало, але ця пара добре нагадує, що сучасні exploit chains Apple часто потребують **не лише «простого» kernel R/W**: post-exploitation проти захисту пам'яті, коду, суміжного з coprocessor, або вторинних trust boundaries часто є тим етапом, на якому стабілізується реальний ланцюжок.

Швидке сортування patch-ів:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) Joseph Ravichandran є дуже хорошим сучасним прикладом дослідження XNU, оскільки це **не класичний buffer overflow**:<sup>[1]</sup>

- `proc_ro.p_ucred` — це **SMR-protected pointer**, що зберігається в об’єкті `proc_ro`, доступному лише для читання.
- Записувачі повинні оновлювати цей pointer **атомарно**.
- `kauth_cred_proc_update()` використовувала `zalloc_ro_mut(...)` для зміни `p_ucred`; на x86_64 цей шлях зрештою викликає `memcpy` / `rep movsb`, тому конкурентний reader може побачити **torn pointer**.
- Вразливість перетворюється на **data-only privilege escalation**: якщо пошкоджений credential pointer вказує на інший дійсний credential object, поточний thread може успадкувати привілейованіший стан, не отримуючи спочатку очевидного control-flow hijack.

Мінімальний шаблон trigger:
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
Корисна евристика для аудиту: щоразу, коли шлях ядра поєднує **читачі SMR**, **модифікацію read-only зон** і **метадані облікових даних або завдань**, перевіряйте, що оновлення використовують атомарні варіанти `zalloc_ro_mut_*`, а не допоміжні функції на основі копіювання.

---

## 2024-2025: обхід SIP, який повторно відкриває шляхи завантаження kernel (CVE-2024-44243)

Microsoft показала, що `storagekitd` можна було використати для **обходу SIP**, після чого сторонній kernel code знову ставав актуальним на машинах, які інакше виглядали б як системи "post-kext". Ключова ідея:<sup>[2]</sup>

1. Розмістити або перезаписати шкідливий `.fs` bundle у `/Library/Filesystems`.
2. Запустити `storagekitd` через Disk Utility або `diskutil`.
3. Дозволити daemon зі спеціальними entitlement запускати виконувані файли bundle **без належного скидання привілеїв / перевірки шляху**.
4. Використати отриманий обхід SIP для зміни захищеного стану file-system і, як продемонструвала Microsoft, перевизначити список виключень kernel extension.

Для дослідників kernel важливо, що **attack surface ядра може бути повторно відкритий через userland management daemons**, навіть коли пряме завантаження сторонніх kext значно обмежене.

Корисна первинна перевірка:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing і робочий процес дослідження

Якщо ви активно шукаєте цей клас багів, нещодавні публічні дослідження вказують у тому самому напрямку:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) і досі залишається одним із найкращих матеріалів для дослідження kernel в епоху Apple Silicon. Він використовує **static binary rewriting** для відновлення покриття, вимикає шляхи, захищені **entitlement**, під час тестування та виводить структуру інтерфейсів із userspace-обгорток.<sup>[4]</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) від Project Zero демонструє дуже практичний робочий процес **rebasing kext / fileset у userspace**, щоб код із великою кількістю парсерів можна було fuzzing на значно вищій швидкості перед відтворенням на пристрої.<sup>[5]</sup>
- Для цілей із великою кількістю Mach створюйте harness навколо **реальних структур повідомлень і state machines із кількома викликами**, а не лише одиночних selector blob. Нещодавні дослідження CoreAudio/Mach від Project Zero та конференційні доповіді, зокрема **Fuzzing at Mach Speed**, показують, чому stateful-послідовності повідомлень і надалі дають результат.

Швидкі локальні команди, які ви насправді часто використовуватимете:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Коротка шпаргалка з перерахування
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Аналіз CVE-2024-44243, обходу System Integrity Protection у macOS через kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Кошмар OTA Update від Apple: обхід перевірки підпису та отримання контролю над kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin та ін. - KextFuzz: fuzzing kernel extensions macOS на Apple Silicon через використання mitigation (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Простий fuzzing kernel extensions macOS у userspace за допомогою IDA та TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
