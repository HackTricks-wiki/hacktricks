# Вразливості ядра macOS

{{#include ../../../banners/hacktricks-training.md}}

Сучасна експлуатація ядра macOS полягає вже не стільки в тому, щоб «завантажити тривіальний unsigned kext і отримати ring-0», скільки в зловживанні **парсерами Mach/MIG**, **IOKit user clients**, **data-only race conditions усередині XNU** та **спеціально привілейованими демонами**, які все ще можуть повторно відкрити поверхню атаки ядра. Для реверсингу конкретних інтерфейсів також перегляньте сторінки про [**IOKit**](macos-iokit.md) і [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Поверхні атаки, які досі мають значення

- **Обробники Mach/MIG** у системних демонах і сервісах, що взаємодіють із ядром: некоректні дескриптори, out-of-line (OOL) data та stateful flows із кількома повідомленнями.
- **IOKit user clients**: parsing, специфічний для selector, методи, захищені entitlement, а також wrapper-бібліотеки/демони, які приховують реальний call graph.
- **Data-only primitives XNU**: race conditions навколо облікових даних, вказівників, захищених SMR, read-only зон та інших місць, де corruption змінює policy без необхідності спочатку отримувати контроль над RIP/PC.
- **Сторонній / допоміжний kernel code**: legacy kexts трапляються рідше, але enterprise-флоти, системи Apple Silicon зі зниженим рівнем безпеки та vendor `.fs` / helper bundles і досі створюють цінні шляхи, суміжні з ядром.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) кілька багів в OTA/update chain об’єднано для досягнення компрометації ядра через зловживання software update pipeline і можливостями, пов’язаними з rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: ланцюжок обходу захисту ядра, використаний in-the-wild (CVE-2024-23225 і CVE-2024-23296)

У [**березневих security releases macOS 2024 року**](https://support.apple.com/en-us/120895) Apple виправила дві проблеми, які **активно експлуатувалися**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: memory-corruption bug, за допомогою якого attacker із довільним kernel read/write міг обійти захист пам’яті ядра.
- **CVE-2024-23296 – RTKit**: другий memory-corruption bug із таким самим публічним описом впливу.

Публічних деталей щодо root cause досі мало, але ця пара добре нагадує, що сучасні Apple exploit chains часто потребують **не лише «просто» kernel R/W**: post-exploitation проти захисту пам’яті, коду, суміжного з coprocessor, або вторинних trust boundaries часто є саме тим етапом, на якому стабілізується реальний ланцюжок.

Швидка triage для patch:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + гонка read-only credential (CVE-2025-24118)

[**Звіт TRAVERTINE**](https://jprx.io/cve-2025-24118/) Joseph Ravichandran є дуже хорошим сучасним прикладом дослідження XNU, оскільки це **не** класичний buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` — це **SMR-захищений pointer**, що зберігається в об’єкті `proc_ro`, доступному лише для читання.
- Записувачі повинні оновлювати цей pointer **атомарно**.
- `kauth_cred_proc_update()` використовував `zalloc_ro_mut(...)` для зміни `p_ucred`; на x86_64 цей шлях зрештою доходить до `memcpy` / `rep movsb`, тому конкурентний читач може побачити **частково записаний pointer**.
- Помилка перетворюється на **data-only privilege escalation**: якщо пошкоджений pointer вказує на інший дійсний credential object, поточний thread може успадкувати привілейованіший стан, не отримуючи спочатку очевидного control-flow hijack.

Мінімальний шаблон запуску:
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
Корисна евристика для аудиту: щоразу, коли kernel path поєднує **SMR readers**, **мутацію read-only zone** і **метадані credential або task**, перевіряйте, що оновлення використовують атомарні варіанти `zalloc_ro_mut_*`, а не helpers на основі копіювання.

---

## 2024-2025: SIP bypass, який повторно відкриває kernel loading paths (CVE-2024-44243)

Microsoft показала, що `storagekitd` можна було використати для **обходу SIP**, після чого third-party kernel code знову ставав актуальним на машинах, які інакше виглядали б як "post-kext". Ключова ідея:<sup>[[2]](#references)</sup>

1. Розмістити або перезаписати malicious `.fs` bundle у `/Library/Filesystems`.
2. Запустити `storagekitd` через Disk Utility або `diskutil`.
3. Дозволити daemon зі спеціальними entitlement запускати executables bundle **без належного скидання privileges / перевірки path**.
4. Використати отриманий SIP bypass для зміни захищеного file-system state і, як продемонструвала Microsoft, перевизначити kernel extension exclusion list.

Для kernel researchers важливий висновок полягає в тому, що **kernel attack surface може бути повторно введений через userland management daemons**, навіть коли пряме завантаження third-party kext суттєво обмежене.

Корисний triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing і дослідницький workflow

Якщо ви активно шукаєте цей клас багів, нещодавні публічні дослідження вказують у тому самому напрямку:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) досі є одним із найкращих орієнтирів для дослідження kernel в епоху Apple Silicon. Він використовує **static binary rewriting** для відновлення coverage, вимикає шляхи, обмежені **entitlement**, під час тестування та визначає структуру інтерфейсів із userspace-обгорток.<sup>[[4]](#references)</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) від Project Zero демонструє дуже практичний workflow для **rebasing kext / fileset у userspace**, щоб parser-heavy code можна було fuzzити на значно вищій швидкості перед відтворенням на пристрої.<sup>[[5]](#references)</sup>
- Для Mach-heavy targets створюйте harnesses на основі **real message layouts і multi-call state machines**, а не лише окремих selector blobs. Нещодавні дослідження CoreAudio/Mach від Project Zero та доповіді на конференціях, такі як **Fuzzing at Mach Speed**, показують, чому stateful message sequences продовжують давати результати.

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
## Шпаргалка для швидкого перерахування
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
- [2] [Microsoft Security Blog - Аналіз CVE-2024-44243, обходу macOS System Integrity Protection через kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Кошмар OTA Update від Apple: обхід Signature Verification і отримання контролю над Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin та ін. - KextFuzz: fuzzing macOS Kernel EXTensions на Apple Silicon шляхом використання Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Простий fuzzing macOS kernel extension у userspace за допомогою IDA і TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Про вміст оновлення безпеки macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
