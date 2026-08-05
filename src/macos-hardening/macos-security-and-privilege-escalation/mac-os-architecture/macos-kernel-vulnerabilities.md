# Уразливості ядра macOS

{{#include ../../../banners/hacktricks-training.md}}

Сучасна експлуатація ядра macOS полягає не стільки в тому, щоб «завантажити тривіальний unsigned kext і отримати ring-0», скільки у зловживанні **Mach/MIG parsers**, **IOKit user clients**, **data-only races всередині XNU** та **specially entitled daemons**, які досі можуть повторно відкрити attack surface ядра. Для реверсингу конкретних інтерфейсів також перегляньте сторінки про [**IOKit**](macos-iokit.md) і [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces, які досі мають значення

- **Mach/MIG handlers** у системних daemons і сервісах, що взаємодіють із ядром: malformed descriptors, out-of-line (OOL) data та stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods і wrapper libraries/daemons, які приховують реальний call graph.
- **XNU data-only primitives**: races навколо credentials, SMR-protected pointers, read-only zones та інших місць, де corruption змінює policy без попереднього отримання контролю над RIP/PC.
- **Third-party / auxiliary kernel code**: legacy kexts трапляються рідше, але enterprise fleets, системи Apple Silicon зі зниженим рівнем безпеки та vendor `.fs` / helper bundles і надалі створюють цінні kernel-adjacent paths.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

У [**цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) кілька bugs в OTA/update-chain об’єднано для отримання компрометації ядра через зловживання software update pipeline і можливостями, пов’язаними з rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: ланцюжок обходу захисту ядра, використаний in-the-wild (CVE-2024-23225 & CVE-2024-23296)

У [**березневих security releases macOS 2024 року**](https://support.apple.com/en-us/120895) Apple виправила дві issues, які **активно експлуатувалися**:

- **CVE-2024-23225 – Kernel**: memory-corruption bug, за допомогою якого attacker з arbitrary kernel read/write міг обійти kernel memory protections.
- **CVE-2024-23296 – RTKit**: ще один memory-corruption bug із таким самим public impact statement.

Публічних деталей root cause досі мало, але ця пара добре нагадує, що сучасні Apple exploit chains часто потребують **не лише «просто» kernel R/W**: post-exploitation проти memory protections, coprocessor-adjacent code або secondary trust boundaries часто є саме тим етапом, на якому стабілізується реальний chain.

Швидкий patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + race condition with a read-only credential (CVE-2025-24118)

Joseph Ravichandran's [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) is a very good modern XNU case study because it is **not** a classic buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` is an **SMR-protected pointer** stored in a **read-only** `proc_ro` object.
- Writers must update that pointer **atomically**.
- `kauth_cred_proc_update()` used `zalloc_ro_mut(...)` to mutate `p_ucred`; on x86_64 that path eventually hits `memcpy` / `rep movsb`, so a concurrent reader can observe a **torn pointer**.
- The bug turns into a **data-only privilege escalation**: if the corrupted credential pointer resolves to a different valid credential object, the current thread can inherit more privileged state without first winning an obvious control-flow hijack.

Minimal trigger pattern:
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
Корисна евристика аудиту: щоразу, коли шлях ядра поєднує **SMR readers**, **мутацію read-only зон** і **метадані credentials або task**, перевіряйте, чи використовують оновлення атомарні варіанти `zalloc_ro_mut_*`, а не helper-и на основі копіювання.

---

## 2024-2025: SIP bypass, який повторно відкриває шляхи завантаження ядра (CVE-2024-44243)

Microsoft показала, що `storagekitd` можна використати для **обходу SIP**, після чого сторонній kernel code знову стає актуальним на машинах, які інакше виглядали б як такі, що перебувають у стані "post-kext". Ключова ідея:<sup>[[2]](#references)</sup>

1. Розмістити або перезаписати шкідливий `.fs` bundle у `/Library/Filesystems`.
2. Запустити `storagekitd` через Disk Utility або `diskutil`.
3. Дозволити daemon зі спеціальними entitlement-ами запускати executables bundle **без належного скидання privileges / перевірки path**.
4. Використати отриманий SIP bypass для зміни захищеного стану file system і, у демонстрації Microsoft, перевизначити список виключень kernel extension.

Для kernel researchers важливий висновок полягає в тому, що **kernel attack surface може бути повторно введена через userland management daemons**, навіть коли пряме завантаження сторонніх kext значно обмежене.

Корисний triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow fuzzing і research

Якщо ви активно шукаєте помилки цього класу, нещодавні публічні дослідження вказують у тому самому напрямку:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) і досі є одним із найкращих джерел для дослідження kernel в епоху Apple Silicon. Він використовує **static binary rewriting** для відновлення coverage, вимикає шляхи, захищені **entitlement**, під час тестування та виводить структуру інтерфейсу з userspace-обгорток.<sup>[[4]](#references)</sup>
- Project Zero у матеріалі [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) демонструє дуже практичний workflow для **rebasing kext / fileset у userspace**, щоб parser-heavy код можна було fuzzити на значно вищій швидкості перед відтворенням на пристрої.<sup>[[5]](#references)</sup>
- Для цілей із великою часткою Mach створюйте harnesses на основі **реальних структур повідомлень і state machines із кількома викликами**, а не лише окремих selector blobs. Нещодавні дослідження CoreAudio/Mach від Project Zero та доповіді на конференціях, як-от **Fuzzing at Mach Speed**, демонструють, чому stateful послідовності повідомлень продовжують давати результати.

Короткі локальні команди, які ви часто використовуватимете:
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Аналіз CVE-2024-44243, обходу macOS System Integrity Protection через kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Кошмар OTA Update від Apple: обхід перевірки підпису та pwning kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions на Apple Silicon через використання mitigation (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Простий fuzzing macOS kernel extension у userspace за допомогою IDA та TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
