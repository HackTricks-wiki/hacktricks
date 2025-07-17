# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**У цьому звіті**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) пояснюються кілька вразливостей, які дозволили скомпрометувати ядро, скомпрометувавши програмне забезпечення для оновлення.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Вразливості ядра 0-days у диких умовах (CVE-2024-23225 & CVE-2024-23296)

Apple виправила дві помилки корупції пам'яті, які активно експлуатувалися проти iOS та macOS у березні 2024 року (виправлено в macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Ядро**
• Запис за межами меж у підсистемі віртуальної пам'яті XNU дозволяє непривабливому процесу отримати довільний читання/запис у адресному просторі ядра, обходячи PAC/KTRR.
• Викликано з простору користувача через спеціально підготовлене повідомлення XPC, яке переповнює буфер у `libxpc`, а потім переходить у ядро, коли повідомлення аналізується.
* **CVE-2024-23296 – RTKit**
• Корупція пам'яті в Apple Silicon RTKit (процесор реального часу).
• Спостережені ланцюги експлуатації використовували CVE-2024-23225 для R/W ядра та CVE-2024-23296 для виходу з пісочниці безпечного сопроцесора та відключення PAC.

Виявлення рівня патчу:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Якщо оновлення неможливе, зменшіть ризики, вимкнувши вразливі сервіси:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` запити, надіслані до неправа IOKit користувацького клієнта, призводять до **плутанини типів** у згенерованому MIG клеєвому коді. Коли повідомлення-відповідь повторно інтерпретується з більшим поза межами дескриптором, ніж було спочатку виділено, зловмисник може досягти контрольованого **OOB запису** в зони ядра та врешті-решт
підвищити привілеї до `root`.

Примітивний контур (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Публічні експлойти використовують уразливість наступним чином:
1. Розподіляючи буфери `ipc_kmsg` з активними вказівниками портів.
2. Перезаписуючи `ip_kobject` висячого порту.
3. Перемикаючись на shellcode, відображений за адресою, підробленою PAC, за допомогою `mprotect()`.

---

## 2024-2025: Обхід SIP через сторонні Kexts – CVE-2024-44243 (також відомий як “Sigma”)

Дослідники безпеки з Microsoft показали, що високопривілейований демон `storagekitd` може бути змушений завантажити **недопідписане розширення ядра** і таким чином повністю відключити **Захист цілісності системи (SIP)** на повністю оновленому macOS (до 15.2). Потік атаки виглядає так:

1. Зловживання приватним правом `com.apple.storagekitd.kernel-management`, щоб запустити допоміжний процес під контролем зловмисника.
2. Допоміжний процес викликає `IOService::AddPersonalitiesFromKernelModule` з підготовленим словником інформації, що вказує на шкідливий пакет kext.
3. Оскільки перевірки довіри SIP виконуються *після* того, як kext був підготовлений `storagekitd`, код виконується в режимі ring-0 до валідації, і SIP можна вимкнути за допомогою `csr_set_allow_all(1)`.

Поради щодо виявлення:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Негайне усунення проблеми - оновитися до macOS Sequoia 15.2 або пізнішої версії.

---

### Швидка таблиця для перерахунку
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach message fuzzer, що націлений на MIG підсистеми (`github.com/preshing/luftrauser`).
* **oob-executor** – Генератор примітивів IPC out-of-bounds, використаний у дослідженні CVE-2024-23225.
* **kmutil inspect** – Вбудована утиліта Apple (macOS 11+), що дозволяє статично аналізувати kexts перед завантаженням: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
