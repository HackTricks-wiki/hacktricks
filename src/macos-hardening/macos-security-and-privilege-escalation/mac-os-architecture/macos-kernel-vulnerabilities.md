# Luki w jądrze macOS

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**W tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) wyjaśniono kilka luk, które pozwoliły na skompromitowanie jądra, co naraziło aktualizator oprogramowania.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Luki 0-day w dzikiej przyrodzie (CVE-2024-23225 & CVE-2024-23296)

Apple załatał dwa błędy związane z uszkodzeniem pamięci, które były aktywnie wykorzystywane przeciwko iOS i macOS w marcu 2024 (naprawione w macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Jądro**
• Zapis poza granicami w subsystemie pamięci wirtualnej XNU pozwala procesowi bez uprawnień na uzyskanie dowolnego odczytu/zapisu w przestrzeni adresowej jądra, omijając PAC/KTRR.
• Wywoływane z przestrzeni użytkownika za pomocą spreparowanej wiadomości XPC, która przepełnia bufor w `libxpc`, a następnie przechodzi do jądra, gdy wiadomość jest analizowana.
* **CVE-2024-23296 – RTKit**
• Uszkodzenie pamięci w Apple Silicon RTKit (procesor współpracujący w czasie rzeczywistym).
• Obserwowane łańcuchy eksploatacji wykorzystywały CVE-2024-23225 do R/W jądra i CVE-2024-23296 do ucieczki z piaskownicy bezpiecznego współprocesora i wyłączenia PAC.

Wykrywanie poziomu łaty:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Jeśli aktualizacja nie jest możliwa, złagodź ryzyko, wyłączając podatne usługi:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` wysyłane do nieuprzywilejowanego klienta IOKit prowadzą do **pomieszania typów** w kodzie klejącym generowanym przez MIG. Gdy wiadomość odpowiedzi jest reinterpretowana z większym zewnętrznym deskryptorem niż pierwotnie przydzielony, atakujący może osiągnąć kontrolowane **OOB write** w strefach sterty jądra i ostatecznie
eskalować do `root`.

Zarys prymitywy (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Publiczne exploity wykorzystują błąd poprzez:
1. Spryskiwanie buforów `ipc_kmsg` wskaźnikami aktywnych portów.
2. Nadpisywanie `ip_kobject` wiszącego portu.
3. Skakanie do shellcode'u mapowanego pod adresem sfałszowanym przez PAC za pomocą `mprotect()`.

---

## 2024-2025: Ominięcie SIP przez zewnętrzne Kexty – CVE-2024-44243 (znane jako “Sigma”)

Badacze bezpieczeństwa z Microsoftu pokazali, że wysoko uprzywilejowany demon `storagekitd` może być zmuszony do załadowania **niepodpisanego rozszerzenia jądra**, a tym samym całkowicie wyłączyć **Ochronę Integralności Systemu (SIP)** na w pełni załatanej wersji macOS (przed 15.2). Przebieg ataku to:

1. Wykorzystanie prywatnego uprawnienia `com.apple.storagekitd.kernel-management` do uruchomienia pomocnika pod kontrolą atakującego.
2. Pomocnik wywołuje `IOService::AddPersonalitiesFromKernelModule` z przygotowanym słownikiem informacji wskazującym na złośliwy pakiet kext.
3. Ponieważ kontrole zaufania SIP są przeprowadzane *po* tym, jak kext jest przygotowywany przez `storagekitd`, kod wykonuje się w ring-0 przed walidacją, a SIP można wyłączyć za pomocą `csr_set_allow_all(1)`.

Wskazówki dotyczące wykrywania:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Natychmiastowe rozwiązanie to zaktualizowanie do macOS Sequoia 15.2 lub nowszego.

---

### Szybka ściągawka do enumeracji
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

* **Luftrauser** – Fuzzer wiadomości Mach, który celuje w podsystemy MIG (`github.com/preshing/luftrauser`).
* **oob-executor** – Generator prymitywów IPC poza zakresem używany w badaniach CVE-2024-23225.
* **kmutil inspect** – Wbudowane narzędzie Apple (macOS 11+) do statycznej analizy kextów przed załadowaniem: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
