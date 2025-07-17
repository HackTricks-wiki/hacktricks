# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**U ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) objašnjene su nekoliko ranjivosti koje su omogućile kompromitovanje kernela kompromitujući softverski ažurirač.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: U divljini Kernel 0-dana (CVE-2024-23225 & CVE-2024-23296)

Apple je zakrpio dve greške u korupciji memorije koje su aktivno korišćene protiv iOS-a i macOS-a u martu 2024. (ispravljeno u macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**
• Pisanje van granica u XNU virtuelnom memorijskom podsistemu omogućava neprivilegovanom procesu da dobije proizvoljno čitanje/pisanje u adresnom prostoru kernela, zaobilazeći PAC/KTRR.
• Aktivira se iz korisničkog prostora putem kreirane XPC poruke koja preplavljuje bafer u `libxpc`, a zatim prelazi u kernel kada se poruka analizira.
* **CVE-2024-23296 – RTKit**
• Korupcija memorije u Apple Silicon RTKit (real-time ko-procesor).
• Lanac eksploatacije koji je primećen koristio je CVE-2024-23225 za kernel R/W i CVE-2024-23296 za izlazak iz sandboxes-a sigurnog ko-procesora i onemogućavanje PAC.

Patch level detection:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Ako nadogradnja nije moguća, ublažite problem onemogućavanjem ranjivih usluga:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` zahtevi poslati neprivilegovanom IOKit korisničkom klijentu dovode do **tipa konfuzije** u MIG generisanom lepljivom kodu. Kada se odgovor poruka ponovo interpretira sa većim van-linijskim deskriptorom nego što je prvobitno alocirano, napadač može postići kontrolisano **OOB pisanje** u kernel heap zone i na kraju
escalirati na `root`.

Primitive outline (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits weaponise the bug by:
1. Prskanjem `ipc_kmsg` bafera sa aktivnim pokazivačima portova.
2. Prepisivanjem `ip_kobject` od visećeg porta.
3. Skakanjem na shellcode mapiran na PAC-falsifikovanu adresu koristeći `mprotect()`.

---

## 2024-2025: SIP Bypass kroz treće strane Kexts – CVE-2024-44243 (poznat kao “Sigma”)

Istraživači bezbednosti iz Microsoft-a su pokazali da se visoko privilegovani demon `storagekitd` može primorati da učita **nepotpisanu kernel ekstenziju** i tako potpuno onemogući **System Integrity Protection (SIP)** na potpuno zakrčenom macOS-u (pre 15.2). Tok napada je:

1. Zloupotreba privatnog prava `com.apple.storagekitd.kernel-management` da se pokrene pomoćni program pod kontrolom napadača.
2. Pomoćni program poziva `IOService::AddPersonalitiesFromKernelModule` sa kreiranim info-rečnikom koji upućuje na zloćudni kext paket.
3. Pošto se SIP provere poverenja vrše *nakon* što `storagekitd` postavi kext, kod se izvršava u ring-0 pre validacije i SIP se može isključiti sa `csr_set_allow_all(1)`.

Detection tips:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Odmah rešenje je ažuriranje na macOS Sequoia 15.2 ili noviji.

---

### Brza enumeracija Cheatsheet
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

* **Luftrauser** – Mach message fuzzer koji cilja MIG pod sisteme (`github.com/preshing/luftrauser`).
* **oob-executor** – IPC out-of-bounds primitivni generator korišćen u istraživanju CVE-2024-23225.
* **kmutil inspect** – Ugrađeni Apple alat (macOS 11+) za statičku analizu kext-ova pre učitavanja: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
