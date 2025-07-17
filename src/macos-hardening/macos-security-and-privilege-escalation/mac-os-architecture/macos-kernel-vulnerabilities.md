# macOS Kernel Kw vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**In hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) word verskeie kwesbaarhede verduidelik wat die kern gecompromitteer het deur die sagteware-opdatering te kompromitteer.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-die-wild Kern 0-dae (CVE-2024-23225 & CVE-2024-23296)

Apple het twee geheue-korrupsie foute reggestel wat aktief teen iOS en macOS in Maart 2024 uitgebuit is (reggestel in macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kern**
• Uit-die-grense skrywe in die XNU virtuele-geheue subsysteem laat 'n onprivilegieerde proses toe om arbitrêre lees/skrywe in die kern adresruimte te verkry, wat PAC/KTRR omseil.
• Geaktiveer vanuit gebruikersruimte via 'n vervaardigde XPC boodskap wat 'n buffer in `libxpc` oorloop, en dan in die kern draai wanneer die boodskap geparseer word.
* **CVE-2024-23296 – RTKit**
• Geheue korrupsie in die Apple Silicon RTKit (regte tyd co-prosessor).
• Uitbuitingskettings waargeneem het CVE-2024-23225 gebruik vir kern R/W en CVE-2024-23296 om die veilige co-prosessor sandbox te ontsnap en PAC te deaktiveer.

Patch vlak opsporing:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
As opgradering nie moontlik is nie, versag deur kwesbare dienste te deaktiveer:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Tipe-Verwarring – CVE-2023-41075

`mach_msg()` versoeke wat na 'n onprivilegieerde IOKit gebruiker kliënt gestuur word, lei tot 'n **tipe verwarring** in die MIG gegenereerde gomkode. Wanneer die antwoordboodskap herinterpreteer word met 'n groter buite-lijn beskrywer as wat oorspronklik toegeken is, kan 'n aanvaller 'n beheerde **OOB skrywe** in kern heap sone bereik en uiteindelik tot `root` opgradeer.

Primitive oorsig (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits wapen die fout deur:
1. `ipc_kmsg` buffers te spuit met aktiewe poort wysers.
2. `ip_kobject` van 'n hangende poort te oorskryf.
3. Na shellcode te spring wat op 'n PAC-gefabriseerde adres gemap is met behulp van `mprotect()`.

---

## 2024-2025: SIP Bypass deur Derdeparty Kexts – CVE-2024-44243 (ook bekend as “Sigma”)

Sekuriteitsnavorsers van Microsoft het getoon dat die hoog-geprivilegieerde daemon `storagekitd` gedwing kan word om 'n **ongetekende kernuitbreiding** te laai en sodoende **Sisteem Integriteit Beskerming (SIP)** heeltemal te deaktiveer op ten volle gepatchte macOS (voor 15.2). Die aanvalstroom is:

1. Misbruik die private regte `com.apple.storagekitd.kernel-management` om 'n helper onder aanvallerbeheer te laat ontstaan.
2. Die helper roep `IOService::AddPersonalitiesFromKernelModule` aan met 'n vervaardigde inligtingswoordeboek wat na 'n kwaadwillige kext-bundel wys.
3. Omdat SIP vertrouenskontroles *na* die kext deur `storagekitd` gestoor is, voer kode in ring-0 uit voordat validasie plaasvind en kan SIP afgeskakel word met `csr_set_allow_all(1)`.

Detectietips:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Onmiddellike herstel is om op te dateer na macOS Sequoia 15.2 of later.

---

### Vinning Enumerasie Cheatsheet
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

* **Luftrauser** – Mach boodskap fuzzer wat MIG subsisteme teiken (`github.com/preshing/luftrauser`).
* **oob-executor** – IPC out-of-bounds primitiewe generator wat in CVE-2024-23225 navorsing gebruik word.
* **kmutil inspect** – Ingeboude Apple nut (macOS 11+) om kexts staties te analiseer voordat dit gelaai word: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
