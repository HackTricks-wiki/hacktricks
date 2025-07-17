# Vulnerabilità del Kernel macOS

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**In questo rapporto**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) vengono spiegate diverse vulnerabilità che hanno permesso di compromettere il kernel compromettendo l'aggiornamento software.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Kernel 0-days in natura (CVE-2024-23225 & CVE-2024-23296)

Apple ha corretto due bug di corruzione della memoria che sono stati attivamente sfruttati contro iOS e macOS a marzo 2024 (risolti in macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**
• Scrittura fuori dai limiti nel sottosistema di memoria virtuale XNU consente a un processo non privilegiato di ottenere lettura/scrittura arbitraria nello spazio degli indirizzi del kernel, eludendo PAC/KTRR.
• Attivato dallo spazio utente tramite un messaggio XPC creato ad arte che fa traboccare un buffer in `libxpc`, quindi si sposta nel kernel quando il messaggio viene analizzato.
* **CVE-2024-23296 – RTKit**
• Corruzione della memoria nel RTKit di Apple Silicon (co-processore in tempo reale).
• Le catene di sfruttamento osservate utilizzavano CVE-2024-23225 per R/W del kernel e CVE-2024-23296 per sfuggire alla sandbox del co-processore sicuro e disabilitare PAC.

Rilevamento del livello di patch:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Se l'aggiornamento non è possibile, mitigare disabilitando i servizi vulnerabili:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` richieste inviate a un client utente IOKit non privilegiato portano a una **confusione di tipo** nel codice di collegamento generato da MIG. Quando il messaggio di risposta viene reinterpretato con un descrittore out-of-line più grande di quello originariamente allocato, un attaccante può ottenere una **scrittura OOB** controllata nelle zone heap del kernel e infine
escalare a `root`.

Schema primitivo (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits sfruttano il bug in questo modo:
1. Spruzzando i buffer `ipc_kmsg` con puntatori di porta attivi.
2. Sovrascrivendo `ip_kobject` di una porta pendente.
3. Saltando a shellcode mappato a un indirizzo forgiato da PAC usando `mprotect()`.

---

## 2024-2025: Bypass SIP tramite Kext di terze parti – CVE-2024-44243 (noto come “Sigma”)

I ricercatori di sicurezza di Microsoft hanno dimostrato che il demone ad alta privilegi `storagekitd` può essere costretto a caricare un **kernel extension non firmato** e quindi disabilitare completamente **System Integrity Protection (SIP)** su macOS completamente aggiornato (prima della versione 15.2). Il flusso dell'attacco è:

1. Abusare del diritto privato `com.apple.storagekitd.kernel-management` per generare un helper sotto il controllo dell'attaccante.
2. L'helper chiama `IOService::AddPersonalitiesFromKernelModule` con un dizionario di informazioni creato ad hoc che punta a un pacchetto kext malevolo.
3. Poiché i controlli di fiducia SIP vengono eseguiti *dopo* che il kext è stato preparato da `storagekitd`, il codice viene eseguito in ring-0 prima della convalida e SIP può essere disattivato con `csr_set_allow_all(1)`.

Suggerimenti per la rilevazione:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
La remediation immediata è aggiornare a macOS Sequoia 15.2 o successivo.

---

### Scheda di riferimento rapido per l'enumerazione
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

* **Luftrauser** – Fuzzer di messaggi Mach che prende di mira i sottosistemi MIG (`github.com/preshing/luftrauser`).
* **oob-executor** – Generatore di primitive out-of-bounds IPC utilizzato nella ricerca CVE-2024-23225.
* **kmutil inspect** – Utility Apple integrata (macOS 11+) per analizzare staticamente i kext prima del caricamento: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
