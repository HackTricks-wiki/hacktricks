# Vulnerabilità del kernel di macOS

{{#include ../../../banners/hacktricks-training.md}}

Lo sfruttamento recente del kernel di macOS riguarda meno il "caricamento di un kext unsigned banale per ottenere ring-0" e più l'abuso di **parser Mach/MIG**, **user client IOKit**, **race data-only all'interno di XNU** e **demoni con entitlement specifici** che possono ancora riaprire la attack surface del kernel. Per il reversing delle interfacce concrete, consulta anche le pagine su [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surface ancora rilevanti

- **Handler Mach/MIG** nei demoni di sistema e nei servizi che interagiscono con il kernel: descriptor malformati, dati out-of-line (OOL) e flussi stateful composti da più messaggi.
- **User client IOKit**: parsing specifico per selector, metodi soggetti a entitlement e wrapper library/demoni che nascondono il call graph reale.
- **Primitive data-only di XNU**: race attorno alle credenziali, puntatori protetti da SMR, zone di sola lettura e altri punti in cui la corruzione modifica le policy senza dover prima ottenere il controllo di RIP/PC.
- **Codice kernel di terze parti / ausiliario**: i kext legacy sono più rari, ma le flotte enterprise, i sistemi Apple Silicon con sicurezza ridotta e i bundle `.fs` / helper dei vendor continuano a creare percorsi di alto valore adiacenti al kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) diversi bug della catena OTA/update vengono combinati per ottenere la compromissione del kernel abusando della pipeline di software update e delle funzionalità correlate a rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: catena di bypass delle protezioni del kernel in-the-wild (CVE-2024-23225 & CVE-2024-23296)

Le [**release di sicurezza di macOS di marzo 2024**](https://support.apple.com/en-us/120895) di Apple hanno risolto due problemi **sfruttati attivamente**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: un bug di memory corruption mediante il quale un attacker con arbitrary kernel read/write poteva bypassare le protezioni della memoria del kernel.
- **CVE-2024-23296 – RTKit**: un secondo bug di memory corruption con la stessa dichiarazione pubblica sull'impatto.

I dettagli pubblici sulla root cause sono ancora scarsi, ma la coppia ricorda che le moderne exploit chain Apple spesso richiedono **più del "semplice" kernel R/W**: il lavoro di post-exploitation sulle protezioni della memoria, sul codice adiacente ai coprocessori o sui trust boundary secondari è spesso il punto in cui la chain reale viene stabilizzata.

Triage rapido delle patch:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Il [**write-up di TRAVERTINE**](https://jprx.io/cve-2025-24118/) di Joseph Ravichandran è un ottimo case study moderno su XNU, perché **non** si tratta di un classico buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` è un **puntatore protetto da SMR** memorizzato in un oggetto `proc_ro` **read-only**.
- I writer devono aggiornare quel puntatore **atomicamente**.
- `kauth_cred_proc_update()` usava `zalloc_ro_mut(...)` per modificare `p_ucred`; su x86_64 quel percorso alla fine raggiunge `memcpy` / `rep movsb`, quindi un reader concorrente può osservare un **puntatore corrotto**.
- Il bug si trasforma in una **data-only privilege escalation**: se il puntatore alla credential corrotta risolve in un altro oggetto credential valido, il thread corrente può ereditare uno stato con privilegi maggiori senza prima ottenere un evidente control-flow hijack.

Pattern minimo di trigger:
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
Euristica utile per l'audit: ogni volta che un percorso del kernel combina **SMR readers**, **mutazione di zone read-only** e **metadati di credenziali o task**, verifica che gli aggiornamenti utilizzino le varianti atomiche `zalloc_ro_mut_*` anziché helper basati sulla copia.

---

## 2024-2025: SIP bypass che riapre i percorsi di caricamento del kernel (CVE-2024-44243)

Microsoft ha dimostrato che `storagekitd` poteva essere usato per **bypassare SIP** e rendere nuovamente rilevante il codice kernel di terze parti sulle macchine che altrimenti sembrerebbero "post-kext". L'idea chiave è:<sup>[[2]](#references)</sup>

1. Depositare o sovrascrivere un bundle `.fs` malevolo in `/Library/Filesystems`.
2. Attivare `storagekitd` tramite Disk Utility o `diskutil`.
3. Lasciare che il daemon con entitlement specifici avvii gli eseguibili del bundle **senza rimuovere correttamente i privilegi / validare il percorso**.
4. Utilizzare il SIP bypass risultante per modificare lo stato protetto del file system e, nella dimostrazione di Microsoft, sovrascrivere la lista di esclusione delle kernel extension.

Per i ricercatori del kernel, la lezione importante è che la **superficie di attacco del kernel può essere reintrodotta dai daemon di gestione userland**, anche quando il caricamento diretto di kext di terze parti è fortemente limitato.

Triage utile:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow di fuzzing e ricerca

Se stai cercando attivamente questa classe di bug, il recente lavoro pubblico punta nella stessa direzione:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) è ancora uno dei migliori riferimenti per la ricerca sul kernel nell'era Apple Silicon. Utilizza il **reindirizzamento statico dei binari** per recuperare la coverage, disabilita i percorsi **gated dagli entitlement** durante i test e deduce la struttura delle interfacce dai wrapper userspace.<sup>[[4]](#references)</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) di Project Zero mostra un workflow molto pratico per **rebasare una kext / fileset in userspace**, in modo che il codice incentrato sui parser possa essere sottoposto a fuzzing a velocità molto maggiore prima della riproduzione sul dispositivo.<sup>[[5]](#references)</sup>
- Per i target incentrati su Mach, crea harness basati su **layout reali dei messaggi e macchine a stati con chiamate multiple**, non solo su singoli selector blob. Le recenti ricerche su CoreAudio/Mach di Project Zero e talk alle conferenze come **Fuzzing at Mach Speed** mostrano perché le sequenze di messaggi stateful continuano a essere efficaci.

Comandi locali rapidi che utilizzerai davvero spesso:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Scheda rapida di Enumeration
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Riferimenti

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analisi di CVE-2024-44243, un bypass del System Integrity Protection di macOS tramite kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - L'incubo dell'OTA Update di Apple: bypass della verifica della firma e compromissione del kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: fuzzing delle macOS Kernel EXTensions su Apple Silicon tramite lo sfruttamento delle mitigazioni (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Semplice fuzzing delle kernel extensions di macOS in userspace con IDA e TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Informazioni sui contenuti di sicurezza di macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
