# Vulnerabilità del kernel di macOS

{{#include ../../../banners/hacktricks-training.md}}

Lo sfruttamento recente del kernel di macOS riguarda meno il fatto di "caricare un kext unsigned banale e ottenere ring-0" e più l'abuso di **parser Mach/MIG**, **IOKit user clients**, **race data-only all'interno di XNU** e **daemon con entitlement specifici** che possono ancora riaprire la attack surface del kernel. Per analizzare le interfacce concrete, consulta anche le pagine su [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surface ancora rilevanti

- **Handler Mach/MIG** nei daemon di sistema e nei servizi esposti al kernel: descriptor malformati, dati out-of-line (OOL) e flussi stateful composti da più messaggi.
- **IOKit user clients**: parsing specifico per selector, metodi soggetti a entitlement e wrapper library/daemon che nascondono il reale call graph.
- **Primitive data-only di XNU**: race attorno alle credenziali, puntatori protetti da SMR, read-only zone e altri punti in cui la corruzione modifica la policy senza dover prima ottenere il controllo di RIP/PC.
- **Codice kernel di terze parti / ausiliario**: i kext legacy sono più rari, ma le flotte enterprise, i sistemi Apple Silicon con reduced security e i bundle `.fs` / helper dei vendor continuano a creare percorsi di grande valore adiacenti al kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) diversi bug della catena OTA/update vengono combinati per ottenere la compromissione del kernel abusando della pipeline di software update e delle capacità relative a rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: catena di bypass delle protezioni del kernel osservata in the wild (CVE-2024-23225 & CVE-2024-23296)

Le [**release di sicurezza di macOS di marzo 2024**](https://support.apple.com/en-us/120895) di Apple hanno corretto due problemi che erano **attivamente sfruttati**:

- **CVE-2024-23225 – Kernel**: un bug di memory corruption in cui un attacker con arbitrary kernel read/write poteva bypassare le protezioni della memoria del kernel.
- **CVE-2024-23296 – RTKit**: un secondo bug di memory corruption con la stessa dichiarazione pubblica relativa all'impatto.

I dettagli pubblici sulla root cause sono ancora scarsi, ma la coppia ricorda che le moderne exploit chain di Apple spesso richiedono **più del "semplice" kernel R/W**: il post-exploitation contro le protezioni della memoria, il codice adiacente ai coprocessori o i trust boundary secondari è spesso il punto in cui la chain reale viene stabilizzata.

Triage rapido delle patch:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + race sulle credenziali read-only (CVE-2025-24118)

Il [**write-up di TRAVERTINE**](https://jprx.io/cve-2025-24118/) di Joseph Ravichandran è un ottimo case study moderno su XNU, perché **non** si tratta di un classico buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` è un **puntatore protetto da SMR** memorizzato in un oggetto `proc_ro` **read-only**.
- I writer devono aggiornare quel puntatore **atomicamente**.
- `kauth_cred_proc_update()` utilizzava `zalloc_ro_mut(...)` per modificare `p_ucred`; su x86_64 quel percorso arriva infine a `memcpy` / `rep movsb`, quindi un reader concorrente può osservare un **puntatore parzialmente aggiornato**.
- Il bug si trasforma in una **privilege escalation data-only**: se il puntatore alle credenziali corrotto fa riferimento a un altro oggetto credenziale valido, il thread corrente può ereditare uno stato con privilegi maggiori senza dover prima ottenere un evidente control-flow hijack.

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
Utile euristica di audit: ogni volta che un kernel path combina **SMR readers**, **read-only zone mutation** e **credential o task metadata**, verifica che gli aggiornamenti utilizzino le varianti atomiche `zalloc_ro_mut_*` anziché helper basati sulla copia.

---

## 2024-2025: SIP bypass che riapre i kernel loading paths (CVE-2024-44243)

Microsoft ha mostrato che `storagekitd` poteva essere sfruttato per **bypassare SIP** e rendere nuovamente rilevante il codice kernel di terze parti sulle macchine che, altrimenti, sarebbero sembrate "post-kext". L'idea chiave è:<sup>[[2]](#references)</sup>

1. Depositare o sovrascrivere un bundle `.fs` malevolo in `/Library/Filesystems`.
2. Attivare `storagekitd` tramite Disk Utility o `diskutil`.
3. Lasciare che il daemon con entitlement specifici avvii gli eseguibili del bundle **senza rimuovere correttamente i privilegi / validare il path**.
4. Utilizzare il SIP bypass risultante per modificare lo stato protetto del file system e, nella dimostrazione di Microsoft, sovrascrivere la kernel extension exclusion list.

Per i kernel researcher, la lezione importante è che **la kernel attack surface può essere reintrodotta da userland management daemon**, anche quando il caricamento diretto di kext di terze parti è fortemente limitato.

Utile triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow di fuzzing e ricerca

Se stai cercando attivamente questa classe di bug, i recenti lavori pubblici stanno indicando tutti la stessa direzione:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) è ancora uno dei migliori riferimenti per la ricerca sul kernel dell'era Apple Silicon. Utilizza **static binary rewriting** per recuperare la coverage, disabilita i percorsi **entitlement-gated** durante i test e deduce la struttura delle interfacce dai wrapper userspace.<sup>[[4]](#references)</sup>
- Il [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) di Project Zero mostra un workflow molto pratico per **rebasing di un kext / fileset in userspace**, così da poter sottoporre a fuzzing il codice incentrato sui parser a una velocità molto maggiore prima di riprodurlo sul dispositivo.<sup>[[5]](#references)</sup>
- Per i target che fanno ampio uso di Mach, crea harness basati su **real message layouts and multi-call state machines**, non soltanto su singoli selector blob. Le recenti ricerche su CoreAudio/Mach di Project Zero e interventi a conferenze come **Fuzzing at Mach Speed** mostrano perché le sequenze di messaggi stateful continuano a dare risultati.

Comandi locali rapidi che utilizzerai spesso:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Scheda rapida di enumerazione
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
- [2] [Microsoft Security Blog - Analisi di CVE-2024-44243, un bypass di macOS System Integrity Protection tramite kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - L'incubo dell'OTA Update di Apple: bypass della verifica della firma e pwning del kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: fuzzing delle macOS Kernel EXTensions su Apple Silicon tramite lo sfruttamento delle mitigazioni (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Semplice fuzzing delle macOS kernel extension in userspace con IDA e TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
