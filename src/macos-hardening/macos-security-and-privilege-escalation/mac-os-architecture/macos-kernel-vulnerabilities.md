# Vulnerabilità del kernel di macOS

{{#include ../../../banners/hacktricks-training.md}}

La recente kernel exploitation su macOS riguarda meno il "caricare un trivial unsigned kext e ottenere ring-0" e più l'abuso dei **parser Mach/MIG**, degli **IOKit user client**, delle **race data-only all'interno di XNU** e dei **daemon con entitlements specifici**, che possono ancora riaprire la attack surface del kernel. Per il reversing delle interfacce concrete, consulta anche le pagine su [**IOKit**](macos-iokit.md) e [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surface che contano ancora

- **Handler Mach/MIG** nei system daemon e nei servizi che interagiscono con il kernel: descriptor malformati, dati out-of-line (OOL) e flussi stateful composti da più messaggi.
- **IOKit user client**: parsing specifico per selector, metodi protetti da entitlement e wrapper library/daemon che nascondono il reale call graph.
- **Primitive data-only di XNU**: race attorno alle credenziali, puntatori protetti da SMR, zone read-only e altri punti in cui la corruzione modifica la policy senza ottenere prima il controllo di RIP/PC.
- **Codice kernel di terze parti / ausiliario**: i kext legacy sono più rari, ma le flotte enterprise, i sistemi Apple Silicon con sicurezza ridotta e i bundle vendor `.fs` / helper continuano a creare percorsi kernel-adjacent di grande valore.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**questo report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) diversi bug della OTA/update chain vengono combinati per raggiungere la compromissione del kernel abusando della software update pipeline e delle funzionalità legate a rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: chain di bypass delle protezioni del kernel in-the-wild (CVE-2024-23225 & CVE-2024-23296)

Le [**release di sicurezza di macOS di marzo 2024**](https://support.apple.com/en-us/120895) di Apple hanno corretto due problemi che erano **attivamente sfruttati**:

- **CVE-2024-23225 – Kernel**: un bug di memory corruption che consentiva a un attacker con arbitrary kernel read/write di bypassare le protezioni della memoria del kernel.
- **CVE-2024-23296 – RTKit**: un secondo bug di memory corruption con la stessa dichiarazione pubblica sull'impatto.

I dettagli pubblici della root cause sono ancora scarsi, ma la coppia ricorda che le moderne exploit chain Apple spesso richiedono più del **"semplice" kernel R/W**: il lavoro di post-exploitation sulle protezioni della memoria, sul codice adiacente ai coprocessor o sui trust boundary secondari è spesso il punto in cui la chain reale viene stabilizzata.

Triage rapido delle patch:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + race sulla credenziale read-only (CVE-2025-24118)

Il [**write-up su TRAVERTINE**](https://jprx.io/cve-2025-24118/) di Joseph Ravichandran è un ottimo case study moderno su XNU, perché **non** si tratta di un classico buffer overflow:

- `proc_ro.p_ucred` è un **puntatore protetto da SMR** memorizzato in un oggetto `proc_ro` **read-only**.
- I writer devono aggiornare quel puntatore in modo **atomico**.
- `kauth_cred_proc_update()` usava `zalloc_ro_mut(...)` per modificare `p_ucred`; su x86_64 quel percorso arriva infine a `memcpy` / `rep movsb`, quindi un reader concorrente può osservare un **puntatore parzialmente aggiornato**.
- Il bug si trasforma in una **privilege escalation data-only**: se il puntatore alla credenziale corrotto risolve in un altro oggetto credenziale valido, il thread corrente può ereditare uno stato più privilegiato senza dover prima ottenere un evidente controllo del flusso di esecuzione.

Pattern minimo di attivazione:
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
Euristica utile per l'audit: ogni volta che un percorso del kernel combina **SMR readers**, **mutazione di zone read-only** e **metadati di credential o task**, verifica che gli aggiornamenti usino le varianti atomiche `zalloc_ro_mut_*` anziché helper basati sulla copia.

---

## 2024-2025: SIP bypass che riapre i percorsi di caricamento del kernel (CVE-2024-44243)

Microsoft ha mostrato che `storagekitd` poteva essere abusato per **bypassare SIP** e rendere nuovamente rilevante il codice kernel di terze parti sulle macchine che altrimenti sembrerebbero "post-kext". L'idea chiave è:

1. Depositare o sovrascrivere un bundle `.fs` malevolo in `/Library/Filesystems`.
2. Attivare `storagekitd` tramite Disk Utility o `diskutil`.
3. Lasciare che il daemon con entitlement specifici avvii gli eseguibili del bundle **senza rimuovere correttamente i privilegi / validare il path**.
4. Usare il SIP bypass risultante per modificare lo stato protetto del file system e, nella dimostrazione di Microsoft, sovrascrivere l'elenco di esclusione delle kernel extension.

Per i ricercatori del kernel, la lezione importante è che **la attack surface del kernel può essere reintrodotta dai daemon di gestione in userland**, anche quando il caricamento diretto di kext di terze parti è fortemente limitato.

Triage utile:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing e workflow di ricerca

Se stai cercando attivamente questa classe di bug, i recenti lavori pubblici indicano tutti la stessa direzione:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) rimane uno dei migliori riferimenti per la ricerca sul kernel dell'era Apple Silicon. Utilizza la **riscrittura statica dei binari** per recuperare la coverage, disabilita i percorsi **vincolati dagli entitlement** durante i test e deduce la struttura delle interfacce dai wrapper userspace.
- Il lavoro di Project Zero [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) mostra un workflow molto pratico per **riposizionare un kext / fileset in userspace**, in modo da poter sottoporre a fuzzing il codice incentrato sui parser a velocità molto più elevate prima di riprodurlo sul dispositivo.
- Per i target incentrati su Mach, crea harness basati su **layout reali dei messaggi e macchine a stati con chiamate multiple**, non solo su singoli blob di selector. Le recenti ricerche su CoreAudio/Mach di Project Zero e interventi a conferenze come **Fuzzing at Mach Speed** mostrano perché le sequenze di messaggi stateful continuano a dare risultati.

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
## Cheat sheet per l'enumerazione rapida
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

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Analisi di CVE-2024-44243, un bypass di macOS System Integrity Protection tramite kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
