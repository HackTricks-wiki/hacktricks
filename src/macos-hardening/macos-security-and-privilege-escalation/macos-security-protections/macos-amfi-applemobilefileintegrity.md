# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext e amfid

Si concentra sull'applicazione dell'integrità del codice in esecuzione sul sistema, fornendo la logica alla base della verifica delle code signature di XNU. È inoltre in grado di controllare gli entitlements e gestire altre attività sensibili, come consentire il debugging o ottenere task port.

Inoltre, per alcune operazioni, il kext preferisce contattare il daemon in user space `/usr/libexec/amfid`. Questa relazione di trust è stata abusata in diversi jailbreak.

Nelle versioni recenti di macOS, AMFI non è più comodamente esposto come kext standalone su disco, quindi il reversing solitamente richiede di lavorare dal **kernelcache** o da un **KDK**, invece di esplorare `/System/Library/Extensions`.

AMFI utilizza policy **MACF** e registra i suoi hook nel momento in cui viene avviato. Inoltre, impedirne il caricamento o scaricarlo potrebbe causare un kernel panic. Tuttavia, esistono alcuni boot arguments che consentono di disabilitare AMFI:

- `amfi_unrestricted_task_for_pid`: Consente di usare task_for_pid senza gli entitlements richiesti
- `amfi_allow_any_signature`: Consente qualsiasi code signature
- `cs_enforcement_disable`: Argument a livello di sistema utilizzato per disabilitare l'enforcement delle code signing
- `amfi_prevent_old_entitled_platform_binaries`: Invalida i platform binaries con entitlements
- `amfi_get_out_of_my_way`: Disabilita completamente amfi

Queste sono alcune delle policy MACF che registra:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Verrà eseguito l'aggiornamento della label e verrà restituito 1
- **`cred_label_associate`**: Aggiorna lo slot mac label di AMFI con la label
- **`cred_label_destroy`**: Rimuove lo slot mac label di AMFI
- **`cred_label_init`**: Sposta 0 nello slot mac label di AMFI
- **`cred_label_update_execve:`** Controlla gli entitlements del processo per verificare se deve essere autorizzato a modificare le label.
- **`file_check_mmap:`** Controlla se mmap sta acquisendo memoria e impostandola come eseguibile. In tal caso, controlla se è necessaria la library validation e, se lo è, chiama la funzione di library validation.
- **`file_check_library_validation`**: Chiama la funzione di library validation, che controlla, tra le altre cose, se un platform binary sta caricando un altro platform binary oppure se il processo e il nuovo file caricato hanno lo stesso TeamID. Alcuni entitlements consentono inoltre di caricare qualsiasi libreria.
- **`policy_initbsd`**: Configura le trusted NVRAM Keys
- **`policy_syscall`**: Controlla le policy DYLD, ad esempio se il binary ha segmenti unrestricted e se deve consentire le env vars... viene chiamata anche quando un processo viene avviato tramite `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Controlla se, quando un processo esegue un nuovo binary, altri processi con diritti SEND sul task port del processo debbano conservarli o meno. I platform binaries sono autorizzati, l'entitlement `get-task-allow` lo consente, gli entitlements `task_for_pid-allow` sono autorizzati e lo stesso vale per i binaries con lo stesso TeamID.
- **`proc_check_expose_task`**: Applica gli entitlements
- **`amfi_exc_action_check_exception_send`**: Un exception message viene inviato al debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Lifecycle della label durante la gestione delle eccezioni (debugging)
- **`proc_check_get_task`**: Controlla entitlements come `get-task-allow`, che consente ad altri processi di ottenere il task port, e `task_for_pid-allow`, che consente al processo di ottenere i task port di altri processi. Se nessuno dei due è presente, effettua una chiamata a `amfid permitunrestricteddebugging` per verificare se è consentito.
- **`proc_check_mprotect`**: Nega l'operazione se `mprotect` viene chiamata con il flag `VM_PROT_TRUSTED`, che indica che la regione deve essere trattata come se avesse una code signature valida.
- **`vnode_check_exec`**: Viene chiamata quando i file eseguibili vengono caricati in memoria e imposta `cs_hard | cs_kill`, che terminerà il processo se una qualsiasi delle pagine diventa invalida<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Controlla `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Come get + entitlement `com.apple.private.allow-bless` e `internal-installer-equivalent`
- **`vnode_check_signature`**: Codice che chiama XNU per controllare la code signature usando entitlements, trust cache e `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Intercetta le chiamate `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Controlla la presenza di uno degli entitlements `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nessuno è presente, verifica se il debugging è consentito.
- **`proc_check_map_anon`**: Se `mmap` viene chiamata con il flag **`MAP_JIT`**, AMFI controlla l'entitlement `dynamic-codesigning`.

`AMFI.kext` espone inoltre un'API per altri kernel extensions ed è possibile trovare le sue dipendenze con:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Questo è il daemon in user mode che `AMFI.kext` utilizzerà per verificare le firme del codice in user mode.\
Per consentire a `AMFI.kext` di comunicare con il daemon, vengono utilizzati mach messages sulla port `HOST_AMFID_PORT`, che corrisponde alla special port `18`.

Nota che in macOS non è più possibile per i processi root hijackare le special port, poiché sono protette da `SIP` e solo launchd può ottenerle. In iOS viene verificato che il processo che invia la risposta abbia il CDHash di `amfid` hardcoded.

È possibile vedere quando viene richiesto ad `amfid` di verificare un binary e la relativa risposta eseguendo il debugging e impostando un breakpoint in `mach_msg`.

Una volta ricevuto un message tramite la special port, viene utilizzato **MIG** per inviare ogni funzione alla funzione che sta chiamando. Le funzioni principali sono state sottoposte a reverse engineering e spiegate all'interno del libro.

### Policy DYLD e validazione delle librerie

Le versioni recenti di `dyld` chiamano `amfi_check_dyld_policy_self()` molto presto da `configureProcessRestrictions()` per chiedere ad AMFI se il processo può utilizzare le path variables `DYLD_*`, l'interposing, le fallback paths, le embedded variables oppure tollerare il fallimento dell'inserimento di una libreria. Pertanto, durante il triage di una injection surface, non è sufficiente esaminare solo i load commands del Mach-O: è inoltre necessario esaminare gli entitlements e i runtime flags che AMFI convertirà nella policy di `dyld`.

Un pratico loop di triage è:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Sui macOS moderni molti binari Apple non includono più direttamente `com.apple.security.cs.disable-library-validation` e invece vengono distribuiti con `com.apple.private.security.clear-library-validation`. In questo caso la library validation non viene disabilitata al momento di `execve`: il processo deve chiamare `csops(..., CS_OPS_CLEAR_LV, ...)` su se stesso, e XNU consente questa operazione sul processo chiamante solo quando l'entitlement è presente. Dal punto di vista offensivo, questo è importante perché un target può diventare iniettabile solo **dopo** aver raggiunto il code path che cancella esplicitamente LV (ad esempio, poco prima di caricare plugin opzionali).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Un provisioning profile può essere usato per firmare il codice. Esistono profili **Developer**, utilizzabili per firmare il codice e testarlo, e profili **Enterprise**, utilizzabili su tutti i dispositivi.

Dopo che un'App viene inviata all'Apple Store, se viene approvata, viene firmata da Apple e il provisioning profile non è più necessario.

Un profilo utilizza solitamente l'estensione `.mobileprovision` o `.provisionprofile` e può essere dumpato con:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Sebbene a volte vengano definiti certificati, questi provisioning profile contengono più di un certificato:

- **AppIDName:** L'Application Identifier
- **AppleInternalProfile**: Indica che si tratta di un profilo Apple Internal
- **ApplicationIdentifierPrefix**: Anteposto a AppIDName (uguale a TeamIdentifier)
- **CreationDate**: Data nel formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un array di certificati (di solito uno), codificati come dati Base64
- **Entitlements**: Gli entitlements consentiti per questo profilo
- **ExpirationDate**: Data di scadenza nel formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Il nome dell'applicazione, uguale a AppIDName
- **ProvisionedDevices**: Un array (per i certificati developer) di UDID per i quali questo profilo è valido
- **ProvisionsAllDevices**: Un valore booleano (true per i certificati enterprise)
- **TeamIdentifier**: Un array di stringhe alfanumeriche (di solito una) utilizzate per identificare lo sviluppatore ai fini dell'interazione tra app
- **TeamName**: Un nome leggibile utilizzato per identificare lo sviluppatore
- **TimeToLive**: Validità (in giorni) del certificato
- **UUID**: Un Universally Unique Identifier per questo profilo
- **Version**: Attualmente impostato su 1

Si noti che la voce entitlements conterrà un insieme limitato di entitlements e che il provisioning profile potrà fornire soltanto quegli entitlements specifici, per impedire la concessione di entitlements privati di Apple.

Si noti che i profili si trovano generalmente in `/var/MobileDeviceProvisioningProfiles` ed è possibile controllarli con **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Questa è la libreria esterna che `amfid` chiama per chiedere se deve consentire o meno un'operazione. Storicamente è stata sfruttata nel jailbreaking eseguendone una versione backdoored che consentiva qualsiasi operazione.

In macOS si trova all'interno di `MobileDevice.framework`.

## AMFI Trust Caches

I trust cache non sono un concetto esclusivo di iOS. Nelle versioni moderne di macOS, soprattutto su **Apple silicon**, lo static trust cache e i loadable trust cache fanno parte della catena Secure Boot. Quando l'hash **CodeDirectory** di un Mach-O è presente al loro interno, AMFI può concedergli il **platform privilege** senza eseguire ulteriori controlli di autenticità al momento dell'avvio. Ciò significa anche che Apple può vincolare i binari della piattaforma a una versione specifica del sistema operativo e impedire che vecchi binari firmati da Apple vengano riutilizzati su sistemi più recenti.<sup>[[6]](#references)</sup>

Nelle versioni recenti di macOS, i metadati dei trust cache sono inoltre associati alle **launch constraints**, per cui le app e i binari di sistema copiati e avviati dal parent o dalla posizione errati possono essere rifiutati da AMFI anche se sono ancora firmati da Apple. Il workflow dettagliato di estrazione e reversing è descritto in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Nella ricerca su iOS e jailbreak si trova ancora il modello tradizionale dei **loadable trust cache** utilizzato per inserire nella whitelist i binari firmati ad hoc.

## Riferimenti

- [1] [XNU — `security/mac_policy.h` (operazioni delle policy MACF registrate da AMFI, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (flag di code-signing `CS_*` impostati da AMFI)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (parsing e validazione del blob della code signature)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (operazioni `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler di `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust cache](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
