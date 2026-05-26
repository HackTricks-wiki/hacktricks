# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Si concentra sull'imposizione dell'integrità del codice in esecuzione sul sistema, fornendo la logica alla base della verifica della code signature di XNU. È anche in grado di controllare le entitlements e gestire altri compiti sensibili come consentire il debugging o ottenere i task port.

Inoltre, per alcune operazioni, il kext preferisce contattare il daemon in user space `/usr/libexec/amfid`. Questa relazione di fiducia è stata abusata in diversi jailbreaks.

Nelle versioni recenti di macOS, AMFI non è più esposto comodamente come kext autonomo su disco, quindi il reversing di solito significa lavorare dal **kernelcache** o da un **KDK** invece di esplorare `/System/Library/Extensions`.

AMFI usa policy **MACF** e registra i suoi hook nel momento in cui viene avviato. Inoltre, impedirne il caricamento o scaricarlo potrebbe causare un kernel panic. Tuttavia, ci sono alcuni boot arguments che consentono di indebolire AMFI:

- `amfi_unrestricted_task_for_pid`: Consente che task_for_pid sia permesso senza le entitlements richieste
- `amfi_allow_any_signature`: Consente qualsiasi code signature
- `cs_enforcement_disable`: Argomento di sistema usato per disabilitare l'enforcement della code signing
- `amfi_prevent_old_entitled_platform_binaries`: Annulla i platform binaries con entitlements
- `amfi_get_out_of_my_way`: Disabilita completamente amfi

Queste sono alcune delle policy MACF che registra:

- **`cred_check_label_update_execve:`** L'aggiornamento del label verrà eseguito e restituirà 1
- **`cred_label_associate`**: Aggiorna lo slot mac label di AMFI con il label
- **`cred_label_destroy`**: Rimuove lo slot mac label di AMFI
- **`cred_label_init`**: Sposta 0 nello slot mac label di AMFI
- **`cred_label_update_execve`:** Controlla le entitlements del processo per vedere se deve essere autorizzato a modificare i label.
- **`file_check_mmap`:** Controlla se mmap sta acquisendo memoria e la sta impostando come eseguibile. In tal caso controlla se è necessaria la library validation e, se sì, chiama la funzione di library validation.
- **`file_check_library_validation`**: Chiama la funzione di library validation che controlla, tra le altre cose, se un platform binary sta caricando un altro platform binary o se il processo e il nuovo file caricato hanno lo stesso TeamID. Alcune entitlements consentiranno anche di caricare qualsiasi libreria.
- **`policy_initbsd`**: Imposta le chiavi NVRAM fidate
- **`policy_syscall`**: Controlla le policy DYLD come se il binary ha segmenti non limitati, se dovrebbe consentire le env vars... viene anche chiamato quando un processo viene avviato tramite `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Controlla se, quando un processo esegue un nuovo binary, altri processi con diritti SEND sul task port del processo debbano mantenerli o meno. I platform binary sono consentiti, l'entitlement `get-task-allow` lo consente, gli entitlement `task_for_pid-allow` sono consentiti e i binary con lo stesso TeamID.
- **`proc_check_expose_task`**: impone le entitlements
- **`amfi_exc_action_check_exception_send`**: Viene inviato un messaggio di eccezione al debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo di vita del label durante la gestione delle eccezioni (debugging)
- **`proc_check_get_task`**: Controlla entitlements come `get-task-allow` che consente ad altri processi di ottenere il task port e `task_for_pid-allow`, che consente al processo di ottenere i task port di altri processi. Se nessuno di questi è presente, chiama `amfid permitunrestricteddebugging` per verificare se è consentito.
- **`proc_check_mprotect`**: Nega se `mprotect` viene chiamata con il flag `VM_PROT_TRUSTED`, che indica che la regione deve essere trattata come se avesse una code signature valida.
- **`vnode_check_exec`**: Viene chiamata quando file eseguibili vengono caricati in memoria e imposta `cs_hard | cs_kill`, che ucciderà il processo se una qualsiasi delle pagine diventa invalida
- **`vnode_check_getextattr`**: MacOS: Controlla `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Come get + com.apple.private.allow-bless e internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Codice che chiama XNU per controllare la code signature usando entitlements, trust cache e `amfid`
- **`proc_check_run_cs_invalid`**: Intercetta le chiamate `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Controlla eventuali entitlements `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nessuno è presente, verifica se il debugging è consentito.
- **`proc_check_map_anon`**: Se `mmap` viene chiamata con il flag **`MAP_JIT`**, AMFI controllerà l'entitlement `dynamic-codesigning`.

`AMFI.kext` espone anche una API per altre kernel extensions, ed è possibile trovare le sue dipendenze con:
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

Questo è il daemon in user mode che `AMFI.kext` userà per verificare le code signatures in user mode.\
Affinché `AMFI.kext` comunichi con il daemon, usa mach messages sul port `HOST_AMFID_PORT`, che è il port speciale `18`.

Nota che in macOS non è più possibile per i processi root hijackare i special port, perché sono protetti da `SIP` e solo launchd può ottenerli. In iOS viene verificato che il processo che invia la risposta abbia il CDHash hardcoded di `amfid`.

È possibile vedere quando `amfid` viene richiesto per controllare un binary e la sua response facendo debugging e impostando un breakpoint in `mach_msg`.

Una volta ricevuto un message tramite il special port, viene usato **MIG** per inviare ogni function alla function che sta chiamando. Le main functions sono state reverse engineered e spiegate all'interno del libro.

### DYLD policy and library validation

Le versioni recenti di `dyld` chiamano `amfi_check_dyld_policy_self()` molto presto da `configureProcessRestrictions()` per chiedere ad AMFI se il processo può usare le variabili di percorso `DYLD_*`, interposing, fallback paths, embedded variables, o tollerare failed library insertion. Quindi, quando si analizza una injection surface, non basta ispezionare solo i Mach-O load commands: bisogna anche ispezionare gli entitlements e i runtime flags che AMFI tradurrà in `dyld` policy.

Un practical triage loop è:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Su macOS moderne molti binari Apple non portano più direttamente `com.apple.security.cs.disable-library-validation` e invece includono `com.apple.private.security.clear-library-validation`. In quel caso la library validation non viene disabilitata al momento di `execve`: il processo deve chiamare `csops(..., CS_OPS_CLEAR_LV, ...)` su se stesso, e XNU consente quell’operazione solo sul processo chiamante quando l’entitlement è presente. Da una prospettiva offensiva questo è importante perché un target può diventare injectable solo **dopo** aver raggiunto il code path che esplicitamente clear LV (per esempio, poco prima di caricare plugin opzionali).

## Provisioning Profiles

Un provisioning profile può essere usato per firmare il codice. Esistono profili **Developer** che possono essere usati per firmare il codice e testarlo, e profili **Enterprise** che possono essere usati su tutti i dispositivi.

Dopo che un App viene inviata all’Apple Store, se approvata, viene firmata da Apple e il provisioning profile non è più necessario.

Un profile di solito usa l’estensione `.mobileprovision` o `.provisionprofile` e può essere dumpato con:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Anche se a volte vengono chiamati certificated, questi provisioning profiles hanno più di un certificate:

- **AppIDName:** L'Application Identifier
- **AppleInternalProfile**: Designa questo come un profilo Apple Internal
- **ApplicationIdentifierPrefix**: Prefisso aggiunto ad AppIDName (uguale a TeamIdentifier)
- **CreationDate**: Data nel formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un array di certificate(s) (di solito uno), codificati come dati Base64
- **Entitlements**: Gli entitlements consentiti con entitlements per questo profile
- **ExpirationDate**: Data di scadenza nel formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Il nome dell'Application, uguale ad AppIDName
- **ProvisionedDevices**: Un array (per developer certificates) di UDIDs per cui questo profile è valido
- **ProvisionsAllDevices**: Un booleano (true per enterprise certificates)
- **TeamIdentifier**: Un array di stringa(e) alfanumeriche (di solito una) usate per identificare il developer per finalità di inter-app interaction
- **TeamName**: Un nome leggibile dall'uomo usato per identificare il developer
- **TimeToLive**: Validità (in giorni) del certificate
- **UUID**: Un Universally Unique Identifier per questo profile
- **Version**: Attualmente impostato a 1

Nota che la voce entitlements conterrà un set ristretto di entitlements e il provisioning profile potrà concedere solo quegli specifici entitlements per evitare di assegnare Apple private entitlements.

Nota che i profiles sono di solito ubicati in `/var/MobileDeviceProvisioningProfiles` ed è possibile verificarli con **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Questa è la libreria esterna che `amfid` chiama per chiedere se dovrebbe consentire qualcosa o no. Storicamente è stata abusata nel jailbreaking eseguendone una versione backdoored che avrebbe consentito tutto.

In macOS questa si trova dentro `MobileDevice.framework`.

## AMFI Trust Caches

I trust caches non sono solo un concetto di iOS. Su macOS moderni, specialmente su **Apple silicon**, la static trust cache e le loadable trust caches fanno parte della Secure Boot chain. Quando il **CodeDirectory hash** di un Mach-O è presente lì, AMFI può concedergli **platform privilege** senza eseguire ulteriori controlli di autenticità al momento del lancio. Questo significa anche che Apple può vincolare i platform binaries a una specifica versione di OS e impedire che vecchi binary firmati da Apple vengano riprodotti su sistemi più recenti.

Sulle recenti release di macOS, i trust-cache metadata sono anche collegati alle **launch constraints**, quindi le app di sistema e i binary copiati avviati dal parent/location sbagliato possono essere rifiutati da AMFI anche se sono ancora firmati da Apple. Il workflow dettagliato di estrazione e reversing è trattato in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In iOS e nella ricerca sul jailbreak troverai ancora il modello tradizionale di **loadable trust caches** usato per whitelisting binary firmati ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
