# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Si concentra sull'applicazione dell'integrità del codice in esecuzione sul sistema, fornendo la logica dietro la verifica della code signature di XNU. È anche in grado di controllare le entitlements e gestire altre attività sensibili come consentire il debugging o ottenere i task port.

Inoltre, per alcune operazioni, il kext preferisce contattare il daemon in user space `/usr/libexec/amfid`. Questa relazione di fiducia è stata abusata in diversi jailbreak.

Nelle versioni recenti di macOS, AMFI non è più esposto comodamente come kext autonomo su disco, quindi il reversing di solito significa lavorare dal **kernelcache** o da un **KDK** invece di sfogliare `/System/Library/Extensions`.

AMFI usa policy **MACF** e registra i suoi hook nel momento in cui viene avviato. Inoltre, impedirne il caricamento o scaricarlo potrebbe causare un kernel panic. Tuttavia, ci sono alcuni boot arguments che permettono di indebolire AMFI:

- `amfi_unrestricted_task_for_pid`: Consente `task_for_pid` senza le entitlements richieste
- `amfi_allow_any_signature`: Consente qualsiasi code signature
- `cs_enforcement_disable`: Argomento a livello di sistema usato per disabilitare l'enforcement della code signing
- `amfi_prevent_old_entitled_platform_binaries`: Annulla i platform binaries con entitlements
- `amfi_get_out_of_my_way`: Disabilita completamente amfi

Queste sono alcune delle policy MACF che registra:

- **`cred_check_label_update_execve:`** L'aggiornamento del label verrà eseguito e restituirà 1
- **`cred_label_associate`**: Aggiorna lo slot del mac label di AMFI con il label
- **`cred_label_destroy`**: Rimuove lo slot del mac label di AMFI
- **`cred_label_init`**: Sposta 0 nello slot del mac label di AMFI
- **`cred_label_update_execve`:** Controlla le entitlements del processo per vedere se deve essere consentito modificare i label.
- **`file_check_mmap`:** Controlla se `mmap` sta acquisendo memoria e impostandola come eseguibile. In quel caso controlla se è necessaria la library validation e, se sì, chiama la funzione di library validation.
- **`file_check_library_validation`**: Chiama la funzione di library validation che controlla, tra le altre cose, se un platform binary sta caricando un altro platform binary o se il processo e il nuovo file caricato hanno lo stesso TeamID. Alcune entitlements consentono anche di caricare qualsiasi library.
- **`policy_initbsd`**: Imposta le trusted NVRAM Keys
- **`policy_syscall`**: Controlla le policy DYLD come se il binary ha segmenti unrestricted, se deve consentire le env vars... viene anche chiamata quando un processo viene avviato tramite `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Controlla se, quando un processo esegue un nuovo binary, gli altri processi con diritti SEND sul task port del processo devono mantenerli oppure no. I platform binaries sono consentiti, l'entitlement `get-task-allow` lo consente, le entitlements `task_for_pid-allow` sono consentite e i binary con lo stesso TeamID.
- **`proc_check_expose_task`**: applica le entitlements
- **`amfi_exc_action_check_exception_send`**: Viene inviato un messaggio di eccezione al debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Ciclo di vita del label durante la gestione delle eccezioni (debugging)
- **`proc_check_get_task`**: Controlla entitlements come `get-task-allow`, che consente ad altri processi di ottenere il task port, e `task_for_pid-allow`, che consente al processo di ottenere i task port di altri processi. Se nessuna di queste è presente, risale a `amfid permitunrestricteddebugging` per verificare se è consentito.
- **`proc_check_mprotect`**: Nega se `mprotect` viene chiamato con il flag `VM_PROT_TRUSTED`, che indica che la regione deve essere trattata come se avesse una code signature valida
- **`vnode_check_exec`**: Viene chiamata quando file eseguibili vengono caricati in memoria e imposta `cs_hard | cs_kill`, che ucciderà il processo se una delle pagine diventa non valida
- **`vnode_check_getextattr`**: MacOS: controlla `com.apple.root.installed` e `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Come get + `com.apple.private.allow-bless` e entitlement `internal-installer-equivalent`
- **`vnode_check_signature`**: Codice che chiama XNU per controllare la code signature usando entitlements, trust cache e `amfid`
- **`proc_check_run_cs_invalid`**: Intercetta chiamate `ptrace()` (`PT_ATTACH` e `PT_TRACE_ME`). Controlla eventuali entitlements `get-task-allow`, `run-invalid-allow` e `run-unsigned-code` e, se nessuna è presente, verifica se il debugging è consentito.
- **`proc_check_map_anon`**: Se `mmap` viene chiamato con il flag **`MAP_JIT`**, AMFI controllerà l'entitlement `dynamic-codesigning`.

`AMFI.kext` espone anche un'API per altre estensioni del kernel, ed è possibile trovarne le dipendenze con:
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

Questo è il demone in user mode che `AMFI.kext` userà per verificare le code signatures in user mode.\
Per permettere a `AMFI.kext` di comunicare con il demone usa mach messages tramite la porta `HOST_AMFID_PORT`, che è la porta speciale `18`.

Nota che in macOS non è più possibile per i processi root hijackare le porte speciali, perché sono protette da `SIP` e solo launchd può ottenerle. In iOS viene verificato che il processo che invia la risposta abbia il CDHash hardcoded di `amfid`.

È possibile vedere quando a `amfid` viene richiesto di controllare un binary e la sua risposta eseguendone il debug e impostando un breakpoint in `mach_msg`.

Una volta ricevuto un messaggio tramite la porta speciale, **MIG** viene usato per inviare ogni funzione alla funzione che sta chiamando. Le funzioni principali sono state reverse e spiegate all'interno del libro.

### DYLD policy and library validation

Le versioni recenti di `dyld` chiamano `amfi_check_dyld_policy_self()` molto presto da `configureProcessRestrictions()` per chiedere ad AMFI se il processo può usare le variabili di percorso `DYLD_*`, interposing, fallback paths, embedded variables, o tollerare il fallimento dell'inserimento di librerie. Quindi, quando si fa triage di una superficie di injection, non basta ispezionare solo i Mach-O load commands: devi anche ispezionare gli entitlements e i runtime flags che AMFI tradurrà in policy di `dyld`.

Un ciclo pratico di triage è:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Su macOS moderni molti binari Apple non portano più direttamente `com.apple.security.cs.disable-library-validation` e invece usano `com.apple.private.security.clear-library-validation`. In questo caso la library validation non viene disabilitata al momento di `execve`: il processo deve chiamare `csops(..., CS_OPS_CLEAR_LV, ...)` su sé stesso, e XNU consente questa operazione solo al processo chiamante quando l'entitlement è presente. Dal punto di vista offensivo questo è importante perché un target può diventare iniettabile solo **dopo** aver raggiunto il code path che cancella esplicitamente LV (per esempio, poco prima di caricare plugin opzionali).

## Provisioning Profiles

Un provisioning profile può essere usato per firmare il codice. Esistono profili **Developer** che possono essere usati per firmare il codice e testarlo, e profili **Enterprise** che possono essere usati su tutti i dispositivi.

Dopo che un'App viene inviata all'Apple Store, se approvata, viene firmata da Apple e il provisioning profile non è più necessario.

Di solito un profile usa l'estensione `.mobileprovision` o `.provisionprofile` e può essere estratto con:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Anche se talvolta vengono chiamati certificated, questi provisioning profiles hanno più di un certificate:

- **AppIDName:** L'Application Identifier
- **AppleInternalProfile**: Designa questo come un Apple Internal profile
- **ApplicationIdentifierPrefix**: Prefisso aggiunto a AppIDName (uguale a TeamIdentifier)
- **CreationDate**: Data nel formato `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Un array di (di solito uno) certificate(s), codificato come dati Base64
- **Entitlements**: Gli entitlements consentiti con entitlements per questo profile
- **ExpirationDate**: Data di scadenza nel formato `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Il nome dell'application, uguale a AppIDName
- **ProvisionedDevices**: Un array (per developer certificates) di UDID per cui questo profile è valido
- **ProvisionsAllDevices**: Un booleano (true per enterprise certificates)
- **TeamIdentifier**: Un array di stringa(e) alfanumerica di solito una, usata per identificare il developer per scopi di inter-app interaction
- **TeamName**: Un nome leggibile dall'uomo usato per identificare il developer
- **TimeToLive**: Validità (in giorni) del certificate
- **UUID**: Un Universally Unique Identifier per questo profile
- **Version**: Attualmente impostato a 1

Nota che la voce entitlements conterrà un set ristretto di entitlements e il provisioning profile potrà solo assegnare quegli entitlements specifici per evitare di concedere gli Apple private entitlements.

Nota che i profiles si trovano di solito in `/var/MobileDeviceProvisioningProfiles` ed è possibile verificarli con **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Questa è la libreria esterna che `amfid` chiama per chiedere se dovrebbe consentire qualcosa oppure no. Storicamente è stata abusata nel jailbreaking eseguendo una versione backdoored di essa che avrebbe consentito tutto.

In macOS questa si trova in `MobileDevice.framework`.

## AMFI Trust Caches

Le trust caches non sono solo un concetto di iOS. Su macOS moderni, specialmente su **Apple silicon**, la static trust cache e le loadable trust caches fanno parte della catena Secure Boot. Quando l'**CodeDirectory hash** di un Mach-O è presente lì, AMFI può concedergli il **platform privilege** senza eseguire ulteriori controlli di autenticità al momento del lancio. Questo significa anche che Apple può vincolare i platform binaries a una specifica versione del sistema operativo e impedire che vecchi Apple-signed binaries vengano rieseguiti su sistemi più nuovi.

Sulle versioni recenti di macOS, i trust-cache metadata sono anche collegati alle **launch constraints**, quindi le app di sistema e i binaries copiati avviati dal parent/location sbagliato possono essere rifiutati da AMFI anche se sono ancora Apple-signed. Il workflow dettagliato di estrazione e reversing è trattato in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Su iOS e nella ricerca sul jailbreak troverai ancora il modello tradizionale delle **loadable trust caches** usato per whitelistare i binaries ad-hoc signed.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
