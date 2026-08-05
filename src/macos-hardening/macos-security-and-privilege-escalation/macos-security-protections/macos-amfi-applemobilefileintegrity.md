# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext und amfid

Es konzentriert sich auf die Durchsetzung der Integrität des auf dem System ausgeführten Codes und stellt die Logik hinter der Code-Signaturüberprüfung von XNU bereit. Außerdem kann es Entitlements überprüfen und andere sensible Aufgaben wie das Erlauben von Debugging oder das Erhalten von Task-Ports übernehmen.

Darüber hinaus kontaktiert das kext für einige Vorgänge bevorzugt den im User-Space laufenden Daemon `/usr/libexec/amfid`. Diese Vertrauensbeziehung wurde in mehreren Jailbreaks missbraucht.

Bei neueren macOS-Versionen ist AMFI nicht mehr bequem als eigenständiges kext auf der Festplatte verfügbar. Beim Reversing arbeitet man daher normalerweise mit dem **kernelcache** oder einem **KDK**, anstatt `/System/Library/Extensions` zu durchsuchen.

AMFI verwendet **MACF**-Policies und registriert seine Hooks, sobald es gestartet wird. Das Verhindern des Ladens oder das Entladen kann außerdem einen Kernel Panic auslösen. Es gibt jedoch einige Boot-Argumente, mit denen AMFI geschwächt werden kann:

- `amfi_unrestricted_task_for_pid`: Erlaubt `task_for_pid` ohne erforderliche Entitlements
- `amfi_allow_any_signature`: Erlaubt jede Code-Signatur
- `cs_enforcement_disable`: Systemweites Argument zum Deaktivieren der Code-Signatur-Durchsetzung
- `amfi_prevent_old_entitled_platform_binaries`: Entwertet Platform-Binaries mit Entitlements
- `amfi_get_out_of_my_way`: Deaktiviert AMFI vollständig

Dies sind einige der von AMFI registrierten MACF-Policies:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Das Label-Update wird durchgeführt und 1 zurückgegeben
- **`cred_label_associate`**: Aktualisiert AMFIs MAC-Label-Slot mit dem Label
- **`cred_label_destroy`**: Entfernt AMFIs MAC-Label-Slot
- **`cred_label_init`**: Verschiebt 0 in AMFIs MAC-Label-Slot
- **`cred_label_update_execve:`** Überprüft die Entitlements des Prozesses, um festzustellen, ob er die Labels ändern darf.
- **`file_check_mmap:`** Überprüft, ob `mmap` Speicher anfordert und ihn als ausführbar setzt. In diesem Fall wird geprüft, ob Library Validation erforderlich ist, und falls ja, die Library-Validation-Funktion aufgerufen.
- **`file_check_library_validation`**: Ruft die Library-Validation-Funktion auf, die unter anderem überprüft, ob ein Platform-Binary ein anderes Platform-Binary lädt oder ob der Prozess und die neu geladene Datei dieselbe TeamID besitzen. Bestimmte Entitlements erlauben ebenfalls das Laden jeder Library.
- **`policy_initbsd`**: Richtet vertrauenswürdige NVRAM Keys ein
- **`policy_syscall`**: Überprüft DYLD-Policies, etwa ob das Binary uneingeschränkte Segmente besitzt und ob es Umgebungsvariablen erlauben soll. Dies wird auch aufgerufen, wenn ein Prozess über `amfi_check_dyld_policy_self()` gestartet wird.
- **`proc_check_inherit_ipc_ports`**: Überprüft, ob andere Prozesse mit SEND-Rechten über den Task-Port des Prozesses diese behalten sollen, wenn ein Prozess ein neues Binary ausführt. Platform-Binaries sind erlaubt, ein `get-task-allow`-Entitlement erlaubt dies, `task_for_pid-allow`-Entitlements sind erlaubt, ebenso Binaries mit derselben TeamID.
- **`proc_check_expose_task`**: Erzwingt Entitlements
- **`amfi_exc_action_check_exception_send`**: Eine Exception-Nachricht wird an den Debugger gesendet
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label-Lifecycle während der Exception-Behandlung (Debugging)
- **`proc_check_get_task`**: Überprüft Entitlements wie `get-task-allow`, das anderen Prozessen erlaubt, den Task-Port zu erhalten, und `task_for_pid-allow`, das dem Prozess erlaubt, die Task-Ports anderer Prozesse zu erhalten. Wenn keines von beiden vorhanden ist, wird `amfid permitunrestricteddebugging` aufgerufen, um zu prüfen, ob dies erlaubt ist.
- **`proc_check_mprotect`**: Verweigert den Vorgang, wenn `mprotect` mit dem Flag `VM_PROT_TRUSTED` aufgerufen wird, das angibt, dass die Region so behandelt werden muss, als besäße sie eine gültige Code-Signatur.
- **`vnode_check_exec`**: Wird aufgerufen, wenn ausführbare Dateien in den Speicher geladen werden, und setzt `cs_hard | cs_kill`, wodurch der Prozess beendet wird, wenn eine der Pages ungültig wird<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Überprüft `com.apple.root.installed` und `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Wie get + `com.apple.private.allow-bless` und das `internal-installer-equivalent`-Entitlement
- **`vnode_check_signature`**: Code, der XNU aufruft, um die Code-Signatur mithilfe von Entitlements, Trust Cache und `amfid` zu überprüfen<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Fängt `ptrace()`-Aufrufe (`PT_ATTACH` und `PT_TRACE_ME`) ab. Überprüft, ob eines der Entitlements `get-task-allow`, `run-invalid-allow` oder `run-unsigned-code` vorhanden ist. Wenn keines vorhanden ist, wird geprüft, ob Debugging erlaubt ist.
- **`proc_check_map_anon`**: Wenn `mmap` mit dem Flag **`MAP_JIT`** aufgerufen wird, überprüft AMFI das `dynamic-codesigning`-Entitlement.

`AMFI.kext` stellt außerdem eine API für andere Kernel Extensions bereit. Seine Dependencies lassen sich mit folgendem Befehl finden:
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

Dies ist der im User Mode laufende Daemon, den `AMFI.kext` verwendet, um Code-Signaturen im User Mode zu überprüfen.\
Damit `AMFI.kext` mit dem Daemon kommunizieren kann, verwendet es Mach Messages über den Port `HOST_AMFID_PORT`, bei dem es sich um den speziellen Port `18` handelt.

Beachte, dass es in macOS nicht mehr möglich ist, dass Root-Prozesse spezielle Ports übernehmen, da diese durch `SIP` geschützt sind und nur launchd auf sie zugreifen kann. In iOS wird überprüft, ob der Prozess, der die Antwort zurücksendet, den fest im Code hinterlegten CDHash von `amfid` besitzt.

Es ist möglich zu beobachten, wann `amfid` aufgefordert wird, ein Binary zu überprüfen, und welche Antwort es zurückgibt, indem man es debuggt und einen Breakpoint in `mach_msg` setzt.

Sobald eine Nachricht über den speziellen Port empfangen wurde, wird **MIG** verwendet, um jede Funktion an die von ihr aufgerufene Funktion weiterzuleiten. Die wichtigsten Funktionen wurden im Buch reverse-engineered und erklärt.

### DYLD-Richtlinie und Library Validation

Neuere `dyld`-Versionen rufen sehr früh `amfi_check_dyld_policy_self()` aus `configureProcessRestrictions()` auf, um AMFI zu fragen, ob der Prozess `DYLD_*`-Pfadvariablen, Interposing, Fallback-Pfade und eingebettete Variablen verwenden oder das Fehlschlagen einer Library-Injection tolerieren darf. Daher reicht es bei der Analyse einer Injection-Oberfläche nicht aus, nur die Mach-O Load Commands zu überprüfen: Du musst auch die Entitlements und Runtime-Flags untersuchen, die AMFI in eine `dyld`-Richtlinie übersetzt.

Ein praktischer Analyseablauf ist:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Auf modernen macOS-Systemen enthalten viele Apple-Binaries `com.apple.security.cs.disable-library-validation` nicht mehr direkt, sondern werden stattdessen mit `com.apple.private.security.clear-library-validation` ausgeliefert. In diesem Fall ist die Library Validation zum Zeitpunkt von `execve` nicht deaktiviert: Der Prozess muss `csops(..., CS_OPS_CLEAR_LV, ...)` auf sich selbst aufrufen, und XNU erlaubt diese Operation für den aufrufenden Prozess nur, wenn das Entitlement vorhanden ist. Aus offensiver Sicht ist dies relevant, weil ein Ziel möglicherweise erst **nachdem** es den Codepfad erreicht hat, der LV explizit löscht, injizierbar wird (beispielsweise kurz vor dem Laden optionaler Plugins).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Ein Provisioning Profile kann zum Signieren von Code verwendet werden. Es gibt **Developer**-Profile, die zum Signieren und Testen von Code verwendet werden können, sowie **Enterprise**-Profile, die auf allen Geräten verwendet werden können.

Nachdem eine App beim Apple Store eingereicht und genehmigt wurde, wird sie von Apple signiert, und das Provisioning Profile wird nicht mehr benötigt.

Ein Profile verwendet normalerweise die Erweiterung `.mobileprovision` oder `.provisionprofile` und kann mit folgendem Befehl ausgelesen werden:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Obwohl sie manchmal als zertifiziert bezeichnet werden, enthalten diese Provisioning Profiles mehr als nur ein Zertifikat:

- **AppIDName:** Der Application Identifier
- **AppleInternalProfile**: Kennzeichnet dieses als internes Apple-Profil
- **ApplicationIdentifierPrefix**: Wird AppIDName vorangestellt (identisch mit TeamIdentifier)
- **CreationDate**: Datum im Format `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Ein Array aus (normalerweise einem) Zertifikat(en), als Base64-Daten codiert
- **Entitlements**: Die für dieses Profil zulässigen Entitlements
- **ExpirationDate**: Ablaufdatum im Format `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Der Application Name, identisch mit AppIDName
- **ProvisionedDevices**: Ein Array (für Entwicklerzertifikate) von UDIDs, für die dieses Profil gültig ist
- **ProvisionsAllDevices**: Ein Boolean (true für Unternehmenszertifikate)
- **TeamIdentifier**: Ein Array aus (normalerweise einer) alphanumerischen Zeichenkette(n), die zur Identifizierung des Developers für die Inter-App-Interaktion verwendet werden
- **TeamName**: Ein menschenlesbarer Name zur Identifizierung des Developers
- **TimeToLive**: Gültigkeitsdauer (in Tagen) des Zertifikats
- **UUID**: Eine Universally Unique Identifier für dieses Profil
- **Version**: Derzeit auf 1 gesetzt

Beachte, dass der Entitlements-Eintrag eine eingeschränkte Menge an Entitlements enthält und das Provisioning Profile nur diese spezifischen Entitlements vergeben kann, um zu verhindern, dass private Apple-Entitlements vergeben werden.

Beachte, dass sich Profile normalerweise in `/var/MobileDeviceProvisioningProfiles` befinden. Sie können mit **`security cms -D -i /path/to/profile`** überprüft werden.

## **libmis.dylib**

Dies ist die externe Library, die `amfid` aufruft, um zu erfragen, ob etwas erlaubt werden soll oder nicht. Sie wurde beim Jailbreaking historisch missbraucht, indem eine Backdoored-Version ausgeführt wurde, die alles erlaubte.

In macOS befindet sie sich in `MobileDevice.framework`.

## AMFI Trust Caches

Trust Caches sind nicht nur ein iOS-Konzept. Unter modernem macOS, insbesondere auf **Apple silicon**, sind der statische Trust Cache und ladbare Trust Caches Bestandteil der Secure-Boot-Kette. Wenn der **CodeDirectory-Hash** eines Mach-O dort vorhanden ist, kann AMFI ihm **Platform Privilege** gewähren, ohne beim Start weitere Authentizitätsprüfungen durchzuführen. Das bedeutet auch, dass Apple Platform-Binaries an eine bestimmte OS-Version binden und verhindern kann, dass ältere, von Apple signierte Binaries auf neueren Systemen erneut verwendet werden.<sup>[[6]](#references)</sup>

Bei neueren macOS-Releases sind Trust-Cache-Metadaten außerdem an **Launch Constraints** gebunden. Daher können kopierte System-Apps und Binaries, die vom falschen Parent oder am falschen Speicherort gestartet werden, von AMFI abgelehnt werden, selbst wenn sie weiterhin von Apple signiert sind. Der detaillierte Workflow zum Extrahieren und Reversen wird hier behandelt:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In der iOS- und Jailbreak-Forschung findet man weiterhin das traditionelle Modell ladbarer Trust Caches, die zum Whitelisting von ad-hoc signierten Binaries verwendet werden.

## Referenzen

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
