# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext und amfid

Der Schwerpunkt liegt auf der Durchsetzung der Integrität des auf dem System ausgeführten Codes und der Bereitstellung der Logik hinter der Code-Signaturprüfung von XNU. Außerdem kann es Entitlements überprüfen und andere sensible Aufgaben wie das Ermöglichen von Debugging oder das Erlangen von Task-Ports übernehmen.

Darüber hinaus bevorzugt das kext bei einigen Operationen die Kontaktaufnahme mit dem im User Space laufenden Daemon `/usr/libexec/amfid`. Diese Vertrauensbeziehung wurde in mehreren Jailbreaks missbraucht.

In aktuellen macOS-Versionen ist AMFI nicht mehr bequem als eigenständiges kext auf der Festplatte verfügbar. Beim Reverse Engineering arbeitet man daher normalerweise mit dem **kernelcache** oder einem **KDK**, anstatt `/System/Library/Extensions` zu durchsuchen.

AMFI verwendet **MACF**-Richtlinien und registriert seine Hooks unmittelbar nach dem Start. Das Verhindern des Ladens oder das Entladen kann außerdem einen Kernel Panic auslösen. Es gibt jedoch einige Boot-Argumente, mit denen AMFI geschwächt werden kann:

- `amfi_unrestricted_task_for_pid`: Erlaubt `task_for_pid` ohne erforderliche Entitlements
- `amfi_allow_any_signature`: Erlaubt jede Code-Signatur
- `cs_enforcement_disable`: Systemweites Argument zum Deaktivieren der Code-Signatur-Durchsetzung
- `amfi_prevent_old_entitled_platform_binaries`: Macht Platform-Binaries mit Entitlements ungültig
- `amfi_get_out_of_my_way`: Deaktiviert amfi vollständig

Dies sind einige der von AMFI registrierten MACF-Richtlinien:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`**: Die Label-Aktualisierung wird durchgeführt und 1 zurückgegeben
- **`cred_label_associate`**: Aktualisiert den AMFI-MAC-Label-Slot mit dem Label
- **`cred_label_destroy`**: Entfernt den AMFI-MAC-Label-Slot
- **`cred_label_init`**: Verschiebt 0 in den AMFI-MAC-Label-Slot
- **`cred_label_update_execve:`**: Überprüft die Entitlements des Prozesses, um festzustellen, ob er die Labels ändern darf.
- **`file_check_mmap:`**: Überprüft, ob `mmap` Speicher anfordert und ihn als ausführbar festlegt. In diesem Fall wird geprüft, ob eine Library Validation erforderlich ist, und falls ja, die Library-Validation-Funktion aufgerufen.
- **`file_check_library_validation`**: Ruft die Library-Validation-Funktion auf, die unter anderem überprüft, ob ein Platform-Binary ein anderes Platform-Binary lädt oder ob der Prozess und die neu geladene Datei dieselbe TeamID besitzen. Bestimmte Entitlements erlauben ebenfalls das Laden beliebiger Libraries.
- **`policy_initbsd`**: Richtet vertrauenswürdige NVRAM Keys ein
- **`policy_syscall`**: Überprüft DYLD-Richtlinien, etwa ob das Binary uneingeschränkte Segmente besitzt und ob Umgebungsvariablen erlaubt werden sollen. Diese Funktion wird auch aufgerufen, wenn ein Prozess über `amfi_check_dyld_policy_self()` gestartet wird.
- **`proc_check_inherit_ipc_ports`**: Überprüft, ob andere Prozesse mit SEND-Rechten am Task-Port des Prozesses diese Rechte behalten sollen, wenn ein Prozess ein neues Binary ausführt. Platform-Binaries sind erlaubt, ebenso Prozesse mit dem Entitlement `get-task-allow`, mit dem Entitlement `task_for_pid-allow` sowie Binaries mit derselben TeamID.
- **`proc_check_expose_task`**: Erzwingt Entitlements
- **`amfi_exc_action_check_exception_send`**: Eine Exception-Nachricht wird an den Debugger gesendet
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label-Lebenszyklus während der Exception-Behandlung (Debugging)
- **`proc_check_get_task`**: Überprüft Entitlements wie `get-task-allow`, wodurch andere Prozesse den Task-Port erhalten können, und `task_for_pid-allow`, wodurch der Prozess die Task-Ports anderer Prozesse erhalten kann. Wenn keines dieser Entitlements vorhanden ist, wird `amfid permitunrestricteddebugging` aufgerufen, um zu überprüfen, ob dies erlaubt ist.
- **`proc_check_mprotect`**: Verweigert den Vorgang, wenn `mprotect` mit dem Flag `VM_PROT_TRUSTED` aufgerufen wird, das angibt, dass die Region so behandelt werden muss, als besäße sie eine gültige Code-Signatur.
- **`vnode_check_exec`**: Wird aufgerufen, wenn ausführbare Dateien in den Speicher geladen werden, und setzt `cs_hard | cs_kill`, wodurch der Prozess beendet wird, wenn eine der Pages ungültig wird<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Überprüft `com.apple.root.installed` und `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Wie get + `com.apple.private.allow-bless` und das `internal-installer-equivalent`-Entitlement
- **`vnode_check_signature`**: Code, der XNU aufruft, um die Code-Signatur anhand von Entitlements, Trust Cache und `amfid` zu überprüfen<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Fängt `ptrace()`-Aufrufe (`PT_ATTACH` und `PT_TRACE_ME`) ab. Überprüft, ob eines der Entitlements `get-task-allow`, `run-invalid-allow` oder `run-unsigned-code` vorhanden ist. Falls keines vorhanden ist, wird überprüft, ob Debugging erlaubt ist.
- **`proc_check_map_anon`**: Wenn `mmap` mit dem Flag **`MAP_JIT`** aufgerufen wird, überprüft AMFI das Entitlement `dynamic-codesigning`.

`AMFI.kext` stellt außerdem eine API für andere Kernel Extensions bereit. Seine Abhängigkeiten lassen sich folgendermaßen ermitteln:
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

Dies ist der im User mode laufende Daemon, den `AMFI.kext` verwendet, um Code signatures im User mode zu überprüfen.\
Damit `AMFI.kext` mit dem Daemon kommunizieren kann, verwendet es mach messages über den Port `HOST_AMFID_PORT`, bei dem es sich um den speziellen Port `18` handelt.

Beachte, dass es in macOS nicht mehr möglich ist, dass Root-Prozesse spezielle Ports hijacken, da diese durch `SIP` geschützt sind und nur launchd sie erhalten kann. In iOS wird überprüft, ob der Prozess, der die Antwort zurücksendet, den fest einprogrammierten CDHash von `amfid` besitzt.

Es ist möglich zu sehen, wann `amfid` aufgefordert wird, ein Binary zu überprüfen, und welche Antwort es zurückgibt, indem man es debuggt und einen Breakpoint in `mach_msg` setzt.

Sobald eine Nachricht über den speziellen Port empfangen wurde, wird **MIG** verwendet, um jede Funktion an die von ihr aufgerufene Funktion weiterzuleiten. Die wichtigsten Funktionen wurden im Buch reverse-engineered und erklärt.

### DYLD-Richtlinie und Bibliotheksvalidierung

Aktuelle `dyld`-Versionen rufen sehr früh aus `configureProcessRestrictions()` `amfi_check_dyld_policy_self()` auf, um AMFI zu fragen, ob der Prozess `DYLD_*`-Pfadvariablen, Interposing, Fallback-Pfade und eingebettete Variablen verwenden oder das Fehlschlagen des Einfügens einer Bibliothek tolerieren darf. Wenn du daher eine Injection-Oberfläche analysierst, reicht es nicht aus, nur die Mach-O-Load-Commands zu untersuchen: Du musst auch die Entitlements und Runtime-Flags prüfen, die AMFI in eine `dyld`-Richtlinie übersetzt.

Ein praktischer Triage-Ablauf ist:
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

Nachdem eine App an den Apple Store übermittelt und genehmigt wurde, wird sie von Apple signiert, und das Provisioning Profile wird nicht mehr benötigt.

Ein Profile verwendet normalerweise die Erweiterung `.mobileprovision` oder `.provisionprofile` und kann mit folgendem Befehl ausgelesen werden:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Obwohl sie manchmal als zertifiziert bezeichnet werden, enthalten diese provisioning profiles mehr als nur ein certificate:

- **AppIDName:** Der Application Identifier
- **AppleInternalProfile**: Kennzeichnet dieses als internes Apple-Profil
- **ApplicationIdentifierPrefix**: Wird AppIDName vorangestellt (identisch mit TeamIdentifier)
- **CreationDate**: Datum im Format `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Ein Array aus (normalerweise einem) certificate(s), als Base64-Daten codiert
- **Entitlements**: Die mit den entitlements für dieses Profil erlaubten Entitlements
- **ExpirationDate**: Ablaufdatum im Format `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Der Application Name, identisch mit AppIDName
- **ProvisionedDevices**: Ein Array (für developer certificates) von UDIDs, für die dieses Profil gültig ist
- **ProvisionsAllDevices**: Ein Boolean-Wert (true für enterprise certificates)
- **TeamIdentifier**: Ein Array aus (normalerweise einer) alphanumerischen Zeichenkette(n), die zur Identifizierung des Entwicklers für die Inter-App-Interaktion verwendet werden
- **TeamName**: Ein für Menschen lesbarer Name zur Identifizierung des Entwicklers
- **TimeToLive**: Gültigkeitsdauer des certificates (in Tagen)
- **UUID**: Eine Universally Unique Identifier für dieses Profil
- **Version**: Derzeit auf 1 gesetzt

Beachte, dass der Eintrag für entitlements eine eingeschränkte Gruppe von Entitlements enthält und das provisioning profile nur diese spezifischen Entitlements vergeben kann, um die Vergabe privater Apple-Entitlements zu verhindern.

Beachte, dass sich profiles normalerweise in `/var/MobileDeviceProvisioningProfiles` befinden. Sie können mit **`security cms -D -i /path/to/profile`** überprüft werden.

## **libmis.dylib**

Dies ist die externe library, die `amfid` aufruft, um zu erfragen, ob etwas erlaubt werden soll oder nicht. Sie wurde beim Jailbreaking in der Vergangenheit missbraucht, indem eine backdoored-Version ausgeführt wurde, die alles erlaubte.

In macOS befindet sie sich innerhalb von `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches sind kein reines iOS-Konzept. Unter modernem macOS, insbesondere auf **Apple silicon**, sind der statische trust cache und ladbare trust caches Teil der Secure-Boot-Kette. Wenn der **CodeDirectory hash** eines Mach-O dort vorhanden ist, kann AMFI ihm **platform privilege** gewähren, ohne beim Start weitere Authentizitätsprüfungen durchzuführen. Das bedeutet außerdem, dass Apple platform binaries an eine bestimmte OS-Version binden und verhindern kann, dass ältere, von Apple signierte binaries auf neueren Systemen erneut verwendet werden.<sup>[[6]](#references)</sup>

Bei aktuellen macOS-Releases sind Metadaten des trust cache außerdem an **launch constraints** gebunden. Daher können kopierte System-Apps und binaries, die vom falschen Parent oder am falschen Speicherort gestartet werden, von AMFI abgelehnt werden, selbst wenn sie weiterhin von Apple signiert sind. Der detaillierte Workflow zur Extraktion und zum Reversing wird behandelt in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In der iOS- und Jailbreak-Forschung findet man weiterhin das traditionelle Modell ladbarer trust caches, die zum Whitelisting von ad-hoc-signierten binaries verwendet werden.

## Referenzen

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
