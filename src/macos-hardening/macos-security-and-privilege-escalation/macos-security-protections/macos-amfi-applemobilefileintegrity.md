# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Es konzentriert sich darauf, die Integrität des auf dem System laufenden Codes durchzusetzen und liefert die Logik hinter XNUs Code-Signature-Verifizierung. Es kann außerdem Entitlements prüfen und andere sensible Aufgaben übernehmen, wie Debugging zu erlauben oder Task-Ports zu erhalten.

Außerdem bevorzugt das kext für einige Operationen die Kommunikation mit dem im User Space laufenden Daemon `/usr/libexec/amfid`. Dieses Vertrauensverhältnis wurde in mehreren jailbreaks ausgenutzt.

Auf neueren macOS-Versionen wird AMFI nicht mehr bequem als eigenständiges on-disk kext bereitgestellt, daher bedeutet Reverse Engineering normalerweise, mit dem **kernelcache** oder einem **KDK** zu arbeiten, statt `/System/Library/Extensions` zu durchsuchen.

AMFI verwendet **MACF**-Policies und registriert seine Hooks in dem Moment, in dem es startet. Außerdem kann das Verhindern des Ladens oder das Entladen einen kernel panic auslösen. Es gibt jedoch einige Boot-Argumente, die es erlauben, AMFI zu debilitate:

- `amfi_unrestricted_task_for_pid`: Erlaubt, dass task_for_pid ohne erforderliche Entitlements erlaubt wird
- `amfi_allow_any_signature`: Erlaubt jede code signature
- `cs_enforcement_disable`: Systemweites Argument zum Deaktivieren der code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Entwertet platform binaries mit Entitlements
- `amfi_get_out_of_my_way`: Deaktiviert amfi vollständig

Dies sind einige der MACF-Policies, die es registriert:

- **`cred_check_label_update_execve:`** Label-Update wird durchgeführt und gibt 1 zurück
- **`cred_label_associate`**: Aktualisiert AMFIs mac label slot mit label
- **`cred_label_destroy`**: Entfernt AMFIs mac label slot
- **`cred_label_init`**: Setzt 0 in AMFIs mac label slot
- **`cred_label_update_execve`:** Es prüft die Entitlements des Prozesses, um zu sehen, ob das Ändern der Labels erlaubt sein sollte.
- **`file_check_mmap`:** Es prüft, ob mmap Speicher belegt und ihn als ausführbar setzt. In diesem Fall prüft es, ob library validation nötig ist, und wenn ja, ruft es die library validation-Funktion auf.
- **`file_check_library_validation`**: Ruft die library validation-Funktion auf, die unter anderem prüft, ob ein platform binary ein anderes platform binary lädt oder ob der Prozess und die neu geladene Datei dieselbe TeamID haben. Bestimmte Entitlements erlauben auch das Laden jeder beliebigen library.
- **`policy_initbsd`**: Richtet vertrauenswürdige NVRAM Keys ein
- **`policy_syscall`**: Es prüft DYLD-Policies wie ob das binary unbeschränkte Segmente hat, ob env vars erlaubt werden sollen... dies wird auch aufgerufen, wenn ein Prozess über `amfi_check_dyld_policy_self()` gestartet wird.
- **`proc_check_inherit_ipc_ports`**: Es prüft, ob beim Ausführen eines neuen binaries durch einen Prozess andere Prozesse mit SEND-Rechten über den task port des Prozesses diese behalten sollen oder nicht. Platform binaries sind erlaubt, `get-task-allow` berechtigt es, `task_for_pid-allow` berechtigte Prozesse sind erlaubt und binaries mit derselben TeamID.
- **`proc_check_expose_task`**: erzwingt Entitlements
- **`amfi_exc_action_check_exception_send`**: Eine exception message wird an den debugger gesendet
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label-Lebenszyklus während der exception-handling (debugging)
- **`proc_check_get_task`**: Prüft Entitlements wie `get-task-allow`, das anderen Prozessen erlaubt, den tasks port zu erhalten, und `task_for_pid-allow`, das dem Prozess erlaubt, die tasks ports anderer Prozesse zu erhalten. Wenn keines von beiden vorliegt, ruft es `amfid permitunrestricteddebugging` auf, um zu prüfen, ob es erlaubt ist.
- **`proc_check_mprotect`**: Verweigert, wenn `mprotect` mit dem Flag `VM_PROT_TRUSTED` aufgerufen wird, was bedeutet, dass der Bereich so behandelt werden muss, als hätte er eine gültige code signature.
- **`vnode_check_exec`**: Wird aufgerufen, wenn ausführbare Dateien in den Speicher geladen werden, und setzt `cs_hard | cs_kill`, wodurch der Prozess beendet wird, wenn eine der Pages ungültig wird
- **`vnode_check_getextattr`**: MacOS: Prüft `com.apple.root.installed` und `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Wie get + `com.apple.private.allow-bless` und `internal-installer-equivalent` entitlement
- **`vnode_check_signature`**: Code, der XNU aufruft, um die code signature mithilfe von Entitlements, trust cache und `amfid` zu prüfen
- **`proc_check_run_cs_invalid`**: Es fängt `ptrace()`-Aufrufe ab (`PT_ATTACH` und `PT_TRACE_ME`). Es prüft auf die Entitlements `get-task-allow`, `run-invalid-allow` und `run-unsigned-code`; wenn keines vorhanden ist, prüft es, ob Debugging erlaubt ist.
- **`proc_check_map_anon`**: Wenn mmap mit dem **`MAP_JIT`**-Flag aufgerufen wird, prüft AMFI das `dynamic-codesigning` entitlement.

`AMFI.kext` stellt außerdem eine API für andere kernel extensions bereit, und es ist möglich, seine Abhängigkeiten mit folgendem zu finden:
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

Dies ist der Daemon im User-Mode, den `AMFI.kext` verwendet, um Signaturen von Code im User-Mode zu prüfen.\
Damit `AMFI.kext` mit dem Daemon kommunizieren kann, verwendet es mach messages über den Port `HOST_AMFID_PORT`, der der spezielle Port `18` ist.

Beachte, dass es in macOS nicht mehr möglich ist, dass Root-Prozesse spezielle Ports hijacken, da sie durch `SIP` geschützt sind und nur `launchd` sie erhalten kann. In iOS wird geprüft, dass der Prozess, der die Antwort zurücksendet, den fest codierten CDHash von `amfid` hat.

Es ist möglich zu sehen, wann `amfid` aufgerufen wird, um ein Binary zu prüfen, und welche Antwort es gibt, indem man es debuggt und einen Breakpoint in `mach_msg` setzt.

Sobald eine Nachricht über den speziellen Port empfangen wurde, wird **MIG** verwendet, um jede Funktion an die Funktion zu senden, die sie aufruft. Die Hauptfunktionen wurden rückentwickelt und im Buch erklärt.

### DYLD policy and library validation

Neuere `dyld`-Versionen rufen `amfi_check_dyld_policy_self()` sehr früh aus `configureProcessRestrictions()` auf, um AMFI zu fragen, ob der Prozess `DYLD_*`-Path-Variablen, Interposing, Fallback-Pfade, eingebettete Variablen verwenden oder fehlgeschlagene Library-Injection tolerieren darf. Daher reicht es bei der Analyse einer Injection-Angriffsfläche nicht aus, nur Mach-O-Load-Commands zu prüfen: Du musst auch die Entitlements und Runtime-Flags prüfen, die AMFI in `dyld`-Policy übersetzt.

Ein praktischer Triage-Loop ist:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Auf modernen macOS tragen viele Apple-Binaries `com.apple.security.cs.disable-library-validation` nicht mehr direkt, sondern stattdessen `com.apple.private.security.clear-library-validation`. In diesem Fall ist library validation nicht bereits zur `execve`-Zeit deaktiviert: Der Prozess muss `csops(..., CS_OPS_CLEAR_LV, ...)` auf sich selbst aufrufen, und XNU erlaubt diese Operation nur für den aufrufenden Prozess, wenn das entitlement vorhanden ist. Aus offensiver Sicht ist das wichtig, weil ein Target erst **nach** dem Erreichen des Codepfads, der LV explizit deaktiviert, injizierbar werden kann (zum Beispiel kurz bevor optionale Plugins geladen werden).

## Provisioning Profiles

Ein provisioning profile kann verwendet werden, um Code zu signieren. Es gibt **Developer** profiles, die zum Signieren von Code und zum Testen verwendet werden können, und **Enterprise** profiles, die auf allen Geräten verwendet werden können.

Nachdem eine App im Apple Store eingereicht wurde, wird sie, falls genehmigt, von Apple signiert und das provisioning profile wird nicht mehr benötigt.

Ein Profile verwendet normalerweise die Erweiterung `.mobileprovision` oder `.provisionprofile` und kann gedumpt werden mit:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Obwohl manchmal als Zertifikat bezeichnet, enthalten diese Provisioning Profiles mehr als nur ein Zertifikat:

- **AppIDName:** Der Application Identifier
- **AppleInternalProfile**: Kennzeichnet dies als ein Apple Internal Profile
- **ApplicationIdentifierPrefix**: Wird an AppIDName vorangestellt (gleich wie TeamIdentifier)
- **CreationDate**: Datum im `YYYY-MM-DDTHH:mm:ssZ`-Format
- **DeveloperCertificates**: Ein Array von (normalerweise einem) Zertifikat(en), kodiert als Base64-Daten
- **Entitlements**: Die mit Entitlements für dieses Profile erlaubten Entitlements
- **ExpirationDate**: Ablaufdatum im `YYYY-MM-DDTHH:mm:ssZ`-Format
- **Name**: Der Application Name, derselbe wie AppIDName
- **ProvisionedDevices**: Ein Array (für Developer Certificates) von UDIDs, für die dieses Profile gültig ist
- **ProvisionsAllDevices**: Ein boolescher Wert (true für Enterprise Certificates)
- **TeamIdentifier**: Ein Array von (normalerweise einem) alphanumerischen String(s), das zur Identifizierung des Developers für Inter-App-Interaktion verwendet wird
- **TeamName**: Ein menschenlesbarer Name zur Identifizierung des Developers
- **TimeToLive**: Gültigkeit (in Tagen) des Zertifikats
- **UUID**: Ein Universally Unique Identifier für dieses Profile
- **Version**: Derzeit auf 1 gesetzt

Beachte, dass der Entitlements-Eintrag einen eingeschränkten Satz von Entitlements enthält und das Provisioning Profile nur in der Lage sein wird, genau diese spezifischen Entitlements zu vergeben, um zu verhindern, dass Apple private Entitlements vergeben werden.

Beachte, dass Profile normalerweise in `/var/MobileDeviceProvisioningProfiles` liegen und dass man sie mit **`security cms -D -i /path/to/profile`** prüfen kann

## **libmis.dylib**

Dies ist die externe Library, die `amfid` aufruft, um zu fragen, ob sie etwas erlauben soll oder nicht. Dies wurde historisch beim Jailbreaking missbraucht, indem eine Backdoored-Version davon ausgeführt wurde, die alles erlauben würde.

In macOS befindet sich dies in `MobileDevice.framework`.

## AMFI Trust Caches

Trust Caches sind nicht nur ein iOS-Konzept. Auf modernem macOS, besonders auf **Apple silicon**, sind der statische Trust Cache und loadable Trust Caches Teil der Secure Boot-Kette. Wenn der **CodeDirectory hash** eines Mach-O dort vorhanden ist, kann AMFI ihm beim Start **platform privilege** gewähren, ohne weitere Authentizitätsprüfungen durchzuführen. Das bedeutet auch, dass Apple Platform-Binaries auf eine bestimmte OS-Version festlegen und verhindern kann, dass ältere, von Apple signierte Binaries auf neueren Systemen erneut ausgeführt werden.

In neueren macOS-Versionen sind Trust-Cache-Metadaten außerdem mit **launch constraints** verknüpft, sodass kopierte System-Apps und Binaries, die vom falschen Parent/Ort gestartet werden, von AMFI abgelehnt werden können, selbst wenn sie weiterhin von Apple signiert sind. Der detaillierte Extraktions- und Reversing-Workflow wird behandelt in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In iOS- und Jailbreak-Research findet man weiterhin das traditionelle Modell der **loadable trust caches**, die verwendet werden, um ad-hoc signierte Binaries auf eine Whitelist zu setzen.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
