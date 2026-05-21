# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Es konzentriert sich darauf, die Integrität des auf dem System laufenden Codes durchzusetzen und liefert die Logik hinter der Code-Signature-Verifikation von XNU. Es kann außerdem entitlements prüfen und andere sensible Aufgaben übernehmen, wie das Erlauben von Debugging oder das Erhalten von task ports.

Außerdem bevorzugt der kext für einige Operationen die Kontaktaufnahme mit dem im User-Space laufenden Daemon `/usr/libexec/amfid`. Diese Vertrauensbeziehung wurde in mehreren jailbreaks ausgenutzt.

Auf neueren macOS-Versionen ist AMFI nicht mehr bequem als eigenständiger kext auf der Festplatte verfügbar, daher bedeutet Reversing normalerweise, mit dem **kernelcache** oder einem **KDK** zu arbeiten, statt in `/System/Library/Extensions` zu browsen.

AMFI verwendet **MACF**-Policies und registriert seine Hooks in dem Moment, in dem es startet. Außerdem kann das Verhindern des Ladens oder das Entladen einen Kernel Panic auslösen. Es gibt jedoch einige Boot-Argumente, die es ermöglichen, AMFI zu schwächen:

- `amfi_unrestricted_task_for_pid`: Erlaubt, dass task_for_pid ohne erforderliche entitlements erlaubt wird
- `amfi_allow_any_signature`: Erlaubt jede Code-Signature
- `cs_enforcement_disable`: Systemweites Argument zum Deaktivieren der Code-Signature-Durchsetzung
- `amfi_prevent_old_entitled_platform_binaries`: Macht platform binaries mit entitlements ungültig
- `amfi_get_out_of_my_way`: Deaktiviert amfi vollständig

Dies sind einige der MACF-Policies, die es registriert:

- **`cred_check_label_update_execve:`** Label-Update wird durchgeführt und gibt 1 zurück
- **`cred_label_associate`**: Aktualisiert AMFIs mac label slot mit dem Label
- **`cred_label_destroy`**: Entfernt AMFIs mac label slot
- **`cred_label_init`**: Setzt 0 in AMFIs mac label slot
- **`cred_label_update_execve`:** Es prüft die entitlements des Prozesses, um zu sehen, ob es erlaubt sein sollte, die Labels zu ändern.
- **`file_check_mmap`:** Es prüft, ob mmap Speicher anfordert und ihn als ausführbar setzt. In diesem Fall prüft es, ob library validation nötig ist, und falls ja, ruft es die library-validation-Funktion auf.
- **`file_check_library_validation`**: Ruft die library-validation-Funktion auf, die unter anderem prüft, ob ein platform binary ein anderes platform binary lädt oder ob der Prozess und die neu geladene Datei dieselbe TeamID haben. Bestimmte entitlements erlauben außerdem, jede Library zu laden.
- **`policy_initbsd`**: Richtet vertrauenswürdige NVRAM-Keys ein
- **`policy_syscall`**: Es prüft DYLD-Policies, etwa ob das Binary unbeschränkte Segmente hat, ob Env-Variablen erlaubt sein sollen... dies wird auch aufgerufen, wenn ein Prozess über `amfi_check_dyld_policy_self()` gestartet wird.
- **`proc_check_inherit_ipc_ports`**: Es prüft, ob beim Ausführen eines neuen Binaries durch einen Prozess andere Prozesse mit SEND-Rechten über den task port des Prozesses diese behalten sollen oder nicht. Platform binaries sind erlaubt, `get-task-allow`-entitled erlaubt es, `task_for_pid-allow`-entitled sind erlaubt und Binaries mit derselben TeamID.
- **`proc_check_expose_task`**: setzt entitlements durch
- **`amfi_exc_action_check_exception_send`**: Eine Exception-Nachricht wird an den debugger gesendet
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label-Lebenszyklus während der Exception-Behandlung (debugging)
- **`proc_check_get_task`**: Prüft entitlements wie `get-task-allow`, das anderen Prozessen erlaubt, den task port zu erhalten, und `task_for_pid-allow`, das dem Prozess erlaubt, die task ports anderer Prozesse zu erhalten. Wenn keines davon zutrifft, wird `amfid permitunrestricteddebugging` aufgerufen, um zu prüfen, ob es erlaubt ist.
- **`proc_check_mprotect`**: Verweigert, wenn `mprotect` mit dem Flag `VM_PROT_TRUSTED` aufgerufen wird, das anzeigt, dass der Bereich so behandelt werden muss, als hätte er eine gültige Code-Signature.
- **`vnode_check_exec`**: Wird aufgerufen, wenn ausführbare Dateien in den Speicher geladen werden, und setzt `cs_hard | cs_kill`, wodurch der Prozess beendet wird, wenn eine der Pages ungültig wird
- **`vnode_check_getextattr`**: MacOS: Prüft `com.apple.root.installed` und `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Wie get + com.apple.private.allow-bless und internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code, der XNU aufruft, um die Code-Signature mithilfe von entitlements, trust cache und `amfid` zu prüfen
- **`proc_check_run_cs_invalid`**: Es fängt `ptrace()`-Aufrufe ab (`PT_ATTACH` und `PT_TRACE_ME`). Es prüft auf die entitlements `get-task-allow`, `run-invalid-allow` und `run-unsigned-code`, und wenn keines davon vorhanden ist, prüft es, ob Debugging erlaubt ist.
- **`proc_check_map_anon`**: Wenn `mmap` mit dem **`MAP_JIT`**-Flag aufgerufen wird, prüft AMFI das `dynamic-codesigning` entitlement.

`AMFI.kext` stellt außerdem eine API für andere Kernel-Extensions bereit, und es ist möglich, seine Abhängigkeiten mit folgender Methode zu finden:
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

Dies ist der Daemon im User-Mode, den `AMFI.kext` verwendet, um Code-Signaturen im User-Mode zu überprüfen.\
Damit `AMFI.kext` mit dem Daemon kommunizieren kann, verwendet es mach messages über den Port `HOST_AMFID_PORT`, der der spezielle Port `18` ist.

Beachte, dass es in macOS nicht mehr möglich ist, dass Root-Prozesse spezielle Ports hijacken, da sie durch `SIP` geschützt sind und nur launchd sie bekommen kann. In iOS wird geprüft, ob der Prozess, der die Antwort zurücksendet, den hardcoded CDHash von `amfid` hat.

Es ist möglich zu sehen, wann `amfid` aufgefordert wird, ein Binary zu prüfen, und welche Antwort es zurückgibt, indem man es debuggt und einen Breakpoint in `mach_msg` setzt.

Sobald eine Nachricht über den speziellen Port empfangen wird, wird **MIG** verwendet, um jede Funktion an die Funktion zu senden, die sie aufruft. Die Hauptfunktionen wurden reverse engineered und im Buch erklärt.

### DYLD policy and library validation

Neuere `dyld`-Versionen rufen `amfi_check_dyld_policy_self()` sehr früh aus `configureProcessRestrictions()` auf, um AMFI zu fragen, ob der Prozess `DYLD_*`-Path-Variablen, Interposing, Fallback-Pfade, eingebettete Variablen verwenden darf oder fehlgeschlagene Library-Injektion tolerieren kann. Daher reicht es bei der Analyse einer Injection-Use-Case nicht aus, nur die Mach-O-Load-Commands zu prüfen: Du musst auch die Entitlements und Runtime-Flags prüfen, die AMFI in `dyld`-Policy übersetzt.

Ein praktischer Triage-Loop ist:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Auf modernen macOS tragen viele Apple-Binaries `com.apple.security.cs.disable-library-validation` nicht mehr direkt und werden stattdessen mit `com.apple.private.security.clear-library-validation` ausgeliefert. In diesem Fall wird library validation nicht zur `execve`-Zeit deaktiviert: Der Prozess muss `csops(..., CS_OPS_CLEAR_LV, ...)` auf sich selbst aufrufen, und XNU erlaubt diese Operation nur für den aufrufenden Prozess, wenn die Entitlement vorhanden ist. Aus offensiver Sicht ist das wichtig, weil ein Ziel erst injizierbar werden kann, **nachdem** es den Codepfad erreicht, der LV explizit deaktiviert (zum Beispiel kurz bevor optionale Plugins geladen werden).

## Provisioning Profiles

Ein provisioning profile kann verwendet werden, um Code zu signieren. Es gibt **Developer**-Profile, die zum Signieren von Code und zum Testen verwendet werden können, sowie **Enterprise**-Profile, die auf allen Geräten verwendet werden können.

Nachdem eine App beim Apple Store eingereicht wurde, wird sie, falls genehmigt, von Apple signiert und das provisioning profile wird nicht mehr benötigt.

Ein profile verwendet normalerweise die Endung `.mobileprovision` oder `.provisionprofile` und kann gedumpt werden mit:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Auch wenn sie manchmal als Zertifikate bezeichnet werden, enthalten diese Provisioning Profiles mehr als nur ein Zertifikat:

- **AppIDName:** Der Application Identifier
- **AppleInternalProfile**: Kennzeichnet dies als ein Apple Internal Profile
- **ApplicationIdentifierPrefix**: Wird an AppIDName vorangestellt (gleich wie TeamIdentifier)
- **CreationDate**: Datum im Format `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Ein Array von (meist einem) Zertifikat(en), kodiert als Base64-Daten
- **Entitlements**: Die Entitlements, die mit Entitlements für dieses Profile erlaubt sind
- **ExpirationDate**: Ablaufdatum im Format `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Der Application Name, derselbe wie AppIDName
- **ProvisionedDevices**: Ein Array (für Entwicklerzertifikate) von UDIDs, für die dieses Profile gültig ist
- **ProvisionsAllDevices**: Ein Boolean (true für Enterprise-Zertifikate)
- **TeamIdentifier**: Ein Array von (meist einem) alphanumerischen String(s), die verwendet werden, um den Entwickler für Inter-App-Interaktion zu identifizieren
- **TeamName**: Ein menschenlesbarer Name zur Identifizierung des Entwicklers
- **TimeToLive**: Gültigkeit (in Tagen) des Zertifikats
- **UUID**: Ein Universally Unique Identifier für dieses Profile
- **Version**: Derzeit auf 1 gesetzt

Beachte, dass der Entitlements-Eintrag eine eingeschränkte Menge an Entitlements enthalten wird und das Provisioning Profile nur in der Lage sein wird, genau diese spezifischen Entitlements zu vergeben, um zu verhindern, dass Apple private Entitlements vergeben werden.

Beachte, dass sich Profile normalerweise in `/var/MobileDeviceProvisioningProfiles` befinden und es möglich ist, sie mit **`security cms -D -i /path/to/profile`** zu prüfen

## **libmis.dylib**

Dies ist die externe Library, die `amfid` aufruft, um zu fragen, ob etwas erlaubt werden soll oder nicht. Dies wurde historisch beim Jailbreaking missbraucht, indem eine Backdoored-Version davon ausgeführt wurde, die alles erlauben würde.

In macOS befindet sich dies in `MobileDevice.framework`.

## AMFI Trust Caches

Trust Caches sind nicht nur ein iOS-Konzept. Auf modernem macOS, insbesondere auf **Apple silicon**, sind der statische Trust Cache und loadable trust caches Teil der Secure Boot Chain. Wenn der **CodeDirectory hash** eines Mach-O dort vorhanden ist, kann AMFI ihm **platform privilege** gewähren, ohne beim Start weitere Authentizitätsprüfungen durchzuführen. Das bedeutet auch, dass Apple Plattform-Binaries an eine bestimmte OS-Version binden und verhindern kann, dass ältere von Apple signierte Binaries auf neueren Systemen erneut ausgeführt werden.

Auf neueren macOS-Releases sind Trust-Cache-Metadaten auch mit **launch constraints** verknüpft, sodass kopierte System-Apps und Binaries, die vom falschen Parent/Ort gestartet werden, von AMFI abgelehnt werden können, selbst wenn sie immer noch von Apple signiert sind. Der detaillierte Extraktions- und Reversing-Workflow wird behandelt in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In iOS- und Jailbreak-Research findet man weiterhin das traditionelle Modell von **loadable trust caches**, das verwendet wird, um ad-hoc signierte Binaries auf eine Whitelist zu setzen.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
