# Sicurezza ed escalation dei privilegi su macOS

{{#include ../../banners/hacktricks-training.md}}

## Nozioni di base su MacOS

Se non hai familiarità con macOS, dovresti iniziare apprendendo le nozioni di base di macOS:

- **Files e permissions** speciali di macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Users** comuni di macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- L'**architecture** del k**ernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **Network services e protocols** comuni di macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
- Per scaricare un `tar.gz`, modifica un URL come [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Nelle aziende, i sistemi **macOS** sono molto probabilmente **managed with a MDM**. Pertanto, dal punto di vista di un attacker, è interessante sapere **come funziona**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecting, Debugging e Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protezioni di sicurezza di MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

Se un **process running as root writes** un file che può essere controllato da un user, quest'ultimo potrebbe abusarne per **escalate privileges**.\
Ciò potrebbe verificarsi nelle seguenti situazioni:

- Il file utilizzato è già stato creato da un user (ed è di proprietà dell'user)
- Il file utilizzato è scrivibile dall'user a causa di un group
- Il file utilizzato si trova all'interno di una directory di proprietà dell'user (l'user potrebbe creare il file)
- Il file utilizzato si trova all'interno di una directory di proprietà di root, ma l'user dispone di accesso in scrittura tramite un group (l'user potrebbe creare il file)

La possibilità di **create a file** che verrà **used by root** consente a un user di **take advantage of its content** o persino di creare **symlinks/hardlinks** per indirizzarlo verso un'altra posizione.

Per questo tipo di vulnerabilità, non dimenticare di **check vulnerable `.pkg` installers**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension e URL scheme app handlers

Le app anomale registrate tramite estensioni di file potrebbero essere sfruttate e diverse applicazioni possono essere registrate per aprire protocolli specifici


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

In macOS, **applications and binaries can have permissions** per accedere a cartelle o impostazioni che le rendono più privilegiate di altre.

Pertanto, un attacker che vuole compromettere con successo una macchina macOS dovrà **escalate its TCC privileges** (o persino **bypass SIP**, a seconda delle sue esigenze).

Questi privilegi vengono solitamente concessi sotto forma di **entitlements** con cui l'applicazione è firmata, oppure l'applicazione potrebbe richiedere determinati accessi e, dopo che **l'user li ha approvati**, questi possono essere trovati nei **TCC databases**. Un altro modo con cui un process può ottenere questi privilegi è essere **child di un process** con tali **privileges**, poiché solitamente vengono **inherited**.

Segui questi link per scoprire diversi modi per [**escalate privileges in TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) e sapere come in passato [**SIP has been bypassed**](macos-security-protections/macos-sip.md#sip-bypasses).

## Traditional Privilege Escalation su macOS

Naturalmente, dal punto di vista dei red teams, dovresti essere interessato anche a effettuare l'escalation a root. Consulta il seguente post per alcuni suggerimenti:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Conformità di macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Riferimenti

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
