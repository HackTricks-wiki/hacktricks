# Sicurezza di macOS ed escalation dei privilegi

{{#include ../../banners/hacktricks-training.md}}

## Nozioni di base su MacOS

Se non hai familiarità con macOS, dovresti iniziare imparando le basi di macOS:

- **file e permessi** speciali di macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **utenti** comuni di macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- L'**architettura** del k**ernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **servizi e protocolli di rete** comuni di macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
- Per scaricare un `tar.gz`, modifica un URL come [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Nelle aziende, i sistemi **macOS** saranno molto probabilmente **gestiti con un MDM**. Pertanto, dal punto di vista di un attaccante, è interessante sapere **come funziona**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Ispezione, debugging e fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protezioni di sicurezza di MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Superficie di attacco

### Permessi dei file

Se un **processo in esecuzione come root scrive** un file che può essere controllato da un utente, quest'ultimo potrebbe sfruttare la situazione per **escalare i privilegi**.\
Ciò potrebbe verificarsi nelle seguenti situazioni:

- Il file utilizzato è già stato creato da un utente (appartiene all'utente)
- Il file utilizzato è scrivibile dall'utente a causa di un gruppo
- Il file utilizzato si trova all'interno di una directory appartenente all'utente (l'utente potrebbe creare il file)
- Il file utilizzato si trova all'interno di una directory appartenente a root, ma l'utente ha accesso in scrittura su di essa a causa di un gruppo (l'utente potrebbe creare il file)

La possibilità di **creare un file** che verrà **utilizzato da root** consente a un utente di **sfruttarne il contenuto** o persino di creare **symlink/hardlink** per puntarlo verso un'altra posizione.

Per questo tipo di vulnerabilità, non dimenticare di **controllare gli installer `.pkg` vulnerabili**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Gestori di app per estensioni di file e schemi URL

Le app anomale registrate dalle estensioni dei file potrebbero essere sfruttate e diverse applicazioni possono essere registrate per aprire protocolli specifici


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalation dei privilegi tramite macOS TCC / SIP

In macOS, **applicazioni e binari possono avere permessi** per accedere a cartelle o impostazioni che li rendono più privilegiati rispetto ad altri.

Pertanto, un attaccante che vuole compromettere con successo una macchina macOS dovrà **escalare i propri privilegi TCC** (o persino **bypassare SIP**, a seconda delle proprie esigenze).

Questi privilegi vengono solitamente concessi sotto forma di **entitlements** con cui l'applicazione è firmata, oppure l'applicazione potrebbe aver richiesto determinati accessi e, dopo che **l'utente li ha approvati**, questi possono essere trovati nei **database TCC**. Un altro modo in cui un processo può ottenere questi privilegi è essere **figlio di un processo** con tali **privilegi**, poiché solitamente vengono **ereditati**.<sup>[[5]](#references)</sup>

Segui questi link per scoprire diversi modi per [**escalare i privilegi in TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypassare TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) e come in passato [**SIP è stato bypassato**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalation tradizionale dei privilegi su macOS

Naturalmente, dal punto di vista dei red teams, dovresti essere interessato anche a eseguire un'escalation verso root. Consulta il seguente post per alcuni suggerimenti:


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
