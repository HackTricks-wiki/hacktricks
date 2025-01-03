# Sicurezza macOS e Escalation dei Privilegi

{{#include ../../banners/hacktricks-training.md}}

## MacOS di Base

Se non sei familiare con macOS, dovresti iniziare a imparare le basi di macOS:

- File e **permessi speciali di macOS:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Utenti comuni di macOS**

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

- Servizi e **protocolli di rete comuni di macOS**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Per scaricare un `tar.gz`, cambia un URL come [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM di MacOS

Nelle aziende, i sistemi **macOS** saranno molto probabilmente **gestiti con un MDM**. Pertanto, dal punto di vista di un attaccante, è interessante sapere **come funziona**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Ispezione, Debugging e Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protezioni di Sicurezza di MacOS

{{#ref}}
macos-security-protections/
{{#endref}}

## Superficie di Attacco

### Permessi dei File

Se un **processo in esecuzione come root scrive** un file che può essere controllato da un utente, l'utente potrebbe abusarne per **escalare i privilegi**.\
Questo potrebbe verificarsi nelle seguenti situazioni:

- Il file utilizzato era già stato creato da un utente (di proprietà dell'utente)
- Il file utilizzato è scrivibile dall'utente a causa di un gruppo
- Il file utilizzato si trova all'interno di una directory di proprietà dell'utente (l'utente potrebbe creare il file)
- Il file utilizzato si trova all'interno di una directory di proprietà di root, ma l'utente ha accesso in scrittura su di essa a causa di un gruppo (l'utente potrebbe creare il file)

Essere in grado di **creare un file** che sarà **utilizzato da root** consente a un utente di **sfruttare il suo contenuto** o persino creare **symlink/hardlink** per puntarlo in un'altra posizione.

Per questo tipo di vulnerabilità non dimenticare di **controllare gli installer `.pkg` vulnerabili**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Gestori di App per Estensioni di File e Schemi URL

App strane registrate da estensioni di file potrebbero essere abusate e diverse applicazioni possono essere registrate per aprire protocolli specifici

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalation dei Privilegi TCC / SIP di macOS

In macOS **le applicazioni e i binari possono avere permessi** per accedere a cartelle o impostazioni che li rendono più privilegiati di altri.

Pertanto, un attaccante che desidera compromettere con successo una macchina macOS dovrà **escalare i suoi privilegi TCC** (o persino **bypassare SIP**, a seconda delle sue necessità).

Questi privilegi sono solitamente concessi sotto forma di **diritti** con cui l'applicazione è firmata, oppure l'applicazione potrebbe richiedere alcuni accessi e dopo che il **utente li approva**, possono essere trovati nei **database TCC**. Un altro modo in cui un processo può ottenere questi privilegi è essendo un **figlio di un processo** con quei **privilegi**, poiché di solito sono **ereditati**.

Segui questi link per trovare diversi modi per [**escalare i privilegi in TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), per [**bypassare TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) e come in passato [**SIP è stato bypassato**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalation Tradizionale dei Privilegi di macOS

Certo, dal punto di vista di un red team, dovresti essere anche interessato a escalare a root. Controlla il seguente post per alcuni suggerimenti:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Conformità di macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Riferimenti

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
