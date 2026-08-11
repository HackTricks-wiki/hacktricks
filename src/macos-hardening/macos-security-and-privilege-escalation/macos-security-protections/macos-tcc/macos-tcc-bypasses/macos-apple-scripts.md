# Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript è un linguaggio di automazione in grado di inviare Apple Events alle applicazioni scriptable. Con le autorizzazioni pertinenti, il malware può iniettare JavaScript in una scheda di un browser scriptable oppure utilizzare System Events/Accessibility per fare clic su una finestra di dialogo relativa alle autorizzazioni. Apple Events e Accessibility sono servizi TCC distinti e generalmente richiedono le rispettive approvazioni dell'utente.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Il repository `abbeycode/AppleScripts` contiene esempi di automazione.<sup>[[7]](#references)</sup>\
Trova maggiori informazioni sul malware che usa AppleScript [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automazione / peculiarità di TCC

Le approvazioni di Apple Events sono **direzionali**: il prompt riguarda una coppia **processo sorgente -> processo target**. Dopo che l'utente fa clic su **Allow**, le richieste future dalla stessa sorgente allo stesso target vengono consentite finché la voce non viene reimpostata. Durante i test, concedere una volta `Terminal -> Finder` o `Terminal -> System Events` è sufficiente per riutilizzare in seguito l'autorizzazione senza un altro popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Ciò è particolarmente rilevante quando il **target** è **Finder**, perché Finder dispone sempre di **Full Disk Access**, anche se non compare nell'interfaccia FDA. Pertanto, qualsiasi host che disponga già di Automation su Finder può essere utilizzato come proxy AppleScript/JXA per accedere ai file protetti da TCC.<sup>[[1]](#references)</sup> I payload generici per Finder e System Events sono già documentati nella [pagina principale di TCC](../README.md) e nella [pagina Apple Events](../macos-apple-events.md).

### Tradecraft offensivo moderno

`/usr/bin/osascript` è solo l'entry point più visibile. AppleScript e JXA possono essere eseguiti anche da **Mach-O binaries** tramite **`NSAppleScript`** / **`OSAScript`**, una tecnica utile sia per l'evasione sia per operare all'interno di un host che dispone già di grant TCC interessanti.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se crei un helper personalizzato che invia direttamente Apple Events, assegnargli una **vera identità applicativa** rende i test e le operazioni molto più affidabili. In pratica, ciò significa incorporare un `Info.plist` con `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, firmare il binary e concedere l'entitlement `com.apple.security.automation.apple-events`. Altrimenti, la richiesta di Apple Events viene spesso attribuita al **parent host** (ad esempio `Terminal`) oppure l'esecuzione di `NSAppleScript` semplicemente fallisce con errori confusi `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Gli AppleScripts possono essere salvati in forma compilata e normalmente decompilati con `osadecompile`.

Tuttavia, questi script possono anche essere **esportati come "Sola lettura"** (tramite l'opzione "Esporta..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
In tal caso `osadecompile` rifiuta di recuperare il codice sorgente normale, ma il bytecode e la terminologia Apple Event possono ancora essere analizzati.

La ricerca di SentinelOne sui run-only descrive come recuperare la struttura nonostante questa restrizione. `applescript-disassembler` e `aevt_decompile` aiutano a esaminare lo script compilato e i dati Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Aggirare accidentalmente e intenzionalmente le protezioni della privacy utente TCC di macOS](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Far funzionare AppleScript negli strumenti CLI di macOS: le parti non documentate](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Come gli attori offensivi usano AppleScript per attaccare macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avventure nel reverse engineering di AppleScript run-only malevoli](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Esempi di AppleScripts di abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
