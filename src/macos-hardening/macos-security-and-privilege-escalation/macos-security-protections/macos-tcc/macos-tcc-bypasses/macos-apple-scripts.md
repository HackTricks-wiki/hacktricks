# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

È un linguaggio di scripting utilizzato per l'automazione delle attività, **interagendo con processi remoti**. Rende piuttosto semplice **chiedere ad altri processi di eseguire determinate azioni**. **Malware** potrebbe abusare di queste funzionalità per sfruttare le funzioni esportate da altri processi.\
Ad esempio, un malware potrebbe **iniettare codice JS arbitrario nelle pagine aperte nel browser**. Oppure eseguire **auto click** su alcuni permessi di autorizzazione richiesti all'utente;<sup>[3]</sup>.
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ecco alcuni esempi: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trova ulteriori informazioni sul malware che utilizza AppleScripts [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automazione / peculiarità di TCC

Le approvazioni degli Apple Events sono **direzionali**: il prompt riguarda una coppia **processo sorgente -> processo target**. Dopo che l'utente fa clic su **Allow**, le richieste future dallo stesso sorgente verso lo stesso target vengono consentite finché la voce non viene reimpostata. Durante i test, concedere una volta `Terminal -> Finder` o `Terminal -> System Events` è sufficiente per riutilizzare successivamente il permesso senza un altro popup.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Questo è particolarmente rilevante quando il **target** è **Finder**, perché Finder dispone sempre di **Full Disk Access**, anche se non appare nella UI di FDA. Pertanto, qualsiasi host che disponga già dell'automazione su Finder può essere utilizzato come proxy AppleScript/JXA per accedere ai file protetti da TCC.<sup>[1]</sup> I payload generici per Finder e System Events sono già documentati [nella pagina principale di TCC](../README.md) e [nella pagina Apple Events](../macos-apple-events.md).

### Tradecraft offensiva moderna

`/usr/bin/osascript` è solo l'entry point più visibile. AppleScript e JXA possono essere eseguiti anche da **binari Mach-O** tramite **`NSAppleScript`** / **`OSAScript`**, una tecnica utile sia per l'evasione sia per operare all'interno di un host che dispone già di interessanti autorizzazioni TCC.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se crei un helper personalizzato che invia direttamente Apple Events, assegnargli una **vera identità applicativa** rende i test e le operazioni molto più affidabili. In pratica, ciò significa incorporare un `Info.plist` con `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, firmare il binario e concedere l'entitlement `com.apple.security.automation.apple-events`. In caso contrario, la richiesta Apple Events viene spesso attribuita al **parent host** (ad esempio `Terminal`) oppure l'esecuzione di `NSAppleScript` semplicemente fallisce con errori poco chiari `-1750` / `errOSASystemError`.<sup>[2]</sup>

Gli Apple script possono essere facilmente "**compilati**". Queste versioni possono essere facilmente "**decompilate**" con `osadecompile`

Tuttavia, questi script possono anche essere **esportati come "Sola lettura"** (tramite l'opzione "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e in questo caso il contenuto non può essere decompilato nemmeno con `osadecompile`

Tuttavia, esistono ancora alcuni strumenti che possono essere utilizzati per comprendere questo tipo di eseguibili, [**leggi questa ricerca per maggiori informazioni**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> Lo strumento [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler), insieme a [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), sarà molto utile per comprendere come funziona lo script.

## Riferimenti

- [1] [Aggirare le protezioni della privacy degli utenti di macOS TCC accidentalmente e intenzionalmente](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Far funzionare AppleScript negli strumenti CLI di macOS: gli aspetti non documentati](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Come gli attori offensivi utilizzano AppleScript per attaccare macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Avventure nel reverse engineering di AppleScript malicious run-only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
