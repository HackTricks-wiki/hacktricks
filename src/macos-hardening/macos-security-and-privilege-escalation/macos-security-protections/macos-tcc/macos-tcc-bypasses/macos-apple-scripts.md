# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

È un linguaggio di scripting utilizzato per l'automazione delle attività, **interagendo con processi remoti**. Rende piuttosto semplice **chiedere ad altri processi di eseguire determinate azioni**. I **malware** possono abusare di queste funzionalità per sfruttare le funzioni esportate da altri processi.\
Ad esempio, un malware potrebbe **iniettare codice JS arbitrario nelle pagine aperte del browser**. Oppure **fare clic automaticamente** su alcune richieste di autorizzazione allow mostrate all'utente;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ecco alcuni esempi: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trova maggiori informazioni sul malware che utilizza AppleScripts [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Quirks di Automation / TCC

Le approvazioni degli Apple Events sono **direzionali**: il prompt riguarda una coppia **processo sorgente -> processo target**. Dopo che l'utente fa clic su **Allow**, le richieste future dalla stessa sorgente verso lo stesso target vengono consentite finché la voce non viene reimpostata. Durante i test, concedere una volta `Terminal -> Finder` o `Terminal -> System Events` è sufficiente per riutilizzare successivamente l'autorizzazione senza un altro popup.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Questo è particolarmente rilevante quando il **target** è **Finder**, perché Finder dispone sempre di **Full Disk Access**, anche se non compare nell'interfaccia utente FDA. Pertanto, qualsiasi host che disponga già di **Automation** su Finder può essere utilizzato come proxy AppleScript/JXA per accedere ai file protetti da TCC.<sup>[[1]](#references)</sup> I payload generici per Finder e System Events sono già documentati nella [pagina principale di TCC](../README.md) e nella [pagina Apple Events](../macos-apple-events.md).

### Tecniche offensive moderne

`/usr/bin/osascript` è soltanto l'entry point più visibile. AppleScript e JXA possono anche essere eseguiti da **Mach-O binaries** tramite **`NSAppleScript`** / **`OSAScript`**, il che è utile sia per l'evasion sia per operare all'interno di un host che dispone già di grant TCC interessanti.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se crei un helper personalizzato che invia direttamente Apple Events, assegnargli una **vera identità applicativa** rende i test e le operazioni molto più affidabili. In pratica, ciò significa incorporare un `Info.plist` con `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, firmare il binary e concedere l'entitlement `com.apple.security.automation.apple-events`. Altrimenti, la richiesta di Apple Events viene spesso attribuita al **parent host** (ad esempio `Terminal`) oppure l'esecuzione di `NSAppleScript` fallisce semplicemente con errori poco chiari `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Gli script Apple possono essere facilmente "**compilati**". Queste versioni possono essere facilmente "**decompilate**" con `osadecompile`

Tuttavia, questi script possono anche essere **esportati come "Read only"** (tramite l'opzione "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e in questo caso il contenuto non può essere decompilato nemmeno con `osadecompile`

Tuttavia, esistono ancora alcuni strumenti che possono essere utilizzati per comprendere questo tipo di executables, [**leggi questa ricerca per maggiori informazioni**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> Lo strumento [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler), insieme a [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), sarà molto utile per comprendere come funziona lo script.

## Riferimenti

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
