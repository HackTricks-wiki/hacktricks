# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

È un linguaggio di scripting usato per l'automazione di task **interagendo con processi remoti**. Rende molto facile **chiedere ad altri processi di eseguire alcune azioni**. **Malware** può abusare di queste funzionalità per sfruttare funzioni esportate da altri processi.\
Per esempio, un malware potrebbe **iniettare codice JS arbitrario nelle pagine aperte nel browser**. Oppure **cliccare automaticamente** su alcuni permessi di allow richiesti all'utente;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Qui trovi alcuni esempi: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trova maggiori informazioni su malware che usa applescripts [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Le approvazioni di Apple Events sono **direzionali**: il prompt riguarda una coppia **processo sorgente -> processo target**. Una volta che l'utente clicca **Allow**, le richieste future dalla stessa sorgente allo stesso target sono consentite fino a quando la voce non viene resettata. Durante i test, concedere una volta `Terminal -> Finder` o `Terminal -> System Events` è sufficiente per riutilizzare in seguito il permesso senza un altro popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Questo è particolarmente rilevante quando il **target** è **Finder**, perché Finder ha sempre **Full Disk Access** anche se non appare nella UI di FDA. Quindi, qualsiasi host che abbia già Automation su Finder può essere usato come proxy AppleScript/JXA per accedere a file protetti da TCC. I payload generici per Finder e System Events sono già documentati nella [main TCC page](../README.md) e nella [Apple Events page](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` è solo il punto di ingresso più visibile. AppleScript e JXA possono anche essere eseguiti da **Mach-O binaries** tramite **`NSAppleScript`** / **`OSAScript`**, il che è utile sia per l’evasion sia per vivere all’interno di un host che ha già grant TCC interessanti.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Se crei un helper personalizzato che invia direttamente Apple Events, assegnargli una **real app identity** rende i test e le operazioni molto più affidabili. In pratica questo significa incorporare un `Info.plist` con `CFBundleIdentifier` e `NSAppleEventsUsageDescription`, firmare il binary e concedere l’entitlement `com.apple.security.automation.apple-events`. Altrimenti il prompt di Apple Events viene spesso attribuito all’**parent host** (ad esempio `Terminal`) oppure l’esecuzione di `NSAppleScript` fallisce semplicemente con errori confusi `-1750` / `errOSASystemError`.

Gli apple scripts possono essere facilmente "**compiled**". Queste versioni possono essere facilmente "**decompiled**" con `osadecompile`

Tuttavia, questi scripts possono anche essere **exported as "Read only"** (tramite l’opzione "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e in questo caso il contenuto non può essere decompilato nemmeno con `osadecompile`

Tuttavia, ci sono ancora alcuni strumenti che possono essere usati per comprendere questo tipo di executables, [**leggi questa ricerca per maggiori info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Lo strumento [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sarà molto utile per capire come funziona lo script.

## Riferimenti

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
