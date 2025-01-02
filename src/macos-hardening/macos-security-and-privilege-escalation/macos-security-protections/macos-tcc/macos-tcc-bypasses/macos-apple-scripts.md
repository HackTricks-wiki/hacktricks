# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

È un linguaggio di scripting utilizzato per l'automazione delle attività **interagendo con processi remoti**. Rende abbastanza facile **chiedere ad altri processi di eseguire alcune azioni**. **Il malware** può abusare di queste funzionalità per sfruttare le funzioni esportate da altri processi.\
Ad esempio, un malware potrebbe **iniettare codice JS arbitrario nelle pagine aperte del browser**. Oppure **cliccare automaticamente** su alcune autorizzazioni richieste all'utente;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Ecco alcuni esempi: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trova ulteriori informazioni su malware che utilizza applescripts [**qui**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Gli Apple scripts possono essere facilmente "**compilati**". Queste versioni possono essere facilmente "**decompilate**" con `osadecompile`

Tuttavia, questi script possono anche essere **esportati come "Sola lettura"** (tramite l'opzione "Esporta..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
e in questo caso il contenuto non può essere decompilato nemmeno con `osadecompile`

Tuttavia, ci sono ancora alcuni strumenti che possono essere utilizzati per comprendere questo tipo di eseguibili, [**leggi questa ricerca per maggiori informazioni**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Lo strumento [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) sarà molto utile per capire come funziona lo script.

{{#include ../../../../../banners/hacktricks-training.md}}
