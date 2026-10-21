# Strumenti di reversing e metodi di base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automazione di WinDbg in user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Flusso di controllo guidato dalle eccezioni di Windows

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Debugging del kernel di Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Decompiler Wasm / compiler Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) per **decompilare** da wasm (binario) a wat (testo leggibile)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) per **compilare** da wat a wasm
- Puoi anche provare [web-wasmdec](https://wwwg.github.io/web-wasmdec/) per la decompilazione.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode memorizzato nella cache di Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payload virtualizzati e VM personalizzate

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina più formati**, tra cui **librerie** (.dll), **file di metadati di Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio è che, se è necessario ripristinare codice sorgente perduto a partire da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una comoda navigazione nel codice decompilato, rendendolo uno strumento ideale per l'**analisi di algoritmi Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello di add-in completo e a un'API che estende lo strumento per adattarlo alle tue esigenze, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo i numerosi servizi di reverse engineering offerti da questo strumento:

- Mostra come fluiscono i dati attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'uso dei linguaggi e dei framework .NET
- Individua funzionalità non documentate e non esposte, per sfruttare meglio le API e le tecnologie utilizzate.
- Individua dipendenze e assembly diversi
- Trova la posizione esatta degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
- Esegue il debugging del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi usarlo su qualsiasi OS (puoi installarlo direttamente da VSCode, senza bisogno di scaricare il repository git. Clicca su **Extensions** e **cerca ILSpy**).\
Se devi **decompilare**, **modificare** e **ricompilare**, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic destro -> Modify Method** per modificare qualcosa all'interno di una funzione).

### Ispezione gestita senza esecuzione con REA

**REA** può esaminare i metadati PE/CLI e il CIL senza caricare l'assembly. Inizia identificando l'artefatto, poi esamina i membri e i confini nativi dichiarati; è utile quando si analizzano chiamate sospette prima di usare un decompiler o eseguire il programma.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Per il confronto tra versioni, `compare_managed_members` usa l’identità grezza di CIL/firme e fingerprint delle istruzioni decodificate, invece di considerare stabili i metadata token tra build diverse. Una dichiarazione P/Invoke non dimostra che sia stato eseguito codice nativo; `verify_managed_native_boundaries` ha bisogno di un export nativo corrispondente o di prove relative alla funzione per verificare quel confine. Conserva con il risultato il digest dell’artefatto, l’MVID e le mapping non risolte.<sup>[[17]](#references)</sup>

### Logging di DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debug di DNSpy

Per eseguire il debug del codice usando DNSpy, devi:

Per prima cosa, modificare gli **attributi dell'assembly** relativi al **debug**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

Da:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

A:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

E fai clic su **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Poi salva il nuovo file tramite _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

È necessario perché, se non lo fai, al **runtime** verranno applicate diverse **ottimizzazioni** al codice e potrebbe succedere che durante il debugging un **breakpoint non venga mai raggiunto** oppure che alcune **variabili non esistano**.

Poi, se la tua applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:

```
iisreset /noforce
```

Quindi, per iniziare il debugging, chiudi tutti i file aperti e nella **Debug Tab** seleziona **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Quindi, per iniziare il debugging, chiudi tutti i file aperti e nella Debug Tab seleziona Attach to Process](<../../images/image (318).png>)

Seleziona quindi **w3wp.exe** per collegarti al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Seleziona w3wp.exe per collegarti al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Fai clic prima su _Debug >> Break All_, quindi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Fai clic prima su Debug Break All, quindi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Fai clic prima su Debug Break All, quindi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il pulsante destro del mouse su un modulo qualsiasi in **Assembly Explorer** e seleziona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il pulsante destro del mouse su un modulo qualsiasi in Assembly Explorer e seleziona Sort Assemblies](<../../images/image (339).png>)

## Decompilatore Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging delle DLL

### Con IDA

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- Seleziona il debugger **Windbg**
- Seleziona "**Suspend on library load/unload**"

![Debugging DLLs - Con IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parametri** di esecuzione inserendo il **percorso della DLL** e la funzione che vuoi chiamare:

![Debugging DLLs - Con IDA: Configura i parametri di esecuzione inserendo il percorso della DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Quindi, quando avvii il debugging, **l'esecuzione si interrompe al caricamento di ogni DLL**; quando rundll32 carica la tua DLL, l'esecuzione si interrompe.

Questo metodo si interrompe in corrispondenza degli eventi di caricamento dei moduli, ma raggiungere il punto di ingresso della DLL caricata è meno diretto rispetto al workflow con x64dbg descritto sotto.

### Con x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la Command Line** ( _File --> Change Command Line_ ) e imposta il percorso della DLL e la funzione che vuoi chiamare, per esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- **Avvia quindi l'esecuzione**: il debugger si interromperà in corrispondenza di ogni DLL main; a un certo punto ti **fermerai nel punto di ingresso della tua DLL**. Da lì, cerca i punti in cui vuoi impostare un breakpoint.

Nota che, quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** guardando la **parte superiore della finestra di win64dbg**:

![Using IDA - Con x64dbg/x32dbg: Nota che, quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi guardando la parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma che l'esecuzione si è interrotta all'interno della DLL di cui vuoi eseguire il debugging.

## App GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati nella memoria i valori importanti di un gioco in esecuzione e modificarli. Maggiori informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è un front-end/strumento di reverse engineering per GNU Project Debugger (GDB), pensato per i giochi. Tuttavia, può essere usato per qualsiasi attività legata al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompilatori. Questo servizio web permette di confrontare l'output di diversi decompilatori su piccoli eseguibili.

## Indagine nativa basata su evidenze con REA

**REA** espone le funzionalità di analisi di Hopper, Ghidra e IDA tramite CLI e MCP. Richiede Node.js 22.x (almeno 22.19), 24.x (almeno 24.11) o 26+, oltre a npm. Configura prima un provider nativo esistente; controlla `rea providers --json` e seleziona esplicitamente un provider se più di uno supporta il target. Usa al posto di `0x1000` qui sotto il nome o l'indirizzo di una funzione rilevata nell'inventario.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Parti da una stringa o un simbolo della feature, segui i riferimenti e i chiamanti, quindi esamina la scheda della funzione selezionata e il pseudocodice con `rea decompile`. REA associa una sessione al provider selezionato invece di sostituirlo silenziosamente dopo un errore. Per query ripetibili, `--snapshot PATH` riutilizza solo i byte degli artefatti, il provider, le impostazioni, l'operazione e i parametri corrispondenti; uno snapshot è una cache locale, non un database del provider salvato. Conserva gli Evidence restituiti e le incognite esplicite, invece di trattare i percorsi dedotti o il testo del decompiler come codice sorgente originale.<sup>[[16]](#references)[[18]](#references)</sup>

Per gli entry point JavaScript/Electron che conducono agli add-on nativi, vedi [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Analisi di IDA e Ghidra con script tramite un bridge TCP locale

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) viene eseguito all'interno di un database IDA o di un programma Ghidra CodeBrowser **già aperto** e permette a uno script separato di interrogare e modificare quel database di analisi. Esegui `ID_Server.py` dalla Python CLI di IDA (`import ID_Server`) o `Ghidra_Server.py` dallo Script Manager di Ghidra. IDA si collega a `127.0.0.1` a partire dalla porta `5073` e controlla le porte successive. Lo script Ghidra attuale parte dalla porta `5093` e prova dieci porte fino a `5102`; il suo socket Java si collega all'indirizzo wildcard, non solo al loopback. Controlla la porta stampata dall'istanza prima di connetterti. A differenza di un analizzatore headless, questo bridge opera sul programma attualmente aperto in quell'istanza della GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Invia **un comando terminato da newline per connessione** e leggi la risposta, anch'essa terminata da newline. Il risultato è normalmente JSON. Ad esempio, dopo aver individuato un'API importata pertinente a un percorso di input, `IMPORTXREF` trova i suoi call site; `DECOMP_XREF` decompila quindi in batch i chiamanti di un indirizzo selezionato. `FUNC` esamina una funzione, mentre `PCODE` restituisce la rappresentazione intermedia del decompiler. Usa l'indirizzo del database attivo, non un indirizzo copiato da un binario con una base di caricamento diversa. L'esempio seguente usa la porta predefinita di IDA; per Ghidra, usa la porta stampata dal suo script.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Lo stesso canale può **modificare il database di analisi**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` e `PATCH` modificano nomi, tipi, definizioni delle strutture, confini delle funzioni o byte memorizzati. `PATCH` è una modifica al database, **non** una prova di una patch applicata a un processo in esecuzione. Nessuno dei due listener documenta l’autenticazione. IDA è limitato all’interfaccia loopback, ma Ghidra potrebbe essere raggiungibile tramite interfacce di rete; quando lo usi, limita l’accesso al listener di Ghidra. `QUIT` arresta entrambi i listener e IDA espone anche `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging di una shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca la **shellcode**, stampa il suo **indirizzo di memoria** e mette in pausa l’esecuzione.\
Collega un debugger come IDA o x64dbg, imposta un breakpoint all’indirizzo stampato e riprendi l’esecuzione per eseguire il debugging della shellcode.

La pagina GitHub delle release contiene archivi ZIP con le versioni compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, **crea un progetto C/C++ in Visual Studio Code, copia e incolla il codice e compilalo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging di una shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca la shellcode ed entra in un loop infinito. Collega il debugger, riprendi l’esecuzione per **2–5 secondi**, metti in pausa l’esecuzione all’interno del loop e fai uno step fino alla chiamata successiva che trasferisce l’esecuzione alla shellcode allocata.

![Debugger in pausa nel loop infinito di jmp2it, subito prima della chiamata alla shellcode allocata](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Debugging di una shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Con Cutter puoi emulare la shellcode e analizzarla dinamicamente.

Nota che Cutter permette di scegliere "Open File" e "Open Shellcode". Nel mio caso, aprendola come file la shellcode è stata decompilata correttamente, mentre aprendola come shellcode no:

![Cutter mostra risultati di analisi diversi quando gli stessi byte vengono aperti come file o come shellcode](<../../images/image (562).png>)

Per avviare l’emulazione nel punto desiderato, imposta un bp lì: a quanto pare Cutter avvierà automaticamente l’emulazione da quel punto:

![Impostazione di un breakpoint nel punto desiderato della shellcode prima di avviare l’emulazione di Cutter](<../../images/image (589).png>)

![Emulatore di Cutter in pausa sul breakpoint selezionato nella shellcode](<../../images/image (387).png>)

Ad esempio, puoi visualizzare lo stack in un dump esadecimale:

![Visualizzazione dello stack della shellcode emulata nel dump esadecimale di Cutter](<../../images/image (186).png>)

### Deoffuscare la shellcode e individuare le funzioni eseguite

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà, ad esempio, **quali funzioni** usa la shellcode e se si sta **decodificando** in memoria.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg include anche un launcher grafico in cui puoi selezionare le opzioni desiderate ed eseguire lo shellcode

![Launcher grafico di scDbg per selezionare le opzioni di emulazione e tracing dello shellcode](<../../images/image (258).png>)

L’opzione **Create Dump** esegue il dump dello shellcode finale se vengono apportate modifiche dinamiche allo shellcode in memoria (utile per scaricare lo shellcode decodificato). Lo **start offset** può essere utile per avviare lo shellcode da un offset specifico. L’opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, per questo scopo trovo migliori le opzioni spiegate prima, perché permettono di usare Ida o x64dbg).

### Disassemblare usando CyberChef

Carica il file dello shellcode come input e usa la seguente ricetta per disassemblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

L’obfuscation **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). L’aspetto importante è che queste identità sono generalmente corrette solo con un’aritmetica modulare a **larghezza fissa**, quindi carry e overflow sono importanti:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se semplifichi questo tipo di espressione con strumenti algebrici generici, puoi facilmente ottenere un risultato errato perché la semantica della larghezza in bit è stata ignorata.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la larghezza in bit originale** dell'output del codice/IR/decompiler ottenuto tramite lifting (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
   - **Lineare**: somme pesate di atomi bitwise
   - **Semilineare**: espressioni lineari più maschere costanti come `x & 0xFF`
   - **Polinomiale**: sono presenti prodotti
   - **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una prova SMT. Se l'equivalenza non può essere dimostrata, mantieni l'espressione originale invece di tirare a indovinare.

### Bypass del control flow flattening con uno slice di esecuzione ridotto

Spesso non è necessario ricostruire l'intero grafo del control flow. In presenza di control-flow flattening, opaque predicates, dispatcher di grandi dimensioni o codice ricco di MBA, segui i riferimenti dai blob cifrati e dai buffer di output fino alla routine più piccola che li trasforma. Poi riproduci solo quello slice del data flow, oppure eseguilo in modo indipendente; il dispatcher non è necessario per la soluzione se lo stato rilevante può essere inizializzato direttamente.<sup>[[7]](#references)</sup>

Un workflow pratico è:<sup>[[7]](#references)</sup>

1. Fai l'inventario delle sezioni eseguibili e dei dati, delle rilocazioni e dei riferimenti incrociati. Estrai le tabelle candidate da `.rodata`, preservandone l'ordine dei byte e la larghezza degli elementi.
2. Individua l'ultima routine che scrive il plaintext o il buffer di output. Annota i suoi input, le tabelle a cui fa riferimento, le chiamate importate e lo stato globale richiesto.
3. Esegui il lifting solo di queste operazioni in un modello Python a larghezza fissa. Se lo slice dipende ancora da troppo stato, richiama la routine con Unicorn, QEMU o un debugger e intercetta le importazioni irrilevanti invece di emulare l'intero programma.
4. Verifica che l'extractor ricavi davvero il proprio output dal binario fornito: rimuovi i fallback silenziosi, cerca risposte incorporate al suo interno ed eseguilo su build mai viste, con stringhe, chiavi, identificatori, layout e seed di offuscamento modificati.

Alcuni comandi utili per una prima analisi sono:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Rilevare le espressioni MBA che nascondono costanti

Un'espressione di byte apparentemente dipendente dall'input può annullare completamente il proprio input. Dopo aver estratto le tabelle, valuta l'espressione sull'intero dominio a 8 bit; un insieme di output composto da un solo valore dimostra che il byte è costante, senza dover ricostruire la macchina a stati circostante.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Mantieni la maschera finale perché l’addizione originale prevede un wraparound alla larghezza del byte. Per un dominio più ampio, chiedi a un SMT solver se `f(x1) != f(x2)` è soddisfacibile per due input simbolici della stessa larghezza: `unsat` dimostra l’invarianza, mentre `sat` fornisce un controesempio e significa che l’input non può essere scartato.<sup>[[7]](#references)</sup>

#### Riconoscere il decoding legato all’ambiente

I controlli anti-analisi non devono necessariamente causare un branch o un crash. Un decoder può incorporare il risultato di un sensore in un bit della chiave, in una costante di opaque predicate o nello stato di un dispatcher appiattito, continuare normalmente e produrre un plaintext plausibile ma falso in un emulatore. Quindi, applicare patch solo ai branch di errore visibili non è sufficiente; traccia le dipendenze dei dati dalle sonde ambientali allo stato del decoder, confronta la stessa porzione su un dispositivo autentico e sull’emulatore e verifica come forzare il risultato di ciascun sensore modifica il buffer finale.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l’analisi del malware e il reversing di binari protetti. Classifica l’espressione e la instrada attraverso pipeline specializzate, invece di applicare un’unica passata di riscrittura generica a tutto.<sup>[[2]](#references)</sup>

Uso rapido:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Casi utili:

- **Linear MBA**: CoBRA valuta l’espressione su input booleani, ricava una signature e mette in competizione diversi metodi di recupero, come il pattern matching, la conversione ANF e l’interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo che le regioni mascherate rimangano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in core e le sottoespressioni ripetute possono essere spostate in temporanei prima di semplificare la relazione esterna.

Esempio di identità mista che spesso vale la pena provare a recuperare:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Questo può ridursi a:

```c
x * y
```

### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR sollevate** o sull'output del decompiler, dopo aver isolato il calcolo esatto.
- Usa esplicitamente `--bitwidth` quando l'espressione deriva da aritmetica mascherata o da registri stretti.
- Se ti serve una dimostrazione più solida, consulta qui le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin LLVM pass** (`libCobraPass.so`), utile per normalizzare LLVM IR con molte operazioni MBA prima di ulteriori pass di analisi.
- I residui misti non supportati, sensibili al carry, indicano che è meglio mantenere l'espressione originale e analizzare manualmente il percorso del carry.

## Recuperare il control-flow flattening con stato XOR

Un flattener in stile OLLVM può mantenere lo stato del basic block corrente in due registri a 64 bit e ricostruirlo con XOR in un dispatcher. Ogni blocco originale scrive la coppia corrispondente allo stato successivo e torna al dispatcher. Un blocco condizionale può usare `CMOVcc` per sostituire una metà della coppia in base ai flag della CPU; seguire solo le istruzioni di branch visibili fa quindi perdere di vista i due successori. A differenza di un dispatcher con indirect jump, questa struttura può usare back-edge diretti ovunque.<sup>[[19]](#references)[[20]](#references)</sup>

Per recuperare il grafo, individua l'albero di confronti del dispatcher e i due registri di stato, associa ogni stato XOR confrontato al relativo blocco target, quindi risali alle scritture della coppia di registri che raggiungono ciascun blocco originale. Per le scritture condizionali, includi l'istruzione che imposta i flag e entrambi gli esiti di `CMOVcc`. Riscrivi l'uscita dal dispatcher di ogni blocco nel successore diretto risolto o nel branch condizionale; il dispatcher diventerà così irraggiungibile senza modificare il binario. Questo approccio ricostruisce l'intero CFG; se ti interessa un solo decoder, il [workflow con execution slice ristretto](#bypass-flattened-control-flow-with-a-narrow-execution-slice) qui sopra potrebbe essere più rapido.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizza questa struttura in Binary Ninja. Copia `plugins/DispatchThis` nella directory dei plugin utente di Binary Ninja e riavvia. Sulla funzione interessata, apri **Function Settings** e seleziona `OLLVM_XOR_64`; se l'analisi non si avvia, usa **Analysis → Reanalyze All Functions**. Questa modalità riscrive gli archi di control-flow MLIL, non i byte del file, e non richiede Z3 né l'indirect-jump resolver. È stato testato con Binary Ninja 5.3.9757+; non rimuove le scritture di stato per-blocco non più utilizzate, quindi non confonderle con transizioni ancora attive.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione di segnali/eccezioni per modificare il control-flow. Per maggiori dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deoffuscare il risultato. Ha diverse dipendenze.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

E [installa keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai partecipando a un **CTF, questa soluzione alternativa per trovare la flag** può essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point**, cerca le funzioni con `::main`, come in:

![Ricerca dell'entry point di Rust in Ghidra cercando i nomi delle funzioni con doppio due punti e main](<../../images/image (1080).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Avendo il **nome** delle **funzioni** chiamate, cercale su **Internet** per scoprire quali sono i loro **input** e **output**.

### Recuperare le stringhe Rust dal firmware ELF

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate da puntatori terminati da NUL come quelli in stile C. Una disposizione comune di `rustc` consiste in una **tupla puntatore/lunghezza** all'interno di **`.data.rel.ro`**, che punta alla vera area delle stringhe archiviata in **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Questo significa che `strings` o l'analisi predefinita di Ghidra possono unire stringhe adiacenti o non rilevare affatto i riferimenti incrociati.<sup>[[3]](#references)</sup>

Flusso di lavoro rapido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ottieni l’indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una word alla volta.
3. Considera qualsiasi valore compreso nell’intervallo di indirizzi di `.rodata` come un possibile puntatore a una stringa.
4. Considera la word successiva come la possibile lunghezza.
5. Applica filtri di plausibilità (ad esempio, mantieni le lunghezze comprese tra **4** e **100** byte).
6. Leggi esattamente `length` byte da `.rodata`, invece di eseguire la scansione fino a `0x00`.

Logica minima dell’estrattore:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Questo è particolarmente utile nel firmware reversing, perché le stringhe Rust recuperate spesso rivelano **route HTTP, nomi RPC, messaggi di log, asserzioni, nomi di file, chiavi di configurazione, gestori di comandi e logica relativa all'autenticazione**.

Se Ghidra non rileva queste stringhe, esegui uno script/plugin personalizzato che applica la stessa euristica e crea dati stringa agli offset `.rodata` a cui si fa riferimento. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono ottimi riferimenti per adattare l'idea ad altri **word size, endianness e layout delle sezioni**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati con Delphi, puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti consiglio di usare il plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, poi seleziona il file del plugin.

All'avvio del debugging, questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni. Dopo aver avviato il debugging, premi di nuovo il pulsante Start (quello verde o f9) e verrà raggiunto un breakpoint all'inizio del codice effettivo.

Se premi un pulsante nell'applicazione grafica, il debugger può fermarsi nella funzione richiamata da quel pulsante.

## Golang

Per i normali binari Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) può recuperare le strutture di runtime e migliorare i nomi delle funzioni in IDA. Carica il suo plugin Python con **Alt+F7**.

Se devi fare reversing di un binario Golang, ti consiglio di usare il plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi **Alt+F7** in IDA per caricare un plugin Python, poi seleziona il file del plugin.

Questo risolverà i nomi delle funzioni.

### Recuperare i metadati senza la tabella dei simboli

Un eseguibile Go stripped ha comunque bisogno dei metadati di runtime per mappare i program counter alle funzioni. [GoReSym](https://github.com/mandiant/GoReSym) individua e analizza strutture come `pclntab` e `moduledata`, usando codice derivato dal runtime di Go. In questo modo può recuperare i confini delle funzioni, i nomi, i percorsi dei sorgenti, i tipi e i dettagli della build senza dipendere dalla tabella dei simboli convenzionale.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscator può lasciare utilizzabili queste strutture, sostituendo però i nomi recuperati. Garble, ad esempio, genera hash per gli identificatori e i percorsi dei package e rimuove le informazioni di build, dei moduli e di debug.<sup>[[12]](#references)</sup> Il token offuscato del package deve rimanere coerente tra le funzioni di quel package. Raggruppa le funzioni in base al token ripetuto, deduci un package da funzioni chiamate, stringhe e API, quindi propaga l'etichetta del package all'intero gruppo.<sup>[[13]](#references)</sup>

### Recuperare i nomi Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina l'estrazione dei simboli runtime con la generazione di riferimenti non offuscati e il confronto dei grafi di flusso di controllo (CFG). Segui questa procedura:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versione del compilatore.** Prova prima `BuildInfo` e le stringhe di versione incorporate. Se l'obfuscator le ha rimosse, confronta porzioni del runtime Go incluso con runtime di riferimento versionati. Nei test di Volexity, circa il `2%` del runtime era sufficiente per distinguere le versioni principali di Go. Consideralo un'ottimizzazione empirica, non una soglia universale.<sup>[[13]](#references)</sup>
2. **Prepara i riferimenti corrispondenti.** Genera binari non offuscati per la versione di Go identificata, l'architettura di destinazione e le librerie probabili. Allineare la toolchain riduce le differenze nei CFG generati dal compilatore.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Confronta le funzioni.** GoGrapher confronta i CFG delle funzioni e produce punteggi normalizzati da `0.0` a `1.0`. Il confronto dei basic block si basa su una comparazione ponderata di istruzioni simili. Le corrispondenze ad alta affidabilità associano le funzioni con nomi randomizzati all'implementazione non offuscata. Anche le corrispondenze meno affidabili possono identificare un package o un modulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Convalida e importa.** Conferma i nomi proposti verificando le relazioni tra le chiamate, le costanti, le stringhe e gli effetti collaterali, quindi importa il report JSON con il plugin GoResolver per IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installa la toolchain ed esegui l'estrattore e il matcher dei grafi combinati:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

La soglia predefinita per le corrispondenze significative è `0.9`. Le opzioni `--extract` e `--graph` consentono di isolare ciascuna fase, mentre per impostazione predefinita vengono eseguite entrambe, poiché i metadati runtime recuperati e le evidenze del CFG si completano a vicenda.<sup>[[10]](#references)</sup> I punteggi del CFG sono euristici: l'inlining, i flag di build, l'architettura e le differenze tra versioni delle librerie possono modificare la struttura del grafo; è quindi preferibile mantenere le funzioni irrisolte anziché assegnare nomi con un basso livello di confidenza.<sup>[[13]](#references)</sup>

### Recuperare la tabella delle stringhe Go

I binari Go collocano i byte delle stringhe di tutti i pacchetti collegati in un'unica tabella contigua. Le voci non sono terminate da NUL e le strutture runtime non espongono la base o le dimensioni della tabella. Tuttavia, il compilatore ordina le voci prima per lunghezza e poi alfabeticamente, su tutti i sistemi operativi e le architetture. Dopo aver individuato una voce, un analista può quindi scorrere le voci adiacenti e usare i riferimenti incrociati ai dati per associare le stringhe al codice.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizza questo flusso di lavoro in IDA Pro e Ghidra. Attendi il completamento dell'analisi automatica, perché il plugin si basa sui riferimenti incrociati del segmento dati. L'ancora predefinita è la stringa runtime `entersyscall`; da lì, il plugin può eseguire la scansione in entrambe le direzioni, definire le stringhe recuperate nel database ed esportare una mappatura JSON delle stringhe e delle funzioni che vi fanno riferimento.<sup>[[14]](#references)</sup>

Filtra il report in base al pacchetto della funzione che fa riferimento alla stringa per separare il codice dell'applicazione o del malware dal rumore delle librerie collegate. Questa tecnica non può recuperare i literal eliminati da tecniche di offuscamento come la trasformazione `-literals` di Garble. Può comunque organizzare le stringhe runtime che non sono state offuscate.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperare i tipi runtime di Go

Go incorpora informazioni sui tipi runtime usate da funzionalità come la garbage collection. Quando le informazioni di build sono state rimosse o il disassembler non analizza questi metadati, le istruzioni possono sembrare caricare indirizzi dati arbitrari e la regione di destinazione resta priva di tipo. Recuperare i metadati trasforma questi indirizzi in riferimenti ai tipi leggibili e facilita la comprensione delle funzionalità dei pacchetti.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) può estrarre i simboli e analizzare i tipi runtime per generare un report JSON. La CLI attuale usa il sottocomando `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

L'opzione `-y`/`--types` abilita l'analisi dei tipi. Importa il report con il plugin IDA Pro o Ghidra di GoResolver per definire i tipi recuperati e applicarne i riferimenti nel database di analisi. Nel formato di report introdotto con questa funzionalità, se ometti `-y`, i membri RTTI address e recovered-types restano null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver supporta campioni PE, ELF e Mach-O per x86, AMD64, ARM e ARM64, quindi lo stesso flusso di lavoro si applica ai binari Go di Windows, Linux e macOS.<sup>[[10]](#references)</sup>

## Python compilato

In questa pagina puoi scoprire come ottenere il codice Python da un binario ELF/EXE compilato da Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **file binario** di un gioco GBA, puoi usare diversi strumenti per **emularlo** ed eseguire il **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Include un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Include un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **pulsanti** del Game Boy Advance

![Configurazione dei controlli di no$gba con le mappature dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

Quando vengono premuti, ogni **tasto ha un valore** che lo identifica:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Quindi, in questo tipo di programma, la parte interessante sarà **il modo in cui il programma gestisce l'input dell'utente**. All'indirizzo **0x4000130** troverai la funzione comunemente presente: **KEYINPUT**.

![Vista di Ghidra di un binario GBA che fa riferimento a KEYINPUT all'indirizzo 0x4000130](<../../images/image (447).png>)

Nell'immagine precedente puoi vedere che la funzione viene chiamata da **FUN_080015a8** (indirizzi: _0x080015fa_ e _0x080017ac_).

In quella funzione, dopo alcune operazioni di inizializzazione (irrilevanti):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

È stato trovato questo codice:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

L'ultimo if verifica che **`uVar4`** sia nell'ultimo elenco Keys e non sia il tasto corrente, ovvero che si stia rilasciando un pulsante (il tasto corrente è memorizzato in **`uVar1`**).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

Nel codice precedente puoi vedere che confrontiamo **uVar1** (la posizione in cui si trova il **valore del pulsante premuto**) con alcuni valori:

- Per prima cosa, viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge, questo pulsante cancella lo schermo
- Poi il valore viene confrontato con **8** (pulsante **START**); in questa challenge, quel percorso verifica se il codice inserito è valido.
  - In questo caso la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore corrisponde, viene eseguito del codice.
- In tutti gli altri casi, viene verificato e incrementato un contatore (`DAT_030000d4`).\
  Finché il contatore è minore di 8, i valori dei tasti premuti vengono sommati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione di lunghezza inferiore a 8 la cui somma risultante fosse 0xf3.**

**Riferimento per questo tutorial:** [writeup archiviato della challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deoffuscamento dei binari)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository CoBRA di Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificare le stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - stringhe Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reverse engineering per GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sconfiggere il reverse engineering assistito dall'IA, o almeno provarci](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Un approccio al confronto dei grafi del flusso di controllo basato sulla corrispondenza dei blocchi base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [GoReSym di Mandiant](https://github.com/mandiant/GoReSym)
- [10] [Repository GoResolver di Volexity](https://github.com/volexity/GoResolver)
- [11] [GoGrapher di Volexity](https://github.com/volexity/GoGrapher)
- [12] [Meccanismo di offuscamento di Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: uso della similarità dei grafi del flusso di controllo per deoffuscare automaticamente i binari Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repository GoStringExtractor di Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aggiornamenti agli strumenti Golang di Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: esegui reverse engineering su qualsiasi cosa](https://github.com/morluto/rea)
- [17] [Analisi del codice gestito con REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Guida alla CLI e alle prove di REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: flusso di lavoro per l'appiattimento inverso del flusso di controllo in Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: intrusione zero-day in PaperCut MF, Java Loader, Web Shell e AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README di IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementazione del server bridge di IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementazione del server bridge di Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) associa l'indirizzo wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
