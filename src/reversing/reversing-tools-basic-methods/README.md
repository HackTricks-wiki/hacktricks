# Strumenti di reversing basati su ImGui

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automazione di WinDbg in modalità utente

{{#ref}}
windbg-automation.md
{{#endref}}

## Debugging del kernel di Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Decompilatore Wasm / compilatore Wat

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

## Decompilatore .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompilatore che **decompila ed esamina diversi formati**, tra cui **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto di Visual Studio (.csproj).

Il vantaggio è che, se è necessario recuperare il codice sorgente mancante da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una comoda navigazione nel codice decompilato, diventando così uno strumento ideale per l'**analisi di algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello di add-in completo e a un'API che consente di adattare lo strumento alle proprie esigenze specifiche, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo la vasta gamma di funzionalità di reverse engineering offerte da questo strumento:

- Mostra come fluiscono i dati attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'utilizzo dei linguaggi e dei framework .NET
- Individua funzionalità non documentate e non esposte per sfruttare meglio le API e le tecnologie utilizzate.
- Individua le dipendenze e i diversi assembly
- Individua la posizione esatta degli errori nel codice, nei componenti di terze parti e nelle librerie.
- Esegue il debugging del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi usarlo su qualsiasi sistema operativo (puoi installarlo direttamente da VSCode, senza dover scaricare git. Fai clic su **Extensions** e **cerca ILSpy**).\
Se devi **decompilare**, **modificare** e **ricompilare**, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un suo fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** per modificare qualcosa all'interno di una funzione).

### Ispezione di assembly gestiti senza esecuzione con REA

**REA** può esaminare i metadati PE/CLI e il CIL senza caricare l'assembly. Inizia identificando l'artefatto, quindi esamina i membri e i confini nativi dichiarati; è utile per analizzare chiamate sospette prima di usare un decompilatore o eseguire il programma.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Per il confronto tra versioni, `compare_managed_members` usa l’identità grezza di CIL/firma e le impronte delle istruzioni decodificate, invece di considerare stabili i token dei metadati tra build diverse. Una dichiarazione P/Invoke non dimostra che sia stato eseguito codice nativo; `verify_managed_native_boundaries` richiede un’esportazione nativa corrispondente o Evidence della funzione per verificare quel confine. Conserva con il risultato il digest dell’artefatto, l’MVID e le associazioni irrisolte.<sup>[[17]](#references)</sup>

### Logging di DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging con DNSpy

Per eseguire il debugging del codice usando DNSpy, devi:

Per prima cosa, modificare gli **attributi dell'Assembly** relativi al **debugging**:

![DNSpy Logging - Debugging con DNSpy: per prima cosa, modifica gli attributi dell'Assembly relativi al debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: E fai clic su compile](<../../images/image (314) (1).png>)

Quindi salva il nuovo file tramite _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Quindi salva il nuovo file tramite File Save module](<../../images/image (602).png>)

Questo è necessario perché, se non lo fai, in **runtime** verranno applicate diverse **ottimizzazioni** al codice e potrebbe accadere che, durante il debug, un **breakpoint non venga mai raggiunto** o che alcune **variabili non esistano**.

Quindi, se la tua applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:

```
iisreset /noforce
```

Quindi, per iniziare il debugging, chiudi tutti i file aperti e, nella **scheda Debug**, seleziona **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Quindi, per iniziare il debugging, chiudi tutti i file aperti e, nella scheda Debug, seleziona Attach to Process](<../../images/image (318).png>)

Poi seleziona **w3wp.exe** per collegarti al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Poi seleziona w3wp.exe per collegarti al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Per prima cosa fai clic su _Debug >> Break All_, poi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Per prima cosa fai clic su Debug Break All, poi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Per prima cosa fai clic su Debug Break All, poi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il tasto destro su un modulo qualsiasi in **Assembly Explorer** e fai clic su **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il tasto destro su un modulo qualsiasi in Assembly Explorer e fai clic su Sort Assemblies](<../../images/image (339).png>)

## Decompiler Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging delle DLL

### Uso di IDA

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- Seleziona il debugger **Windbg**
- Seleziona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parametri** di esecuzione inserendo il **percorso della DLL** e la funzione che vuoi chiamare:

![Debugging DLLs - Using IDA: Configura i parametri di esecuzione inserendo il percorso della DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Poi, quando avvii il debugging, **l'esecuzione verrà interrotta ogni volta che viene caricata una DLL**; quindi, quando rundll32 caricherà la tua DLL, l'esecuzione verrà interrotta.

Questo metodo si interrompe in corrispondenza degli eventi di caricamento dei moduli, ma raggiungere l'entry point della DLL caricata è meno diretto rispetto al flusso di lavoro con x64dbg descritto di seguito.

### Uso di x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la Command Line** ( _File --> Change Command Line_ ) e imposta il percorso della DLL e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- Poi **avvia l'esecuzione**: il debugger si fermerà all'entry point di ogni DLL e, a un certo punto, **si fermerà all'entry point della tua DLL**. Da lì, cerca i punti in cui vuoi impostare un breakpoint.

Nota che quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** nella **parte superiore della finestra di win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Nota che quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi nella parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma che l'esecuzione è stata interrotta all'interno della DLL di cui vuoi eseguire il debugging.

## App GUI / videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli. Maggiori informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è uno strumento front-end/reverse engineering per GNU Project Debugger (GDB), pensato per i giochi. Tuttavia, può essere usato per qualsiasi attività correlata al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo servizio web permette di confrontare i risultati di diversi decompiler su piccoli eseguibili.

## Analisi nativa basata su evidenze con REA

**REA** espone le funzionalità di analisi di Hopper, Ghidra e IDA tramite CLI e MCP. Richiede Node.js 22.x (almeno 22.19), 24.x (almeno 24.11) o 26+, oltre a npm. Configura prima un provider nativo esistente; controlla `rea providers --json` e seleziona esplicitamente un provider se più di uno supporta il target. Usa al posto di `0x1000` qui sotto il nome o l'indirizzo di una funzione osservati nell'inventario.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Parti da una stringa di funzionalità o da un simbolo, segui i riferimenti e i chiamanti, poi esamina il dossier della funzione selezionata e il pseudocodice con `rea decompile`. REA associa una sessione al provider selezionato, invece di sostituirlo silenziosamente dopo un errore. Per query ripetibili, `--snapshot PATH` riutilizza solo i byte degli artifact, il provider, le impostazioni, l'operazione e i parametri corrispondenti; uno snapshot è una cache locale, non un database del provider salvato. Conserva gli Evidence restituiti e le incognite esplicite invece di considerare percorsi dedotti o testo del decompiler come codice sorgente originale.<sup>[[16]](#references)[[18]](#references)</sup>

Per gli entry point JavaScript/Electron che portano agli add-on nativi, consulta [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging di una shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca la **shellcode**, ne stampa l'**indirizzo di memoria** e mette in pausa l'esecuzione.\
Collega un debugger, come IDA o x64dbg, imposta un breakpoint all'indirizzo stampato e riprendi l'esecuzione per eseguire il debugging della shellcode.

La pagina GitHub delle release contiene archivi ZIP con le release compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, basta **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging di una shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca la shellcode ed entra in un loop infinito. Collega il debugger, riprendi l'esecuzione per **2–5 secondi**, metti in pausa il loop e fai uno step fino alla chiamata successiva, che trasferisce l'esecuzione alla shellcode allocata.

![Debugger in pausa nel loop infinito di jmp2it, subito prima della chiamata alla shellcode allocata](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Debugging della shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Con Cutter puoi emulare la shellcode e ispezionarla dinamicamente.

Nota che Cutter permette di scegliere "Open File" e "Open Shellcode". Nel mio caso, quando ho aperto la shellcode come file, l'ha decompilata correttamente, mentre quando l'ho aperta come shellcode non ci è riuscito:

![Cutter mostra risultati di analisi diversi quando gli stessi byte vengono aperti come file o come shellcode](<../../images/image (562).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp lì: a quanto pare Cutter avvierà automaticamente l'emulazione da quel punto:

![Impostazione di un breakpoint all'entry point desiderato della shellcode prima di avviare l'emulazione di Cutter](<../../images/image (589).png>)

![Emulatore di Cutter in pausa al breakpoint selezionato nella shellcode](<../../images/image (387).png>)

Puoi, ad esempio, visualizzare lo stack all'interno di un hex dump:

![Visualizzazione dello stack della shellcode emulata nell'hex dump di Cutter](<../../images/image (186).png>)

### Deoffuscare la shellcode e individuare le funzioni eseguite

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà, ad esempio, **quali funzioni** usa la shellcode e se si **decodifica** in memoria.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg dispone anche di un launcher grafico in cui puoi selezionare le opzioni desiderate ed eseguire lo shellcode

![Launcher grafico di scDbg per selezionare le opzioni di emulazione e tracing dello shellcode](<../../images/image (258).png>)

L'opzione **Create Dump** esegue il dump dello shellcode finale se viene apportata qualche modifica dinamica allo shellcode in memoria (utile per scaricare lo shellcode decodificato). Lo **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, trovo che una qualsiasi delle opzioni spiegate prima sia più adatta a questo scopo, perché permette di usare Ida o x64dbg).

### Disassemblare usando CyberChef

Carica il file dello shellcode come input e usa la seguente ricetta per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deoffuscazione dell'obfuscation MBA

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). Il punto importante è che queste identità sono generalmente corrette solo con un'aritmetica modulare a **larghezza fissa**, quindi riporti e overflow sono rilevanti:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se semplifichi questo tipo di espressione con strumenti algebrici generici, puoi facilmente ottenere un risultato errato perché è stata ignorata la semantica della larghezza in bit.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la larghezza in bit originale** dall'output del codice/IR/decompiler sottoposto a lifting (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
   - **Lineare**: somme pesate di atomi bitwise
   - **Semilineare**: lineare più maschere costanti, come `x & 0xFF`
   - **Polinomiale**: compaiono prodotti
   - **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una dimostrazione SMT. Se non è possibile dimostrarne l'equivalenza, mantieni l'espressione originale invece di fare supposizioni.

### Bypass del flusso di controllo appiattito con una slice di esecuzione ristretta

Spesso non è necessario ricostruire l'intero grafo del flusso di controllo. In presenza di control-flow flattening, opaque predicate, grandi dispatcher o codice con molte operazioni MBA, segui i riferimenti dai blob cifrati e dai buffer di output fino alla routine più piccola che li trasforma. Quindi riproduci solo quella slice del flusso dei dati oppure eseguila in modo indipendente; il dispatcher non è necessario se è possibile inizializzare direttamente lo stato rilevante.<sup>[[7]](#references)</sup>

Un workflow pratico è:<sup>[[7]](#references)</sup>

1. Fai l'inventario delle sezioni eseguibili e dei dati, delle rilocazioni e dei riferimenti incrociati. Estrai le tabelle candidate da `.rodata`, preservandone l'ordine dei byte e la larghezza degli elementi.
2. Individua l'ultima routine che scrive il testo in chiaro o il buffer di output. Registra i suoi input, le tabelle a cui fa riferimento, le chiamate importate e lo stato globale richiesto.
3. Esegui il lifting delle sole operazioni necessarie in un modello Python a larghezza fissa. Se la slice dipende ancora da troppo stato, invoca la routine con Unicorn, QEMU o un debugger e intercetta le importazioni irrilevanti invece di emulare l'intero programma.
4. Verifica che l'estrattore ricavi effettivamente il proprio output dal binario fornito: rimuovi i fallback silenziosi, cerca risposte incorporate al suo interno ed eseguilo su build non viste con stringhe, chiavi, identificatori, layout e seed di offuscamento modificati.

Alcuni comandi utili per una prima analisi sono:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Rilevare espressioni MBA che nascondono costanti

Un'espressione a byte apparentemente dipendente dall'input può annullare completamente il proprio input. Dopo aver estratto le tabelle, valutate l'espressione sull'intero dominio a 8 bit: un insieme di output con un solo elemento dimostra che quel byte è costante, senza dover recuperare la macchina a stati circostante.<sup>[[7]](#references)</sup>

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

Mantieni la maschera finale perché l’addizione originale ha un wraparound alla larghezza di un byte. Per un dominio più ampio, chiedi a un solver SMT se `f(x1) != f(x2)` è soddisfacibile per due input simbolici della stessa larghezza: `unsat` dimostra l’invarianza, mentre `sat` fornisce un controesempio e indica che l’input non può essere scartato.<sup>[[7]](#references)</sup>

#### Riconoscere la decodifica vincolata all’ambiente

I controlli anti-analisi non devono necessariamente causare un branch o un crash. Un decoder può mescolare il risultato di un sensore in un bit della chiave, in una costante di opaque predicate o nello stato di un flattened dispatcher, continuare normalmente e produrre testo in chiaro plausibile ma falso in un emulatore. Pertanto, applicare patch solo ai branch di errore visibili non è sufficiente; traccia le dipendenze dei dati dalle sonde ambientali allo stato del decoder, confronta la stessa porzione sul dispositivo autentico e sull’emulatore e verifica in che modo forzare ciascun risultato del sensore modifica il buffer finale.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un pratico semplificatore MBA per l’analisi di malware e il reverse engineering di binari protetti. Classifica l’espressione e la instrada attraverso pipeline specializzate, invece di applicare un unico passaggio di riscrittura generico a tutto.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA valuta l’espressione su input booleani, ricava una signature e mette in competizione diversi metodi di recovery, come il pattern matching, la conversione ANF e l’interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo che le regioni mascherate rimangano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in core e le sottoespressioni ripetute possono essere estratte in temporanei prima di semplificare la relazione esterna.

Esempio di identità mista che spesso vale la pena provare a recuperare:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Questo può ridursi a:

```c
x * y
```

### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR lifted** o sull'output del decompiler, dopo aver isolato il calcolo esatto.
- Usa `--bitwidth` esplicitamente se l'espressione deriva da operazioni aritmetiche con maschere o da registri di larghezza ridotta.
- Se ti serve un passaggio di proof più robusto, consulta le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin LLVM pass** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR con molte operazioni MBA prima dei pass di analisi successivi.
- I residui misti tra domini, non supportati e sensibili al carry, sono un segnale che conviene mantenere l'espressione originale e ragionare manualmente sul percorso del carry.

## Recuperare il control-flow flattening con stato XOR

Un flattener in stile OLLVM può mantenere lo stato del basic block corrente in due registri a 64 bit e ricostruirlo con XOR nel dispatcher. Ogni blocco originale scrive la coppia corrispondente allo stato successivo e salta di nuovo al dispatcher. Un blocco condizionale può usare `CMOVcc` per sostituire una metà della coppia in base ai flag della CPU, quindi seguire solo le istruzioni di branch visibili fa perdere i due successori. A differenza di un dispatcher con indirect jump, questa struttura può usare direct back-edge ovunque.<sup>[[19]](#references)[[20]](#references)</sup>

Per recuperare il grafo, individua l'albero di confronti del dispatcher e i due registri di stato, associa ogni stato XOR confrontato al relativo blocco target, quindi traccia le scritture ai due registri che raggiungono ciascun blocco originale. Per le scritture condizionali, includi l'istruzione che imposta i flag e entrambi i possibili esiti di `CMOVcc`. Riscrivi l'uscita di ogni blocco verso il dispatcher come successor diretto risolto o branch condizionale; così il dispatcher diventa irraggiungibile senza patchare il binario. Questo approccio riguarda l'intero CFG; se ti interessa un solo decoder, il [workflow narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) qui sopra può essere più rapido.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatizza questa struttura in Binary Ninja. Copia `plugins/DispatchThis` nella directory dei plugin utente di Binary Ninja e riavvia. Sulla funzione interessata, apri **Function Settings** e seleziona `OLLVM_XOR_64`; se l'analisi non parte, usa **Analysis → Reanalyze All Functions**. Questa modalità riscrive gli archi di control-flow in MLIL, non i byte del file, e non richiede Z3 né l'indirect-jump resolver. È stato testato con Binary Ninja 5.3.9757+; non rimuove le scritture di stato per blocco ormai inutilizzate, quindi non confonderle con transizioni ancora attive.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione di segnali/eccezioni per modificare il control-flow. Per i dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deoffuscare il risultato. Ha diverse dipendenze.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [installa keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questa soluzione alternativa per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point**, cerca le funzioni tramite `::main`, come in:

![Individuazione di un entry point Rust in Ghidra cercando i nomi delle funzioni con doppio due punti e main](<../../images/image (1080).png>)

In questo caso, il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Una volta ottenuti i **nomi** delle **funzioni** chiamate, cercali su **Internet** per conoscerne gli **input** e gli **output**.

### Recuperare le stringhe Rust dal firmware ELF

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate tramite puntatori terminati da NUL in stile C. Un layout comune di `rustc` consiste in una **coppia puntatore/lunghezza** all'interno di **`.data.rel.ro`**, che punta alla stringa effettiva archiviata in **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Questo significa che `strings` o l’analisi predefinita di Ghidra potrebbero unire stringhe adiacenti o non rilevare affatto i riferimenti incrociati.<sup>[[3]](#references)</sup>

Flusso di lavoro rapido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ottieni l’indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una word alla volta.
3. Considera ogni valore compreso nell’intervallo di indirizzi di `.rodata` come un potenziale puntatore a stringa.
4. Considera la word successiva come la lunghezza potenziale.
5. Applica dei filtri di plausibilità (per esempio, mantieni le lunghezze comprese tra **4** e **100** byte).
6. Leggi esattamente `length` byte da `.rodata` invece di continuare la scansione fino a `0x00`.

Logica minima dell’estrattore:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Questo è particolarmente utile nel reversing del firmware, perché le stringhe Rust recuperate spesso rivelano **route HTTP, nomi RPC, messaggi di log, asserzioni, nomi di file, chiavi di configurazione, gestori di comandi e logica relativa all’autenticazione**.

Se Ghidra non rileva queste stringhe, esegui uno script o un plugin personalizzato che applica la stessa euristica e crea dati stringa agli offset di `.rodata` a cui si fa riferimento. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono ottimi riferimenti per adattare l’idea ad altre **dimensioni delle parole, endianness e disposizioni delle sezioni**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati con Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti consiglio di usare il plugin per IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

All’avvio del debugging, questo plugin esegue il binario e risolve dinamicamente i nomi delle funzioni. Dopo aver avviato il debugging, premi di nuovo il pulsante Start (quello verde o f9): verrà raggiunto un breakpoint all’inizio del codice effettivo.

Se premi un pulsante nell’applicazione grafica, il debugger può fermarsi nella funzione invocata da quel pulsante.

## Golang

Per i normali binari Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) può recuperare le strutture runtime e migliorare i nomi delle funzioni in IDA. Carica il suo plugin Python con **Alt+F7**.

Se devi fare reversing di un binario Golang, ti consiglio di usare il plugin per IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo risolverà i nomi delle funzioni.

### Recuperare i metadati senza la symbol table

Un eseguibile Go privato dei simboli ha comunque bisogno dei metadati runtime per associare i program counter alle funzioni. [GoReSym](https://github.com/mandiant/GoReSym) individua e analizza strutture come `pclntab` e `moduledata` usando codice derivato dal runtime Go. Può recuperare i limiti delle funzioni, i nomi, i percorsi sorgente, i tipi e i dettagli di build senza fare affidamento sulla symbol table convenzionale.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscator può lasciare utilizzabili queste strutture, sostituendo però i nomi recuperati. Garble, per esempio, esegue l’hashing degli identificatori e dei percorsi dei package e rimuove le informazioni di build, dei moduli e di debug.<sup>[[12]](#references)</sup> Il token offuscato del package deve rimanere coerente tra le funzioni di quel package. Raggruppa le funzioni in base al token ripetuto, deduci un package dalle funzioni chiamate, dalle stringhe e dalle API, poi propaga l’etichetta del package all’intero gruppo.<sup>[[13]](#references)</sup>

### Recuperare i nomi Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina l’estrazione dei simboli runtime con la generazione di riferimenti puliti e il matching dei control-flow graph (CFG). Segui questa procedura:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versione del compilatore.** Prova prima `BuildInfo` e le stringhe di versione incorporate. Se l’obfuscator le ha rimosse, confronta parti del runtime Go incluso con runtime di riferimento associati a versioni specifiche. Nei test di Volexity, circa il `2%` del runtime è stato sufficiente per distinguere le versioni principali di Go. Consideralo un’ottimizzazione basata su risultati empirici, non una soglia universale.<sup>[[13]](#references)</sup>
2. **Crea riferimenti corrispondenti.** Genera binari puliti per la versione di Go identificata, l’architettura di destinazione e le librerie probabili. Usare una toolchain corrispondente riduce le differenze nei CFG generati dal compilatore.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Confronta le funzioni.** GoGrapher confronta i CFG delle funzioni e restituisce punteggi normalizzati da `0.0` a `1.0`. Il matching dei basic block si basa su un confronto ponderato delle istruzioni simili. Le corrispondenze con elevata affidabilità associano le funzioni randomizzate all’implementazione pulita. Anche le corrispondenze meno affidabili possono identificare un package o un modulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Convalida e importa.** Conferma i nomi proposti usando le relazioni tra le chiamate, le costanti, le stringhe e gli effetti collaterali, quindi importa il report JSON con il plugin GoResolver per IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installa la toolchain ed esegui l’estrattore e il graph matcher combinati:<sup>[[10]](#references)</sup>

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

La soglia predefinita per le corrispondenze significative è `0.9`. Le opzioni `--extract` e `--graph` consentono di isolare ciascuna fase, mentre per impostazione predefinita vengono eseguite entrambe, poiché i metadati runtime recuperati e le evidenze del CFG si completano a vicenda.<sup>[[10]](#references)</sup> I punteggi CFG sono euristici: l'inlining, i flag di build, l'architettura e le differenze tra versioni delle librerie possono modificare la struttura del grafo, quindi è preferibile mantenere le funzioni non risolte invece di assegnare nomi con un basso livello di confidenza.<sup>[[13]](#references)</sup>

### Recuperare la tabella delle stringhe Go

I binari Go collocano i byte delle stringhe di ogni package collegato in un'unica tabella contigua. Le voci non sono terminate da NUL e le strutture runtime non espongono la base né la dimensione della tabella. Tuttavia, il compilatore ordina le voci prima per lunghezza e poi alfabeticamente, indipendentemente dal sistema operativo e dall'architettura. Dopo aver individuato una voce, un analista può quindi scorrere le voci adiacenti e usare i riferimenti incrociati ai dati per associare le stringhe al codice.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizza questo flusso di lavoro in IDA Pro e Ghidra. Attendere il completamento dell'auto-analisi, perché il plugin si basa sui riferimenti incrociati dei segmenti dati. L'ancora predefinita è la stringa runtime `entersyscall`; da lì, lo strumento può eseguire la scansione in entrambe le direzioni, definire le stringhe recuperate nel database ed esportare una mappatura JSON delle stringhe e delle funzioni che vi fanno riferimento.<sup>[[14]](#references)</sup>

Filtrare il report in base al package della funzione che fa riferimento alla stringa, per separare il codice dell'applicazione o del malware dal rumore delle librerie collegate. Questa tecnica non può recuperare i literal distrutti da tecniche di offuscamento come la trasformazione `-literals` di Garble. Può comunque organizzare le stringhe runtime rimaste non offuscate.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperare i tipi runtime Go

Go incorpora informazioni sui tipi runtime usate da funzionalità come il garbage collection. Quando le informazioni di build vengono rimosse o il disassembler non analizza questi metadati, le istruzioni possono sembrare caricare indirizzi dati arbitrari e la regione di destinazione rimane priva di tipo. Recuperare i metadati trasforma quegli indirizzi in riferimenti a tipi leggibili e facilita la comprensione delle funzionalità dei package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) può estrarre i simboli e analizzare i tipi runtime, generando un report JSON. La CLI attuale usa il subcommand `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

L'opzione `-y`/`--types` abilita l'analisi dei tipi. Importa il report con il plugin di GoResolver per IDA Pro o Ghidra per definire i tipi recuperati e applicare i relativi riferimenti nel database di analisi. Nel formato del report introdotto con questa funzionalità, se si omette `-y`, i membri relativi all'indirizzo RTTI e ai tipi recuperati restano null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver supporta campioni PE, ELF e Mach-O per x86, AMD64, ARM e ARM64, quindi lo stesso workflow si applica ai binari Go per Windows, Linux e macOS.<sup>[[10]](#references)</sup>

## Python compilato

In questa pagina puoi trovare come ottenere il codice Python da un binario ELF/EXE compilato da Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **binario** di un gioco GBA, puoi usare diversi strumenti per **emularlo** e **debuggarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Include un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Include un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin di Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin di Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **pulsanti** del Game Boy Advance

![Configurazione dei controlli di no$gba con la mappatura dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

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

In quella funzione, dopo alcune operazioni di inizializzazione (non importanti):

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

L'ultimo if verifica che **`uVar4`** sia nell'ultimo Keys e non sia il tasto corrente; in altre parole, indica il rilascio di un pulsante (il tasto corrente è memorizzato in **`uVar1`**).

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

Nel codice precedente puoi vedere che confrontiamo **uVar1** (la variabile che contiene il **valore del pulsante premuto**) con alcuni valori:

- Per prima cosa, viene confrontato con il **valore 4** (pulsante **SELECT**): in questa challenge, questo pulsante cancella lo schermo
- Poi viene confrontato con **8** (il pulsante **START**); in questa challenge, quel percorso verifica se il codice inserito è valido.
  - In questo caso la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore corrisponde, viene eseguito del codice.
- In tutti gli altri casi, viene controllato e incrementato un contatore (`DAT_030000d4`).\
  Finché il contatore è inferiore a 8, i valori dei tasti premuti vengono accumulati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione lunga meno di 8 tasti, la cui somma risultante fosse 0xf3.**

**Riferimento per questo tutorial:** [writeup archiviato della challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deoffuscamento di binari)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository CoBRA di Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificare le stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - stringhe Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reversing GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sconfiggere il reverse engineering assistito dall'IA, o almeno provarci](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Un approccio al confronto dei grafi di flusso di controllo basato sulla corrispondenza dei blocchi di base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repository GoResolver di Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Meccanismo di offuscamento di Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: usare la somiglianza dei grafi di flusso di controllo per deoffuscare automaticamente i binari Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repository GoStringExtractor di Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aggiornamenti agli strumenti Golang di Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: fare reverse engineering di qualsiasi cosa](https://github.com/morluto/rea)
- [17] [Analisi del codice gestito con REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Guida a REA CLI ed Evidence](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: workflow di rimozione del control-flow flattening con Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: intrusione zero-day in PaperCut MF, loader Java, web shell e AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
{{#include ../../banners/hacktricks-training.md}}
