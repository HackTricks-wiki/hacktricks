# Strumenti di reversing e metodi di base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automazione di WinDbg in modalità user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Debugging del kernel Windows

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

## Bytecode in cache di Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payload virtualizzati e VM personalizzate

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina diversi formati**, tra cui **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Dopo la decompilazione, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio è che, se è necessario recuperare il codice sorgente perduto da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una pratica navigazione nel codice decompilato, rendendolo uno degli strumenti perfetti per l'**analisi di algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello completo di add-in e a un'API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo i numerosi servizi di reverse engineering offerti da questo strumento:

- Fornisce informazioni sul flusso dei dati attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'uso dei linguaggi e dei framework .NET
- Individua funzionalità non documentate e non esposte per sfruttare meglio le API e le tecnologie utilizzate.
- Individua le dipendenze e i diversi assembly
- Trova la posizione esatta degli errori nel codice, nei componenti di terze parti e nelle librerie.
- Esegue il debugging del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi usarlo su qualsiasi sistema operativo (puoi installarlo direttamente da VSCode, senza dover scaricare git. Fai clic su **Extensions** e **cerca ILSpy**).\
Se devi **decompilare**, **modificare** e **ricompilare**, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un suo fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic destro -> Modify Method** per modificare qualcosa all'interno di una funzione).

### Ispezione di assembly gestiti senza esecuzione con REA

**REA** può esaminare i metadati PE/CLI e il CIL senza caricare l'assembly. Inizia identificando l'artefatto, quindi esamina i membri e i confini nativi dichiarati; questo è utile per analizzare chiamate sospette prima di usare un decompiler o eseguire il programma.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Per il confronto tra versioni, `compare_managed_members` usa l’identità raw di CIL/firma e le impronte delle istruzioni decodificate, invece di considerare stabili i metadata token tra diverse build. Una dichiarazione P/Invoke non dimostra che sia stato eseguito codice nativo; per verificare quel confine, `verify_managed_native_boundaries` richiede riscontri corrispondenti nell’export nativo o nella funzione. Conserva con il risultato l’hash dell’artifact, l’MVID e le associazioni irrisolte.<sup>[[17]](#references)</sup>

### Logging di DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging con DNSpy

Per eseguire il debug del codice usando DNSpy, devi:

Per prima cosa, modifica gli **attributi dell'assembly** relativi al **debugging**:

![Logging di DNSpy - Debugging con DNSpy: per prima cosa, modifica gli attributi dell'assembly relativi al debugging](<../../images/image (973).png>)

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

Quindi salva il nuovo file tramite _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

È necessario perché, se non lo fai, a **runtime** al codice verranno applicate diverse **ottimizzazioni** e, durante il debugging, è possibile che un **breakpoint non venga mai raggiunto** o che alcune **variabili non esistano**.

Poi, se l'applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:

```
iisreset /noforce
```

Poi, per iniziare il debugging, chiudi tutti i file aperti e, nella **scheda Debug**, seleziona **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Poi, per iniziare il debugging, chiudi tutti i file aperti e, nella scheda Debug, seleziona Attach to Process](<../../images/image (318).png>)

Quindi seleziona **w3wp.exe** per collegarti al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Quindi seleziona w3wp.exe per collegarti al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Fai prima clic su _Debug >> Break All_, quindi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Fai prima clic su Debug Break All, quindi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di interromperlo e caricare tutti i moduli. Fai prima clic su Debug Break All, quindi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il tasto destro su un modulo qualsiasi in **Assembly Explorer** e seleziona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il tasto destro su un modulo qualsiasi in Assembly Explorer e seleziona Sort Assemblies](<../../images/image (339).png>)

## Decompiler Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging delle DLL

### Con IDA

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- Seleziona il debugger **Windbg**
- Seleziona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parametri** di esecuzione inserendo il **percorso della DLL** e la funzione che vuoi chiamare:

![Debugging DLLs - Using IDA: Configura i parametri di esecuzione inserendo il percorso della DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Quando avvii il debugging, **l'esecuzione si interromperà ogni volta che viene caricata una DLL**. Quindi, quando rundll32 caricherà la tua DLL, l'esecuzione si interromperà.

Questo metodo si interrompe in corrispondenza degli eventi di caricamento dei moduli, ma raggiungere il punto di ingresso della DLL caricata è meno immediato rispetto al flusso di lavoro con x64dbg descritto di seguito.

### Con x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la Command Line** ( _File --> Change Command Line_ ) e imposta il percorso della DLL e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- Quindi **avvia l'esecuzione**: il debugger si interromperà in ogni dll main e, a un certo punto, **si fermerà nel punto di ingresso della tua DLL**. Da lì, cerca i punti in cui vuoi impostare un breakpoint.

Nota che, quando l'esecuzione si interrompe per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** nella **parte superiore della finestra di win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Nota che, quando l'esecuzione si interrompe per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi nella parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma che l'esecuzione si è interrotta all'interno della DLL di cui vuoi eseguire il debugging.

## App GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati in memoria i valori importanti di un gioco in esecuzione e modificarli. Per maggiori informazioni:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è uno strumento front-end/reverse engineering per il GNU Project Debugger (GDB), pensato per i giochi. Tuttavia, può essere usato per qualsiasi attività legata al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo servizio web consente di confrontare i risultati di diversi decompiler su piccoli eseguibili.

## Analisi nativa supportata da evidenze con REA

**REA** espone l'analisi di Hopper, Ghidra e IDA tramite CLI e MCP. Richiede Node.js 22.x (almeno 22.19), 24.x (almeno 24.11) o 26+, oltre a npm. Configura prima un provider nativo esistente; controlla `rea providers --json` e seleziona esplicitamente un provider se più di uno supporta il target. Al posto di `0x1000` qui sotto, usa il nome o l'indirizzo di una funzione rilevati nell'inventario.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Parti da una stringa o un simbolo relativo a una feature, segui i riferimenti e i chiamanti, poi esamina la scheda della funzione selezionata e il pseudocodice con `rea decompile`. REA associa una sessione al provider selezionato, invece di sostituirlo silenziosamente dopo un errore. Per query ripetibili, `--snapshot PATH` riutilizza solo i byte dell’artefatto, il provider, le impostazioni, l’operazione e i parametri corrispondenti; uno snapshot è una cache locale, non un database del provider salvato. Conserva gli Evidence restituiti e le incognite esplicite, invece di trattare i percorsi dedotti o il testo del decompilatore come codice sorgente originale.<sup>[[16]](#references)[[18]](#references)</sup>

Per gli entry point JavaScript/Electron che portano agli add-on nativi, vedi [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debuggare uno shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca lo **shellcode**, ne stampa l’**indirizzo di memoria** e mette in pausa l’esecuzione.\
Collega un debugger come IDA o x64dbg, imposta un breakpoint all’indirizzo stampato e riprendi l’esecuzione per debuggare lo shellcode.

La pagina GitHub delle release contiene archivi zip con le versioni compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, basta **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debuggare uno shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca lo shellcode ed entra in un loop infinito. Collega il debugger, riprendi per **2–5 secondi**, metti in pausa all’interno del loop e avanza fino alla chiamata successiva che trasferisce l’esecuzione allo shellcode allocato.

![Debugger in pausa nel loop infinito di jmp2it, subito prima della chiamata allo shellcode allocato](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Debuggare uno shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Con Cutter puoi emulare lo shellcode ed esaminarlo dinamicamente.

Tieni presente che Cutter consente di scegliere "Open File" e "Open Shellcode". Nel mio caso, aprendo lo shellcode come file è stato decompilato correttamente, mentre aprendolo come shellcode no:

![Cutter mostra risultati di analisi diversi quando gli stessi byte vengono aperti come file o come shellcode](<../../images/image (562).png>)

Per avviare l’emulazione nel punto desiderato, imposta un bp lì: a quanto pare Cutter avvierà automaticamente l’emulazione da quel punto:

![Impostazione di un breakpoint all’entry point dello shellcode desiderato prima di avviare l’emulazione di Cutter](<../../images/image (589).png>)

![Emulatore di Cutter in pausa al breakpoint selezionato dello shellcode](<../../images/image (387).png>)

Ad esempio, puoi visualizzare lo stack in un hex dump:

![Visualizzazione dello stack dello shellcode emulato nell’hex dump di Cutter](<../../images/image (186).png>)

### Deoffuscare uno shellcode e ottenere le funzioni eseguite

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà cose come **quali funzioni** usa lo shellcode e se si sta **decodificando** in memoria.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg dispone anche di un launcher grafico da cui puoi selezionare le opzioni desiderate ed eseguire lo shellcode

![Launcher grafico di scDbg per selezionare le opzioni di emulazione e tracing dello shellcode](<../../images/image (258).png>)

L'opzione **Create Dump** esegue il dump dello shellcode finale se questo viene modificato dinamicamente in memoria (utile per scaricare lo shellcode decodificato). L'opzione **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, per questo scopo trovo migliori le opzioni spiegate prima, perché ti permettono di usare Ida o x64dbg).

### Disassemblare usando CyberChef

Carica il file dello shellcode come input e usa la seguente ricetta per disassemblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deoffuscazione MBA

L'offuscamento **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). L'aspetto importante è che queste identità sono generalmente corrette solo con l'**aritmetica modulare a larghezza fissa**, quindi carry e overflow sono importanti:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se semplifichi questo tipo di espressione con strumenti algebrici generici, puoi facilmente ottenere un risultato errato perché la semantica della larghezza in bit è stata ignorata.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la larghezza originale in bit** del codice/IR decompilato o trasformato (`8/16/32/64` bit).
2. **Classifica l’espressione** prima di provare a semplificarla:
   - **Lineare**: somme pesate di atomi bitwise
   - **Semilineare**: espressione lineare più maschere costanti come `x & 0xFF`
   - **Polinomiale**: compaiono prodotti
   - **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una dimostrazione SMT. Se non è possibile dimostrare l’equivalenza, mantieni l’espressione originale invece di tirare a indovinare.

### Bypass del flusso di controllo appiattito con una slice di esecuzione ristretta

Spesso non è necessario ricostruire l’intero grafo del flusso di controllo. In presenza di appiattimento del flusso di controllo, predicati opachi, dispatcher di grandi dimensioni o codice ricco di MBA, segui i riferimenti dai blob cifrati e dai buffer di output fino alla routine più piccola che li trasforma. Quindi riproduci solo quella slice del flusso di dati oppure eseguila in modo indipendente; il dispatcher non è necessario per la soluzione se lo stato rilevante può essere inizializzato direttamente.<sup>[[7]](#references)</sup>

Un workflow pratico è:<sup>[[7]](#references)</sup>

1. Elenca le sezioni eseguibili e di dati, le rilocazioni e i riferimenti incrociati. Estrai le tabelle candidate da `.rodata`, preservandone l’ordine dei byte e la larghezza degli elementi.
2. Individua l’ultima routine che scrive il testo in chiaro o il buffer di output. Registra i suoi input, le tabelle a cui fa riferimento, le chiamate importate e lo stato globale necessario.
3. Trasforma solo quelle operazioni in un modello Python a larghezza fissa. Se la slice dipende ancora da uno stato eccessivo, invoca la routine con Unicorn, QEMU o un debugger e intercetta le importazioni irrilevanti invece di emulare l’intero programma.
4. Verifica che l’estrattore ricavi davvero il proprio output dal binario fornito: rimuovi i fallback silenziosi, cerca eventuali risposte incorporate e provalo su build non viste con stringhe, chiavi, identificatori, layout e seed di offuscamento modificati.

Alcuni comandi utili per una prima analisi sono:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Rilevare espressioni MBA che sono costanti mascherate

Un’espressione di byte apparentemente dipendente dall’input può annullare completamente il proprio input. Dopo aver estratto le tabelle, valuta l’espressione sull’intero dominio a 8 bit; un insieme di output con un solo elemento dimostra che quel byte è costante, senza dover ricostruire la macchina a stati circostante.<sup>[[7]](#references)</sup>

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

Mantieni la maschera finale perché l’addizione originale va in overflow alla larghezza di un byte. Per un dominio più ampio, chiedi a un solver SMT se `f(x1) != f(x2)` è soddisfacibile per due input simbolici della stessa larghezza: `unsat` dimostra l’invarianza, mentre `sat` fornisce un controesempio e significa che l’input non può essere scartato.<sup>[[7]](#references)</sup>

#### Riconoscere la decodifica legata all’ambiente

I controlli anti-analisi non devono necessariamente causare un salto o un crash. Un decoder può incorporare il risultato di un sensore in un bit della chiave, in una costante di un opaque predicate o nello stato di un flattened dispatcher, proseguire normalmente e produrre un plaintext plausibile ma falso in un emulatore. Pertanto, applicare patch solo ai rami di errore visibili non è sufficiente: traccia le dipendenze dei dati dalle sonde dell’ambiente allo stato del decoder, confronta la stessa porzione di codice sul dispositivo autentico e sull’emulatore e verifica come la forzatura di ciascun risultato del sensore modifichi il buffer finale.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l’analisi di malware e il reversing di binari protetti. Classifica l’espressione e la instrada attraverso pipeline specializzate invece di applicare a tutto un’unica passata di riscrittura generica.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA valuta l’espressione su input booleani, ricava una firma e mette in competizione diversi metodi di recupero, come il pattern matching, la conversione ANF e l’interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo che le regioni mascherate rimangano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in nuclei e le sottoespressioni ripetute possono essere trasferite in variabili temporanee prima di semplificare la relazione esterna.

Esempio di identità mista che spesso vale la pena provare a recuperare:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Questo può ridursi a:

```c
x * y
```

### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR sollevate** o sull'output del decompiler dopo aver isolato il calcolo esatto.
- Usa `--bitwidth` in modo esplicito quando l'espressione deriva da aritmetica con maschere o da registri di larghezza ridotta.
- Se ti serve un passaggio di dimostrazione più robusto, consulta qui le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin LLVM pass** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR ricco di MBA prima di eseguire ulteriori passaggi di analisi.
- I residui misti tra domini sensibili ai carry e non supportati vanno considerati un segnale per mantenere l'espressione originale e ragionare manualmente sul percorso dei carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione di segnali/eccezioni per alterare il flusso di controllo. Per i dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deoffuscare il risultato. Ha diverse dipendenze.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [installa keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai partecipando a un **CTF, questo metodo alternativo per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point**, cerca le funzioni con `::main`, come in:

![Individuare un entry point Rust in Ghidra cercando i nomi delle funzioni con due punti doppi seguiti da main](<../../images/image (1080).png>)

In questo caso, il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Conoscendo i **nomi** delle **funzioni** chiamate, cercale su **Internet** per scoprirne gli **input** e gli **output**.

### Recuperare stringhe Rust dal firmware ELF

Nei binari **ELF Rust**, molte stringhe statiche non sono referenziate tramite puntatori terminati con NUL in stile C. Un layout comune di `rustc` usa una **tupla puntatore/lunghezza** in **`.data.rel.ro`**, che punta al vero blocco di stringhe memorizzato in **`.rodata`**:

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
2. Enumera **`.data.rel.ro`** una parola alla volta.
3. Considera ogni valore compreso nell’intervallo di indirizzi di `.rodata` come un possibile puntatore a una stringa.
4. Considera la parola successiva come la possibile lunghezza.
5. Applica filtri di validità (per esempio, mantieni le lunghezze comprese tra **4** e **100** byte).
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

Se Ghidra non individua queste stringhe, esegui uno script/plugin personalizzato che applica la stessa euristica e crea dati stringa agli offset `.rodata` referenziati. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono ottimi riferimenti per adattare l’idea ad altre **dimensioni delle word, endianness e layout delle sezioni**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati con Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti suggerisco di usare il plugin per IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo plugin esegue il binario e risolve dinamicamente i nomi delle funzioni all’inizio del debugging. Dopo aver avviato il debugging, premi di nuovo il pulsante Start (quello verde o f9) e verrà raggiunto un breakpoint all’inizio del codice effettivo.

Se premi un pulsante nell’applicazione grafica, il debugger può fermarsi nella funzione invocata da quel pulsante.

## Golang

Per i normali binari Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) può recuperare le strutture runtime e migliorare i nomi delle funzioni in IDA. Carica il suo plugin Python con **Alt+F7**.

Se devi fare reversing di un binario Golang, ti suggerisco di usare il plugin per IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo risolverà i nomi delle funzioni.

### Recuperare i metadati senza la tabella dei simboli

Un eseguibile Go stripped ha comunque bisogno dei metadati runtime per associare i program counter alle funzioni. [GoReSym](https://github.com/mandiant/GoReSym) individua e analizza strutture come `pclntab` e `moduledata` usando codice derivato dal runtime Go. In questo modo è possibile recuperare i confini delle funzioni, i nomi, i percorsi sorgente, i tipi e i dettagli della build senza affidarsi alla tabella dei simboli convenzionale.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscator può lasciare utilizzabili queste strutture sostituendo però i nomi recuperati. Garble, ad esempio, esegue l’hashing degli identificatori e dei percorsi dei package e rimuove le informazioni di build, modulo e debug.<sup>[[12]](#references)</sup> Il token del package offuscato deve rimanere coerente tra le funzioni di quel package. Raggruppa le funzioni in base al token ripetuto, deduci un package dai suoi callees, dalle stringhe e dalle API, quindi propaga l’etichetta del package all’intero gruppo.<sup>[[13]](#references)</sup>

### Recuperare i nomi Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina l’estrazione dei simboli runtime con la generazione di riferimenti puliti e il matching dei grafi di flusso di controllo (CFG). Segui questa sequenza:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versione del compilatore.** Prova prima `BuildInfo` e le stringhe di versione incorporate. Se l’obfuscator le ha rimosse, confronta parti del runtime Go incluso con runtime di riferimento associati alle versioni. Nei test di Volexity, circa il `2%` del runtime è bastato a distinguere le versioni principali di Go. Consideralo un’ottimizzazione empirica, non una soglia universale.<sup>[[13]](#references)</sup>
2. **Prepara riferimenti compatibili.** Genera binari puliti per la versione di Go identificata, l’architettura di destinazione e le librerie probabili. Usare una toolchain compatibile riduce le differenze nei CFG generati dal compilatore.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Confronta le funzioni.** GoGrapher confronta i CFG delle funzioni e produce punteggi normalizzati da `0.0` a `1.0`. Il matching dei basic block si basa su un confronto pesato di istruzioni simili. I match con un alto livello di confidenza associano le funzioni randomizzate all’implementazione pulita. Anche i match meno affidabili possono identificare un package o un modulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Verifica e importa.** Conferma i nomi proposti tramite le relazioni tra chiamate, le costanti, le stringhe e gli effetti collaterali, quindi importa il report JSON con il plugin GoResolver per IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installa la toolchain ed esegui insieme l’estrattore e il matcher dei grafi:<sup>[[10]](#references)</sup>

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

La soglia predefinita di corrispondenza significativa è `0.9`. Le opzioni `--extract` e `--graph` consentono di isolare una delle due fasi, mentre per impostazione predefinita vengono eseguite entrambe, poiché i metadati runtime recuperati e le evidenze del CFG si completano a vicenda.<sup>[[10]](#references)</sup> I punteggi del CFG sono euristici: l'inlining, i flag di compilazione, l'architettura e le differenze tra versioni delle librerie possono modificare la struttura del grafo, quindi è meglio conservare le funzioni non risolte anziché assegnare nomi con un livello di confidenza basso.<sup>[[13]](#references)</sup>

### Recuperare la tabella di stringhe Go

I binari Go collocano i byte delle stringhe di tutti i package collegati in un'unica tabella contigua. Le voci non sono terminate da NUL e le strutture runtime non espongono la base o la dimensione della tabella. Tuttavia, il compilatore ordina le voci prima per lunghezza e poi alfabeticamente, indipendentemente dal sistema operativo e dall'architettura. Dopo aver trovato una voce, un analista può quindi esaminare le voci adiacenti e usare i riferimenti incrociati ai dati per associare le stringhe al codice.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatizza questo flusso di lavoro in IDA Pro e Ghidra. Attendi che l'auto-analisi sia terminata, perché il plugin si basa sui riferimenti incrociati ai segmenti di dati. L'ancora predefinita è la stringa runtime `entersyscall`; da lì, lo strumento può esaminare entrambe le direzioni, definire nel database le stringhe recuperate ed esportare una mappatura JSON delle stringhe e delle funzioni che le referenziano.<sup>[[14]](#references)</sup>

Filtra il report in base al package della funzione che effettua il riferimento per separare il codice dell'applicazione o del malware dal rumore delle librerie collegate. Questa tecnica non può recuperare i literal eliminati dall'offuscamento, come la trasformazione `-literals` di Garble. Può comunque organizzare le stringhe runtime che sono rimaste non offuscate.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperare i tipi runtime Go

Go incorpora informazioni sui tipi runtime utilizzate da funzionalità come il garbage collection. Quando le informazioni di compilazione vengono rimosse o il disassembler non analizza questi metadati, le istruzioni possono sembrare caricare indirizzi di dati arbitrari e la regione di destinazione rimane senza tipo. Recuperando i metadati, questi indirizzi diventano riferimenti a tipi leggibili e risulta più facile comprendere le capacità dei package.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) può estrarre i simboli e analizzare i tipi runtime per generare un report JSON. La CLI attuale usa il sottocomando `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

L'opzione `-y`/`--types` abilita l'analisi dei tipi. Importa il report con il plugin IDA Pro o Ghidra di GoResolver per definire i tipi recuperati e applicare i relativi riferimenti nel database di analisi. Nel formato del report introdotto con questa funzionalità, se ometti `-y`, i campi RTTI address e recovered-types rimangono null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver supporta campioni PE, ELF e Mach-O per x86, AMD64, ARM e ARM64; lo stesso flusso di lavoro si applica quindi ai binari Go di Windows, Linux e macOS.<sup>[[10]](#references)</sup>

## Python compilato

In questa pagina puoi scoprire come ottenere il codice Python da un binario ELF/EXE compilato da Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **binario** di un gioco GBA, puoi usare diversi strumenti per **emularlo** e **debuggarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Include un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Include un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **pulsanti** del Game Boy Advance

![Configurazione dei controlli di no$gba con la mappatura dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

Quando viene premuto, ogni **tasto ha un valore** che lo identifica:

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

In questa funzione, dopo alcune operazioni di inizializzazione (non importanti):

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

L'ultimo if verifica che **`uVar4`** sia tra le **Keys** precedenti e non sia il tasto corrente: questo corrisponde al rilascio di un pulsante (il tasto corrente è memorizzato in **`uVar1`**).

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

Nel codice precedente puoi vedere che stiamo confrontando **uVar1** (il punto in cui si trova il **valore del pulsante premuto**) con alcuni valori:

- Per prima cosa, viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge questo pulsante cancella lo schermo
- Poi confronta il valore con **8** (pulsante **START**); in questa challenge, quel percorso verifica se il codice inserito è valido.
  - In questo caso, la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore è uguale, viene eseguito del codice.
- In ogni altro caso, viene controllato e incrementato un contatore (`DAT_030000d4`).\
  Finché il contatore è minore di 8, i valori dei tasti premuti vengono accumulati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione di lunghezza inferiore a 8, la cui somma risultante fosse 0xf3.**

**Riferimento per questo tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deoffuscamento dei binari)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Decodificare le stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - stringhe Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reversing per GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sconfiggere il reverse engineering assistito dall'IA, o almeno provarci](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Un approccio al confronto dei grafi di flusso di controllo basato sull'abbinamento dei blocchi base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repository Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Meccanismo di offuscamento Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: usare la somiglianza dei grafi di flusso di controllo per deoffuscare automaticamente i binari Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repository Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: aggiornamenti agli strumenti Golang di Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: reverse engineering di qualsiasi cosa](https://github.com/morluto/rea)
- [17] [Analisi del codice gestito con REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Guida alla CLI e alle prove di REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
