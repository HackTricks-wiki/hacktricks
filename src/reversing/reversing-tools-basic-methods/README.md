# Strumenti di reversing e metodi di base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

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

## Bytecode memorizzato nella cache di Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina diversi formati**, tra cui **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio è che, se è necessario ripristinare il codice sorgente perso partendo da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una pratica navigazione nel codice decompilato, rendendolo uno degli strumenti ideali per l’**analisi di algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello di add-in completo e a un’API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo la vasta gamma di servizi di reverse engineering offerti da questo strumento:

- Mostra come i dati fluiscono attraverso una libreria o un componente
- Fornisce informazioni sull’implementazione e sull’uso dei linguaggi e dei framework .NET
- Trova funzionalità non documentate e non esposte, per sfruttare al meglio le API e le tecnologie utilizzate.
- Individua le dipendenze e i diversi assembly
- Individua la posizione esatta degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
- Esegue il debugging del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi usarlo su qualsiasi sistema operativo (puoi installarlo direttamente da VSCode, senza bisogno di scaricare il repository Git. Fai clic su **Extensions** e **cerca ILSpy**).\
Se hai bisogno di **decompilare**, **modificare** e **ricompilare**, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un suo fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic destro -> Modify Method** per modificare qualcosa all’interno di una funzione).

### Logging di DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging con DNSpy

Per eseguire il debug del codice usando DNSpy, devi:

Per prima cosa, modifica gli **attributi dell'assembly** relativi al **debug**:

![DNSpy Logging - Debugging con DNSpy: per prima cosa, modifica gli attributi dell'assembly relativi al debug](<../../images/image (973).png>)

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

Poi salva il nuovo file tramite _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Poi salva il nuovo file tramite File Save module](<../../images/image (602).png>)

Questo è necessario perché, se non lo fai, in **runtime** verranno applicate al codice diverse **ottimizzazioni** e potrebbe accadere che, durante il debugging, un **break-point non venga mai raggiunto** o che alcune **variabili non esistano**.

Poi, se la tua applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:

```
iisreset /noforce
```

Poi, per iniziare il debugging, chiudi tutti i file aperti e, nella **scheda Debug**, seleziona **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Poi, per iniziare il debugging, chiudi tutti i file aperti e, nella scheda Debug, seleziona Attach to Process](<../../images/image (318).png>)

Poi seleziona **w3wp.exe** per collegarti al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Poi seleziona w3wp.exe per collegarti al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, dobbiamo interromperlo e caricare tutti i moduli. Per prima cosa fai clic su _Debug >> Break All_, poi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, dobbiamo interromperlo e caricare tutti i moduli. Per prima cosa fai clic su Debug Break All, poi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, dobbiamo interromperlo e caricare tutti i moduli. Per prima cosa fai clic su Debug Break All, poi su Debug Windows Modules](<../../images/image (834).png>)

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

![Debugging DLL - Con IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parametri** di esecuzione specificando il **percorso della DLL** e la funzione che vuoi chiamare:

![Debugging DLL - Con IDA: Configura i parametri di esecuzione specificando il percorso della DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Quando avvii il debugging, **l'esecuzione si interromperà ogni volta che viene caricata una DLL**. Quindi, quando rundll32 caricherà la tua DLL, l'esecuzione si interromperà.

Questo metodo si interrompe sugli eventi di caricamento dei moduli, ma raggiungere l'entry point della DLL caricata è meno immediato rispetto al workflow con x64dbg descritto di seguito.

### Con x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la riga di comando** ( _File --> Change Command Line_ ) e specifica il percorso della DLL e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- Poi **avvia l'esecuzione**. Il debugger si interromperà all'entry point di ogni DLL; a un certo punto **si fermerà all'entry point della tua DLL**. Da qui, cerca i punti in cui vuoi impostare un breakpoint.

Nota: quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** guardando **nella parte superiore della finestra di win64dbg**:

![Con IDA - Con x64dbg/x32dbg: Nota: quando l'esecuzione viene interrotta per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi guardando nella parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma che l'esecuzione si è interrotta all'interno della DLL di cui vuoi eseguire il debugging.

## App GUI / videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati in memoria i valori importanti di un gioco in esecuzione e modificarli. Maggiori informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è uno strumento di front-end/reverse engineering per il GNU Project Debugger (GDB), pensato per i giochi. Tuttavia, può essere usato per qualsiasi attività legata al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo servizio web permette di confrontare l'output di diversi decompiler su piccoli eseguibili.

## ARM e MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Eseguire il debugging di uno shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca lo **shellcode**, ne stampa l'**indirizzo di memoria** e mette in pausa l'esecuzione.\
Collegati con un debugger come IDA o x64dbg, imposta un breakpoint all'indirizzo stampato e riprendi l'esecuzione per eseguire il debugging dello shellcode.

La pagina GitHub delle release contiene archivi ZIP con le versioni compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, **crea un progetto C/C++ in Visual Studio Code, copia e incolla il codice e compilalo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Eseguire il debugging di uno shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca lo shellcode ed entra in un loop infinito. Collega il debugger, riprendi l'esecuzione per **2–5 secondi**, mettila in pausa all'interno del loop e avanza fino alla chiamata successiva, che trasferisce l'esecuzione allo shellcode allocato.

![Debugger in pausa nel loop infinito di jmp2it, subito prima della chiamata allo shellcode allocato](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Eseguire il debugging dello shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Con Cutter puoi emulare lo shellcode e analizzarlo dinamicamente.

Nota che Cutter permette di usare "Open File" e "Open Shellcode". Nel mio caso, aprendo lo shellcode come file il decompiler lo ha analizzato correttamente, mentre aprendolo come shellcode non ci è riuscito:

![Cutter mostra risultati di analisi diversi quando gli stessi byte vengono aperti come file o come shellcode](<../../images/image (562).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp lì: a quanto pare Cutter avvierà automaticamente l'emulazione da quel punto:

![Breakpoint impostato all'entry point dello shellcode desiderato prima di avviare l'emulazione di Cutter](<../../images/image (589).png>)

![Emulatore di Cutter in pausa sul breakpoint selezionato nello shellcode](<../../images/image (387).png>)

Puoi visualizzare, ad esempio, lo stack all'interno di un hex dump:

![Stack dello shellcode emulato visualizzato nell'hex dump di Cutter](<../../images/image (186).png>)

### Deoffuscare lo shellcode e individuare le funzioni eseguite

Prova [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti indicherà, ad esempio, **quali funzioni** usa lo shellcode e se si sta **decodificando** in memoria.

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

L'opzione **Create Dump** salva lo shellcode finale se viene apportata una modifica dinamica allo shellcode in memoria (utile per scaricare lo shellcode decodificato). L'opzione **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, trovo che una delle opzioni spiegate prima sia migliore per questo scopo, perché ti permetterà di usare Ida o x64dbg).

### Disassemblare usando CyberChef

Carica il file dello shellcode come input e usa la seguente ricetta per disassemblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deoffuscazione di MBA obfuscation

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). L'aspetto importante è che queste identità sono solitamente corrette solo nell'ambito di un'**aritmetica modulare a larghezza fissa**, quindi i riporti e gli overflow sono rilevanti:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se semplifichi questo tipo di espressione con strumenti algebrici generici, puoi facilmente ottenere un risultato errato perché la semantica della larghezza in bit è stata ignorata.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la larghezza in bit originale** del codice/IR decompilato o sollevato (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
   - **Lineare**: somme pesate di atomi bitwise
   - **Semilineare**: lineare più maschere costanti come `x & 0xFF`
   - **Polinomiale**: sono presenti prodotti
   - **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una prova SMT. Se l'equivalenza non può essere dimostrata, mantieni l'espressione originale invece di fare supposizioni.

### Eludere il flusso di controllo appiattito con uno slice di esecuzione ristretto

Spesso non è necessario ricostruire il grafo completo del flusso di controllo. Con il control-flow flattening, predicati opachi, dispatcher di grandi dimensioni o codice ricco di MBA, segui i riferimenti dai blob cifrati e dai buffer di output fino alla routine più piccola che li trasforma. Poi riproduci solo quello slice del flusso di dati, oppure eseguilo in modo indipendente; il dispatcher non è necessario per la soluzione se lo stato rilevante può essere inizializzato direttamente.<sup>[[7]](#references)</sup>

Un workflow pratico è:<sup>[[7]](#references)</sup>

1. Fai l'inventario delle sezioni eseguibili e dati, delle rilocazioni e dei riferimenti incrociati. Estrai le tabelle candidate da `.rodata`, preservandone l'ordine dei byte e la larghezza degli elementi.
2. Individua l'ultima routine che scrive il testo in chiaro o il buffer di output. Registra i suoi input, le tabelle a cui fa riferimento, le chiamate importate e lo stato globale necessario.
3. Trasponi solo queste operazioni in un modello Python a larghezza fissa. Se lo slice dipende ancora da troppo stato, invoca la routine con Unicorn, QEMU o un debugger e aggancia le importazioni irrilevanti invece di emulare l'intero programma.
4. Verifica che l'estrattore ricavi effettivamente il proprio output dal binario fornito: rimuovi i fallback silenziosi, cerca risposte incorporate e testalo su build non viste con stringhe, chiavi, identificatori, layout e seed di offuscamento diversi.

Comandi utili per una prima analisi sono:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Rilevare le espressioni MBA che nascondono costanti

Un’espressione di byte apparentemente dipendente dall’input può annullare completamente l’input. Dopo aver estratto le tabelle, valuta l’espressione sull’intero dominio a 8 bit; un insieme di output con un solo elemento dimostra che il byte è costante, senza dover ricostruire la state machine circostante.<sup>[[7]](#references)</sup>

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

Mantieni la maschera finale perché l’addizione originale prevede il wraparound della larghezza del byte. Per un dominio più ampio, chiedi a un SMT solver se `f(x1) != f(x2)` è soddisfacibile per due input simbolici della stessa larghezza: `unsat` dimostra l’invarianza, mentre `sat` fornisce un controesempio e significa che l’input non può essere scartato.<sup>[[7]](#references)</sup>

#### Riconoscere la decodifica legata all’ambiente

I controlli anti-analisi non devono necessariamente causare un salto o un crash. Un decoder può incorporare il risultato di un sensore in un bit della chiave, in una costante di opaque predicate o nello stato di un dispatcher appiattito, continuare normalmente e produrre testo in chiaro plausibile ma falso in un emulatore. Pertanto, correggere solo i rami di errore visibili non è sufficiente; traccia le dipendenze dei dati dai probe dell’ambiente allo stato del decoder, confronta lo stesso slice sul dispositivo autentico e sull’emulatore e verifica in che modo forzare il risultato di ciascun sensore modifica il buffer finale.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l’analisi di malware e il reversing di binari protetti. Classifica l’espressione e la instrada attraverso pipeline specializzate, invece di applicare a tutto un’unica riscrittura generica.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA valuta l'espressione su input booleani, ne ricava una signature e mette in competizione diversi metodi di recovery, come pattern matching, conversione ANF e interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo da preservare la correttezza delle regioni mascherate.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in core e le sottoespressioni ripetute possono essere spostate in variabili temporanee prima di semplificare la relazione esterna.

Esempio di identità mista che spesso vale la pena provare a recuperare:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Questo può ridursi a:

```c
x * y
```

### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR sollevate** o sull'output del decompilatore, dopo aver isolato il calcolo esatto.
- Usa `--bitwidth` in modo esplicito quando l'espressione deriva da aritmetica mascherata o da registri di larghezza ridotta.
- Se ti serve una dimostrazione più robusta, consulta qui le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin LLVM pass** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR ricco di MBA prima di eseguire pass di analisi successive.
- I residui misti di domini non supportati e sensibili al riporto sono un segnale che conviene mantenere l'espressione originale e ragionare manualmente sul percorso del riporto.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo offuscatore sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione di segnali/eccezioni per alterare il flusso di controllo. Per i dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deoffuscare il risultato. Ha diverse dipendenze.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

E [installa keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questa soluzione alternativa per trovare la flag** potrebbe esserti molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point**, cerca le funzioni con `::main`, come in:

![Ricerca di un entry point Rust in Ghidra cercando i nomi delle funzioni con due punti doppi seguiti da main](<../../images/image (1080).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Una volta ottenuto il **nome** delle **funzioni** chiamate, cercale su **Internet** per scoprirne gli **input** e gli **output**.

### Recuperare stringhe Rust dal firmware ELF

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate da puntatori con terminazione NUL in stile C. Un layout comune di `rustc` è una **tupla puntatore/lunghezza** all'interno di **`.data.rel.ro`** che punta alla stringa effettiva memorizzata in **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Questo significa che `strings` o l’analisi predefinita di Ghidra possono unire stringhe adiacenti o non rilevare affatto i riferimenti incrociati.<sup>[[3]](#references)</sup>

Flusso di lavoro rapido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ottieni l’indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una parola alla volta.
3. Considera ogni valore compreso nell’intervallo di indirizzi di `.rodata` come un possibile puntatore a una stringa.
4. Considera la parola successiva come la possibile lunghezza.
5. Applica filtri di plausibilità (ad esempio, mantieni le lunghezze comprese tra **4** e **100** byte).
6. Leggi esattamente `length` byte da `.rodata` invece di scansionare fino a `0x00`.

Logica minima dell’estrattore:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Questo è particolarmente utile nel firmware reversing, perché le stringhe Rust recuperate spesso rivelano **route HTTP, nomi RPC, messaggi di log, assertion, nomi di file, chiavi di configurazione, gestori di comandi e logica relativa all'autenticazione**.

Se Ghidra non rileva queste stringhe, esegui uno script/plugin personalizzato che applica la stessa euristica e crea dati stringa agli offset `.rodata` referenziati. Gli strumenti pubblicati `rust-strings` e `RustStrings.py` di Pen Test Partners sono ottimi riferimenti per adattare l'idea ad altre **dimensioni delle parole, endianness e layout delle sezioni**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati con Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti consiglio di usare il plugin per IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo plugin esegue il binario e risolve dinamicamente i nomi delle funzioni all'avvio del debugging. Dopo aver avviato il debugging, premi di nuovo il pulsante Start (quello verde o f9) e verrà raggiunto un breakpoint all'inizio del codice effettivo.

Se premi un pulsante nell'applicazione grafica, il debugger può fermarsi nella funzione richiamata da quel pulsante.

## Golang

Se devi fare reversing di un binario Golang, ti consiglio di usare il plugin per IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo risolverà i nomi delle funzioni.

## Python compilato

In questa pagina puoi scoprire come ottenere il codice Python da un binario ELF/EXE compilato da Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **binario** di un gioco GBA, puoi usare diversi strumenti per **emularlo** e **debuggarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Include un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Include un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin per Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin per Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **pulsanti** del Game Boy Advance

![Configurazione dei controlli di no$gba con le associazioni dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

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

In quella funzione, dopo alcune operazioni di inizializzazione (senza alcuna importanza):

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

L'ultimo if verifica che **`uVar4`** sia tra gli ultimi Keys e non sia il tasto corrente, ovvero che si stia rilasciando un pulsante (il tasto corrente è memorizzato in **`uVar1`**).

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

Nel codice precedente puoi vedere che confrontiamo **uVar1** (dove si trova il **valore del pulsante premuto**) con alcuni valori:

- Per prima cosa, viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge questo pulsante cancella lo schermo.
- Poi confronta il valore con **8** (pulsante **START**); in questa challenge, quel percorso verifica se il codice inserito è valido.
  - In questo caso, la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore coincide, viene eseguito del codice.
- In tutti gli altri casi, viene controllato e incrementato un contatore (`DAT_030000d4`).\
  Finché il contatore è inferiore a 8, i valori dei tasti premuti vengono accumulati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione con una lunghezza inferiore a 8, la cui somma risultante fosse 0xf3.**

**Riferimento per questo tutorial:** [soluzione della challenge Nostalgia archiviata](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Deoffuscamento dei binari)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository CoBRA di Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificare le stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reverse engineering per GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sconfiggere il reverse engineering assistito dall'AI, o almeno provarci](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
