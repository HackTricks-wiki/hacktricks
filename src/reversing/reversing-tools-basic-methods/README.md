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

## Payload virtualizzati e VM personalizzate

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina diversi formati**, tra cui **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio è che, se è necessario ripristinare il codice sorgente mancante a partire da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una comoda navigazione nel codice decompilato, rendendolo uno degli strumenti ideali per l'**analisi degli algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello di add-in completo e a un'API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo i numerosi servizi di reverse engineering offerti da questo strumento:

- Mostra come i dati fluiscono attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'uso dei linguaggi e dei framework .NET
- Trova funzionalità non documentate e non esposte per sfruttare al meglio le API e le tecnologie utilizzate.
- Trova dipendenze e assembly diversi
- Individua la posizione esatta degli errori nel codice, nei componenti di terze parti e nelle librerie.
- Esegue il debugging del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi usarlo su qualsiasi OS (puoi installarlo direttamente da VSCode, senza dover scaricare git. Clicca su **Extensions** e **cerca ILSpy**).\
Se devi **decompilare**, **modificare** e **ricompilare**, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un suo fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic destro -> Modify Method** per modificare qualcosa all'interno di una funzione).

### Logging con DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging con DNSpy

Per eseguire il debug del codice usando DNSpy devi:

Per prima cosa, modifica gli **attributi dell'assembly** relativi al **debugging**:

![DNSpy Logging - Debugging con DNSpy: per prima cosa, modifica gli attributi dell'assembly relativi al debugging](<../../images/image (973).png>)

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

And click on **compila**:

![DNSpy Logging - DNSpy Debugging: E fai clic su compila](<../../images/image (314) (1).png>)

Then save the new file via _**File >> Salva modulo...**_:

![DNSpy Logging - DNSpy Debugging: Quindi salva il nuovo file tramite File Salva modulo](<../../images/image (602).png>)

This is necessary because if you don't do this, at **runtime** several **ottimizzazioni** will be applied to the code and it could be possible that while debugging a **breakpoint is never hit** or some **variabili non esistono**.

Then, if your .NET application is being **eseguita** by **IIS** you can **riavviarla** with:

```
iisreset /noforce
```

Quindi, per iniziare il debugging, chiudi tutti i file aperti e nella scheda **Debug** seleziona **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Quindi, per iniziare il debugging, chiudi tutti i file aperti e nella scheda Debug seleziona Attach to Process](<../../images/image (318).png>)

Seleziona quindi **w3wp.exe** per collegarti al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Seleziona quindi w3wp.exe per collegarti al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, è il momento di fermarlo e caricare tutti i moduli. Fai prima clic su _Debug >> Break All_, quindi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di fermarlo e caricare tutti i moduli. Fai prima clic su Debug Break All, quindi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di fermarlo e caricare tutti i moduli. Fai prima clic su Debug Break All, quindi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il tasto destro su un modulo qualsiasi in **Assembly Explorer** e seleziona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il tasto destro su un modulo qualsiasi in Assembly Explorer e seleziona Sort Assemblies](<../../images/image (339).png>)

## Decompiler Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLL

### Uso di IDA

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- Seleziona il debugger **Windbg**
- Seleziona "**Suspend on library load/unload**"

![Debugging DLL - Uso di IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parametri** di esecuzione specificando il **percorso della DLL** e la funzione che vuoi chiamare:

![Debugging DLL - Uso di IDA: Configura i parametri di esecuzione specificando il percorso della DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Quando avvii il debugging, **l'esecuzione si fermerà al caricamento di ogni DLL**; quindi, quando rundll32 caricherà la tua DLL, l'esecuzione si fermerà.

Questo metodo si ferma agli eventi di caricamento dei moduli, ma raggiungere l'entry point della DLL caricata è meno diretto rispetto al flusso di lavoro con x64dbg descritto di seguito.

### Uso di x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la Command Line** (_File --> Change Command Line_) e imposta il percorso della DLL e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- **Avvia quindi l'esecuzione**: il debugger si fermerà in ogni dll main e, a un certo punto, **si fermerà nell'Entry della tua DLL**. Da lì, cerca i punti in cui vuoi impostare un breakpoint.

Nota che, quando l'esecuzione si ferma per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** guardando la **parte superiore della finestra di win64dbg**:

![Uso di IDA - Uso di x64dbg/x32dbg: Nota che, quando l'esecuzione si ferma per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi guardando la parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma che l'esecuzione si è fermata all'interno della DLL di cui vuoi eseguire il debugging.

## Applicazioni GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per individuare dove vengono salvati in memoria i valori importanti di un gioco in esecuzione e modificarli. Altre informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è uno strumento front-end/reverse engineering per il GNU Project Debugger (GDB), dedicato ai giochi. Tuttavia, può essere usato per qualsiasi attività relativa al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo servizio web consente di confrontare l'output di diversi decompiler su piccoli eseguibili.

## ARM e MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugging di shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca la **shellcode**, ne stampa l'**indirizzo di memoria** e mette in pausa l'esecuzione.\
Collegati con un debugger come IDA o x64dbg, imposta un breakpoint all'indirizzo stampato e riprendi l'esecuzione per eseguire il debugging della shellcode.

La pagina delle release su GitHub contiene archivi ZIP con le release compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, **crea un progetto C/C++ in Visual Studio Code, copia e incolla il codice e compilalo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging di shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca la shellcode ed entra in un loop infinito. Collegati al debugger, riprendi l'esecuzione per **2–5 secondi**, metti in pausa all'interno del loop e avanza fino alla chiamata successiva che trasferisce l'esecuzione alla shellcode allocata.

![Debugger in pausa nel loop infinito di jmp2it, subito prima della chiamata alla shellcode allocata](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it dalla pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Debugging di shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Con Cutter puoi emulare la shellcode e analizzarla dinamicamente.

Nota che Cutter consente di scegliere "Open File" e "Open Shellcode". Nel mio caso, aprendo la shellcode come file l'ha decompilata correttamente, mentre aprendola come shellcode non ci è riuscito:

![Cutter mostra risultati di analisi diversi quando gli stessi byte vengono aperti come file o come shellcode](<../../images/image (562).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp in quel punto; a quanto pare, Cutter avvierà automaticamente l'emulazione da lì:

![Impostazione di un breakpoint all'entry point desiderato della shellcode prima di avviare l'emulazione di Cutter](<../../images/image (589).png>)

![L'emulatore di Cutter è in pausa sul breakpoint selezionato nella shellcode](<../../images/image (387).png>)

Puoi visualizzare, ad esempio, lo stack in un hex dump:

![Visualizzazione dello stack della shellcode emulata nell'hex dump di Cutter](<../../images/image (186).png>)

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

L’opzione **Create Dump** salva lo shellcode finale se viene apportata una modifica dinamica allo shellcode in memoria (utile per scaricare lo shellcode decodificato). L’opzione **start offset** può essere utile per avviare lo shellcode da un offset specifico. L’opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, per questo scopo trovo migliori le opzioni spiegate in precedenza, perché permettono di usare Ida o x64dbg).

### Disassemblare usando CyberChef

Carica il file dello shellcode come input e usa la seguente ricetta per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deoffuscamento di MBA

L’offuscamento **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). L’aspetto importante è che queste identità sono generalmente corrette solo con l’**aritmetica modulare a larghezza fissa**, quindi riporti e overflow sono rilevanti:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Se semplifichi questo tipo di espressione con strumenti di algebra generici, puoi facilmente ottenere un risultato errato perché la semantica dell'ampiezza in bit è stata ignorata.<sup>[[1]](#references)</sup>

### Flusso di lavoro pratico

1. **Mantieni l'ampiezza in bit originale** del codice/IR/output del decompiler (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
   - **Lineare**: somme ponderate di atomi bitwise
   - **Semilineare**: espressione lineare più maschere costanti come `x & 0xFF`
   - **Polinomiale**: sono presenti prodotti
   - **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una prova SMT. Se non è possibile dimostrarne l'equivalenza, mantieni l'espressione originale invece di tirare a indovinare.

### Bypass del flusso di controllo appiattito con uno slice di esecuzione ristretto

Spesso non è necessario ricostruire l'intero grafo del flusso di controllo. Con control-flow flattening, opaque predicate, dispatcher di grandi dimensioni o codice con molto MBA, segui i riferimenti dai blob cifrati e dai buffer di output fino alla routine più piccola che li trasforma. Poi riproduci solo quello slice del flusso dei dati oppure eseguilo autonomamente; il dispatcher non è necessario per la soluzione se è possibile inizializzare direttamente lo stato rilevante.<sup>[[7]](#references)</sup>

Un flusso di lavoro pratico è:<sup>[[7]](#references)</sup>

1. Fai l'inventario delle sezioni eseguibili e dei dati, delle rilocazioni e dei riferimenti incrociati. Estrai le tabelle candidate da `.rodata`, preservandone l'ordine dei byte e l'ampiezza degli elementi.
2. Individua l'ultima routine che scrive il testo in chiaro o il buffer di output. Registra i suoi input, le tabelle a cui fa riferimento, le chiamate importate e lo stato globale necessario.
3. Trasponi solo quelle operazioni in un modello Python ad ampiezza fissa. Se lo slice dipende ancora da troppo stato, richiama la routine con Unicorn, QEMU o un debugger e intercetta le importazioni irrilevanti invece di emulare l'intero programma.
4. Verifica che l'estrattore ricavi effettivamente il suo output dal binario fornito: rimuovi i fallback silenziosi, cerca al suo interno risposte incorporate ed eseguilo su build non viste con stringhe, chiavi, identificatori, layout e seed di offuscamento diversi.

I comandi utili per una prima analisi sono:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Rilevare espressioni MBA che mascherano costanti

Un'espressione a byte apparentemente dipendente dall'input può annullare completamente il proprio input. Dopo aver estratto le tabelle, valuta l'espressione sull'intero dominio a 8 bit; un insieme di output con un solo elemento dimostra che il byte è costante, senza dover recuperare la state machine circostante.<sup>[[7]](#references)</sup>

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

Mantieni la maschera finale perché l'addizione originale ha un wraparound a larghezza di byte. Per un dominio più ampio, chiedi a un solver SMT se `f(x1) != f(x2)` è soddisfacibile per due input simbolici della stessa larghezza: `unsat` dimostra l'invarianza, mentre `sat` fornisce un controesempio e significa che l'input non può essere scartato.<sup>[[7]](#references)</sup>

#### Riconoscere la decodifica vincolata all'ambiente

I controlli anti-analisi non devono necessariamente causare un branch o un crash. Un decoder può combinare il risultato di un sensore con un bit della chiave, una costante di opaque predicate o lo stato di un dispatcher appiattito, continuare normalmente e produrre plaintext plausibile ma errato in un emulatore. Pertanto, applicare patch solo ai branch di errore visibili non è sufficiente: traccia le dipendenze dei dati dalle sonde dell'ambiente allo stato del decoder, confronta la stessa porzione sul dispositivo autentico e sull'emulatore, e verifica come forzare il risultato di ciascun sensore modifichi il buffer finale.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l'analisi del malware e il reversing di binari protetti. Classifica l'espressione e la instrada attraverso pipeline specializzate, invece di applicare un'unica passata di riscrittura generica a tutto.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA valuta l’espressione su input booleani, ne ricava una firma e mette in competizione diversi metodi di recupero, come il pattern matching, la conversione ANF e l’interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo da mantenere corrette le regioni mascherate.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in nuclei e le sottoespressioni ripetute possono essere trasferite in variabili temporanee prima di semplificare la relazione esterna.

Esempio di un’identità mista che spesso vale la pena provare a recuperare:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Questo può ridursi a:

```c
x * y
```

### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR lifted** o sull’output del decompiler, dopo aver isolato il calcolo esatto.
- Usa esplicitamente `--bitwidth` quando l’espressione deriva da aritmetica con maschere o da registri di larghezza ridotta.
- Se ti serve una dimostrazione più solida, consulta qui le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin pass di LLVM** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR ricco di MBA prima di eseguire pass di analisi successive.
- I residui misti tra domini, sensibili al carry e non supportati, vanno considerati un segnale per mantenere l’espressione originale e analizzare manualmente il percorso del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione dei segnali e delle eccezioni per alterare il flusso di controllo. Per i dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deoffuscare il risultato. Ha diverse dipendenze.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

And [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai partecipando a un **CTF, questo workaround per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare il **punto di ingresso**, cerca le funzioni usando `::main`, come in:

![Individuare un punto di ingresso Rust in Ghidra cercando i nomi delle funzioni con doppio due punti e main](<../../images/image (1080).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Una volta ottenuti i **nomi** delle **funzioni** chiamate, cercale su **Internet** per scoprire quali sono i loro **input** e **output**.

### Recuperare le stringhe Rust dal firmware ELF

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate da puntatori terminati con NUL in stile C. Un layout comune di `rustc` è una **tupla puntatore/lunghezza** dentro **`.data.rel.ro`**, che punta al blob di stringhe effettivo memorizzato in **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Questo significa che `strings` o l’analisi predefinita di Ghidra potrebbero unire stringhe adiacenti o non rilevare affatto i cross-reference.<sup>[[3]](#references)</sup>

Workflow rapido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Ottieni l’indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una word alla volta.
3. Considera qualsiasi valore compreso nell’intervallo di indirizzi di `.rodata` come un possibile puntatore a una stringa.
4. Considera la word successiva come la possibile lunghezza.
5. Applica filtri di plausibilità (ad esempio, mantieni le lunghezze comprese tra **4** e **100** byte).
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

Questo è particolarmente utile nel reversing del firmware, perché le stringhe Rust recuperate spesso rivelano **route HTTP, nomi RPC, messaggi di log, asserzioni, nomi di file, chiavi di configurazione, gestori di comandi e logica relativa all'autenticazione**.

Se Ghidra non individua queste stringhe, esegui uno script/plugin personalizzato che applica la stessa euristica e crea dati stringa agli offset `.rodata` a cui fanno riferimento. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono utili come riferimento per adattare l'idea ad altri **word size, ordini dei byte e layout delle sezioni**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati con Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti consiglio di usare il plugin per IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni all'avvio del debugging. Dopo aver avviato il debugging, premi di nuovo il pulsante Start (quello verde, oppure f9) e verrà raggiunto un breakpoint all'inizio del codice effettivo.

Se premi un pulsante nell'applicazione grafica, il debugger può fermarsi nella funzione invocata da quel pulsante.

## Golang

Per i normali binari Go, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) può recuperare le strutture runtime e migliorare i nomi delle funzioni in IDA. Carica il suo plugin Python con **Alt+F7**.

### Recuperare i metadati senza la tabella dei simboli

Un eseguibile Go stripped ha comunque bisogno dei metadati runtime per associare i program counter alle funzioni. [GoReSym](https://github.com/mandiant/GoReSym) individua e analizza strutture come `pclntab` e `moduledata` usando codice derivato dal runtime Go. Può recuperare limiti delle funzioni, nomi, percorsi dei sorgenti, tipi e dettagli della build senza fare affidamento sulla normale tabella dei simboli.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscator può lasciare utilizzabili queste strutture sostituendo i nomi recuperati. Garble, per esempio, applica hash agli identificatori e ai percorsi dei package e rimuove le informazioni di build, dei moduli e di debug.<sup>[[12]](#references)</sup> Il token del package offuscato deve rimanere coerente tra le funzioni di quel package. Raggruppa le funzioni in base al token ripetuto, deduci un package dai suoi callees, dalle stringhe e dalle API, quindi propaga l'etichetta del package all'intero gruppo.<sup>[[13]](#references)</sup>

### Recuperare i nomi di Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina l'estrazione dei simboli runtime con la generazione di riferimenti non offuscati e il confronto dei control-flow graph (CFG). Segui questa sequenza:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versione del compilatore.** Prova prima `BuildInfo` e le stringhe di versione incorporate. Se l'obfuscator le ha rimosse, confronta parti del runtime Go incluso con runtime di riferimento associati alle diverse versioni. Nei test di Volexity, circa il `2%` del runtime è bastato a distinguere le versioni principali di Go. Consideralo un'ottimizzazione empirica, non una soglia universale.<sup>[[13]](#references)</sup>
2. **Crea riferimenti corrispondenti.** Genera binari non offuscati per la versione di Go identificata, l'architettura target e le librerie probabili. La corrispondenza della toolchain riduce le differenze nei CFG generati dal compilatore.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Confronta le funzioni.** GoGrapher confronta i CFG delle funzioni e produce punteggi normalizzati da `0.0` a `1.0`. Il confronto dei basic block si basa su una comparazione ponderata di istruzioni simili. Le corrispondenze ad alta affidabilità associano le funzioni con nomi casuali all'implementazione non offuscata. Le corrispondenze meno affidabili possono comunque identificare un package o un modulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Convalida e importa.** Verifica i nomi proposti usando le relazioni tra chiamate, le costanti, le stringhe e gli effetti collaterali, quindi importa il report JSON con il plugin GoResolver per IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Installa la toolchain ed esegui l'estrattore e il graph matcher combinati:<sup>[[10]](#references)</sup>

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

The default significant-match threshold is `0.9`. Gli switch `--extract` e `--graph` possono isolare ciascuna fase, mentre per impostazione predefinita vengono eseguite entrambe, poiché i metadati runtime recuperati e le prove del CFG si completano a vicenda.<sup>[[10]](#references)</sup> I punteggi del CFG sono euristici: l’inlining, i flag di compilazione, l’architettura e le differenze tra versioni delle librerie possono modificare la struttura del grafo, quindi conserva le funzioni irrisolte invece di assegnare nomi con un basso livello di confidenza.<sup>[[13]](#references)</sup>

## Python compilato

In questa pagina puoi scoprire come ottenere il codice Python da un binario ELF/EXE compilato da Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **binario** di un gioco GBA, puoi usare diversi strumenti per **emularlo** e fare **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione di debug_) - Include un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Include un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin per Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin per Ghidra

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

Quindi, in questo tipo di programma, la parte interessante sarà **come il programma gestisce l'input dell'utente**. All'indirizzo **0x4000130** troverai la funzione comunemente presente: **KEYINPUT**.

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

L'ultimo if verifica che **`uVar4`** sia nell'ultimo Keys e non sia la chiave corrente, ovvero che sia stato rilasciato un pulsante (la chiave corrente è memorizzata in **`uVar1`**).

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

- Per prima cosa, viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge questo pulsante cancella lo schermo
- Poi il valore viene confrontato con **8** (il pulsante **START**); in questa challenge, quel percorso verifica se il codice inserito è valido.
  - In questo caso, la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore coincide, viene eseguito del codice.
- In tutti gli altri casi, viene verificato e incrementato un contatore (`DAT_030000d4`).\
  Finché il contatore è inferiore a 8, i valori dei tasti premuti vengono accumulati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione di lunghezza inferiore a 8 la cui somma risultante fosse 0xf3.**

**Riferimento per questo tutorial:** [writeup archiviato della challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deoffuscamento di binari)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository CoBRA di Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificare le stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - stringhe Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reversing GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sconfiggere il reverse engineering assistito dall'IA, o almeno provarci](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Un approccio al confronto dei grafi di flusso di controllo basato sulla corrispondenza dei blocchi di base](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [GoReSym di Mandiant](https://github.com/mandiant/GoReSym)
- [10] [GoResolver di Volexity](https://github.com/volexity/GoResolver)
- [11] [GoGrapher di Volexity](https://github.com/volexity/GoGrapher)
- [12] [Meccanismo di offuscamento Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: usare la similarità dei grafi di flusso di controllo per deoffuscare automaticamente i binari Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
