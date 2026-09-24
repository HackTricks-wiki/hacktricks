# Strumenti di reversing e metodi di base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

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

Il vantaggio è che, se è necessario ripristinare il codice sorgente perduto da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una comoda navigazione all'interno del codice decompilato, rendendolo uno degli strumenti ideali per l'**analisi degli algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello completo di add-in e a un'API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Diamo un'occhiata alla vasta gamma di servizi di reverse engineering offerti da questo strumento:

- Fornisce una panoramica del flusso dei dati attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'utilizzo dei linguaggi e dei framework .NET
- Individua funzionalità non documentate e non esposte per ottenere il massimo dalle API e dalle tecnologie utilizzate.
- Individua le dipendenze e i diversi assembly
- Individua la posizione esatta degli errori nel codice, nei componenti di terze parti e nelle librerie.
- Esegue il debug del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) e [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi utilizzarlo su qualsiasi sistema operativo (puoi installarlo direttamente da VSCode, senza dover scaricare git. Fai clic su **Extensions** e **cerca ILSpy**).\
Se devi **decompilare**, **modificare** e **ricompilare**, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic destro -> Modify Method** per modificare qualcosa all'interno di una funzione).

### Logging di DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugging con DNSpy

Per eseguire il debugging del codice usando DNSpy è necessario:

Innanzitutto, modificare gli **Assembly attributes** relativi al **debugging**:

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

![DNSpy Logging - DNSpy Debugging: E fai clic su compile](<../../images/image (314) (1).png>)

Quindi salva il nuovo file tramite _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Quindi salva il nuovo file tramite File Save module](<../../images/image (602).png>)

Questo è necessario perché, se non lo fai, durante il **runtime** verranno applicate diverse **ottimizzazioni** al codice e potrebbe accadere che durante il debugging un **break-point non venga mai raggiunto** o che alcune **variabili non esistano**.

Quindi, se la tua applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:
```
iisreset /noforce
```
Quindi, per iniziare il debugging dovresti chiudere tutti i file aperti e, all'interno della **Debug Tab**, selezionare **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Quindi, per iniziare il debugging dovresti chiudere tutti i file aperti e, all'interno della Debug Tab, selezionare Attach to Process](<../../images/image (318).png>)

Seleziona quindi **w3wp.exe** per effettuare l'attach al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Seleziona quindi w3wp.exe per effettuare l'attach al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo facendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Per prima cosa fai clic su _Debug >> Break All_ e poi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo facendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Per prima cosa fai clic su Debug Break All e poi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo facendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Per prima cosa fai clic su Debug Break All e poi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il pulsante destro del mouse su un modulo qualsiasi in **Assembly Explorer** e fai clic su **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il pulsante destro del mouse su un modulo qualsiasi in Assembly Explorer e fai clic su Sort Assemblies](<../../images/image (339).png>)

## Decompiler Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging delle DLL

### Utilizzando IDA

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- Seleziona il debugger **Windbg**
- Seleziona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parametri** dell'esecuzione inserendo il **percorso della DLL** e la funzione che vuoi chiamare:

![Debugging DLLs - Using IDA: Configura i parametri dell'esecuzione inserendo il percorso della DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Quindi, quando inizi il debugging, **l'esecuzione verrà arrestata ogni volta che viene caricata una DLL**; quando rundll32 caricherà la tua DLL, l'esecuzione verrà arrestata.

Questo metodo si arresta in corrispondenza degli eventi di caricamento dei moduli, ma raggiungere l'entry point della DLL caricata è meno diretto rispetto al workflow con x64dbg illustrato di seguito.

### Utilizzando x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la Command Line** ( _File --> Change Command Line_ ) e imposta il percorso della dll e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- Quindi **avvia l'esecuzione**; il debugger si arresterà in corrispondenza di ogni dll main e, a un certo punto, **si arresterà nell'Entry della dll**. Da lì, cerca semplicemente i punti in cui vuoi inserire un breakpoint.

Nota che quando l'esecuzione viene arrestata per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** osservando la **parte superiore della finestra di win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Nota che quando l'esecuzione viene arrestata per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi osservando la parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma quando l'esecuzione è stata arrestata all'interno della DLL di cui vuoi eseguire il debugging.

## App GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati nella memoria i valori importanti di un gioco in esecuzione e modificarli. Ulteriori informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è un front-end/tool di reverse engineering per il GNU Project Debugger (GDB), incentrato sui giochi. Tuttavia, può essere utilizzato per qualsiasi attività correlata al reverse engineering

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo servizio web consente di confrontare l'output di diversi decompiler su piccoli eseguibili.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Debugging di una shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca la **shellcode**, stampa il suo **indirizzo di memoria** e mette in pausa l'esecuzione.\
Effettua l'attach con un debugger come IDA o x64dbg, imposta un breakpoint sull'indirizzo stampato e riprendi l'esecuzione per eseguire il debugging della shellcode.

La pagina github delle release contiene archivi zip con le release compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner nel seguente link. Per compilarla, **crea semplicemente un progetto C/C++ in Visual Studio Code, copia e incolla il codice ed esegui la build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging di una shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca la shellcode ed entra in un loop infinito. Effettua l'attach con il debugger, riprendi l'esecuzione per **2–5 secondi**, metti in pausa all'interno del loop e fai step fino alla chiamata successiva che trasferisce l'esecuzione alla shellcode allocata.

![Debugger in pausa nel loop infinito di jmp2it, immediatamente prima della chiamata alla shellcode allocata](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Debugging della shellcode utilizzando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Utilizzando Cutter puoi emulare la shellcode ed esaminarla dinamicamente.

Nota che Cutter permette di "Open File" e "Open Shellcode". Nel mio caso, quando ho aperto la shellcode come file, l'ha decompilata correttamente, mentre quando l'ho aperta come shellcode non l'ha fatto:

![Cutter che mostra risultati di analisi diversi quando apre gli stessi byte come file o come shellcode](<../../images/image (562).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp in quel punto; apparentemente Cutter avvierà automaticamente l'emulazione da lì:

![Impostazione di un breakpoint all'entry point desiderato della shellcode prima di avviare l'emulazione di Cutter](<../../images/image (589).png>)

![Emulatore di Cutter in pausa sul breakpoint selezionato della shellcode](<../../images/image (387).png>)

Ad esempio, puoi visualizzare lo stack all'interno di un hex dump:

![Visualizzazione dello stack della shellcode emulata nell'hex dump di Cutter](<../../images/image (186).png>)

### Deoffuscare la shellcode e ottenere le funzioni eseguite

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà informazioni come **quali funzioni** utilizza la shellcode e se la shellcode si sta **decodificando** in memoria.
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

L'opzione **Create Dump** esegue il dump dello shellcode finale se lo shellcode viene modificato dinamicamente in memoria (utile per scaricare lo shellcode decodificato). Lo **start offset** può essere utile per avviare lo shellcode a un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, per questo scopo, trovo migliori le opzioni spiegate in precedenza, poiché potrai usare Ida o x64dbg).

### Disassemblaggio usando CyberChef

Carica il file dello shellcode come input e usa la seguente recipe per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deobfuscation dell'obfuscation MBA

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). L'aspetto importante è che queste identità sono generalmente corrette solo nell'ambito dell'**aritmetica modulare a larghezza fissa**, quindi carry e overflow sono importanti:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se semplifichi questo tipo di espressione con strumenti di algebra generica, puoi facilmente ottenere un risultato errato perché la semantica della bit-width è stata ignorata.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la bit-width originale** derivata dal codice/IR/decompiler (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
- **Lineare**: somme pesate di atomi bitwise
- **Semilineare**: lineare più maschere costanti come `x & 0xFF`
- **Polinomiale**: sono presenti prodotti
- **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni possibile riscrittura** con test casuali o una dimostrazione SMT. Se l'equivalenza non può essere dimostrata, mantieni l'espressione originale invece di fare supposizioni.

### Aggira il control-flow flattening con una narrow execution slice

Recuperare il grafo completo del flusso di controllo è spesso inutile. Con control-flow flattening, opaque predicates, dispatcher di grandi dimensioni o codice ricco di MBA, segui i riferimenti dai blob cifrati e dai buffer di output fino alla routine più piccola che li trasforma. Quindi riproduci solo quella data-flow slice oppure eseguila indipendentemente; il dispatcher non fa parte della soluzione necessaria se lo stato rilevante può essere inizializzato direttamente.<sup>[[7]](#references)</sup>

Un workflow pratico è:<sup>[[7]](#references)</sup>

1. Inventaria le sezioni eseguibili e dati, le relocation e i cross-reference. Esegui il dump delle tabelle candidate da `.rodata`, preservandone l'ordine dei byte e la dimensione degli elementi.
2. Identifica l'ultima routine che scrive il plaintext o il buffer di output. Registra i suoi input, le tabelle referenziate, le chiamate importate e lo stato globale richiesto.
3. Solleva solo quelle operazioni in un modello Python a larghezza fissa. Se la slice dipende ancora da troppo stato, invoca la routine con Unicorn, QEMU o un debugger e fai hook degli import irrilevanti invece di emulare l'intero programma.
4. Verifica che l'estrattore derivi effettivamente il proprio output dal binary fornito: rimuovi i fallback silenziosi, cerca le risposte incorporate e provalo su build non presenti nel set di addestramento con stringhe, chiavi, identificatori, layout e seed di offuscamento modificati.

Comandi utili per un primo passaggio sono:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Rilevare le espressioni MBA che sono costanti mascherate

Un'espressione di byte apparentemente dipendente dall'input può annullare completamente il proprio input. Dopo aver estratto le relative tabelle, valuta l'espressione sull'intero dominio a 8 bit; un insieme di output con un solo elemento dimostra che quel byte è costante senza dover recuperare la macchina a stati circostante.<sup>[[7]](#references)</sup>
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
Mantieni la maschera finale perché l'addizione originale ha un wraparound alla larghezza del byte. Per un dominio più ampio, chiedi a un SMT solver se `f(x1) != f(x2)` è soddisfacibile per due input simbolici della stessa larghezza: `unsat` dimostra l'invarianza, mentre `sat` fornisce un controesempio e significa che l'input non può essere scartato.<sup>[[7]](#references)</sup>

#### Riconoscere il decoding vincolato all'ambiente

I controlli anti-analisi non devono necessariamente eseguire un branch o causare un crash. Un decoder può combinare il risultato di un sensore in un bit della chiave, in una costante di un opaque predicate o nello stato di un flattened dispatcher, continuare normalmente e produrre un plaintext plausibile ma falso in un emulatore. Pertanto, applicare patch solo ai branch di errore visibili non è sufficiente; traccia le dipendenze dei dati dalle sonde ambientali fino allo stato del decoder, confronta la stessa slice sul dispositivo autentico e sull'emulatore e verifica come la forzatura di ciascun risultato del sensore modifichi il buffer finale.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l'analisi di malware e il reversing di binary protetti. Classifica l'espressione e la instrada attraverso pipeline specializzate invece di applicare un'unica passata di riscrittura generica a tutto.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA valuta l'espressione su input booleani, ricava una signature e mette in competizione diversi metodi di recovery, come il pattern matching, la conversione ANF e l'interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo che le regioni mascherate rimangano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in core e le sottoespressioni ripetute possono essere trasferite in temporanei prima di semplificare la relazione esterna.

Esempio di un'identità mixed che vale comunemente la pena provare a recuperare:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Questo può essere semplificato in:
```c
x * y
```
### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR sollevate** o sull’output del decompiler dopo aver isolato il calcolo esatto.
- Usa esplicitamente `--bitwidth` quando l’espressione proviene da aritmetica con mascheramento o da registri di ampiezza ridotta.
- Se ti serve un passaggio di dimostrazione più forte, consulta le note locali su Z3 qui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA viene fornito anche come **plugin pass di LLVM** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR con molti MBA prima dei successivi pass di analisi.
- I residui misti di domini sensibili al carry non supportati devono essere trattati come un segnale per mantenere l’espressione originale e analizzare manualmente il percorso del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione di segnali/eccezioni per alterare il flusso di controllo. Per i dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deoffuscare il risultato. Ha diverse dipendenze.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questa soluzione alternativa per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point**, cerca le funzioni tramite `::main`, come in:

![Ricerca di un entry point Rust in Ghidra cercando i nomi delle funzioni con main preceduto da due punti](<../../images/image (1080).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Avendo il **nome** delle **funzioni** chiamate, cercale su **Internet** per scoprire i loro **input** e **output**.

### Recupero delle stringhe Rust dal firmware ELF

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate come puntatori con terminazione NUL in stile C. Un layout comune di `rustc` è una **tupla puntatore/lunghezza** all'interno di **`.data.rel.ro`** che punta al vero blocco di stringhe memorizzato in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Ciò significa che `strings` o l'analisi predefinita di Ghidra potrebbero unire stringhe adiacenti o non rilevare completamente i riferimenti incrociati.<sup>[[3]](#references)</sup>

Flusso di lavoro rapido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Ottieni l'indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una word alla volta.
3. Considera qualsiasi valore nell'intervallo di indirizzi di `.rodata` come un potenziale puntatore a una stringa.
4. Considera la word successiva come la potenziale lunghezza.
5. Applica filtri di validità (ad esempio, mantieni le lunghezze comprese tra **4** e **100** byte).
6. Leggi esattamente `length` byte da `.rodata` invece di eseguire la scansione fino a `0x00`.

Logica minima dell'estrattore:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Questo è particolarmente utile nel firmware reversing perché le stringhe Rust recuperate spesso rivelano **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers e auth-related logic**.

Se Ghidra non individua queste stringhe, esegui uno script/plugin personalizzato che applichi la stessa euristica e crei dati stringa agli offset `.rodata` referenziati. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono buoni riferimenti per adattare l'idea ad altri **word sizes, endianness e section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti suggerisco di usare il plugin di IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni all'avvio del debugging. Dopo aver avviato il debugging, premi nuovamente il pulsante Start (quello verde o f9) e un breakpoint verrà raggiunto all'inizio del codice reale.

Se premi un pulsante nell'applicazione grafica, il debugger può fermarsi nella funzione invocata da quel pulsante.

## Golang

Se devi fare reversing di un binario Golang, ti suggerisco di usare il plugin di IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo risolverà i nomi delle funzioni.

## Python compilato

In questa pagina puoi trovare come ottenere il codice Python da un binario ELF/EXE Python compilato:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **binario** di un gioco GBA, puoi usare diversi strumenti per **emularlo** ed eseguirne il **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione per il debug_) - Contiene un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin di Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin di Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **pulsanti** del Game Boy Advance

![configurazione dei controlli di no$gba con la mappatura dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

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
L'ultimo **`if`** verifica che **`uVar4`** sia nell'ultimo Keys e non sia il tasto corrente, operazione chiamata anche rilascio di un pulsante (il tasto corrente è memorizzato in **`uVar1`**).
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
- In questo caso la var **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore è lo stesso, viene eseguito del codice.
- In ogni altro caso, viene controllato e incrementato un contatore (`DAT_030000d4`).\
Finché il contatore è inferiore a 8, i valori dei tasti premuti vengono accumulati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, era necessario **premere una combinazione con una lunghezza inferiore a 8 la cui somma risultante fosse 0xf3.**

**Riferimento per questo tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository CoBRA di Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodifica delle stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reversing GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Sconfiggere il reverse engineering assistito dall'AI, o almeno provarci](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
