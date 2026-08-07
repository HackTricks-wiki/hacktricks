# Strumenti di reversing e metodi di base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) per **decompilare** da wasm (binario) a wat (testo leggibile)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) per **compilare** da wat a wasm
- puoi anche provare a usare [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) per decompilare

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina diversi formati**, incluse **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio è che, se il codice sorgente perduto deve essere ripristinato da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una comoda navigazione all'interno del codice decompilato, rendendolo uno degli strumenti ideali per l'**analisi degli algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello completo di add-in e a un'API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo la vasta gamma di funzionalità di reverse engineering offerte da questo strumento:

- Fornisce una panoramica del flusso dei dati attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'utilizzo dei linguaggi e dei framework .NET
- Trova funzionalità non documentate e non esposte per ottenere di più dalle API e dalle tecnologie utilizzate.
- Trova dipendenze e assembly diversi
- Individua la posizione esatta degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
- Esegue il debug nel codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy per Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): puoi usarlo su qualsiasi OS (puoi installarlo direttamente da VSCode, senza bisogno di scaricare il git. Fai clic su **Extensions** e **cerca ILSpy**).\
Se devi **decompilare**, **modificare** e **ricompilare** nuovamente, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork di esso mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic destro -> Modify Method** per modificare qualcosa all'interno di una funzione).

### DNSpy Logging

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugging di DNSpy

Per eseguire il debugging del codice usando DNSpy è necessario:

Innanzitutto, modifica gli attributi **Assembly** relativi al **debugging**:

![DNSpy Logging - DNSpy Debugging: Innanzitutto, modifica gli attributi Assembly relativi al debugging](<../../images/image (973).png>)

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

Questo è necessario perché, se non lo fai, durante il **runtime** verranno applicate diverse **ottimizzazioni** al codice e potrebbe accadere che, durante il debugging, un **break-point non venga mai raggiunto** o che alcune **variabili non esistano**.

Quindi, se la tua applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:
```
iisreset /noforce
```
Then, per iniziare il debugging, dovresti chiudere tutti i file aperti e, nella **Debug Tab**, selezionare **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Quindi, per iniziare il debugging, dovresti chiudere tutti i file aperti e, nella Debug Tab, selezionare Attach to Process](<../../images/image (318).png>)

Seleziona quindi **w3wp.exe** per effettuare l'attach al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Seleziona quindi w3wp.exe per effettuare l'attach al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Fai prima clic su _Debug >> Break All_ e poi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Fai prima clic su Debug Break All e poi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Fai prima clic su Debug Break All e poi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il tasto destro su un modulo qualsiasi in **Assembly Explorer** e fai clic su **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il tasto destro su un modulo qualsiasi in Assembly Explorer e fai clic su Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Seleziona il debugger **Windbg**
- Seleziona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Seleziona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parameters** dell'esecuzione inserendo il **path alla DLL** e la funzione che vuoi chiamare:

![Debugging DLLs - Using IDA: Configura i parameters dell'esecuzione inserendo il path alla DLL e la funzione che vuoi chiamare](<../../images/image (704).png>)

Poi, quando inizi il debugging, **l'esecuzione verrà arrestata ogni volta che viene caricata una DLL**; quindi, quando rundll32 caricherà la tua DLL, l'esecuzione verrà arrestata.

Ma come puoi raggiungere il codice della DLL che è stata caricata? Con questo metodo, non so come fare.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) e imposta il path della dll e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- Quindi **avvia l'esecuzione**; il debugger si arresterà a ogni dll main e, a un certo punto, **si arresterà nella dll Entry della tua dll**. Da lì, cerca semplicemente i punti in cui vuoi impostare un breakpoint.

Nota che, quando l'esecuzione viene arrestata per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** osservando la **parte superiore della finestra di win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Nota che, quando l'esecuzione viene arrestata per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi osservando la parte superiore della finestra di win64dbg](<../../images/image (842).png>)

In questo modo puoi vedere quando l'esecuzione è stata arrestata nella dll che vuoi sottoporre a debugging.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati nella memoria i valori importanti di un gioco in esecuzione e modificarli. Maggiori informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è un front-end/reverse engineering tool per il GNU Project Debugger (GDB), focalizzato sui giochi. Tuttavia, può essere utilizzato per qualsiasi attività relativa al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo web service consente di confrontare l'output di diversi decompiler su piccoli eseguibili.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **allochera** la **shellcode** all'interno di uno spazio di memoria, **indicherà** l'**indirizzo di memoria** in cui è stata allocata la shellcode e **arresterà** l'esecuzione.\
Dovrai quindi **effettuare l'attach di un debugger** (Ida o x64dbg) al processo, impostare un **breakpoint all'indirizzo di memoria indicato** e **riprendere** l'esecuzione. In questo modo eseguirai il debugging della shellcode.

La pagina GitHub delle release contiene zip con le release compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, **crea semplicemente un progetto C/C++ in Visual Studio Code, copia e incolla il codice ed esegui la build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è molto simile a blobrunner. **Allocherà** la **shellcode** all'interno di uno spazio di memoria e avvierà un **loop infinito**. Dovrai quindi **effettuare l'attach del debugger** al processo, **avviare l'esecuzione, attendere 2-5 secondi e premere stop**; ti troverai all'interno del **loop infinito**. Passa all'istruzione successiva del loop infinito, poiché sarà una call alla shellcode, e infine ti troverai a eseguire la shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it è molto simile a blobrunner. Allocherà la shellcode all'interno di uno spazio di memoria e avvierà un...](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Usando Cutter puoi emulare la shellcode e analizzarla dinamicamente.

Nota che Cutter consente di utilizzare "Open File" e "Open Shellcode". Nel mio caso, quando ho aperto la shellcode come file, l'ha decompilata correttamente, ma quando l'ho aperta come shellcode non ci è riuscito:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Nota che Cutter consente di utilizzare "Open File" e "Open Shellcode". Nel mio caso, quando ho aperto la shellcode come file l'ha...](<../../images/image (562).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp in quel punto; apparentemente Cutter avvierà automaticamente l'emulazione da lì:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Per avviare l'emulazione nel punto desiderato, imposta un bp in quel punto; apparentemente Cutter avvierà automaticamente l'emulazione...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Per avviare l'emulazione nel punto desiderato, imposta un bp in quel punto; apparentemente Cutter avvierà automaticamente l'emulazione...](<../../images/image (387).png>)

Puoi vedere lo stack, ad esempio, all'interno di un hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Puoi vedere lo stack, ad esempio, all'interno di un hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà informazioni come **quali funzioni** sta utilizzando la shellcode e se la shellcode si sta **decodificando** in memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispone anche di un launcher grafico in cui è possibile selezionare le opzioni desiderate ed eseguire lo shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg dispone anche di un launcher grafico in cui è possibile selezionare le opzioni desiderate ed eseguire lo...](<../../images/image (258).png>)

L'opzione **Create Dump** esegue il dump dello shellcode finale se viene apportata una modifica dinamicamente allo shellcode in memoria (utile per scaricare lo shellcode decodificato). Lo **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, per questo scopo, ritengo migliori le opzioni spiegate in precedenza, poiché sarà possibile usare Ida o x64dbg).

### Disassemblaggio usando CyberChef

Carica il file dello shellcode come input e usa la seguente recipe per disassemblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). L'aspetto importante è che queste identità sono generalmente corrette solo in presenza di **aritmetica modulare a larghezza fissa**, quindi carry e overflow sono rilevanti:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se semplifichi questo tipo di espressione con strumenti di algebra generica, puoi facilmente ottenere un risultato errato perché la semantica della bit-width è stata ignorata.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la bit-width originale** ottenuta dal codice/IR/decompiler liftato (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
- **Lineare**: somme pesate di atomi bitwise
- **Semilineare**: lineare più maschere costanti come `x & 0xFF`
- **Polinomiale**: sono presenti prodotti
- **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una dimostrazione SMT. Se l'equivalenza non può essere dimostrata, mantieni l'espressione originale invece di fare supposizioni.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l'analisi di malware e il reversing di binari protetti. Classifica l'espressione e la instrada attraverso pipeline specializzate invece di applicare un unico passaggio di riscrittura generico a tutto.<sup>[[2]](#references)</sup>

Utilizzo rapido:
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

- **Linear MBA**: CoBRA valuta l'espressione su input booleani, ricava una firma ed esegue in parallelo diversi metodi di recupero, come il pattern matching, la conversione ANF e l'interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione partizionata per bit, in modo che le regioni mascherate rimangano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in componenti fondamentali e le sottoespressioni ripetute possono essere estratte in variabili temporanee prima di semplificare la relazione esterna.

Esempio di identità mista che vale comunemente la pena provare a recuperare:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Questo può essere ridotto a:
```c
x * y
```
### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR liftate** o sull'output del decompiler dopo aver isolato il calcolo esatto.
- Usa esplicitamente `--bitwidth` quando l'espressione proviene da operazioni aritmetiche con maschere o da registri di ampiezza ridotta.
- Se ti serve un passaggio di dimostrazione più rigoroso, consulta qui le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA viene fornito anche come **LLVM pass plugin** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR ricco di MBA prima dei passaggi di analisi successivi.
- I residui misti di domini sensibili al carry non supportati devono essere trattati come un segnale per mantenere l'espressione originale e ragionare manualmente sul percorso del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator **modifica tutte le istruzioni in `mov`** (sì, davvero fantastico). Usa anche gli interrupt per modificare i flussi di esecuzione. Per maggiori informazioni sul suo funzionamento:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se sei fortunato, [demovfuscator](https://github.com/kirschju/demovfuscator) deoffuscherà il binary. Ha diverse dipendenze
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questo workaround per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare il **punto di ingresso**, cerca le funzioni con `::main`, come in:

![Movfuscator - Rust: Per trovare il punto di ingresso, cerca le funzioni con ::main, come in](<../../images/image (1080).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Avendo il **nome** delle **funzioni** chiamate, cercale su **Internet** per ottenere informazioni sui loro **input** e **output**.

### Recuperare le stringhe Rust dal firmware ELF

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate come puntatori terminati da NUL in stile C. Un layout comune di `rustc` è una tupla **puntatore/lunghezza** all'interno di **`.data.rel.ro`**, che punta al vero blob di stringhe memorizzato in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Questo significa che `strings` o l'analisi predefinita di Ghidra possono unire stringhe adiacenti o non rilevare affatto i riferimenti incrociati.<sup>[[3]](#references)</sup>

Flusso di lavoro rapido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Recupera l'indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una word alla volta.
3. Considera qualsiasi valore compreso nell'intervallo di indirizzi di `.rodata` come un potenziale puntatore a una stringa.
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
Questo è particolarmente utile nel firmware reversing perché le stringhe Rust recuperate spesso rivelano **HTTP routes, nomi RPC, messaggi di log, assertions, nomi di file, chiavi di configurazione, command handlers e logica relativa all'autenticazione**.

Se Ghidra non individua queste stringhe, esegui uno script/plugin personalizzato che applichi la stessa euristica e crei dati stringa agli offset `.rodata` referenziati. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono buoni riferimenti per adattare l'idea ad altre **word sizes, endianness e configurazioni delle sezioni**.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Per i binari compilati Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti suggerisco di usare il plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi semplicemente **ATL+f7** (importa il plugin Python in IDA) e seleziona il plugin Python.

Questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni all'inizio del debugging. Dopo aver avviato il debugging, premi nuovamente il pulsante Start (quello verde o f9) e un breakpoint verrà raggiunto all'inizio del codice reale.

È anche molto interessante perché, se premi un pulsante nell'applicazione grafica, il debugger si fermerà nella funzione eseguita da quel pulsante.

## Golang

Se devi fare reversing di un binario Golang, ti suggerisco di usare il plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi semplicemente **ATL+f7** (importa il plugin Python in IDA) e seleziona il plugin Python.

Questo risolverà i nomi delle funzioni.

## Compiled Python

In questa pagina puoi trovare come ottenere il codice Python da un binario ELF/EXE compilato Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se ottieni il **binary** di un gioco GBA, puoi usare diversi strumenti per **emulate** e fare **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione per il debug_) - Contiene un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **buttons** del Game Boy Advance

![configurazione dei controlli di no$gba che mostra la mappatura dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

Quando vengono premuti, ogni **key ha un valore** che la identifica:
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

In quella funzione, dopo alcune operazioni di init (senza alcuna importanza):
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
L'ultimo if verifica che **`uVar4`** sia nelle **last Keys** e non sia la chiave corrente, ovvero che sia stato rilasciato un pulsante (la chiave corrente è memorizzata in **`uVar1`**).
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

- Prima viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge questo pulsante cancella lo schermo
- Poi viene confrontato con il **valore 8** (pulsante **START**): nella challenge verifica se il codice è valido per ottenere la flag.
- In questo caso la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore è lo stesso, viene eseguito del codice.
- In tutti gli altri casi, viene controllato un contatore (`DAT_030000d4`). È un contatore perché viene incrementato di 1 subito dopo l'inserimento del codice.\
**S**e è minore di 8, viene eseguito qualcosa che comporta l'**aggiunta** di valori a **`DAT_030000d8`** (in pratica, in questa variabile vengono aggiunti i valori dei tasti premuti finché il contatore è minore di 8).

Quindi, in questa challenge, conoscendo i valori dei pulsanti, era necessario **premere una combinazione con una lunghezza inferiore a 8 il cui risultato della somma fosse 0xf3.**

**Riferimento per questo tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Riferimenti

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
