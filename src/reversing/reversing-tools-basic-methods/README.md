# Strumenti di reversing e metodi di base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompiler Wasm / compilatore Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) per **decompilare** da wasm (binario) a wat (testo leggibile)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) per **compilare** da wat a wasm
- Puoi anche provare [web-wasmdec](https://wwwg.github.io/web-wasmdec/) per la decompilazione.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina più formati**, tra cui **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio è che, se è necessario ripristinare il codice sorgente perduto a partire da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una comoda navigazione all'interno del codice decompilato, rendendolo uno degli strumenti perfetti per l'**analisi degli algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Grazie a un modello completo di add-in e a un'API che estende lo strumento per adattarlo alle tue esigenze specifiche, .NET Reflector fa risparmiare tempo e semplifica lo sviluppo. Vediamo la vasta gamma di servizi di reverse engineering offerti da questo strumento:

- Fornisce una visione di come i dati fluiscono attraverso una libreria o un componente
- Fornisce informazioni sull'implementazione e sull'uso dei linguaggi e dei framework .NET
- Individua funzionalità non documentate e non esposte per ottenere di più dalle API e dalle tecnologie utilizzate.
- Individua dipendenze e assembly diversi
- Individua la posizione esatta degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
- Esegue il debug del codice sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puoi usarlo su qualsiasi sistema operativo (puoi installarlo direttamente da VSCode, senza bisogno di scaricare git. Fai clic su **Extensions** e **search ILSpy**).\
Se hai bisogno di **decompilare**, **modificare** e **ricompilare** nuovamente, puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork di esso mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** per modificare qualcosa all'interno di una funzione).

### Logging di DNSpy

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Per eseguire il debug del codice usando DNSpy devi:

Innanzitutto, modifica gli **attributi Assembly** relativi al **debugging**:

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

Questo è necessario perché, se non lo fai, in fase di **runtime** verranno applicate diverse **ottimizzazioni** al codice e potrebbe accadere che durante il debugging un **break-point non venga mai raggiunto** o che alcune **variabili non esistano**.

Quindi, se la tua applicazione .NET viene **eseguita** da **IIS**, puoi **riavviarla** con:
```
iisreset /noforce
```
Quindi, per iniziare il debugging dovresti chiudere tutti i file aperti e, nella **Debug Tab**, selezionare **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Quindi, per iniziare il debugging dovresti chiudere tutti i file aperti e, nella Debug Tab, selezionare Attach to Process](<../../images/image (318).png>)

Seleziona quindi **w3wp.exe** per collegarti al **server IIS** e fai clic su **attach**:

![DNSpy Logging - DNSpy Debugging: Seleziona quindi w3wp.exe per collegarti al server IIS e fai clic su attach](<../../images/image (113).png>)

Ora che stiamo eseguendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Fai prima clic su _Debug >> Break All_ e poi su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Fai prima clic su Debug Break All e poi su Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ora che stiamo eseguendo il debugging del processo, è il momento di arrestarlo e caricare tutti i moduli. Fai prima clic su Debug Break All e poi su Debug Windows Modules](<../../images/image (834).png>)

Fai clic su un modulo qualsiasi in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Fai clic su un modulo qualsiasi in Modules e seleziona Open All Modules](<../../images/image (922).png>)

Fai clic con il tasto destro su un modulo qualsiasi in **Assembly Explorer** e fai clic su **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Fai clic con il tasto destro su un modulo qualsiasi in Assembly Explorer e fai clic su Sort Assemblies](<../../images/image (339).png>)

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

Questo metodo si arresta in corrispondenza degli eventi di caricamento dei moduli, ma raggiungere l'entry point della DLL caricata è meno diretto rispetto al workflow con x64dbg descritto di seguito.

### Utilizzando x64dbg/x32dbg

- **Carica rundll32** (64 bit in C:\Windows\System32\rundll32.exe e 32 bit in C:\Windows\SysWOW64\rundll32.exe)
- **Modifica la Command Line** ( _File --> Change Command Line_ ) e imposta il percorso della dll e la funzione che vuoi chiamare, ad esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Modifica _Options --> Settings_ e seleziona "**DLL Entry**".
- Quindi **avvia l'esecuzione**; il debugger si arresterà in corrispondenza del main di ogni dll e, a un certo punto, **si arresterà nell'Entry della dll** della tua dll. Da lì, cerca semplicemente i punti in cui vuoi inserire un breakpoint.

Nota che, quando l'esecuzione viene arrestata per qualsiasi motivo in win64dbg, puoi vedere **in quale codice ti trovi** guardando nella **parte superiore della finestra di win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Nota che, quando l'esecuzione viene arrestata per qualsiasi motivo in win64dbg, puoi vedere in quale codice ti trovi guardando nella parte superiore della finestra di win64dbg](<../../images/image (842).png>)

Questo indicatore conferma che l'esecuzione è stata arrestata all'interno della DLL di cui vuoi eseguire il debugging.

## App GUI / Videogiochi

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati i valori importanti nella memoria di un gioco in esecuzione e modificarli. Maggiori informazioni in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è un front-end/tool di reverse engineering per il GNU Project Debugger (GDB), incentrato sui giochi. Tuttavia, può essere utilizzato per qualsiasi attività correlata al reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) è un front-end web per diversi decompiler. Questo servizio web consente di confrontare l'output di diversi decompiler su piccoli eseguibili.

## ARM e MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcode

### Eseguire il debugging di una shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) alloca la **shellcode**, stampa il suo **indirizzo di memoria** e mette in pausa l'esecuzione.\
Collega un debugger come IDA o x64dbg, imposta un breakpoint sull'indirizzo stampato e riprendi l'esecuzione per eseguire il debugging della shellcode.

La pagina github delle release contiene archivi zip con le release compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner al link seguente. Per compilarla, **crea semplicemente un progetto C/C++ in Visual Studio Code, copia e incolla il codice ed esegui la build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Eseguire il debugging di una shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) è simile a BlobRunner. Alloca la shellcode ed entra in un loop infinito. Collega il debugger, riprendi l'esecuzione per **2–5 secondi**, metti in pausa l'esecuzione all'interno del loop e fai step fino alla chiamata successiva che trasferisce l'esecuzione alla shellcode allocata.

![Debugger in pausa nel loop infinito di jmp2it, immediatamente prima della chiamata alla shellcode allocata](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina delle release](https://github.com/adamkramer/jmp2it/releases/).

### Eseguire il debugging di una shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Usando Cutter puoi emulare la shellcode e analizzarla dinamicamente.

Nota che Cutter consente di utilizzare "Open File" e "Open Shellcode". Nel mio caso, quando ho aperto la shellcode come file, l'ha decompilata correttamente, ma quando l'ho aperta come shellcode non lo ha fatto:

![Cutter che mostra risultati di analisi diversi quando apre gli stessi byte come file o come shellcode](<../../images/image (562).png>)

Per avviare l'emulazione nel punto desiderato, imposta un bp in quel punto e, a quanto pare, Cutter avvierà automaticamente l'emulazione da lì:

![Impostazione di un breakpoint sull'entry point desiderato della shellcode prima di avviare l'emulazione di Cutter](<../../images/image (589).png>)

![Emulatore di Cutter in pausa sul breakpoint selezionato della shellcode](<../../images/image (387).png>)

Puoi visualizzare lo stack, ad esempio, all'interno di un hex dump:

![Visualizzazione dello stack della shellcode emulata nell'hex dump di Cutter](<../../images/image (186).png>)

### Deobfuscating della shellcode e recupero delle funzioni eseguite

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà cose come **quali funzioni** sta usando la shellcode e se la shellcode si sta **decodificando** in memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispone inoltre di un launcher grafico in cui è possibile selezionare le opzioni desiderate ed eseguire lo shellcode

![Launcher grafico di scDbg per selezionare le opzioni di emulazione e tracing dello shellcode](<../../images/image (258).png>)

L'opzione **Create Dump** esegue il dump dello shellcode finale se lo shellcode viene modificato dinamicamente in memoria (utile per scaricare lo shellcode decodificato). Lo **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia, ritengo che una delle opzioni spiegate in precedenza sia più adatta a questo scopo, poiché sarà possibile usare Ida o x64dbg).

### Disassembly usando CyberChef

Carica il file dello shellcode come input e usa la seguente recipe per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Deoffuscazione dell'offuscamento MBA

L'offuscamento **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che combinano operazioni aritmetiche (`+`, `-`, `*`) e operatori bitwise (`&`, `|`, `^`, `~`, shift). L'aspetto importante è che queste identità sono generalmente corrette solo nell'ambito dell'**aritmetica modulare a larghezza fissa**, quindi carry e overflow sono importanti:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se semplifichi questo tipo di espressione con strumenti di algebra generica, puoi facilmente ottenere un risultato errato perché la semantica della larghezza in bit è stata ignorata.<sup>[[1]](#references)</sup>

### Workflow pratico

1. **Mantieni la larghezza originale in bit** del codice/IR/decompiler output ottenuto tramite lifting (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
- **Lineare**: somme pesate di atomi bitwise
- **Semilineare**: lineare più maschere costanti come `x & 0xFF`
- **Polinomiale**: sono presenti prodotti
- **Mista**: prodotti e logica bitwise sono intercalati, spesso con sottoespressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una dimostrazione SMT. Se l'equivalenza non può essere dimostrata, mantieni l'espressione originale invece di fare supposizioni.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un semplificatore MBA pratico per l'analisi di malware e il reversing di binari protetti. Classifica l'espressione e la instrada attraverso pipeline specializzate invece di applicare un'unica procedura generica di riscrittura a tutto.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA valuta l'espressione su input booleani, ricava una signature e mette in competizione diversi metodi di recupero, come il pattern matching, la conversione ANF e l'interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi constant-masked vengono ricostruiti con una ricostruzione partizionata per bit, in modo che le regioni mascherate rimangano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in core e le sottoespressioni ripetute possono essere sollevate in temporanei prima di semplificare la relazione esterna.

Esempio di un'identità mixed che vale comunemente la pena provare a recuperare:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Si può ridurre a:
```c
x * y
```
### Note sul reversing

- Preferisci eseguire CoBRA su **espressioni IR lifted** o sull'output del decompiler dopo aver isolato il calcolo esatto.
- Usa esplicitamente `--bitwidth` quando l'espressione proviene da aritmetica con maschere o da registri di ampiezza ridotta.
- Se ti serve un passaggio di dimostrazione più forte, consulta le note locali su Z3 qui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin pass LLVM** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR ricco di MBA prima dei passaggi di analisi successivi.
- I residui misti di domini sensibili al carry non supportati devono essere trattati come un segnale per mantenere l'espressione originale e ragionare manualmente sul percorso del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator sostituisce le operazioni del programma con sequenze di istruzioni basate su `mov` e usa la gestione di segnali/eccezioni per alterare il flusso di controllo. Per i dettagli:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Per i binari supportati, [demovfuscator](https://github.com/kirschju/demovfuscator) può deobfuscate il risultato. Ha diverse dipendenze.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questo workaround per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point**, cerca le funzioni tramite `::main`, come in:

![Ricerca di un entry point Rust in Ghidra cercando i nomi delle funzioni con main preceduto da due punti](<../../images/image (1080).png>)

In questo caso il binary si chiamava authenticator, quindi è abbastanza ovvio che questa sia la funzione main interessante.\
Dopo aver individuato il **name** delle **functions** chiamate, cercale su **Internet** per ottenere informazioni sui loro **inputs** e **outputs**.

### Recupero delle stringhe Rust dal firmware ELF

Nei binary **Rust ELF**, molte stringhe statiche non sono referenziate come puntatori con terminazione NUL in stile C. Un layout comune di `rustc` è una **coppia puntatore/lunghezza** all'interno di **`.data.rel.ro`** che punta al vero blob di stringhe memorizzato in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Ciò significa che `strings` o l'analisi predefinita di Ghidra possono unire stringhe adiacenti o non rilevare affatto i riferimenti incrociati.<sup>[[3]](#references)</sup>

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
6. Leggi esattamente `length` byte da `.rodata` invece di scansionare fino a `0x00`.

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

Se Ghidra non rileva queste stringhe, esegui uno script/plugin personalizzato che applichi la stessa euristica e crei dati stringa agli offset `.rodata` referenziati. Gli strumenti `rust-strings` e `RustStrings.py` pubblicati da Pen Test Partners sono buoni riferimenti per adattare l'idea ad altri **word size, endianness e layout delle sezioni**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Per i binari compilati Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binario Delphi, ti suggerisco di usare il plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo plugin eseguirà il binario e risolverà dinamicamente i nomi delle funzioni all'avvio del debugging. Dopo aver avviato il debugging, premi nuovamente il pulsante Start (quello verde o f9) e un breakpoint verrà raggiunto all'inizio del codice reale.

Se premi un pulsante nell'applicazione grafica, il debugger può fermarsi nella funzione invocata da quel pulsante.

## Golang

Se devi fare reversing di un binario Golang, ti suggerisco di usare il plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Premi **Alt+F7** in IDA per caricare un plugin Python, quindi seleziona il file del plugin.

Questo risolverà i nomi delle funzioni.

## Python compilato

In questa pagina puoi trovare come ottenere il codice Python da un binario ELF/EXE Python compilato:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Se ottieni il **binary** di un gioco GBA, puoi usare diversi strumenti per **emularlo** e fare **debugging**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Contiene un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **pulsanti** del Game Boy Advance

![configurazione dei controlli di no$gba che mostra la mappatura dei pulsanti del Game Boy Advance](<../../images/image (581).png>)

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
L'ultimo **`if`** verifica che **`uVar4`** sia in **last Keys** e non sia la chiave corrente, chiamato anche rilascio di un pulsante (la chiave corrente è memorizzata in **`uVar1`**).
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

- Innanzitutto, viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge questo pulsante cancella lo schermo
- Poi confronta il valore con **8** (il pulsante **START**); in questa challenge, quel percorso verifica se il codice inserito è valido.
- In questo caso la variabile **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore è uguale, viene eseguito del codice.
- In ogni altro caso, viene controllato e incrementato un contatore (`DAT_030000d4`).\
Finché il contatore è inferiore a 8, i valori dei tasti premuti vengono accumulati in `DAT_030000d8`.

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione con una lunghezza inferiore a 8 il cui risultato della somma fosse 0xf3.**

**Riferimento per questo tutorial:** [writeup archiviato della challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Corsi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deoffuscamento binario)

## References

- [1] [Semplificare l'offuscamento MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Decodifica delle stringhe Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial di reversing GBA (archiviato)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
