# Strumenti di Reversing & Metodi Base

{{#include ../../banners/hacktricks-training.md}}

## Strumenti di reversing basati su ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompiler Wasm / compilatore Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) per **decompilare** da wasm (binary) a wat (clear text)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) per **compilare** da wat a wasm
- puoi anche provare a usare [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) per decompilare

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompiler .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila ed esamina più formati**, incluse **librerie** (.dll), **file di metadati Windows** (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il vantaggio qui è che, se il codice sorgente perso deve essere ripristinato da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una navigazione comoda all'interno del codice decompilato, rendendolo uno degli strumenti perfetti per l'**analisi di algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modello completo di add-in e un'API che estende lo strumento in base alle tue esigenze precise, .NET reflector fa risparmiare tempo e semplifica lo sviluppo. Diamo un'occhiata alla moltitudine di servizi di reverse engineering che questo strumento offre:

- Offre una visione di come i dati fluiscono attraverso una library o un componente
- Offre una visione dell'implementazione e dell'uso dei linguaggi e framework .NET
- Trova funzionalità non documentate e non esposte per ottenere di più dalle API e dalle tecnologie usate.
- Trova dipendenze e assembly diversi
- Individua la posizione esatta degli errori nel tuo codice, nei componenti di terze parti e nelle library.
- Esegue il debug nel sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puoi averlo su qualsiasi OS (puoi installarlo direttamente da VSCode, non serve scaricare il git. Clicca su **Extensions** e **cerca ILSpy**).\
Se hai bisogno di **decompilare**, **modificare** e **ricompilare** di nuovo puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) oppure un fork mantenuto attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** per cambiare qualcosa dentro una funzione).

### DNSpy Logging

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Per eseguire il debug del codice usando DNSpy, devi:

Per prima cosa, modificare gli **Assembly attributes** relativi al **debugging**:

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

Questo è necessario perché, se non lo fai, a **runtime** verranno applicate diverse **optimisations** al codice e potrebbe essere possibile che durante il debugging un **break-point is never hit** o che alcune **variables don't exist**.

Poi, se la tua applicazione .NET viene **run** da **IIS**, puoi **riavviarla** con:
```
iisreset /noforce
```
Allora, per iniziare il debugging dovresti chiudere tutti i file aperti e, dentro la **Debug Tab**, selezionare **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Poi seleziona **w3wp.exe** per collegarti al **IIS server** e clicca **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Ora che stiamo facendo debug del processo, è il momento di fermarlo e caricare tutti i moduli. Prima clicca su _Debug >> Break All_ e poi clicca su _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Clicca su qualsiasi modulo in **Modules** e seleziona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Fai clic destro su qualsiasi modulo in **Assembly Explorer** e clicca **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura i **parameters** dell'esecuzione inserendo il **path to the DLL** e la funzione che vuoi chiamare:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Poi, quando avvii il debugging, **l'esecuzione si fermerà ogni volta che viene caricata una DLL**, quindi, quando rundll32 carica la tua DLL l'esecuzione si fermerà.

Ma, come puoi arrivare al codice della DLL che è stata caricata? Usando questo metodo, non lo so.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la Command Line** ( _File --> Change Command Line_ ) e imposta il path della dll e la funzione che vuoi chiamare, per esempio: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ e seleziona "**DLL Entry**".
- Poi **avvia l'esecuzione**, il debugger si fermerà a ogni dll main; a un certo punto ti **fermerai nella dll Entry della tua dll**. Da lì, cerca semplicemente i punti in cui vuoi mettere un breakpoint.

Nota che quando l'esecuzione si ferma per qualsiasi motivo in win64dbg puoi vedere **in quale codice ti trovi** guardando in alto nella finestra di win64dbg:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Poi, guardando questo ca puoi vedere quando l'esecuzione si è fermata nella dll che vuoi debuggare.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove i valori importanti sono salvati nella memoria di un gioco in esecuzione e modificarli. Più info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) è un front-end/reverse engineering tool per il GNU Project Debugger (GDB), focalizzato sui giochi. Tuttavia, può essere usato per qualsiasi cosa relativa alla reverse-engineering

[**Decompiler Explorer**](https://dogbolt.org/) è un web front-end per diversi decompilers. Questo web service ti permette di confrontare l'output di diversi decompilers su piccoli eseguibili.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **allocherà** lo **shellcode** dentro uno spazio di memoria, **indicherà** l'**indirizzo di memoria** in cui lo shellcode è stato allocato e **fermerà** l'esecuzione.\
Poi, devi **attaccare un debugger** (Ida o x64dbg) al processo e mettere un **breakpoint sull'indirizzo di memoria indicato** e **riprendere** l'esecuzione. In questo modo starai facendo debugging dello shellcode.

La pagina github delle release contiene zip con le release compilate: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puoi trovare una versione leggermente modificata di Blobrunner nel seguente link. Per compilarla, basta **creare un progetto C/C++ in Visual Studio Code, copiare e incollare il codice e buildarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)è molto simile a blobrunner. **Alloccherà** lo **shellcode** dentro uno spazio di memoria e avvierà un **loop eterno**. Devi poi **attaccare il debugger** al processo, **avviare start wait 2-5 secs e premere stop** e ti ritroverai dentro il **loop eterno**. Vai alla prossima istruzione del loop eterno perché sarà una call allo shellcode e, infine, ti ritroverai a eseguire lo shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

Puoi scaricare una versione compilata di [jmp2it nella pagina releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) è la GUI di radare. Usando cutter puoi emulare lo shellcode e ispezionarlo dinamicamente.

Nota che Cutter permette di "Open File" e "Open Shellcode". Nel mio caso, quando ho aperto lo shellcode come file lo ha decompilato correttamente, ma quando l'ho aperto come shellcode no:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

Per avviare l'emulazione nel punto che vuoi, imposta lì un bp e apparentemente cutter avvierà automaticamente l'emulazione da lì:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

Puoi vedere lo stack per esempio dentro un hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Dovresti provare [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà cose come **quali funzioni** sta usando lo shellcode e se lo shellcode si sta **decodificando** in memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg ha anche un launcher grafico dove puoi selezionare le opzioni che vuoi ed eseguire lo shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

L'opzione **Create Dump** eseguirà il dump dello shellcode finale se viene apportata qualsiasi modifica dinamica allo shellcode in memoria (utile per scaricare lo shellcode decodificato). L'opzione **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per fare il debug dello shellcode usando il terminale di scDbg (tuttavia, per questo scopo trovo migliori le opzioni spiegate prima, perché potrai usare Ida o x64dbg).

### Disassembling using CyberChef

Carica il tuo file shellcode come input e usa la seguente recipe per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

L'**Mixed Boolean-Arithmetic (MBA)** obfuscation nasconde espressioni semplici come `x + y` dietro formule che mescolano operatori aritmetici (`+`, `-`, `*`) e bitwise (`&`, `|`, `^`, `~`, shift). La parte importante è che queste identità sono di solito corrette solo sotto **aritmetica modulare a larghezza fissa**, quindi carry e overflow contano:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se semplifichi questo tipo di espressione con strumenti algebrici generici puoi facilmente ottenere un risultato sbagliato perché la semantica della bit-width è stata ignorata.

### Flusso di lavoro pratico

1. **Mantieni la bit-width originale** dal codice/IR/decompiler output sollevato (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
- **Lineare**: somme pesate di atomi bitwise
- **Semilineare**: lineare più maschere costanti come `x & 0xFF`
- **Polinomiale**: compaiono prodotti
- **Mista**: prodotti e logica bitwise sono intrecciati, spesso con sottose espressioni ripetute
3. **Verifica ogni riscrittura candidata** con test casuali o una prova SMT. Se l'equivalenza non può essere dimostrata, mantieni l'espressione originale invece di andare a intuito.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un pratico semplificatore MBA per l'analisi malware e il reversing di binary protetti. Classifica l'espressione e la instrada attraverso pipeline specializzate invece di applicare un unico passaggio di riscrittura generico a tutto.

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

- **Linear MBA**: CoBRA valuta l’espressione su input Booleani, ricava una signature e mette in competizione diversi metodi di recupero come pattern matching, conversione in ANF e interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi mascherati da costanti vengono ricostruiti con una ricostruzione bit-partitioned, così le regioni mascherate restano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in cores e le sottospressioni ripetute possono essere sollevate in temporanei prima di semplificare la relazione esterna.

Esempio di un’identità mixed che spesso vale la pena provare a recuperare:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Questo può collassare in:
```c
x * y
```
### Note di Reversing

- Preferisci eseguire CoBRA su **espressioni IR sollevate** o sull'output del decompiler dopo aver isolato il calcolo esatto.
- Usa `--bitwidth` esplicitamente quando l'espressione proviene da aritmetica mascherata o da registri stretti.
- Se hai bisogno di un passo di prova più forte, consulta le note locali su Z3 qui:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **plugin LLVM pass** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR con molto MBA prima di passaggi di analisi successivi.
- I residuali mixed-domain sensibili al carry non supportati dovrebbero essere trattati come un segnale per mantenere l'espressione originale e ragionare manualmente sul percorso del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Questo obfuscator **modifica tutte le istruzioni in `mov`** (sì, davvero cool). Usa anche interruptions per cambiare i flussi di esecuzione. Per maggiori informazioni su come funziona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Se sei fortunato [demovfuscator](https://github.com/kirschju/demovfuscator) deobfuscaterà il binario. Ha diverse dipendenze
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E installa [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questo workaround per trovare la flag** può essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare l'**entry point** cerca le funzioni con `::main` come in:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

In questo caso il binario si chiamava authenticator, quindi è abbastanza ovvio che questa sia la main function interessante.\
Avendo il **nome** delle **funzioni** chiamate, cercale su **Internet** per conoscere i loro **input** e **output**.

### Recovering Rust strings from ELF firmware

Nei binari **Rust ELF**, molte stringhe statiche non sono referenziate come puntatori in stile C terminati da NUL. Un layout comune di `rustc` è una **coppia puntatore/lunghezza** dentro **`.data.rel.ro`** che punta al vero blob di stringa memorizzato in **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Questo significa che `strings` o l'analisi predefinita di Ghidra potrebbero unire stringhe adiacenti o perdere completamente i cross-reference.

Flusso di lavoro rapido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Ottieni l'indirizzo virtuale e la dimensione di **`.rodata`**.
2. Enumera **`.data.rel.ro`** una word alla volta.
3. Considera qualsiasi valore all'interno dell'intervallo di indirizzi `.rodata` come un potenziale puntatore a stringa.
4. Considera la word successiva come la lunghezza candidata.
5. Applica filtri di sanità mentale (ad esempio, mantieni lunghezze tra **4** e **100** byte).
6. Leggi esattamente `length` byte da `.rodata` invece di scansionare fino a `0x00`.

Logica minimale dell'extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Questo è particolarmente utile nel reversing del firmware perché le stringhe Rust recuperate spesso rivelano **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, e logica correlata all'auth**.

Se Ghidra non trova quelle stringhe, esegui uno script/plugin custom che applichi la stessa heuristic e crei string data agli offset `.rodata` referenziati. I tool pubblicati `rust-strings` e `RustStrings.py` di Pen Test Partners sono buoni riferimenti per adattare l'idea ad altri **word sizes, endianness, e section layouts**.

## **Delphi**

Per i binary compilati con Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binary Delphi ti suggerirei di usare il plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta premere **ATL+f7** (import python plugin in IDA) e selezionare il python plugin.

Questo plugin eseguirà il binary e risolverà dinamicamente i nomi delle function all'inizio del debugging. Dopo aver avviato il debugging premi di nuovo il bottone Start (quello verde o f9) e un breakpoint verrà raggiunto all'inizio del codice reale.

È anche molto interessante perché se premi un bottone nell'applicazione grafica il debugger si fermerà nella function eseguita da quel bottone.

## Golang

Se devi fare reversing di un binary Golang ti suggerirei di usare il plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta premere **ATL+f7** (import python plugin in IDA) e selezionare il python plugin.

Questo risolverà i nomi delle function.

## Compiled Python

In questa pagina puoi trovare come ottenere il codice python da un binary compilato python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se ottieni il **binary** di un gioco GBA puoi usare diversi tool per **emularlo** e **debuggarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Contiene un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i **bottoni** del Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Quando viene premuto, ogni **key ha un valore** per identificarla:
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
Quindi, in questo tipo di programma, la parte interessante sarà **come il programma tratta l'input dell'utente**. Nell'indirizzo **0x4000130** troverai la funzione comunemente presente: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

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
L'ultimo if sta verificando che **`uVar4`** sia nelle **ultime Keys** e non sia la chiave corrente, anche chiamato rilasciare un button (la chiave corrente è memorizzata in **`uVar1`**).
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

- Per prima cosa, viene confrontato con il **valore 4** (**SELECT** button): nella challenge questo button pulisce lo schermo
- Poi, viene confrontato con il **valore 8** (**START** button): nella challenge questo verifica se il codice è valido per ottenere la flag.
- In questo caso la var **`DAT_030000d8`** viene confrontata con 0xf3 e, se il valore è lo stesso, viene eseguito un certo codice.
- In qualsiasi altro caso, viene controllato un cont (`DAT_030000d4`). È un cont perché viene incrementato di 1 subito dopo essere entrato nel codice.\
**S**e è minore di 8, viene fatto qualcosa che coinvolge l'**aggiunta** di valori a **`DAT_030000d8`** (in pratica, vengono sommati i valori dei tasti premuti in questa variabile finché il cont è minore di 8).

Quindi, in questa challenge, conoscendo i valori dei button, dovevi **premere una combinazione con una lunghezza minore di 8 tale che la somma risultante sia 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
