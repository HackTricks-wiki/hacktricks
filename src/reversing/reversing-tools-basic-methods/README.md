# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek è un decompiler che **decompila e analizza più formati**, inclusi **librerie** (.dll), **Windows metadata file**s (.winmd) ed **eseguibili** (.exe). Una volta decompilato, un assembly può essere salvato come progetto Visual Studio (.csproj).

Il merito qui è che, se il codice sorgente perduto richiede il ripristino da un assembly legacy, questa operazione può far risparmiare tempo. Inoltre, dotPeek offre una navigazione pratica all'interno del codice decompilato, rendendolo uno degli strumenti perfetti per l'**analisi degli algoritmi Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modello completo di add-in e un'API che estende lo strumento per adattarlo esattamente alle tue esigenze, .NET reflector fa risparmiare tempo e semplifica lo sviluppo. Diamo un'occhiata alla moltitudine di servizi di reverse engineering che questo strumento offre:

- Fornisce una visione di come i dati fluiscono attraverso una libreria o un componente
- Fornisce una visione dell'implementazione e dell'uso dei linguaggi e framework .NET
- Trova funzionalità non documentate e non esposte per ottenere di più dalle API e dalle tecnologie usate.
- Trova dipendenze e assembly diversi
- Individua l'esatta posizione degli errori nel tuo codice, nei componenti di terze parti e nelle librerie.
- Esegue il debug nel sorgente di tutto il codice .NET con cui lavori.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puoi averlo in qualsiasi OS (puoi installarlo direttamente da VSCode, non c'è bisogno di scaricare il git. Clicca su **Extensions** e **cerca ILSpy**).\
Se hai bisogno di **decompilare**, **modificare** e **ricompilare** di nuovo puoi usare [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o una fork mantenuta attivamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Tasto destro -> Modify Method** per cambiare qualcosa dentro una funzione).

### DNSpy Logging

Per fare in modo che **DNSpy registri alcune informazioni in un file**, puoi usare questo snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Debugging DNSpy

Per eseguire il debug del codice usando DNSpy devi:

Per prima cosa, modifica gli **attributi dell'assembly** relativi al **debug**:

![](<../../images/image (973).png>)

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

![](<../../images/image (314) (1).png>)

Poi salva il nuovo file tramite _**File >> Save module...**_:

![](<../../images/image (602).png>)

Questo è necessario perché, se non lo fai, a **runtime** verranno applicate diverse **optimisations** al codice e potrebbe succedere che durante il debugging un **break-point is never hit** oppure che alcune **variables don't exist**.

Poi, se la tua applicazione .NET viene **run** da **IIS** puoi **restart**arla con:
```
iisreset /noforce
```
Allora, per iniziare il debugging dovresti chiudere tutti i file aperti e, dentro la **Debug Tab**, selezionare **Attach to Process...**:

![](<../../images/image (318).png>)

Poi seleziona **w3wp.exe** per collegarti al **IIS server** e clicca **attach**:

![](<../../images/image (113).png>)

Ora che stiamo debuggando il processo, è il momento di fermarlo e caricare tutti i moduli. Prima clicca su _Debug >> Break All_ e poi clicca su _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Clicca su qualsiasi modulo in **Modules** e seleziona **Open All Modules**:

![](<../../images/image (922).png>)

Fai clic destro su qualsiasi modulo in **Assembly Explorer** e clicca **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) è un programma utile per trovare dove vengono salvati nella memoria di un gioco in esecuzione i valori importanti e modificarli. Maggiori info in:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) è un web front-end per diversi decompilatori. Questo servizio web ti permette di confrontare l'output di diversi decompilatori su piccoli eseguibili.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Poi devi **collegare un debugger** (Ida o x64dbg) al processo e mettere un **breakpoint all'indirizzo di memoria indicato** e **riprendere** l'esecuzione. In questo modo starai debuggando lo shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Ti dirà cose come **quali funzioni** sta usando lo shellcode e se lo shellcode si sta **decoding** da solo in memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg dispone anche di un launcher grafico dove puoi selezionare le opzioni desiderate ed eseguire lo shellcode

![](<../../images/image (258).png>)

L'opzione **Create Dump** farà il dump del shellcode finale se viene effettuata qualsiasi modifica al shellcode dinamicamente in memoria (utile per scaricare lo shellcode decodificato). Lo **start offset** può essere utile per avviare lo shellcode da un offset specifico. L'opzione **Debug Shell** è utile per eseguire il debug dello shellcode usando il terminale di scDbg (tuttavia trovo che una qualsiasi delle opzioni spiegate prima sia migliore per questo scopo, poiché potrai usare Ida o x64dbg).

### Disassembling using CyberChef

Carica il tuo file shellcode come input e usa la seguente recipe per decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

L'obfuscation **Mixed Boolean-Arithmetic (MBA)** nasconde espressioni semplici come `x + y` dietro formule che mescolano operatori aritmetici (`+`, `-`, `*`) e operatori bitwise (`&`, `|`, `^`, `~`, shift). La parte importante è che queste identità sono di solito corrette solo sotto **fixed-width modular arithmetic**, quindi contano carry e overflow:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Se semplifichi questo tipo di espressione con tool algebrici generici puoi facilmente ottenere un risultato errato perché la semantica della bit-width è stata ignorata.

### Workflow pratico

1. **Mantieni la bit-width originale** dal codice/IR/decompiler output sollevato (`8/16/32/64` bit).
2. **Classifica l'espressione** prima di provare a semplificarla:
- **Lineare**: somme pesate di atomi bitwise
- **Semilineare**: lineare più maschere costanti come `x & 0xFF`
- **Polinomiale**: compaiono prodotti
- **Mista**: prodotti e logica bitwise sono intrecciati, spesso con sottospressioni ripetute
3. **Verifica ogni candidate rewrite** con random testing o una prova SMT. Se l'equivalenza non può essere provata, mantieni l'espressione originale invece di andare a intuito.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) è un practical MBA simplifier per malware analysis e protected-binary reversing. Classifica l'espressione e la instrada attraverso pipeline specializzate invece di applicare un unico generic rewrite pass a tutto.

Quick usage:
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

- **Linear MBA**: CoBRA valuta l'espressione sugli input Booleani, ricava una signature e mette in competizione diversi metodi di recovery come pattern matching, conversione ANF e interpolazione dei coefficienti.
- **Semilinear MBA**: gli atomi constant-masked vengono ricostruiti con bit-partitioned reconstruction così le regioni mascherate restano corrette.
- **Polynomial/Mixed MBA**: i prodotti vengono scomposti in core e le sottoespressioni ripetute possono essere sollevate in temporaries prima di semplificare la relazione esterna.

Esempio di una mixed identity che spesso vale la pena provare a recovery:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Questo può collassare in:
```c
x * y
```
### Reversing notes

- Preferisci eseguire CoBRA su **lifted IR expressions** o sull'output del decompiler dopo aver isolato il calcolo esatto.
- Usa `--bitwidth` esplicitamente quando l'espressione proviene da masked arithmetic o da registri stretti.
- Se ti serve un passo di prova più forte, controlla qui le note locali su Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA è disponibile anche come **LLVM pass plugin** (`libCobraPass.so`), utile quando vuoi normalizzare LLVM IR pesante di MBA prima dei successivi analysis passes.
- I residuals mixed-domain sensibili al carry non supportati dovrebbero essere trattati come un segnale per mantenere l'espressione originale e ragionare manualmente sul carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E installa [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Se stai giocando a un **CTF, questo workaround per trovare la flag** potrebbe essere molto utile: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Per trovare il **entry point** cerca le funzioni con `::main` come in:

![](<../../images/image (1080).png>)

In questo caso il binary si chiamava authenticator, quindi è abbastanza ovvio che questa sia la main function interessante.\
Avendo il **nome** delle **functions** chiamate, cercale su **Internet** per imparare i loro **inputs** e **outputs**.

## **Delphi**

Per i binary compilati con Delphi puoi usare [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Se devi fare reversing di un binary Delphi ti suggerirei di usare il plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Basta premere **ATL+f7** (import python plugin in IDA) e selezionare il python plugin.

Questo plugin eseguirà il binary e risolverà dinamicamente i nomi delle funzioni all'inizio del debugging. Dopo aver avviato il debugging premi di nuovo il pulsante Start (quello verde o f9) e un breakpoint verrà raggiunto all'inizio del codice reale.

È anche molto interessante perché se premi un pulsante nell'applicazione grafica il debugger si fermerà nella funzione eseguita da quel bottom.

## Golang

Se devi fare reversing di un binary Golang ti suggerirei di usare il plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Basta premere **ATL+f7** (import python plugin in IDA) e selezionare il python plugin.

Questo risolverà i nomi delle funzioni.

## Compiled Python

In questa pagina puoi trovare come ottenere il codice python da un binary compilato python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Se ottieni il **binary** di un gioco GBA puoi usare diversi strumenti per **emularlo** e **debuggarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Scarica la versione debug_) - Contiene un debugger con interfaccia
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin per Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin per Ghidra

In [**no$gba**](https://problemkaputt.de/gba.htm), in _**Options --> Emulation Setup --> Controls**_** ** puoi vedere come premere i pulsanti del Game Boy Advance

![](<../../images/image (581).png>)

Quando vengono premuti, ogni **key ha un valore** per identificarla:
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
Quindi, in questo tipo di programma, la parte interessante sarà **come il programma tratta l'input dell'utente**. All'indirizzo **0x4000130** troverai la funzione comunemente presente: **KEYINPUT**.

![](<../../images/image (447).png>)

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
L’ultimo `if` controlla se **`uVar4`** è nelle **ultime Keys** e non è la chiave corrente, chiamato anche rilascio di un pulsante (la chiave corrente è memorizzata in **`uVar1`**).
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

- Per prima cosa, viene confrontato con il **valore 4** (pulsante **SELECT**): nella challenge questo pulsante pulisce lo schermo
- Poi, viene confrontato con il **valore 8** (pulsante **START**): nella challenge questo verifica se il codice è valido per ottenere la flag.
- In questo caso la var **`DAT_030000d8`** viene confrontata con 0xf3 e se il valore è lo stesso viene eseguito del codice.
- In qualsiasi altro caso, viene controllato un cont (`DAT_030000d4`). È un cont perché viene incrementato di 1 subito dopo essere entrati nel codice.\
**S**e è minore di 8, viene fatto qualcosa che coinvolge l’**aggiunta** di valori a **`DAT_030000d8`** (in pratica, vengono sommati i valori dei tasti premuti in questa variabile finché il cont è minore di 8).

Quindi, in questa challenge, conoscendo i valori dei pulsanti, dovevi **premere una combinazione con lunghezza minore di 8 il cui risultato della somma fosse 0xf3.**

**Riferimento per questo tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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

{{#include ../../banners/hacktricks-training.md}}
