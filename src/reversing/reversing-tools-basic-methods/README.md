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

Το dotPeek είναι ένας decompiler που **decompiles και examines πολλαπλά formats**, συμπεριλαμβανομένων των **libraries** (.dll), των **Windows metadata file**s (.winmd) και των **executables** (.exe). Μόλις γίνει decompile, ένα assembly μπορεί να αποθηκευτεί ως Visual Studio project (.csproj).

Το πλεονέκτημα εδώ είναι ότι αν ένας χαμένος source code χρειάζεται αποκατάσταση από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση σε όλο το decompiled code, καθιστώντας το ένα από τα ιδανικά tools για **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο add-in model και ένα API που επεκτείνει το tool ώστε να καλύπτει ακριβώς τις ανάγκες σου, το .NET reflector εξοικονομεί χρόνο και απλοποιεί το development. Ας δούμε την πληθώρα των reverse engineering services που παρέχει αυτό το tool:

- Παρέχει insight στο πώς τα data flow μέσα από μια library ή component
- Παρέχει insight στην implementation και usage των .NET languages και frameworks
- Βρίσκει undocumented και unexposed functionality για να αξιοποιήσεις περισσότερο τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Βρίσκει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή θέση των errors στον code σου, σε third-party components και libraries.
- Debugs into the source of all the .NET code you work with.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείς να το έχεις σε οποιοδήποτε OS (μπορείς να το εγκαταστήσεις απευθείας από το VSCode, δεν χρειάζεται να κατεβάσεις το git. Κάνε κλικ στο **Extensions** και αναζήτησε **ILSpy**).\
Αν χρειάζεται να **decompile**, **modify** και **recompile** ξανά, μπορείς να χρησιμοποιήσεις το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα ενεργά συντηρούμενο fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξεις κάτι μέσα σε μια function).

### DNSpy Logging

Για να κάνεις το **DNSpy log some information in a file**, μπορείς να χρησιμοποιήσεις αυτό το snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Για να κάνετε debug κώδικα χρησιμοποιώντας DNSpy, πρέπει να:

Πρώτα, αλλάξτε τα **Assembly attributes** που σχετίζονται με το **debugging**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

Από:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Προς:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Και κάντε κλικ στο **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Στη συνέχεια αποθηκεύστε το νέο αρχείο μέσω του _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο επειδή αν δεν το κάνετε, στο **runtime** θα εφαρμοστούν αρκετές **optimisations** στον κώδικα και είναι πιθανό, κατά το debugging, να μη χτυπηθεί ποτέ ένα **break-point** ή να μην υπάρχουν κάποια **variables**.

Έπειτα, αν η .NET εφαρμογή σας εκτελείται από το **IIS**, μπορείτε να την **restart** με:
```
iisreset /noforce
```
Then, in order to start debugging you should close all the opened files and inside the **Debug Tab** select **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Then select **w3wp.exe** to attach to the **IIS server** and click **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Now that we are debugging the process, it's time to stop it and load all the modules. First click on _Debug >> Break All_ and then click on _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Click any module on **Modules** and select **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Right click any module in **Assembly Explorer** and click **Sort Assemblies**:

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

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg διαθέτει επίσης έναν γραφικό launcher όπου μπορείς να επιλέξεις τις επιλογές που θέλεις και να εκτελέσεις το shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

Η επιλογή **Create Dump** θα κάνει dump το τελικό shellcode αν γίνει κάποια αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για να κατεβάσεις το decoded shellcode). Η επιλογή **start offset** μπορεί να είναι χρήσιμη για να ξεκινήσεις το shellcode σε συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για να κάνεις debug το shellcode χρησιμοποιώντας το scDbg terminal (αν και βρίσκω ότι οποιαδήποτε από τις προηγούμενες επιλογές είναι καλύτερη γι' αυτό, καθώς θα μπορείς να χρησιμοποιήσεις Ida ή x64dbg).

### Disassembling using CyberChef

Ανέβασε το shellcode αρχείο σου ως input και χρησιμοποίησε το παρακάτω recipe για να το decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Το obfuscation **Mixed Boolean-Arithmetic (MBA)** κρύβει απλές εκφράσεις όπως `x + y` πίσω από formulas που συνδυάζουν αριθμητικούς τελεστές (`+`, `-`, `*`) και bitwise operators (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες συνήθως είναι σωστές μόνο υπό **fixed-width modular arithmetic**, οπότε τα carries και τα overflows έχουν σημασία:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Αν απλοποιήσεις αυτού του είδους την έκφραση με generic algebra tooling, μπορείς εύκολα να πάρεις λάθος αποτέλεσμα επειδή αγνοήθηκαν τα bit-width semantics.

### Practical workflow

1. **Keep the original bit-width** από το lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Classify the expression** πριν προσπαθήσεις να το απλοποιήσεις:
- **Linear**: weighted sums of bitwise atoms
- **Semilinear**: linear plus constant masks such as `x & 0xFF`
- **Polynomial**: products appear
- **Mixed**: products and bitwise logic are interleaved, often with repeated subexpressions
3. **Verify every candidate rewrite** με random testing or an SMT proof. Αν η ισοδυναμία δεν μπορεί να αποδειχθεί, κράτα την αρχική έκφραση αντί να μαντέψεις.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός MBA simplifier για malware analysis και protected-binary reversing. Κατηγοριοποιεί την έκφραση και τη δρομολογεί μέσα από specialized pipelines αντί να εφαρμόζει ένα generic rewrite pass σε όλα.

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
Χρήσιμες περιπτώσεις:

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean inputs, παράγει ένα signature, και εκτελεί παράλληλα several recovery methods όπως pattern matching, ANF conversion, και coefficient interpolation.
- **Semilinear MBA**: constant-masked atoms ξαναχτίζονται με bit-partitioned reconstruction ώστε οι masked regions να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: τα products αποσυντίθενται σε cores και επαναλαμβανόμενα subexpressions μπορούν να ανυψωθούν σε temporaries πριν απλοποιηθεί η outer relation.

Παράδειγμα ενός mixed identity που συνήθως αξίζει να προσπαθήσετε να ανακτήσετε:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Αυτό μπορεί να καταρρεύσει σε:
```c
x * y
```
### Σημειώσεις Reversing

- Προτίμησε να τρέχεις το CoBRA πάνω σε **lifted IR expressions** ή σε decompiler output αφού έχεις απομονώσει την ακριβή computation.
- Χρησιμοποίησε το `--bitwidth` ρητά όταν το expression προήλθε από masked arithmetic ή narrow registers.
- Αν χρειάζεσαι πιο ισχυρό proof step, έλεγξε τις τοπικές σημειώσεις Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), κάτι που είναι χρήσιμο όταν θέλεις να κανονικοποιήσεις MBA-heavy LLVM IR πριν από μεταγενέστερα analysis passes.
- Τα unsupported carry-sensitive mixed-domain residuals θα πρέπει να αντιμετωπίζονται ως ένδειξη ότι πρέπει να κρατήσεις το αρχικό expression και να αιτιολογήσεις το carry path χειροκίνητα.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτό το obfuscator **τροποποιεί όλες τις instructions για `mov`**(ναι, πραγματικά cool). Επίσης χρησιμοποιεί interruptions για να αλλάζει τα executions flows. Για περισσότερες πληροφορίες για το πώς λειτουργεί:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Αν είσαι τυχερός το [demovfuscator](https://github.com/kirschju/demovfuscator) θα deofuscate το binary. Έχει αρκετές εξαρτήσεις
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε ένα **CTF, αυτό το workaround για να βρείτε το flag** μπορεί να είναι πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point** κάντε αναζήτηση στις functions με `::main` όπως στο:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα main function.\
Έχοντας το **όνομα** των **functions** που καλούνται, αναζητήστε τα στο **Internet** για να μάθετε για τα **inputs** και τα **outputs** τους.

### Recovering Rust strings from ELF firmware

Σε **Rust ELF** binaries, πολλές static strings δεν αναφέρονται ως C-style NUL-terminated pointers. Ένα συνηθισμένο **rustc** layout είναι ένα **pointer/length tuple** μέσα στο **`.data.rel.ro`** που δείχνει προς το πραγματικό string blob που είναι αποθηκευμένο στο **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικά strings ή να χάσει εντελώς cross-references.

Γρήγορη ροή εργασίας:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Πάρε τη virtual address και το μέγεθος του **`.rodata`**.
2. Κάνε enumerate το **`.data.rel.ro`** μία λέξη τη φορά.
3. Θεώρησε οποιαδήποτε τιμή μέσα στο `.rodata` address range ως υποψήφιο string pointer.
4. Θεώρησε την επόμενη λέξη ως το υποψήφιο μήκος.
5. Εφάρμοσε sanity filters (για παράδειγμα, κράτα μήκη μεταξύ **4** και **100** bytes).
6. Διάβασε ακριβώς `length` bytes από το `.rodata` αντί να κάνεις scan μέχρι το `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Αυτό είναι ιδιαίτερα χρήσιμο στο reversing firmware, επειδή τα ανακτημένα Rust strings συχνά αποκαλύπτουν **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers, και auth-related logic**.

Αν το Ghidra χάσει αυτά τα strings, τρέξε ένα custom script/plugin που εφαρμόζει την ίδια heuristic και δημιουργεί string data στα αναφερόμενα `.rodata` offsets. Τα δημοσιευμένα `rust-strings` και `RustStrings.py` tools από Pen Test Partners είναι καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness, και section layouts**.

## **Delphi**

Για Delphi compiled binaries μπορείς να χρησιμοποιήσεις [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειαστεί να κάνεις reverse ένα Delphi binary, θα πρότεινα να χρησιμοποιήσεις το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Απλώς πάτησε **ATL+f7** (import python plugin in IDA) και επίλεξε το python plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει function names δυναμικά στην αρχή του debugging. Μετά την εκκίνηση του debugging πάτησε ξανά το Start button (το πράσινο ή f9) και ένα breakpoint θα χτυπήσει στην αρχή του πραγματικού code.

Είναι επίσης πολύ ενδιαφέρον επειδή αν πατήσεις ένα κουμπί στη γραφική εφαρμογή ο debugger θα σταματήσει στη function που εκτελείται από αυτό το κουμπί.

## Golang

Αν χρειαστεί να κάνεις reverse ένα Golang binary, θα πρότεινα να χρησιμοποιήσεις το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Απλώς πάτησε **ATL+f7** (import python plugin in IDA) και επίλεξε το python plugin.

Αυτό θα επιλύσει τα names των functions.

## Compiled Python

Σε αυτή τη σελίδα μπορείς να βρεις πώς να πάρεις τον python code από ένα ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Αν πάρεις το **binary** ενός GBA game, μπορείς να χρησιμοποιήσεις διαφορετικά tools για να το **emulate** και να το **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Περιέχει debugger με interface
- [**mgba** ](https://mgba.io)- Περιέχει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στο _**Options --> Emulation Setup --> Controls**_** ** μπορείς να δεις πώς να πατάς τα Game Boy Advance **buttons**

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Όταν πατηθούν, κάθε **key έχει μια value** για να το αναγνωρίζει:
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
Λοιπόν, σε αυτό το είδος προγράμματος, το ενδιαφέρον μέρος θα είναι το **πώς το πρόγραμμα χειρίζεται το user input**. Στη διεύθυνση **0x4000130** θα βρεις τη συνήθως συναντώμενη function: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείς να δεις ότι η function καλείται από τη **FUN_080015a8** (addresses: _0x080015fa_ and _0x080017ac_).

Σε εκείνη τη function, μετά από κάποιες init operations (χωρίς καμία σημασία):
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
Βρέθηκε αυτός ο κώδικας:
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
Το τελευταίο if ελέγχει αν το **`uVar4`** είναι στα **last Keys** και όχι το τρέχον key, επίσης αυτό λέγεται ότι αφήνεις ένα κουμπί (το τρέχον key αποθηκεύεται στο **`uVar1`**).
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
Στον προηγούμενο code μπορείς να δεις ότι συγκρίνουμε το **uVar1** (το σημείο όπου βρίσκεται η **value of the pressed button**) με κάποιες values:

- Πρώτα, συγκρίνεται με την **value 4** (**SELECT** button): Στο challenge αυτό το button καθαρίζει την οθόνη
- Μετά, συγκρίνεται με την **value 8** (**START** button): Στο challenge αυτό ελέγχει αν ο code είναι valid για να πάρεις το flag.
- Σε αυτή την περίπτωση η var **`DAT_030000d8`** συγκρίνεται με 0xf3 και αν η value είναι η ίδια εκτελείται κάποιο code.
- Σε κάθε άλλη περίπτωση, ελέγχεται κάποιο cont (**`DAT_030000d4`**). Είναι cont γιατί προστίθεται 1 αμέσως μετά την είσοδο στον code.\
**Α**ν είναι μικρότερο από 8, γίνεται κάτι που involves **adding** values στο **`DAT_030000d8`** (ουσιαστικά προσθέτει τις values των keys που πατιούνται σε αυτή τη var όσο το cont είναι μικρότερο από 8).

Άρα, σε αυτό το challenge, γνωρίζοντας τις values των buttons, έπρεπε να **πατήσεις έναν συνδυασμό με μήκος μικρότερο από 8, έτσι ώστε το αποτέλεσμα της πρόσθεσης να είναι 0xf3.**

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
