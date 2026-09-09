# Εργαλεία Reversing και Βασικές Μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **decompile** από wasm (δυαδικό) σε wat (απλό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **compile** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για decompilation.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας decompiler που **κάνει decompile και εξετάζει πολλαπλές μορφές**, συμπεριλαμβανομένων των **libraries** (.dll), των **Windows metadata file**s (.winmd) και των **executables** (.exe). Μετά το decompile, ένα assembly μπορεί να αποθηκευτεί ως project του Visual Studio (.csproj).

Το πλεονέκτημα εδώ είναι ότι, αν απαιτείται η αποκατάσταση χαμένου source code από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύκολη πλοήγηση στον decompiled κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο add-in model και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει τις ακριβείς ανάγκες σας, το .NET reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας εξετάσουμε το πλήθος των υπηρεσιών reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα για τον τρόπο με τον οποίο ρέουν τα δεδομένα μέσα από μια library ή ένα component
- Παρέχει εικόνα για την υλοποίηση και τη χρήση των .NET languages και frameworks
- Εντοπίζει undocumented και unexposed λειτουργίες, ώστε να αξιοποιείτε περισσότερο τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή τοποθεσία σφαλμάτων στον κώδικά σας, σε third-party components και libraries.
- Κάνει debug στον source όλων των .NET code με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **search ILSpy**).\
Αν χρειάζεται να κάνετε **decompile**, **modify** και ξανά **recompile**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα actively maintained fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια function).

### DNSpy Logging

Για να κάνετε το **DNSpy log ορισμένες πληροφορίες σε ένα file**, μπορείτε να χρησιμοποιήσετε το ακόλουθο snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Αποσφαλμάτωση DNSpy

Για να κάνετε debugging κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **Assembly attributes** που σχετίζονται με το **debugging**:

![Καταγραφή DNSpy - Αποσφαλμάτωση DNSpy: Αρχικά, αλλάξτε τα Assembly attributes που σχετίζονται με το debugging](<../../images/image (973).png>)

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

![DNSpy Logging - DNSpy Debugging: Και κάντε κλικ στο compile](<../../images/image (314) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω του _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω του File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, επειδή αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και υπάρχει πιθανότητα, κατά το debugging, ένα **break-point να μην ενεργοποιηθεί ποτέ** ή ορισμένες **variables να μην υπάρχουν**.

Στη συνέχεια, αν η εφαρμογή σας .NET **εκτελείται** από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:
```
iisreset /noforce
```
Στη συνέχεια, για να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και μέσα από το **Debug Tab** να επιλέξετε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και μέσα από το Debug Tab να επιλέξετε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο _Debug >> Break All_ και στη συνέχεια στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο Debug Break All και στη συνέχεια στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο Debug Break All και στη συνέχεια στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε τον **Windbg** debugger
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Ρυθμίστε τις **parameters** της εκτέλεσης, εισάγοντας το **path to the DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Ρυθμίστε τις parameters της εκτέλεσης, εισάγοντας το path to the DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα σταματά όταν φορτώνεται κάθε DLL**. Όταν, λοιπόν, το rundll32 φορτώσει το DLL σας, η εκτέλεση θα σταματήσει.

Αυτή η μέθοδος σταματά στα module-load events, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση σε σχέση με το workflow του x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) και ορίστε το path του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και, κάποια στιγμή, θα **σταματήσει στο dll Entry του dll σας**. Από εκεί, απλώς αναζητήστε τα σημεία στα οποία θέλετε να τοποθετήσετε ένα breakpoint.

Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε**, κοιτάζοντας στο **επάνω μέρος του παραθύρου του win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε, κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει σταματήσει μέσα στο DLL που θέλετε να κάνετε debug.

## GUI Apps / Videogames

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να βρίσκετε πού αποθηκεύονται σημαντικές τιμές μέσα στη memory ενός game που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες στο:

{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/reverse engineering tool για το GNU Project Debugger (GDB), με έμφαση στα games. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιοδήποτε θέμα σχετίζεται με reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web service σάς επιτρέπει να συγκρίνετε το output διαφορετικών decompilers σε μικρά executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει το **shellcode**, εμφανίζει τη **memory address** του και σταματά την εκτέλεση.\
Συνδεθείτε με έναν debugger, όπως οι IDA ή x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εμφανίστηκε και συνεχίστε την εκτέλεση για να κάνετε debug στο shellcode.

Η σελίδα releases στο github περιέχει zips με τα compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να την κάνετε compile, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, κάντε copy και paste τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει το shellcode και εισέρχεται σε έναν infinite loop. Συνδεθείτε με τον debugger, συνεχίστε για **2–5 δευτερόλεπτα**, σταματήστε μέσα σε αυτόν τον loop και προχωρήστε στο επόμενο call που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Debugger σε παύση στον infinite loop του jmp2it, ακριβώς πριν από το call προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια compiled έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter επιτρέπει τις επιλογές "Open File" και "Open Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο, το έκανε decompile σωστά, αλλά όταν το άνοιξα ως shellcode δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης κατά το άνοιγμα των ίδιων bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσετε το emulation από το σημείο που θέλετε, ορίστε ένα bp εκεί και, aparentemente, το Cutter θα ξεκινήσει αυτόματα το emulation από εκεί:

![Ορισμός breakpoint στο επιθυμητό shellcode entry πριν από την έναρξη του emulation στο Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter σε παύση στο επιλεγμένο shellcode breakpoint](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του emulated shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει για πράγματα όπως **ποιες functions** χρησιμοποιεί το shellcode και αν το shellcode κάνει **decoding** του εαυτού του στη memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
Το scDbg διαθέτει επίσης έναν graphical launcher, όπου μπορείτε να επιλέξετε τις options που θέλετε και να εκτελέσετε το shellcode

![scDbg graphical launcher for selecting shellcode emulation and tracing options](<../../images/image (258).png>)

Η option **Create Dump** θα κάνει dump το τελικό shellcode, αν έχει γίνει κάποια αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του decoded shellcode). Το **start offset** μπορεί να είναι χρήσιμο για την εκκίνηση του shellcode σε συγκεκριμένο offset. Η option **Debug Shell** είναι χρήσιμη για το debugging του shellcode χρησιμοποιώντας το scDbg terminal (ωστόσο θεωρώ ότι οποιαδήποτε από τις options που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτόν τον σκοπό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Disassembling using CyberChef

Κάντε upload το shellcode file ως input και χρησιμοποιήστε το ακόλουθο recipe για να το κάνετε decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Το **Mixed Boolean-Arithmetic (MBA)** obfuscation αποκρύπτει απλές εκφράσεις, όπως `x + y`, πίσω από formulas που συνδυάζουν arithmetic (`+`, `-`, `*`) και bitwise operators (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι identities είναι συνήθως σωστές μόνο υπό **fixed-width modular arithmetic**, επομένως τα carries και τα overflows έχουν σημασία:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Αν απλοποιήσετε αυτό το είδος έκφρασης με generic algebra tooling, μπορείτε εύκολα να καταλήξετε σε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκαν τα bit-width semantics.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό bit-width** από το lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Κατηγοριοποιήστε την έκφραση** πριν προσπαθήσετε να την απλοποιήσετε:
- **Linear**: weighted sums από bitwise atoms
- **Semilinear**: linear συν constant masks όπως `x & 0xFF`
- **Polynomial**: εμφανίζονται products
- **Mixed**: products και bitwise logic είναι interleaved, συχνά με repeated subexpressions
3. **Επαληθεύστε κάθε υποψήφιο rewrite** με random testing ή απόδειξη SMT. Αν η ισοδυναμία δεν μπορεί να αποδειχθεί, διατηρήστε την αρχική έκφραση αντί να κάνετε εικασίες.

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός MBA simplifier για malware analysis και protected-binary reversing. Κατηγοριοποιεί την έκφραση και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει ένα generic rewrite pass σε όλες τις εκφράσεις.<sup>[[2]](#references)</sup>

Γρήγορη χρήση:
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

- **Linear MBA**: το CoBRA αξιολογεί την έκφραση σε Boolean inputs, παράγει μια signature και ανταγωνίζεται αρκετές μεθόδους ανάκτησης, όπως pattern matching, μετατροπή σε ANF και interpolation συντελεστών.
- **Semilinear MBA**: τα constant-masked atoms ανακατασκευάζονται με bit-partitioned reconstruction, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: τα γινόμενα αποσυντίθενται σε cores και οι επαναλαμβανόμενες subexpressions μπορούν να μεταφερθούν σε temporaries πριν από την απλοποίηση της εξωτερικής σχέσης.

Παράδειγμα μιας mixed identity που συνήθως αξίζει να προσπαθήσετε να ανακτήσετε:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Αυτό μπορεί να συμπτυχθεί σε:
```c
x * y
```
### Σημειώσεις Reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ένα ισχυρότερο βήμα απόδειξης, ελέγξτε τις τοπικές σημειώσεις Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), το οποίο είναι χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από μεταγενέστερα analysis passes.
- Τα unsupported carry-sensitive mixed-domain residuals θα πρέπει να αντιμετωπίζονται ως ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα το carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτό το obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με instruction sequences βασισμένα σε `mov` και χρησιμοποιεί signal/exception handling για να μεταβάλλει τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε ένα **CTF, αυτό το workaround για την εύρεση του flag** μπορεί να είναι πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point**, αναζητήστε τις functions με `::main`, όπως στο:

![Εύρεση ενός Rust entry point στο Ghidra με αναζήτηση ονομάτων functions για main με διπλή άνω και κάτω τελεία](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το binary ονομαζόταν authenticator, επομένως είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα main function.\
Έχοντας το **όνομα** των **functions** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε περισσότερα σχετικά με τα **inputs** και τα **outputs** τους.

### Ανάκτηση Rust strings από ELF firmware

Στα **Rust ELF** binaries, πολλά static strings δεν αναφέρονται ως C-style NUL-terminated pointers. Ένα συνηθισμένο layout του `rustc` είναι ένα **pointer/length tuple** μέσα στο **`.data.rel.ro`**, το οποίο δείχνει στο πραγματικό string blob που είναι αποθηκευμένο στο **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Αυτό σημαίνει ότι τα `strings` ή η προεπιλεγμένη ανάλυση του Ghidra ενδέχεται να συγχωνεύσουν γειτονικά strings ή να παραλείψουν εντελώς cross-references.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Λάβετε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία λέξη τη φορά.
3. Αντιμετωπίστε οποιαδήποτε τιμή εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Αντιμετωπίστε την επόμενη λέξη ως το υποψήφιο μήκος.
5. Εφαρμόστε sanity filters (για παράδειγμα, διατηρήστε μήκη μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata` αντί να συνεχίσετε τη σάρωση μέχρι το `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες Rust strings συχνά αποκαλύπτουν **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers και auth-related logic**.

Αν το Ghidra δεν εντοπίζει αυτές τις strings, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια heuristic και δημιουργεί string data στα αναφερόμενα `.rodata` offsets. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` από την Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν γίνει compile από Delphi μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα function names στην αρχή του debugging. Αφού ξεκινήσετε το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και ένα breakpoint θα ενεργοποιηθεί στην αρχή του πραγματικού code.

Αν πατήσετε ένα button στη graphical application, ο debugger μπορεί να σταματήσει στη function που καλείται από αυτό το button.

## Golang

Αν πρέπει να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα names των functions.

## Compiled Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον python code από ένα ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός GBA game, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να κάνετε **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την debug version_) - Περιλαμβάνει debugger με interface
- [**mgba** ](https://mgba.io)- Περιλαμβάνει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στην ενότητα _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **buttons** του Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Όταν πατηθεί, κάθε **key έχει μια value** για την αναγνώρισή του:
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
Επομένως, σε αυτού του είδους τα προγράμματα, το ενδιαφέρον μέρος θα είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνήθως χρησιμοποιούμενη συνάρτηση: **KEYINPUT**.

![Προβολή του Ghidra ενός δυαδικού αρχείου GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη συνάρτηση, μετά από ορισμένες αρχικές λειτουργίες (χωρίς καμία σημασία):
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
Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στο **last Keys** και δεν είναι το τρέχον key, κάτι που ονομάζεται επίσης απελευθέρωση ενός button (το τρέχον key αποθηκεύεται στο **`uVar1`**).
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
Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε το **uVar1** (τη θέση όπου βρίσκεται η **value του πατημένου κουμπιού**) με ορισμένες values:

- Αρχικά, συγκρίνεται με τη **value 4** (κουμπί **SELECT**): στο challenge αυτό το κουμπί καθαρίζει την οθόνη
- Έπειτα συγκρίνει τη value με το **8** (κουμπί **START**). Σε αυτό το challenge, αυτό το path ελέγχει αν ο κωδικός που εισήχθη είναι valid.
- Σε αυτή την περίπτωση, η var **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν η value είναι ίδια, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας counter (`DAT_030000d4`).\
Όσο ο counter είναι μικρότερος από 8, οι values των πατημένων πλήκτρων συσσωρεύονται στο `DAT_030000d8`.

Επομένως, σε αυτό το challenge, γνωρίζοντας τις values των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, του οποίου το αποτέλεσμα της πρόσθεσης είναι 0xf3.**

**Reference για αυτό το tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Απλοποίηση του MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [CoBRA repository της Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
