# Εργαλεία Reversing και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία Reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **decompile** από wasm (binary) σε wat (clear text)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **compile** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για decompilation.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας decompiler που **κάνει decompile και εξετάζει πολλαπλές μορφές**, συμπεριλαμβανομένων **libraries** (.dll), **Windows metadata files** (.winmd) και **executables** (.exe). Μετά το decompile, ένα assembly μπορεί να αποθηκευτεί ως project του Visual Studio (.csproj).

Το πλεονέκτημα εδώ είναι ότι, αν απαιτείται η αποκατάσταση χαμένου source code από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύκολη πλοήγηση μέσα στον decompiled κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο add-in model και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει τις ακριβείς ανάγκες σας, το .NET reflector εξοικονομεί χρόνο και απλοποιεί το development. Ας δούμε το πλήθος των reverse engineering υπηρεσιών που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα για το πώς ρέουν τα δεδομένα μέσα από ένα library ή component
- Παρέχει εικόνα για την υλοποίηση και χρήση των .NET languages και frameworks
- Εντοπίζει undocumented και unexposed functionality για να αξιοποιήσετε περισσότερο τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή τοποθεσία των errors στον κώδικά σας, σε third-party components και libraries.
- Κάνει debug στο source όλου του .NET κώδικα με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το έχετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **search ILSpy**).\
Αν χρειάζεται να κάνετε **decompile**, **modify** και να κάνετε ξανά **recompile**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα actively maintained fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια function).

### DNSpy Logging

Για να κάνετε το **DNSpy log κάποιες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε το ακόλουθο snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Για να κάνετε debug σε κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξετε τα **Assembly attributes** που σχετίζονται με το **debugging**:

![DNSpy Logging - DNSpy Debugging: Αρχικά, αλλάξτε τα Assembly attributes που σχετίζονται με το debugging](<../../images/image (973).png>)

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

Αυτό είναι απαραίτητο, επειδή αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και ενδέχεται κατά το debugging ένα **breakpoint να μην επιτευχθεί ποτέ** ή ορισμένες **μεταβλητές να μην υπάρχουν**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:
```
iisreset /noforce
```
Στη συνέχεια, προκειμένου να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και στην **Debug Tab** να επιλέξετε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, προκειμένου να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και μέσα από το Debug Tab να επιλέξετε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο _Debug >> Break All_ και στη συνέχεια στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο Debug Break All και στη συνέχεια στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο Debug Break All και στη συνέχεια στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε τον **Windbg** debugger
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Διαμορφώστε τις **παραμέτρους** της εκτέλεσης, εισάγοντας το **path προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Διαμορφώστε τις παραμέτρους της εκτέλεσης, εισάγοντας το path προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα διακόπτεται κάθε φορά που φορτώνεται ένα DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση σε events φόρτωσης modules, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση από ό,τι με το workflow του x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε το Command Line** ( _File --> Change Command Line_ ) και ορίστε το path του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια **ξεκινήστε την εκτέλεση**. Ο debugger θα διακόπτεται σε κάθε dll main και, κάποια στιγμή, θα **σταματήσει στο dll Entry του dll σας**. Από εκεί, απλώς αναζητήστε τα σημεία στα οποία θέλετε να τοποθετήσετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας στο **επάνω μέρος του παραθύρου του win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει διακοπεί μέσα στο DLL που θέλετε να κάνετε debug.

## GUI Apps / Videogames

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να βρίσκετε πού αποθηκεύονται σημαντικές τιμές μέσα στη μνήμη ενός running game και να τις αλλάζετε. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/reverse engineering tool για το GNU Project Debugger (GDB), με έμφαση στα games. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιοδήποτε θέμα σχετικό με reverse-engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web service σάς επιτρέπει να συγκρίνετε το output διαφορετικών decompilers σε μικρά executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει το **shellcode**, εκτυπώνει τη **διεύθυνση μνήμης** του και διακόπτει την εκτέλεση.\
Συνδέστε έναν debugger, όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εκτυπώθηκε και συνεχίστε την εκτέλεση για να κάνετε debugging στο shellcode.

Η σελίδα github των releases περιέχει zips με τα compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να την κάνετε compile, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, κάντε copy και paste τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει το shellcode και εισέρχεται σε έναν infinite loop. Συνδέστε τον debugger, συνεχίστε για **2–5 seconds**, διακόψτε την εκτέλεση μέσα σε αυτόν τον loop και προχωρήστε μέχρι την επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Debugger σε παύση στον infinite loop του jmp2it ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια compiled έκδοση του [jmp2it από τη σελίδα των releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να κάνετε "Open File" και "Open Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο, το έκανε decompile σωστά, αλλά όταν το άνοιξα ως shellcode δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα analysis όταν ανοίγει τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσετε το emulation από το σημείο που θέλετε, ορίστε ένα bp εκεί και, προφανώς, το Cutter θα ξεκινήσει αυτόματα το emulation από εκεί:

![Ορισμός breakpoint στο επιθυμητό shellcode entry πριν από την έναρξη του Cutter emulation](<../../images/image (589).png>)

![Ο emulator του Cutter σε παύση στο επιλεγμένο shellcode breakpoint](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του emulated shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει για πράγματα όπως **ποιες functions** χρησιμοποιεί το shellcode και αν το shellcode κάνει **decoding** του εαυτού του στη μνήμη.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
Το scDbg διαθέτει επίσης ένα γραφικό launcher, όπου μπορείτε να επιλέξετε τις options που θέλετε και να εκτελέσετε το shellcode

![Γραφικός launcher του scDbg για την επιλογή options emulation και tracing του shellcode](<../../images/image (258).png>)

Η option **Create Dump** θα κάνει dump το τελικό shellcode, αν έχει γίνει οποιαδήποτε αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του decoded shellcode). Το **start offset** μπορεί να είναι χρήσιμο για την εκκίνηση του shellcode από ένα συγκεκριμένο offset. Η option **Debug Shell** είναι χρήσιμη για το debugging του shellcode μέσω του terminal του scDbg (ωστόσο θεωρώ ότι οποιαδήποτε από τις options που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Disassembling using CyberChef

Κάντε upload το αρχείο shellcode ως input και χρησιμοποιήστε την ακόλουθη recipe για να το κάνετε decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Το **Mixed Boolean-Arithmetic (MBA)** obfuscation αποκρύπτει απλές expressions, όπως `x + y`, πίσω από formulas που συνδυάζουν arithmetic (`+`, `-`, `*`) και bitwise operators (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι identities είναι συνήθως σωστές μόνο υπό **arithmetic modulo σταθερού πλάτους**, επομένως τα carries και τα overflows έχουν σημασία:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Αν απλοποιήσετε αυτόν τον τύπο έκφρασης με generic algebra tooling, μπορείτε εύκολα να λάβετε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκαν τα semantics του bit-width.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό bit-width** από το lifted code/IR/decompiler output (`8/16/32/64` bits).
2. **Ταξινομήστε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
- **Γραμμική**: weighted sums από bitwise atoms
- **Semilinear**: γραμμική έκφραση συν constant masks όπως `x & 0xFF`
- **Πολυωνυμική**: εμφανίζονται products
- **Μεικτή**: products και bitwise logic είναι interleaved, συχνά με repeated subexpressions
3. **Επαληθεύστε κάθε υποψήφιο rewrite** με random testing ή proof μέσω SMT. Αν δεν μπορεί να αποδειχθεί η equivalence, διατηρήστε την αρχική έκφραση αντί να κάνετε υποθέσεις.

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός MBA simplifier για malware analysis και protected-binary reversing. Ταξινομεί την έκφραση και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει ένα generic rewrite pass σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean inputs, παράγει ένα signature και δοκιμάζει παράλληλα διάφορες recovery methods, όπως pattern matching, ANF conversion και coefficient interpolation.
- **Semilinear MBA**: Τα constant-masked atoms ανακατασκευάζονται με bit-partitioned reconstruction, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα products αποσυντίθενται σε cores και οι repeated subexpressions μπορούν να μετατραπούν σε temporaries πριν από την απλοποίηση της outer relation.

Παράδειγμα ενός mixed identity που συνήθως αξίζει να επιχειρήσετε να ανακτήσετε:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Αυτό μπορεί να συμπτυχθεί σε:
```c
x * y
```
### Σημειώσεις reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η expression προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ισχυρότερο proof step, ελέγξτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), το οποίο είναι χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από μεταγενέστερα analysis passes.
- Τα unsupported carry-sensitive mixed-domain residuals θα πρέπει να αντιμετωπίζονται ως ένδειξη ότι πρέπει να διατηρήσετε την αρχική expression και να αναλύσετε χειροκίνητα το carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με instruction sequences βασισμένα σε `mov` και χρησιμοποιεί signal/exception handling για να τροποποιεί το control flow. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε ένα **CTF, αυτό το workaround για την εύρεση του flag** μπορεί να είναι πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point**, αναζητήστε τις συναρτήσεις με `::main`, όπως στο:

![Εύρεση ενός Rust entry point στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για double-colon main](<../../images/image (1080).png>)

Σε αυτήν την περίπτωση, το binary ονομαζόταν authenticator, επομένως είναι αρκετά προφανές ότι πρόκειται για την ενδιαφέρουσα main function.\
Έχοντας το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε περισσότερα σχετικά με τα **inputs** και τα **outputs** τους.

### Ανάκτηση Rust strings από ELF firmware

Σε **Rust ELF** binaries, πολλά static strings δεν αναφέρονται ως pointers τερματισμένοι με NUL σε στυλ C. Μια συνηθισμένη διάταξη του `rustc` είναι ένα **tuple pointer/length** μέσα στο **`.data.rel.ro`**, το οποίο δείχνει στο πραγματικό string blob που είναι αποθηκευμένο στο **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Αυτό σημαίνει ότι τα `strings` ή η προεπιλεγμένη ανάλυση του Ghidra ενδέχεται να συγχωνεύσουν γειτονικά strings ή να παραλείψουν εντελώς τις cross-references.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Αποκτήστε την virtual address και το μέγεθος του **`.rodata`**.
2. Enumerate το **`.data.rel.ro`** μία word κάθε φορά.
3. Αντιμετωπίστε κάθε τιμή μέσα στο address range του `.rodata` ως πιθανό string pointer.
4. Αντιμετωπίστε την επόμενη word ως το υποψήφιο length.
5. Εφαρμόστε sanity filters (για παράδειγμα, κρατήστε lengths μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata` αντί να κάνετε scanning μέχρι το `0x00`.

Ελάχιστη λογική extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή τα ανακτημένα Rust strings συχνά αποκαλύπτουν **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers και auth-related logic**.

Αν το Ghidra δεν εντοπίζει αυτά τα strings, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια heuristic και δημιουργεί string data στα αναφερόμενα offsets του `.rodata`. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` από την Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για Delphi compiled binaries μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα function names κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού code.

Αν πατήσετε ένα κουμπί στη graphical application, ο debugger μπορεί να σταματήσει στη function που καλείται από αυτό το κουμπί.

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

Αν αποκτήσετε το **binary** ενός GBA game, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να το **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την debug version_) - Περιέχει debugger με interface
- [**mgba** ](https://mgba.io)- Περιέχει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **buttons** του Game Boy Advance

![διαμόρφωση controls του no$gba που εμφανίζει τις αντιστοιχίσεις των buttons του Game Boy Advance](<../../images/image (581).png>)

Όταν πατηθεί, κάθε **key έχει μια τιμή** που το αναγνωρίζει:
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
Λοιπόν, σε αυτού του είδους τα προγράμματα, το ενδιαφέρον μέρος θα είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνάρτηση που συναντάται συχνά: **KEYINPUT**.

![Προβολή του Ghidra ενός binary GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη συνάρτηση, μετά από ορισμένες λειτουργίες init (χωρίς ιδιαίτερη σημασία):
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
Βρέθηκε ο ακόλουθος κώδικας:
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
Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **last Keys** και δεν είναι το τρέχον πλήκτρο, κάτι που ονομάζεται επίσης letting go off a button (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).
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
Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε το **uVar1** (τη θέση όπου βρίσκεται η **τιμή του πατημένου κουμπιού**) με ορισμένες τιμές:

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): Σε αυτό το challenge, το συγκεκριμένο κουμπί καθαρίζει την οθόνη
- Στη συνέχεια, συγκρίνει την τιμή με το **8** (κουμπί **START**). Σε αυτό το challenge, αυτή η διαδρομή ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
- Σε αυτή την περίπτωση, η var **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν η τιμή είναι ίδια, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων συσσωρεύονται στο `DAT_030000d8`.

Επομένως, σε αυτό το challenge, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, ώστε το αποτέλεσμα της πρόσθεσης να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένο writeup του challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Απλοποίηση του MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο CoBRA του Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversing για GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
