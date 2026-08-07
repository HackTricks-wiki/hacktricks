# Εργαλεία Reversing & Βασικές Μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία Reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **decompile** από wasm (binary) σε wat (clear text)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **compile** από wat σε wasm
- μπορείτε επίσης να δοκιμάσετε το [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) για decompile

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένα decompiler που **κάνει decompile και εξετάζει πολλαπλές μορφές**, συμπεριλαμβανομένων **libraries** (.dll), **Windows metadata file**s (.winmd) και **executables** (.exe). Μετά το decompile, ένα assembly μπορεί να αποθηκευτεί ως Visual Studio project (.csproj).

Το πλεονέκτημα εδώ είναι ότι, αν απαιτείται η αποκατάσταση χαμένου source code από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση μέσα στον decompiled code, καθιστώντας το ένα από τα ιδανικά εργαλεία για **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο add-in model και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει τις ακριβείς ανάγκες σας, το .NET reflector εξοικονομεί χρόνο και απλοποιεί το development. Ας δούμε το πλήθος των reverse engineering υπηρεσιών που παρέχει αυτό το εργαλείο:

- Παρέχει insight σχετικά με τον τρόπο ροής των δεδομένων μέσα από ένα library ή component
- Παρέχει insight σχετικά με την υλοποίηση και τη χρήση των .NET languages και frameworks
- Εντοπίζει undocumented και unexposed functionality, ώστε να αξιοποιείτε περισσότερο τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή τοποθεσία των errors στον κώδικά σας, σε third-party components και libraries.
- Κάνει debug στο source όλου του .NET code με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κάνετε download το git. Κάντε κλικ στις **Extensions** και **search ILSpy**).\
Αν χρειάζεται να κάνετε **decompile**, **modify** και να κάνετε ξανά **recompile**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα fork του που συντηρείται ενεργά, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια function).

### DNSpy Logging

Για να κάνετε το **DNSpy log κάποιες πληροφορίες σε ένα file**, μπορείτε να χρησιμοποιήσετε το παρακάτω snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Αποσφαλμάτωση DNSpy

Για να κάνετε αποσφαλμάτωση κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξετε τα **Assembly attributes** που σχετίζονται με την **αποσφαλμάτωση**:

![Καταγραφή DNSpy - Αποσφαλμάτωση DNSpy: Αρχικά, αλλάξτε τα Assembly attributes που σχετίζονται με την αποσφαλμάτωση](<../../images/image (973).png>)

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

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, επειδή αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **optimisations** στον κώδικα και ενδέχεται κατά το debugging να μην ενεργοποιηθεί ποτέ ένα **break-point** ή να μην υπάρχουν ορισμένες **variables**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να κάνετε **restart** με:
```
iisreset /noforce
```
Στη συνέχεια, για να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και στην **Debug Tab** να επιλέξετε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και στην Debug Tab να επιλέξετε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο _Debug >> Break All_ και στη συνέχεια στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και στη συνέχεια στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και στη συνέχεια στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και κάντε κλικ στο **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και κάντε κλικ στο Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε τον **Windbg** debugger
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Ρυθμίστε τις **parameters** της εκτέλεσης, εισάγοντας το **path προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Ρυθμίστε τις parameters της εκτέλεσης, εισάγοντας το path προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα σταματά κάθε φορά που φορτώνεται ένα DLL**. Όταν, λοιπόν, το rundll32 φορτώσει το DLL σας, η εκτέλεση θα σταματήσει.

Όμως, πώς μπορείτε να μεταβείτε στον κώδικα του DLL που φορτώθηκε; Με αυτή τη μέθοδο, δεν γνωρίζω πώς.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη Command Line** ( _File --> Change Command Line_ ) και ορίστε το path του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και, κάποια στιγμή, θα **σταματήσει στο dll Entry του dll σας**. Από εκεί, αναζητήστε απλώς τα σημεία στα οποία θέλετε να τοποθετήσετε ένα breakpoint.

Σημειώστε ότι όταν η εκτέλεση σταματά για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε**, κοιτάζοντας στο **πάνω μέρος του παραθύρου του win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση σταματά για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε, κοιτάζοντας στο πάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Έτσι, κοιτάζοντας εκεί, μπορείτε να δείτε πότε η εκτέλεση σταμάτησε στο dll που θέλετε να κάνετε debug.

## GUI Apps / Videogames

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να βρίσκετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός running game και να τις αλλάζετε. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/reverse engineering tool για το GNU Project Debugger (GDB), εστιασμένο στα games. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιοδήποτε θέμα σχετίζεται με το reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web service σάς επιτρέπει να συγκρίνετε το output διαφορετικών decompilers σε μικρά executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

Το [**Blobrunner**](https://github.com/OALabs/BlobRunner) θα **δεσμεύσει** το **shellcode** μέσα σε έναν χώρο μνήμης, θα σας **υποδείξει** τη **memory address** στην οποία δεσμεύτηκε το shellcode και θα **σταματήσει** την εκτέλεση.\
Στη συνέχεια, πρέπει να **συνδεθείτε με έναν debugger** (Ida ή x64dbg) στη διεργασία, να τοποθετήσετε ένα **breakpoint στη memory address που υποδείχθηκε** και να **συνεχίσετε** την εκτέλεση. Με αυτόν τον τρόπο θα κάνετε debugging στο shellcode.

Η σελίδα github των releases περιέχει zips με τα compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον ακόλουθο σύνδεσμο. Για να την κάνετε compile, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, κάντε copy και paste τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

Το [**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι πολύ παρόμοιο με το blobrunner. Θα **δεσμεύσει** το **shellcode** μέσα σε έναν χώρο μνήμης και θα ξεκινήσει έναν **ατέρμονο βρόχο**. Στη συνέχεια, πρέπει να **συνδεθείτε με τον debugger** στη διεργασία, να **πατήσετε start, να περιμένετε 2-5 δευτερόλεπτα και να πατήσετε stop**, και θα βρεθείτε μέσα στον **ατέρμονο βρόχο**. Μεταβείτε στην επόμενη εντολή του ατέρμονου βρόχου, καθώς θα είναι μια κλήση προς το shellcode, και τελικά θα βρεθείτε να εκτελείτε το shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: Το jmp2it είναι πολύ παρόμοιο με το blobrunner. Θα δεσμεύσει το shellcode μέσα σε έναν χώρο μνήμης και θα ξεκινήσει έναν...](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια compiled έκδοση του [jmp2it από τη σελίδα των releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το επιθεωρείτε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να κάνετε "Open File" και "Open Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως file, το έκανε decompile σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Σημειώστε ότι το Cutter σάς επιτρέπει να κάνετε "Open File" και "Open Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως file, το...](<../../images/image (562).png>)

Για να ξεκινήσετε το emulation από το σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα το emulation από το συγκεκριμένο σημείο:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Για να ξεκινήσετε το emulation από το σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα το emulation από...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Για να ξεκινήσετε το emulation από το σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα το emulation από...](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει για πράγματα όπως **ποιες functions** χρησιμοποιεί το shellcode και αν το shellcode **κάνει decoding** του εαυτού του στη μνήμη.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
Το scDbg διαθέτει επίσης ένα graphical launcher, όπου μπορείτε να επιλέξετε τις options που θέλετε και να εκτελέσετε το shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: Το scDbg διαθέτει επίσης ένα graphical launcher, όπου μπορείτε να επιλέξετε τις options που θέλετε και να...](<../../images/image (258).png>)

Η option **Create Dump** θα κάνει dump το τελικό shellcode, αν πραγματοποιηθεί οποιαδήποτε αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του decoded shellcode). Το **start offset** μπορεί να είναι χρήσιμο για την εκκίνηση του shellcode από ένα συγκεκριμένο offset. Η option **Debug Shell** είναι χρήσιμη για το debugging του shellcode μέσω του scDbg terminal (ωστόσο θεωρώ καλύτερες για αυτόν τον σκοπό οποιεσδήποτε από τις options που εξηγήθηκαν προηγουμένως, καθώς θα μπορείτε να χρησιμοποιήσετε τα Ida ή x64dbg).

### Disassembling using CyberChef

Ανεβάστε το αρχείο shellcode ως input και χρησιμοποιήστε το παρακάτω recipe για να το κάνετε decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Απο-απόκρυψη MBA obfuscation

Η **Mixed Boolean-Arithmetic (MBA)** obfuscation αποκρύπτει απλές εκφράσεις όπως η `x + y` πίσω από formulas που συνδυάζουν arithmetic (`+`, `-`, `*`) και bitwise operators (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι identities είναι συνήθως σωστές μόνο υπό **fixed-width modular arithmetic**, επομένως τα carries και τα overflows έχουν σημασία:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Αν απλοποιήσετε αυτό το είδος έκφρασης με generic algebra tooling, μπορείτε εύκολα να λάβετε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκαν τα semantics του bit-width.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό bit-width** από τον lifted κώδικα/IR/decompiler output (`8/16/32/64` bits).
2. **Ταξινομήστε την έκφραση** πριν προσπαθήσετε να την απλοποιήσετε:
- **Linear**: weighted sums από bitwise atoms
- **Semilinear**: linear συν constant masks όπως `x & 0xFF`
- **Polynomial**: εμφανίζονται products
- **Mixed**: products και bitwise logic είναι interleaved, συχνά με repeated subexpressions
3. **Επαληθεύστε κάθε υποψήφιο rewrite** με random testing ή SMT proof. Αν η equivalence δεν μπορεί να αποδειχθεί, διατηρήστε την αρχική έκφραση αντί να κάνετε εικασίες.

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός MBA simplifier για malware analysis και protected-binary reversing. Ταξινομεί την έκφραση και τη δρομολογεί μέσω specialized pipelines, αντί να εφαρμόζει ένα generic rewrite pass σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean inputs, παράγει ένα signature και εκτελεί παράλληλα αρκετές μεθόδους ανάκτησης, όπως pattern matching, μετατροπή ANF και interpolation συντελεστών.
- **Semilinear MBA**: Τα constant-masked atoms ανακατασκευάζονται με bit-partitioned reconstruction, ώστε οι masked regions να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αποσυντίθενται σε cores και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε temporaries πριν από την απλοποίηση της εξωτερικής σχέσης.

Παράδειγμα mixed identity που συνήθως αξίζει να επιχειρήσετε να ανακτήσετε:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Αυτό μπορεί να συμπτυχθεί σε:
```c
x * y
```
### Reversing notes

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η expression προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, ελέγξτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), το οποίο είναι χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από επόμενα analysis passes.
- Τα residuals mixed-domain που δεν υποστηρίζουν carry-sensitive χειρισμό θα πρέπει να αντιμετωπίζονται ως ένδειξη ότι πρέπει να διατηρήσετε την αρχική expression και να αναλύσετε χειροκίνητα το μονοπάτι του carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator **τροποποιεί όλες τις instructions για το `mov`** (ναι, πραγματικά πολύ cool). Χρησιμοποιεί επίσης interruptions για να αλλάζει τις execution flows. Για περισσότερες πληροφορίες σχετικά με τον τρόπο λειτουργίας του:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Αν είστε τυχεροί, το [demovfuscator](https://github.com/kirschju/demovfuscator) θα αποσυσκοτίσει το binary. Έχει αρκετές dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε ένα **CTF, αυτό το workaround για να βρείτε το flag** μπορεί να είναι πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου**, αναζητήστε τις functions με `::main`, όπως στο:

![Movfuscator - Rust: Για να βρείτε το σημείο εισόδου, αναζητήστε τις functions με ::main, όπως στο](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το binary ονομαζόταν authenticator, επομένως είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα main function.\
Έχοντας το **όνομα** των **functions** που καλούνται, αναζητήστε τα στο **Internet** για να μάθετε σχετικά με τα **inputs** και τα **outputs** τους.

### Ανάκτηση Rust strings από ELF firmware

Στα **Rust ELF** binaries, πολλά static strings δεν αναφέρονται ως pointers με τερματισμό NUL, όπως στη C. Ένα συνηθισμένο layout του `rustc` είναι ένα **tuple pointer/length** μέσα στο **`.data.rel.ro`**, το οποίο δείχνει στο πραγματικό string blob που είναι αποθηκευμένο στο **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Αυτό σημαίνει ότι τα `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσουν γειτονικά strings ή να παραλείψουν εντελώς cross-references.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Λάβετε την virtual address και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία word κάθε φορά.
3. Αντιμετωπίστε οποιαδήποτε τιμή εντός του address range του **`.rodata`** ως candidate string pointer.
4. Αντιμετωπίστε την επόμενη word ως το candidate length.
5. Εφαρμόστε sanity filters (για παράδειγμα, διατηρήστε lengths μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το **`.rodata`** αντί να κάνετε scanning μέχρι το `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή τα ανακτημένα Rust strings συχνά αποκαλύπτουν **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers και auth-related logic**.

Αν το Ghidra δεν εντοπίζει αυτά τα strings, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια heuristic και δημιουργεί string data στα referenced `.rodata` offsets. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` από την Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν γίνει compile με Delphi μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Απλώς πατήστε **ATL+f7** (import python plugin στο IDA) και επιλέξτε το python plugin.

Αυτό το plugin θα εκτελέσει το binary και θα κάνει resolve τα function names δυναμικά στην αρχή του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το Start button (το πράσινο ή το f9) και ένα breakpoint θα ενεργοποιηθεί στην αρχή του πραγματικού code.

Είναι επίσης πολύ ενδιαφέρον, επειδή αν πατήσετε ένα button στη graphic application, ο debugger θα σταματήσει στη function που εκτελείται από αυτό το button.

## Golang

Αν πρέπει να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Απλώς πατήστε **ATL+f7** (import python plugin στο IDA) και επιλέξτε το python plugin.

Αυτό θα κάνει resolve τα names των functions.

## Compiled Python

Σε αυτή τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον python code από ένα ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Αν αποκτήσετε το **binary** ενός GBA game, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να το **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την debug version_) - Περιέχει debugger με interface
- [**mgba** ](https://mgba.io)- Περιέχει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς πατιούνται τα **buttons** του Game Boy Advance

![Διαμόρφωση των controls του no$gba που εμφανίζει τις αντιστοιχίσεις των buttons του Game Boy Advance](<../../images/image (581).png>)

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
Έτσι, σε αυτό το είδος προγράμματος, το ενδιαφέρον μέρος θα είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνήθως εμφανιζόμενη συνάρτηση: **KEYINPUT**.

![Προβολή του Ghidra ενός binary GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη συνάρτηση, μετά από ορισμένες αρχικοποιήσεις (χωρίς καμία σημασία):
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
Βρέθηκε ο εξής κώδικας:
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
Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα τελευταία Keys και δεν είναι το τρέχον key, κάτι που ονομάζεται επίσης απελευθέρωση ενός κουμπιού (το τρέχον key αποθηκεύεται στο **`uVar1`**).
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
Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε το **uVar1** (τη θέση όπου βρίσκεται η **value του pressed button**) με κάποιες values:

- Αρχικά, συγκρίνεται με τη **value 4** (κουμπί **SELECT**): στο challenge αυτό το κουμπί καθαρίζει την οθόνη
- Στη συνέχεια, συγκρίνεται με τη **value 8** (κουμπί **START**): στο challenge αυτό ελέγχεται αν το code είναι valid για να ληφθεί το flag.
- Σε αυτή την περίπτωση, το var **`DAT_030000d8`** συγκρίνεται με 0xf3 και, αν η value είναι ίδια, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται κάποιο cont (**`DAT_030000d4`**). Είναι cont επειδή αυξάνεται κατά 1 αμέσως μετά την εισαγωγή του code.\
Αν είναι μικρότερο από 8, εκτελείται κάτι που περιλαμβάνει **πρόσθεση** values στο **`DAT_030000d8`** (βασικά, προσθέτει τις values των pressed keys σε αυτό το variable, όσο το cont είναι μικρότερο από 8).

Επομένως, σε αυτό το challenge, γνωρίζοντας τις values των buttons, έπρεπε να **πατήσετε έναν συνδυασμό με length μικρότερο από 8, ώστε το resulting addition να είναι 0xf3.**

**Reference για αυτό το tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
