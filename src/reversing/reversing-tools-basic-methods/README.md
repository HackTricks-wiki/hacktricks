# Εργαλεία Reversing και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία Reversing βασισμένα σε ImGui

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

## Node.js / V8 cached bytecode

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας decompiler που **κάνει decompile και εξετάζει πολλαπλές μορφές**, συμπεριλαμβανομένων **βιβλιοθηκών** (.dll), **Windows metadata file**s (.winmd) και **εκτελέσιμων** (.exe). Αφού γίνει το decompile, ένα assembly μπορεί να αποθηκευτεί ως Visual Studio project (.csproj).

Το πλεονέκτημα εδώ είναι ότι, αν απαιτείται αποκατάσταση lost source code από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση σε ολόκληρο το decompiled code, καθιστώντας το ένα από τα ιδανικά εργαλεία για **Xamarin algorithm analysis.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο add-in model και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει τις ακριβείς ανάγκες σας, το .NET reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας εξετάσουμε το πλήθος των reverse engineering υπηρεσιών που παρέχει αυτό το εργαλείο:

- Παρέχει insight σχετικά με το πώς ρέουν τα δεδομένα μέσα από μια βιβλιοθήκη ή ένα component
- Παρέχει insight σχετικά με την υλοποίηση και τη χρήση των .NET languages και frameworks
- Εντοπίζει undocumented και unexposed functionality, ώστε να αξιοποιείτε περισσότερο τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή τοποθεσία των errors στον κώδικά σας, σε third-party components και σε libraries.
- Κάνει debug στο source όλου του .NET code με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **search ILSpy**).\
Αν χρειάζεται να κάνετε **decompile**, **modify** και στη συνέχεια να κάνετε ξανά **recompile**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα actively maintained fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια function).

### Καταγραφή DNSpy

Για να κάνετε το **DNSpy να καταγράφει ορισμένες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Για να κάνετε debugging κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

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

Αυτό είναι απαραίτητο, επειδή, αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και ενδέχεται κατά το debugging ένα **break-point να μην ενεργοποιηθεί ποτέ** ή ορισμένες **μεταβλητές να μην υπάρχουν**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται μέσω του **IIS**, μπορείτε να την **επανεκκινήσετε** με:
```
iisreset /noforce
```
Στη συνέχεια, για να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και μέσα στο **Debug Tab** να επιλέξετε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και μέσα στο Debug Tab να επιλέξετε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο _Debug >> Break All_ και στη συνέχεια κάντε κλικ στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο Debug Break All και στη συνέχεια κάντε κλικ στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά κάντε κλικ στο Debug Break All και στη συνέχεια κάντε κλικ στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και κάντε κλικ στο **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και κάντε κλικ στο Sort Assemblies](<../../images/image (339).png>)

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

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα σταματά όταν φορτώνεται κάθε DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα σταματήσει.

Αυτή η μέθοδος σταματά σε events φόρτωσης module, αλλά η προσέγγιση του entry point του φορτωμένου DLL είναι λιγότερο άμεση από ό,τι στη ροή εργασίας με το x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) και ορίστε το path του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και κάποια στιγμή θα **σταματήσει στο dll Entry του dll σας**. Από εκεί, απλώς αναζητήστε τα σημεία στα οποία θέλετε να βάλετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση σταματά για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε**, κοιτάζοντας **στο επάνω μέρος του παραθύρου του win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση σταματά για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε, κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει σταματήσει μέσα στο DLL που θέλετε να κάνετε debug.

## GUI Apps / Videogames

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για την εύρεση των σημείων όπου αποθηκεύονται σημαντικές τιμές στη μνήμη ενός game που εκτελείται και για την αλλαγή τους. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/reverse engineering tool για το GNU Project Debugger (GDB), με έμφαση στα games. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιοδήποτε θέμα σχετίζεται με reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web service σας επιτρέπει να συγκρίνετε το output διαφορετικών decompilers σε μικρά executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει το **shellcode**, εμφανίζει τη **memory address** του και κάνει pause στην εκτέλεση.\
Συνδεθείτε με έναν debugger, όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εμφανίστηκε και συνεχίστε την εκτέλεση για να κάνετε debugging στο shellcode.

Η σελίδα releases στο github περιέχει zips με τα compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει το shellcode και εισέρχεται σε έναν infinite loop. Συνδεθείτε με τον debugger, συνεχίστε για **2–5 seconds**, κάντε pause μέσα σε αυτόν τον loop και προχωρήστε έως την επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Debugger σε pause στον infinite loop του jmp2it ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια compiled έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter επιτρέπει **Open File** και **Open Shellcode**. Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο, το έκανε decompile σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα analysis όταν ανοίγει τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσετε το emulation στο σημείο που θέλετε, ορίστε εκεί ένα bp και, aparentemente, το Cutter θα ξεκινήσει αυτόματα το emulation από εκεί:

![Ορισμός breakpoint στο επιθυμητό shellcode entry πριν από την έναρξη του Cutter emulation](<../../images/image (589).png>)

![Ο emulator του Cutter σε pause στο επιλεγμένο shellcode breakpoint](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του emulated shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει, μεταξύ άλλων, **ποιες functions** χρησιμοποιεί το shellcode και αν το shellcode κάνει **decoding** του εαυτού του στη μνήμη.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
Το scDbg διαθέτει επίσης έναν γραφικό launcher, όπου μπορείτε να επιλέξετε τις options που θέλετε και να εκτελέσετε το shellcode

![Γραφικός launcher του scDbg για την επιλογή options emulation και tracing του shellcode](<../../images/image (258).png>)

Η option **Create Dump** αποθηκεύει το τελικό shellcode, εάν έχει γίνει οποιαδήποτε αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του decoded shellcode). Το **start offset** μπορεί να είναι χρήσιμο για την εκκίνηση του shellcode από ένα συγκεκριμένο offset. Η option **Debug Shell** είναι χρήσιμη για το debugging του shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι οποιαδήποτε από τις options που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτόν τον σκοπό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Disassembling με χρήση του CyberChef

Κάντε upload το αρχείο shellcode ως input και χρησιμοποιήστε το ακόλουθο recipe για να το κάνετε decompile: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Το **Mixed Boolean-Arithmetic (MBA)** obfuscation αποκρύπτει απλές expressions, όπως `x + y`, πίσω από formulas που συνδυάζουν arithmetic (`+`, `-`, `*`) και bitwise operators (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι identities είναι συνήθως σωστές μόνο υπό **fixed-width modular arithmetic**, επομένως τα carries και τα overflows έχουν σημασία:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Αν απλοποιήσετε αυτό το είδος έκφρασης με generic algebra tooling, μπορείτε εύκολα να πάρετε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του bit-width.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό bit-width** από τον lifted κώδικα/IR/decompiler output (`8/16/32/64` bits).
2. **Κατηγοριοποιήστε την έκφραση** πριν προσπαθήσετε να την απλοποιήσετε:
- **Γραμμική**: σταθμισμένα αθροίσματα από bitwise atoms
- **Semilinear**: γραμμική έκφραση συν σταθερές μάσκες, όπως `x & 0xFF`
- **Πολυωνυμική**: εμφανίζονται γινόμενα
- **Μεικτή**: τα γινόμενα και η bitwise λογική είναι αλληλεπλεγμένα, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια rewrite** με random testing ή απόδειξη SMT. Αν η ισοδυναμία δεν μπορεί να αποδειχθεί, διατηρήστε την αρχική έκφραση αντί να κάνετε υποθέσεις.

### Παρακάμψτε το flattened control flow με ένα περιορισμένο execution slice

Η ανάκτηση ολόκληρου του control-flow graph συχνά δεν είναι απαραίτητη. Με control-flow flattening, opaque predicates, μεγάλους dispatchers ή MBA-heavy κώδικα, ακολουθήστε τις αναφορές από encrypted blobs και output buffers μέχρι τη μικρότερη routine που τα μετασχηματίζει. Στη συνέχεια αναπαραγάγετε μόνο αυτό το data-flow slice ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, εφόσον η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι η εξής:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα executable και data sections, τα relocations και τα cross-references. Κάντε dump των υποψήφιων tables από το `.rodata`, διατηρώντας τη σειρά των bytes και το πλάτος των στοιχείων.
2. Εντοπίστε την τελευταία routine που γράφει στο plaintext ή output buffer. Καταγράψτε τα inputs της, τα referenced tables, τα imported calls και την απαιτούμενη global state.
3. Κάντε lift μόνο αυτές τις operations σε ένα fixed-width Python model. Αν το slice εξακολουθεί να εξαρτάται από υπερβολικά μεγάλο state, καλέστε τη routine μέσω Unicorn, QEMU ή debugger και κάντε hook τα irrelevant imports αντί να κάνετε emulate ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor αντλεί πράγματι το output του από το παρεχόμενο binary: αφαιρέστε τα silent fallbacks, αναζητήστε embedded answers και εκτελέστε τον σε unseen builds με αλλαγμένα strings, keys, identifiers, layouts και obfuscation seeds.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι οι εξής:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Εντοπισμός εκφράσεων MBA που είναι μεταμφιεσμένες σταθερές

Μια φαινομενικά εξαρτώμενη από την είσοδο έκφραση byte μπορεί να εξαλείφει πλήρως την είσοδό της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το domain των 8 bit· ένα σύνολο αποτελεσμάτων με ένα μόνο στοιχείο αποδεικνύει ότι αυτό το byte είναι σταθερό, χωρίς να χρειάζεται η ανάκτηση της περιβάλλουσας state machine.<sup>[[7]](#references)</sup>
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
Διατήρησε την τελική μάσκα, επειδή η αρχική πρόσθεση έχει αναδίπλωση εύρους byte. Για ευρύτερο πεδίο τιμών, ρώτησε έναν SMT solver αν το `f(x1) != f(x2)` είναι ικανοποιήσιμο για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει την αμεταβλητότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνώριση decoding που εξαρτάται από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας decoder μπορεί να αναμείξει το αποτέλεσμα ενός sensor σε ένα bit του key, σε μια σταθερά opaque-predicate ή στην κατάσταση ενός flattened-dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά εσφαλμένο plaintext σε έναν emulator. Επομένως, το patching μόνο των ορατών failure branches δεν επαρκεί· παρακολούθησε τις εξαρτήσεις δεδομένων από τα environment probes έως την κατάσταση του decoder, σύγκρινε το ίδιο slice στην αυθεντική συσκευή και στον emulator και έλεγξε πώς η εξαναγκασμένη τιμή κάθε sensor αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός MBA simplifier για malware analysis και protected-binary reversing. Κατηγοριοποιεί την expression και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει ένα γενικό rewrite pass σε όλα.<sup>[[2]](#references)</sup>

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
- **Semilinear MBA**: Τα constant-masked atoms ανακατασκευάζονται με bit-partitioned reconstruction, ώστε οι masked regions να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα products αποσυντίθενται σε cores και οι repeated subexpressions μπορούν να μεταφερθούν σε temporaries πριν από την απλοποίηση της outer relation.

Παράδειγμα μιας mixed identity που συνήθως αξίζει να δοκιμαστεί για recovery:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Αυτό μπορεί να απλοποιηθεί σε:
```c
x * y
```
### Σημειώσεις Reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η expression προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ένα ισχυρότερο βήμα proof, ελέγξτε τις τοπικές σημειώσεις Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), το οποίο είναι χρήσιμο όταν θέλετε να κανονικοποιήσετε MBA-heavy LLVM IR πριν από μεταγενέστερα analysis passes.
- Τα unsupported carry-sensitive mixed-domain residuals θα πρέπει να αντιμετωπίζονται ως ένδειξη ότι πρέπει να διατηρήσετε την αρχική expression και να αναλύσετε χειροκίνητα το carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με instruction sequences βασισμένες σε `mov` και χρησιμοποιεί signal/exception handling για να μεταβάλλει το control flow. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για supported binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές dependencies.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν ασχολείστε με ένα **CTF, αυτό το workaround για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point**, αναζητήστε τις functions με `::main`, όπως στο:

![Εύρεση ενός Rust entry point στο Ghidra μέσω αναζήτησης των ονομάτων των functions για double-colon main](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το binary ονομαζόταν authenticator, επομένως είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα main function.\
Έχοντας το **όνομα** των **functions** που καλούνται, αναζητήστε τις στο **Διαδίκτυο** για να μάθετε περισσότερα σχετικά με τα **inputs** και τα **outputs** τους.

### Ανάκτηση Rust strings από ELF firmware

Στα **Rust ELF** binaries, πολλά static strings δεν αναφέρονται ως C-style NUL-terminated pointers. Ένα συνηθισμένο layout του `rustc` είναι ένα **pointer/length tuple** μέσα στο **`.data.rel.ro`**, το οποίο δείχνει στο πραγματικό string blob που είναι αποθηκευμένο στο **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Αυτό σημαίνει ότι τα `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσουν γειτονικά strings ή να παραλείψουν εντελώς cross-references.<sup>[[3]](#references)</sup>

Γρήγορο workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Λάβετε την virtual address και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία word τη φορά.
3. Θεωρήστε οποιαδήποτε τιμή εντός του address range του `.rodata` ως υποψήφιο δείκτη σε string.
4. Θεωρήστε την επόμενη word ως το υποψήφιο μήκος.
5. Εφαρμόστε φίλτρα εγκυρότητας (για παράδειγμα, διατηρήστε μήκη μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata` αντί να κάνετε σάρωση μέχρι το `0x00`.

Ελάχιστη λογική extractor:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή τα strings της Rust που ανακτώνται συχνά αποκαλύπτουν **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers και auth-related logic**.

Αν το Ghidra δεν εντοπίζει αυτά τα strings, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια heuristic και δημιουργεί δεδομένα string στα referenced offsets του `.rodata`. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` από την Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν γίνει compile με Delphi μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα ονόματα των functions κατά την έναρξη του debugging. Αφού ξεκινήσετε το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και ένα breakpoint θα ενεργοποιηθεί στην αρχή του πραγματικού code.

Αν πατήσετε ένα κουμπί στη graphical εφαρμογή, ο debugger μπορεί να σταματήσει στη function που καλείται από αυτό το κουμπί.

## Golang

Αν πρέπει να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των functions.

## Compiled Python

Σε αυτή τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον python code από ένα ELF/EXE python compiled binary:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να το **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιέχει debugger με interface
- [**mgba** ](https://mgba.io)- Περιέχει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στο _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατάτε τα **buttons** του Game Boy Advance

![διαμόρφωση controls του no$gba που εμφανίζει τα button mappings του Game Boy Advance](<../../images/image (581).png>)

Όταν πατηθεί, κάθε **key έχει μια τιμή** για την αναγνώρισή του:
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
Έτσι, σε αυτού του είδους τα προγράμματα, το ενδιαφέρον μέρος θα είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται το user input**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνηθισμένη function: **KEYINPUT**.

![Προβολή του Ghidra ενός GBA binary που αναφέρεται στην KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η function καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη function, μετά από ορισμένες init operations (χωρίς καμία σημασία):
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
Έχει βρει αυτόν τον κώδικα:
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
Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στο τελευταίο Keys και δεν είναι το τρέχον πλήκτρο, κάτι που ονομάζεται επίσης απελευθέρωση ενός κουμπιού (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).
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

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): Στο challenge αυτό το κουμπί καθαρίζει την οθόνη
- Στη συνέχεια, συγκρίνει την τιμή με το **8** (κουμπί **START**). Σε αυτό το challenge, αυτό το path ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
- Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν η τιμή είναι ίδια, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων συσσωρεύονται στο `DAT_030000d8`.

Επομένως, σε αυτό το challenge, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, ώστε το άθροισμα να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένο writeup του Nostalgia challenge](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Απλοποίηση του MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο CoBRA των Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversing GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετωπίζοντας το AI-Assisted Reverse Engineering ή τουλάχιστον προσπαθώντας](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
