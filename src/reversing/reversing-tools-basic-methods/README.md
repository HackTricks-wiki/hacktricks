# Εργαλεία Reversing & Βασικές Μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία Reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugging πυρήνα Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Wasm decompiler / Wat compiler

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **decompile** από wasm (binary) σε wat (απλό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **compile** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για decompilation.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Cached bytecode Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualized payloads και custom VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας decompiler που **απομεταγλωττίζει και εξετάζει πολλαπλές μορφές**, όπως **libraries** (.dll), **αρχεία μεταδεδομένων Windows** (.winmd) και **executables** (.exe). Μετά την απομεταγλώττιση, ένα assembly μπορεί να αποθηκευτεί ως project του Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να ανακτηθεί χαμένος πηγαίος κώδικας από ένα legacy assembly, αυτή η διαδικασία μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύκολη πλοήγηση στον απομεταγλωττισμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει ακριβώς τις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολλές υπηρεσίες reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα του τρόπου με τον οποίο ρέουν τα δεδομένα μέσα από μια library ή ένα component
- Παρέχει εικόνα της υλοποίησης και της χρήσης των γλωσσών και frameworks του .NET
- Εντοπίζει μη τεκμηριωμένες και μη εκτεθειμένες λειτουργίες, ώστε να αξιοποιείτε καλύτερα τα APIs και τις τεχνολογίες που χρησιμοποιείτε.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή θέση των σφαλμάτων στον κώδικά σας, σε components τρίτων και σε libraries.
- Κάνει debugging στον πηγαίο κώδικα όλου του .NET code με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να κάνετε **decompile**, **modify** και ξανά **recompile**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα ενεργά συντηρούμενο fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια function).

### Καταγραφή συμβάντων στο DNSpy

Για να κάνετε το **DNSpy να καταγράφει κάποιες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Αποσφαλμάτωση DNSpy

Για να κάνετε αποσφαλμάτωση κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Πρώτα, αλλάξτε τα **χαρακτηριστικά του Assembly** που σχετίζονται με την **αποσφαλμάτωση**:

![Καταγραφή DNSpy - Αποσφαλμάτωση DNSpy: Πρώτα, αλλάξτε τα χαρακτηριστικά του Assembly που σχετίζονται με την αποσφαλμάτωση](<../../images/image (973).png>)

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

Αυτό είναι απαραίτητο, γιατί αν δεν το κάνετε, κατά τον **χρόνο εκτέλεσης** θα εφαρμοστούν διάφορες **βελτιστοποιήσεις** στον κώδικα και υπάρχει πιθανότητα κατά την αποσφαλμάτωση να μην ενεργοποιηθεί ποτέ ένα **σημείο διακοπής** ή να μην υπάρχουν κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε την αποσφαλμάτωση, κλείστε όλα τα ανοιχτά αρχεία και από το **Debug Tab** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε την αποσφαλμάτωση, κλείστε όλα τα ανοιχτά αρχεία και από το Debug Tab επιλέξτε Attach to Process](<../../images/image (318).png>)

Έπειτα, επιλέξτε **w3wp.exe** για να συνδεθείτε στον **IIS server** και πατήστε **attach**:

![DNSpy Logging - DNSpy Debugging: Έπειτα, επιλέξτε w3wp.exe για να συνδεθείτε στον IIS server και πατήστε attach](<../../images/image (113).png>)

Τώρα που κάνουμε αποσφαλμάτωση της διεργασίας, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, επιλέξτε _Debug >> Break All_ και έπειτα _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε αποσφαλμάτωση της διεργασίας, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, επιλέξτε Debug Break All και έπειτα Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε αποσφαλμάτωση της διεργασίας, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, επιλέξτε Debug Break All και έπειτα Debug Windows Modules](<../../images/image (834).png>)

Πατήστε σε οποιοδήποτε module στην καρτέλα **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Πατήστε σε οποιοδήποτε module στην καρτέλα Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Αποσφαλμάτωση DLLs

### Χρήση IDA

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε τον debugger **Windbg**
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Διαμορφώστε τις **παραμέτρους** εκτέλεσης, ορίζοντας τη **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Διαμορφώστε τις παραμέτρους εκτέλεσης, ορίζοντας τη διαδρομή προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε την αποσφαλμάτωση, **η εκτέλεση θα διακόπτεται κάθε φορά που φορτώνεται ένα DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση σε συμβάντα φόρτωσης module, αλλά η μετάβαση στο σημείο εισόδου του φορτωμένου DLL είναι λιγότερο άμεση σε σχέση με τη ροή εργασίας του x64dbg παρακάτω.

### Χρήση x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε τη διαδρομή του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Έπειτα, **ξεκινήστε την εκτέλεση**. Ο debugger θα διακόπτεται στο main κάθε dll και κάποια στιγμή θα **διακοπεί στο Entry του dll σας**. Από εκεί, αναζητήστε τα σημεία όπου θέλετε να τοποθετήσετε ένα breakpoint.

Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας **στο επάνω μέρος του παραθύρου win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε κοιτάζοντας στο επάνω μέρος του παραθύρου win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει διακοπεί μέσα στο DLL που θέλετε να αποσφαλματώσετε.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετίζεται με το reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web υπηρεσία σάς επιτρέπει να συγκρίνετε τα αποτελέσματα διαφορετικών decompilers σε μικρά executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει χώρο για το **shellcode**, εμφανίζει τη **διεύθυνση μνήμης** του και διακόπτει την εκτέλεση.\
Συνδεθείτε με έναν debugger όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εμφανίζεται και συνεχίστε την εκτέλεση για να αποσφαλματώσετε το shellcode.

Η σελίδα releases στο github περιέχει zip με τις μεταγλωττισμένες εκδόσεις: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, απλώς **δημιουργήστε ένα project C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει χώρο για το shellcode και εκτελεί έναν ατέρμονο βρόχο. Συνδεθείτε με τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, διακόψτε την μέσα σε αυτόν τον βρόχο και προχωρήστε μέχρι την επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει διακόψει την εκτέλεση μέσα στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it στη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το εξετάσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να επιλέξετε "Open File" και "Open Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο, το decompile έγινε σωστά, ενώ όταν το άνοιξα ως shellcode, δεν έγινε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγονται τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσει το emulation από το σημείο που θέλετε, ορίστε εκεί ένα bp και το Cutter φαίνεται να ξεκινά αυτόματα το emulation από εκεί:

![Ορισμός breakpoint στο επιθυμητό σημείο εισόδου του shellcode πριν από την έναρξη του emulation στο Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter έχει διακόψει την εκτέλεση στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του shellcode που γίνεται emulate στο hex dump του Cutter](<../../images/image (186).png>)

### Απο-συσκότιση shellcode και εντοπισμός συναρτήσεων που εκτελούνται

Δοκιμάστε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας δείξει, για παράδειγμα, **ποιες συναρτήσεις** χρησιμοποιεί το shellcode και αν το shellcode **αποκωδικοποιεί** τον εαυτό του στη μνήμη.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

Το scDbg διαθέτει επίσης γραφικό launcher, όπου μπορείτε να επιλέξετε τις επιθυμητές επιλογές και να εκτελέσετε το shellcode

![Γραφικό launcher του scDbg για την επιλογή των επιλογών εξομοίωσης και tracing του shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** αποθηκεύει το τελικό shellcode, αν έχει γίνει κάποια αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Το **start offset** μπορεί να είναι χρήσιμο για την εκκίνηση του shellcode σε συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων στο shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι οποιαδήποτε από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη γι' αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με το CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε την ακόλουθη συνταγή για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Η απόκρυψη **Mixed Boolean-Arithmetic (MBA)** κρύβει απλές εκφράσεις, όπως `x + y`, πίσω από τύπους που συνδυάζουν αριθμητικές πράξεις (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες είναι συνήθως σωστές μόνο υπό **αριθμητική modulo σταθερού πλάτους**, επομένως τα carry και τα overflow έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε τέτοιου είδους έκφραση με γενικά εργαλεία άλγεβρας, μπορεί εύκολα να καταλήξετε σε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον lifted κώδικα/την έξοδο IR ή decompiler (`8/16/32/64` bits).
2. **Κατατάξτε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα από bitwise atoms
   - **Ημιγραμμική**: γραμμική έκφραση μαζί με σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: εμφανίζονται γινόμενα
   - **Μικτή**: τα γινόμενα και η bitwise λογική συνδυάζονται, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια αναγραφή** με τυχαίες δοκιμές ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, κρατήστε την αρχική έκφραση αντί να μαντέψετε.

### Παράκαμψη του flattened control flow με ένα στενό execution slice

Η ανάκτηση ολόκληρου του control-flow graph συχνά δεν είναι απαραίτητη. Με control-flow flattening, opaque predicates, μεγάλους dispatchers ή κώδικα με πολλά MBA, ακολουθήστε τις αναφορές από κρυπτογραφημένα blobs και output buffers έως τη μικρότερη ρουτίνα που τα μετασχηματίζει. Έπειτα αναπαραγάγετε μόνο αυτό το data-flow slice ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, αν η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι η εξής:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα executable και data sections, τις relocations και τις cross-references. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των byte και το πλάτος των στοιχείων.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει το plaintext ή το output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις imported calls και την απαιτούμενη global state.
3. Κάντε lift μόνο αυτές τις λειτουργίες σε ένα μοντέλο Python σταθερού πλάτους. Αν το slice εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα με Unicorn, QEMU ή debugger και κάντε hook τις άσχετες imports αντί να κάνετε emulate ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor αντλεί πράγματι την έξοδό του από το παρεχόμενο binary: αφαιρέστε τα σιωπηρά fallbacks, αναζητήστε ενσωματωμένες απαντήσεις και εκτελέστε τον σε builds που δεν έχετε ξαναδεί, με διαφορετικά strings, keys, identifiers, layouts και obfuscation seeds.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι οι εξής:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός εκφράσεων MBA που κρύβουν σταθερές

Μια έκφραση byte που φαινομενικά εξαρτάται από την είσοδο μπορεί στην πραγματικότητα να ακυρώνει πλήρως την επίδρασή της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το πεδίο τιμών των 8 bit· ένα σύνολο εξόδων με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε την περιβάλλουσα μηχανή καταστάσεων.<sup>[[7]](#references)</sup>

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

Διατηρήστε την τελική μάσκα, επειδή η αρχική πρόσθεση έχει αναδίπλωση στο πλάτος του byte. Για ευρύτερο πεδίο τιμών, ρωτήστε έναν SMT solver αν είναι ικανοποιήσιμη η συνθήκη `f(x1) != f(x2)` για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει αναλλοιωτότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνώριση αποκωδικοποίησης δεσμευμένης στο περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας decoder μπορεί να αναμείξει το αποτέλεσμα ενός αισθητήρα σε ένα bit κλειδιού, σε μια σταθερά opaque predicate ή στην κατάσταση ενός flattened dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά εσφαλμένο plaintext σε έναν emulator. Επομένως, δεν αρκεί να τροποποιήσετε μόνο τις ορατές διακλαδώσεις αποτυχίας· ανιχνεύστε τις εξαρτήσεις δεδομένων από τους ελέγχους περιβάλλοντος έως την κατάσταση του decoder, συγκρίνετε το ίδιο slice στην αυθεντική συσκευή και στον emulator και δοκιμάστε πώς η επιβολή κάθε αποτελέσματος αισθητήρα αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένα πρακτικό εργαλείο απλοποίησης MBA για ανάλυση malware και reverse engineering προστατευμένων binaries. Ταξινομεί την έκφραση και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει μία γενική διαδικασία επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση με Boolean εισόδους, παράγει μια υπογραφή και εκτελεί παράλληλα διάφορες μεθόδους ανάκτησης, όπως pattern matching, μετατροπή ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα atoms με constant mask ανακατασκευάζονται με ανακατασκευή διαμερισμένη σε bit, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αναλύονται σε cores, ενώ επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε temporaries πριν από την απλοποίηση της εξωτερικής σχέσης.

Παράδειγμα μικτής ταυτότητας που συνήθως αξίζει να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να συμπτυχθεί σε:

```c
x * y
```

### Σημειώσεις για reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted εκφράσεις IR** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked αριθμητική ή στενούς καταχωρητές.
- Αν χρειάζεστε ένα ισχυρότερο βήμα απόδειξης, δείτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από μεταγενέστερα analysis passes.
- Τα μη υποστηριζόμενα mixed-domain residuals που εξαρτώνται από carry θα πρέπει να εκλαμβάνονται ως ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα τη διαδρομή του carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί signal/exception handling για να μεταβάλλει τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές εξαρτήσεις.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε **CTF, αυτή η παράκαμψη για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου**, αναζητήστε τις συναρτήσεις με βάση το `::main`, όπως εδώ:

![Εύρεση του σημείου εισόδου Rust στο Ghidra, κάνοντας αναζήτηση στα ονόματα συναρτήσεων για διπλή άνω και κάτω τελεία και main](<../../images/image (1080).png>)

Σε αυτή την περίπτωση, το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ποια είναι η ενδιαφέρουσα συνάρτηση main.\
Έχοντας το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση συμβολοσειρών Rust από firmware ELF

Σε **Rust** binaries **ELF**, πολλές στατικές συμβολοσειρές δεν αναφέρονται μέσω δεικτών με τερματισμό NUL, όπως στη C. Μια συνηθισμένη διάταξη του `rustc` είναι μια **πλειάδα δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, η οποία δείχνει προς το πραγματικό blob συμβολοσειρών που είναι αποθηκευμένο στο **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικές συμβολοσειρές ή να μην εντοπίσει καθόλου διασταυρούμενες αναφορές.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Λάβετε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** λέξη προς λέξη.
3. Αντιμετωπίστε κάθε τιμή εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη σε string.
4. Αντιμετωπίστε την επόμενη λέξη ως το υποψήφιο μήκος.
5. Εφαρμόστε ελέγχους εγκυρότητας (για παράδειγμα, κρατήστε μήκη μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata`, αντί να κάνετε σάρωση μέχρι το `0x00`.

Ελάχιστη λογική extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες συμβολοσειρές Rust συχνά αποκαλύπτουν **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers και auth-related logic**.

Αν το Ghidra δεν εντοπίζει αυτές τις συμβολοσειρές, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στα αναφερόμενα offsets του `.rodata`. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` από την Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν μεταγλωττιστεί με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειαστεί να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα ονόματα των συναρτήσεων κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη συνάρτηση που καλείται από αυτό το κουμπί.

## Golang

Για συνηθισμένα Go binaries, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει runtime structures και να βελτιώσει τα ονόματα των συναρτήσεων στο IDA. Φορτώστε το Python plugin με **Alt+F7**.

### Ανάκτηση metadata χωρίς τον πίνακα συμβόλων

Ένα stripped Go executable εξακολουθεί να χρειάζεται runtime metadata για να αντιστοιχίσει τους program counters σε συναρτήσεις. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει structures όπως τα `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Έτσι μπορεί να ανακτήσει όρια συναρτήσεων, ονόματα, source paths, τύπους και build details, χωρίς να βασίζεται στον συμβατικό πίνακα συμβόλων.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές λειτουργικές, αντικαθιστώντας παράλληλα τα ανακτημένα ονόματα. Το Garble, για παράδειγμα, κάνει hash στα identifiers και στα package paths και αφαιρεί πληροφορίες build, module και debug.<sup>[[12]](#references)</sup> Το obfuscated package token πρέπει να παραμένει ίδιο σε όλες τις συναρτήσεις αυτού του package. Ομαδοποιήστε τις συναρτήσεις με βάση το επαναλαμβανόμενο token, συμπεράνετε ένα package από τις συναρτήσεις που καλεί, τα strings και τα APIs του και, στη συνέχεια, εφαρμόστε αυτή την ετικέτα package σε όλη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή runtime-symbols με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση control-flow-graph (CFG). Ακολουθήστε αυτή τη σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Εντοπίστε την έκδοση του compiler.** Δοκιμάστε πρώτα τα `BuildInfo` και τις ενσωματωμένες συμβολοσειρές έκδοσης. Αν ο obfuscator τα αφαίρεσε, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtimes αναφοράς συγκεκριμένων εκδόσεων. Στις δοκιμές της Volexity, περίπου το `2%` του runtime αρκούσε για να διακρίνει τις κύριες εκδόσεις του Go. Αντιμετωπίστε αυτό το ποσοστό ως εμπειρική βελτιστοποίηση, όχι ως καθολικό όριο.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε κατάλληλες αναφορές.** Δημιουργήστε καθαρά binaries για την εντοπισμένη έκδοση του Go, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση της toolchain περιορίζει τις διαφορές CFG που εισάγει ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε τις συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και παράγει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση basic blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής βεβαιότητας συνδέουν τις τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Ακόμη και οι ασθενέστερες αντιστοιχίσεις μπορούν να εντοπίσουν ένα package ή module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επικυρώστε και εισαγάγετε.** Επιβεβαιώστε τα προτεινόμενα ονόματα με βάση τις σχέσεις κλήσεων, τις σταθερές, τα strings και τα side effects και, στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin του GoResolver για IDA ή Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Εγκαταστήστε την toolchain και εκτελέστε τον συνδυασμένο extractor και graph matcher:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

Το προεπιλεγμένο όριο σημαντικής αντιστοίχισης είναι `0.9`. Οι επιλογές `--extract` και `--graph` μπορούν να απομονώσουν οποιοδήποτε από τα δύο στάδια, ενώ από προεπιλογή εκτελούνται και τα δύο, επειδή τα ανακτημένα metadata του runtime και τα στοιχεία CFG συμπληρώνουν το ένα το άλλο.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, οι σημαίες build, η αρχιτεκτονική και οι διαφορές στις εκδόσεις βιβλιοθηκών μπορούν να αλλάξουν τη μορφή του γράφου, επομένως διατηρήστε τις μη επιλυμένες συναρτήσεις αντί να επιβάλλετε ονόματα με χαμηλή βεβαιότητα.<sup>[[13]](#references)</sup>

## Compiled Python

Σε αυτή τη σελίδα μπορείτε να μάθετε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο δυαδικό αρχείο Python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **δυαδικό αρχείο** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **προσομοιώσετε** και να το **αποσφαλματώσετε**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με γραφικό περιβάλλον
- [**mgba** ](https://mgba.io)- Περιλαμβάνει debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin του Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin του Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance

![Διαμόρφωση χειριστηρίων no$gba με αντιστοιχίσεις κουμπιών Game Boy Advance](<../../images/image (581).png>)

Όταν πατηθεί, κάθε **πλήκτρο έχει μια τιμή** που το προσδιορίζει:

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

Έτσι, σε αυτό το είδος προγράμματος, το ενδιαφέρον θα είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνηθισμένη συνάρτηση: **KEYINPUT**.

![Προβολή του Ghidra ενός δυαδικού αρχείου GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από την **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη συνάρτηση, μετά από ορισμένες αρχικές λειτουργίες (χωρίς ιδιαίτερη σημασία):

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **τελευταία πλήκτρα** και δεν είναι το τρέχον πλήκτρο, κάτι που ονομάζεται επίσης άφημα ενός κουμπιού (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): στην πρόκληση αυτό το κουμπί καθαρίζει την οθόνη
- Έπειτα, συγκρίνεται με την τιμή **8** (κουμπί **START**). Σε αυτή την πρόκληση, αυτή η διαδρομή ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
  - Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων προστίθενται στην `DAT_030000d8`.

Επομένως, σε αυτή την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, ώστε το άθροισμα των τιμών του να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [1] [Απλοποίηση της MBA obfuscation με CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο CoBRA της Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversing για GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετώπιση του AI-Assisted Reverse Engineering ή, τουλάχιστον, προσπάθεια](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση στη σύγκριση γραφημάτων ροής ελέγχου με βάση την αντιστοίχιση βασικών μπλοκ](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας γραφημάτων ροής ελέγχου για την αυτόματη απο-obfuscation δυαδικών αρχείων Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
