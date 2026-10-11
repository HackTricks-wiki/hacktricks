# Reversing Tools & Βασικές Μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία Reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Debugging πυρήνα Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Απομεταγλωττιστής Wasm / Μεταγλωττιστής Wat

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **απομεταγλώττιση** από wasm (δυαδική μορφή) σε wat (απλό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **μεταγλώττιση** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για απομεταγλώττιση.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode σε cache για Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Απομεταγλωττιστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας απομεταγλωττιστής που **απομεταγλωττίζει και εξετάζει πολλαπλές μορφές**, συμπεριλαμβανομένων **βιβλιοθηκών** (.dll), **αρχείων μεταδεδομένων των Windows** (.winmd) και **εκτελέσιμων αρχείων** (.exe). Μετά την απομεταγλώττιση, μια assembly μπορεί να αποθηκευτεί ως έργο Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να αποκατασταθεί χαμένος πηγαίος κώδικας από μια παλαιότερη assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύκολη πλοήγηση στον απομεταγλωττισμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει ακριβώς τις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολυάριθμες υπηρεσίες reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα για τον τρόπο με τον οποίο ρέουν τα δεδομένα μέσα από μια βιβλιοθήκη ή ένα στοιχείο
- Παρέχει εικόνα για την υλοποίηση και τη χρήση γλωσσών και frameworks .NET
- Εντοπίζει μη τεκμηριωμένες και μη εκτεθειμένες λειτουργίες, ώστε να αξιοποιείτε καλύτερα τα API και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει εξαρτήσεις και διαφορετικές assemblies
- Εντοπίζει την ακριβή θέση των σφαλμάτων στον κώδικά σας, σε στοιχεία τρίτων και σε βιβλιοθήκες.
- Κάνει debugging στον πηγαίο κώδικα όλου του κώδικα .NET με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Πρόσθετο ILSpy για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε λειτουργικό σύστημα (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να **απομεταγλωττίσετε**, να **τροποποιήσετε** και να **μεταγλωττίσετε ξανά**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα fork του που συντηρείται ενεργά, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί κλικ -> Modify Method** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Καταγραφή στο DNSpy

Για να κάνετε το **DNSpy να καταγράφει πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το απόσπασμα κώδικα:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Για να κάνετε debugging κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **Assembly attributes** που σχετίζονται με το **debugging**:

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

![Καταγραφή στο DNSpy - Αποσφαλμάτωση στο DNSpy: Κάντε κλικ στο compile](<../../images/image (314) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω _**File >> Save module...**_:

![Καταγραφή στο DNSpy - Αποσφαλμάτωση στο DNSpy: Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, επειδή αν δεν το κάνετε, κατά τον **runtime** θα εφαρμοστούν αρκετές **optimisations** στον κώδικα και ενδέχεται, κατά την αποσφαλμάτωση, ένα **break-point να μην ενεργοποιηθεί ποτέ** ή κάποιες **μεταβλητές να μην υπάρχουν**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα **Debug Tab** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα Debug Tab επιλέξτε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging της διεργασίας, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Πρώτα, κάντε κλικ στο _Debug >> Break All_ και, στη συνέχεια, στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging της διεργασίας, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Πρώτα, κάντε κλικ στο Debug Break All και, στη συνέχεια, στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging της διεργασίας, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Πρώτα, κάντε κλικ στο Debug Break All και, στη συνέχεια, στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε τον debugger **Windbg**
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Διαμορφώστε τις **παραμέτρους** εκτέλεσης, εισάγοντας τη **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Διαμορφώστε τις παραμέτρους εκτέλεσης, εισάγοντας τη διαδρομή προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα διακόπτεται κάθε φορά που φορτώνεται ένα DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση στα συμβάντα φόρτωσης module, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση από ό,τι με τη ροή εργασίας του x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε τη διαδρομή του DLL και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Ανοίξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και κάποια στιγμή θα **σταματήσει στο DLL Entry του DLL σας**. Από εκεί, απλώς αναζητήστε τα σημεία στα οποία θέλετε να τοποθετήσετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε**, κοιτάζοντας **στο επάνω μέρος του παραθύρου του win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε, κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει σταματήσει μέσα στο DLL που θέλετε να κάνετε debugging.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετική με το reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompiler. Αυτή η διαδικτυακή υπηρεσία σάς επιτρέπει να συγκρίνετε την έξοδο διαφορετικών decompiler σε μικρά εκτελέσιμα αρχεία.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει χώρο για το **shellcode**, εμφανίζει τη **διεύθυνση μνήμης** του και διακόπτει την εκτέλεση.\
Συνδεθείτε με έναν debugger, όπως το IDA ή το x64dbg, ορίστε breakpoint στη διεύθυνση που εμφανίστηκε και συνεχίστε την εκτέλεση για να κάνετε debugging του shellcode.

Η σελίδα releases στο GitHub περιέχει zip με τις μεταγλωττισμένες εκδόσεις: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, **δημιουργήστε ένα project C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει χώρο για το shellcode και εισέρχεται σε έναν ατέρμονο βρόχο. Συνδεθείτε με τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, κάντε pause μέσα στον βρόχο και προχωρήστε στην επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει κάνει pause στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το εξετάσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να επιλέξετε "Open File" και "Open Shellcode". Στη δική μου περίπτωση, όταν άνοιξα το shellcode ως αρχείο, έγινε σωστό decompile, αλλά όταν το άνοιξα ως shellcode, δεν έγινε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγει τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσετε το emulation από το σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα το emulation από εκεί:

![Ορισμός breakpoint στο επιθυμητό σημείο εισόδου του shellcode πριν από την εκκίνηση του emulation στο Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter έχει κάνει pause στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Για παράδειγμα, μπορείτε να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του shellcode που γίνεται emulate στο hex dump του Cutter](<../../images/image (186).png>)

### Αποκωδικοποίηση shellcode και εντοπισμός συναρτήσεων που εκτελούνται

Δοκιμάστε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας δείξει, για παράδειγμα, **ποιες συναρτήσεις** χρησιμοποιεί το shellcode και αν **αποκωδικοποιεί** τον εαυτό του στη μνήμη.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

Το scDbg διαθέτει επίσης ένα γραφικό πρόγραμμα εκκίνησης, όπου μπορείτε να επιλέξετε τις επιθυμητές ρυθμίσεις και να εκτελέσετε το shellcode

![Γραφικό πρόγραμμα εκκίνησης του scDbg για την επιλογή ρυθμίσεων εξομοίωσης και ανίχνευσης shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** αποθηκεύει το τελικό shellcode, αν αυτό έχει τροποποιηθεί δυναμικά στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Το **start offset** μπορεί να χρησιμοποιηθεί για την εκκίνηση του shellcode από συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων στο shellcode μέσω του τερματικού του scDbg (ωστόσο, θεωρώ ότι οι επιλογές που εξηγήθηκαν παραπάνω είναι καλύτερες, καθώς μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με το CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε την παρακάτω συνταγή για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Αποσυσκότιση MBA

Η συσκότιση **Mixed Boolean-Arithmetic (MBA)** κρύβει απλές εκφράσεις, όπως η `x + y`, πίσω από τύπους που συνδυάζουν αριθμητικές πράξεις (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts`). Το σημαντικό είναι ότι αυτές οι ταυτότητες ισχύουν συνήθως μόνο υπό **αριθμητική modulo σταθερού πλάτους**, επομένως τα κρατούμενα και οι υπερχειλίσεις έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτό το είδος έκφρασης με γενικά εργαλεία άλγεβρας, μπορεί εύκολα να καταλήξετε σε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον lifted κώδικα/IR/την έξοδο του decompiler (`8/16/32/64` bits).
2. **Κατηγοριοποιήστε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα bitwise ατόμων
   - **Ημιγραμμική**: γραμμική έκφραση συν σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: περιέχει γινόμενα
   - **Μικτή**: γινόμενα και bitwise λογική είναι αλληλένδετα, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια αναδιατύπωση** με τυχαίες δοκιμές ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, διατηρήστε την αρχική έκφραση αντί να μαντέψετε.

### Παρακάμψτε την flattened ροή ελέγχου με ένα στενό τμήμα εκτέλεσης

Συχνά δεν χρειάζεται να ανακτήσετε ολόκληρο το γράφημα ροής ελέγχου. Σε περιπτώσεις control-flow flattening, opaque predicates, μεγάλων dispatchers ή κώδικα με πολλά MBA, ακολουθήστε τις αναφορές από encrypted blobs και buffers εξόδου μέχρι τη μικρότερη ρουτίνα που τα μετασχηματίζει. Έπειτα, αναπαραγάγετε μόνο αυτό το τμήμα ροής δεδομένων ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, αν η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα εκτελέσιμα τμήματα και τα τμήματα δεδομένων, τις relocations και τις διασταυρούμενες αναφορές. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των byte και το πλάτος των στοιχείων τους.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει το plaintext ή το buffer εξόδου. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις εισαγόμενες κλήσεις και την απαιτούμενη καθολική κατάσταση.
3. Ανυψώστε μόνο αυτές τις πράξεις σε ένα μοντέλο Python σταθερού πλάτους. Αν το τμήμα εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα με Unicorn, QEMU ή debugger και κάντε hook τις άσχετες εισαγωγές αντί να εξομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι την έξοδό του από το δοσμένο binary: αφαιρέστε τις σιωπηρές εναλλακτικές λύσεις, αναζητήστε ενσωματωμένες απαντήσεις και δοκιμάστε τον σε builds που δεν έχει ξαναδεί, με αλλαγμένες συμβολοσειρές, κλειδιά, αναγνωριστικά, διατάξεις και seeds obfuscation.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός εκφράσεων MBA που είναι μεταμφιεσμένες σταθερές

Μια έκφραση byte που φαίνεται να εξαρτάται από την είσοδο μπορεί να ακυρώνει πλήρως την είσοδό της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το πεδίο των 8 bit· ένα σύνολο εξόδων με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε την περιβάλλουσα μηχανή καταστάσεων.<sup>[[7]](#references)</sup>

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

Διατηρήστε την τελική μάσκα, επειδή στην αρχική πρόσθεση γίνεται αναδίπλωση στο εύρος του byte. Για ευρύτερο πεδίο τιμών, ρωτήστε έναν SMT solver αν η έκφραση `f(x1) != f(x2)` είναι ικανοποιήσιμη για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει ότι η συνάρτηση είναι αμετάβλητη, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνωρίστε αποκωδικοποίηση εξαρτώμενη από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας decoder μπορεί να αναμείξει το αποτέλεσμα ενός αισθητήρα σε ένα bit του κλειδιού, σε μια σταθερά opaque predicate ή στην κατάσταση ενός flattened dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά ψευδές plaintext σε έναν emulator. Επομένως, δεν αρκεί η τροποποίηση μόνο των ορατών κλάδων αποτυχίας· παρακολουθήστε τις εξαρτήσεις δεδομένων από τους ανιχνευτές περιβάλλοντος έως την κατάσταση του decoder, συγκρίνετε το ίδιο τμήμα στον αυθεντικό device και στον emulator και ελέγξτε πώς η επιβολή κάθε αποτελέσματος αισθητήρα αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένα πρακτικό εργαλείο απλοποίησης MBA για ανάλυση malware και reversing προστατευμένων binaries. Ταξινομεί την έκφραση και τη διοχετεύει σε εξειδικευμένες διαδικασίες, αντί να εφαρμόζει ένα γενικό πέρασμα επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean εισόδους, παράγει μια υπογραφή και εκτελεί παράλληλα διάφορες μεθόδους ανάκτησης, όπως αντιστοίχιση μοτίβων, μετατροπή ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα άτομα με μάσκες σταθερών ανακατασκευάζονται με ανακατασκευή διαμερισμένη σε bit, ώστε οι περιοχές με μάσκες να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αποσυντίθενται σε πυρήνες, ενώ επαναλαμβανόμενες υποεκφράσεις μπορούν να μετατραπούν σε προσωρινές μεταβλητές πριν από την απλοποίηση της εξωτερικής σχέσης.

Παράδειγμα μικτής ταυτότητας που συχνά αξίζει να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να συμπτυχθεί σε:

```c
x * y
```

### Σημειώσεις reverse engineering

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, δείτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), το οποίο είναι χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από μεταγενέστερα analysis passes.
- Τα μη υποστηριζόμενα carry-sensitive mixed-domain residuals θα πρέπει να θεωρούνται ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα τη διαδρομή του carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί signal/exception handling για να τροποποιεί τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές εξαρτήσεις.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν συμμετέχετε σε **CTF, αυτός ο τρόπος αντιμετώπισης για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμος: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point**, αναζητήστε τις συναρτήσεις με `::main`, όπως εδώ:

![Εντοπισμός ενός Rust entry point στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για διπλή άνω και κάτω τελεία και main](<../../images/image (1080).png>)

Σε αυτήν την περίπτωση, το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα συνάρτηση main.\
Έχοντας τα **ονόματα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση Rust strings από ELF firmware

Σε **Rust ELF** binaries, πολλά στατικά strings δεν αναφέρονται μέσω δεικτών με τερματισμό NUL, όπως στα C. Μια συνηθισμένη διάταξη του `rustc` είναι ένα **ζεύγος δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, που δείχνει στο πραγματικό string blob το οποίο είναι αποθηκευμένο στο **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικές συμβολοσειρές ή να παραλείψει εντελώς τις διασταυρούμενες αναφορές.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Λάβετε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία λέξη κάθε φορά.
3. Αντιμετωπίστε κάθε τιμή εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Αντιμετωπίστε την επόμενη λέξη ως το υποψήφιο μήκος.
5. Εφαρμόστε φίλτρα εγκυρότητας (για παράδειγμα, κρατήστε μήκη από **4** έως **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata`, αντί να σαρώσετε μέχρι το `0x00`.

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

Αν το Ghidra δεν εντοπίσει αυτές τις συμβολοσειρές, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί string data στα αναφερόμενα offsets του `.rodata`. Τα εργαλεία `rust-strings` και `RustStrings.py` που δημοσίευσε η Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν γίνει compile με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα function names κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη function που καλείται από αυτό το κουμπί.

## Golang

Αν πρέπει να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα names των functions.

## Compiled Python

Σε αυτή τη σελίδα μπορείτε να δείτε πώς να ανακτήσετε τον κώδικα Python από ένα compiled Python binary ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να κάνετε **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με interface
- [**mgba** ](https://mgba.io)- Περιλαμβάνει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στη διαδρομή _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Όταν πατηθεί, κάθε **πλήκτρο έχει μια τιμή** που το αναγνωρίζει:

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

Λοιπόν, σε αυτό το είδος προγράμματος, το ενδιαφέρον είναι **πώς χειρίζεται το πρόγραμμα την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνάρτηση που συναντάται συχνά: **KEYINPUT**.

![Προβολή του Ghidra ενός binary GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτήν τη συνάρτηση, μετά από ορισμένες αρχικοποιήσεις (χωρίς ιδιαίτερη σημασία):

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στο τελευταίο Keys και δεν είναι το τρέχον key, δηλαδή αν αφήνουμε ένα κουμπί (το τρέχον key αποθηκεύεται στο **`uVar1`**).

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

Στον προηγούμενο κώδικα βλέπετε ότι συγκρίνουμε το **uVar1** (τη θέση όπου βρίσκεται η **τιμή του πατημένου κουμπιού**) με κάποιες τιμές:

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): στην πρόκληση, αυτό το κουμπί καθαρίζει την οθόνη.
- Έπειτα, η τιμή συγκρίνεται με το **8** (κουμπί **START**). Σε αυτή την πρόκληση, αυτή η διαδρομή ελέγχει αν ο κωδικός που πληκτρολογήθηκε είναι έγκυρος.
  - Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων αθροίζονται στο `DAT_030000d8`.

Έτσι, σε αυτή την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, ώστε το άθροισμα να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένη λύση της πρόκλησης Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Αποσυσκότιση Binary)

## References

- [1] [Απλοποίηση της MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο CoBRA του Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - συμβολοσειρές Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial για reverse engineering σε GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετώπιση του reverse engineering με τη βοήθεια AI ή, τουλάχιστον, προσπάθεια](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
