# Εργαλεία Αντίστροφης Μηχανικής & Βασικές Μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία Αντίστροφης Μηχανικής Βασισμένα σε ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Αποσυμπιεστής Wasm / Μεταγλωττιστής Wat

Διαδικτυακά:

- Χρησιμοποιήστε [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για να **αποσυμπιέσετε** από wasm (δυαδικό) σε wat (καθαρό κείμενο)
- Χρησιμοποιήστε [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για να **μεταγλωττίσετε** από wat σε wasm
- μπορείτε επίσης να δοκιμάσετε να χρησιμοποιήσετε [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) για αποσυμπίεση

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Αποσυμπιεστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας αποσυμπιεστής που **αποσυμπιέζει και εξετάζει πολλαπλές μορφές**, συμπεριλαμβανομένων των **βιβλιοθηκών** (.dll), **αρχείων μεταδεδομένων Windows** (.winmd) και **εκτελέσιμων** (.exe). Αφού αποσυμπιεστεί, μια assembly μπορεί να αποθηκευτεί ως έργο Visual Studio (.csproj).

Το πλεονέκτημα εδώ είναι ότι αν ένας χαμένος κωδικός πηγής απαιτεί αποκατάσταση από μια κληρονομημένη assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει βολική πλοήγηση σε όλο τον αποσυμπιεσμένο κώδικα, καθιστώντας το ένα από τα τέλεια εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο προσθέτων και μια API που επεκτείνει το εργαλείο για να ταιριάζει ακριβώς στις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας ρίξουμε μια ματιά στην πληθώρα υπηρεσιών αντίστροφης μηχανικής που παρέχει αυτό το εργαλείο:

- Παρέχει μια εικόνα για το πώς ρέει τα δεδομένα μέσω μιας βιβλιοθήκης ή συστατικού
- Παρέχει πληροφορίες για την υλοποίηση και τη χρήση γλωσσών και πλαισίων .NET
- Βρίσκει μη τεκμηριωμένη και μη εκτεθειμένη λειτουργικότητα για να αξιοποιήσει περισσότερο τις APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Βρίσκει εξαρτήσεις και διαφορετικές assemblies
- Εντοπίζει την ακριβή τοποθεσία σφαλμάτων στον κώδικά σας, σε τρίτα μέρη και βιβλιοθήκες.
- Αποσφαλματώνει την πηγή όλου του κώδικα .NET με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το έχετε σε οποιοδήποτε λειτουργικό σύστημα (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, δεν χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεστε να **αποσυμπιέσετε**, **τροποποιήσετε** και **μεταγλωττίσετε** ξανά μπορείτε να χρησιμοποιήσετε [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή μια ενεργά συντηρούμενη παραλλαγή του, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί Κλικ -> Τροποποίηση Μεθόδου** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Καταγραφή DNSpy

Για να κάνετε το **DNSpy να καταγράψει κάποιες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το απόσπασμα:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

Για να κάνετε αποσφαλμάτωση κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **Assembly attributes** που σχετίζονται με την **αποσφαλμάτωση**:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Για:
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Και κάντε κλικ στο **compile**:

![](<../../images/image (314) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω _**File >> Save module...**_:

![](<../../images/image (602).png>)

Αυτό είναι απαραίτητο γιατί αν δεν το κάνετε αυτό, κατά τη διάρκεια της **runtime** θα εφαρμοστούν πολλές **βελτιστοποιήσεις** στον κώδικα και είναι πιθανό ότι κατά την αποσφαλμάτωση μια **break-point δεν θα χτυπηθεί** ή κάποιες **μεταβλητές δεν θα υπάρχουν**.

Στη συνέχεια, αν η εφαρμογή .NET σας εκτελείται από το **IIS** μπορείτε να την **επανεκκινήσετε** με:
```
iisreset /noforce
```
Στη συνέχεια, για να ξεκινήσετε την αποσφαλμάτωση, θα πρέπει να κλείσετε όλα τα ανοιχτά αρχεία και μέσα στην **Κατηγορία Αποσφαλμάτωσης** να επιλέξετε **Σύνδεση με Διαδικασία...**:

![](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε **w3wp.exe** για να συνδεθείτε με τον **διακομιστή IIS** και κάντε κλικ στο **σύνδεση**:

![](<../../images/image (113).png>)

Τώρα που αποσφαλματώνουμε τη διαδικασία, ήρθε η ώρα να την σταματήσουμε και να φορτώσουμε όλα τα modules. Πρώτα κάντε κλικ στο _Αποσφαλμάτωση >> Διακοπή Όλων_ και στη συνέχεια κάντε κλικ στο _**Αποσφαλμάτωση >> Παράθυρα >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Άνοιγμα Όλων των Modules**:

![](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και κάντε κλικ στο **Ταξινόμηση Συγκροτημάτων**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Αποσφαλμάτωση DLLs

### Χρησιμοποιώντας IDA

- **Φορτώστε το rundll32** (64bit στο C:\Windows\System32\rundll32.exe και 32bit στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε **Windbg** debugger
- Επιλέξτε "**Αναστολή κατά τη φόρτωση/εκφόρτωση βιβλιοθήκης**"

![](<../../images/image (868).png>)

- Ρυθμίστε τις **παραμέτρους** της εκτέλεσης βάζοντας το **μονοπάτι στη DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε την αποσφαλμάτωση, **η εκτέλεση θα σταματήσει όταν φορτωθεί κάθε DLL**, και όταν το rundll32 φορτώσει τη DLL σας, η εκτέλεση θα σταματήσει.

Αλλά, πώς μπορείτε να φτάσετε στον κώδικα της DLL που φορτώθηκε; Χρησιμοποιώντας αυτή τη μέθοδο, δεν ξέρω πώς.

### Χρησιμοποιώντας x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bit στο C:\Windows\System32\rundll32.exe και 32bit στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη Γραμμή Εντολών** (_Αρχείο --> Αλλαγή Γραμμής Εντολών_) και ορίστε το μονοπάτι της dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε _Επιλογές --> Ρυθμίσεις_ και επιλέξτε "**Είσοδος DLL**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**, ο debugger θα σταματήσει σε κάθε κύρια dll, σε κάποιο σημείο θα **σταματήσετε στην είσοδο της dll σας**. Από εκεί, απλώς αναζητήστε τα σημεία όπου θέλετε να βάλετε ένα breakpoint.

Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας **στην κορυφή του παραθύρου win64dbg**:

![](<../../images/image (842).png>)

Στη συνέχεια, κοιτάζοντας αυτό μπορείτε να δείτε πότε η εκτέλεση σταμάτησε στη dll που θέλετε να αποσφαλματώσετε.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να βρείτε πού αποθηκεύονται σημαντικές τιμές μέσα στη μνήμη ενός τρέχοντος παιχνιδιού και να τις αλλάξετε. Περισσότερες πληροφορίες στο:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα εργαλείο front-end/αντίστροφης μηχανικής για τον GNU Project Debugger (GDB), επικεντρωμένο σε παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιοδήποτε σχετικό με την αντίστροφη μηχανική.

[**Decompiler Explorer**](https://dogbolt.org/) είναι ένα διαδικτυακό front-end για αρκετούς decompilers. Αυτή η διαδικτυακή υπηρεσία σας επιτρέπει να συγκρίνετε την έξοδο διαφορετικών decompilers σε μικρές εκτελέσιμες.

## ARM & MIPS

{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση ενός shellcode με το blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) θα **κατανείμει** το **shellcode** μέσα σε έναν χώρο μνήμης, θα **υποδείξει** τη **διεύθυνση μνήμης** όπου το shellcode κατανέμεται και θα **σταματήσει** την εκτέλεση.\
Στη συνέχεια, θα χρειαστεί να **συνδέσετε έναν debugger** (Ida ή x64dbg) στη διαδικασία και να βάλετε ένα **breakpoint στη διεύθυνση μνήμης που υποδείχθηκε** και να **συνεχίσετε** την εκτέλεση. Με αυτόν τον τρόπο θα αποσφαλματώνετε το shellcode.

Η σελίδα κυκλοφορίας στο github περιέχει zip με τις εκδόσεις που έχουν μεταγλωττιστεί: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να το μεταγλωττίσετε, απλώς **δημιουργήστε ένα έργο C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.

{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση ενός shellcode με το jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)είναι πολύ παρόμοιο με το blobrunner. Θα **κατανείμει** το **shellcode** μέσα σε έναν χώρο μνήμης και θα ξεκινήσει έναν **αιώνιο βρόχο**. Στη συνέχεια, θα χρειαστεί να **συνδέσετε τον debugger** στη διαδικασία, **πατήστε start, περιμένετε 2-5 δευτερόλεπτα και πατήστε stop** και θα βρεθείτε μέσα στον **αιώνιο βρόχο**. Μεταβείτε στην επόμενη εντολή του αιώνιου βρόχου καθώς θα είναι μια κλήση στο shellcode, και τελικά θα βρεθείτε να εκτελείτε το shellcode.

![](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it στη σελίδα κυκλοφορίας](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode χρησιμοποιώντας το Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Χρησιμοποιώντας το cutter μπορείτε να προσομοιώσετε το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter σας επιτρέπει να "Ανοίξετε Αρχείο" και "Ανοίξετε Shellcode". Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο, το αποσυμπίεσε σωστά, αλλά όταν το άνοιξα ως shellcode δεν το έκανε:

![](<../../images/image (562).png>)

Για να ξεκινήσετε την προσομοίωση από το σημείο που θέλετε, ορίστε ένα bp εκεί και προφανώς το cutter θα ξεκινήσει αυτόματα την προσομοίωση από εκεί:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Μπορείτε να δείτε τη στοίβα, για παράδειγμα, μέσα σε μια εξαγωγή hex:

![](<../../images/image (186).png>)

### Αποκατάσταση shellcode και λήψη εκτελούμενων συναρτήσεων

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας πει πράγματα όπως **ποιες συναρτήσεις** χρησιμοποιεί το shellcode και αν το shellcode **αποκωδικοποιεί** τον εαυτό του στη μνήμη.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg διαθέτει επίσης έναν γραφικό εκκινητή όπου μπορείτε να επιλέξετε τις επιλογές που θέλετε και να εκτελέσετε το shellcode

![](<../../images/image (258).png>)

Η επιλογή **Create Dump** θα αποθηκεύσει το τελικό shellcode αν γίνει οποιαδήποτε αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για να κατεβάσετε το αποκωδικοποιημένο shellcode). Η **start offset** μπορεί να είναι χρήσιμη για να ξεκινήσετε το shellcode σε μια συγκεκριμένη θέση. Η επιλογή **Debug Shell** είναι χρήσιμη για να κάνετε αποσφαλμάτωση του shellcode χρησιμοποιώντας το τερματικό scDbg (ωστόσο, θεωρώ ότι οποιαδήποτε από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτό το θέμα καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Disassembling using CyberChef

Ανεβάστε το αρχείο shellcode σας ως είσοδο και χρησιμοποιήστε την παρακάτω συνταγή για να το αποσυμπιέσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator **τροποποιεί όλες τις εντολές για `mov`** (ναι, πραγματικά ωραίο). Χρησιμοποιεί επίσης διακοπές για να αλλάξει τις ροές εκτέλεσης. Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργεί:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Αν έχετε τύχη, ο [demovfuscator](https://github.com/kirschju/demovfuscator) θα αποκαταστήσει την ορατότητα του δυαδικού. Έχει αρκετές εξαρτήσεις
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Και [install keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε ένα **CTF, αυτή η λύση για να βρείτε τη σημαία** θα μπορούσε να είναι πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point** αναζητήστε τις συναρτήσεις με `::main` όπως στο:

![](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το δυαδικό αρχείο ονομάζεται authenticator, οπότε είναι προφανές ότι αυτή είναι η ενδιαφέρουσα κύρια συνάρτηση.\
Έχοντας το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε για τις **εισόδους** και **εξόδους** τους.

## **Delphi**

Για τα δυαδικά αρχεία που έχουν μεταγλωττιστεί με Delphi μπορείτε να χρησιμοποιήσετε [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να αναστρέψετε ένα δυαδικό αρχείο Delphi, θα σας πρότεινα να χρησιμοποιήσετε το plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Απλά πατήστε **ATL+f7** (εισαγωγή python plugin στο IDA) και επιλέξτε το python plugin.

Αυτό το plugin θα εκτελέσει το δυαδικό αρχείο και θα επιλύσει τα ονόματα των συναρτήσεων δυναμικά στην αρχή της αποσφαλμάτωσης. Μετά την έναρξη της αποσφαλμάτωσης, πατήστε ξανά το κουμπί Έναρξη (το πράσινο ή f9) και ένα breakpoint θα χτυπήσει στην αρχή του πραγματικού κώδικα.

Είναι επίσης πολύ ενδιαφέρον γιατί αν πατήσετε ένα κουμπί στην γραφική εφαρμογή, ο αποσφαλματωτής θα σταματήσει στη συνάρτηση που εκτελείται από αυτό το κουμπί.

## Golang

Αν πρέπει να αναστρέψετε ένα δυαδικό αρχείο Golang, θα σας πρότεινα να χρησιμοποιήσετε το plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Απλά πατήστε **ATL+f7** (εισαγωγή python plugin στο IDA) και επιλέξτε το python plugin.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

## Compiled Python

Σε αυτή τη σελίδα μπορείτε να βρείτε πώς να αποκτήσετε τον κώδικα python από ένα δυαδικό αρχείο python που έχει μεταγλωττιστεί σε ELF/EXE:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Αν αποκτήσετε το **δυαδικό** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να **εξομοιώσετε** και να **αποσφαλματώσετε** αυτό:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση αποσφαλμάτωσης_) - Περιέχει έναν αποσφαλματωτή με διεπαφή
- [**mgba** ](https://mgba.io)- Περιέχει έναν CLI αποσφαλματωτή
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra plugin
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra plugin

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στο _**Options --> Emulation Setup --> Controls**_\*\* \*\* μπορείτε να δείτε πώς να πατήσετε τα κουμπιά του Game Boy Advance **buttons**

![](<../../images/image (581).png>)

Όταν πατηθούν, κάθε **κουμπί έχει μια τιμή** για να το αναγνωρίσει:
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
Έτσι, σε αυτό το είδος προγράμματος, το ενδιαφέρον μέρος θα είναι **πώς το πρόγραμμα επεξεργάζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνήθως συναντώμενη συνάρτηση: **KEYINPUT**.

![](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από κάποιες αρχικές λειτουργίες (χωρίς καμία σημασία):
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
Η τελευταία συνθήκη ελέγχει αν **`uVar4`** είναι στα **τελευταία Κλειδιά** και όχι το τρέχον κλειδί, που ονομάζεται επίσης απελευθέρωση ενός κουμπιού (το τρέχον κλειδί αποθηκεύεται στο **`uVar1`**).
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
Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε **uVar1** (το σημείο όπου βρίσκεται το **value of the pressed button**) με κάποιες τιμές:

- Πρώτα, συγκρίνεται με την **τιμή 4** (**SELECT** κουμπί): Στην πρόκληση αυτό το κουμπί καθαρίζει την οθόνη
- Στη συνέχεια, συγκρίνεται με την **τιμή 8** (**START** κουμπί): Στην πρόκληση αυτό ελέγχει αν ο κώδικας είναι έγκυρος για να πάρει τη σημαία.
- Σε αυτή την περίπτωση η μεταβλητή **`DAT_030000d8`** συγκρίνεται με 0xf3 και αν η τιμή είναι η ίδια εκτελείται κάποιος κώδικας.
- Σε οποιαδήποτε άλλη περίπτωση, ελέγχεται κάποιος μετρητής (`DAT_030000d4`). Είναι μετρητής γιατί προσθέτει 1 αμέσως μετά την είσοδο στον κώδικα.\
**Α**ν είναι λιγότερο από 8, γίνεται κάτι που περιλαμβάνει **πρόσθεση** τιμών σε \*\*`DAT_030000d8` \*\* (βασικά προσθέτει τις τιμές των κουμπιών που πατήθηκαν σε αυτή τη μεταβλητή όσο ο μετρητής είναι λιγότερος από 8).

Έτσι, σε αυτή την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8 ώστε η προκύπτουσα πρόσθεση να είναι 0xf3.**

**Αναφορά για αυτό το σεμινάριο:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

{{#include ../../banners/hacktricks-training.md}}
