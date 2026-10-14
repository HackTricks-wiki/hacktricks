# Εργαλεία Reversing και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Εντοπισμός σφαλμάτων στον πυρήνα των Windows

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

## Εικονικοποιημένα payloads και προσαρμοσμένα VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένα decompiler που **κάνει decompile και εξετάζει πολλαπλές μορφές**, όπως **libraries** (.dll), αρχεία **Windows metadata** (.winmd) και **executables** (.exe). Μετά το decompile, ένα assembly μπορεί να αποθηκευτεί ως project Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να ανακτηθεί χαμένος πηγαίος κώδικας από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek διευκολύνει την πλοήγηση στον decompiled κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει ακριβώς τις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολλές υπηρεσίες reverse engineering που παρέχει αυτό το εργαλείο:

- Δίνει εικόνα για το πώς ρέουν τα δεδομένα μέσα από ένα library ή component
- Δίνει εικόνα για την υλοποίηση και τη χρήση γλωσσών και frameworks .NET
- Εντοπίζει μη τεκμηριωμένες και μη εκτεθειμένες λειτουργίες, ώστε να αξιοποιείτε καλύτερα τα APIs και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή θέση των σφαλμάτων στον κώδικά σας, σε components τρίτων και σε libraries.
- Κάνει debugging στον πηγαίο κώδικα όλου του .NET κώδικα με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Πρόσθετο ILSpy για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να κάνετε **decompile**, **modify** και ξανά **recompile**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα ενεργά συντηρούμενο fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** για να αλλάξετε κάτι μέσα σε μια function).

### Επιθεώρηση managed κώδικα χωρίς εκτέλεση με το REA

Το **REA** μπορεί να επιθεωρήσει PE/CLI metadata και CIL χωρίς να φορτώσει το assembly. Ξεκινήστε με την ταυτότητα του artifact και, στη συνέχεια, εξετάστε τα μέλη και τα δηλωμένα όρια native κώδικα. Αυτό είναι χρήσιμο κατά την εξέταση ύποπτων κλήσεων, πριν χρησιμοποιήσετε decompiler ή εκτελέσετε το πρόγραμμα.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Για τη σύγκριση διαφορών μεταξύ εκδόσεων, το `compare_managed_members` χρησιμοποιεί ταυτότητα βάσει raw CIL/signature και fingerprints αποκωδικοποιημένων εντολών, αντί να θεωρεί τα metadata tokens σταθερά μεταξύ builds. Μια δήλωση P/Invoke δεν αποδεικνύει ότι εκτελέστηκε native code· το `verify_managed_native_boundaries` χρειάζεται αντίστοιχο native export ή function Evidence για να ελέγξει αυτό το όριο. Διατηρήστε το artifact digest, το MVID και τις ανεπίλυτες αντιστοιχίσεις μαζί με το αποτέλεσμα.<sup>[[17]](#references)</sup>

### Καταγραφή DNSpy

Για να κάνετε το **DNSpy να καταγράφει κάποιες πληροφορίες σε αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Για να κάνετε debugging κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **Assembly attributes** που σχετίζονται με το **debugging**:

![Καταγραφή DNSpy - DNSpy Debugging: Αρχικά, αλλάξτε τα Assembly attributes που σχετίζονται με το debugging](<../../images/image (973).png>)

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

And click on **compile**:

![DNSpy Logging - DNSpy Debugging: Και κάντε κλικ στο compile](<../../images/image (314) (1).png>)

Then save the new file via _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω του File Save module](<../../images/image (602).png>)

This is necessary because if you don't do this, at **runtime** several **optimisations** will be applied to the code and it could be possible that while debugging a **break-point is never hit** or some **variables don't exist**.

Then, if your .NET application is being **run** by **IIS** you can **restart** it with:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από το **Debug Tab** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από το Debug Tab επιλέξτε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε **w3wp.exe** για να συνδεθείτε στον **IIS server** και πατήστε **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε w3wp.exe για να συνδεθείτε στον IIS server και πατήστε attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging τη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, πατήστε _Debug >> Break All_ και, στη συνέχεια, _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging τη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, πατήστε Debug Break All και, στη συνέχεια, Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging τη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, πατήστε Debug Break All και, στη συνέχεια, Debug Windows Modules](<../../images/image (834).png>)

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

- Διαμορφώστε τις **παραμέτρους** εκτέλεσης, προσθέτοντας το **path προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Διαμορφώστε τις παραμέτρους εκτέλεσης, προσθέτοντας το path προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα διακόπτεται κάθε φορά που φορτώνεται ένα DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση σε συμβάντα φόρτωσης module, αλλά η μετάβαση στο entry point του DLL που φορτώθηκε είναι λιγότερο άμεση από ό,τι με τη ροή εργασίας x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε το path του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και κάποια στιγμή θα **σταματήσει στο DLL Entry του DLL σας**. Από εκεί, αναζητήστε τα σημεία όπου θέλετε να βάλετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας στο **επάνω μέρος του παραθύρου win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε κοιτάζοντας στο επάνω μέρος του παραθύρου win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει σταματήσει μέσα στο DLL που θέλετε να κάνετε debug.

## GUI Apps / Videogames

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετική με reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορα decompilers. Αυτή η web υπηρεσία σάς επιτρέπει να συγκρίνετε την έξοδο διαφορετικών decompilers σε μικρά εκτελέσιμα αρχεία.

## Evidence-backed native investigation with REA

Το **REA** παρέχει πρόσβαση μέσω CLI και MCP στις αναλύσεις των Hopper, Ghidra και IDA. Απαιτεί Node.js 22.x (τουλάχιστον 22.19), 24.x (τουλάχιστον 24.11) ή 26+, καθώς και npm. Διαμορφώστε πρώτα έναν υπάρχοντα native provider. Ελέγξτε το `rea providers --json` και επιλέξτε ρητά έναν provider όταν περισσότεροι από ένας υποστηρίζουν τον στόχο. Χρησιμοποιήστε ένα όνομα συνάρτησης ή μια διεύθυνση που παρατηρήσατε στο inventory, αντί για το `0x1000` παρακάτω.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Ξεκινήστε από ένα feature string ή symbol, ακολουθήστε τις references και τους callers και, στη συνέχεια, εξετάστε το dossier και το pseudocode της επιλεγμένης συνάρτησης με `rea decompile`. Το REA δεσμεύει μια session στον επιλεγμένο provider, αντί να τον αντικαθιστά σιωπηρά μετά από αποτυχία. Για επαναλήψιμα queries, το `--snapshot PATH` επαναχρησιμοποιεί μόνο bytes artifact, provider, settings, operation και parameters που ταιριάζουν· ένα snapshot είναι τοπική cache, όχι αποθηκευμένη βάση δεδομένων provider. Διατηρήστε το Evidence που επιστρέφεται και τα ρητά άγνωστα στοιχεία, αντί να αντιμετωπίζετε τα συναγόμενα paths ή το κείμενο του decompiler ως αρχικό source.<sup>[[16]](#references)[[18]](#references)</sup>

Για entry points JavaScript/Electron που οδηγούν σε native add-ons, δείτε [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει το **shellcode**, εκτυπώνει τη **διεύθυνση μνήμης** του και διακόπτει την εκτέλεση.\
Συνδέστε έναν debugger, όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εκτυπώθηκε και συνεχίστε την εκτέλεση για να αποσφαλματώσετε το shellcode.

Η σελίδα releases στο GitHub περιέχει zip με τις μεταγλωττισμένες εκδόσεις: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει το shellcode και μπαίνει σε έναν ατέρμονο βρόχο. Συνδέστε τον debugger, συνεχίστε για **2–5 δευτερόλεπτα**, διακόψτε μέσα στον βρόχο και κάντε step μέχρι την επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει διακοπεί στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να προσομοιώσετε το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter επιτρέπει τις επιλογές "Open File" και "Open Shellcode". Στη δική μου περίπτωση, όταν άνοιξα το shellcode ως αρχείο, το αποσυμβόλισε σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγει τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσει η προσομοίωση στο σημείο που θέλετε, ορίστε εκεί ένα bp· φαίνεται ότι το Cutter ξεκινά αυτόματα την προσομοίωση από εκεί:

![Ορισμός breakpoint στην επιθυμητή είσοδο του shellcode πριν από την έναρξη της προσομοίωσης στο Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter έχει διακοπεί στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε τη στοίβα μέσα σε ένα hex dump:

![Προβολή της στοίβας του προσομοιωμένου shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Αποσυσκότιση shellcode και εντοπισμός συναρτήσεων που εκτελούνται

Δοκιμάστε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει, για παράδειγμα, **ποιες συναρτήσεις** χρησιμοποιεί το shellcode και αν **αποκωδικοποιεί** τον εαυτό του στη μνήμη.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

Το scDbg διαθέτει επίσης ένα γραφικό launcher, όπου μπορείτε να επιλέξετε τις επιθυμητές ρυθμίσεις και να εκτελέσετε το shellcode

![Γραφικό launcher του scDbg για την επιλογή ρυθμίσεων emulation και tracing του shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** δημιουργεί ένα dump του τελικού shellcode, αν έχει γίνει κάποια αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Το **start offset** μπορεί να είναι χρήσιμο για την εκκίνηση του shellcode από ένα συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων του shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι κάποια από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτόν τον σκοπό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με το CyberChef

Μεταφορτώστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε την ακόλουθη συνταγή για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Αποκάλυψη obfuscation MBA

Το obfuscation **Mixed Boolean-Arithmetic (MBA)** κρύβει απλές εκφράσεις όπως `x + y` πίσω από τύπους που συνδυάζουν αριθμητικές πράξεις (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες ισχύουν συνήθως μόνο υπό **αριθμητική modular σταθερού πλάτους**, επομένως τα carry και τα overflow έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτό το είδος έκφρασης με γενικά εργαλεία άλγεβρας, μπορεί εύκολα να καταλήξετε σε λάθος αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον lifted κώδικα/IR/την έξοδο του decompiler (`8/16/32/64` bit).
2. **Ταξινομήστε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα ατομικών bitwise εκφράσεων
   - **Ημιγραμμική**: γραμμική έκφραση συν σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: υπάρχουν γινόμενα
   - **Μικτή**: τα γινόμενα και η bitwise λογική είναι αλληλένδετα, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια αντικατάσταση** με τυχαίες δοκιμές ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, διατηρήστε την αρχική έκφραση αντί να μαντέψετε.

### Παρακάμψτε την ισοπεδωμένη ροή ελέγχου με ένα περιορισμένο τμήμα εκτέλεσης

Συχνά δεν χρειάζεται να ανακτήσετε ολόκληρο το γράφημα ροής ελέγχου. Σε περιπτώσεις flattening της ροής ελέγχου, opaque predicates, μεγάλων dispatchers ή κώδικα με πολλά MBA, ακολουθήστε τις αναφορές από τα κρυπτογραφημένα blobs και τα output buffers έως τη μικρότερη ρουτίνα που τα μετασχηματίζει. Στη συνέχεια, αναπαραγάγετε μόνο αυτό το τμήμα ροής δεδομένων ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, αν η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι η εξής:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα εκτελέσιμα τμήματα και τα τμήματα δεδομένων, τις relocations και τις διασταυρούμενες αναφορές. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των byte και το πλάτος των στοιχείων τους.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει το plaintext ή το output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις εισαγόμενες κλήσεις και την απαιτούμενη global state.
3. Μεταφέρετε μόνο αυτές τις λειτουργίες σε ένα μοντέλο Python σταθερού πλάτους. Αν το τμήμα εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα με Unicorn, QEMU ή debugger και κάντε hook τις άσχετες εισαγωγές, αντί να προσομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι την έξοδό του από το παρεχόμενο binary: αφαιρέστε τις σιωπηρές εναλλακτικές, αναζητήστε ενσωματωμένες απαντήσεις και εκτελέστε τον σε builds που δεν έχει δει, με αλλαγμένες συμβολοσειρές, κλειδιά, αναγνωριστικά, layouts και seeds obfuscation.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι οι εξής:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός εκφράσεων MBA που είναι συγκαλυμμένες σταθερές

Μια έκφραση byte που φαινομενικά εξαρτάται από την είσοδο μπορεί να ακυρώνει εντελώς την είσοδό της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το πεδίο 8-bit· ένα σύνολο εξόδων με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε την περιβάλλουσα μηχανή καταστάσεων.<sup>[[7]](#references)</sup>

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

Διατηρήστε την τελική μάσκα, επειδή η αρχική πρόσθεση κάνει αναδίπλωση τιμών στο εύρος του byte. Για ευρύτερο πεδίο τιμών, ρωτήστε έναν SMT solver αν είναι ικανοποιήσιμη η συνθήκη `f(x1) != f(x2)` για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει αμεταβλητότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνώριση αποκωδικοποίησης εξαρτώμενης από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας αποκωδικοποιητής μπορεί να αναμείξει το αποτέλεσμα ενός αισθητήρα σε ένα bit κλειδιού, σε μια σταθερά opaque-predicate ή στην κατάσταση ενός flattened-dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά λανθασμένο plaintext σε έναν emulator. Επομένως, δεν αρκεί η επιδιόρθωση μόνο των ορατών κλάδων αποτυχίας· παρακολουθήστε τις εξαρτήσεις δεδομένων από τους ελέγχους περιβάλλοντος έως την κατάσταση του αποκωδικοποιητή, συγκρίνετε την ίδια διαδρομή σε αυθεντική συσκευή και emulator και ελέγξτε πώς η επιβολή κάθε αποτελέσματος αισθητήρα αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένα πρακτικό εργαλείο απλοποίησης MBA για ανάλυση malware και reverse engineering προστατευμένων binary. Ταξινομεί την έκφραση και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει ένα γενικό πέρασμα επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean εισόδους, εξάγει μια υπογραφή και δοκιμάζει παράλληλα διάφορες μεθόδους ανάκτησης, όπως αντιστοίχιση προτύπων, μετατροπή σε ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα atoms που έχουν καλυφθεί με σταθερές ανασυντίθενται με ανακατασκευή βάσει διαμερισμού bit, ώστε οι καλυμμένες περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αναλύονται σε cores και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε προσωρινές μεταβλητές πριν απλοποιηθεί η εξωτερική σχέση.

Παράδειγμα μικτής ταυτότητας που συνήθως αξίζει να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να απλοποιηθεί σε:

```c
x * y
```

### Σημειώσεις reverse engineering

- Προτιμήστε να εκτελείτε το CoBRA σε **εκφράσεις lifted IR** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή στενούς καταχωρητές.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, δείτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), το οποίο είναι χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από μεταγενέστερα analysis passes.
- Τα μη υποστηριζόμενα υπολείμματα μικτών domains που εξαρτώνται από carry πρέπει να θεωρούνται ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα τη διαδρομή του carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί χειρισμό σημάτων/εξαιρέσεων για να τροποποιήσει τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές εξαρτήσεις.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε **CTF, αυτή η λύση για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου**, αναζητήστε στις συναρτήσεις το `::main`, όπως στο:

![Εύρεση σημείου εισόδου Rust στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για διπλή άνω και κάτω τελεία και main](<../../images/image (1080).png>)

Σε αυτήν την περίπτωση, το binary ονομαζόταν authenticator, οπότε είναι προφανές ποια είναι η ενδιαφέρουσα συνάρτηση main.\
Αν γνωρίζετε το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση συμβολοσειρών Rust από firmware ELF

Σε binary **Rust ELF**, πολλές στατικές συμβολοσειρές δεν αναφέρονται μέσω δεικτών με τερματισμό NUL, όπως στη C. Μια συνηθισμένη διάταξη του `rustc` είναι μια **πλειάδα δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, η οποία δείχνει στο πραγματικό blob συμβολοσειράς που βρίσκεται στο **`.rodata`**:

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
2. Απαριθμήστε το **`.data.rel.ro`** λέξη προς λέξη.
3. Θεωρήστε κάθε τιμή εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Θεωρήστε την επόμενη λέξη ως το υποψήφιο μήκος.
5. Εφαρμόστε ελέγχους εγκυρότητας (για παράδειγμα, κρατήστε μήκη μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata` αντί να αναζητάτε μέχρι το `0x00`.

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

Αν το Ghidra δεν εντοπίζει αυτές τις συμβολοσειρές, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στα αναφερόμενα offsets του `.rodata`. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` της Pen Test Partners είναι καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **word sizes, endianness και section layouts**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries μεταγλωττισμένα με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειαστεί να κάνετε reverse ένα Delphi binary, θα πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα ονόματα των functions κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη function που καλείται από αυτό το κουμπί.

## Golang

Για συνηθισμένα Go binaries, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει runtime structures και να βελτιώσει τα ονόματα των functions στο IDA. Φορτώστε το Python plugin με **Alt+F7**.

Αν χρειαστεί να κάνετε reverse ένα Golang binary, θα πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των functions.

### Ανάκτηση metadata χωρίς τον πίνακα συμβόλων

Ένα stripped Go executable εξακολουθεί να χρειάζεται runtime metadata για να αντιστοιχίζει program counters σε functions. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει structures όπως τα `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Έτσι μπορεί να ανακτήσει όρια functions, ονόματα, source paths, types και build details χωρίς να βασίζεται στον συμβατικό πίνακα συμβόλων.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές λειτουργικές, αντικαθιστώντας παράλληλα τα ανακτημένα ονόματα. Για παράδειγμα, το Garble κατακερματίζει τα αναγνωριστικά και τις διαδρομές πακέτων και αφαιρεί πληροφορίες για το build, το module και το debugging.<sup>[[12]](#references)</sup> Το obfuscated αναγνωριστικό πακέτου πρέπει να παραμένει συνεπές σε όλες τις συναρτήσεις αυτού του πακέτου. Ομαδοποιήστε τις συναρτήσεις με βάση το επαναλαμβανόμενο αναγνωριστικό, συμπεράνετε ένα πακέτο από τις συναρτήσεις που καλούν, τις συμβολοσειρές και τα API του και, στη συνέχεια, αντιστοιχίστε αυτή την ετικέτα πακέτου σε ολόκληρη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή συμβόλων runtime με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση γράφων ροής ελέγχου (CFG). Ακολουθήστε την εξής σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Προσδιορίστε την έκδοση του compiler.** Δοκιμάστε πρώτα το `BuildInfo` και τις ενσωματωμένες συμβολοσειρές έκδοσης. Αν ο obfuscator τις αφαίρεσε, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtimes αναφοράς συγκεκριμένων εκδόσεων. Στις δοκιμές της Volexity, περίπου `2%` του runtime αρκούσε για να διακριθούν οι κύριες εκδόσεις του Go. Αντιμετωπίστε το ως εμπειρική βελτιστοποίηση, όχι ως καθολικό όριο.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε αντίστοιχες αναφορές.** Δημιουργήστε καθαρά binaries για την προσδιορισμένη έκδοση του Go, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση του toolchain περιορίζει τις διαφορές CFG που εισάγει ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και παράγει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση βασικών blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής βεβαιότητας συνδέουν τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Οι ασθενέστερες αντιστοιχίσεις μπορούν και πάλι να προσδιορίσουν ένα πακέτο ή module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επαληθεύστε και εισαγάγετε.** Επιβεβαιώστε τα προτεινόμενα ονόματα με βάση τις σχέσεις κλήσεων, τις σταθερές, τις συμβολοσειρές και τις παρενέργειες και, στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin GoResolver για IDA ή Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Εγκαταστήστε το toolchain και εκτελέστε τον συνδυασμένο extractor και matcher γράφων:<sup>[[10]](#references)</sup>

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

Το προεπιλεγμένο όριο σημαντικής αντιστοίχισης είναι `0.9`. Οι επιλογές `--extract` και `--graph` μπορούν να απομονώσουν οποιοδήποτε από τα δύο στάδια, ενώ η προεπιλεγμένη λειτουργία εκτελεί και τα δύο, επειδή τα ανακτημένα metadata του runtime και τα στοιχεία CFG αλληλοσυμπληρώνονται.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, οι build flags, η αρχιτεκτονική και οι διαφορές στις εκδόσεις βιβλιοθηκών μπορούν να αλλάξουν τη μορφή του γράφου, επομένως διατηρήστε τις συναρτήσεις που δεν έχουν επιλυθεί αντί να τους αποδώσετε ονόματα με χαμηλή βεβαιότητα.<sup>[[13]](#references)</sup>

### Ανάκτηση του πίνακα συμβολοσειρών Go

Τα binaries Go τοποθετούν τα bytes συμβολοσειρών από κάθε συνδεδεμένο πακέτο σε έναν ενιαίο συνεχόμενο πίνακα. Οι εγγραφές δεν τερματίζονται με NUL και οι δομές του runtime δεν εκθέτουν τη βάση ή το μέγεθος του πίνακα. Ωστόσο, ο compiler ταξινομεί τις εγγραφές πρώτα κατά μήκος και έπειτα αλφαβητικά, σε όλα τα λειτουργικά συστήματα και τις αρχιτεκτονικές. Επομένως, αφού εντοπίσει μία εγγραφή, ένας αναλυτής μπορεί να διατρέξει τις γειτονικές εγγραφές και να χρησιμοποιήσει cross-references δεδομένων για να συσχετίσει συμβολοσειρές με κώδικα.<sup>[[15]](#references)</sup>

Το [GoStringExtractor](https://github.com/volexity/GoStringExtractor) αυτοματοποιεί αυτή τη διαδικασία στα IDA Pro και Ghidra. Αφήστε πρώτα να ολοκληρωθεί η αυτόματη ανάλυση, καθώς το plugin βασίζεται σε cross-references του segment δεδομένων. Το προεπιλεγμένο anchor είναι η συμβολοσειρά runtime `entersyscall`. Έπειτα, μπορεί να σαρώσει προς οποιαδήποτε κατεύθυνση, να ορίσει τις ανακτημένες συμβολοσειρές στη βάση δεδομένων και να εξαγάγει μια αντιστοίχιση JSON από συμβολοσειρές σε συναρτήσεις που τις αναφέρουν.<sup>[[14]](#references)</sup>

Φιλτράρετε την αναφορά με βάση το πακέτο της συνάρτησης που αναφέρει τη συμβολοσειρά, ώστε να διαχωρίσετε τον κώδικα της εφαρμογής ή του malware από τον θόρυβο των συνδεδεμένων βιβλιοθηκών. Αυτή η τεχνική δεν μπορεί να ανακτήσει literals που καταστράφηκαν από obfuscation, όπως με τον μετασχηματισμό `-literals` του Garble. Μπορεί, ωστόσο, να οργανώσει συμβολοσειρές runtime που παραμένουν χωρίς obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Ανάκτηση των τύπων runtime του Go

Το Go ενσωματώνει πληροφορίες τύπων runtime που χρησιμοποιούνται από λειτουργίες όπως η συλλογή απορριμμάτων. Όταν έχουν αφαιρεθεί οι πληροφορίες build ή ο disassembler δεν αναλύει αυτά τα metadata, οι εντολές μπορεί να φαίνεται ότι φορτώνουν αυθαίρετες διευθύνσεις δεδομένων και η περιοχή-στόχος παραμένει χωρίς τύπο. Η ανάκτηση των metadata μετατρέπει αυτές τις διευθύνσεις σε ευανάγνωστες αναφορές τύπων και διευκολύνει την κατανόηση των δυνατοτήτων των πακέτων.<sup>[[15]](#references)</sup>

Το [GoResolver](https://github.com/volexity/GoResolver) μπορεί να εξαγάγει σύμβολα και να αναλύσει τους τύπους runtime σε μια αναφορά JSON. Το τρέχον CLI χρησιμοποιεί την υποεντολή `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Η επιλογή `-y`/`--types` ενεργοποιεί την ανάλυση τύπων. Εισαγάγετε την αναφορά με το plugin του GoResolver για IDA Pro ή Ghidra, για να ορίσετε τους τύπους που ανακτήθηκαν και να εφαρμόσετε τις αναφορές τους στη βάση δεδομένων ανάλυσης. Στη μορφή αναφοράς που εισήχθη με αυτήν τη λειτουργία, αν παραλείψετε το `-y`, τα πεδία RTTI address και recovered-types παραμένουν null.<sup>[[10]](#references)[[15]](#references)</sup>

Το GoResolver υποστηρίζει δείγματα PE, ELF και Mach-O για x86, AMD64, ARM και ARM64, επομένως η ίδια ροή εργασίας εφαρμόζεται σε Go binaries από Windows, Linux και macOS.<sup>[[10]](#references)</sup>

## Μεταγλωττισμένη Python

Σε αυτήν τη σελίδα θα βρείτε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο binary Python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **προσομοιώσετε** και να το **αποσφαλματώσετε**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με διεπαφή
- [**mgba** ](https://mgba.io)- Περιλαμβάνει debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin του Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin του Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance

![Διαμόρφωση χειριστηρίων του no$gba με αντιστοιχίσεις κουμπιών του Game Boy Advance](<../../images/image (581).png>)

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

Σε αυτού του είδους τα προγράμματα, το ενδιαφέρον είναι **πώς χειρίζεται το πρόγραμμα την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνηθισμένη συνάρτηση: **KEYINPUT**.

![Προβολή του Ghidra ενός δυαδικού αρχείου GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από κάποιες αρχικές λειτουργίες (χωρίς ιδιαίτερη σημασία):

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

Βρίσκεται ο εξής κώδικας:

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

Η τελευταία συνθήκη if ελέγχει αν το **`uVar4`** βρίσκεται στο τελευταίο Keys και δεν είναι το τρέχον πλήκτρο — δηλαδή, αν έχει αφεθεί ένα κουμπί (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

Στον προηγούμενο κώδικα μπορείτε να δείτε ότι συγκρίνουμε το **uVar1** (τη θέση όπου βρίσκεται η **τιμή του πατημένου κουμπιού**) με κάποιες τιμές:

- Πρώτα, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): Στην πρόκληση, αυτό το κουμπί καθαρίζει την οθόνη
- Έπειτα, συγκρίνεται με την τιμή **8** (κουμπί **START**). Στην πρόκληση, αυτή η διαδρομή ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
  - Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων συσσωρεύονται στο `DAT_030000d8`.

Επομένως, σε αυτή την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, του οποίου το άθροισμα να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένη λύση της πρόκλησης Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Αποσυσκότιση δυαδικών αρχείων)

## References

- [1] [Απλοποίηση της MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - συμβολοσειρές Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reverse engineering για GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετώπιση του reverse engineering με τη βοήθεια AI — ή τουλάχιστον προσπάθεια](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση για τη σύγκριση γραφημάτων ροής ελέγχου με βάση την αντιστοίχιση βασικών μπλοκ](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Αποθετήριο Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας γραφημάτων ροής ελέγχου για αυτόματη αποσυσκότιση δυαδικών αρχείων Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Αποθετήριο Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ενημερώσεις στα εργαλεία Golang της Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Αντίστροφη μηχανική σε οτιδήποτε](https://github.com/morluto/rea)
- [17] [Ανάλυση managed code του REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Οδηγός CLI και Evidence του REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
