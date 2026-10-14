# Εργαλεία reversing και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Αυτοματοποίηση user-mode του WinDbg

{{#ref}}
windbg-automation.md
{{#endref}}

## Debugging πυρήνα των Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Απομεταγλωττιστής Wasm / μεταγλωττιστής Wat

Διαδικτυακά:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **απομεταγλώττιση** από wasm (δυαδική μορφή) σε wat (καθαρό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **μεταγλώττιση** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για απομεταγλώττιση.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode από cache των Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Εικονικοποιημένα payloads και προσαρμοσμένες VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Απομεταγλωττιστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας απομεταγλωττιστής που **απομεταγλωττίζει και εξετάζει πολλαπλές μορφές**, όπως **βιβλιοθήκες** (.dll), **αρχεία μεταδεδομένων των Windows** (.winmd) και **εκτελέσιμα αρχεία** (.exe). Μετά την απομεταγλώττιση, μια assembly μπορεί να αποθηκευτεί ως project του Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να ανακτηθεί χαμένος πηγαίος κώδικας από μια παλαιότερη assembly, αυτή η διαδικασία μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση στον απομεταγλωττισμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει τις ακριβείς ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολλές δυνατότητες reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα της ροής των δεδομένων μέσα από μια βιβλιοθήκη ή ένα component
- Παρέχει εικόνα της υλοποίησης και της χρήσης των γλωσσών και των frameworks .NET
- Εντοπίζει μη τεκμηριωμένη και μη εκτεθειμένη λειτουργικότητα, ώστε να αξιοποιήσετε περισσότερο τα API και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικές assemblies
- Εντοπίζει την ακριβή θέση των σφαλμάτων στον κώδικά σας, σε components τρίτων και σε βιβλιοθήκες.
- Κάνει debugging στον πηγαίο κώδικα όλου του κώδικα .NET με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Πρόσθετο ILSpy για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να **απομεταγλωττίσετε**, να **τροποποιήσετε** και να **μεταγλωττίσετε ξανά**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα fork του που συντηρείται ενεργά, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί κλικ -> Modify Method** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Επιθεώρηση managed κώδικα με το REA χωρίς εκτέλεση

Το **REA** μπορεί να επιθεωρεί μεταδεδομένα PE/CLI και CIL χωρίς να φορτώνει την assembly. Ξεκινήστε με την ταυτότητα του artifact και, στη συνέχεια, εξετάστε τα μέλη και τα δηλωμένα native όρια· αυτό είναι χρήσιμο κατά την αξιολόγηση ύποπτων κλήσεων, πριν χρησιμοποιήσετε έναν απομεταγλωττιστή ή εκτελέσετε το πρόγραμμα.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Για τη σύγκριση εκδόσεων, το `compare_managed_members` χρησιμοποιεί την ταυτότητα των ακατέργαστων CIL/signature και fingerprints αποκωδικοποιημένων εντολών, αντί να θεωρεί τα metadata tokens σταθερά μεταξύ builds. Μια δήλωση P/Invoke δεν αποδεικνύει ότι εκτελέστηκε native code· το `verify_managed_native_boundaries` χρειάζεται αντίστοιχο native export ή function Evidence για να ελέγξει αυτό το όριο. Διατηρήστε το artifact digest, το MVID και τις ανεπίλυτες αντιστοιχίσεις μαζί με το αποτέλεσμα.<sup>[[17]](#references)</sup>

### Καταγραφή στο DNSpy

Για να κάνετε το **DNSpy να καταγράφει ορισμένες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Αποσφαλμάτωση DNSpy

Για να κάνετε αποσφαλμάτωση κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **χαρακτηριστικά Assembly** που σχετίζονται με την **αποσφαλμάτωση**:

![Καταγραφή DNSpy - Αποσφαλμάτωση DNSpy: Αρχικά, αλλάξτε τα χαρακτηριστικά Assembly που σχετίζονται με την αποσφαλμάτωση](<../../images/image (973).png>)

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

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω του _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, γιατί αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και υπάρχει πιθανότητα, κατά το debugging, να μη γίνει ποτέ hit σε κάποιο **break-point** ή να μην υπάρχουν κάποιες **variables**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την **Debug Tab** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την Debug Tab επιλέξτε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο _Debug >> Break All_ και έπειτα στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και έπειτα στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και έπειτα στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Απομεταγλωττιστής Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Χρήση του IDA

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε debugger **Windbg**
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Χρήση του IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Διαμορφώστε τις **παραμέτρους** εκτέλεσης, ορίζοντας τη **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Χρήση του IDA: Διαμορφώστε τις παραμέτρους εκτέλεσης, ορίζοντας τη διαδρομή προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα σταματά κάθε φορά που φορτώνεται ένα DLL**. Όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα σταματήσει.

Αυτή η μέθοδος σταματά την εκτέλεση σε συμβάντα φόρτωσης module, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση από ό,τι στη ροή εργασίας με το x64dbg παρακάτω.

### Χρήση των x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε τη διαδρομή του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Έπειτα, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και, κάποια στιγμή, θα **σταματήσει στο DLL Entry του dll σας**. Από εκεί, απλώς αναζητήστε τα σημεία όπου θέλετε να ορίσετε ένα breakpoint.

Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας στο **επάνω μέρος του παραθύρου του win64dbg**:

![Χρήση του IDA - Χρήση των x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση σταματήσει για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει σταματήσει μέσα στο DLL που θέλετε να κάνετε debug.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες:

{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετική με reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η διαδικτυακή υπηρεσία σάς επιτρέπει να συγκρίνετε την έξοδο διαφορετικών decompilers σε μικρά εκτελέσιμα αρχεία.

## Διερεύνηση native κώδικα με τεκμηριωμένα στοιχεία μέσω του REA

Το **REA** παρέχει πρόσβαση στις αναλύσεις των Hopper, Ghidra και IDA μέσω CLI και MCP. Απαιτεί Node.js 22.x (τουλάχιστον 22.19), 24.x (τουλάχιστον 24.11) ή 26+, καθώς και npm. Διαμορφώστε πρώτα έναν υπάρχοντα native provider. Ελέγξτε το `rea providers --json` και επιλέξτε ρητά έναν provider όταν περισσότεροι από ένας υποστηρίζουν τον στόχο. Αντικαταστήστε το `0x1000` παρακάτω με ένα παρατηρημένο όνομα συνάρτησης ή μια διεύθυνση από το inventory.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Ξεκινήστε από ένα feature string ή symbol, ακολουθήστε τις references και τους callers και, στη συνέχεια, επιθεωρήστε τον φάκελο και το pseudocode της επιλεγμένης συνάρτησης με το `rea decompile`. Το REA συνδέει μια session με τον επιλεγμένο provider αντί να τον αντικαθιστά σιωπηρά έπειτα από αποτυχία. Για επαναλήψιμα queries, το `--snapshot PATH` επαναχρησιμοποιεί μόνο bytes artifacts, provider, settings, operation και parameters που ταιριάζουν· ένα snapshot είναι τοπική cache, όχι αποθηκευμένη βάση δεδομένων provider. Διατηρήστε το Evidence που επιστρέφεται και τα ρητά unknowns, αντί να αντιμετωπίζετε τα inferred paths ή το κείμενο του decompiler ως πρωτότυπο source.<sup>[[16]](#references)[[18]](#references)</sup>

Για entry points JavaScript/Electron που οδηγούν σε native add-ons, δείτε το [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging ενός shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει το **shellcode**, εκτυπώνει τη **memory address** του και κάνει παύση στην εκτέλεση.\
Συνδεθείτε με έναν debugger, όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εκτυπώθηκε και συνεχίστε την εκτέλεση για να κάνετε debugging του shellcode.

Η σελίδα releases του github περιέχει zip με τα compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να την κάνετε compile, απλώς **δημιουργήστε ένα C/C++ project στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging ενός shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει το shellcode και εισέρχεται σε έναν ατέρμονο βρόχο. Συνδεθείτε με τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, κάντε παύση μέσα σε αυτόν τον βρόχο και προχωρήστε μέχρι την επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει κάνει παύση στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια compiled έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να επιλέξετε «Open File» και «Open Shellcode». Στην περίπτωσή μου, όταν άνοιξα το shellcode ως αρχείο, το έκανε decompile σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγει τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσει το emulation στο σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα το emulation από εκεί:

![Ορισμός breakpoint στο επιθυμητό entry point του shellcode πριν από την έναρξη του emulation στο Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter έχει κάνει παύση στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του emulated shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Απο-obfuscation shellcode και εντοπισμός των συναρτήσεων που εκτελούνται

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει, για παράδειγμα, **ποιες συναρτήσεις** χρησιμοποιεί το shellcode και αν το shellcode κάνει **decoding** του εαυτού του στη μνήμη.

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

Η επιλογή **Create Dump** θα δημιουργήσει dump του τελικού shellcode, αν αυτό έχει αλλάξει δυναμικά στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Η επιλογή **start offset** μπορεί να είναι χρήσιμη για την εκκίνηση του shellcode από συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων του shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι κάποια από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με το CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε το ακόλουθο recipe για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Η obfuscation **Mixed Boolean-Arithmetic (MBA)** αποκρύπτει απλές εκφράσεις, όπως η `x + y`, πίσω από τύπους που συνδυάζουν αριθμητικές πράξεις (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες είναι συνήθως σωστές μόνο υπό **αριθμητική modulo σταθερού πλάτους**, επομένως τα κρατούμενα και οι υπερχειλίσεις έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτό το είδος έκφρασης με γενικά εργαλεία άλγεβρας, μπορεί εύκολα να καταλήξετε σε λάθος αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του bit-width.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό bit-width** από το lifted code/IR/αποτέλεσμα του decompiler (`8/16/32/64` bits).
2. **Ταξινομήστε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα από bitwise atoms
   - **Ημιγραμμική**: γραμμική έκφραση με σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: υπάρχουν γινόμενα
   - **Μεικτή**: γινόμενα και bitwise λογική συνδυάζονται, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε πιθανή αναδιατύπωση** με τυχαίες δοκιμές ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, κρατήστε την αρχική έκφραση αντί να κάνετε εικασίες.

### Παράκαμψη flattened control flow με ένα στενό execution slice

Συχνά δεν χρειάζεται να ανακτήσετε ολόκληρο το control-flow graph. Σε κώδικα με control-flow flattening, opaque predicates, μεγάλους dispatchers ή κώδικα με πολλά MBA, ακολουθήστε τις αναφορές από κρυπτογραφημένα blobs και output buffers έως τη μικρότερη ρουτίνα που τα μετασχηματίζει. Έπειτα αναπαράγετε μόνο αυτό το data-flow slice ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν είναι απαραίτητος, αν μπορεί να αρχικοποιηθεί απευθείας η σχετική κατάσταση.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα εκτελέσιμα και τα data sections, τα relocations και τις cross-references. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των bytes και το πλάτος των στοιχείων τους.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει το plaintext ή το output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις imported calls και την απαιτούμενη global state.
3. Μεταφέρετε μόνο αυτές τις λειτουργίες σε ένα μοντέλο Python σταθερού πλάτους. Αν το slice εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα μέσω Unicorn, QEMU ή debugger και κάντε hook τις άσχετες imports, αντί να εξομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι το output από το παρεχόμενο binary: αφαιρέστε τα σιωπηρά fallbacks, αναζητήστε ενσωματωμένες απαντήσεις και δοκιμάστε τον σε builds που δεν έχετε δει, με αλλαγμένα strings, keys, identifiers, layouts και obfuscation seeds.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός εκφράσεων MBA που είναι μεταμφιεσμένες σταθερές

Μια φαινομενικά εξαρτώμενη από την είσοδο έκφραση byte μπορεί να ακυρώνει πλήρως την είσοδό της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο τον τομέα των 8 bit· ένα σύνολο εξόδων με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε την περιβάλλουσα μηχανή καταστάσεων.<sup>[[7]](#references)</sup>

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

Διατήρησε την τελική μάσκα, επειδή η αρχική πρόσθεση προκαλεί αναδίπλωση στο όριο του byte. Για ευρύτερο πεδίο τιμών, ρώτησε έναν SMT solver αν η έκφραση `f(x1) != f(x2)` είναι ικανοποιήσιμη για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει αμεταβλητότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνώριση αποκωδικοποίησης που εξαρτάται από το περιβάλλον

Οι έλεγχοι anti-analysis δεν είναι απαραίτητο να προκαλούν διακλάδωση ή κατάρρευση. Ένας decoder μπορεί να αναμείξει το αποτέλεσμα ενός sensor σε ένα bit του κλειδιού, σε μια σταθερά opaque-predicate ή στην κατάσταση ενός flattened-dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά λανθασμένο plaintext σε έναν emulator. Επομένως, δεν αρκεί να διορθώσεις μόνο τις ορατές διακλαδώσεις αποτυχίας· παρακολούθησε τις εξαρτήσεις δεδομένων από τους ελέγχους του περιβάλλοντος μέχρι την κατάσταση του decoder, σύγκρινε το ίδιο τμήμα στον αυθεντικό device και στον emulator και έλεγξε πώς η επιβολή κάθε αποτελέσματος sensor αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός απλοποιητής MBA για ανάλυση malware και reversing προστατευμένων binary. Ταξινομεί την έκφραση και τη δρομολογεί σε εξειδικευμένα pipelines, αντί να εφαρμόζει ένα γενικό πέρασμα επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean εισόδους, εξάγει μια υπογραφή και εκτελεί παράλληλα διάφορες μεθόδους ανάκτησης, όπως pattern matching, ANF conversion και coefficient interpolation.
- **Semilinear MBA**: Τα atoms με constant masking ανακατασκευάζονται με bit-partitioned reconstruction, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αποσυντίθενται σε cores και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε προσωρινές μεταβλητές πριν απλοποιηθεί η εξωτερική σχέση.

Παράδειγμα μιας mixed ταυτότητας που συχνά αξίζει να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να συμπτυχθεί σε:

```c
x * y
```

### Σημειώσεις reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, δείτε εδώ τις τοπικές σημειώσεις για το Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), χρήσιμο όταν θέλετε να κανονικοποιήσετε MBA-heavy LLVM IR πριν από μεταγενέστερα analysis passes.
- Τα unsupported carry-sensitive mixed-domain residuals θα πρέπει να θεωρούνται ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα τη διαδρομή του carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτό το obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί signal/exception handling για να τροποποιήσει το control flow. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές εξαρτήσεις.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν συμμετέχετε σε **CTF, αυτή η παράκαμψη για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου**, αναζητήστε τις συναρτήσεις με βάση το `::main`, όπως εδώ:

![Εύρεση σημείου εισόδου Rust στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για διπλή άνω και κάτω τελεία main](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το binary ονομαζόταν authenticator, οπότε είναι προφανές ποια είναι η ενδιαφέρουσα συνάρτηση main.\
Αφού έχετε τα **ονόματα** των **συναρτήσεων** που καλούνται, αναζητήστε τα στο **Internet** για να μάθετε ποιες είναι οι **είσοδοι** και οι **έξοδοί** τους.

### Ανάκτηση συμβολοσειρών Rust από firmware ELF

Σε **Rust ELF** binaries, πολλές στατικές συμβολοσειρές δεν αναφέρονται μέσω δεικτών με τερματισμό NUL, όπως στη C. Μια συνηθισμένη διάταξη του `rustc` είναι μια **πλειάδα δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, η οποία δείχνει στο πραγματικό blob συμβολοσειράς που είναι αποθηκευμένο στο **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικές συμβολοσειρές ή να μην εντοπίσει καθόλου cross-references.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Λάβετε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία λέξη τη φορά.
3. Θεωρήστε κάθε τιμή εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Θεωρήστε την επόμενη λέξη ως υποψήφιο μήκος.
5. Εφαρμόστε ελέγχους εγκυρότητας (για παράδειγμα, διατηρήστε μήκη μεταξύ **4** και **100** byte).
6. Διαβάστε ακριβώς `length` byte από το `.rodata` αντί να κάνετε σάρωση μέχρι το `0x00`.

Ελάχιστη λογική εξαγωγής:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες συμβολοσειρές Rust συχνά αποκαλύπτουν **HTTP routes, ονόματα RPC, μηνύματα log, assertions, ονόματα αρχείων, κλειδιά config, command handlers και λογική σχετική με το auth**.

Αν το Ghidra δεν εντοπίσει αυτές τις συμβολοσειρές, εκτελέστε ένα προσαρμοσμένο script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στα σχετικά offsets του `.rodata`. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` από την Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλες **μεγέθη λέξεων, endianness και διατάξεις sections**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν μεταγλωττιστεί με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν πρέπει να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin εκτελεί το binary και επιλύει δυναμικά τα ονόματα των συναρτήσεων κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και ένα breakpoint θα ενεργοποιηθεί στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη συνάρτηση που καλείται από αυτό το κουμπί.

## Golang

Για συνηθισμένα Go binaries, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει runtime structures και να βελτιώσει τα ονόματα συναρτήσεων στο IDA. Φορτώστε το Python plugin με **Alt+F7**.

Αν πρέπει να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

### Ανάκτηση metadata χωρίς τον symbol table

Ένα stripped Go executable εξακολουθεί να χρειάζεται runtime metadata για να αντιστοιχίσει τους μετρητές προγράμματος σε συναρτήσεις. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει structures όπως τα `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Έτσι μπορούν να ανακτηθούν όρια συναρτήσεων, ονόματα, διαδρομές πηγαίου κώδικα, τύποι και στοιχεία του build, χωρίς να βασιστούμε στον συμβατικό symbol table.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές αξιοποιήσιμες, αντικαθιστώντας παράλληλα τα ονόματα που ανακτήθηκαν. Το Garble, για παράδειγμα, κατακερματίζει τα identifiers και τα package paths και αφαιρεί πληροφορίες build, module και debug.<sup>[[12]](#references)</sup> Το obfuscated token του package πρέπει να παραμένει σταθερό σε όλες τις συναρτήσεις αυτού του package. Ομαδοποιήστε τις συναρτήσεις με βάση το επαναλαμβανόμενο token, συμπεράνετε ένα package από τις συναρτήσεις που καλεί, τα strings και τα APIs του και, στη συνέχεια, μεταδώστε την ετικέτα του package σε ολόκληρη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή runtime symbols με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση control-flow graphs (CFG). Ακολουθήστε αυτή τη σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Προσδιορίστε την έκδοση του compiler.** Δοκιμάστε πρώτα το `BuildInfo` και ενσωματωμένα strings έκδοσης. Αν ο obfuscator τα έχει αφαιρέσει, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtimes αναφοράς για γνωστές εκδόσεις. Στις δοκιμές της Volexity, περίπου το `2%` του runtime αρκούσε για να διακριθούν οι κύριες εκδόσεις του Go. Θεωρήστε το αυτό εμπειρική βελτιστοποίηση, όχι καθολικό όριο.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε αντίστοιχες αναφορές.** Δημιουργήστε καθαρά binaries για την αναγνωρισμένη έκδοση του Go, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση του toolchain μειώνει τις διαφορές CFG που εισάγει ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και παράγει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση basic blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής βεβαιότητας αντιστοιχίζουν τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Οι ασθενέστερες αντιστοιχίσεις μπορούν και πάλι να προσδιορίσουν ένα package ή module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επαληθεύστε και εισαγάγετε τα αποτελέσματα.** Επιβεβαιώστε τα προτεινόμενα ονόματα με βάση τις σχέσεις κλήσεων, τις σταθερές, τα strings και τις παρενέργειες και, στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin GoResolver για IDA ή Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Εγκαταστήστε το toolchain και εκτελέστε τον συνδυασμένο extractor και graph matcher:<sup>[[10]](#references)</sup>

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

Το προεπιλεγμένο όριο για σημαντική αντιστοίχιση είναι `0.9`. Οι επιλογές `--extract` και `--graph` μπορούν να απομονώσουν οποιοδήποτε από τα δύο στάδια, ενώ από προεπιλογή εκτελούνται και τα δύο, επειδή τα ανακτημένα metadata του runtime και τα στοιχεία του CFG αλληλοσυμπληρώνονται.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, τα build flags, η αρχιτεκτονική και οι διαφορές στις εκδόσεις βιβλιοθηκών μπορούν να αλλάξουν τη μορφή του γράφου, γι’ αυτό διατηρήστε τις μη επιλυμένες συναρτήσεις αντί να επιβάλλετε ονόματα με χαμηλή βεβαιότητα.<sup>[[13]](#references)</sup>

### Ανάκτηση του πίνακα συμβολοσειρών της Go

Τα binaries της Go τοποθετούν τα bytes συμβολοσειρών από κάθε συνδεδεμένο πακέτο σε έναν ενιαίο, συνεχόμενο πίνακα. Οι εγγραφές δεν τερματίζονται με NUL και οι δομές του runtime δεν αποκαλύπτουν τη βάση ή το μέγεθος του πίνακα. Ωστόσο, ο compiler ταξινομεί τις εγγραφές πρώτα κατά μήκος και έπειτα αλφαβητικά, σε όλα τα λειτουργικά συστήματα και τις αρχιτεκτονικές. Επομένως, αφού εντοπίσει μια εγγραφή, ένας αναλυτής μπορεί να διατρέξει τις γειτονικές εγγραφές και να χρησιμοποιήσει αναφορές διασταύρωσης δεδομένων για να συσχετίσει συμβολοσειρές με κώδικα.<sup>[[15]](#references)</sup>

Το [GoStringExtractor](https://github.com/volexity/GoStringExtractor) αυτοματοποιεί αυτή τη διαδικασία στα IDA Pro και Ghidra. Αφήστε πρώτα να ολοκληρωθεί η αυτόματη ανάλυση, επειδή το plugin βασίζεται σε αναφορές διασταύρωσης του τμήματος δεδομένων. Το προεπιλεγμένο σημείο αναφοράς είναι η συμβολοσειρά του runtime `entersyscall`. Έπειτα, μπορεί να σαρώσει προς οποιαδήποτε κατεύθυνση, να ορίσει τις ανακτημένες συμβολοσειρές στη βάση δεδομένων και να εξαγάγει μια αντιστοίχιση JSON από συμβολοσειρές σε συναρτήσεις που τις αναφέρουν.<sup>[[14]](#references)</sup>

Φιλτράρετε την αναφορά με βάση το πακέτο της συνάρτησης που κάνει την αναφορά, ώστε να διαχωρίσετε τον κώδικα της εφαρμογής ή του malware από τον θόρυβο των συνδεδεμένων βιβλιοθηκών. Αυτή η τεχνική δεν μπορεί να ανακτήσει literals που έχουν καταστραφεί από obfuscation, όπως με τον μετασχηματισμό `-literals` του Garble. Μπορεί, ωστόσο, να οργανώσει τις συμβολοσειρές του runtime που παραμένουν χωρίς obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Ανάκτηση τύπων του runtime της Go

Η Go ενσωματώνει πληροφορίες τύπων του runtime, τις οποίες χρησιμοποιούν λειτουργίες όπως το garbage collection. Όταν αφαιρούνται οι πληροφορίες build ή ο disassembler δεν αναλύει αυτά τα metadata, οι εντολές μπορεί να φαίνεται ότι φορτώνουν αυθαίρετες διευθύνσεις δεδομένων και η περιοχή-στόχος παραμένει χωρίς τύπο. Η ανάκτηση των metadata μετατρέπει αυτές τις διευθύνσεις σε ευανάγνωστες αναφορές τύπων και διευκολύνει την κατανόηση των δυνατοτήτων του πακέτου.<sup>[[15]](#references)</sup>

Το [GoResolver](https://github.com/volexity/GoResolver) μπορεί να εξαγάγει symbols και να αναλύσει τους τύπους του runtime σε αναφορά JSON. Το τρέχον CLI χρησιμοποιεί την υποεντολή `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Η επιλογή `-y`/`--types` ενεργοποιεί την ανάλυση τύπων. Εισαγάγετε την αναφορά με το plugin του GoResolver για IDA Pro ή Ghidra, για να ορίσετε τους τύπους που ανακτήθηκαν και να εφαρμόσετε τις αναφορές τους στη βάση δεδομένων της ανάλυσης. Στη μορφή αναφοράς που παρουσιάστηκε με αυτήν τη δυνατότητα, αν παραλείψετε το `-y`, τα πεδία RTTI address και recovered-types έχουν τιμή null.<sup>[[10]](#references)[[15]](#references)</sup>

Το GoResolver υποστηρίζει δείγματα PE, ELF και Mach-O για x86, AMD64, ARM και ARM64, επομένως η ίδια ροή εργασίας ισχύει για Go binaries από Windows, Linux και macOS.<sup>[[10]](#references)</sup>

## Μεταγλωττισμένη Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο binary Python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διαφορετικά εργαλεία για να το **emulate** και να κάνετε **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με γραφικό περιβάλλον
- [**mgba** ](https://mgba.io)- Περιλαμβάνει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin του Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin του Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στις _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance

![Διαμόρφωση κουμπιών του no$gba με αντιστοιχίσεις κουμπιών Game Boy Advance](<../../images/image (581).png>)

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

Λοιπόν, σε αυτό το είδος προγράμματος, το ενδιαφέρον θα είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνήθως εμφανιζόμενη συνάρτηση: **KEYINPUT**.

![Προβολή στο Ghidra ενός binary για GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από ορισμένες αρχικοποιήσεις (χωρίς ιδιαίτερη σημασία):

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

Εντοπίστηκε αυτός ο κώδικας:

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **τελευταία Keys** και δεν είναι το τρέχον πλήκτρο, δηλαδή αν αφήνεται ένα κουμπί (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): Σε αυτό το challenge, το κουμπί καθαρίζει την οθόνη.
- Έπειτα, η τιμή συγκρίνεται με το **8** (κουμπί **START**). Σε αυτό το challenge, αυτή η διαδρομή ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
  - Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων προστίθενται στο `DAT_030000d8`.

Επομένως, σε αυτό το challenge, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό μήκους μικρότερου από 8, ώστε το άθροισμα να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένο writeup του challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Αποσυσκότιση binary)

## References

- [1] [Απλοποίηση της MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repository του Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reversing για GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετωπίζοντας το AI-assisted Reverse Engineering ή, τουλάχιστον, προσπαθώντας](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση για τη σύγκριση Control Flow Graphs με βάση την αντιστοίχιση Basic Blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repository του Volexity GoResolver](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας Control-Flow Graph για την αυτόματη αποσυσκότιση binaries Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repository του Volexity GoStringExtractor](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ενημερώσεις στα εργαλεία Golang της Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Αντίστροφη μηχανική σε οτιδήποτε](https://github.com/morluto/rea)
- [17] [Ανάλυση managed code στο REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Οδηγός CLI και Evidence του REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
