# Εργαλεία reversing & βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reversing βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Αυτοματοποίηση του WinDbg σε user mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Windows exception-driven control flow

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Debugging του Windows kernel

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Απομεταγλωττιστής Wasm / μεταγλωττιστής Wat

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για να **απομεταγλωττίσετε** από wasm (binary) σε wat (καθαρό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για να **μεταγλωττίσετε** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για απομεταγλώττιση.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Cached bytecode του Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualized payloads και custom VMs

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Απομεταγλωττιστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας απομεταγλωττιστής που **απομεταγλωττίζει και εξετάζει πολλαπλές μορφές**, όπως **libraries** (.dll), **αρχεία μεταδεδομένων Windows** (.winmd) και **εκτελέσιμα** (.exe). Μετά την απομεταγλώττιση, ένα assembly μπορεί να αποθηκευτεί ως Visual Studio project (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να αποκατασταθεί χαμένος source code από ένα legacy assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση στον απομεταγλωττισμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει ακριβώς τις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολλές υπηρεσίες reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα για τη ροή των δεδομένων μέσα από ένα library ή component
- Παρέχει εικόνα για την υλοποίηση και τη χρήση γλωσσών και frameworks .NET
- Εντοπίζει μη τεκμηριωμένη και μη εκτεθειμένη λειτουργικότητα, ώστε να αξιοποιείτε καλύτερα τα API και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή θέση σφαλμάτων στον κώδικά σας, σε components τρίτων και σε libraries.
- Κάνει debugging στον πηγαίο κώδικα όλου του .NET code με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κάνετε download το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να **απομεταγλωττίσετε**, να **τροποποιήσετε** και να **μεταγλωττίσετε ξανά**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα ενεργά συντηρούμενο fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί κλικ -> Modify Method** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Επιθεώρηση managed κώδικα χωρίς εκτέλεση με το REA

Το **REA** μπορεί να επιθεωρήσει μεταδεδομένα PE/CLI και CIL χωρίς να φορτώσει το assembly. Ξεκινήστε με την ταυτότητα του artifact και, στη συνέχεια, εξετάστε τα μέλη και τα δηλωμένα native όρια· αυτό είναι χρήσιμο κατά την αξιολόγηση ύποπτων κλήσεων, πριν χρησιμοποιήσετε απομεταγλωττιστή ή εκτελέσετε το πρόγραμμα.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Για τη σύγκριση διαφορών μεταξύ εκδόσεων, το `compare_managed_members` χρησιμοποιεί ταυτότητα raw CIL/υπογραφής και αποτυπώματα αποκωδικοποιημένων εντολών, αντί να θεωρεί ότι τα metadata tokens παραμένουν σταθερά μεταξύ διαφορετικών builds. Μια δήλωση P/Invoke δεν αποδεικνύει ότι εκτελέστηκε native κώδικας· το `verify_managed_native_boundaries` χρειάζεται αντίστοιχο native export ή Evidence συνάρτησης για να ελέγξει αυτό το όριο. Διατηρήστε το digest του artifact, το MVID και τις ανεπίλυτες αντιστοιχίσεις μαζί με το αποτέλεσμα.<sup>[[17]](#references)</sup>

### Καταγραφή DNSpy

Για να **καταγράψει το DNSpy κάποιες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το απόσπασμα:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Για να κάνετε debug σε κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

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

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω του _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, επειδή αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **optimisations** στον κώδικα και υπάρχει περίπτωση, κατά το debugging, να μην ενεργοποιηθεί ποτέ ένα **break-point** ή να μην υπάρχουν κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα **Debug Tab** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα Debug Tab επιλέξτε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο _Debug >> Break All_ και έπειτα στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και έπειτα στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, πρέπει να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και έπειτα στο Debug Windows Modules](<../../images/image (834).png>)

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
- Επιλέξτε debugger **Windbg**
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Ρυθμίστε τις **παραμέτρους** εκτέλεσης, εισάγοντας τη **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Ρυθμίστε τις παραμέτρους εκτέλεσης, εισάγοντας τη διαδρομή προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Έπειτα, όταν ξεκινήσετε το debugging, **η εκτέλεση θα διακόπτεται κάθε φορά που φορτώνεται ένα DLL**. Επομένως, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση σε συμβάντα φόρτωσης module, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση από ό,τι με τη ροή εργασίας του x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε τη διαδρομή του DLL και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Έπειτα, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματήσει στο main κάθε DLL και, κάποια στιγμή, θα **σταματήσει στο Entry του DLL σας**. Από εκεί, αναζητήστε τα σημεία όπου θέλετε να ορίσετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε**, κοιτάζοντας **στο επάνω μέρος του παραθύρου win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε κοιτάζοντας στο επάνω μέρος του παραθύρου win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει διακοπεί μέσα στο DLL που θέλετε να κάνετε debug.

## GUI Apps / Videogames

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες:

{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/reverse engineering εργαλείο για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετική με το reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορα decompiler. Αυτή η διαδικτυακή υπηρεσία σάς επιτρέπει να συγκρίνετε τα αποτελέσματα διαφορετικών decompiler σε μικρά εκτελέσιμα αρχεία.

## Evidence-backed native investigation with REA

Το **REA** παρέχει πρόσβαση στην ανάλυση των Hopper, Ghidra και IDA μέσω CLI και MCP. Απαιτεί Node.js 22.x (τουλάχιστον 22.19), 24.x (τουλάχιστον 24.11) ή 26+, καθώς και npm. Διαμορφώστε πρώτα έναν υπάρχοντα native provider· ελέγξτε το `rea providers --json` και επιλέξτε ρητά έναν provider όταν περισσότεροι από ένας υποστηρίζουν τον στόχο. Χρησιμοποιήστε στη θέση του `0x1000` παρακάτω ένα όνομα συνάρτησης ή μια διεύθυνση που παρατηρήσατε στο inventory.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Ξεκινήστε από ένα feature string ή σύμβολο και ακολουθήστε τις αναφορές και τους callers. Έπειτα, εξετάστε τον φάκελο της επιλεγμένης συνάρτησης και το pseudocode με το `rea decompile`. Το REA δεσμεύει μια συνεδρία στον επιλεγμένο provider, αντί να τον αντικαθιστά σιωπηρά σε περίπτωση αποτυχίας. Για επαναλήψιμα ερωτήματα, το `--snapshot PATH` επαναχρησιμοποιεί μόνο bytes τεχνουργημάτων, provider, ρυθμίσεις, λειτουργία και παραμέτρους που ταιριάζουν· ένα snapshot είναι τοπική cache, όχι αποθηκευμένη βάση δεδομένων provider. Διατηρήστε το Evidence που επιστρέφεται και τα ρητά άγνωστα στοιχεία αντί να θεωρείτε ότι τα συναγόμενα paths ή το κείμενο του decompiler είναι ο αρχικός πηγαίος κώδικας.<sup>[[16]](#references)[[18]](#references)</sup>

Για entry points JavaScript/Electron που οδηγούν σε native add-ons, δείτε [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Scripted ανάλυση IDA και Ghidra με τοπικό TCP bridge

Το [IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) εκτελείται μέσα σε μια **ήδη ανοιχτή** βάση δεδομένων IDA ή ένα πρόγραμμα Ghidra CodeBrowser και επιτρέπει σε ένα ξεχωριστό script να υποβάλλει ερωτήματα και να τροποποιεί αυτή τη βάση δεδομένων ανάλυσης. Εκτελέστε το `ID_Server.py` από το Python CLI του IDA (`import ID_Server`) ή το `Ghidra_Server.py` από το Script Manager του Ghidra. Το IDA κάνει bind στη διεύθυνση `127.0.0.1`, ξεκινώντας από τη θύρα `5073`, και ελέγχει τις επόμενες θύρες. Το τρέχον script του Ghidra ξεκινά από τη θύρα `5093` και δοκιμάζει δέκα θύρες, έως και τη `5102`· το Java socket του κάνει bind στη διεύθυνση wildcard, όχι μόνο στο loopback. Ελέγξτε τη θύρα που εμφανίζει το instance πριν συνδεθείτε. Σε αντίθεση με έναν headless analyzer, αυτό το bridge λειτουργεί στο πρόγραμμα που είναι ανοιχτό εκείνη τη στιγμή στο συγκεκριμένο GUI instance.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Στείλτε **μία εντολή που τερματίζεται με newline ανά σύνδεση** και διαβάστε την απάντηση που τερματίζεται με newline. Το αποτέλεσμα είναι συνήθως JSON. Για παράδειγμα, αφού εντοπίσετε ένα imported API σχετικό με ένα input path, το `IMPORTXREF` εντοπίζει τα call sites του· στη συνέχεια, το `DECOMP_XREF` κάνει batch decompile τους callers μιας επιλεγμένης διεύθυνσης. Το `FUNC` εξετάζει μια συνάρτηση, ενώ το `PCODE` επιστρέφει την ενδιάμεση αναπαράσταση του decompiler. Χρησιμοποιήστε τη διεύθυνση από την ενεργή βάση δεδομένων, όχι μια διεύθυνση αντιγραμμένη από binary με διαφορετικό rebase. Το παρακάτω παράδειγμα χρησιμοποιεί την προεπιλεγμένη θύρα του IDA· για το Ghidra, χρησιμοποιήστε τη θύρα που εμφανίζει το script του.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Το ίδιο κανάλι μπορεί να **αλλάξει τη βάση δεδομένων ανάλυσης**: οι εντολές `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` και `PATCH` τροποποιούν ονόματα, τύπους, ορισμούς δομών, όρια συναρτήσεων ή αποθηκευμένα bytes. Η `PATCH` είναι επεξεργασία της βάσης δεδομένων, **όχι** απόδειξη τροποποίησης μιας διεργασίας σε εκτέλεση. Κανένας από τους δύο listeners δεν τεκμηριώνει αυθεντικοποίηση. Το IDA δέχεται συνδέσεις μόνο μέσω loopback, αλλά το Ghidra μπορεί να είναι προσβάσιμο μέσω διεπαφών δικτύου· περιορίστε την πρόσβαση στον listener του Ghidra όταν το χρησιμοποιείτε. Η `QUIT` σταματά οποιονδήποτε listener, ενώ το IDA παρέχει επίσης την `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση shellcode με blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει χώρο για το **shellcode**, εμφανίζει τη **διεύθυνση μνήμης** του και διακόπτει προσωρινά την εκτέλεση.\
Συνδέστε έναν debugger όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εμφανίζεται και συνεχίστε την εκτέλεση για να αποσφαλματώσετε το shellcode.

Η σελίδα releases στο GitHub περιέχει zip με τις μεταγλωττισμένες εκδόσεις: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, **δημιουργήστε ένα έργο C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση shellcode με jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει χώρο για το shellcode και εισέρχεται σε έναν ατέρμονο βρόχο. Συνδέστε τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, διακόψτε την μέσα στον βρόχο και κάντε step μέχρι την επόμενη κλήση, η οποία μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει σταματήσει στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να προσομοιώσετε το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να επιλέξετε «Open File» και «Open Shellcode». Στη δική μου περίπτωση, όταν άνοιξα το shellcode ως αρχείο, το απομεταγλώττισε σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγονται τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσετε την προσομοίωση στο σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα την προσομοίωση από εκεί:

![Ορισμός breakpoint στην επιθυμητή είσοδο του shellcode πριν από την έναρξη της προσομοίωσης στο Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter έχει σταματήσει στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του προσομοιωμένου shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Αποσυσκότιση shellcode και εντοπισμός συναρτήσεων που εκτελέστηκαν

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

Το scDbg διαθέτει επίσης γραφικό launcher, όπου μπορείτε να επιλέξετε τις επιθυμητές επιλογές και να εκτελέσετε το shellcode

![Γραφικός launcher του scDbg για την επιλογή των ρυθμίσεων emulation και tracing του shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** αποθηκεύει το τελικό shellcode, αν έχουν γίνει δυναμικά αλλαγές στο shellcode στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Το **start offset** μπορεί να φανεί χρήσιμο για να ξεκινήσει το shellcode από μια συγκεκριμένη μετατόπιση. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων του shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι οποιαδήποτε από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με το CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε την ακόλουθη συνταγή για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Αποσυσκότιση MBA obfuscation

Η συσκότιση **Mixed Boolean-Arithmetic (MBA)** αποκρύπτει απλές εκφράσεις, όπως `x + y`, πίσω από τύπους που συνδυάζουν αριθμητικές πράξεις (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες είναι συνήθως σωστές μόνο υπό **αριθμητική modulo σταθερού πλάτους**, οπότε τα κρατούμενα και οι υπερχειλίσεις έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτού του είδους την έκφραση με γενικά εργαλεία άλγεβρας, μπορείτε εύκολα να καταλήξετε σε λανθασμένο αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον lifted κώδικα/IR/την έξοδο του decompiler (`8/16/32/64` bit).
2. **Ταξινομήστε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα bitwise atoms
   - **Ημιγραμμική**: γραμμική έκφραση μαζί με σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: εμφανίζονται γινόμενα
   - **Μικτή**: γινόμενα και bitwise λογική είναι συνυφασμένα, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια αναγραφή** με τυχαίους ελέγχους ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, διατηρήστε την αρχική έκφραση αντί να μαντεύετε.

### Παράκαμψη flattened control flow με ένα στενό execution slice

Η ανάκτηση ολόκληρου του control-flow graph συχνά δεν είναι απαραίτητη. Σε περιπτώσεις control-flow flattening, opaque predicates, μεγάλων dispatchers ή κώδικα με πολλά MBA, ακολουθήστε τις αναφορές από encrypted blobs και output buffers μέχρι τη μικρότερη ρουτίνα που τα μετασχηματίζει. Έπειτα, αναπαραγάγετε μόνο αυτό το data-flow slice ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, αν η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι:<sup>[[7]](#references)</sup>

1. Καταγράψτε τις εκτελέσιμες ενότητες και τις ενότητες δεδομένων, τις relocations και τις cross-references. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των byte και το πλάτος των στοιχείων.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει στο plaintext ή στο output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις εισαγόμενες κλήσεις και την απαιτούμενη global state.
3. Μεταφέρετε μόνο αυτές τις λειτουργίες σε ένα μοντέλο Python σταθερού πλάτους. Αν το slice εξακολουθεί να εξαρτάται από υπερβολικά μεγάλο μέρος της κατάστασης, καλέστε τη ρουτίνα με Unicorn, QEMU ή debugger και κάντε hook τις άσχετες εισαγωγές αντί να προσομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι την έξοδό του από το παρεχόμενο binary: αφαιρέστε τα σιωπηρά fallbacks, αναζητήστε ενσωματωμένες απαντήσεις και εκτελέστε τον σε builds που δεν έχετε ξαναδεί, με αλλαγμένα strings, keys, identifiers, layouts και seeds obfuscation.

Χρήσιμες εντολές για έναν αρχικό έλεγχο είναι:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός εκφράσεων MBA που συγκαλύπτουν σταθερές

Μια φαινομενικά εξαρτώμενη από την είσοδο έκφραση byte μπορεί να απαλείφει πλήρως την είσοδό της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το πεδίο των 8 bit· ένα σύνολο εξόδων με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε την περιβάλλουσα μηχανή καταστάσεων.<sup>[[7]](#references)</sup>

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

Διατηρήστε την τελική μάσκα, επειδή η αρχική πρόσθεση προκαλεί αναδίπλωση στο πλάτος του byte. Για ένα ευρύτερο πεδίο τιμών, ρωτήστε έναν SMT solver αν είναι ικανοποιήσιμη η συνθήκη `f(x1) != f(x2)` για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει ότι η συνάρτηση είναι αναλλοίωτη, ενώ το `sat` δίνει ένα αντιπαράδειγμα και σημαίνει ότι δεν μπορείτε να απορρίψετε την είσοδο.<sup>[[7]](#references)</sup>

#### Αναγνωρίστε αποκωδικοποίηση εξαρτώμενη από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας αποκωδικοποιητής μπορεί να αναμείξει το αποτέλεσμα ενός αισθητήρα σε ένα bit κλειδιού, μια σταθερά opaque predicate ή την κατάσταση ενός flattened dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά λανθασμένο απλό κείμενο σε έναν emulator. Επομένως, δεν αρκεί να διορθώσετε μόνο τους ορατούς κλάδους αποτυχίας· ανιχνεύστε τις εξαρτήσεις δεδομένων από τις περιβαλλοντικές διερευνήσεις έως την κατάσταση του αποκωδικοποιητή, συγκρίνετε το ίδιο τμήμα σε αυθεντική συσκευή και emulator και ελέγξτε πώς η επιβολή κάθε αποτελέσματος αισθητήρα αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένα πρακτικό εργαλείο απλοποίησης MBA για την ανάλυση malware και το reverse engineering προστατευμένων binaries. Ταξινομεί την έκφραση και την κατευθύνει σε εξειδικευμένες ροές επεξεργασίας, αντί να εφαρμόζει ένα γενικό πέρασμα επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean εισόδους, παράγει μια υπογραφή και δοκιμάζει παράλληλα διάφορες μεθόδους ανάκτησης, όπως αντιστοίχιση προτύπων, μετατροπή σε ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα atoms με μάσκα σταθερών ανακατασκευάζονται με ανακατασκευή σε διαμερίσματα bit, ώστε οι περιοχές με μάσκα να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αναλύονται σε πυρήνες και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε προσωρινές μεταβλητές πριν απλοποιηθεί η εξωτερική σχέση.

Παράδειγμα μικτής ταυτότητας που συχνά αξίζει να δοκιμάσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να συμπτυχθεί σε:

```c
x * y
```

### Σημειώσεις για reverse engineering

- Προτιμήστε να εκτελείτε το CoBRA σε **εκφράσεις IR μετά την ανύψωση** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από αριθμητική με μάσκες ή από καταχωρητές μικρότερου πλάτους.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, δείτε εδώ τις τοπικές σημειώσεις για το Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **πρόσθετο LLVM pass** (`libCobraPass.so`), χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από μεταγενέστερα analysis passes.
- Τα υπολειπόμενα μικτά πεδία που δεν υποστηρίζονται και είναι ευαίσθητα στο carry πρέπει να θεωρούνται ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα τη διαδρομή του carry.

## Ανάκτηση flattening της ροής ελέγχου με κατάσταση XOR

Ένας flattener τύπου OLLVM μπορεί να διατηρεί την κατάσταση του τρέχοντος basic block σε δύο καταχωρητές 64 bit και να την ανασυνθέτει με XOR σε έναν dispatcher. Κάθε αρχικό block γράφει το ζεύγος που αντιστοιχεί στην επόμενη κατάστασή του και επιστρέφει στον dispatcher. Ένα conditional block μπορεί να χρησιμοποιεί `CMOVcc` για να αντικαθιστά το ένα μισό του ζεύγους με βάση τα CPU flags, οπότε η παρακολούθηση μόνο των ορατών εντολών διακλάδωσης παραβλέπει τους δύο διαδόχους. Σε αντίθεση με έναν dispatcher έμμεσων jumps, αυτή η μορφή μπορεί να χρησιμοποιεί άμεσα back-edges παντού.<sup>[[19]](#references)[[20]](#references)</sup>

Για να ανακτήσετε το γράφημα, εντοπίστε το δέντρο συγκρίσεων του dispatcher και τους δύο καταχωρητές κατάστασης, αντιστοιχίστε κάθε συγκρινόμενη κατάσταση XOR στο block-στόχο της και, στη συνέχεια, εντοπίστε τις εγγραφές στο ζεύγος καταχωρητών που φτάνουν σε κάθε αρχικό block. Για εγγραφές υπό συνθήκη, συμπεριλάβετε την εντολή που θέτει τα flags και τις δύο εκβάσεις του `CMOVcc`. Αντικαταστήστε την έξοδο κάθε block προς τον dispatcher με τον αντίστοιχο άμεσο διάδοχο ή conditional branch· έτσι ο dispatcher καθίσταται μη προσπελάσιμος χωρίς να γίνει patch στο binary. Αυτή είναι μια προσέγγιση πλήρους CFG· αν σας ενδιαφέρει μόνο ένας decoder, η παραπάνω [ροή εργασίας στενού execution slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) μπορεί να είναι ταχύτερη.<sup>[[19]](#references)[[20]](#references)</sup>

Το [DispatchThis](https://github.com/YungBinary/DispatchThis) αυτοματοποιεί αυτή τη μορφή στο Binary Ninja. Αντιγράψτε το `plugins/DispatchThis` στον κατάλογο πρόσθετων χρήστη του Binary Ninja και κάντε επανεκκίνηση. Στην επηρεαζόμενη συνάρτηση, ανοίξτε το **Function Settings** και επιλέξτε `OLLVM_XOR_64`· αν δεν ξεκινήσει η ανάλυση, χρησιμοποιήστε **Analysis → Reanalyze All Functions**. Αυτή η λειτουργία ξαναγράφει τις ακμές ροής ελέγχου του MLIL, όχι τα bytes του αρχείου, και δεν χρειάζεται Z3 ή τον επιλυτή έμμεσων jumps. Έχει δοκιμαστεί στο Binary Ninja 5.3.9757+· δεν αφαιρεί τις νεκρές εγγραφές κατάστασης ανά block, επομένως μην τις εκλάβετε λανθασμένα ως ενεργές μεταβάσεις που παραμένουν.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί χειρισμό σημάτων/εξαιρέσεων για να αλλάξει τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να αναιρέσει το obfuscation του αποτελέσματος. Έχει αρκετές εξαρτήσεις.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε σε **CTF, αυτή η λύση για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point**, αναζητήστε στις συναρτήσεις το `::main`, όπως εδώ:

![Εύρεση του entry point μιας Rust στο Ghidra με αναζήτηση στα ονόματα συναρτήσεων για διπλή άνω και κάτω τελεία και main](<../../images/image (1080).png>)

Σε αυτήν την περίπτωση, το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα συνάρτηση main.\
Αφού βρείτε το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση Rust strings από firmware ELF

Σε **Rust ELF** binaries, πολλές στατικές συμβολοσειρές δεν αναφέρονται από δείκτες με τερματισμό NUL, όπως συμβαίνει στη C. Μια συνηθισμένη διάταξη του `rustc` είναι μια **πλειάδα pointer/length** μέσα στο **`.data.rel.ro`**, η οποία δείχνει στο πραγματικό blob συμβολοσειρών που είναι αποθηκευμένο στο **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικές συμβολοσειρές ή να χάσει εντελώς τις διασταυρούμενες αναφορές.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Λάβετε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία λέξη κάθε φορά.
3. Θεωρήστε κάθε τιμή εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Θεωρήστε την επόμενη λέξη ως το υποψήφιο μήκος.
5. Εφαρμόστε φίλτρα εγκυρότητας (για παράδειγμα, διατηρήστε μήκη μεταξύ **4** και **100** bytes).
6. Διαβάστε ακριβώς `length` bytes από το `.rodata`, αντί να κάνετε σάρωση μέχρι το `0x00`.

Ελάχιστη λογική εξαγωγής:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες συμβολοσειρές Rust συχνά αποκαλύπτουν **HTTP routes, ονόματα RPC, μηνύματα καταγραφής, assertions, ονόματα αρχείων, κλειδιά διαμόρφωσης, handlers εντολών και λογική σχετική με τον έλεγχο ταυτότητας**.

Αν το Ghidra δεν εντοπίσει αυτές τις συμβολοσειρές, εκτελέστε ένα προσαρμοσμένο script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στις αναφερόμενες μετατοπίσεις του `.rodata`. Τα εργαλεία `rust-strings` και `RustStrings.py` που δημοσίευσε η Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλες **μεγέθη λέξεων, σειρά byte και διατάξεις τμημάτων**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για δυαδικά αρχεία που έχουν μεταγλωττιστεί με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειαστεί να κάνετε reverse engineering σε ένα δυαδικό αρχείο Delphi, θα σας πρότεινα να χρησιμοποιήσετε το plugin IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα plugin Python και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το δυαδικό αρχείο και θα επιλύσει δυναμικά τα ονόματα των συναρτήσεων κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη συνάρτηση που καλεί αυτό το κουμπί.

## Golang

Για συνηθισμένα δυαδικά αρχεία Go, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει δομές runtime και να βελτιώσει τα ονόματα των συναρτήσεων στο IDA. Φορτώστε το plugin Python με **Alt+F7**.

Αν χρειαστεί να κάνετε reverse engineering σε ένα δυαδικό αρχείο Golang, θα σας πρότεινα να χρησιμοποιήσετε το plugin IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα plugin Python και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

### Ανάκτηση μεταδεδομένων χωρίς τον πίνακα συμβόλων

Ένα stripped εκτελέσιμο Go εξακολουθεί να χρειάζεται μεταδεδομένα runtime για να αντιστοιχίσει τους μετρητές προγράμματος σε συναρτήσεις. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει δομές όπως τα `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Έτσι μπορούν να ανακτηθούν όρια συναρτήσεων, ονόματα, διαδρομές πηγαίου κώδικα, τύποι και πληροφορίες build, χωρίς να βασίζεται κανείς στον συμβατικό πίνακα συμβόλων.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές λειτουργικές, αντικαθιστώντας τα ανακτημένα ονόματα. Το Garble, για παράδειγμα, κατακερματίζει τα αναγνωριστικά και τις διαδρομές πακέτων και αφαιρεί πληροφορίες build, module και debug.<sup>[[12]](#references)</sup> Το obfuscated token πακέτου πρέπει να παραμένει συνεπές σε όλες τις συναρτήσεις αυτού του πακέτου. Ομαδοποιήστε τις συναρτήσεις με βάση το επαναλαμβανόμενο token, συμπεράνετε ένα πακέτο από τις συναρτήσεις που καλεί, τις συμβολοσειρές και τα API του και, στη συνέχεια, διαδώστε την ετικέτα αυτού του πακέτου σε ολόκληρη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή συμβόλων runtime με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση control-flow graph (CFG). Ακολουθήστε αυτήν τη σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Προσδιορίστε την έκδοση του compiler.** Δοκιμάστε πρώτα το `BuildInfo` και τις ενσωματωμένες συμβολοσειρές έκδοσης. Αν ο obfuscator τις αφαίρεσε, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtime αναφοράς συγκεκριμένων εκδόσεων. Στις δοκιμές της Volexity, περίπου το `2%` του runtime αρκούσε για να διακρίνει κύριες εκδόσεις Go. Αντιμετωπίστε το ως εμπειρική βελτιστοποίηση, όχι ως καθολικό κατώφλι.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε αντίστοιχες αναφορές.** Δημιουργήστε καθαρά binaries για την προσδιορισμένη έκδοση Go, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση του toolchain περιορίζει τις διαφορές CFG που δημιουργεί ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και παράγει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση basic blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής βεβαιότητας συνδέουν τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Οι ασθενέστερες αντιστοιχίσεις μπορούν και πάλι να προσδιορίσουν ένα πακέτο ή ένα module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επαληθεύστε και εισαγάγετε.** Επιβεβαιώστε τα προτεινόμενα ονόματα με τις σχέσεις κλήσεων, τις σταθερές, τις συμβολοσειρές και τις παρενέργειες και, στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin GoResolver για IDA ή Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Το προεπιλεγμένο όριο σημαντικής αντιστοίχισης είναι `0.9`. Οι διακόπτες `--extract` και `--graph` μπορούν να απομονώσουν κάθε στάδιο, ενώ η προεπιλεγμένη λειτουργία εκτελεί και τα δύο, επειδή τα ανακτημένα metadata του runtime και τα στοιχεία CFG αλληλοσυμπληρώνονται.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, οι σημαίες build, η αρχιτεκτονική και οι διαφορές στις εκδόσεις βιβλιοθηκών μπορούν να αλλάξουν τη μορφή του γράφου, επομένως διατηρήστε τις μη επιλυμένες συναρτήσεις αντί να επιβάλλετε ονόματα με χαμηλή βεβαιότητα.<sup>[[13]](#references)</sup>

### Ανάκτηση του πίνακα συμβολοσειρών Go

Τα δυαδικά αρχεία Go τοποθετούν τα bytes συμβολοσειρών από κάθε συνδεδεμένο πακέτο σε έναν ενιαίο, συνεχόμενο πίνακα. Οι καταχωρίσεις δεν τερματίζονται με NUL και οι δομές runtime δεν αποκαλύπτουν τη βάση ή το μέγεθος του πίνακα. Ωστόσο, ο compiler ταξινομεί τις καταχωρίσεις πρώτα κατά μήκος και έπειτα αλφαβητικά, σε όλα τα λειτουργικά συστήματα και τις αρχιτεκτονικές. Επομένως, αφού βρει μία καταχώριση, ένας αναλυτής μπορεί να διατρέξει τις γειτονικές καταχωρίσεις και να χρησιμοποιήσει διασταυρούμενες αναφορές δεδομένων για να συσχετίσει συμβολοσειρές με κώδικα.<sup>[[15]](#references)</sup>

Το [GoStringExtractor](https://github.com/volexity/GoStringExtractor) αυτοματοποιεί αυτή τη ροή εργασιών στα IDA Pro και Ghidra. Αφήστε πρώτα να ολοκληρωθεί η αυτόματη ανάλυση, επειδή το plugin βασίζεται σε διασταυρούμενες αναφορές του τμήματος δεδομένων. Το προεπιλεγμένο σημείο αναφοράς είναι η συμβολοσειρά runtime `entersyscall`. Έπειτα, μπορεί να σαρώσει και προς τις δύο κατευθύνσεις, να ορίσει τις ανακτημένες συμβολοσειρές στη βάση δεδομένων και να εξαγάγει μια αντιστοίχιση JSON από συμβολοσειρές σε συναρτήσεις που τις αναφέρουν.<sup>[[14]](#references)</sup>

Φιλτράρετε την αναφορά με βάση το πακέτο της συνάρτησης που κάνει την αναφορά, ώστε να διαχωρίσετε τον κώδικα της εφαρμογής ή του malware από τον θόρυβο των συνδεδεμένων βιβλιοθηκών. Αυτή η τεχνική δεν μπορεί να ανακτήσει literals που έχουν καταστραφεί από obfuscation, όπως με τον μετασχηματισμό `-literals` του Garble. Μπορεί, ωστόσο, να οργανώσει συμβολοσειρές runtime που παραμένουν χωρίς obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Ανάκτηση τύπων runtime της Go

Η Go ενσωματώνει πληροφορίες τύπων runtime που χρησιμοποιούνται από λειτουργίες όπως το garbage collection. Όταν αφαιρούνται τα build information ή ο disassembler δεν αναλύει αυτά τα metadata, οι εντολές μπορεί να φαίνεται ότι φορτώνουν αυθαίρετες διευθύνσεις δεδομένων και η περιοχή-στόχος παραμένει χωρίς τύπο. Η ανάκτηση των metadata μετατρέπει αυτές τις διευθύνσεις σε ευανάγνωστες αναφορές τύπων και διευκολύνει την κατανόηση των δυνατοτήτων των πακέτων.<sup>[[15]](#references)</sup>

Το [GoResolver](https://github.com/volexity/GoResolver) μπορεί να εξαγάγει symbols και να αναλύσει τους τύπους runtime σε μια αναφορά JSON. Το τρέχον CLI χρησιμοποιεί την υποεντολή `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Η επιλογή `-y`/`--types` ενεργοποιεί την ανάλυση τύπων. Εισαγάγετε την αναφορά με το plugin του GoResolver για IDA Pro ή Ghidra, για να ορίσετε τους τύπους που ανακτήθηκαν και να εφαρμόσετε τις αναφορές τους στη βάση δεδομένων ανάλυσης. Στη μορφή αναφοράς που εισήχθη με αυτήν τη λειτουργία, αν παραλείψετε το `-y`, τα πεδία διεύθυνσης RTTI και τύπων που ανακτήθηκαν παραμένουν null.<sup>[[10]](#references)[[15]](#references)</sup>

Το GoResolver υποστηρίζει δείγματα PE, ELF και Mach-O για x86, AMD64, ARM και ARM64, επομένως η ίδια ροή εργασίας ισχύει για Go binaries από Windows, Linux και macOS.<sup>[[10]](#references)</sup>

## Compiled Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο Python binary ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να κάνετε **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με γραφικό περιβάλλον
- [**mgba** ](https://mgba.io)- Περιλαμβάνει debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin του Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin του Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στην επιλογή _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance.

![Διαμόρφωση χειριστηρίων του no$gba που δείχνει τις αντιστοιχίσεις κουμπιών του Game Boy Advance](<../../images/image (581).png>)

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

Επομένως, σε αυτό το είδος προγράμματος, το ενδιαφέρον είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνάρτηση που συναντάται συχνά: **KEYINPUT**.

![Προβολή του Ghidra ενός δυαδικού αρχείου GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από κάποιες αρχικές λειτουργίες (χωρίς σημασία):

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **τελευταία πλήκτρα** και δεν είναι το τρέχον πλήκτρο· αυτό συμβαίνει επίσης όταν αφήνουμε ένα κουμπί (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

Στον προηγούμενο κώδικα βλέπουμε ότι συγκρίνουμε το **uVar1** (τη θέση όπου βρίσκεται η **τιμή του πατημένου κουμπιού**) με κάποιες τιμές:

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): Στο challenge, αυτό το κουμπί καθαρίζει την οθόνη.
- Έπειτα, συγκρίνεται με την τιμή **8** (κουμπί **START**). Στο συγκεκριμένο challenge, αυτή η διαδρομή ελέγχει αν ο κωδικός που καταχωρίστηκε είναι έγκυρος.
  - Σε αυτήν την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων αθροίζονται στο `DAT_030000d8`.

Επομένως, σε αυτό το challenge, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσεις έναν συνδυασμό με μήκος μικρότερο από 8, ώστε το άθροισμα να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένο writeup του challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [4] [pentestpartners/reverse-engineering - συμβολοσειρές Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial για reverse engineering GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Ανατρέποντας το reverse engineering με τη βοήθεια AI ή τουλάχιστον προσπαθώντας](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση για τη σύγκριση γραφημάτων ροής ελέγχου βάσει αντιστοίχισης βασικών blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Αποθετήριο GoResolver της Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας γραφημάτων ροής ελέγχου για αυτόματη deobfuscation δυαδικών αρχείων Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Αποθετήριο GoStringExtractor της Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ενημερώσεις στα εργαλεία Golang της Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Ανάλυση managed code του REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Οδηγός CLI και Evidence του REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Ροή εργασιών unflattening ροής ελέγχου του Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Εισβολή zero-day στο PaperCut MF, Java Loader, Web Shell και AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README του IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Υλοποίηση του IDA bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Υλοποίηση του Ghidra bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - Το InetSocketAddress(int) δεσμεύεται στη διεύθυνση wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
{{#include ../../banners/hacktricks-training.md}}
