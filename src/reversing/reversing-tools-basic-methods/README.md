# Εργαλεία Reverse Engineering και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reverse engineering βασισμένα στο ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Αυτοματοποίηση user-mode του WinDbg

{{#ref}}
windbg-automation.md
{{#endref}}

## Ανάλυση macro σε έγγραφα Office

Για ύποπτα έγγραφα Office, εξετάστε [κώδικα junk σε VBA macro και κρυφά στοιχεία ελέγχου UserForm](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

## Ροή ελέγχου Windows βάσει εξαιρέσεων

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Debugging του πυρήνα των Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Απομεταγλωττιστής Wasm / μεταγλωττιστής Wat

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **απομεταγλώττιση** από wasm (binary) σε wat (απλό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **μεταγλώττιση** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για απομεταγλώττιση.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Cached bytecode του Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualized payloads και προσαρμοσμένα VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Απομεταγλωττιστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας decompiler που **απομεταγλωττίζει και εξετάζει πολλαπλές μορφές**, όπως **βιβλιοθήκες** (.dll), **αρχεία metadata των Windows** (.winmd) και **εκτελέσιμα** (.exe). Μετά την απομεταγλώττιση, ένα assembly μπορεί να αποθηκευτεί ως project του Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν απαιτείται η αποκατάσταση χαμένου πηγαίου κώδικα από ένα παλιό assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση στον απομεταγλωττισμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει ακριβώς τις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολλές υπηρεσίες reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα για τη ροή των δεδομένων μέσα σε μια βιβλιοθήκη ή ένα component
- Παρέχει εικόνα για την υλοποίηση και τη χρήση γλωσσών και frameworks .NET
- Εντοπίζει μη τεκμηριωμένες και μη εκτεθειμένες λειτουργίες, ώστε να αξιοποιείτε καλύτερα τα API και τις τεχνολογίες που χρησιμοποιείτε.
- Εντοπίζει dependencies και διαφορετικά assemblies
- Εντοπίζει την ακριβή θέση σφαλμάτων στον κώδικά σας, σε components τρίτων και σε βιβλιοθήκες.
- Κάνει debugging στον πηγαίο κώδικα όλου του .NET code με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Πρόσθετο ILSpy για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να **απομεταγλωττίσετε**, να **τροποποιήσετε** και να **μεταγλωττίσετε ξανά**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα fork του που συντηρείται ενεργά, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί κλικ -> Modify Method** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Επιθεώρηση managed κώδικα με REA χωρίς εκτέλεση

Το **REA** μπορεί να επιθεωρεί PE/CLI metadata και CIL χωρίς να φορτώνει το assembly. Ξεκινήστε με την ταυτότητα του artifact και, στη συνέχεια, εξετάστε τα μέλη και τα δηλωμένα όρια native κώδικα. Αυτό είναι χρήσιμο κατά την εξέταση ύποπτων κλήσεων, πριν χρησιμοποιήσετε decompiler ή εκτελέσετε το πρόγραμμα.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Για τη σύγκριση διαφορών μεταξύ εκδόσεων, το `compare_managed_members` χρησιμοποιεί ταυτότητα βάσει ακατέργαστου CIL/υπογραφής και αποτυπώματα αποκωδικοποιημένων εντολών, αντί να θεωρεί ότι τα metadata tokens παραμένουν σταθερά μεταξύ builds. Μια δήλωση P/Invoke δεν αποδεικνύει ότι εκτελέστηκε native κώδικας· το `verify_managed_native_boundaries` χρειάζεται αντίστοιχο native export ή Evidence συνάρτησης για να ελέγξει αυτό το όριο. Διατηρήστε το digest του artifact, το MVID και τις ανεπίλυτες αντιστοιχίσεις μαζί με το αποτέλεσμα.<sup>[[17]](#references)</sup>

### Καταγραφή DNSpy

Για να κάνετε το **DNSpy να καταγράφει ορισμένες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το απόσπασμα:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Αποσφαλμάτωση με DNSpy

Για να κάνετε αποσφαλμάτωση κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **γνωρίσματα του Assembly** που σχετίζονται με την **αποσφαλμάτωση**:

![Καταγραφή DNSpy - Αποσφαλμάτωση με DNSpy: Αρχικά, αλλάξτε τα γνωρίσματα του Assembly που σχετίζονται με την αποσφαλμάτωση](<../../images/image (973).png>)

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

Αυτό είναι απαραίτητο, γιατί αν δεν το κάνετε, κατά τον **runtime** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και υπάρχει πιθανότητα κατά το debugging να μην ενεργοποιηθεί ποτέ ένα **breakpoint** ή να μην υπάρχουν κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή .NET **εκτελείται** από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα **Debug Tab** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα Debug Tab επιλέξτε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε το **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε το w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο _Debug >> Break All_ και μετά στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και μετά στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάντε κλικ στο Debug Break All και μετά στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιοδήποτε module στην καρτέλα **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιοδήποτε module στην καρτέλα Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε τον debugger **Windbg**
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Ρυθμίστε τις **parameters** της εκτέλεσης, ορίζοντας τη **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Using IDA: Ρυθμίστε τις parameters της εκτέλεσης, ορίζοντας τη διαδρομή προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα διακόπτεται κάθε φορά που φορτώνεται ένα DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση σε συμβάντα φόρτωσης module, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση από ό,τι στη ροή εργασίας με το x64dbg παρακάτω.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε τη διαδρομή του DLL και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε το _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**. Ο debugger θα σταματά σε κάθε dll main και κάποια στιγμή θα **σταματήσει στο DLL Entry του DLL σας**. Από εκεί, απλώς αναζητήστε τα σημεία όπου θέλετε να ορίσετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε**, κοιτάζοντας **στο επάνω μέρος του παραθύρου του win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε, κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει διακοπεί μέσα στο DLL που θέλετε να κάνετε debug.

## GUI Apps / Βιντεοπαιχνίδια

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετίζεται με reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web υπηρεσία σάς επιτρέπει να συγκρίνετε τα αποτελέσματα διαφορετικών decompilers σε μικρά εκτελέσιμα αρχεία.

### Αποκρυπτογράφηση Godot PCK και ανάκτηση project

Για ένα διανεμημένο παιχνίδι Godot, εντοπίστε το PCK του ως αυτόνομο αρχείο `.pck`, ως προσαρτημένο ή ενσωματωμένο pack σε εκτελέσιμο αρχείο ή στον κατάλογο `assets` ενός APK. Το [gore](https://github.com/figurophobia/gore) μπορεί να επιθεωρήσει και να εξαγάγει το pack, ενώ για την πλήρη ανακατασκευή των script και των resource απαιτούνται τα GDRE Tools (`gore setup` τα εγκαθιστά, ή χρησιμοποιήστε το `--gdre`). Για αυτή τη ροή εργασίας, το εργαλείο υποστηρίζει μορφές PCK v2–v4 του Godot 4.x· μπορεί να εντοπίσει κεφαλίδες v1, αλλά για v1 απαιτείται να δοθεί κλειδί.<sup>[[25]](#references)</sup>

Η αυτόματη ανάκτηση κλειδιού απαιτεί έναν κρυπτογραφημένο πίνακα αρχείων· αν είναι κρυπτογραφημένα μόνο τα περιεχόμενα των αρχείων, δώστε ένα γνωστό κλειδί. Μια αποτυχημένη ανάκτηση δεν αποδεικνύει ότι ένα pack δεν είναι κρυπτογραφημένο.<sup>[[28]](#references)</sup>

Η αναζήτηση κλειδιού **δεν** είναι επίθεση στον χώρο κλειδιών AES-256. Ένας κρυπτογραφημένος πίνακας αρχείων αποκαλύπτει το MD5 του απλού κειμένου, το μήκος του απλού κειμένου, το IV και το κρυπτοκείμενο AES-256-CFB.<sup>[[27]](#references)</sup> Το `gore` ελέγχει παράθυρα 32 byte από το εκτελέσιμο αρχείο του παιχνιδιού ή από γειτονικά αρχεία ως υποψήφια κλειδιά. Φιλτράρει τα υποψήφια κλειδιά με βάση το εύλογο μήκος και το πρόθεμα της αποκρυπτογραφημένης διαδρομής και, στη συνέχεια, επιβεβαιώνει τα ευρήματα της δυαδικής σάρωσης αποκρυπτογραφώντας ολόκληρο τον πίνακα και ελέγχοντας το MD5 του.<sup>[[26]](#references)[[28]](#references)</sup> Αρχικά αναζητά σε αρχικοποιημένες ενότητες δεδομένων PE/ELF και, αν δεν βρει κάτι, σαρώνει ολόκληρο το αρχείο· το `--scan` προσθέτει άλλα υποψήφια αρχεία.<sup>[[28]](#references)</sup>

Αν δεν βρεθεί ενσωματωμένο κλειδί, δοκιμάζεται μια μικρή ενσωματωμένη λίστα κωδικών πρόσβασης· το `--wordlist` δέχεται άλλους υποψηφίους. Κάθε κωδικός πρόσβασης δοκιμάζεται ως αναπαράσταση κλειδιού που προκύπτει από τον κωδικό πρόσβασης του engine, ως κυριολεκτική τιμή με συμπλήρωση μηδενικών ή ως κλειδί 64 δεκαεξαδικών χαρακτήρων. Σε αντίθεση με τα ευρήματα της δυαδικής σάρωσης, τα ευρήματα της wordlist περνούν σε αυτή την υλοποίηση μόνο από το φίλτρο δομής διαδρομών. Επιβεβαιώστε τα ανοίγοντας το pack και επικυρώνοντας τα εξαγόμενα assets.<sup>[[26]](#references)[[28]](#references)</sup>

Αφού έχετε τοπικά το artifact του παιχνιδιού, επιλέξτε το στάδιο που χρειάζεστε για την ανάλυση. Το `recover` καλεί το GDRE για να ανακατασκευάσει ένα project που μπορεί να ανοιχτεί, ενώ το `extract` απλώς αποσυσκευάζει τα ακατέργαστα αρχεία. Το `key` εμφανίζει ένα υποψήφιο κλειδί για χρήση με άλλο εργαλείο.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Διερεύνηση εγγενούς κώδικα με τεκμηρίωση μέσω REA

Το **REA** παρέχει πρόσβαση στην ανάλυση των Hopper, Ghidra και IDA μέσω CLI και MCP. Απαιτεί Node.js 22.x (τουλάχιστον 22.19), 24.x (τουλάχιστον 24.11) ή 26+, καθώς και npm. Ρυθμίστε πρώτα έναν υπάρχοντα εγγενή πάροχο· ελέγξτε το `rea providers --json` και επιλέξτε ρητά έναν πάροχο, αν περισσότεροι από ένας υποστηρίζουν τον στόχο. Αντικαταστήστε το `0x1000` παρακάτω με ένα παρατηρημένο όνομα συνάρτησης ή διεύθυνση από την απογραφή.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Ξεκινήστε από μια συμβολοσειρά χαρακτηριστικού ή ένα σύμβολο, ακολουθήστε τις αναφορές και τους callers και, στη συνέχεια, επιθεωρήστε τον φάκελο της επιλεγμένης συνάρτησης και το pseudocode με το `rea decompile`. Το REA συνδέει μια συνεδρία με τον επιλεγμένο provider, αντί να τον αντικαθιστά σιωπηρά μετά από αποτυχία. Για επαναλήψιμα ερωτήματα, το `--snapshot PATH` επαναχρησιμοποιεί μόνο bytes artifacts, provider, ρυθμίσεις, operation και παραμέτρους που αντιστοιχούν· ένα snapshot είναι τοπική cache, όχι αποθηκευμένη βάση δεδομένων provider. Διατηρήστε το Evidence που επιστρέφεται και τα ρητά άγνωστα στοιχεία, αντί να αντιμετωπίζετε τις συναγόμενες διαδρομές ή το κείμενο του decompiler ως αρχικό source.<sup>[[16]](#references)[[18]](#references)</sup>

Για entry points JavaScript/Electron που οδηγούν σε native add-ons, δείτε το [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Scripted ανάλυση IDA και Ghidra με τοπική γέφυρα TCP

Το [IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) εκτελείται μέσα σε μια βάση δεδομένων IDA ή ένα πρόγραμμα Ghidra CodeBrowser που είναι **ήδη ανοιχτό** και επιτρέπει σε ένα ξεχωριστό script να υποβάλλει ερωτήματα και να τροποποιεί αυτή τη βάση δεδομένων ανάλυσης. Εκτελέστε το `ID_Server.py` από το Python CLI του IDA (`import ID_Server`) ή το `Ghidra_Server.py` από το Script Manager του Ghidra. Το IDA συνδέεται στη `127.0.0.1`, ξεκινώντας από τη θύρα `5073`, και ελέγχει τις επόμενες θύρες. Το τρέχον script του Ghidra ξεκινά από τη θύρα `5093` και δοκιμάζει δέκα θύρες έως και τη `5102`· το Java socket του συνδέεται στη διεύθυνση wildcard, όχι μόνο στο loopback. Ελέγξτε τη θύρα που εμφανίζει το instance πριν συνδεθείτε. Σε αντίθεση με έναν headless analyzer, αυτή η γέφυρα λειτουργεί στο πρόγραμμα που είναι ανοιχτό εκείνη τη στιγμή σε αυτό το GUI instance.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Στείλτε **μία εντολή που τελειώνει με newline ανά σύνδεση** και διαβάστε την απόκριση που τελειώνει με newline. Το αποτέλεσμα είναι συνήθως JSON. Για παράδειγμα, αφού εντοπίσετε ένα imported API σχετικό με μια διαδρομή εισόδου, το `IMPORTXREF` εντοπίζει τα σημεία κλήσης του· έπειτα, το `DECOMP_XREF` αποσυμπιέζει μαζικά τους callers μιας επιλεγμένης διεύθυνσης. Το `FUNC` επιθεωρεί μια συνάρτηση, ενώ το `PCODE` επιστρέφει την ενδιάμεση αναπαράσταση του decompiler. Χρησιμοποιήστε τη διεύθυνση από την ενεργή βάση δεδομένων, όχι μια διεύθυνση αντιγραμμένη από binary με διαφορετικό rebase. Το παρακάτω παράδειγμα χρησιμοποιεί την προεπιλεγμένη θύρα του IDA· για το Ghidra, χρησιμοποιήστε τη θύρα που εμφανίζει το script του.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Το ίδιο κανάλι μπορεί να **αλλάξει τη βάση δεδομένων ανάλυσης**: τα `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` και `PATCH` τροποποιούν ονόματα, τύπους, ορισμούς δομών, όρια συναρτήσεων ή αποθηκευμένα bytes. Το `PATCH` είναι επεξεργασία της βάσης δεδομένων, **όχι** απόδειξη εφαρμογής patch σε ενεργή διεργασία. Κανένας από τους δύο listeners δεν τεκμηριώνει έλεγχο ταυτότητας. Το IDA ακούει μόνο στη loopback διεύθυνση, αλλά το Ghidra μπορεί να είναι προσβάσιμο μέσω διεπαφών δικτύου· περιορίστε την πρόσβαση στον listener του Ghidra όταν το χρησιμοποιείτε. Το `QUIT` σταματά οποιονδήποτε από τους δύο listeners, ενώ το IDA εκθέτει επίσης τη `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει μνήμη για το **shellcode**, εκτυπώνει τη **διεύθυνση μνήμης** του και διακόπτει την εκτέλεση.\
Συνδέστε έναν debugger, όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εκτυπώθηκε και συνεχίστε την εκτέλεση για να αποσφαλματώσετε το shellcode.

Η σελίδα releases στο GitHub περιέχει zip αρχεία με τις μεταγλωττισμένες εκδόσεις: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, **δημιουργήστε ένα project C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει μνήμη για το shellcode και εισέρχεται σε έναν ατέρμονο βρόχο. Συνδέστε τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, διακόψτε την εκτέλεση ενώ βρίσκεται μέσα στον βρόχο και κάντε step μέχρι την επόμενη κλήση, η οποία μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει διακόψει την εκτέλεση μέσα στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να εξομοιώσετε το shellcode και να το εξετάσετε δυναμικά.

Σημειώστε ότι το Cutter επιτρέπει τις επιλογές «Open File» και «Open Shellcode». Στη δική μου περίπτωση, όταν άνοιξα το shellcode ως αρχείο, το απομεταγλώττισε σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγει τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσει η εξομοίωση στο σημείο που θέλετε, ορίστε εκεί ένα bp και, όπως φαίνεται, το Cutter θα ξεκινήσει αυτόματα την εξομοίωση από εκεί:

![Ορισμός breakpoint στην επιθυμητή είσοδο του shellcode πριν από την έναρξη της εξομοίωσης στο Cutter](<../../images/image (589).png>)

![Ο εξομοιωτής του Cutter έχει διακόψει την εκτέλεση στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε τη στοίβα μέσα σε ένα hex dump:

![Προβολή της στοίβας του εξομοιωμένου shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Απο-συσκότιση shellcode και εντοπισμός συναρτήσεων που εκτελέστηκαν

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

![Γραφικός launcher του scDbg για την επιλογή ρυθμίσεων emulation και tracing του shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** αποθηκεύει το τελικό shellcode, αν έχουν γίνει δυναμικά αλλαγές στο shellcode στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Το **start offset** μπορεί να χρησιμεύσει για την εκκίνηση του shellcode σε συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων στο shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι κάποια από τις επιλογές που εξηγήθηκαν παραπάνω είναι καλύτερη για αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με το CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε το ακόλουθο recipe για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Αποσυσκότιση MBA obfuscation

Η obfuscation **Mixed Boolean-Arithmetic (MBA)** αποκρύπτει απλές εκφράσεις όπως `x + y` πίσω από τύπους που συνδυάζουν αριθμητικούς τελεστές (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες συνήθως ισχύουν μόνο υπό **αριθμητική modulo σταθερού πλάτους**, επομένως οι κρατούμενοι και οι υπερχειλίσεις έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτό το είδος έκφρασης με γενικά εργαλεία άλγεβρας, μπορείτε εύκολα να καταλήξετε σε λάθος αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον κώδικα/IR/decompiler output που έχει ανακτηθεί (`8/16/32/64` bits).
2. **Κατατάξτε την έκφραση** πριν προσπαθήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα bitwise atoms
   - **Ημιγραμμική**: γραμμική έκφραση συν σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: εμφανίζονται γινόμενα
   - **Μικτή**: γινόμενα και bitwise λογική συνυπάρχουν, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια αναδιατύπωση** με τυχαίο έλεγχο ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, κρατήστε την αρχική έκφραση αντί να μαντέψετε.

### Παράκαμψη του flattened control flow με μια στενή τομή εκτέλεσης

Η ανάκτηση του πλήρους γράφου ροής ελέγχου συχνά δεν είναι απαραίτητη. Με control-flow flattening, opaque predicates, μεγάλους dispatchers ή κώδικα με πολλά MBA, ακολουθήστε τις αναφορές από κρυπτογραφημένα blobs και output buffers έως τη μικρότερη ρουτίνα που τα μετασχηματίζει. Στη συνέχεια, αναπαραγάγετε μόνο αυτή την τομή ροής δεδομένων ή εκτελέστε την ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, αν η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι:<sup>[[7]](#references)</sup>

1. Καταγράψτε τις εκτελέσιμες ενότητες και τις ενότητες δεδομένων, τα relocations και τις διασταυρούμενες αναφορές. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των byte και το πλάτος των στοιχείων τους.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει στο buffer απλού κειμένου ή στο output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις imported calls και την απαιτούμενη καθολική κατάσταση.
3. Μεταφέρετε μόνο αυτές τις πράξεις σε ένα μοντέλο Python σταθερού πλάτους. Αν η τομή εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα με Unicorn, QEMU ή debugger και κάντε hook στις άσχετες imports, αντί να εξομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι το output του από το παρεχόμενο binary: αφαιρέστε τις σιωπηρές εναλλακτικές, αναζητήστε ενσωματωμένες απαντήσεις και εκτελέστε τον σε builds που δεν έχετε ξαναδεί, με αλλαγμένες συμβολοσειρές, κλειδιά, αναγνωριστικά, διατάξεις και seeds obfuscation.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός εκφράσεων MBA που κρύβουν σταθερές

Μια έκφραση byte που φαίνεται να εξαρτάται από την είσοδο μπορεί να απαλείφει πλήρως την είσοδό της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το πεδίο των 8 bit· ένα σύνολο εξόδων με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε τη μηχανή καταστάσεων που το περιβάλλει.<sup>[[7]](#references)</sup>

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

Κράτησε την τελική μάσκα, επειδή η αρχική πρόσθεση έχει αναδίπλωση στο πλάτος byte. Για ευρύτερο πεδίο τιμών, ρώτησε έναν SMT solver αν είναι ικανοποιήσιμη η συνθήκη `f(x1) != f(x2)` για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει αμεταβλητότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι δεν μπορείς να απορρίψεις την είσοδο.<sup>[[7]](#references)</sup>

#### Αναγνώριση αποκωδικοποίησης που εξαρτάται από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή crash. Ένας decoder μπορεί να ενσωματώνει το αποτέλεσμα ενός αισθητήρα σε ένα bit του κλειδιού, σε μια σταθερά opaque predicate ή στην κατάσταση ενός flattened dispatcher, να συνεχίζει κανονικά και να παράγει εύλογο αλλά λανθασμένο plaintext σε έναν emulator. Επομένως, δεν αρκεί να κάνεις patch μόνο στους ορατούς κλάδους αποτυχίας· ανίχνευσε τις εξαρτήσεις δεδομένων από τους περιβαλλοντικούς ελέγχους έως την κατάσταση του decoder, σύγκρινε το ίδιο τμήμα σε αυθεντική συσκευή και emulator και έλεγξε πώς αλλάζει το τελικό buffer όταν εξαναγκάζεις κάθε αποτέλεσμα αισθητήρα.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένας πρακτικός απλοποιητής MBA για ανάλυση malware και reversing προστατευμένων binaries. Ταξινομεί την έκφραση και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει ένα γενικό πέρασμα rewrite σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση με Boolean εισόδους, παράγει μια υπογραφή και δοκιμάζει παράλληλα διάφορες μεθόδους ανάκτησης, όπως αντιστοίχιση μοτίβων, μετατροπή ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα atoms με σταθερές μάσκες ανακατασκευάζονται με ανακατασκευή κατά bit, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αναλύονται σε cores και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε προσωρινές μεταβλητές πριν από την απλοποίηση της εξωτερικής σχέσης.

Παράδειγμα mixed ταυτότητας που συνήθως αξίζει να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να απλοποιηθεί σε:

```c
x * y
```

### Σημειώσεις για reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή narrow registers.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, δείτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από τα επόμενα analysis passes.
- Τα μη υποστηριζόμενα carry-sensitive mixed-domain residuals πρέπει να θεωρούνται ένδειξη ότι χρειάζεται να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα το carry path.

## Ανάκτηση control-flow flattening με XOR-state

Ένας flattener τύπου OLLVM μπορεί να διατηρεί την κατάσταση του τρέχοντος basic block σε δύο 64-bit registers και να την ανασυνθέτει με XOR σε έναν dispatcher. Κάθε αρχικό block γράφει το ζεύγος για την επόμενη κατάστασή του και επιστρέφει στον dispatcher. Ένα conditional block μπορεί να χρησιμοποιεί `CMOVcc` για να αντικαταστήσει το ένα μισό του ζεύγους σύμφωνα με τα CPU flags, οπότε η παρακολούθηση μόνο των ορατών branch instructions παραβλέπει τους δύο successors. Σε αντίθεση με έναν dispatcher έμμεσου άλματος, αυτή η μορφή μπορεί να χρησιμοποιεί direct back-edges σε όλη τη ροή.<sup>[[19]](#references)[[20]](#references)</sup>

Για να ανακτήσετε το γράφημα, εντοπίστε το comparison tree του dispatcher και τα δύο state registers, αντιστοιχίστε κάθε συγκρινόμενη XOR state στο target block της και, στη συνέχεια, ανιχνεύστε τις reaching writes στο ζεύγος registers μέσα σε κάθε αρχικό block. Για conditional writes, συμπεριλάβετε το flag-setting instruction και τις δύο εκβάσεις του `CMOVcc`. Αντικαταστήστε την έξοδο κάθε block προς τον dispatcher με τον επιλυμένο άμεσο successor ή conditional branch· έτσι ο dispatcher καθίσταται unreachable χωρίς να τροποποιηθεί το binary. Αυτή είναι προσέγγιση πλήρους CFG· αν σας ενδιαφέρει μόνο ένας decoder, η [ροή εργασίας narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) παραπάνω μπορεί να είναι ταχύτερη.<sup>[[19]](#references)[[20]](#references)</sup>

Το [DispatchThis](https://github.com/YungBinary/DispatchThis) αυτοματοποιεί αυτή τη μορφή στο Binary Ninja. Αντιγράψτε το `plugins/DispatchThis` στον κατάλογο user plugin του Binary Ninja και κάντε επανεκκίνηση. Στην επηρεαζόμενη function, ανοίξτε το **Function Settings** και επιλέξτε `OLLVM_XOR_64`· αν δεν ξεκινήσει η ανάλυση, χρησιμοποιήστε **Analysis → Reanalyze All Functions**. Αυτή η λειτουργία ξαναγράφει τις ακμές control-flow του MLIL, όχι τα bytes του αρχείου, και δεν χρειάζεται Z3 ή τον indirect-jump resolver. Έχει δοκιμαστεί στο Binary Ninja 5.3.9757+· δεν αφαιρεί τις νεκρές state writes ανά block, επομένως μην τις εκλάβετε ως ζωντανές μεταβάσεις που απομένουν.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί signal/exception handling για να αλλάζει το control flow. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές dependencies.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε σε **CTF, αυτό το workaround για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου**, αναζητήστε τις συναρτήσεις με `::main`, όπως στο:

![Εύρεση σημείου εισόδου Rust στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για διπλή άνω και κάτω τελεία main](<../../images/image (1080).png>)

Σε αυτή την περίπτωση, το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα συνάρτηση main.\
Αφού βρείτε τα **ονόματα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Internet** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση Rust strings από ELF firmware

Σε **Rust ELF** binaries, πολλά στατικά strings δεν αναφέρονται μέσω δεικτών με μηδενικό τερματισμό σε στυλ C. Μια συνηθισμένη διάταξη του `rustc` είναι ένα **tuple δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, που δείχνει στο πραγματικό blob string αποθηκευμένο στο **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικές συμβολοσειρές ή να παραλείψει εντελώς τις διασταυρούμενες αναφορές.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Βρείτε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Απαριθμήστε το **`.data.rel.ro`** μία λέξη κάθε φορά.
3. Θεωρήστε κάθε τιμή που βρίσκεται εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Θεωρήστε την επόμενη λέξη ως υποψήφιο μήκος.
5. Εφαρμόστε φίλτρα εγκυρότητας (για παράδειγμα, κρατήστε μήκη μεταξύ **4** και **100** byte).
6. Διαβάστε ακριβώς `length` byte από το `.rodata`, αντί να σαρώσετε μέχρι να βρείτε `0x00`.

Ελάχιστη λογική εξαγωγής:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες συμβολοσειρές Rust συχνά αποκαλύπτουν **HTTP routes, ονόματα RPC, μηνύματα καταγραφής, assertions, ονόματα αρχείων, κλειδιά ρυθμίσεων, handlers εντολών και λογική σχετική με τον έλεγχο ταυτότητας**.

Αν το Ghidra δεν εντοπίσει αυτές τις συμβολοσειρές, εκτελέστε ένα προσαρμοσμένο script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στα αντίστοιχα offsets του `.rodata`. Τα εργαλεία `rust-strings` και `RustStrings.py` που δημοσίευσε η Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **μεγέθη λέξεων, endianness και διατάξεις section**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν μεταγλωττιστεί με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειαστεί να κάνετε reverse ένα binary Delphi, θα σας πρότεινα να χρησιμοποιήσετε το plugin του IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin εκτελεί το binary και επιλύει δυναμικά τα ονόματα των συναρτήσεων κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη συνάρτηση που καλείται από αυτό το κουμπί.

## Golang

Για συνηθισμένα Go binaries, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει δομές runtime και να βελτιώσει τα ονόματα συναρτήσεων στο IDA. Φορτώστε το Python plugin με **Alt+F7**.

Αν χρειαστεί να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το plugin του IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

### Ανάκτηση metadata χωρίς τον πίνακα συμβόλων

Ένα stripped εκτελέσιμο Go εξακολουθεί να χρειάζεται metadata runtime για να αντιστοιχίσει τους μετρητές προγράμματος σε συναρτήσεις. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει δομές όπως οι `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Έτσι μπορεί να ανακτήσει όρια συναρτήσεων, ονόματα, διαδρομές πηγαίου κώδικα, τύπους και λεπτομέρειες build χωρίς να βασίζεται στον συμβατικό πίνακα συμβόλων.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές αξιοποιήσιμες, ενώ αντικαθιστά τα ονόματα που ανακτήθηκαν. Το Garble, για παράδειγμα, κατακερματίζει τα αναγνωριστικά και τις διαδρομές των πακέτων και αφαιρεί πληροφορίες για το build, τα modules και το debugging.<sup>[[12]](#references)</sup> Το obfuscated token ενός πακέτου πρέπει να παραμένει σταθερό σε όλες τις συναρτήσεις του πακέτου. Ομαδοποιήστε τις συναρτήσεις βάσει του επαναλαμβανόμενου token, συναγάγετε ένα πακέτο από τις συναρτήσεις που καλούν, τις συμβολοσειρές και τα API του και, στη συνέχεια, διαδώστε την ετικέτα του πακέτου σε ολόκληρη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή συμβόλων runtime με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση γραφημάτων ροής ελέγχου (CFG). Ακολουθήστε αυτή τη σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Προσδιορίστε την έκδοση του compiler.** Δοκιμάστε πρώτα το `BuildInfo` και τις ενσωματωμένες συμβολοσειρές έκδοσης. Αν ο obfuscator τα αφαίρεσε, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtime αναφοράς ανά έκδοση. Στις δοκιμές της Volexity, περίπου `2%` του runtime αρκούσε για να διακριθούν οι κύριες εκδόσεις του Go. Αντιμετωπίστε το ως εμπειρική βελτιστοποίηση και όχι ως καθολικό όριο.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε κατάλληλες αναφορές.** Δημιουργήστε καθαρά binaries για την έκδοση Go που προσδιορίσατε, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση της toolchain μειώνει τις διαφορές CFG που εισάγει ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και εκδίδει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση βασικών blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής βεβαιότητας συνδέουν τις τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Οι ασθενέστερες αντιστοιχίσεις μπορούν και πάλι να προσδιορίσουν ένα πακέτο ή module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επαληθεύστε και εισαγάγετε.** Επιβεβαιώστε τα προτεινόμενα ονόματα με τις σχέσεις κλήσεων, τις σταθερές, τις συμβολοσειρές και τις παρενέργειες και, στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin GoResolver για το IDA ή το Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Εγκαταστήστε την toolchain και εκτελέστε τον συνδυασμένο extractor και matcher γραφημάτων:<sup>[[10]](#references)</sup>

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

Το προεπιλεγμένο όριο σημαντικής αντιστοίχισης είναι `0.9`. Τα switches `--extract` και `--graph` μπορούν να απομονώσουν οποιοδήποτε από τα δύο στάδια, ενώ από προεπιλογή εκτελούνται και τα δύο, επειδή τα ανακτημένα metadata του runtime και τα στοιχεία CFG αλληλοσυμπληρώνονται.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, τα build flags, η αρχιτεκτονική και οι διαφορές στις εκδόσεις των libraries μπορούν να αλλάξουν τη δομή του graph, επομένως διατηρήστε τις συναρτήσεις που δεν έχουν επιλυθεί αντί να επιβάλλετε ονόματα με χαμηλή βεβαιότητα.<sup>[[13]](#references)</sup>

### Ανάκτηση του πίνακα συμβολοσειρών Go

Τα binaries Go τοποθετούν τα bytes των συμβολοσειρών από κάθε συνδεδεμένο package σε έναν ενιαίο συνεχόμενο πίνακα. Οι εγγραφές δεν τερματίζονται με NUL και οι δομές του runtime δεν αποκαλύπτουν τη βάση ή το μέγεθος του πίνακα. Ωστόσο, ο compiler ταξινομεί τις εγγραφές πρώτα κατά μήκος και έπειτα αλφαβητικά, σε όλα τα λειτουργικά συστήματα και τις αρχιτεκτονικές. Αφού βρει μία εγγραφή, ο analyst μπορεί επομένως να σαρώσει τις γειτονικές εγγραφές και να χρησιμοποιήσει διασταυρούμενες αναφορές δεδομένων για να συσχετίσει συμβολοσειρές με κώδικα.<sup>[[15]](#references)</sup>

Το [GoStringExtractor](https://github.com/volexity/GoStringExtractor) αυτοματοποιεί αυτή τη διαδικασία στα IDA Pro και Ghidra. Περιμένετε πρώτα να ολοκληρωθεί η αυτόματη ανάλυση, καθώς το plugin βασίζεται σε διασταυρούμενες αναφορές του data segment. Το προεπιλεγμένο anchor του είναι η συμβολοσειρά runtime `entersyscall`. Στη συνέχεια, μπορεί να σαρώσει προς οποιαδήποτε κατεύθυνση, να ορίσει τις ανακτημένες συμβολοσειρές στη βάση δεδομένων και να εξαγάγει ένα JSON mapping των συμβολοσειρών προς τις συναρτήσεις που τις αναφέρουν.<sup>[[14]](#references)</sup>

Φιλτράρετε την αναφορά με βάση το package της συνάρτησης που κάνει την αναφορά, για να διαχωρίσετε τον κώδικα της εφαρμογής ή του malware από τον θόρυβο των συνδεδεμένων libraries. Αυτή η τεχνική δεν μπορεί να ανακτήσει literals που έχουν καταστραφεί από obfuscation, όπως από τον μετασχηματισμό `-literals` του Garble. Μπορεί, ωστόσο, να οργανώσει τις συμβολοσειρές runtime που παραμένουν μη obfuscated.<sup>[[14]](#references)[[15]](#references)</sup>

### Ανάκτηση των τύπων runtime της Go

Η Go ενσωματώνει πληροφορίες τύπων runtime, τις οποίες χρησιμοποιούν λειτουργίες όπως το garbage collection. Όταν έχουν αφαιρεθεί οι πληροφορίες build ή ο disassembler δεν αναλύει αυτά τα metadata, οι εντολές μπορεί να φαίνεται ότι φορτώνουν αυθαίρετες διευθύνσεις δεδομένων και η περιοχή-στόχος παραμένει χωρίς τύπο. Η ανάκτηση των metadata μετατρέπει αυτές τις διευθύνσεις σε ευανάγνωστες αναφορές τύπων και διευκολύνει την κατανόηση των δυνατοτήτων των packages.<sup>[[15]](#references)</sup>

Το [GoResolver](https://github.com/volexity/GoResolver) μπορεί να εξαγάγει symbols και να αναλύσει τύπους runtime σε μια αναφορά JSON. Το τρέχον CLI χρησιμοποιεί το subcommand `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Η επιλογή `-y`/`--types` ενεργοποιεί την ανάλυση τύπων. Εισαγάγετε την αναφορά με το plugin του GoResolver για IDA Pro ή Ghidra, για να ορίσετε τους τύπους που ανακτήθηκαν και να εφαρμόσετε τις αναφορές τους στη βάση δεδομένων ανάλυσης. Στη μορφή αναφοράς που εισήχθη με αυτήν τη λειτουργία, αν παραλειφθεί το `-y`, τα πεδία διεύθυνσης RTTI και ανακτημένων τύπων παραμένουν null.<sup>[[10]](#references)[[15]](#references)</sup>

Το GoResolver υποστηρίζει δείγματα PE, ELF και Mach-O για x86, AMD64, ARM και ARM64, επομένως η ίδια ροή εργασίας ισχύει για δυαδικά αρχεία Go από Windows, Linux και macOS.<sup>[[10]](#references)</sup>

## Compiled Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο δυαδικό αρχείο Python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **δυαδικό αρχείο** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **προσομοιώσετε** και να το **αποσφαλματώσετε**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με γραφικό περιβάλλον
- [**mgba** ](https://mgba.io)- Περιλαμβάνει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin του Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin του Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στην επιλογή _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance

![Διαμόρφωση χειριστηρίων no$gba με αντιστοιχίσεις κουμπιών του Game Boy Advance](<../../images/image (581).png>)

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

Λοιπόν, σε αυτού του είδους τα προγράμματα, το ενδιαφέρον είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνηθισμένη συνάρτηση: **KEYINPUT**.

![Προβολή του Ghidra ενός binary GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από ορισμένες αρχικές λειτουργίες (χωρίς ιδιαίτερη σημασία):

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στη λίστα Keys της προηγούμενης κατάστασης και δεν είναι το τρέχον πλήκτρο. Αυτό σημαίνει ότι αφήνεται ένα κουμπί (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): Στο challenge, αυτό το κουμπί καθαρίζει την οθόνη
- Έπειτα, συγκρίνεται με την τιμή **8** (κουμπί **START**). Σε αυτό το challenge, αυτή η διαδρομή ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
  - Σε αυτήν την περίπτωση, η var **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν η τιμή είναι ίδια, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων αθροίζονται στο `DAT_030000d8`.

Επομένως, σε αυτό το challenge, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με λιγότερα από 8 πλήκτρα, ώστε το άθροισμα των τιμών τους να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένη λύση του challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Αποσυσκότιση binary)

## References

- [1] [Απλοποίηση της MBA obfuscation με το CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο CoBRA του Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - συμβολοσειρές Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial για reverse engineering GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετώπιση του reverse engineering με υποβοήθηση AI ή, τουλάχιστον, προσπάθεια αντιμετώπισής του](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση για τη σύγκριση control flow graph βάσει αντιστοίχισης basic block](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Αποθετήριο GoResolver του Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας control-flow graph για την αυτόματη αποσυσκότιση binary Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Αποθετήριο GoStringExtractor του Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ενημερώσεις στα εργαλεία Golang του Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Ανάλυση managed code με το REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Οδηγός για το REA CLI και τα Evidence](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Ροή εργασίας για control-flow unflattening στο Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Εισβολή με PaperCut MF zero-day, Java loader, web shell και AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README του IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Υλοποίηση του IDA bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Υλοποίηση του Ghidra bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - Το InetSocketAddress(int) δεσμεύεται στη διεύθυνση wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Εργαλειοθήκη reverse engineering για Godot](https://github.com/figurophobia/gore)
- [26] [Υλοποίηση ανάκτησης κλειδιού του gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Μορφή encrypted blob του gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Υλοποίηση εντολών και ανάκτησης του gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
