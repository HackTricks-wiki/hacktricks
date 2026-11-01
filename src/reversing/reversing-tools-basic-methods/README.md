# Εργαλεία reverse engineering και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reverse engineering βασισμένα σε ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Αυτοματοποίηση του WinDbg σε user mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Ροή ελέγχου στα Windows μέσω εξαιρέσεων

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Αποσφαλμάτωση του πυρήνα των Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Αποσυμπιεστής Wasm / μεταγλωττιστής Wat

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **αποσυμπίεση** από wasm (δυαδικό) σε wat (απλό κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **μεταγλώττιση** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για αποσυμπίεση.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode σε cache των Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Εικονικοποιημένα payloads και προσαρμοσμένες VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Αποσυμπιεστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας αποσυμπιεστής που **αποσυμπιέζει και εξετάζει πολλαπλές μορφές**, μεταξύ των οποίων **βιβλιοθήκες** (.dll), **αρχεία μεταδεδομένων των Windows** (.winmd) και **εκτελέσιμα** (.exe). Μετά την αποσυμπίεση, μια assembly μπορεί να αποθηκευτεί ως έργο Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να ανακτηθεί χαμένος πηγαίος κώδικας από μια παλαιότερη assembly, αυτή η διαδικασία μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek προσφέρει εύκολη πλοήγηση στον αποσυμπιεσμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο add-in και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει τις ακριβείς ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε τις πολλές υπηρεσίες reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα για τον τρόπο με τον οποίο ρέουν τα δεδομένα μέσα από μια βιβλιοθήκη ή ένα component
- Παρέχει εικόνα για την υλοποίηση και τη χρήση των γλωσσών και των frameworks του .NET
- Εντοπίζει μη τεκμηριωμένες και μη εκτεθειμένες λειτουργίες, ώστε να αξιοποιείτε περισσότερο τα API και τις τεχνολογίες που χρησιμοποιείτε.
- Εντοπίζει dependencies και διαφορετικές assemblies
- Εντοπίζει την ακριβή θέση των σφαλμάτων στον κώδικά σας, σε components τρίτων και σε βιβλιοθήκες.
- Κάνει debug στον πηγαίο κώδικα όλου του κώδικα .NET με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν θέλετε να **αποσυμπιέσετε**, να **τροποποιήσετε** και να **επαναμεταγλωττίσετε**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα ενεργά συντηρούμενο fork του, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί κλικ -> Modify Method** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Επιθεώρηση managed κώδικα χωρίς εκτέλεση με το REA

Το **REA** μπορεί να επιθεωρεί μεταδεδομένα PE/CLI και CIL χωρίς να φορτώνει την assembly. Ξεκινήστε εξετάζοντας την ταυτότητα του artifact και, στη συνέχεια, ελέγξτε τα μέλη και τα δηλωμένα όρια native κώδικα. Αυτό είναι χρήσιμο κατά την εξέταση ύποπτων κλήσεων πριν χρησιμοποιήσετε έναν αποσυμπιεστή ή εκτελέσετε το πρόγραμμα.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Για version diffing, το `compare_managed_members` χρησιμοποιεί raw CIL/signature identity και decoded-instruction fingerprints, αντί να θεωρεί τα metadata tokens σταθερά μεταξύ builds. Μια δήλωση P/Invoke δεν αποδεικνύει ότι εκτελέστηκε native code· το `verify_managed_native_boundaries` χρειάζεται αντιστοιχισμένο native export ή function Evidence για να ελέγξει αυτό το boundary. Διατηρήστε το artifact digest, το MVID και τα unresolved mappings μαζί με το αποτέλεσμα.<sup>[[17]](#references)</sup>

### Καταγραφή στο DNSpy

Για να κάνετε το **DNSpy να καταγράφει ορισμένες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το απόσπασμα:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Debugging με DNSpy

Για να κάνετε debugging κώδικα χρησιμοποιώντας το DNSpy, πρέπει να:

Αρχικά, αλλάξτε τα **Assembly attributes** που σχετίζονται με το **debugging**:

![DNSpy Logging - Debugging με DNSpy: Αρχικά, αλλάξτε τα Assembly attributes που σχετίζονται με το debugging](<../../images/image (973).png>)

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

Και κάντε κλικ στο **μεταγλώττιση**:

![DNSpy Logging - DNSpy Debugging: Και κάντε κλικ στο μεταγλώττιση](<../../images/image (314) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω _**Αρχείο >> Αποθήκευση ενότητας...**_:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω Αρχείο Αποθήκευση ενότητας](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, γιατί αν δεν το κάνετε, κατά την **εκτέλεση** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και μπορεί να μην ενεργοποιηθεί ποτέ κάποιο **breakpoint** κατά τον εντοπισμό σφαλμάτων ή να **μην υπάρχουν** κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Έπειτα, για να ξεκινήσεις το debugging, πρέπει να κλείσεις όλα τα ανοιχτά αρχεία και στην **Debug Tab** να επιλέξεις **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Έπειτα, για να ξεκινήσεις το debugging, πρέπει να κλείσεις όλα τα ανοιχτά αρχεία και στην Debug Tab να επιλέξεις Attach to Process](<../../images/image (318).png>)

Έπειτα, επίλεξε το **w3wp.exe** για να συνδεθείς στον **IIS server** και κάνε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Έπειτα, επίλεξε το w3wp.exe για να συνδεθείς στον IIS server και κάνε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάνε κλικ στο _Debug >> Break All_ και μετά στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάνε κλικ στο Debug Break All και μετά στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη σταματήσουμε και να φορτώσουμε όλα τα modules. Αρχικά, κάνε κλικ στο Debug Break All και μετά στο Debug Windows Modules](<../../images/image (834).png>)

Κάνε κλικ σε οποιοδήποτε module στο **Modules** και επίλεξε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάνε κλικ σε οποιοδήποτε module στο Modules και επίλεξε Open All Modules](<../../images/image (922).png>)

Κάνε δεξί κλικ σε οποιοδήποτε module στο **Assembly Explorer** και επίλεξε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάνε δεξί κλικ σε οποιοδήποτε module στο Assembly Explorer και επίλεξε Sort Assemblies](<../../images/image (339).png>)

## Απομεταγλωττιστής Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Χρήση του IDA

- **Φόρτωσε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επίλεξε τον debugger **Windbg**
- Επίλεξε "**Suspend on library load/unload**"

![Debugging DLLs - Χρήση του IDA: Επίλεξε " Suspend on library load/unload "](<../../images/image (868).png>)

- Ρύθμισε τις **parameters** της εκτέλεσης, εισάγοντας το **path προς το DLL** και τη συνάρτηση που θέλεις να καλέσεις:

![Debugging DLLs - Χρήση του IDA: Ρύθμισε τις parameters της εκτέλεσης, εισάγοντας το path προς το DLL και τη συνάρτηση που θέλεις να καλέσεις](<../../images/image (704).png>)

Έπειτα, όταν ξεκινήσεις το debugging, **η εκτέλεση θα σταματά κάθε φορά που φορτώνεται ένα DLL**. Έτσι, όταν το rundll32 φορτώσει το DLL σου, η εκτέλεση θα σταματήσει.

Αυτή η μέθοδος σταματά την εκτέλεση σε συμβάντα φόρτωσης module, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση απ' ό,τι με τη ροή εργασίας του x64dbg παρακάτω.

### Χρήση των x64dbg/x32dbg

- **Φόρτωσε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Άλλαξε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και όρισε το path του dll και τη συνάρτηση που θέλεις να καλέσεις, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Άλλαξε το _Options --> Settings_ και επίλεξε "**DLL Entry**".
- Έπειτα, **ξεκίνησε την εκτέλεση**. Ο debugger θα σταματήσει σε κάθε dll main και, κάποια στιγμή, θα **σταματήσεις στο dll Entry του DLL σου**. Από εκεί, απλώς αναζήτησε τα σημεία όπου θέλεις να βάλεις breakpoint.

Σημείωσε ότι όταν η εκτέλεση σταματά για οποιονδήποτε λόγο στο win64dbg, μπορείς να δεις **σε ποιον κώδικα βρίσκεσαι** κοιτάζοντας **στο επάνω μέρος του παραθύρου του win64dbg**:

![Χρήση του IDA - Χρήση των x64dbg/x32dbg: Σημείωσε ότι όταν η εκτέλεση σταματά για οποιονδήποτε λόγο στο win64dbg, μπορείς να δεις σε ποιον κώδικα βρίσκεσαι κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει πότε η εκτέλεση έχει σταματήσει μέσα στο DLL που θέλεις να κάνεις debug.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζεις πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζεις. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετική με το reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η web υπηρεσία σάς επιτρέπει να συγκρίνετε την έξοδο διαφορετικών decompilers σε μικρά εκτελέσιμα αρχεία.

### Αποκρυπτογράφηση Godot PCK και ανάκτηση project

Για ένα διανεμημένο παιχνίδι Godot, εντόπισε το PCK του είτε ως αυτόνομο `.pck`, είτε ως προσαρτημένο ή ενσωματωμένο πακέτο στο εκτελέσιμο, είτε στον κατάλογο `assets` ενός APK. Το [gore](https://github.com/figurophobia/gore) μπορεί να επιθεωρήσει και να εξαγάγει το πακέτο, ενώ για την πλήρη ανακατασκευή των scripts και των resources χρειάζονται τα GDRE Tools (`gore setup` τα εγκαθιστά ή μπορείς να χρησιμοποιήσεις το `--gdre`). Για αυτή τη ροή εργασίας, το εργαλείο υποστηρίζει Godot 4.x PCK formats v2–v4. Μπορεί να εντοπίσει v1 headers, αλλά για v1 απαιτείται να δοθεί κλειδί.<sup>[[25]](#references)</sup>

Η αυτόματη ανάκτηση κλειδιού απαιτεί κρυπτογραφημένο file table. Αν είναι κρυπτογραφημένα μόνο τα περιεχόμενα των αρχείων, δώσε ένα γνωστό κλειδί. Η αποτυχία ανάκτησης δεν αποδεικνύει ότι το πακέτο δεν είναι κρυπτογραφημένο.<sup>[[28]](#references)</sup>

Η αναζήτηση κλειδιού **δεν** είναι επίθεση στον χώρο κλειδιών AES-256. Ένα κρυπτογραφημένο file table αποκαλύπτει το MD5 του plaintext, το μήκος του plaintext, το IV και το ciphertext AES-256-CFB.<sup>[[27]](#references)</sup> Το `gore` ελέγχει παράθυρα 32 byte από το εκτελέσιμο του παιχνιδιού ή από γειτονικά αρχεία ως υποψήφια κλειδιά. Απορρίπτει υποψήφια κλειδιά με βάση το εύλογο μήκος και το πρόθεμα της αποκρυπτογραφημένης διαδρομής, και στη συνέχεια επιβεβαιώνει τα ευρήματα της δυαδικής σάρωσης αποκρυπτογραφώντας ολόκληρο τον πίνακα και ελέγχοντας το MD5 του.<sup>[[26]](#references)[[28]](#references)</sup> Αρχικά αναζητά σε αρχικοποιημένα τμήματα δεδομένων PE/ELF και, αν δεν βρει κάτι, σαρώνει ολόκληρο το αρχείο. Η επιλογή `--scan` προσθέτει και άλλα υποψήφια αρχεία.<sup>[[28]](#references)</sup>

Αν δεν βρεθεί ενσωματωμένο κλειδί, δοκιμάζεται μια μικρή ενσωματωμένη λίστα κωδικών πρόσβασης. Η επιλογή `--wordlist` δέχεται επιπλέον υποψήφιους κωδικούς. Κάθε κωδικός πρόσβασης δοκιμάζεται ως αναπαράσταση κλειδιού που προκύπτει από κωδικό πρόσβασης, ως κυριολεκτική τιμή με συμπλήρωση μηδενικών ή ως κλειδί 64 χαρακτήρων σε δεκαεξαδική μορφή. Σε αντίθεση με τα ευρήματα της δυαδικής σάρωσης, τα ευρήματα της wordlist περνούν σε αυτήν την υλοποίηση μόνο το φίλτρο δομής διαδρομής. Επιβεβαίωσέ τα ανοίγοντας το πακέτο και επικυρώνοντας τα αρχεία που εξήχθησαν.<sup>[[26]](#references)[[28]](#references)</sup>

Αν το αρχείο του παιχνιδιού είναι διαθέσιμο τοπικά, επίλεξε το στάδιο που χρειάζεσαι για την ανάλυση. Το `recover` καλεί το GDRE για να ανακατασκευάσει ένα project που μπορεί να ανοιχτεί, ενώ το `extract` αποσυσκευάζει μόνο τα ακατέργαστα αρχεία. Το `key` εμφανίζει ένα υποψήφιο κλειδί για χρήση με άλλο εργαλείο.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Έρευνα εγγενούς κώδικα με τεκμηριωμένα στοιχεία μέσω REA

Το **REA** εκθέτει την ανάλυση των Hopper, Ghidra και IDA μέσω CLI και MCP. Απαιτεί Node.js 22.x (τουλάχιστον 22.19), 24.x (τουλάχιστον 24.11) ή 26+, καθώς και npm. Διαμορφώστε πρώτα έναν υπάρχοντα native provider· ελέγξτε το `rea providers --json` και επιλέξτε provider ρητά όταν περισσότεροι από ένας υποστηρίζουν τον στόχο. Χρησιμοποιήστε στη θέση του `0x1000` παρακάτω ένα όνομα συνάρτησης ή μια διεύθυνση που παρατηρήσατε στο inventory.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Ξεκινήστε από ένα feature string ή symbol και ακολουθήστε τις αναφορές και τους callers. Έπειτα, εξετάστε το dossier και το pseudocode της επιλεγμένης συνάρτησης με `rea decompile`. Το REA συνδέει μια συνεδρία με τον επιλεγμένο provider, αντί να τον αντικαθιστά σιωπηρά μετά από αποτυχία. Για επαναλήψιμα queries, το `--snapshot PATH` επαναχρησιμοποιεί μόνο bytes artifacts που ταιριάζουν ως προς τον provider, τις ρυθμίσεις, την operation και τις παραμέτρους. Ένα snapshot είναι τοπική cache, όχι αποθηκευμένη βάση δεδομένων provider. Διατηρήστε το Evidence που επιστρέφεται και τα ρητά unknowns, αντί να θεωρείτε τις συναγόμενες διαδρομές ή το κείμενο decompiler ως αρχικό source.<sup>[[16]](#references)[[18]](#references)</sup>

Για entry points JavaScript/Electron που οδηγούν σε native add-ons, δείτε το [Electron Desktop Apps](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Scripted ανάλυση IDA και Ghidra με τοπική γέφυρα TCP

Το [IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) εκτελείται μέσα σε μια **ήδη ανοιχτή** βάση δεδομένων IDA ή σε ένα πρόγραμμα Ghidra CodeBrowser και επιτρέπει σε ένα ξεχωριστό script να υποβάλλει queries και να τροποποιεί αυτή τη βάση ανάλυσης. Εκτελέστε το `ID_Server.py` από το Python CLI του IDA (`import ID_Server`) ή το `Ghidra_Server.py` από το Script Manager του Ghidra. Το IDA κάνει bind στη διεύθυνση `127.0.0.1`, ξεκινώντας από τη θύρα `5073`, και ελέγχει τις επόμενες θύρες. Το τρέχον script του Ghidra ξεκινά από τη θύρα `5093` και δοκιμάζει δέκα θύρες, μέχρι και την `5102`. Το Java socket του κάνει bind στη διεύθυνση wildcard, όχι μόνο στο loopback. Ελέγξτε τη θύρα που εμφανίζει το instance πριν συνδεθείτε. Σε αντίθεση με έναν headless analyzer, αυτή η γέφυρα λειτουργεί στο πρόγραμμα που είναι ανοιχτό εκείνη τη στιγμή στο αντίστοιχο GUI instance.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Στείλτε **μία εντολή που τερματίζεται με newline ανά σύνδεση** και διαβάστε την απόκριση που τερματίζεται με newline. Το αποτέλεσμα είναι συνήθως JSON. Για παράδειγμα, αφού εντοπίσετε ένα imported API σχετικό με ένα input path, το `IMPORTXREF` εντοπίζει τα call sites του· στη συνέχεια, το `DECOMP_XREF` κάνει batch decompile στους callers μιας επιλεγμένης διεύθυνσης. Το `FUNC` εξετάζει μια συνάρτηση, ενώ το `PCODE` επιστρέφει την intermediate representation του decompiler. Χρησιμοποιήστε τη διεύθυνση από την ενεργή βάση δεδομένων, όχι μια διεύθυνση που αντιγράφηκε από binary με διαφορετικό rebase. Το παρακάτω παράδειγμα χρησιμοποιεί την προεπιλεγμένη θύρα του IDA· για το Ghidra, χρησιμοποιήστε τη θύρα που εμφανίζει το script του.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Το ίδιο κανάλι μπορεί να **αλλάξει τη βάση δεδομένων ανάλυσης**: τα `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` και `PATCH` τροποποιούν ονόματα, τύπους, ορισμούς δομών, όρια συναρτήσεων ή αποθηκευμένα bytes. Το `PATCH` είναι επεξεργασία της βάσης δεδομένων, **όχι** απόδειξη patch σε live process. Κανένας listener δεν τεκμηριώνει authentication. Το IDA είναι προσβάσιμο μόνο μέσω loopback, αλλά το Ghidra μπορεί να είναι προσβάσιμο μέσω διεπαφών δικτύου· περιορίστε την πρόσβαση στον listener του Ghidra όταν το χρησιμοποιείτε. Το `QUIT` σταματά οποιονδήποτε από τους δύο listeners, ενώ το IDA παρέχει επίσης το `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει χώρο για το **shellcode**, εμφανίζει τη **διεύθυνση μνήμης** του και διακόπτει προσωρινά την εκτέλεση.\
Συνδέστε έναν debugger, όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εμφανίζεται και συνεχίστε την εκτέλεση για να αποσφαλματώσετε το shellcode.

Η σελίδα github των releases περιέχει zip με τα μεταγλωττισμένα releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, απλώς **δημιουργήστε ένα project C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει χώρο για το shellcode και εισέρχεται σε έναν ατέρμονα βρόχο. Συνδέστε τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, διακόψτε την εκτέλεση μέσα στον βρόχο και προχωρήστε μέχρι την επόμενη κλήση που μεταφέρει την εκτέλεση στο shellcode που έχει δεσμευτεί.

![Debugger paused in jmp2it's infinite loop immediately before the call to the allocated shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it μέσα από τη σελίδα releases](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να κάνετε emulate το shellcode και να το εξετάσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να κάνετε «Open File» και «Open Shellcode». Στη δική μου περίπτωση, όταν άνοιξα το shellcode ως αρχείο, το αποσυμβόλισε σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Cutter showing different analysis results when opening the same bytes as a file or as shellcode](<../../images/image (562).png>)

Για να ξεκινήσει το emulation από το σημείο που θέλετε, ορίστε εκεί ένα bp και, απ' ό,τι φαίνεται, το Cutter θα ξεκινήσει αυτόματα το emulation από εκεί:

![Setting a breakpoint at the desired shellcode entry before starting Cutter emulation](<../../images/image (589).png>)

![Cutter emulator paused at the selected shellcode breakpoint](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Viewing the emulated shellcode stack in Cutter's hex dump](<../../images/image (186).png>)

### Αποφλοίωση obfuscation του shellcode και εύρεση των συναρτήσεων που εκτελεί

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

Το scDbg διαθέτει επίσης ένα γραφικό launcher, όπου μπορείτε να επιλέξετε τις επιθυμητές επιλογές και να εκτελέσετε το shellcode

![Γραφικό launcher του scDbg για την επιλογή των ρυθμίσεων emulation και tracing του shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** θα δημιουργήσει dump του τελικού shellcode, αν έχει γίνει κάποια αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του decoded shellcode). Το **start offset** μπορεί να φανεί χρήσιμο για την εκκίνηση του shellcode από συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων στο shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι οποιαδήποτε από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Disassembling using CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε την ακόλουθη συνταγή για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

Η obfuscation **Mixed Boolean-Arithmetic (MBA)** κρύβει απλές εκφράσεις όπως η `x + y` πίσω από τύπους που συνδυάζουν αριθμητικούς τελεστές (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες είναι συνήθως σωστές μόνο υπό **αριθμητική modular σταθερού πλάτους**, επομένως τα carries και τα overflows έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτό το είδος έκφρασης με γενικά εργαλεία άλγεβρας, μπορεί εύκολα να καταλήξετε σε λάθος αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον lifted κώδικα/την έξοδο IR/decompiler (`8/16/32/64` bits).
2. **Ταξινομήστε την έκφραση** πριν επιχειρήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα από bitwise άτομα
   - **Ημιγραμμική**: γραμμική έκφραση συν σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: περιλαμβάνει γινόμενα
   - **Μικτή**: γινόμενα και bitwise λογική είναι αλληλένδετα, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια μετατροπή** με τυχαίες δοκιμές ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, κρατήστε την αρχική έκφραση αντί να κάνετε εικασίες.

### Παρακάμψτε το flattened control flow με ένα στενό execution slice

Συχνά δεν είναι απαραίτητο να ανακτήσετε ολόκληρο το control-flow graph. Με control-flow flattening, opaque predicates, μεγάλους dispatchers ή κώδικα με έντονη χρήση MBA, ακολουθήστε τις αναφορές από τα κρυπτογραφημένα blobs και τα output buffers έως τη μικρότερη ρουτίνα που τα μετασχηματίζει. Έπειτα, αναπαράγετε μόνο αυτό το data-flow slice ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, εφόσον η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα executable και data sections, τα relocations και τις cross-references. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των bytes και το πλάτος των στοιχείων τους.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει το plaintext ή το output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις imported calls και την απαιτούμενη global state.
3. Μεταφέρετε μόνο αυτές τις πράξεις σε ένα μοντέλο Python σταθερού πλάτους. Αν το slice εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα με Unicorn, QEMU ή debugger και κάντε hook τις άσχετες imports, αντί να προσομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι το output από το παρεχόμενο binary: αφαιρέστε τα σιωπηρά fallbacks, αναζητήστε ενσωματωμένες απαντήσεις και δοκιμάστε τον σε builds που δεν έχετε ξαναδεί, με αλλαγμένα strings, keys, identifiers, layouts και obfuscation seeds.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι οι εξής:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Εντοπισμός MBA expressions που είναι μεταμφιεσμένες σταθερές

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

Κράτησε την τελική μάσκα, επειδή η αρχική πρόσθεση έχει αναδίπλωση στο πλάτος του byte. Για ευρύτερο πεδίο τιμών, ρώτησε έναν SMT solver αν είναι ικανοποιήσιμη η συνθήκη `f(x1) != f(x2)` για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει αμεταβλητότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνώριση αποκωδικοποίησης που εξαρτάται από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας decoder μπορεί να ενσωματώσει το αποτέλεσμα ενός αισθητήρα σε ένα bit του κλειδιού, σε μια σταθερά opaque predicate ή στην κατάσταση ενός flattened dispatcher, να συνεχίσει κανονικά και να παράγει εύλογο αλλά λανθασμένο plaintext σε έναν emulator. Επομένως, δεν αρκεί η επιδιόρθωση μόνο των ορατών κλάδων αποτυχίας· ανίχνευσε τις εξαρτήσεις δεδομένων από τις περιβαλλοντικές διερευνήσεις έως την κατάσταση του decoder, σύγκρινε το ίδιο τμήμα σε αυθεντική συσκευή και emulator και έλεγξε πώς η επιβολή κάθε αποτελέσματος αισθητήρα αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένα πρακτικό εργαλείο απλοποίησης MBA για ανάλυση malware και reverse engineering προστατευμένων binary. Ταξινομεί την έκφραση και την περνά από εξειδικευμένες ροές επεξεργασίας, αντί να εφαρμόζει ένα γενικό πέρασμα επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean εισόδους, εξάγει μια υπογραφή και δοκιμάζει παράλληλα διάφορες μεθόδους ανάκτησης, όπως pattern matching, μετατροπή ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα atoms με σταθερές μάσκες ανακατασκευάζονται με ανακατασκευή διαμερισμένη σε bit, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αναλύονται σε πυρήνες και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε προσωρινές μεταβλητές πριν απλοποιηθεί η εξωτερική σχέση.

Παράδειγμα μικτής ταυτότητας που αξίζει συχνά να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να συμπτυχθεί σε:

```c
x * y
```

### Σημειώσεις για reverse engineering

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιείτε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή στενούς registers.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, συμβουλευτείτε τις τοπικές σημειώσεις για το Z3 εδώ:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με έντονη χρήση MBA πριν από μεταγενέστερα analysis passes.
- Τα μη υποστηριζόμενα carry-sensitive mixed-domain residuals πρέπει να θεωρούνται ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να αναλύσετε χειροκίνητα τη διαδρομή του carry.

## Ανάκτηση control-flow flattening με XOR-state

Ένας flattener τύπου OLLVM μπορεί να διατηρεί την κατάσταση του τρέχοντος basic block σε δύο registers των 64 bit και να την ανασυνθέτει με XOR σε έναν dispatcher. Κάθε αρχικό block γράφει το ζεύγος για την επόμενη κατάστασή του και επιστρέφει στον dispatcher. Ένα conditional block μπορεί να χρησιμοποιεί `CMOVcc` για να αντικαθιστά το ένα μισό του ζεύγους σύμφωνα με τα CPU flags, οπότε αν ακολουθείτε μόνο τις ορατές εντολές διακλάδωσης, δεν εντοπίζετε τους δύο successors. Σε αντίθεση με έναν dispatcher με indirect jump, αυτή η μορφή μπορεί να χρησιμοποιεί direct back-edges παντού.<sup>[[19]](#references)[[20]](#references)</sup>

Για να ανακτήσετε το γράφημα, εντοπίστε το δέντρο συγκρίσεων του dispatcher και τους δύο state registers, αντιστοιχίστε κάθε συγκρινόμενη XOR state στο block-στόχο της και, στη συνέχεια, εντοπίστε τις εγγραφές στο ζεύγος registers που φτάνουν σε κάθε αρχικό block. Για conditional writes, συμπεριλάβετε την εντολή που ορίζει τα flags και τα δύο αποτελέσματα του `CMOVcc`. Αντικαταστήστε την έξοδο κάθε block προς τον dispatcher με τον άμεσο successor ή το conditional branch που επιλύσατε· έτσι ο dispatcher καθίσταται unreachable χωρίς να χρειαστεί patching του binary. Αυτή είναι μια προσέγγιση πλήρους CFG· αν σας ενδιαφέρει μόνο ένας decoder, η [narrow execution-slice workflow](#bypass-flattened-control-flow-with-a-narrow-execution-slice) παραπάνω μπορεί να είναι ταχύτερη.<sup>[[19]](#references)[[20]](#references)</sup>

Το [DispatchThis](https://github.com/YungBinary/DispatchThis) αυτοματοποιεί αυτή τη μορφή στο Binary Ninja. Αντιγράψτε το `plugins/DispatchThis` στον κατάλογο plugins χρήστη του Binary Ninja και κάντε επανεκκίνηση. Στην επηρεαζόμενη συνάρτηση, ανοίξτε το **Function Settings** και επιλέξτε `OLLVM_XOR_64`· αν η ανάλυση δεν ξεκινήσει, επιλέξτε **Analysis → Reanalyze All Functions**. Αυτή η λειτουργία ξαναγράφει τις ακμές control-flow του MLIL, όχι τα bytes του αρχείου, και δεν χρειάζεται Z3 ή τον indirect-jump resolver. Έχει δοκιμαστεί στο Binary Ninja 5.3.9757+· δεν αφαιρεί τις νεκρές εγγραφές κατάστασης ανά block, γι’ αυτό μην τις εκλάβετε λανθασμένα ως εναπομείνασες ενεργές μεταβάσεις.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες σε `mov` και χρησιμοποιεί χειρισμό σημάτων/εξαιρέσεων για να τροποποιεί τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να αποσυσκοτίσει το αποτέλεσμα. Έχει αρκετές εξαρτήσεις.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε σε **CTF, αυτό το workaround για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμο: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **σημείο εισόδου**, αναζητήστε στις συναρτήσεις το `::main`, όπως εδώ:

![Εύρεση του σημείου εισόδου Rust στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για διπλή άνω και κάτω τελεία main](<../../images/image (1080).png>)

Σε αυτή την περίπτωση το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα συνάρτηση main.\
Έχοντας τα **ονόματα** των **συναρτήσεων** που καλούνται, αναζητήστε τα στο **Διαδίκτυο** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση συμβολοσειρών Rust από firmware ELF

Στα binary **Rust ELF**, πολλές στατικές συμβολοσειρές δεν αναφέρονται μέσω δεικτών με τερματισμό NUL, όπως στη C. Μια συνηθισμένη διάταξη της `rustc` είναι ένα **tuple δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, που δείχνει στο πραγματικό blob συμβολοσειράς που είναι αποθηκευμένο στο **`.rodata`**:

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
3. Αντιμετωπίστε κάθε τιμή που βρίσκεται εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη συμβολοσειράς.
4. Αντιμετωπίστε την επόμενη λέξη ως υποψήφιο μήκος.
5. Εφαρμόστε φίλτρα εγκυρότητας (για παράδειγμα, κρατήστε μήκη μεταξύ **4** και **100** byte).
6. Διαβάστε ακριβώς `length` byte από το `.rodata` αντί να κάνετε σάρωση μέχρι το `0x00`.

Ελάχιστη λογική extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες συμβολοσειρές Rust συχνά αποκαλύπτουν **HTTP routes, ονόματα RPC, μηνύματα log, assertions, ονόματα αρχείων, κλειδιά config, handlers εντολών και λογική σχετική με το auth**.

Αν το Ghidra δεν εντοπίσει αυτές τις συμβολοσειρές, εκτελέστε ένα προσαρμοσμένο script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στα offsets του `.rodata` στα οποία παραπέμπουν. Τα εργαλεία `rust-strings` και `RustStrings.py` που δημοσίευσε η Pen Test Partners είναι καλές αναφορές για την προσαρμογή της ιδέας σε άλλα **μεγέθη λέξεων, endianness και διατάξεις section**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries που έχουν μεταγλωττιστεί με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειαστεί να κάνετε reverse ένα binary Delphi, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin θα εκτελέσει το binary και θα επιλύσει δυναμικά τα ονόματα των συναρτήσεων κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη συνάρτηση που καλείται από αυτό το κουμπί.

## Golang

Για συνηθισμένα Go binaries, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει runtime δομές και να βελτιώσει τα ονόματα των συναρτήσεων στο IDA. Φορτώστε το Python plugin με **Alt+F7**.

Αν χρειαστεί να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

### Ανάκτηση metadata χωρίς τον πίνακα συμβόλων

Ένα stripped εκτελέσιμο Go εξακολουθεί να χρειάζεται runtime metadata για να αντιστοιχίσει τους program counters στις συναρτήσεις. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει δομές όπως τα `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Με αυτόν τον τρόπο μπορεί να ανακτήσει όρια συναρτήσεων, ονόματα, διαδρομές πηγαίου κώδικα, τύπους και λεπτομέρειες του build, χωρίς να βασίζεται στον συμβατικό πίνακα συμβόλων.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές λειτουργικές, αντικαθιστώντας παράλληλα τα ονόματα που ανακτήθηκαν. Το Garble, για παράδειγμα, κατακερματίζει τα αναγνωριστικά και τις διαδρομές πακέτων και αφαιρεί πληροφορίες build, module και debug.<sup>[[12]](#references)</sup> Το obfuscated token ενός πακέτου πρέπει να παραμένει σταθερό σε όλες τις συναρτήσεις αυτού του πακέτου. Ομαδοποιήστε τις συναρτήσεις με βάση το επαναλαμβανόμενο token, συμπεράνετε ένα πακέτο από τις συναρτήσεις που καλεί, τις συμβολοσειρές και τα API του και, στη συνέχεια, εφαρμόστε την ετικέτα αυτού του πακέτου σε ολόκληρη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή συμβόλων runtime με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση γραφημάτων ροής ελέγχου (CFG). Ακολουθήστε αυτήν τη σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Εντοπίστε την έκδοση του compiler.** Δοκιμάστε πρώτα τα `BuildInfo` και τις ενσωματωμένες συμβολοσειρές έκδοσης. Αν ο obfuscator τις αφαίρεσε, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtimes αναφοράς συγκεκριμένων εκδόσεων. Στις δοκιμές της Volexity, περίπου το `2%` του runtime αρκούσε για να διακριθούν οι κύριες εκδόσεις Go. Θεωρήστε το αυτό εμπειρική βελτιστοποίηση και όχι καθολικό όριο.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε αντίστοιχες αναφορές.** Δημιουργήστε καθαρά binaries για την εντοπισμένη έκδοση Go, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση του toolchain περιορίζει τις διαφορές CFG που δημιουργεί ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και παράγει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση βασικών blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής αξιοπιστίας συνδέουν τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Οι ασθενέστερες αντιστοιχίσεις μπορούν και πάλι να προσδιορίσουν ένα πακέτο ή module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επαληθεύστε και εισαγάγετε.** Επιβεβαιώστε τα προτεινόμενα ονόματα εξετάζοντας τις σχέσεις κλήσεων, τις σταθερές, τις συμβολοσειρές και τις παρενέργειες. Στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin GoResolver για IDA ή Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Το προεπιλεγμένο όριο σημαντικής αντιστοίχισης είναι `0.9`. Οι διακόπτες `--extract` και `--graph` μπορούν να απομονώσουν οποιοδήποτε από τα δύο στάδια, ενώ η προεπιλεγμένη λειτουργία εκτελεί και τα δύο, επειδή τα ανακτημένα runtime metadata και τα στοιχεία CFG συμπληρώνουν το ένα το άλλο.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, οι ρυθμίσεις build, η αρχιτεκτονική και οι διαφορές στις εκδόσεις των βιβλιοθηκών μπορούν να αλλάξουν τη μορφή του γράφου, επομένως διατηρήστε τις συναρτήσεις που δεν έχουν επιλυθεί αντί να επιβάλλετε ονόματα με χαμηλή βεβαιότητα.<sup>[[13]](#references)</sup>

### Ανάκτηση του πίνακα συμβολοσειρών της Go

Τα binaries της Go τοποθετούν τα bytes των συμβολοσειρών από κάθε συνδεδεμένο package σε έναν ενιαίο, συνεχόμενο πίνακα. Οι εγγραφές δεν τερματίζονται με NUL και οι runtime δομές δεν αποκαλύπτουν τη βάση ή το μέγεθος του πίνακα. Ωστόσο, ο compiler ταξινομεί τις εγγραφές πρώτα κατά μήκος και έπειτα αλφαβητικά, σε όλα τα λειτουργικά συστήματα και τις αρχιτεκτονικές. Αφού βρει μία εγγραφή, ένας analyst μπορεί επομένως να διατρέξει τις γειτονικές εγγραφές και να χρησιμοποιήσει τις διασταυρούμενες αναφορές δεδομένων για να συσχετίσει συμβολοσειρές με κώδικα.<sup>[[15]](#references)</sup>

Το [GoStringExtractor](https://github.com/volexity/GoStringExtractor) αυτοματοποιεί αυτή τη ροή εργασίας στα IDA Pro και Ghidra. Περιμένετε πρώτα να ολοκληρωθεί η αυτόματη ανάλυση, επειδή το plugin βασίζεται στις διασταυρούμενες αναφορές του τμήματος δεδομένων. Το προεπιλεγμένο σημείο αναφοράς του είναι η runtime συμβολοσειρά `entersyscall`. Έπειτα μπορεί να σαρώσει και προς τις δύο κατευθύνσεις, να ορίσει τις ανακτημένες συμβολοσειρές στη βάση δεδομένων και να εξαγάγει μια αντιστοίχιση JSON από συμβολοσειρές σε συναρτήσεις που τις αναφέρουν.<sup>[[14]](#references)</sup>

Φιλτράρετε την αναφορά με βάση το package της συνάρτησης που κάνει την αναφορά, ώστε να διαχωρίσετε τον κώδικα της εφαρμογής ή του malware από τον περιττό θόρυβο των συνδεδεμένων βιβλιοθηκών. Αυτή η τεχνική δεν μπορεί να ανακτήσει literals που έχουν καταστραφεί από obfuscation, όπως με τον μετασχηματισμό `-literals` του Garble. Μπορεί, ωστόσο, να οργανώσει runtime συμβολοσειρές που παραμένουν χωρίς obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Ανάκτηση τύπων του Go runtime

Η Go ενσωματώνει πληροφορίες τύπων runtime που χρησιμοποιούνται από λειτουργίες όπως το garbage collection. Όταν αφαιρούνται τα build information ή ο disassembler δεν αναλύει αυτά τα metadata, οι εντολές μπορεί να φαίνεται ότι φορτώνουν αυθαίρετες διευθύνσεις δεδομένων, ενώ η περιοχή-στόχος παραμένει χωρίς τύπο. Η ανάκτηση των metadata μετατρέπει αυτές τις διευθύνσεις σε ευανάγνωστες αναφορές τύπων και διευκολύνει την κατανόηση των δυνατοτήτων των packages.<sup>[[15]](#references)</sup>

Το [GoResolver](https://github.com/volexity/GoResolver) μπορεί να εξαγάγει σύμβολα και να αναλύσει τους runtime τύπους σε μια αναφορά JSON. Το τρέχον CLI χρησιμοποιεί την υποεντολή `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Η επιλογή `-y`/`--types` ενεργοποιεί την ανάλυση τύπων. Εισαγάγετε την αναφορά με το πρόσθετο του GoResolver για IDA Pro ή Ghidra, ώστε να ορίσετε τους ανακτημένους τύπους και να εφαρμόσετε τις αναφορές τους στη βάση δεδομένων ανάλυσης. Στη μορφή αναφοράς που εισήχθη με αυτήν τη δυνατότητα, αν παραλείψετε το `-y`, τα πεδία RTTI address και recovered-types παραμένουν null.<sup>[[10]](#references)[[15]](#references)</sup>

Το GoResolver υποστηρίζει δείγματα PE, ELF και Mach-O για x86, AMD64, ARM και ARM64, επομένως η ίδια ροή εργασίας ισχύει για Go binaries από Windows, Linux και macOS.<sup>[[10]](#references)</sup>

## Μεταγλωττισμένη Python

Σε αυτήν τη σελίδα μπορείτε να δείτε πώς να ανακτήσετε τον κώδικα Python από ένα μεταγλωττισμένο binary Python τύπου ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διαφορετικά εργαλεία για να το **προσομοιώσετε** και να κάνετε **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με γραφικό περιβάλλον
- [**mgba** ](https://mgba.io)- Περιλαμβάνει CLI debugger
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Πρόσθετο Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Πρόσθετο Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στην επιλογή _**Επιλογές --> Ρύθμιση προσομοίωσης --> Στοιχεία ελέγχου**_** ** μπορείτε να δείτε πώς να πατήσετε τα **κουμπιά** του Game Boy Advance

![Ρύθμιση στοιχείων ελέγχου no$gba που εμφανίζει τις αντιστοιχίσεις κουμπιών του Game Boy Advance](<../../images/image (581).png>)

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

Λοιπόν, σε αυτού του είδους τα προγράμματα, το ενδιαφέρον είναι **πώς το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνηθισμένη συνάρτηση: **KEYINPUT**.

![Προβολή του Ghidra ενός δυαδικού αρχείου GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από ορισμένες αρχικές λειτουργίες (χωρίς καμία σημασία):

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **last Keys** και δεν είναι το τρέχον πλήκτρο· αυτό σημαίνει ότι αφήνουμε ένα κουμπί (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

- Αρχικά, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): στην πρόκληση, αυτό το κουμπί καθαρίζει την οθόνη
- Έπειτα, συγκρίνεται με την τιμή **8** (κουμπί **START**): σε αυτή την πρόκληση, αυτή η διαδρομή ελέγχει αν ο κωδικός που εισήχθη είναι έγκυρος.
  - Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων αθροίζονται στην `DAT_030000d8`.

Έτσι, σε αυτή την πρόκληση, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό μήκους μικρότερου από 8, του οποίου το άθροισμα να είναι 0xf3.**

**Αναφορά για αυτό το tutorial:** [αρχειοθετημένη παρουσίαση λύσης της πρόκλησης Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Αποσυσκότιση δυαδικών αρχείων)

## References

- [1] [Απλοποίηση της MBA obfuscation με CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Αποθετήριο CoBRA της Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Αποκωδικοποίηση συμβολοσειρών Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - συμβολοσειρές Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial reverse engineering για GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετώπιση του reverse engineering με τη βοήθεια AI ή τουλάχιστον η προσπάθεια](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση για τη σύγκριση γραφημάτων ροής ελέγχου με βάση την αντιστοίχιση βασικών blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Αποθετήριο GoResolver της Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας γραφημάτων ροής ελέγχου για την αυτόματη αποσυσκότιση δυαδικών αρχείων Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Αποθετήριο GoStringExtractor της Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ενημερώσεις στα εργαλεία Golang της Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Ανάλυση managed code του REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Οδηγός CLI και τεκμηρίωσης του REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Ροή εργασίας για την αποδίπλωση της ροής ελέγχου στο Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Εισβολή μέσω zero-day στο PaperCut MF, Java Loader, Web Shell και AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README του IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Υλοποίηση διακομιστή bridge για IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Υλοποίηση διακομιστή bridge για Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - Η InetSocketAddress(int) κάνει bind στη διεύθυνση wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: toolkit reverse engineering για Godot](https://github.com/figurophobia/gore)
- [26] [Υλοποίηση ανάκτησης κλειδιού του gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Μορφή κρυπτογραφημένου blob του gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Υλοποίηση εντολών και ανάκτησης του gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
