# Εργαλεία Reversing και βασικές μέθοδοι

{{#include ../../banners/hacktricks-training.md}}

## Εργαλεία reversing βασισμένα σε ImGui

Λογισμικό:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Αυτοματοποίηση WinDbg σε user-mode

{{#ref}}
windbg-automation.md
{{#endref}}

## Ροή ελέγχου Windows με βάση τις εξαιρέσεις

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Αποσφαλμάτωση πυρήνα των Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Απομεταγλωττιστής Wasm / μεταγλωττιστής Wat

Online:

- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) για **απομεταγλώττιση** από wasm (δυαδικό) σε wat (ευανάγνωστο κείμενο)
- Χρησιμοποιήστε το [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) για **μεταγλώττιση** από wat σε wasm
- Μπορείτε επίσης να δοκιμάσετε το [web-wasmdec](https://wwwg.github.io/web-wasmdec/) για απομεταγλώττιση.

Λογισμικό:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode που έχει αποθηκευτεί στην cache του Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Virtualized payloads και προσαρμοσμένες VM

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Απομεταγλωττιστής .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

Το dotPeek είναι ένας απομεταγλωττιστής που **απομεταγλωττίζει και εξετάζει πολλαπλές μορφές**, όπως **βιβλιοθήκες** (.dll), **αρχεία μεταδεδομένων Windows** (.winmd) και **εκτελέσιμα** (.exe). Μετά την απομεταγλώττιση, μια assembly μπορεί να αποθηκευτεί ως έργο Visual Studio (.csproj).

Το πλεονέκτημα είναι ότι, αν χρειάζεται να ανακτηθεί χαμένος πηγαίος κώδικας από μια παλαιότερη assembly, αυτή η ενέργεια μπορεί να εξοικονομήσει χρόνο. Επιπλέον, το dotPeek παρέχει εύχρηστη πλοήγηση στον απομεταγλωττισμένο κώδικα, καθιστώντας το ένα από τα ιδανικά εργαλεία για **ανάλυση αλγορίθμων Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Με ένα ολοκληρωμένο μοντέλο πρόσθετων και ένα API που επεκτείνει το εργαλείο ώστε να καλύπτει ακριβώς τις ανάγκες σας, το .NET Reflector εξοικονομεί χρόνο και απλοποιεί την ανάπτυξη. Ας δούμε το ευρύ φάσμα υπηρεσιών reverse engineering που παρέχει αυτό το εργαλείο:

- Παρέχει εικόνα της ροής των δεδομένων μέσα από μια βιβλιοθήκη ή ένα στοιχείο
- Παρέχει εικόνα της υλοποίησης και της χρήσης των γλωσσών και των frameworks του .NET
- Εντοπίζει μη τεκμηριωμένη και μη εκτεθειμένη λειτουργικότητα, ώστε να αξιοποιείτε καλύτερα τα API και τις τεχνολογίες που χρησιμοποιούνται.
- Εντοπίζει εξαρτήσεις και διαφορετικές assemblies
- Εντοπίζει την ακριβή θέση των σφαλμάτων στον κώδικά σας, σε στοιχεία τρίτων και σε βιβλιοθήκες.
- Κάνει debugging στον πηγαίο κώδικα όλου του .NET κώδικα με τον οποίο εργάζεστε.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Μπορείτε να το χρησιμοποιήσετε σε οποιοδήποτε OS (μπορείτε να το εγκαταστήσετε απευθείας από το VSCode, χωρίς να χρειάζεται να κατεβάσετε το git. Κάντε κλικ στο **Extensions** και **αναζητήστε ILSpy**).\
Αν χρειάζεται να **απομεταγλωττίσετε**, να **τροποποιήσετε** και να **μεταγλωττίσετε ξανά**, μπορείτε να χρησιμοποιήσετε το [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) ή ένα fork του που συντηρείται ενεργά, το [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Δεξί κλικ -> Modify Method** για να αλλάξετε κάτι μέσα σε μια συνάρτηση).

### Επιθεώρηση managed κώδικα χωρίς εκτέλεση με REA

Το **REA** μπορεί να επιθεωρεί μεταδεδομένα PE/CLI και CIL χωρίς να φορτώνει την assembly. Ξεκινήστε με την ταυτότητα του artifact και, στη συνέχεια, επιθεωρήστε τα μέλη και τα δηλωμένα όρια native κώδικα· αυτό είναι χρήσιμο κατά την εξέταση ύποπτων κλήσεων πριν χρησιμοποιήσετε απομεταγλωττιστή ή εκτελέσετε το πρόγραμμα.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Για το version diffing, το `compare_managed_members` χρησιμοποιεί ακατέργαστη ταυτότητα CIL/signature και fingerprints αποκωδικοποιημένων instructions, αντί να θεωρεί τα metadata tokens σταθερά μεταξύ builds. Μια δήλωση P/Invoke δεν αποδεικνύει ότι εκτελέστηκε native code· το `verify_managed_native_boundaries` χρειάζεται αντίστοιχο native export ή function Evidence για να ελέγξει αυτό το όριο. Διατηρήστε το artifact digest, το MVID και τα unresolved mappings μαζί με το αποτέλεσμα.<sup>[[17]](#references)</sup>

### Καταγραφή DNSpy

Για να κάνετε το **DNSpy να καταγράφει κάποιες πληροφορίες σε ένα αρχείο**, μπορείτε να χρησιμοποιήσετε αυτό το snippet:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### DNSpy Debugging

Για να κάνετε debugging σε κώδικα με το DNSpy, πρέπει να:

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

Και κάντε κλικ στο **compile**:

![DNSpy Logging - DNSpy Debugging: Και κάντε κλικ στο compile](<../../images/image (314) (1).png>)

Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, αποθηκεύστε το νέο αρχείο μέσω File Save module](<../../images/image (602).png>)

Αυτό είναι απαραίτητο, επειδή αν δεν το κάνετε, κατά το **runtime** θα εφαρμοστούν αρκετές **βελτιστοποιήσεις** στον κώδικα και υπάρχει πιθανότητα, κατά το debugging, να μην ενεργοποιηθεί ποτέ ένα **break-point** ή να μην υπάρχουν κάποιες **μεταβλητές**.

Στη συνέχεια, αν η εφαρμογή .NET εκτελείται από το **IIS**, μπορείτε να την **επανεκκινήσετε** με:

```
iisreset /noforce
```

Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα **Debug** επιλέξτε **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, για να ξεκινήσετε το debugging, κλείστε όλα τα ανοιχτά αρχεία και από την καρτέλα Debug επιλέξτε Attach to Process](<../../images/image (318).png>)

Στη συνέχεια, επιλέξτε **w3wp.exe** για να συνδεθείτε στον **IIS server** και κάντε κλικ στο **attach**:

![DNSpy Logging - DNSpy Debugging: Στη συνέχεια, επιλέξτε w3wp.exe για να συνδεθείτε στον IIS server και κάντε κλικ στο attach](<../../images/image (113).png>)

Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλες τις μονάδες. Αρχικά, κάντε κλικ στο _Debug >> Break All_ και, στη συνέχεια, στο _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλες τις μονάδες. Αρχικά, κάντε κλικ στο Debug Break All και, στη συνέχεια, στο Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Τώρα που κάνουμε debugging στη διεργασία, ήρθε η ώρα να τη διακόψουμε και να φορτώσουμε όλες τις μονάδες. Αρχικά, κάντε κλικ στο Debug Break All και, στη συνέχεια, στο Debug Windows Modules](<../../images/image (834).png>)

Κάντε κλικ σε οποιαδήποτε μονάδα στο **Modules** και επιλέξτε **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Κάντε κλικ σε οποιαδήποτε μονάδα στο Modules και επιλέξτε Open All Modules](<../../images/image (922).png>)

Κάντε δεξί κλικ σε οποιαδήποτε μονάδα στο **Assembly Explorer** και επιλέξτε **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Κάντε δεξί κλικ σε οποιαδήποτε μονάδα στο Assembly Explorer και επιλέξτε Sort Assemblies](<../../images/image (339).png>)

## Απομεταγλωττιστής Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLL

### Χρήση του IDA

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- Επιλέξτε το debugger **Windbg**
- Επιλέξτε "**Suspend on library load/unload**"

![Debugging DLLs - Χρήση του IDA: Επιλέξτε " Suspend on library load/unload "](<../../images/image (868).png>)

- Διαμορφώστε τις **παραμέτρους** εκτέλεσης, ορίζοντας τη **διαδρομή προς το DLL** και τη συνάρτηση που θέλετε να καλέσετε:

![Debugging DLLs - Χρήση του IDA: Διαμορφώστε τις παραμέτρους εκτέλεσης, ορίζοντας τη διαδρομή προς το DLL και τη συνάρτηση που θέλετε να καλέσετε](<../../images/image (704).png>)

Στη συνέχεια, όταν ξεκινήσετε το debugging, **η εκτέλεση θα διακόπτεται κατά τη φόρτωση κάθε DLL**. Επομένως, όταν το rundll32 φορτώσει το DLL σας, η εκτέλεση θα διακοπεί.

Αυτή η μέθοδος διακόπτει την εκτέλεση σε συμβάντα φόρτωσης μονάδων, αλλά η μετάβαση στο entry point του φορτωμένου DLL είναι λιγότερο άμεση απ' ό,τι με τη ροή εργασίας του x64dbg παρακάτω.

### Χρήση των x64dbg/x32dbg

- **Φορτώστε το rundll32** (64bits στο C:\Windows\System32\rundll32.exe και 32 bits στο C:\Windows\SysWOW64\rundll32.exe)
- **Αλλάξτε τη γραμμή εντολών** ( _File --> Change Command Line_ ) και ορίστε τη διαδρομή του dll και τη συνάρτηση που θέλετε να καλέσετε, για παράδειγμα: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Αλλάξτε τη ρύθμιση _Options --> Settings_ και επιλέξτε "**DLL Entry**".
- Στη συνέχεια, **ξεκινήστε την εκτέλεση**. Το debugger θα διακόπτεται σε κάθε dll main και κάποια στιγμή θα **διακοπεί στο Entry του δικού σας dll**. Από εκεί, απλώς αναζητήστε τα σημεία στα οποία θέλετε να ορίσετε breakpoint.

Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε **σε ποιον κώδικα βρίσκεστε** κοιτάζοντας **στο επάνω μέρος του παραθύρου του win64dbg**:

![Χρήση του IDA - Χρήση των x64dbg/x32dbg: Σημειώστε ότι όταν η εκτέλεση διακόπτεται για οποιονδήποτε λόγο στο win64dbg, μπορείτε να δείτε σε ποιον κώδικα βρίσκεστε κοιτάζοντας στο επάνω μέρος του παραθύρου του win64dbg](<../../images/image (842).png>)

Αυτή η ένδειξη επιβεβαιώνει ότι η εκτέλεση έχει διακοπεί μέσα στο DLL που θέλετε να κάνετε debug.

## Εφαρμογές GUI / Βιντεοπαιχνίδια

Το [**Cheat Engine**](https://www.cheatengine.org/downloads.php) είναι ένα χρήσιμο πρόγραμμα για να εντοπίζετε πού αποθηκεύονται σημαντικές τιμές στη μνήμη ενός παιχνιδιού που εκτελείται και να τις αλλάζετε. Περισσότερες πληροφορίες στο:


{{#ref}}
cheat-engine.md
{{#endref}}

Το [**PiNCE**](https://github.com/korcankaraokcu/PINCE) είναι ένα front-end/εργαλείο reverse engineering για το GNU Project Debugger (GDB), με έμφαση στα παιχνίδια. Ωστόσο, μπορεί να χρησιμοποιηθεί για οποιαδήποτε εργασία σχετική με το reverse engineering.

Το [**Decompiler Explorer**](https://dogbolt.org/) είναι ένα web front-end για διάφορους decompilers. Αυτή η διαδικτυακή υπηρεσία σάς επιτρέπει να συγκρίνετε τα αποτελέσματα διαφορετικών decompilers σε μικρά εκτελέσιμα αρχεία.

### Αποκρυπτογράφηση Godot PCK και ανάκτηση project

Για ένα διανεμόμενο παιχνίδι Godot, εντοπίστε το PCK σε ένα αυτόνομο αρχείο `.pck`, σε ένα προσαρτημένο ή ενσωματωμένο πακέτο εκτελέσιμου αρχείου ή στον κατάλογο `assets` ενός APK. Το [gore](https://github.com/figurophobia/gore) μπορεί να επιθεωρήσει και να εξαγάγει το πακέτο, ενώ για την πλήρη ανακατασκευή των scripts και των resources απαιτούνται τα GDRE Tools (το `gore setup` τα εγκαθιστά ή μπορείτε να χρησιμοποιήσετε το `--gdre`). Για αυτή τη ροή εργασίας, το εργαλείο υποστηρίζει τις μορφές Godot 4.x PCK v2–v4. Μπορεί να εντοπίσει κεφαλίδες v1, αλλά απαιτεί να δοθεί κλειδί για την v1.<sup>[[25]](#references)</sup>

Η αυτόματη ανάκτηση κλειδιού απαιτεί έναν κρυπτογραφημένο πίνακα αρχείων. Αν είναι κρυπτογραφημένα μόνο τα περιεχόμενα των αρχείων, δώστε ένα γνωστό κλειδί. Η αποτυχία ανάκτησης δεν αποδεικνύει ότι ένα πακέτο δεν είναι κρυπτογραφημένο.<sup>[[28]](#references)</sup>

Η αναζήτηση κλειδιού **δεν** είναι επίθεση στον χώρο κλειδιών AES-256. Ένας κρυπτογραφημένος πίνακας αρχείων εκθέτει το MD5 του αποκρυπτογραφημένου κειμένου, το μήκος του αποκρυπτογραφημένου κειμένου, το IV και το κρυπτοκείμενο AES-256-CFB.<sup>[[27]](#references)</sup> Το `gore` ελέγχει παράθυρα 32 bytes από το εκτελέσιμο αρχείο του παιχνιδιού ή από γειτονικά αρχεία ως υποψήφια κλειδιά. Φιλτράρει τους υποψηφίους με βάση το εύλογο μήκος και το πρόθεμα μιας αποκρυπτογραφημένης διαδρομής και, στη συνέχεια, επιβεβαιώνει τα ευρήματα της δυαδικής σάρωσης αποκρυπτογραφώντας ολόκληρο τον πίνακα και ελέγχοντας το MD5 του.<sup>[[26]](#references)[[28]](#references)</sup> Αρχικά αναζητά δεδομένα στις αρχικοποιημένες ενότητες δεδομένων PE/ELF και, αν δεν βρει αποτέλεσμα, σαρώνει ολόκληρο το αρχείο. Με το `--scan` προστίθενται και άλλα υποψήφια αρχεία.<sup>[[28]](#references)</sup>

Αν δεν βρεθεί ενσωματωμένο κλειδί, δοκιμάζεται μια μικρή ενσωματωμένη λίστα κωδικών πρόσβασης. Με το `--wordlist` μπορείτε να δώσετε άλλους υποψηφίους. Κάθε κωδικός πρόσβασης δοκιμάζεται ως αναπαράσταση κλειδιού που προκύπτει από τον κωδικό πρόσβασης της engine, ως κυριολεκτική τιμή με συμπλήρωση μηδενικών ή ως κλειδί 64 χαρακτήρων σε δεκαεξαδική μορφή. Σε αντίθεση με τα ευρήματα της δυαδικής σάρωσης, σε αυτήν την υλοποίηση τα ευρήματα της wordlist περνούν μόνο από το φίλτρο δομής διαδρομών. Επιβεβαιώστε τα ανοίγοντας το πακέτο και επικυρώνοντας τα εξαγόμενα assets.<sup>[[26]](#references)[[28]](#references)</sup>

Όταν το artifact του παιχνιδιού είναι διαθέσιμο τοπικά, επιλέξτε το στάδιο που χρειάζεστε για την ανάλυση. Η εντολή `recover` καλεί τα GDRE για να ανακατασκευάσει ένα project που μπορεί να ανοιχτεί, ενώ η `extract` απλώς αποσυσκευάζει τα ακατέργαστα αρχεία. Η `key` εμφανίζει ένα υποψήφιο κλειδί για χρήση με άλλο εργαλείο.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Εγγενής διερεύνηση με τεκμηρίωση μέσω REA

Το **REA** εκθέτει την ανάλυση των Hopper, Ghidra και IDA μέσω CLI και MCP. Απαιτεί Node.js 22.x (τουλάχιστον 22.19), 24.x (τουλάχιστον 24.11) ή 26+, καθώς και npm. Ρυθμίστε πρώτα έναν υπάρχοντα εγγενή πάροχο· ελέγξτε το `rea providers --json` και επιλέξτε ρητά έναν πάροχο, αν περισσότεροι από ένας υποστηρίζουν τον στόχο. Χρησιμοποιήστε παρακάτω ένα παρατηρημένο όνομα συνάρτησης ή μια διεύθυνση από την απογραφή, στη θέση του `0x1000`.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Ξεκινήστε από μια συμβολοσειρά χαρακτηριστικού ή ένα σύμβολο, ακολουθήστε τις αναφορές και τους callers και, στη συνέχεια, εξετάστε τον φάκελο της επιλεγμένης συνάρτησης και το pseudocode με `rea decompile`. Το REA συνδέει μια συνεδρία με τον επιλεγμένο provider, αντί να τον αντικαθιστά σιωπηρά μετά από αποτυχία. Για επαναλήψιμα queries, το `--snapshot PATH` επαναχρησιμοποιεί μόνο bytes artifacts, provider, ρυθμίσεις, λειτουργία και παραμέτρους που ταιριάζουν· ένα snapshot είναι τοπική cache, όχι αποθηκευμένη βάση δεδομένων provider. Διατηρήστε το Evidence που επιστρέφεται και τα ρητά άγνωστα στοιχεία, αντί να θεωρείτε ότι οι συναγόμενες διαδρομές ή το κείμενο του decompiler είναι αρχικός πηγαίος κώδικας.<sup>[[16]](#references)[[18]](#references)</sup>

Για entry points JavaScript/Electron που οδηγούν σε native add-ons, δείτε το [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Scripted ανάλυση IDA και Ghidra με τοπικό TCP bridge

Το [IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) εκτελείται μέσα σε μια βάση δεδομένων IDA ή ένα πρόγραμμα Ghidra CodeBrowser που είναι **ήδη ανοιχτό** και επιτρέπει σε ένα ξεχωριστό script να κάνει queries και να τροποποιεί αυτή τη βάση ανάλυσης. Εκτελέστε το `ID_Server.py` από το Python CLI της IDA (`import ID_Server`) ή το `Ghidra_Server.py` από το Ghidra Script Manager. Η IDA κάνει bind στη `127.0.0.1`, ξεκινώντας από τη θύρα `5073`, και ελέγχει τις επόμενες θύρες. Το τρέχον script της Ghidra ξεκινά από τη θύρα `5093` και δοκιμάζει δέκα θύρες, έως τη `5102`· το Java socket του κάνει bind στη διεύθυνση wildcard, όχι μόνο στο loopback. Ελέγξτε τη θύρα που εμφανίζει το instance πριν συνδεθείτε. Σε αντίθεση με έναν headless analyzer, αυτό το bridge λειτουργεί στο πρόγραμμα που είναι ανοιχτό αυτή τη στιγμή στο αντίστοιχο GUI instance.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Στείλτε **μία εντολή που τερματίζεται με newline ανά σύνδεση** και διαβάστε την απάντηση που τερματίζεται με newline. Συνήθως το αποτέλεσμα είναι JSON. Για παράδειγμα, αφού εντοπίσετε ένα imported API που σχετίζεται με μια διαδρομή εισόδου, το `IMPORTXREF` εντοπίζει τα σημεία κλήσης του· στη συνέχεια, το `DECOMP_XREF` κάνει batch decompile στους callers μιας επιλεγμένης διεύθυνσης. Το `FUNC` εξετάζει μια συνάρτηση, ενώ το `PCODE` επιστρέφει την ενδιάμεση αναπαράσταση του decompiler. Χρησιμοποιήστε τη διεύθυνση από την ενεργή βάση δεδομένων και όχι μια διεύθυνση που αντιγράψατε από binary με διαφορετική βάση αναπροσαρμογής. Το παρακάτω παράδειγμα χρησιμοποιεί την προεπιλεγμένη θύρα της IDA· για τη Ghidra, χρησιμοποιήστε τη θύρα που εμφανίζει το script της.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

Το ίδιο κανάλι μπορεί να **αλλάξει τη βάση δεδομένων ανάλυσης**: οι εντολές `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` και `PATCH` τροποποιούν ονόματα, τύπους, ορισμούς δομών, όρια συναρτήσεων ή αποθηκευμένα bytes. Η `PATCH` είναι επεξεργασία της βάσης δεδομένων, **όχι** ένδειξη patch σε ζωντανή διεργασία. Κανένας listener δεν τεκμηριώνει έλεγχο ταυτότητας. Το IDA είναι διαθέσιμο μόνο μέσω loopback, αλλά το Ghidra μπορεί να είναι προσβάσιμο μέσω διεπαφών δικτύου· περιορίστε την πρόσβαση στον listener του Ghidra όταν το χρησιμοποιείτε. Η `QUIT` σταματά οποιονδήποτε από τους δύο listeners, ενώ το IDA διαθέτει επίσης την `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Αποσφαλμάτωση shellcode με το blobrunner

Το [**BlobRunner**](https://github.com/OALabs/BlobRunner) δεσμεύει χώρο για το **shellcode**, εκτυπώνει τη **διεύθυνση μνήμης** του και θέτει σε παύση την εκτέλεση.\
Συνδέστε έναν debugger όπως το IDA ή το x64dbg, ορίστε ένα breakpoint στη διεύθυνση που εκτυπώθηκε και συνεχίστε την εκτέλεση για να αποσφαλματώσετε το shellcode.

Η σελίδα github των releases περιέχει zip με τα μεταγλωττισμένα releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Μπορείτε να βρείτε μια ελαφρώς τροποποιημένη έκδοση του Blobrunner στον παρακάτω σύνδεσμο. Για να τη μεταγλωττίσετε, απλώς **δημιουργήστε ένα project C/C++ στο Visual Studio Code, αντιγράψτε και επικολλήστε τον κώδικα και κάντε build**.


{{#ref}}
blobrunner.md
{{#endref}}

### Αποσφαλμάτωση shellcode με το jmp2it

Το [**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) είναι παρόμοιο με το BlobRunner. Δεσμεύει χώρο για το shellcode και εισέρχεται σε έναν ατέρμονο βρόχο. Συνδέστε τον debugger, συνεχίστε την εκτέλεση για **2–5 δευτερόλεπτα**, θέστε σε παύση μέσα στον βρόχο και κάντε step μέχρι την επόμενη κλήση που μεταφέρει την εκτέλεση στο δεσμευμένο shellcode.

![Ο debugger έχει τεθεί σε παύση στον ατέρμονο βρόχο του jmp2it, ακριβώς πριν από την κλήση προς το δεσμευμένο shellcode](<../../images/image (509).png>)

Μπορείτε να κατεβάσετε μια μεταγλωττισμένη έκδοση του [jmp2it από τη σελίδα των releases](https://github.com/adamkramer/jmp2it/releases/).

### Αποσφαλμάτωση shellcode με το Cutter

Το [**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) είναι το GUI του radare. Με το Cutter μπορείτε να προσομοιώσετε το shellcode και να το επιθεωρήσετε δυναμικά.

Σημειώστε ότι το Cutter σάς επιτρέπει να επιλέξετε «Open File» και «Open Shellcode». Στη δική μου περίπτωση, όταν άνοιξα το shellcode ως αρχείο, το αποσυμπίλησε σωστά, αλλά όταν το άνοιξα ως shellcode, δεν το έκανε:

![Το Cutter εμφανίζει διαφορετικά αποτελέσματα ανάλυσης όταν ανοίγουν τα ίδια bytes ως αρχείο ή ως shellcode](<../../images/image (562).png>)

Για να ξεκινήσει η προσομοίωση στο σημείο που θέλετε, ορίστε εκεί ένα bp και, απ' ό,τι φαίνεται, το Cutter θα ξεκινήσει αυτόματα την προσομοίωση από εκεί:

![Ορισμός breakpoint στην επιθυμητή είσοδο του shellcode πριν από την έναρξη της προσομοίωσης του Cutter](<../../images/image (589).png>)

![Ο emulator του Cutter έχει τεθεί σε παύση στο επιλεγμένο breakpoint του shellcode](<../../images/image (387).png>)

Μπορείτε, για παράδειγμα, να δείτε το stack μέσα σε ένα hex dump:

![Προβολή του stack του προσομοιωμένου shellcode στο hex dump του Cutter](<../../images/image (186).png>)

### Αποσυσκότιση shellcode και εντοπισμός συναρτήσεων που εκτελούνται

Θα πρέπει να δοκιμάσετε το [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Θα σας ενημερώσει, για παράδειγμα, **ποιες συναρτήσεις** χρησιμοποιεί το shellcode και αν το shellcode **αποκωδικοποιεί** τον εαυτό του στη μνήμη.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

Το scDbg διαθέτει επίσης ένα γραφικό launcher, όπου μπορείτε να επιλέξετε τις επιθυμητές ρυθμίσεις και να εκτελέσετε το shellcode.

![Γραφικό launcher του scDbg για την επιλογή ρυθμίσεων emulation και tracing του shellcode](<../../images/image (258).png>)

Η επιλογή **Create Dump** δημιουργεί ένα dump του τελικού shellcode, αν έχει γίνει κάποια αλλαγή στο shellcode δυναμικά στη μνήμη (χρήσιμο για τη λήψη του αποκωδικοποιημένου shellcode). Το `start offset` μπορεί να φανεί χρήσιμο για να ξεκινήσει η εκτέλεση του shellcode από συγκεκριμένο offset. Η επιλογή **Debug Shell** είναι χρήσιμη για τον εντοπισμό σφαλμάτων στο shellcode μέσω του terminal του scDbg (ωστόσο, θεωρώ ότι κάποια από τις επιλογές που εξηγήθηκαν προηγουμένως είναι καλύτερη για αυτό, καθώς θα μπορείτε να χρησιμοποιήσετε το Ida ή το x64dbg).

### Αποσυναρμολόγηση με χρήση του CyberChef

Ανεβάστε το αρχείο shellcode ως είσοδο και χρησιμοποιήστε το ακόλουθο recipe για να το αποσυναρμολογήσετε: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Αναίρεση της συσκότισης MBA

Η συσκότιση **Mixed Boolean-Arithmetic (MBA)** κρύβει απλές εκφράσεις, όπως `x + y`, πίσω από τύπους που συνδυάζουν αριθμητικές πράξεις (`+`, `-`, `*`) και bitwise τελεστές (`&`, `|`, `^`, `~`, shifts). Το σημαντικό είναι ότι αυτές οι ταυτότητες ισχύουν συνήθως μόνο στο πλαίσιο **modular αριθμητικής σταθερού πλάτους**, οπότε οι μεταφορές κρατουμένου και οι υπερχειλίσεις έχουν σημασία:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Αν απλοποιήσετε αυτό το είδος έκφρασης με εργαλεία γενικής άλγεβρας, μπορεί εύκολα να καταλήξετε σε λάθος αποτέλεσμα, επειδή αγνοήθηκε η σημασιολογία του πλάτους bit.<sup>[[1]](#references)</sup>

### Πρακτική ροή εργασίας

1. **Διατηρήστε το αρχικό πλάτος bit** από τον lifted κώδικα/IR/την έξοδο του decompiler (`8/16/32/64` bits).
2. **Κατηγοριοποιήστε την έκφραση** πριν προσπαθήσετε να την απλοποιήσετε:
   - **Γραμμική**: σταθμισμένα αθροίσματα από bitwise atoms
   - **Ημιγραμμική**: γραμμική συν σταθερές μάσκες, όπως `x & 0xFF`
   - **Πολυωνυμική**: περιέχει γινόμενα
   - **Μικτή**: γινόμενα και bitwise λογική είναι αλληλένδετα, συχνά με επαναλαμβανόμενες υποεκφράσεις
3. **Επαληθεύστε κάθε υποψήφια αναδιατύπωση** με τυχαίους ελέγχους ή απόδειξη SMT. Αν δεν μπορεί να αποδειχθεί η ισοδυναμία, κρατήστε την αρχική έκφραση αντί να μαντέψετε.

### Παράκαμψη flattened control flow με ένα στενό execution slice

Συχνά δεν είναι απαραίτητο να ανακτήσετε ολόκληρο το γράφημα ροής ελέγχου. Σε κώδικα με control-flow flattening, opaque predicates, μεγάλους dispatchers ή έντονη χρήση MBA, ακολουθήστε τις αναφορές από κρυπτογραφημένα blobs και output buffers έως τη μικρότερη ρουτίνα που τα μετασχηματίζει. Έπειτα, αναπαραγάγετε μόνο αυτό το data-flow slice ή εκτελέστε το ανεξάρτητα· ο dispatcher δεν αποτελεί μέρος της απαιτούμενης λύσης, αν η σχετική κατάσταση μπορεί να αρχικοποιηθεί απευθείας.<sup>[[7]](#references)</sup>

Μια πρακτική ροή εργασίας είναι η εξής:<sup>[[7]](#references)</sup>

1. Καταγράψτε τα εκτελέσιμα τμήματα και τα τμήματα δεδομένων, τις relocations και τις cross-references. Κάντε dump τους υποψήφιους πίνακες από το `.rodata`, διατηρώντας τη σειρά των byte και το πλάτος των στοιχείων.
2. Εντοπίστε την τελευταία ρουτίνα που γράφει το plaintext ή το output buffer. Καταγράψτε τις εισόδους της, τους πίνακες στους οποίους αναφέρεται, τις εισαγόμενες κλήσεις και την απαιτούμενη καθολική κατάσταση.
3. Μεταφέρετε μόνο αυτές τις λειτουργίες σε ένα μοντέλο Python σταθερού πλάτους. Αν το slice εξακολουθεί να εξαρτάται από υπερβολικά πολλή κατάσταση, καλέστε τη ρουτίνα με Unicorn, QEMU ή έναν debugger και κάντε hook τις άσχετες εισαγωγές, αντί να εξομοιώσετε ολόκληρο το πρόγραμμα.
4. Επαληθεύστε ότι ο extractor παράγει πράγματι την έξοδό του από το παρεχόμενο binary: αφαιρέστε τις σιωπηρές εναλλακτικές, αναζητήστε ενσωματωμένες απαντήσεις και δοκιμάστε τον σε builds που δεν έχετε ξαναδεί, με αλλαγμένες συμβολοσειρές, κλειδιά, αναγνωριστικά, layouts και seeds obfuscation.

Χρήσιμες εντολές για έναν πρώτο έλεγχο είναι οι εξής:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Ανίχνευση εκφράσεων MBA που κρύβουν σταθερές

Μια έκφραση byte που φαίνεται να εξαρτάται από την είσοδο μπορεί να ακυρώνει πλήρως την επίδρασή της. Αφού εξαγάγετε τους πίνακές της, αξιολογήστε την έκφραση σε ολόκληρο το πεδίο 8 bit· ένα σύνολο εξόδου με ένα μόνο στοιχείο αποδεικνύει ότι το byte είναι σταθερό, χωρίς να χρειάζεται να ανακτήσετε την περιβάλλουσα μηχανή καταστάσεων.<sup>[[7]](#references)</sup>

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

Διατήρησε την τελική μάσκα, επειδή η αρχική πρόσθεση έχει αναδίπλωση στο πλάτος του byte. Για ένα ευρύτερο πεδίο τιμών, ρώτησε έναν SMT solver αν είναι ικανοποιήσιμη η συνθήκη `f(x1) != f(x2)` για δύο συμβολικές εισόδους ίδιου πλάτους: το `unsat` αποδεικνύει την αμεταβλητότητα, ενώ το `sat` παρέχει ένα αντιπαράδειγμα και σημαίνει ότι η είσοδος δεν μπορεί να απορριφθεί.<sup>[[7]](#references)</sup>

#### Αναγνώριση αποκωδικοποίησης εξαρτώμενης από το περιβάλλον

Οι έλεγχοι anti-analysis δεν χρειάζεται να προκαλούν διακλάδωση ή κατάρρευση. Ένας decoder μπορεί να συνδυάζει το αποτέλεσμα ενός αισθητήρα με ένα bit κλειδιού, μια σταθερά opaque-predicate ή την κατάσταση ενός flattened-dispatcher, να συνεχίζει κανονικά και να παράγει εύλογο αλλά λανθασμένο plaintext σε έναν emulator. Επομένως, η τροποποίηση μόνο των ορατών κλάδων αποτυχίας δεν αρκεί· ιχνηλάτησε τις εξαρτήσεις δεδομένων από τις διερευνήσεις του περιβάλλοντος έως την κατάσταση του decoder, σύγκρινε το ίδιο τμήμα σε αυθεντική συσκευή και emulator και έλεγξε πώς η επιβολή κάθε αποτελέσματος αισθητήρα αλλάζει το τελικό buffer.<sup>[[7]](#references)</sup>

### CoBRA

Το [**CoBRA**](https://github.com/trailofbits/CoBRA) είναι ένα πρακτικό εργαλείο απλοποίησης MBA για ανάλυση malware και reversing προστατευμένων binaries. Ταξινομεί την έκφραση και τη δρομολογεί μέσω εξειδικευμένων pipelines, αντί να εφαρμόζει ένα γενικό πέρασμα επανεγγραφής σε όλα.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: Το CoBRA αξιολογεί την έκφραση σε Boolean εισόδους, εξάγει μια υπογραφή και εκτελεί παράλληλα διάφορες μεθόδους ανάκτησης, όπως pattern matching, μετατροπή ANF και παρεμβολή συντελεστών.
- **Semilinear MBA**: Τα atoms με constant masking ανακατασκευάζονται με ανακατασκευή βάσει bit-partition, ώστε οι masked περιοχές να παραμένουν σωστές.
- **Polynomial/Mixed MBA**: Τα γινόμενα αποσυντίθενται σε cores και οι επαναλαμβανόμενες υποεκφράσεις μπορούν να μεταφερθούν σε temporaries πριν από την απλοποίηση της εξωτερικής σχέσης.

Παράδειγμα μιας mixed ταυτότητας που συχνά αξίζει να προσπαθήσετε να ανακτήσετε:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Αυτό μπορεί να συμπτυχθεί σε:

```c
x * y
```

### Σημειώσεις για reversing

- Προτιμήστε να εκτελείτε το CoBRA σε **lifted IR expressions** ή σε έξοδο decompiler, αφού απομονώσετε τον ακριβή υπολογισμό.
- Χρησιμοποιήστε ρητά το `--bitwidth` όταν η έκφραση προέρχεται από masked arithmetic ή στενούς καταχωρητές.
- Αν χρειάζεστε ισχυρότερο βήμα απόδειξης, δείτε εδώ τις τοπικές σημειώσεις για το Z3:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- Το CoBRA διατίθεται επίσης ως **LLVM pass plugin** (`libCobraPass.so`), χρήσιμο όταν θέλετε να κανονικοποιήσετε LLVM IR με πολλά MBA πριν από επόμενα analysis passes.
- Τα μη υποστηριζόμενα carry-sensitive mixed-domain residuals θα πρέπει να θεωρούνται ένδειξη ότι πρέπει να διατηρήσετε την αρχική έκφραση και να εξετάσετε χειροκίνητα τη διαδρομή του carry.

## Ανάκτηση control-flow flattening με κατάσταση XOR

Ένας flattener τύπου OLLVM μπορεί να αποθηκεύει την τρέχουσα κατάσταση του basic block σε δύο καταχωρητές 64 bit και να την ανακατασκευάζει με XOR σε έναν dispatcher. Κάθε αρχικό block γράφει το ζεύγος που αντιστοιχεί στην επόμενη κατάστασή του και επιστρέφει στον dispatcher. Ένα conditional block μπορεί να χρησιμοποιεί `CMOVcc` για να αντικαθιστά το ένα μισό του ζεύγους ανάλογα με τα CPU flags, οπότε η παρακολούθηση μόνο των ορατών εντολών διακλάδωσης παραβλέπει τους δύο successors. Σε αντίθεση με έναν dispatcher έμμεσου άλματος, αυτή η μορφή μπορεί να χρησιμοποιεί απευθείας back-edges παντού.<sup>[[19]](#references)[[20]](#references)</sup>

Για να ανακτήσετε το γράφημα, εντοπίστε το δέντρο συγκρίσεων του dispatcher και τους δύο καταχωρητές κατάστασης, αντιστοιχίστε κάθε συγκρινόμενη κατάσταση XOR στο block-στόχο της και, στη συνέχεια, εντοπίστε τις εγγραφές στο ζεύγος καταχωρητών που φτάνουν σε κάθε αρχικό block. Για conditional writes, συμπεριλάβετε την εντολή που ορίζει τα flags και τις δύο εκβάσεις του `CMOVcc`. Αντικαταστήστε την έξοδο κάθε block προς τον dispatcher με τον άμεσο successor ή την conditional branch που εντοπίσατε· έτσι ο dispatcher καθίσταται μη προσβάσιμος χωρίς να τροποποιήσετε το binary. Πρόκειται για προσέγγιση full-CFG· αν σας ενδιαφέρει μόνο ένας decoder, η παραπάνω [ροή εργασίας narrow execution-slice](#bypass-flattened-control-flow-with-a-narrow-execution-slice) μπορεί να είναι ταχύτερη.<sup>[[19]](#references)[[20]](#references)</sup>

Το [DispatchThis](https://github.com/YungBinary/DispatchThis) αυτοματοποιεί αυτήν τη μορφή στο Binary Ninja. Αντιγράψτε το `plugins/DispatchThis` στον κατάλογο user plugins του Binary Ninja και κάντε επανεκκίνηση. Στη σχετική συνάρτηση, ανοίξτε το **Function Settings** και επιλέξτε `OLLVM_XOR_64`· αν η ανάλυση δεν ξεκινήσει, χρησιμοποιήστε το **Analysis → Reanalyze All Functions**. Αυτή η λειτουργία ξαναγράφει τις ακμές control-flow του MLIL, όχι τα bytes του αρχείου, και δεν χρειάζεται Z3 ή τον resolver έμμεσων αλμάτων. Έχει δοκιμαστεί στο Binary Ninja 5.3.9757+· δεν αφαιρεί τις νεκρές εγγραφές κατάστασης ανά block, γι’ αυτό μην τις εκλάβετε λανθασμένα ως μεταβάσεις που παραμένουν ενεργές.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Αυτός ο obfuscator αντικαθιστά τις λειτουργίες του προγράμματος με ακολουθίες εντολών βασισμένες στο `mov` και χρησιμοποιεί signal/exception handling για να μεταβάλλει τη ροή ελέγχου. Για λεπτομέρειες:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Για υποστηριζόμενα binaries, το [demovfuscator](https://github.com/kirschju/demovfuscator) μπορεί να κάνει deobfuscate το αποτέλεσμα. Έχει αρκετές dependencies.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Και [εγκαταστήστε το keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Αν παίζετε **CTF, αυτή η παράκαμψη για να βρείτε το flag** μπορεί να σας φανεί πολύ χρήσιμη: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Για να βρείτε το **entry point**, αναζητήστε τις συναρτήσεις με `::main`, όπως εδώ:

![Εύρεση ενός entry point Rust στο Ghidra με αναζήτηση ονομάτων συναρτήσεων για διπλή άνω και κάτω τελεία και main](<../../images/image (1080).png>)

Σε αυτήν την περίπτωση το binary ονομαζόταν authenticator, οπότε είναι αρκετά προφανές ότι αυτή είναι η ενδιαφέρουσα main function.\
Έχοντας το **όνομα** των **συναρτήσεων** που καλούνται, αναζητήστε τις στο **Διαδίκτυο** για να μάθετε τις **εισόδους** και τις **εξόδους** τους.

### Ανάκτηση συμβολοσειρών Rust από firmware ELF

Σε **Rust ELF** binaries, πολλές στατικές συμβολοσειρές δεν αναφέρονται μέσω δεικτών με τερματισμό NUL, όπως στη C. Μια συνηθισμένη διάταξη του `rustc` είναι μια **πλειάδα δείκτη/μήκους** μέσα στο **`.data.rel.ro`**, η οποία δείχνει προς το πραγματικό blob συμβολοσειρών που είναι αποθηκευμένο στο **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Αυτό σημαίνει ότι το `strings` ή η προεπιλεγμένη ανάλυση του Ghidra μπορεί να συγχωνεύσει γειτονικές συμβολοσειρές ή να μην εντοπίσει καθόλου τις cross-references.<sup>[[3]](#references)</sup>

Γρήγορη ροή εργασίας:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Βρείτε την εικονική διεύθυνση και το μέγεθος του **`.rodata`**.
2. Διατρέξτε το **`.data.rel.ro`** μία λέξη τη φορά.
3. Θεωρήστε κάθε τιμή που βρίσκεται εντός του εύρους διευθύνσεων του `.rodata` ως υποψήφιο δείκτη σε συμβολοσειρά.
4. Θεωρήστε την επόμενη λέξη ως υποψήφιο μήκος.
5. Εφαρμόστε φίλτρα εγκυρότητας (για παράδειγμα, κρατήστε μήκη μεταξύ **4** και **100** byte).
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

Αυτό είναι ιδιαίτερα χρήσιμο στο firmware reversing, επειδή οι ανακτημένες συμβολοσειρές Rust συχνά αποκαλύπτουν **HTTP routes, ονόματα RPC, μηνύματα καταγραφής, assertions, ονόματα αρχείων, κλειδιά config, command handlers και λογική σχετική με το auth**.

Αν το Ghidra δεν εντοπίζει αυτές τις συμβολοσειρές, εκτελέστε ένα custom script/plugin που εφαρμόζει την ίδια ευρετική και δημιουργεί δεδομένα συμβολοσειρών στις αναφερόμενες μετατοπίσεις `.rodata`. Τα δημοσιευμένα εργαλεία `rust-strings` και `RustStrings.py` της Pen Test Partners αποτελούν καλές αναφορές για την προσαρμογή της ιδέας σε άλλες **μεγέθη λέξεων, endianness και διατάξεις τμημάτων**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Για binaries μεταγλωττισμένα με Delphi, μπορείτε να χρησιμοποιήσετε το [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Αν χρειάζεται να κάνετε reverse ένα Delphi binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό το plugin εκτελεί το binary και επιλύει δυναμικά τα ονόματα των συναρτήσεων κατά την έναρξη του debugging. Αφού ξεκινήσει το debugging, πατήστε ξανά το κουμπί Start (το πράσινο ή το f9) και θα ενεργοποιηθεί ένα breakpoint στην αρχή του πραγματικού κώδικα.

Αν πατήσετε ένα κουμπί στη γραφική εφαρμογή, ο debugger μπορεί να σταματήσει στη συνάρτηση που καλείται από αυτό το κουμπί.

## Golang

Για συνηθισμένα Go binaries, το [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) μπορεί να ανακτήσει runtime structures και να βελτιώσει τα ονόματα των συναρτήσεων στο IDA. Φορτώστε το Python plugin με **Alt+F7**.

Αν χρειάζεται να κάνετε reverse ένα Golang binary, θα σας πρότεινα να χρησιμοποιήσετε το IDA plugin [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Πατήστε **Alt+F7** στο IDA για να φορτώσετε ένα Python plugin και, στη συνέχεια, επιλέξτε το αρχείο του plugin.

Αυτό θα επιλύσει τα ονόματα των συναρτήσεων.

### Ανάκτηση metadata χωρίς τον πίνακα συμβόλων

Ένα Go executable από το οποίο έχουν αφαιρεθεί τα σύμβολα εξακολουθεί να χρειάζεται runtime metadata για την αντιστοίχιση των program counters με τις συναρτήσεις. Το [GoReSym](https://github.com/mandiant/GoReSym) εντοπίζει και αναλύει structures όπως τα `pclntab` και `moduledata`, χρησιμοποιώντας κώδικα που προέρχεται από το Go runtime. Έτσι μπορούν να ανακτηθούν τα όρια των συναρτήσεων, τα ονόματα, οι διαδρομές του πηγαίου κώδικα, οι τύποι και λεπτομέρειες του build, χωρίς να βασίζεται κανείς στον συμβατικό πίνακα συμβόλων.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Ένας obfuscator μπορεί να αφήσει αυτές τις δομές αξιοποιήσιμες, αντικαθιστώντας παράλληλα τα ονόματα που ανακτήθηκαν. Το Garble, για παράδειγμα, κατακερματίζει τα αναγνωριστικά και τις διαδρομές των πακέτων και αφαιρεί πληροφορίες για το build, τα modules και το debugging.<sup>[[12]](#references)</sup> Το obfuscated token του πακέτου πρέπει να παραμένει σταθερό μεταξύ των συναρτήσεων του ίδιου πακέτου. Ομαδοποιήστε τις συναρτήσεις με βάση το επαναλαμβανόμενο token, συμπεράνετε το πακέτο από τις συναρτήσεις που καλεί, τις συμβολοσειρές και τα API και, στη συνέχεια, μεταβιβάστε την ετικέτα του πακέτου σε ολόκληρη την ομάδα.<sup>[[13]](#references)</sup>

### Ανάκτηση ονομάτων Garble με το GoResolver

Το [GoResolver](https://github.com/volexity/GoResolver) συνδυάζει την εξαγωγή συμβόλων runtime με τη δημιουργία καθαρών αναφορών και την αντιστοίχιση γραφημάτων ροής ελέγχου (CFG). Ακολουθήστε αυτή τη σειρά:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Προσδιορίστε την έκδοση του compiler.** Δοκιμάστε πρώτα το `BuildInfo` και τις ενσωματωμένες συμβολοσειρές έκδοσης. Αν ο obfuscator τις έχει αφαιρέσει, συγκρίνετε τμήματα του ενσωματωμένου Go runtime με runtime αναφοράς συγκεκριμένων εκδόσεων. Στις δοκιμές της Volexity, περίπου το `2%` του runtime ήταν αρκετό για να διακρίνει τις κύριες εκδόσεις του Go. Αντιμετωπίστε το ως εμπειρική βελτιστοποίηση, όχι ως καθολικό όριο.<sup>[[13]](#references)</sup>
2. **Δημιουργήστε αντίστοιχες αναφορές.** Δημιουργήστε καθαρά binaries για την προσδιορισμένη έκδοση του Go, την αρχιτεκτονική-στόχο και τις πιθανές βιβλιοθήκες. Η αντιστοίχιση του toolchain περιορίζει τις διαφορές στα CFG που δημιουργεί ο compiler.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Συγκρίνετε τις συναρτήσεις.** Το GoGrapher αντιστοιχίζει CFG συναρτήσεων και εξάγει κανονικοποιημένες βαθμολογίες από `0.0` έως `1.0`. Η αντιστοίχιση βασικών blocks βασίζεται σε σταθμισμένη σύγκριση παρόμοιων εντολών. Οι αντιστοιχίσεις υψηλής βεβαιότητας συνδέουν τυχαιοποιημένες συναρτήσεις με την καθαρή υλοποίηση. Οι ασθενέστερες αντιστοιχίσεις μπορούν και πάλι να προσδιορίσουν ένα πακέτο ή ένα module.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Επαληθεύστε και εισαγάγετε.** Επιβεβαιώστε τα προτεινόμενα ονόματα με τις σχέσεις κλήσεων, τις σταθερές, τις συμβολοσειρές και τις παρενέργειες και, στη συνέχεια, εισαγάγετε την αναφορά JSON με το plugin του GoResolver για IDA ή Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

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

Το προεπιλεγμένο κατώφλι σημαντικής αντιστοίχισης είναι `0.9`. Τα switches `--extract` και `--graph` μπορούν να απομονώσουν οποιοδήποτε από τα δύο στάδια, ενώ η προεπιλεγμένη λειτουργία εκτελεί και τα δύο, επειδή τα ανακτημένα runtime metadata και τα στοιχεία CFG αλληλοσυμπληρώνονται.<sup>[[10]](#references)</sup> Οι βαθμολογίες CFG είναι ευρετικές: το inlining, τα build flags, η αρχιτεκτονική και οι διαφορές στις εκδόσεις βιβλιοθηκών μπορούν να αλλάξουν τη μορφή του γράφου, γι’ αυτό διατηρήστε τις ανεπίλυτες συναρτήσεις αντί να επιβάλλετε ονόματα με χαμηλό βαθμό εμπιστοσύνης.<sup>[[13]](#references)</sup>

### Ανάκτηση του πίνακα συμβολοσειρών Go

Τα Go binaries τοποθετούν τα bytes συμβολοσειρών από όλα τα συνδεδεμένα packages σε έναν ενιαίο, συνεχόμενο πίνακα. Οι καταχωρίσεις δεν τερματίζονται με NUL και οι runtime δομές δεν εκθέτουν τη βάση ή το μέγεθος του πίνακα. Ωστόσο, ο compiler ταξινομεί τις καταχωρίσεις πρώτα κατά μήκος και έπειτα αλφαβητικά, σε όλα τα λειτουργικά συστήματα και τις αρχιτεκτονικές. Επομένως, αφού βρει μία καταχώριση, ένας αναλυτής μπορεί να διατρέξει τις γειτονικές καταχωρίσεις και να χρησιμοποιήσει τις διασταυρούμενες αναφορές δεδομένων για να συσχετίσει συμβολοσειρές με κώδικα.<sup>[[15]](#references)</sup>

Το [GoStringExtractor](https://github.com/volexity/GoStringExtractor) αυτοματοποιεί αυτή τη διαδικασία στα IDA Pro και Ghidra. Αφήστε πρώτα να ολοκληρωθεί η αυτόματη ανάλυση, επειδή το plugin βασίζεται στις διασταυρούμενες αναφορές του τμήματος δεδομένων. Το προεπιλεγμένο σημείο αγκύρωσης είναι η runtime συμβολοσειρά `entersyscall`. Έπειτα, μπορεί να σαρώσει προς οποιαδήποτε κατεύθυνση, να ορίσει τις ανακτημένες συμβολοσειρές στη βάση δεδομένων και να εξαγάγει ένα JSON mapping συμβολοσειρών προς τις συναρτήσεις που τις αναφέρουν.<sup>[[14]](#references)</sup>

Φιλτράρετε την αναφορά με βάση το package της συνάρτησης που κάνει την αναφορά, ώστε να διαχωρίσετε τον κώδικα της εφαρμογής ή του malware από τον θόρυβο των συνδεδεμένων βιβλιοθηκών. Αυτή η τεχνική δεν μπορεί να ανακτήσει literals που έχουν καταστραφεί από obfuscation, όπως με τον μετασχηματισμό `-literals` του Garble. Μπορεί, ωστόσο, να οργανώσει runtime συμβολοσειρές που παραμένουν χωρίς obfuscation.<sup>[[14]](#references)[[15]](#references)</sup>

### Ανάκτηση των Go runtime τύπων

Το Go ενσωματώνει πληροφορίες τύπων runtime που χρησιμοποιούνται από λειτουργίες όπως το garbage collection. Όταν έχουν αφαιρεθεί οι πληροφορίες build ή ο disassembler δεν αναλύει αυτά τα metadata, οι εντολές μπορεί να φαίνεται ότι φορτώνουν αυθαίρετες διευθύνσεις δεδομένων και η περιοχή-στόχος παραμένει χωρίς τύπο. Η ανάκτηση των metadata μετατρέπει αυτές τις διευθύνσεις σε ευανάγνωστες αναφορές τύπων και διευκολύνει την κατανόηση των δυνατοτήτων των packages.<sup>[[15]](#references)</sup>

Το [GoResolver](https://github.com/volexity/GoResolver) μπορεί να εξαγάγει σύμβολα και να αναλύσει runtime τύπους σε μια αναφορά JSON. Το τρέχον CLI χρησιμοποιεί την υποεντολή `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

Η επιλογή `-y`/`--types` ενεργοποιεί την ανάλυση τύπων. Εισαγάγετε την αναφορά με το plugin του GoResolver για IDA Pro ή Ghidra, ώστε να ορίσετε τους τύπους που ανακτήθηκαν και να εφαρμόσετε τις αναφορές τους στη βάση δεδομένων ανάλυσης. Στη μορφή αναφοράς που εισήχθη με αυτήν τη δυνατότητα, αν παραλείψετε το `-y`, τα μέλη της διεύθυνσης RTTI και των τύπων που ανακτήθηκαν παραμένουν null.<sup>[[10]](#references)[[15]](#references)</sup>

Το GoResolver υποστηρίζει δείγματα PE, ELF και Mach-O για x86, AMD64, ARM και ARM64, επομένως η ίδια ροή εργασίας εφαρμόζεται σε Go binaries από Windows, Linux και macOS.<sup>[[10]](#references)</sup>

## Compiled Python

Σε αυτήν τη σελίδα μπορείτε να βρείτε πώς να εξαγάγετε τον κώδικα Python από ένα μεταγλωττισμένο binary Python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Αν αποκτήσετε το **binary** ενός παιχνιδιού GBA, μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για να το **emulate** και να κάνετε **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Κατεβάστε την έκδοση debug_) - Περιλαμβάνει debugger με interface
- [**mgba** ](https://mgba.io)- Περιλαμβάνει debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin για Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin για Ghidra

Στο [**no$gba**](https://problemkaputt.de/gba.htm), στην επιλογή _**Options --> Emulation Setup --> Controls**_** ** μπορείτε να δείτε πώς να πατάτε τα **κουμπιά** του Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

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

Έτσι, σε αυτό το είδος προγράμματος, το ενδιαφέρον είναι **ο τρόπος με τον οποίο το πρόγραμμα χειρίζεται την είσοδο του χρήστη**. Στη διεύθυνση **0x4000130** θα βρείτε τη συνηθισμένη συνάρτηση: **KEYINPUT**.

![Προβολή στο Ghidra ενός δυαδικού αρχείου GBA που αναφέρεται στο KEYINPUT στη διεύθυνση 0x4000130](<../../images/image (447).png>)

Στην προηγούμενη εικόνα μπορείτε να δείτε ότι η συνάρτηση καλείται από τη **FUN_080015a8** (διευθύνσεις: _0x080015fa_ και _0x080017ac_).

Σε αυτή τη συνάρτηση, μετά από ορισμένες αρχικοποιητικές λειτουργίες (που δεν έχουν σημασία):

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

Το τελευταίο if ελέγχει αν το **`uVar4`** βρίσκεται στα **τελευταία πλήκτρα** και δεν είναι το τρέχον πλήκτρο· δηλαδή, αν αφήνεται ένα κουμπί (το τρέχον πλήκτρο αποθηκεύεται στο **`uVar1`**).

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

- Πρώτα, συγκρίνεται με την **τιμή 4** (κουμπί **SELECT**): στο challenge αυτό το κουμπί καθαρίζει την οθόνη
- Έπειτα συγκρίνεται με την τιμή **8** (κουμπί **START**): σε αυτό το challenge, αυτή η διαδρομή ελέγχει αν ο κωδικός που πληκτρολογήθηκε είναι έγκυρος.
  - Σε αυτή την περίπτωση, η μεταβλητή **`DAT_030000d8`** συγκρίνεται με το 0xf3 και, αν οι τιμές είναι ίδιες, εκτελείται κάποιος κώδικας.
- Σε κάθε άλλη περίπτωση, ελέγχεται και αυξάνεται ένας μετρητής (`DAT_030000d4`).\
  Όσο ο μετρητής είναι μικρότερος από 8, οι τιμές των πατημένων πλήκτρων αθροίζονται στη μεταβλητή `DAT_030000d8`.

Άρα, σε αυτό το challenge, γνωρίζοντας τις τιμές των κουμπιών, έπρεπε να **πατήσετε έναν συνδυασμό με μήκος μικρότερο από 8, ώστε το άθροισμα των τιμών να είναι 0xf3.**

**Πηγή για αυτό το tutorial:** [αρχειοθετημένο writeup του Nostalgia challenge](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

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
- [6] [Nostalgia - tutorial για reverse engineering στο GBA (αρχειοθετημένο)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Αντιμετώπιση του reverse engineering με τη βοήθεια AI — ή τουλάχιστον προσπάθεια](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Μια προσέγγιση για τη σύγκριση Control Flow Graphs βάσει αντιστοίχισης Basic Blocks](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Αποθετήριο GoResolver της Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Μηχανισμός obfuscation του Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Χρήση ομοιότητας Control-Flow Graph για την αυτόματη deobfuscation δυαδικών αρχείων Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Αποθετήριο GoStringExtractor της Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Ενημερώσεις στα εργαλεία Golang της Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [Ανάλυση managed code στο REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Οδηγός CLI και Evidence του REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Ροή εργασιών control-flow unflattening στο Binary Ninja](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: Εισβολή μηδενικής ημέρας στο PaperCut MF, Java Loader, Web Shell και AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README του IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Υλοποίηση του IDA bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Υλοποίηση του Ghidra bridge server](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - Το InetSocketAddress(int) συνδέεται στη διεύθυνση wildcard](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Εργαλειοθήκη reverse engineering για Godot](https://github.com/figurophobia/gore)
- [26] [Υλοποίηση ανάκτησης κλειδιού του gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Μορφή encrypted blob του gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Υλοποίηση εντολών και ανάκτησης του gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
