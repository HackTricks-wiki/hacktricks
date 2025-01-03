{{#include ../../banners/hacktricks-training.md}}

# Οδηγός Αποσυμπίεσης Wasm και Συμπίεσης Wat

Στον τομέα του **WebAssembly**, τα εργαλεία για **αποσυμπίεση** και **συμπίεση** είναι απαραίτητα για τους προγραμματιστές. Αυτός ο οδηγός εισάγει μερικούς διαδικτυακούς πόρους και λογισμικό για την επεξεργασία αρχείων **Wasm (WebAssembly binary)** και **Wat (WebAssembly text)**.

## Διαδικτυακά Εργαλεία

- Για να **αποσυμπιέσετε** το Wasm σε Wat, το εργαλείο που είναι διαθέσιμο στο [Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) είναι χρήσιμο.
- Για **συμπίεση** του Wat πίσω σε Wasm, το [Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) εξυπηρετεί τον σκοπό.
- Μια άλλη επιλογή αποσυμπίεσης μπορεί να βρεθεί στο [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Λύσεις Λογισμικού

- Για μια πιο ισχυρή λύση, το [JEB by PNF Software](https://www.pnfsoftware.com/jeb/demo) προσφέρει εκτενή χαρακτηριστικά.
- Το ανοιχτού κώδικα έργο [wasmdec](https://github.com/wwwg/wasmdec) είναι επίσης διαθέσιμο για εργασίες αποσυμπίεσης.

# Πόροι Αποσυμπίεσης .Net

Η αποσυμπίεση των .Net assemblies μπορεί να επιτευχθεί με εργαλεία όπως:

- [ILSpy](https://github.com/icsharpcode/ILSpy), το οποίο προσφέρει επίσης ένα [plugin για το Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), επιτρέποντας τη διαλειτουργικότητα σε πολλές πλατφόρμες.
- Για εργασίες που περιλαμβάνουν **αποσυμπίεση**, **τροποποίηση** και **επανσυμπίεση**, το [dnSpy](https://github.com/0xd4d/dnSpy/releases) συνιστάται ιδιαίτερα. **Κάντε δεξί κλικ** σε μια μέθοδο και επιλέξτε **Τροποποίηση Μεθόδου** για να κάνετε αλλαγές στον κώδικα.
- Το [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) είναι μια άλλη εναλλακτική για την αποσυμπίεση των .Net assemblies.

## Ενίσχυση Αποσφαλμάτωσης και Καταγραφής με DNSpy

### Καταγραφή DNSpy

Για να καταγράψετε πληροφορίες σε ένα αρχείο χρησιμοποιώντας το DNSpy, ενσωματώστε το παρακάτω απόσπασμα κώδικα .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Αποσφαλμάτωση DNSpy

Για αποτελεσματική αποσφαλμάτωση με το DNSpy, προτείνεται μια σειρά βημάτων για την προσαρμογή των **Attributes Assembly** για αποσφαλμάτωση, διασφαλίζοντας ότι οι βελτιστοποιήσεις που θα μπορούσαν να εμποδίσουν την αποσφαλμάτωση είναι απενεργοποιημένες. Αυτή η διαδικασία περιλαμβάνει την αλλαγή των ρυθμίσεων `DebuggableAttribute`, την επανασυμπίεση του assembly και την αποθήκευση των αλλαγών.

Επιπλέον, για να αποσφαλματώσετε μια εφαρμογή .Net που εκτελείται από το **IIS**, η εκτέλεση του `iisreset /noforce` επανεκκινεί το IIS. Για να συνδέσετε το DNSpy στη διαδικασία IIS για αποσφαλμάτωση, ο οδηγός καθοδηγεί στην επιλογή της διαδικασίας **w3wp.exe** μέσα στο DNSpy και στην έναρξη της συνεδρίας αποσφαλμάτωσης.

Για μια συνολική εικόνα των φορτωμένων μονάδων κατά την αποσφαλμάτωση, συνιστάται η πρόσβαση στο παράθυρο **Modules** στο DNSpy, ακολουθούμενη από το άνοιγμα όλων των μονάδων και την ταξινόμηση των assemblies για ευκολότερη πλοήγηση και αποσφαλμάτωση.

Αυτός ο οδηγός συνοψίζει την ουσία της αποσυμπίεσης WebAssembly και .Net, προσφέροντας μια διαδρομή για τους προγραμματιστές να πλοηγηθούν σε αυτές τις εργασίες με ευκολία.

## **Java Decompiler**

Για να αποσυμπιέσετε τον bytecode Java, αυτά τα εργαλεία μπορεί να είναι πολύ χρήσιμα:

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Αποσφαλμάτωση DLLs**

### Χρησιμοποιώντας IDA

- **Rundll32** φορτώνεται από συγκεκριμένες διαδρομές για εκδόσεις 64-bit και 32-bit.
- **Windbg** επιλέγεται ως ο αποσφαλματωτής με την επιλογή να ανασταλεί η φόρτωση/εκφόρτωση βιβλιοθήκης ενεργοποιημένη.
- Οι παράμετροι εκτέλεσης περιλαμβάνουν τη διαδρομή DLL και το όνομα της συνάρτησης. Αυτή η ρύθμιση σταματά την εκτέλεση κατά τη φόρτωση κάθε DLL.

### Χρησιμοποιώντας x64dbg/x32dbg

- Παρόμοια με το IDA, το **rundll32** φορτώνεται με τροποποιήσεις γραμμής εντολών για να προσδιορίσει τη DLL και τη συνάρτηση.
- Οι ρυθμίσεις προσαρμόζονται για να σπάσουν στην είσοδο DLL, επιτρέποντας την τοποθέτηση σημείων διακοπής στο επιθυμητό σημείο εισόδου DLL.

### Εικόνες

- Τα σημεία και οι ρυθμίσεις διακοπής εκτέλεσης απεικονίζονται μέσω στιγμιότυπων οθόνης.

## **ARM & MIPS**

- Για προσομοίωση, το [arm_now](https://github.com/nongiach/arm_now) είναι ένας χρήσιμος πόρος.

## **Shellcodes**

### Τεχνικές Αποσφαλμάτωσης

- **Blobrunner** και **jmp2it** είναι εργαλεία για την κατανομή shellcodes στη μνήμη και την αποσφαλμάτωσή τους με το Ida ή το x64dbg.
- Blobrunner [releases](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [compiled version](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** προσφέρει προσομοίωση και επιθεώρηση shellcode με GUI, επισημαίνοντας τις διαφορές στη διαχείριση shellcode ως αρχείο σε σχέση με το άμεσο shellcode.

### Αποκατάσταση και Ανάλυση

- **scdbg** παρέχει πληροφορίες σχετικά με τις λειτουργίες shellcode και τις δυνατότητες αποκατάστασης.
%%%bash
scdbg.exe -f shellcode # Βασικές πληροφορίες
scdbg.exe -f shellcode -r # Αναφορά ανάλυσης
scdbg.exe -f shellcode -i -r # Διαδραστικά hooks
scdbg.exe -f shellcode -d # Dump αποκωδικοποιημένου shellcode
scdbg.exe -f shellcode /findsc # Βρείτε την αρχική μετατόπιση
scdbg.exe -f shellcode /foff 0x0000004D # Εκτέλεση από μετατόπιση
%%%

- **CyberChef** για αποσυναρμολόγηση shellcode: [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- Ένας obfuscator που αντικαθιστά όλες τις εντολές με `mov`.
- Χρήσιμοι πόροι περιλαμβάνουν μια [YouTube εξήγηση](https://www.youtube.com/watch?v=2VF_wPkiBJY) και [PDF slides](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** μπορεί να αντιστρέψει την obfuscation του movfuscator, απαιτώντας εξαρτήσεις όπως `libcapstone-dev` και `libz3-dev`, και την εγκατάσταση του [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**

- Για τα δυαδικά αρχεία Delphi, συνιστάται το [IDR](https://github.com/crypto2011/IDR).

# Μαθήματα

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Αποκατάσταση δυαδικών\)

{{#include ../../banners/hacktricks-training.md}}
