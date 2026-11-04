# Εκτέλεση μέσω Drop-Share επέκτασης VS Code

{{#include ../banners/hacktricks-training.md}}

Οι επεκτάσεις του VS Code και οι επεκτάσεις του Visual Studio VSSDK χρησιμοποιούν και οι δύο συσκευασία `.vsix`, αλλά έχουν διαφορετικά manifests και runtimes. Ένα εγγράψιμο SMB drop share γίνεται διαδρομή εκτέλεσης **μόνο αν** κάποιος άλλος χρήστης ή κάποιο job ανάπτυξης εγκαταστήσει τα πακέτα του στο VS Code. Τότε, η συνάρτηση `activate()` της επέκτασης εκτελείται στο extension host με τα προνόμια του συγκεκριμένου χρήστη. Η απλή εγγραφή ενός `.vsix` σε ένα share δεν το εκτελεί.<sup>[[1]](#references)[[2]](#references)</sup>

## Ροή εργασιών συσκευασίας και ενεργοποίησης

Πρώτα, επιβεβαιώστε την έκδοση του VS Code που χρησιμοποιεί ο καταναλωτής και ότι το share συγχρονίζεται ή εγκαθίσταται πράγματι. Δημιουργήστε μια επέκταση TypeScript και τοποθετήστε την επιθυμητή ενέργεια Node.js στη συνάρτηση `activate()`. Χρησιμοποιήστε ένα activation event που εκτελείται χωρίς να επιλέξει ο χρήστης κάποια εντολή, όπως το `onStartupFinished`, και έπειτα μεταγλωττίστε και συσκευάστε την επέκταση. Το `engines.vscode` είναι η **πύλη συμβατότητας runtime**· η αντιστοίχιση του `@types/vscode` με την έκδοση API-στόχο αποτελεί μέτρο συμβατότητας κατά τον χρόνο κατασκευής, όχι απαίτηση κατά την εγκατάσταση.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Για έναν επεξεργαστή που εκτελεί το VS Code 1.118, τα σχετικά πεδία του `package.json` είναι:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Ένας στοιχειώδης έλεγχος `activate()` μπορεί να εκτελέσει μια εντολή και να καταγράψει την έξοδό της από το extension host. Αντικαταστήστε τη δοκιμαστική ενέργεια μόνο αφού επαληθεύσετε ότι το package έχει ενεργοποιηθεί στον αναμενόμενο λογαριασμό/συνεδρία. Το συμβάν `onStartupFinished` εκτελείται μετά την εκκίνηση, επομένως δεν αποτελεί απόδειξη εκτέλεσης μέχρι να ξεκινήσει πραγματικά ο editor και να εγκατασταθεί και να ενεργοποιηθεί το extension.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Ένας επιτιθέμενος με πρόσβαση εγγραφής στο drop share μπορεί να ανεβάσει το δοκιμασμένο πακέτο και να περιμένει να το χρησιμοποιήσει η εργασία. Στο παράδειγμα του Checkpoint, την πρόσβαση εγγραφής στο share την παρείχε ο λογαριασμός που ανακτήθηκε· ο αρχικός λογαριασμός με χαμηλά προνόμια μπορούσε μόνο να διαβάσει από το share. Μην συγχέετε αυτές τις δύο προϋποθέσεις. Για τις επεκτάσεις **Visual Studio**, χρησιμοποιήστε το ξεχωριστό κεφάλαιο [κατάχρηση επεκτάσεων Visual Studio VSIX](visual-studio-vsix-extension-abuse.md) αντί για αυτήν τη ροή εργασίας του VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Συμβάντα ενεργοποίησης](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Δημοσίευση επεκτάσεων](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
