# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` και profiles του PowerShell

Σε macOS και Linux, το PowerShell χρησιμοποιεί διαδρομές διαμόρφωσης XDG και εκτελεί scripts προφίλ χρήστη κατά την εκκίνηση του `pwsh`. Η ανακατεύθυνση του `XDG_CONFIG_HOME` αλλάζει τον κατάλογο που περιέχει τα `powershell/profile.ps1` και `powershell/Microsoft.PowerShell_profile.ps1`, τα οποία αφορούν τον συγκεκριμένο console host· επομένως, ένα ελεγχόμενο αρχείο εκεί μπορεί να εκτελεστεί πριν από ένα payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Αυτό ισχύει για το PowerShell 6+ (`pwsh`) σε πλατφόρμες που δεν είναι Windows· το Windows PowerShell χρησιμοποιεί διαφορετικές τοποθεσίες profile. Το `pwsh -NoProfile` παρακάμπτει τη φόρτωση των profile. Ελέγξτε επίσης το `HOME` και τα ονόματα profile που αφορούν συγκεκριμένα host, επειδή άλλα PowerShell host μπορούν να επιλέξουν διαφορετικά scripts.

## References

- [1] [Μεταβλητές περιβάλλοντος του PowerShell και διαδρομές XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profile του PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
