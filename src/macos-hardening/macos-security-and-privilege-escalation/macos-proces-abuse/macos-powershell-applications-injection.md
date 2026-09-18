# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

Το PowerShell είναι cross-platform: το ίδιο δυαδικό αρχείο `pwsh` εκτελείται σε macOS, Linux και Windows και είναι μια εφαρμογή **.NET (Core)**. Αυτό παρέχει σε έναν attacker που ελέγχει το περιβάλλον μιας invocation του `pwsh` αρκετές environment-variable → code-execution primitives που λειτουργούν με τον ίδιο τρόπο και στα τρία OS, καθώς και μερικές που αφορούν μόνο τα Windows. Όλες εκτελούνται **πριν** από (ή αντί για) το `-Command`/`-File` που σκόπευε να εκτελέσει το victim, γεγονός που τις καθιστά ιδανικές για επιθέσεις εναντίον privileged wrappers, cron/`launchd`/systemd jobs και CI runners που εκκινούν το `pwsh` μέσω shell με inherited environment.

## `XDG_CONFIG_HOME` και PowerShell profiles

Σε macOS και Linux, το PowerShell χρησιμοποιεί XDG configuration paths και εκτελεί user profile scripts όταν ξεκινά το `pwsh`. Η ανακατεύθυνση του `XDG_CONFIG_HOME` αλλάζει τον κατάλογο που περιέχει τα `powershell/profile.ps1` και το console-host-specific `powershell/Microsoft.PowerShell_profile.ps1`. Επομένως, ένα controlled αρχείο εκεί μπορεί να εκτελεστεί πριν από ένα `-Command` payload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Αυτό ισχύει για το PowerShell 6+ (`pwsh`) σε πλατφόρμες που δεν είναι Windows· το Windows PowerShell χρησιμοποιεί διαφορετικές τοποθεσίες για τα profile. Το `pwsh -NoProfile` αποτρέπει τη φόρτωση των profile. Επίσης, ελέγξτε τα `HOME` και τα ονόματα profile που είναι ειδικά για τον host, επειδή άλλοι PowerShell hosts μπορούν να επιλέξουν διαφορετικά scripts.

> [!TIP]
> Στα **Windows**, οι διαδρομές των profile προκύπτουν από το `$HOME` / τον γνωστό φάκελο *Documents* (π.χ. `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` για το `pwsh`, `Documents\WindowsPowerShell\...` για το Windows PowerShell), επομένως η επίδραση στα `HOME`/`USERPROFILE` — ή απλώς η εγγραφή σε αυτό το αρχείο — είναι το αντίστοιχο primitive.

## Υποκλοπή αυτόματης φόρτωσης module μέσω του `PSModulePath`

Από το PowerShell 3.0, η **αυτόματη φόρτωση module** εισάγει αυτόματα ένα module την πρώτη φορά που γίνεται αναφορά σε μια εντολή που εξάγει (με επίκληση, `Get-Command` ή tab-completion). Το PowerShell αναζητά αναδρομικά σε κάθε κατάλογο που περιλαμβάνεται στο **`$Env:PSModulePath`** αρχεία `.psd1`/`.psm1`, και σε πλατφόρμες που δεν είναι Windows το `PSModulePath` που κληρονομείται από τη διεργασία χρησιμοποιείται ως έχει. Επομένως, αν μπορείτε να **προσθέσετε έναν κατάλογο στην αρχή του `PSModulePath`**, μπορείτε να εγκαταστήσετε ένα module που είτε ταιριάζει με μια εντολή την οποία καλεί το script του θύματος είτε με ένα όνομα module που το script κάνει `Import-Module` — και ο κώδικας σε επίπεδο module εκτελείται κατά την εισαγωγή.<sup>[[3]](#references)</sup>

Επειδή η επίλυση εντολών του PowerShell ακολουθεί τη σειρά *Alias → Function → Cmdlet → Application*, μια **function που εξάγεται από το module σας μπορεί να επισκιάσει ένα ενσωματωμένο cmdlet** που χρησιμοποιεί ο στόχος (π.χ. `Get-ChildItem`), επομένως δεν χρειάζεται καν το θύμα να εισαγάγει κάτι βάσει ονόματος.
```bash
# Attacker-controlled module dir prepended to PSModulePath
mkdir -p /tmp/evil/Hijack
cat >/tmp/evil/Hijack/Hijack.psm1 <<'PS1'
# Top-level module code runs at import time
New-Item -ItemType File -Path /tmp/psmodulepath-executed -Force | Out-Null
function Invoke-Report { 'hijacked' }   # shadows whatever the victim calls
Export-ModuleMember -Function Invoke-Report
PS1
cat >/tmp/evil/Hijack/Hijack.psd1 <<'PS1'
@{ ModuleVersion = '1.0'; RootModule = 'Hijack.psm1'; FunctionsToExport = @('Invoke-Report') }
PS1

# Victim runs pwsh with an inherited/attacker-influenced PSModulePath and calls Invoke-Report
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/psmodulepath-executed && echo 'PSModulePath auto-load executed'
```
Στα **Windows** ισχύει το ίδιο (`;`-separated paths)· το `PSModulePath` τροφοδοτείται επίσης από τα `HKCU:\Environment` και `HKLM:\...\Session Manager\Environment`, επομένως μια εγγράψιμη τιμή σε επίπεδο χρήστη αποτελεί επίσης primitive persistence. Η αυτόματη φόρτωση μπορεί να απενεργοποιηθεί με `$PSModuleAutoloadingPreference = 'None'`, ενώ το `pwsh -NoProfile` **δεν** την σταματά.

## Έγχυση CLR profiler (`CORECLR_PROFILER` / `COR_PROFILER`)

Το `pwsh` εκτελείται στο .NET Core, επομένως το **CLR profiling API** φορτώνει ένα DLL/`.so`/`.dylib` του attacker στη διεργασία κατά την εκκίνηση, αποκλειστικά μέσω του environment — χωρίς signature και χωρίς να απαιτείται COM registration, επειδή οι μεταβλητές `*_PATH` έχουν προτεραιότητα έναντι του registry. Η βιβλιοθήκη του profiler εκτελεί το `DllMain`/entry point της μέσα στη διεργασία του PowerShell, κάτι που αποτελεί κλασική τεχνική in-process code-execution και persistence (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Σε **.NET 8+**, οι μεταβλητές μπορούν επίσης να χρησιμοποιούν το νεότερο πρόθεμα `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`), ενώ το `CORECLR_*` διατηρείται για συμβατότητα προς τα πίσω.
- Στο **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), η αντίστοιχη τριάδα είναι **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** και **`COR_PROFILER_PATH=C:\evil.dll`**.

Το profiler DLL χρειάζεται μόνο να είναι μια έγκυρη βιβλιοθήκη COM/ICorProfilerCallback (ή απλώς να εκτελεί τη λειτουργία του από το `DllMain`). Οι αμυντικοί launchers θα πρέπει να αφαιρούν τα `COR_*`/`CORECLR_*`/`DOTNET_*` από προνομιούχα περιβάλλοντα.

## `DOTNET_STARTUP_HOOKS` (hook .NET πριν από το `Main`)

Επειδή το `pwsh` είναι εφαρμογή .NET Core, το **`DOTNET_STARTUP_HOOKS`** δείχνει σε ένα managed assembly, του οποίου το `StartupHook.Initialize()` εκτελείται συγχρονισμένα πριν από το `Main` του host — δηλαδή πριν ξεκινήσει το ίδιο το PowerShell. Αυτό είναι το καθαρότερο primitive για managed code και χρησιμοποιείται από κάθε άλλη εφαρμογή .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (παράκαμψη ελέγχου Windows)

Στα Windows, ο ορισμός της μεταβλητής περιβάλλοντος **`$Env:PSExecutionPolicyPreference`** (π.χ. σε `Bypass` ή `Unrestricted`) παρακάμπτει την ισχύουσα Execution Policy για τη συγκεκριμένη διεργασία — αυτό ακριβώς γράφει το `Set-ExecutionPolicy -Scope Process`. Από μόνο του δεν εκτελεί κώδικα, αλλά καταργεί το προστατευτικό μέτρο «αποκλείονται τα unsigned scripts», το οποίο συχνά είναι ο κρίκος που λείπει για να εκτελεστεί πραγματικά ένα από τα παραπάνω primitives (ένα planted profile / module). Η Execution Policy αφορά μόνο τα Windows και δεν αποτέλεσε ποτέ security boundary.<sup>[[5]](#references)</sup>

## References

- [1] [Μεταβλητές περιβάλλοντος του PowerShell και διαδρομές XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profiles του PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath και αυτόματη φόρτωση module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Ρυθμίσεις διαμόρφωσης debugging και profiling του .NET (μεταβλητές profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
