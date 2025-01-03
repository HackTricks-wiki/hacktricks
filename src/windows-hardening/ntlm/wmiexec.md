# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식 설명

사용자 이름과 비밀번호 또는 해시가 알려진 호스트에서 프로세스를 열 수 있습니다. WMI를 사용하여 Wmiexec가 명령을 실행하며, 반대화면 상호작용 쉘 경험을 제공합니다.

**dcomexec.py:** 다양한 DCOM 엔드포인트를 활용하여 이 스크립트는 wmiexec.py와 유사한 반대화면 상호작용 쉘을 제공하며, 특히 ShellBrowserWindow DCOM 객체를 활용합니다. 현재 MMC20, Application, Shell Windows 및 Shell Browser Window 객체를 지원합니다. (출처: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI 기초

### 네임스페이스

디렉토리 스타일 계층 구조로 구성된 WMI의 최상위 컨테이너는 \root이며, 그 아래에 네임스페이스라고 하는 추가 디렉토리가 조직되어 있습니다.
네임스페이스를 나열하는 명령:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
네임스페이스 내의 클래스를 나열하려면 다음을 사용합니다:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **클래스**

WMI 클래스 이름, 예를 들어 win32_process, 및 그것이 위치한 네임스페이스를 아는 것은 모든 WMI 작업에 중요합니다.
`win32`로 시작하는 클래스를 나열하는 명령:
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
### 방법

WMI 클래스의 하나 이상의 실행 가능한 함수인 방법은 실행할 수 있습니다.
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

WMI 서비스가 작동하는지 확인하는 명령:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### 시스템 및 프로세스 정보

WMI를 통해 시스템 및 프로세스 정보 수집:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
공격자에게 WMI는 시스템이나 도메인에 대한 민감한 데이터를 열거하는 강력한 도구입니다.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
원격에서 특정 정보를 위한 WMI 쿼리는, 예를 들어 로컬 관리자나 로그인한 사용자와 같은 정보를 신중한 명령 구성으로 수행할 수 있습니다.

### **수동 원격 WMI 쿼리**

원격 머신에서 로컬 관리자와 로그인한 사용자를 은밀하게 식별하는 것은 특정 WMI 쿼리를 통해 달성할 수 있습니다. `wmic`는 또한 여러 노드에서 동시에 명령을 실행하기 위해 텍스트 파일에서 읽는 것을 지원합니다.

WMI를 통해 프로세스를 원격으로 실행하기 위해, 예를 들어 Empire 에이전트를 배포하는 경우, 다음과 같은 명령 구조가 사용되며, 성공적인 실행은 "0"의 반환 값으로 표시됩니다:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
이 프로세스는 원격 실행 및 시스템 열거를 위한 WMI의 기능을 보여주며, 시스템 관리 및 침투 테스트 모두에 대한 유용성을 강조합니다.

## References

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
