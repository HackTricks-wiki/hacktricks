# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

공격자는 **파일의 타임스탬프를 변경**하여 탐지를 피하는 데 관심이 있을 수 있습니다.\
타임스탬프는 MFT의 `$STANDARD_INFORMATION` \_\_ 및 \_\_ `$FILE_NAME` 속성 안에서 찾을 수 있습니다.

두 속성 모두 4개의 타임스탬프를 가지고 있습니다: **수정**, **접근**, **생성**, 및 **MFT 레지스트리 수정** (MACE 또는 MACB).

**Windows 탐색기** 및 기타 도구는 **`$STANDARD_INFORMATION`**의 정보를 표시합니다.

### TimeStomp - Anti-forensic Tool

이 도구는 **`$STANDARD_INFORMATION`** 내의 타임스탬프 정보를 **수정**하지만 **`$FILE_NAME`** 내의 정보는 수정하지 않습니다. 따라서 **의심스러운** **활동**을 **식별**할 수 있습니다.

### Usnjrnl

**USN 저널** (Update Sequence Number Journal)은 NTFS (Windows NT 파일 시스템)의 기능으로, 볼륨 변경 사항을 추적합니다. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 도구를 사용하면 이러한 변경 사항을 검사할 수 있습니다.

![](<../../images/image (801).png>)

이전 이미지는 **도구**에서 표시된 **출력**으로, 파일에 **변경이 수행되었음을** 관찰할 수 있습니다.

### $LogFile

**파일 시스템에 대한 모든 메타데이터 변경 사항은** [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)이라는 프로세스에서 기록됩니다. 기록된 메타데이터는 NTFS 파일 시스템의 루트 디렉토리에 위치한 `**$LogFile**`이라는 파일에 저장됩니다. [LogFileParser](https://github.com/jschicht/LogFileParser)와 같은 도구를 사용하여 이 파일을 구문 분석하고 변경 사항을 식별할 수 있습니다.

![](<../../images/image (137).png>)

다시 말해, 도구의 출력에서 **일부 변경이 수행되었음을** 볼 수 있습니다.

같은 도구를 사용하여 **타임스탬프가 수정된 시간을 식별**할 수 있습니다:

![](<../../images/image (1089).png>)

- CTIME: 파일의 생성 시간
- ATIME: 파일의 수정 시간
- MTIME: 파일의 MFT 레지스트리 수정
- RTIME: 파일의 접근 시간

### `$STANDARD_INFORMATION` 및 `$FILE_NAME` 비교

의심스러운 수정된 파일을 식별하는 또 다른 방법은 두 속성의 시간을 비교하여 **불일치**를 찾는 것입니다.

### 나노초

**NTFS** 타임스탬프는 **100 나노초**의 **정밀도**를 가집니다. 따라서 2010-10-10 10:10:**00.000:0000과 같은 타임스탬프를 가진 파일을 찾는 것은 매우 의심스럽습니다.

### SetMace - Anti-forensic Tool

이 도구는 `$STARNDAR_INFORMATION` 및 `$FILE_NAME` 두 속성을 모두 수정할 수 있습니다. 그러나 Windows Vista부터는 이 정보를 수정하기 위해 라이브 OS가 필요합니다.

## Data Hiding

NFTS는 클러스터와 최소 정보 크기를 사용합니다. 즉, 파일이 클러스터와 반 개를 차지하면 **남은 반은 파일이 삭제될 때까지 절대 사용되지 않습니다**. 따라서 이 슬랙 공간에 **데이터를 숨길 수 있습니다**.

슬래커와 같은 도구를 사용하면 이 "숨겨진" 공간에 데이터를 숨길 수 있습니다. 그러나 `$logfile` 및 `$usnjrnl` 분석을 통해 일부 데이터가 추가되었음을 보여줄 수 있습니다:

![](<../../images/image (1060).png>)

그런 다음 FTK Imager와 같은 도구를 사용하여 슬랙 공간을 복구할 수 있습니다. 이러한 종류의 도구는 내용을 난독화하거나 심지어 암호화된 상태로 저장할 수 있습니다.

## UsbKill

이 도구는 **USB** 포트에서 변경 사항이 감지되면 컴퓨터를 **꺼**버립니다.\
이를 발견하는 방법은 실행 중인 프로세스를 검사하고 **실행 중인 각 파이썬 스크립트를 검토**하는 것입니다.

## Live Linux Distributions

이 배포판은 **RAM** 메모리 내에서 **실행됩니다**. 이를 감지하는 유일한 방법은 **NTFS 파일 시스템이 쓰기 권한으로 마운트된 경우**입니다. 읽기 권한만으로 마운트되면 침입을 감지할 수 없습니다.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

여러 Windows 로깅 방법을 비활성화하여 포렌식 조사를 훨씬 더 어렵게 만들 수 있습니다.

### Disable Timestamps - UserAssist

이것은 사용자가 각 실행 파일을 실행한 날짜와 시간을 유지하는 레지스트리 키입니다.

UserAssist를 비활성화하려면 두 단계를 수행해야 합니다:

1. 두 개의 레지스트리 키, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 및 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`를 모두 0으로 설정하여 UserAssist를 비활성화하겠다는 신호를 보냅니다.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`와 같은 레지스트리 하위 트리를 지웁니다.

### Disable Timestamps - Prefetch

이것은 Windows 시스템의 성능을 향상시키기 위해 실행된 응용 프로그램에 대한 정보를 저장합니다. 그러나 이것은 포렌식 관행에도 유용할 수 있습니다.

- `regedit` 실행
- 파일 경로 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` 선택
- `EnablePrefetcher` 및 `EnableSuperfetch`를 마우스 오른쪽 버튼으로 클릭
- 각 값을 1(또는 3)에서 0으로 변경하기 위해 수정 선택
- 재시작

### Disable Timestamps - Last Access Time

NTFS 볼륨에서 폴더가 열릴 때마다 시스템은 각 나열된 폴더에 대해 **타임스탬프 필드를 업데이트하는 데 시간을 소요**합니다. 이를 마지막 접근 시간이라고 합니다. 사용량이 많은 NTFS 볼륨에서는 성능에 영향을 줄 수 있습니다.

1. 레지스트리 편집기(Regedit.exe)를 엽니다.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`으로 이동합니다.
3. `NtfsDisableLastAccessUpdate`를 찾습니다. 존재하지 않으면 이 DWORD를 추가하고 값을 1로 설정하여 프로세스를 비활성화합니다.
4. 레지스트리 편집기를 닫고 서버를 재부팅합니다.

### Delete USB History

모든 **USB 장치 항목**은 USB 장치를 PC 또는 노트북에 연결할 때 생성되는 하위 키를 포함하는 **USBSTOR** 레지스트리 키 아래에 Windows 레지스트리에 저장됩니다. 이 키는 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`에서 찾을 수 있습니다. **이것을 삭제하면** USB 기록이 삭제됩니다.\
또한 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) 도구를 사용하여 삭제했는지 확인할 수 있습니다 (그리고 삭제할 수 있습니다).

USB에 대한 정보를 저장하는 또 다른 파일은 `C:\Windows\INF` 내의 `setupapi.dev.log` 파일입니다. 이것도 삭제해야 합니다.

### Disable Shadow Copies

**쉐도우 복사본** 목록을 보려면 `vssadmin list shadowstorage`를 실행하세요.\
**삭제**하려면 `vssadmin delete shadow`를 실행하세요.

GUI를 통해 삭제하려면 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)에서 제안된 단계를 따르세요.

쉐도우 복사본을 비활성화하려면 [여기서 단계](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)를 따르세요:

1. Windows 시작 버튼을 클릭한 후 텍스트 검색 상자에 "services"를 입력하여 서비스 프로그램을 엽니다.
2. 목록에서 "Volume Shadow Copy"를 찾아 선택한 후 마우스 오른쪽 버튼을 클릭하여 속성에 접근합니다.
3. "시작 유형" 드롭다운 메뉴에서 비활성화를 선택하고 변경 사항을 적용하고 확인을 클릭합니다.

어떤 파일이 쉐도우 복사본에 복사될지를 레지스트리 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`에서 수정할 수도 있습니다.

### Overwrite deleted files

- **Windows 도구**를 사용할 수 있습니다: `cipher /w:C` 이는 C 드라이브 내의 사용 가능한 미사용 디스크 공간에서 데이터를 제거하도록 지시합니다.
- [**Eraser**](https://eraser.heidi.ie)와 같은 도구를 사용할 수도 있습니다.

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs" 확장 --> 각 카테고리를 마우스 오른쪽 버튼으로 클릭하고 "로그 지우기" 선택
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- 서비스 섹션 내에서 "Windows Event Log" 서비스를 비활성화합니다.
- `WEvtUtil.exec clear-log` 또는 `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

최근 버전의 Windows 10/11 및 Windows Server는 `Microsoft-Windows-PowerShell/Operational` (이벤트 4104/4105/4106) 아래에 **풍부한 PowerShell 포렌식 아티팩트**를 보관합니다. 공격자는 이를 실시간으로 비활성화하거나 삭제할 수 있습니다:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
수비자는 해당 레지스트리 키의 변경 사항과 PowerShell 이벤트의 대량 제거를 모니터링해야 합니다.

### ETW (Windows 이벤트 추적) 패치

엔드포인트 보안 제품은 ETW에 크게 의존합니다. 2024년의 인기 있는 회피 방법은 메모리에서 `ntdll!EtwEventWrite`/`EtwEventWriteFull`을 패치하여 모든 ETW 호출이 이벤트를 발생시키지 않고 `STATUS_SUCCESS`를 반환하도록 하는 것입니다.
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`)는 PowerShell 또는 C++에서 동일한 프리미티브를 구현합니다. 패치가 **프로세스-로컬**이기 때문에 다른 프로세스 내에서 실행되는 EDR은 이를 놓칠 수 있습니다. 탐지: 메모리의 `ntdll`과 디스크의 `ntdll`을 비교하거나 사용자 모드 이전에 후킹합니다.

### 대체 데이터 스트림 (ADS) 부활

2023년의 악성코드 캠페인 (예: **FIN12** 로더)은 전통적인 스캐너의 시야에서 벗어나기 위해 ADS 내에 2단계 바이너리를 스테이징하는 것이 관찰되었습니다:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
스트림을 나열하려면 `dir /R`, `Get-Item -Stream *` 또는 Sysinternals `streams64.exe`를 사용하십시오. 호스트 파일을 FAT/exFAT로 복사하거나 SMB를 통해 복사하면 숨겨진 스트림이 제거되며, 이는 조사자가 페이로드를 복구하는 데 사용할 수 있습니다.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver는 이제 랜섬웨어 침입에서 **안티 포렌식**을 위해 정기적으로 사용됩니다. 오픈 소스 도구 **AuKill**은 서명된 그러나 취약한 드라이버(`procexp152.sys`)를 로드하여 암호화 및 로그 파괴 **전**에 EDR 및 포렌식 센서를 일시 중지하거나 종료합니다:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
드라이버는 제거되어 최소한의 아티팩트를 남깁니다.  
완화 조치: Microsoft 취약한 드라이버 차단 목록(HVCI/SAC)을 활성화하고, 사용자 쓰기 가능한 경로에서 커널 서비스 생성에 대해 경고합니다.

---

## 리눅스 안티 포렌식: 자기 패치 및 클라우드 C2 (2023–2025)

### 탐지를 줄이기 위한 자기 패치된 서비스 (리눅스)  
적대자들은 재침투를 방지하고 취약성 기반 탐지를 억제하기 위해 서비스를 악용한 직후 "자기 패치"를 점점 더 많이 사용합니다. 아이디어는 취약한 구성 요소를 최신의 합법적인 업스트림 바이너리/JAR로 교체하여 스캐너가 호스트를 패치된 것으로 보고하도록 하는 것입니다. 이때 지속성과 C2는 유지됩니다.

예시: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- 포스트 익스플로잇 후, 공격자들은 Maven Central (repo1.maven.org)에서 합법적인 JAR를 가져오고, ActiveMQ 설치에서 취약한 JAR를 삭제한 후 브로커를 재시작했습니다.  
- 이는 초기 RCE를 차단하면서 다른 발판(크론, SSH 구성 변경, 별도의 C2 임플란트)을 유지했습니다.

운영 예시 (설명용)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forensic/hunting tips
- 서비스 디렉토리에서 예정되지 않은 바이너리/JAR 교체를 검토합니다:
- Debian/Ubuntu: `dpkg -V activemq`를 사용하고 파일 해시/경로를 저장소 미러와 비교합니다.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- 패키지 관리자가 소유하지 않는 디스크에 있는 JAR 버전이나 비정상적으로 업데이트된 심볼릭 링크를 찾습니다.
- 타임라인: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`를 사용하여 ctime/mtime과 타협 창을 연관시킵니다.
- 셸 기록/프로세스 텔레메트리: 초기 악용 직후 `curl`/`wget`의 `repo1.maven.org` 또는 기타 아티팩트 CDN에 대한 증거.
- 변경 관리: “패치”를 적용한 사람과 그 이유를 검증합니다. 단순히 패치된 버전이 존재하는지 여부만 확인하지 않습니다.

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
관찰된 무역 기술은 여러 장기 C2 경로와 반분석 패키징을 결합했습니다:
- 샌드박싱 및 정적 분석을 방해하기 위한 비밀번호 보호된 PyInstaller ELF 로더 (예: 암호화된 PYZ, `/_MEI*` 아래의 임시 추출).
- 지표: `strings` 히트 예: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- 런타임 아티팩트: `/tmp/_MEI*` 또는 사용자 정의 `--runtime-tmpdir` 경로로의 추출.
- 하드코딩된 OAuth Bearer 토큰을 사용하는 Dropbox 지원 C2
- 네트워크 마커: `api.dropboxapi.com` / `content.dropboxapi.com`에서 `Authorization: Bearer <token>`.
- 서버 작업 부하에서 Dropbox 도메인으로의 아웃바운드 HTTPS를 찾기 위해 프록시/NetFlow/Zeek/Suricata에서 검색합니다. 일반적으로 파일을 동기화하지 않는 경우.
- 채널이 차단되면 제어를 유지하기 위해 터널링을 통한 병렬/백업 C2 (예: Cloudflare Tunnel `cloudflared`).
- 호스트 IOC: `cloudflared` 프로세스/유닛, `~/.cloudflared/*.json`의 구성, Cloudflare 엣지로의 아웃바운드 443.

### Persistence and “hardening rollback” to maintain access (Linux examples)
공격자는 자주 자가 패치와 내구성 있는 접근 경로를 쌍으로 사용합니다:
- Cron/Anacron: 각 `/etc/cron.*/` 디렉토리의 `0anacron` 스텁을 편집하여 주기적으로 실행합니다.
- 검색:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH 구성 하드닝 롤백: 루트 로그인을 활성화하고 저권한 계정의 기본 셸을 변경합니다.
- 루트 로그인 활성화를 찾습니다:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes"와 같은 플래그 값 또는 지나치게 허용적인 설정
```
- 시스템 계정에서 의심스러운 대화형 셸을 찾습니다 (예: `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- 클라우드 C2와도 연락하는 랜덤, 짧은 이름의 비콘 아티팩트 (8개의 알파벳 문자)가 디스크에 드롭됩니다:
- 검색:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

수비자는 이러한 아티팩트를 외부 노출 및 서비스 패치 이벤트와 연관시켜 초기 악용을 숨기기 위해 사용된 반포렌식 자가 복구를 발견해야 합니다.

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (March 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (June 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
