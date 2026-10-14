# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## 타임스탬프

공격자는 탐지를 피하기 위해 **파일의 타임스탬프를 변경**하려 할 수 있습니다.\
MFT에서 `$STANDARD_INFORMATION` \_\_ 및 \_\_ `$FILE_NAME` 속성을 확인하면 타임스탬프를 찾을 수 있습니다.

두 속성에는 **수정**, **액세스**, **생성**, **MFT 레지스트리 수정** 타임스탬프가 있습니다(MACE 또는 MACB).

**Windows 탐색기**와 다른 도구는 **`$STANDARD_INFORMATION`**의 정보를 표시합니다.

### TimeStomp - Anti-forensic Tool

이 도구는 **`$STANDARD_INFORMATION`**의 타임스탬프 정보를 **수정하지만**, **`$FILE_NAME`**의 정보는 수정하지 않습니다. 따라서 **의심스러운 활동을 식별**할 수 있습니다.

### Usnjrnl

**USN Journal**(Update Sequence Number Journal)은 볼륨의 변경 사항을 추적하는 NTFS(Windows NT 파일 시스템) 기능입니다. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 도구를 사용하면 이러한 변경 사항을 조사할 수 있습니다.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal(Update Sequence Number Journal)은 볼륨의 변경 사항을 추적하는 NTFS(Windows NT 파일 시스템) 기능입니다. ...](<../../images/image (801).png>)

앞의 이미지는 **도구의 출력**으로, 파일에 일부 **변경이 수행된 것**을 확인할 수 있습니다.

### $LogFile

파일 시스템에 대한 **모든 메타데이터 변경 사항은** [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)이라고 하는 프로세스를 통해 기록됩니다. 기록된 메타데이터는 NTFS 파일 시스템의 루트 디렉터리에 있는 `**$LogFile**`이라는 파일에 저장됩니다. [LogFileParser](https://github.com/jschicht/LogFileParser)와 같은 도구를 사용하면 이 파일을 파싱하고 변경 사항을 식별할 수 있습니다.

![Usnjrnl - $LogFile: 파일 시스템에 대한 모든 메타데이터 변경 사항은 write-ahead logging이라고 하는 프로세스를 통해 기록됩니다. 기록된 메타데이터는 NTFS 파일 시스템의 루트...에 있는 $LogFile이라는 파일에 저장됩니다.](<../../images/image (137).png>)

다시 말해, 도구의 출력에서 **일부 변경이 수행된 것**을 확인할 수 있습니다.

같은 도구를 사용해 타임스탬프가 **어느 시점에 수정되었는지** 확인할 수도 있습니다.

![Usnjrnl - $LogFile: 같은 도구를 사용해 타임스탬프가 어느 시점에 수정되었는지 확인할 수 있습니다](<../../images/image (1089).png>)

- CTIME: 파일 생성 시간
- ATIME: 파일 수정 시간
- MTIME: 파일의 MFT 레지스트리 수정 시간
- RTIME: 파일 액세스 시간

### `$STANDARD_INFORMATION` 및 `$FILE_NAME` 비교

의심스럽게 수정된 파일을 식별하는 또 다른 방법은 두 속성의 시간을 비교해 **불일치**를 찾는 것입니다.

### 나노초

**NTFS** 타임스탬프의 **정밀도는 100나노초**입니다. 따라서 2010-10-10 10:10:**00.000:0000과 같은 타임스탬프를 가진 파일은 매우 의심스럽습니다**.

### SetMace - Anti-forensic Tool

이 도구는 `$STARNDAR_INFORMATION`과 `$FILE_NAME` 속성을 모두 수정할 수 있습니다. 하지만 Windows Vista부터는 이 정보를 수정하려면 실행 중인 OS가 필요합니다.

## 데이터 숨기기

NFTS는 클러스터와 최소 정보 크기를 사용합니다. 즉, 파일이 클러스터 하나 반을 사용하면 **나머지 절반은 파일이 삭제될 때까지 사용되지 않습니다**. 따라서 **이 슬랙 공간에 데이터를 숨길 수 있습니다**.

slacker와 같이 이 "숨겨진" 공간에 데이터를 숨길 수 있는 도구가 있습니다. 하지만 `$logfile`과 `$usnjrnl`을 분석하면 데이터가 추가된 것을 확인할 수 있습니다.

![SetMace - Anti-forensic Tool - 데이터 숨기기: slacker와 같이 이 "숨겨진" 공간에 데이터를 숨길 수 있는 도구가 있습니다. 하지만 $logfile과 $usnjrnl을 분석하면...](<../../images/image (1060).png>)

그런 다음 FTK Imager와 같은 도구를 사용해 슬랙 공간을 복구할 수 있습니다. 이러한 종류의 도구를 사용하면 콘텐츠가 난독화되거나 암호화되어 저장될 수도 있습니다.

## UsbKill

이 도구는 USB 포트에 변화가 감지되면 **컴퓨터를 끕니다**.\
실행 중인 프로세스를 살펴보고 실행 중인 각 Python 스크립트를 **검토하면** 이를 발견할 수 있습니다.

## Live Linux 배포판

이 배포판은 **RAM 메모리에서 실행됩니다**. 이를 감지할 수 있는 유일한 경우는 **NTFS 파일 시스템이 쓰기 권한으로 마운트된 경우**입니다. 읽기 권한으로만 마운트되어 있다면 침입을 감지할 수 없습니다.

## 안전한 삭제

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Windows 실행 파일 지연 삭제

프로세스가 활성 상태인 동안에는 실행 중인 Windows 이미지가 잠겨 있을 수 있습니다. 프로세스는 삭제 작업을 자식 `cmd.exe`에 맡기고, `choice`를 타이머로 사용한 다음 셸이 `del`을 실행하기 전에 종료할 수 있습니다. 이렇게 지연하면 원래 프로세스가 이미지 핸들을 해제할 수 있습니다. 경로에 공백이 있는 경우 전체 경로를 따옴표로 묶어야 합니다.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

이 문자열을 다른 대화형 `cmd` 프롬프트에서 입력하는 대신 `cmd.exe`에 직접 인수로 전달할 때는 `^&` 대신 `&`를, `^>nul` 대신 `>nul`을 사용하세요. 이렇게 하면 디렉터리 항목이 제거됩니다. **안전한 삭제는 아니며**, 실행 흔적, 작업 흔적, 파일 시스템 저널 흔적 또는 기타 포렌식 흔적은 제거되지 않습니다. 명령줄에 `choice /T`, `Del`, 부모 프로세스의 이미지 경로가 함께 포함된, 수명이 짧은 `cmd.exe` 자식 프로세스를 찾아보세요.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows 구성

포렌식 조사를 훨씬 어렵게 만들기 위해 여러 Windows 로깅 방식을 비활성화할 수 있습니다.

### 타임스탬프 비활성화 - UserAssist

사용자가 각 실행 파일을 실행한 날짜와 시간을 기록하는 레지스트리 키입니다.

UserAssist를 비활성화하려면 다음 두 단계를 거쳐야 합니다.

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`와 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 두 레지스트리 키를 모두 0으로 설정해 UserAssist를 비활성화하도록 지정합니다.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`처럼 생긴 레지스트리 하위 트리를 삭제합니다.

### 타임스탬프 비활성화 - Prefetch

Windows 시스템의 성능 향상을 위해 실행된 애플리케이션 정보를 저장합니다. 하지만 이 정보는 포렌식에도 유용할 수 있습니다.

- `regedit` 실행
- 파일 경로 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` 선택
- `EnablePrefetcher`와 `EnableSuperfetch`를 모두 마우스 오른쪽 버튼으로 클릭
- 각각 수정 메뉴를 선택해 값을 1(또는 3)에서 0으로 변경
- 재시작

### 타임스탬프 비활성화 - 마지막 액세스 시간

Windows NT 서버에서 NTFS 볼륨의 폴더를 열 때마다 시스템은 **각 폴더 항목의 타임스탬프 필드**를 마지막 액세스 시간으로 업데이트합니다. 사용량이 많은 NTFS 볼륨에서는 성능에 영향을 줄 수 있습니다.

1. 레지스트리 편집기(Regedit.exe)를 엽니다.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`으로 이동합니다.
3. `NtfsDisableLastAccessUpdate`를 찾습니다. 없으면 DWORD를 추가하고 값을 1로 설정해 해당 프로세스를 비활성화합니다.
4. 레지스트리 편집기를 닫고 서버를 재부팅합니다.

### USB 기록 삭제

모든 **USB 장치 항목**은 Windows 레지스트리의 **USBSTOR** 키에 저장됩니다. 이 키에는 USB 장치를 PC 또는 노트북에 연결할 때마다 생성되는 하위 키가 포함됩니다. 이 키는 H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`에서 찾을 수 있습니다. **이 키를 삭제하면** USB 기록이 삭제됩니다.\
도구 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)를 사용해 삭제 여부를 확인하거나 삭제할 수도 있습니다.

USB 정보를 저장하는 또 다른 파일은 `C:\Windows\INF`에 있는 `setupapi.dev.log`입니다. 이 파일도 삭제해야 합니다.

### Shadow Copy 비활성화

`vssadmin list shadowstorage`로 Shadow Copy **목록 표시**\
`vssadmin delete shadow`를 실행해 Shadow Copy **삭제**

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)에 제시된 단계를 따라 GUI에서 삭제할 수도 있습니다.

Shadow Copy를 비활성화하려면 [여기의 단계](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)를 따릅니다.

1. Windows 시작 버튼을 클릭한 후 텍스트 검색 상자에 "services"를 입력해 Services 프로그램을 엽니다.
2. 목록에서 "Volume Shadow Copy"를 찾아 선택한 다음, 마우스 오른쪽 버튼을 클릭해 Properties를 엽니다.
3. "Startup type" 드롭다운 메뉴에서 Disabled를 선택한 다음 Apply와 OK를 클릭해 변경 사항을 적용합니다.

레지스트리 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`에서 Shadow Copy에 복사할 파일의 설정을 수정할 수도 있습니다.

### 삭제된 파일 덮어쓰기

- **Windows 도구**를 사용할 수 있습니다: `cipher /w:C` 이 명령은 C 드라이브에서 사용 가능한 미사용 디스크 공간의 데이터를 모두 제거하도록 cipher에 지시합니다.
- [**Eraser**](https://eraser.heidi.ie) 같은 도구를 사용할 수도 있습니다.

### Windows 이벤트 로그 삭제

- Windows + R --> eventvwr.msc --> "Windows Logs" 확장 --> 각 범주를 마우스 오른쪽 버튼으로 클릭하고 "Clear Log" 선택
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows 이벤트 로그 비활성화

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Services 섹션에서 "Windows Event Log" 서비스를 비활성화합니다.
- `WEvtUtil.exec clear-log` 또는 `WEvtUtil.exe cl`

### $UsnJrnl 비활성화

- `fsutil usn deletejournal /d c:`

---

## 고급 로깅 및 추적 변조 (2023-2025)

### PowerShell ScriptBlock/Module 로깅

최근 버전의 Windows 10/11 및 Windows Server는
`Microsoft-Windows-PowerShell/Operational`에 **상세한 PowerShell 포렌식 아티팩트**(이벤트 4104/4105/4106)를 저장합니다.  
공격자는 실시간으로 이를 비활성화하거나 삭제할 수 있습니다:

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

Defender는 해당 registry key의 변경 사항과 대량의 PowerShell 이벤트 제거를 모니터링해야 합니다.

### ETW (Event Tracing for Windows) Patch

Endpoint security 제품은 ETW에 크게 의존합니다. 2024년에 널리 사용된 evasion 기법은 메모리에서 `ntdll!EtwEventWrite`/`EtwEventWriteFull`을 patch하여 이벤트를 발생시키지 않고 모든 ETW 호출이 `STATUS_SUCCESS`를 반환하게 하는 것입니다:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoC(예: `EtwTiSwallow`)는 PowerShell 또는 C++로 동일한 primitive를 구현합니다.  
patch는 **process-local**이므로 다른 프로세스 내에서 실행되는 EDR은 이를 놓칠 수 있습니다.<sup>[[5]](#references)</sup>
탐지: 메모리의 `ntdll`과 디스크의 `ntdll`을 비교하거나 user-mode 진입 전에 hook을 설정합니다.

### Alternate Data Streams (ADS) 재부상

2023년 악성코드 캠페인(예: **FIN12** 로더)에서는 기존 스캐너의 눈을 피하기 위해 ADS 내부에 2단계 바이너리를 스테이징하는 사례가 발견되었습니다:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

`dir /R`, `Get-Item -Stream *` 또는 Sysinternals `streams64.exe`로 스트림을 열거합니다.
호스트 파일을 FAT/exFAT으로 복사하거나 SMB를 통해 복사하면 숨겨진 스트림이 제거되므로 조사관이 페이로드를 복구하는 데 사용할 수 있습니다.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver는 이제 랜섬웨어 침입에서 **anti-forensics** 목적으로 일상적으로 사용됩니다.  
오픈소스 도구 **AuKill**은 서명되었지만 취약한 드라이버(`procexp152.sys`)를 로드해 **암호화 및 로그 파괴 전에** EDR과 forensic sensor를 일시 중단하거나 종료합니다:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

드라이버는 이후 제거되어 흔적을 최소화합니다.<sup>[[1]](#references)</sup>  
완화 방법: Microsoft 취약 드라이버 차단 목록(HVCI/SAC)을 활성화하고,
사용자 쓰기 가능 경로에서 생성되는 커널 서비스를 경고하도록 설정합니다.

---

## Linux 안티포렌식: 셀프 패치 및 Cloud C2 (2023–2025)

### 탐지를 줄이기 위해 침해된 서비스를 셀프 패치 (Linux)
공격자는 재침해를 방지하고 취약점 기반 탐지를 억제하기 위해 서비스를 악용한 직후 점점 더 자주 “셀프 패치”합니다. 취약한 구성 요소를 최신 정식 upstream 바이너리/JAR로 교체하면, 지속성과 C2는 유지하면서 스캐너에는 호스트가 패치된 것으로 표시됩니다.<sup>[[3]](#references)</sup>

예: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- 공격자는 침해 후 Maven Central(repo1.maven.org)에서 정식 JAR을 가져와 ActiveMQ 설치 디렉터리의 취약한 JAR을 삭제한 다음 broker를 재시작했습니다.
- 이로써 초기 RCE는 차단하면서 cron, SSH 설정 변경, 별도의 C2 implant 등 다른 foothold는 유지했습니다.

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

법의학/헌팅 팁
- 서비스 디렉터리에서 예정에 없던 바이너리/JAR 교체를 검토합니다.
  - Debian/Ubuntu: `dpkg -V activemq`를 실행하고 파일 해시/경로를 저장소 미러와 비교합니다.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - 디스크에 있지만 패키지 관리자가 소유하지 않는 JAR 버전이나, 별도 절차 없이 업데이트된 심볼릭 링크를 찾습니다.
- 타임라인: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`를 실행해 ctime/mtime을 침해 발생 시간대와 대조합니다.
- 셸 기록/프로세스 텔레메트리: 최초 침해 직후 `repo1.maven.org` 또는 다른 아티팩트 CDN으로 `curl`/`wget`을 사용한 흔적을 찾습니다.
- 변경 관리: 패치된 버전이 있는지만 확인하지 말고, 누가 왜 “패치”를 적용했는지 검증합니다.

### Bearer token을 사용하는 Cloud 서비스 C2와 분석 방해 스테이저
관측된 tradecraft에는 여러 장기 C2 경로와 분석 방해 패키징이 함께 사용되었습니다:<sup>[[3]](#references)</sup>
- 샌드박싱과 정적 분석을 방해하기 위한 암호로 보호된 PyInstaller ELF 로더(예: 암호화된 PYZ, `/_MEI*` 아래 임시 추출).
  - 지표: `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS` 등의 `strings` 검색 결과.
  - 런타임 아티팩트: `/tmp/_MEI*` 또는 사용자 지정 `--runtime-tmpdir` 경로로 추출되는 흔적.
- 하드코딩된 OAuth Bearer token을 사용하는 Dropbox 기반 C2
  - 네트워크 흔적: `Authorization: Bearer <token>` 헤더가 포함된 `api.dropboxapi.com` / `content.dropboxapi.com` 요청.
  - 일반적으로 파일을 동기화하지 않는 서버 워크로드에서 Dropbox 도메인으로 나가는 HTTPS 트래픽을 프록시/NetFlow/Zeek/Suricata에서 탐지합니다.
- 터널링을 통한 병렬/백업 C2(예: Cloudflare Tunnel `cloudflared`)로 한 채널이 차단되어도 제어를 유지합니다.
  - 호스트 IOC: `cloudflared` 프로세스/유닛, `~/.cloudflared/*.json`의 설정, Cloudflare 엣지로 나가는 443 트래픽.

### 액세스 유지를 위한 지속성 및 “보안 강화 롤백”(Linux 예시)
공격자는 자가 패치와 지속성 있는 액세스 경로를 자주 함께 사용합니다:<sup>[[3]](#references)</sup>
- Cron/Anacron: 주기적 실행을 위해 각 `/etc/cron.*/` 디렉터리의 `0anacron` 스텁을 수정합니다.
  - 탐지:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH configuration hardening 되돌리기: root 로그인 활성화 및 권한이 낮은 계정의 기본 shell 변경.
  - root 로그인 활성화 여부 확인:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - 시스템 계정(예: `games`)에서 의심스러운 대화형 셸을 찾아보세요:
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- 무작위의 짧은 이름(알파벳 8자)을 가진 beacon artifacts로, 디스크에 생성되고 클라우드 C2에도 연결됨:
  - Hunt:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

방어자는 이러한 흔적을 외부 노출 및 서비스 패치 적용 이력과 연관 지어, 초기 침해를 숨기기 위해 사용된 anti-forensic 자체 복구를 밝혀내야 합니다.

## 정적으로 내장된 셸 실행

인터프리터와 명령 구현이 내장된 스크립트 래퍼는 `/bin/sh`와 별도의 유틸리티 프로세스를 실행하는 대신, 하나의 실행 파일 안에서 지원되는 셸 작업을 수행할 수 있습니다. HimitsuShell은 이러한 정적 musl 바이너리를 빌드합니다. [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md)와 달리, 내장 명령은 호스트 셸이나 별도의 유틸리티 프로세스를 시작할 필요가 없습니다. 지원되지 않는 명령은 시스템 셸로 넘길 수 있습니다.<sup>[[9]](#references)</sup>

이로 인해 셸 프로세스와 자식 `execve`의 가시성이 낮아집니다.<sup>[[9]](#references)</sup> 래퍼 프로세스와 그 시스템 호출은 커널 tracepoint를 통해 계속 관찰할 수 있으므로, 커널 추적에서도 보이지 않는다는 프로젝트의 주장을 문자 그대로 받아들여서는 안 됩니다.<sup>[[9]](#references)[[11]](#references)</sup>

문서에 안내된 x86_64 빌드에서는 입력 파일 이름을 `launcher.sh`로 유지하고, 컴파일하기 전에 컨테이너에 복사합니다. 출력 파일은 `safeLauncher`입니다.<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

공개 `compile.sh`는 script를 AES-256-CTR로 암호화하고, 만료 값과 중간 키/IV를 AES-256-CBC로 암호화한 다음, 암호화된 파일을 `xxd -i`로 C 배열로 변환하고 `-static -s` 옵션을 사용해 `lib.bc`와 링크합니다. 최종 암호화 키와 IV도 포함되므로, 이는 손쉬운 정적 추출을 막기 위한 조치일 뿐 절대로 복구할 수 없는 비밀은 아닙니다.<sup>[[10]](#references)</sup>

기본 LLVM 패스는 `-sobf`와 `-sub`입니다. 빌드하기 전에 `/var/work/compile.sh`를 수정하면 control-flow flattening(`fla`)이나 bogus control flow(`bcf`) 같은 문서화된 대안을 활성화할 수 있습니다.<sup>[[9]](#references)[[10]](#references)</sup>

이 wrapper에 의존하기 전에 script 호환성을 테스트하세요. 이 프로젝트는 POSIX shell 구문을 대상으로 하며 Bash/Zsh script가 실패할 수 있다고 경고하고, 내장 명령어 집합에 없는 명령은 시스템 shell을 호출한다고 설명합니다.<sup>[[9]](#references)</sup>

flattened control flow 분석은 [좁은 실행 슬라이스로 flattened control flow 우회하기](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice)를 참조하세요.

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: EDR 비활성화를 위한 무기화된 취약 드라이버 (2023년 3월)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – 은밀성을 위한 EtwEventWrite 패치: 탐지 및 헌팅 (2024년 6월)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – 지속성을 위한 패치: DripDropper Linux malware가 cloud를 이동하는 방식](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – 정상 소프트웨어에 삽입된 SectopRAT 변종 분석](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del 명령](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell 빌드 script](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux kernel 이벤트 히스토그램 및 syscall 추적](https://docs.kernel.org/trace/histogram.html)
