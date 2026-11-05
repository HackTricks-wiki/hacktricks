# 흥미로운 Windows 레지스트리 키

{{#include ../../../banners/hacktricks-training.md}}

Windows 레지스트리 하이브는 _무슨 일이 있었나?_라는 질문에서 _어떤 사용자가, 언제, 어디에서?_라는 질문으로 빠르게 넘어가는 데 유용합니다. 라이브 분석에서는 `CurrentControlSet`을 사용하고, 오프라인 하이브를 분석할 때는 `ControlSet001`을 하드코딩하지 말고 먼저 활성 `ControlSet00x`가 무엇인지 확인하세요.

### Windows 버전 및 소유자 정보

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows 에디션/빌드, 설치 시간, 등록된 소유자, 제품 이름 및 기타 빌드 메타데이터입니다.
- `SYSTEM\Select`: `Current`, `Default`, `LastKnownGood`을 시스템에서 사용하는 실제 `ControlSet00x` 값에 매핑합니다.

### 컴퓨터 이름

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 현재 호스트 이름입니다.

### 시간대 설정

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 설정된 시간대 및 DST 관련 값입니다.

### 액세스 시간 추적

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`는 NTFS 마지막 액세스 타임스탬프가 업데이트되는지 나타냅니다.
- 활성화하려면 다음을 사용합니다: `fsutil behavior set disablelastaccess 0`

### 종료 세부 정보

- `SYSTEM\CurrentControlSet\Control\Windows`: 마지막 종료 시간입니다.
- 구형 시스템에서는 `SYSTEM\CurrentControlSet\Control\Watchdog\Display`에도 종료 카운터가 있을 수 있습니다.

### 네트워크 구성

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: 인터페이스 IP, DHCP 임대, 게이트웨이 및 DNS 데이터입니다.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: 네트워크 프로필 이름/SSID와 최초 및 마지막 연결 시간입니다.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 및 `...\Unmanaged\{GUID}`: 게이트웨이 MAC 주소와 DNS 접미사 등 프로필 상관관계 데이터입니다.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: 호스트에서 게시한 로컬 공유 폴더입니다.

### 원격 액세스 및 네트워크 공유 기록

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: 발신 RDP MRU 목록(`MRU0`..`MRU9`)입니다.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: 호스트별 발신 RDP 기록입니다. 하위 키에는 일반적으로 `UsernameHint`가 저장되며, 키의 `LastWrite` 시간도 유용한 단서입니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 특정 사용자와 연결된 매핑된 네트워크 드라이브, UNC 공유 및 이동식 미디어 마운트 지점입니다.

### 자동 시작 프로그램 및 예약된 지속성

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 및 `...\Tasks\{GUID}`: 예약된 작업 메타데이터입니다. 여기에 작업이 있지만 `Tree\<TaskName>`에 `SD` 값이 없다면, 숨겨진 Tarrask 스타일의 작업 변조를 의심하고 `C:\Windows\System32\Tasks\<TaskName>`과 대조하세요.

### 검색, 입력한 경로 및 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer 검색어입니다.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer에 직접 입력한 경로입니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 마지막 26개의 `Win + R` 명령입니다. `MRUList`에 명령 순서가 저장됩니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 최근에 연 문서 및 폴더입니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office 최근 파일입니다.

### 사용자 활동 추적

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI를 통해 실행된 기록입니다. 값 이름은 ROT13으로 인코딩되며, 바이너리 데이터에는 실행 횟수와 마지막 실행 시간이 포함됩니다.<sup>[[1]](#references)</sup>
- `UserAssist`는 단독으로 결론을 내리는 근거가 아니라 강력한 보조 증거로 취급하세요. 주로 Explorer를 통해 실행된 앱이나 `.lnk` 파일을 추적하며, 명령줄 또는 서비스 실행은 놓칠 수 있습니다. Windows 10 이상에서는 일부 항목이 프로세스가 완전히 실행되었음을 반드시 의미하지는 않습니다.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 및 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID 및 마지막 실행 시간이 기록된 최신 Windows 10/11 실행 흔적입니다. 로컬에서 실행된 바이너리를 조사하는 데 특히 유용하지만, 오래된 항목은 빠르게 사라질 수 있고 네트워크 공유/이동식 미디어에서의 실행 기록은 신뢰도가 낮습니다.
- Prefetch, Amcache, ShimCache 및 SRUM과 같은 더 광범위한 실행 아티팩트는 [Windows forensics overview](./#programs-executed)를 참조하세요.

### Shellbags

- Shellbags는 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`와 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`에 모두 저장됩니다.<sup>[[1]](#references)</sup>
- `NTUSER.DAT` 항목은 UNC/네트워크 탐색 기록을 확인하는 데 특히 유용하며, Windows Vista 이상에서는 일반적으로 `UsrClass.dat`에 로컬/이동식 폴더 shellbags가 저장됩니다.
- 폴더가 삭제된 후에도 폴더의 존재, 탐색 및 폴더 보기 기본 설정을 확인할 수 있습니다. Explorer와 유사한 방식으로 아카이브 파일에 접근한 경우에도 shellbag 흔적이 남을 수 있습니다.<sup>[[1]](#references)</sup>
- 모든 shellbag이 폴더에 성공적으로 접근했음을 입증하는 것은 아니므로 LNK, Jump Lists, 타임스탬프 또는 볼륨 매핑으로 교차 확인하세요.
- **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 또는 **SBECmd**를 사용해 파싱하세요.

### USB 정보

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB 대용량 저장 장치의 기본 목록입니다(제조업체, 제품, 리비전, 일련 번호/장치 인스턴스).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: 저장 장치가 아닌 장치를 포함한 더 광범위한 USB 장치 목록입니다.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: 최신 Windows 10/11 빌드에서 설치, 최초 설치, 마지막 연결 및 마지막 제거와 같은 장치별 수명 주기 타임스탬프를 확인할 수 있는 중요한 위치입니다.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: 볼륨과 장치 식별자를 드라이브 문자/볼륨 GUID에 매핑합니다. 특정 드라이브 문자의 마지막 매핑만 남을 수 있습니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: 볼륨 일련 번호 및 이전 미디어 메타데이터를 확인하는 데 유용한 단서입니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 사용자별 드라이브 문자 및 공유 접근 기록입니다.<sup>[[2]](#references)</sup>
- MTP/PTP로 연결된 최신 휴대폰과 태블릿은 `USBSTOR`에 나타나지 **않을 수 있습니다**. `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM`과 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`도 확인하세요.<sup>[[2]](#references)</sup>
- 장치를 사용자와 연결하려면 장치 또는 볼륨 식별자에서 shellbags, LNK, Jump Lists, `RecentDocs` 및 `MountPoints2`와 같은 사용자별 아티팩트로 추적하세요.<sup>[[2]](#references)</sup>



## References

- [1] [Windows 레지스트리 포렌식 치트 시트 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Windows 10 및 11의 USB 장치 포렌식 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
