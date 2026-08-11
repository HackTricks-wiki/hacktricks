# 흥미로운 Windows 레지스트리 키

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry 하이브는 _무슨 일이 발생했는가?_에서 _어떤 사용자, 언제, 어디에서 발생했는가?_로 전환하는 가장 빠른 방법 중 하나입니다. 라이브 분석에서는 `CurrentControlSet`을 우선 사용하고, 오프라인 하이브 분석에서는 `ControlSet001`을 하드코딩하지 말고 먼저 어떤 `ControlSet00x`가 활성 상태였는지 확인해야 합니다.

### Windows 버전 및 소유자 정보

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows 에디션/빌드, 설치 시간, 등록된 소유자, 제품명 및 기타 빌드 메타데이터.
- `SYSTEM\Select`: `Current`, `Default`, `LastKnownGood`를 시스템에서 사용한 실제 `ControlSet00x` 값에 매핑합니다.

### 컴퓨터 이름

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 현재 호스트 이름.

### 시간대 설정

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 구성된 시간대 및 DST 관련 값.

### 액세스 시간 추적

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`는 NTFS 마지막 액세스 타임스탬프가 업데이트되는지 나타냅니다.
- 활성화하려면 다음을 사용합니다: `fsutil behavior set disablelastaccess 0`

### 종료 세부 정보

- `SYSTEM\CurrentControlSet\Control\Windows`: 마지막 종료 시간.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: 이전 시스템에서는 종료 카운터도 표시될 수 있습니다.

### 네트워크 구성

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: 인터페이스 IP, DHCP lease, gateway 및 DNS 데이터.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: 네트워크 프로필 이름/SSID와 최초 및 마지막 연결 시간.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 및 `...\Unmanaged\{GUID}`: gateway MAC 주소 및 DNS suffix와 같은 프로필 상관관계 데이터.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: 호스트가 게시한 로컬 shared folder.

### 원격 액세스 및 네트워크 share 기록

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU 목록(`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: 호스트별 outbound RDP 기록. 하위 키에는 일반적으로 `UsernameHint`가 저장되며, 키의 `LastWrite` 시간은 유용한 pivot입니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 특정 사용자에 연결된 mapped network drive, UNC share 및 removable-media mount point.

### 자동으로 시작되는 프로그램 및 예약된 persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 및 `...\Tasks\{GUID}`: scheduled task 메타데이터. 여기에 task가 존재하지만 `SD` 값이 `Tree\<TaskName>`에서 누락되어 있다면, 숨겨진 Tarrask-style task tampering을 의심하고 `C:\Windows\System32\Tasks\<TaskName>`와 상관관계를 분석합니다.

### 검색, 입력한 경로 및 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer 검색어.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer에 수동으로 입력한 경로.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 마지막 26개의 `Win + R` 명령. `MRUList`가 해당 순서를 보존합니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 최근에 연 문서 및 폴더.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office 최근 파일.

### 사용자 활동 추적

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI를 통한 실행 기록. 값 이름은 ROT13으로 인코딩되며, binary data에는 실행 카운터와 마지막 실행 시간이 포함됩니다.<sup>[[1]](#references)</sup>
- `UserAssist`를 단독 결론이 아닌 강력한 보조 증거로 취급해야 합니다. 주로 Explorer를 통해 실행된 앱 또는 `.lnk` 파일을 추적하며, command-line 또는 service 실행은 누락될 수 있습니다. Windows 10 이상에서는 일부 항목이 process가 완전히 실행되었음을 반드시 의미하지는 않습니다.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 및 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution 및 마지막 실행 시간이 포함된 최신 Windows 10/11 실행 trace. 로컬에서 실행된 binary에 특히 유용하지만, 오래된 항목은 빠르게 만료될 수 있으며 network share/removable media에서의 실행은 신뢰도가 낮습니다.
- Prefetch, Amcache, ShimCache 및 SRUM과 같은 보다 광범위한 실행 artifact는 기본 [Windows forensics overview](README.md#programs-executed)를 참조하십시오.

### Shellbags

- Shellbags는 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`와 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 양쪽에 저장됩니다.<sup>[[1]](#references)</sup>
- `NTUSER.DAT` 항목은 UNC/network browsing에 특히 유용하며, `UsrClass.dat`는 Windows Vista 이상에서 local/removable-folder shellbags가 일반적으로 저장되는 위치입니다.
- 폴더가 삭제된 후에도 폴더의 존재, 탐색 및 folder-view preference를 보여줄 수 있습니다. archive file에 대한 Explorer 유사 액세스도 shellbag trace를 남길 수 있습니다.<sup>[[1]](#references)</sup>
- 모든 shellbag이 성공적인 폴더 액세스를 입증하는 것은 아니므로 LNK, Jump List, timestamp 또는 volume mapping과 corroborate해야 합니다.
- **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 또는 **SBECmd**를 사용하여 parse하십시오.

### USB 정보

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage device의 기본 inventory(공급업체, 제품, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage device를 포함한 보다 광범위한 USB device inventory.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: 최신 Windows 10/11 build에서는 install, first install, last arrival 및 last removal과 같은 device별 lifecycle timestamp를 확인할 수 있는 고가치 위치입니다.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volume 및 device identifier를 drive letter / volume GUID에 매핑합니다. 특정 drive letter에 대한 마지막 mapping만 남을 수 있습니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number 및 이전 media 메타데이터로 pivot하는 데 유용합니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 사용자별 drive-letter 및 share interaction 기록.<sup>[[2]](#references)</sup>
- MTP/PTP를 통해 연결된 최신 phone 및 tablet은 `USBSTOR` 아래에 표시되지 **않을** 수 있습니다. `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` 및 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`도 확인하십시오.<sup>[[2]](#references)</sup>
- device를 사용자와 연결하려면 device 또는 volume identifier에서 shellbag, LNK, Jump List, `RecentDocs` 및 `MountPoints2`와 같은 사용자별 artifact로 pivot하십시오.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Windows 10 및 11의 USB Device Forensics - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
