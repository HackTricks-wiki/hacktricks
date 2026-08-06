# 흥미로운 Windows Registry 키

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive는 _무슨 일이 발생했는가?_에서 _어떤 사용자가, 언제, 어디에서 발생시켰는가?_로 가장 빠르게 pivot할 수 있는 방법 중 하나입니다. live analysis에서는 `CurrentControlSet`을 우선 사용하고, offline hive analysis에서는 `ControlSet001`을 하드코딩하지 말고 먼저 어떤 `ControlSet00x`가 활성 상태였는지 확인해야 합니다.

### Windows 버전 및 소유자 정보

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, 설치 시간, 등록된 소유자, product name 및 기타 build metadata.
- `SYSTEM\Select`: `Current`, `Default`, `LastKnownGood`를 시스템에서 사용한 실제 `ControlSet00x` 값에 매핑합니다.

### 컴퓨터 이름

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 현재 hostname.

### Time Zone 설정

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 구성된 time zone 및 DST 관련 값.

### Access Time 추적

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`는 NTFS last-access timestamp가 업데이트되는지 나타냅니다.
- 활성화하려면 다음을 사용합니다: `fsutil behavior set disablelastaccess 0`

### Shutdown 세부 정보

- `SYSTEM\CurrentControlSet\Control\Windows`: 마지막 shutdown 시간.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: 이전 시스템에서는 shutdown counter도 노출될 수 있습니다.

### Network 구성

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IP, DHCP lease, gateway 및 DNS data.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID 및 최초와 마지막 connection 시간.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` 및 `...\Unmanaged\{GUID}`: gateway MAC address 및 DNS suffix와 같은 profile correlation data.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host가 publish한 local shared folder.

### Remote Access 및 Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: host별 outbound RDP history. Subkey에는 일반적으로 `UsernameHint`가 저장되며, key의 `LastWrite` 시간은 유용한 pivot입니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 특정 사용자에게 연결된 mapped network drive, UNC share 및 removable-media mount point.

### 자동 시작 프로그램 및 Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` 및 `...\Tasks\{GUID}`: scheduled task metadata. 여기에 task가 존재하지만 `Tree\<TaskName>`에서 `SD` value가 누락된 경우, 숨겨진 Tarrask-style task tampering을 의심하고 `C:\Windows\System32\Tasks\<TaskName>`와 correlation해야 합니다.

### Search, Typed Path 및 MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer search term.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer에 수동으로 입력한 path.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 마지막 26개의 `Win + R` command. `MRUList`는 순서를 보존합니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 최근에 연 document 및 folder.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent file.

### User Activity 추적

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI 기반 execution history. Value name은 ROT13으로 encoding되어 있으며, binary data에는 run counter 및 마지막 run 시간이 포함됩니다.<sup>[[1]](#references)</sup>
- `UserAssist`는 standalone verdict가 아니라 강력한 supporting evidence로 취급해야 합니다. 주로 Explorer를 통해 실행된 app 또는 `.lnk` file을 추적하므로 command-line 또는 service execution을 놓칠 수 있습니다. Windows 10 이상에서는 일부 entry가 process가 실제로 완전히 실행되었다는 의미가 아닐 수 있습니다.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` 및 `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution 및 마지막 execution 시간이 포함된 최신 Windows 10/11 execution trace. 이는 local에서 실행된 binary에 특히 유용하지만, 오래된 entry는 빠르게 age out될 수 있으며 network share/removable media에서의 execution은 신뢰도가 낮습니다.
- Prefetch, Amcache, ShimCache 및 SRUM과 같은 더 광범위한 execution artifact는 주요 [Windows forensics overview](README.md#programs-executed)를 참조하십시오.

### Shellbag

- Shellbag은 `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 및 `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` 양쪽에 저장됩니다.<sup>[[1]](#references)</sup>
- `NTUSER.DAT` entry는 UNC/network browsing에 특히 유용하며, Windows Vista 이상에서는 local/removable-folder shellbag이 일반적으로 `UsrClass.dat`에 저장됩니다.
- folder가 삭제된 후에도 folder의 존재, traversal 및 folder-view preference를 보여줄 수 있습니다. archive file에 대한 Explorer와 유사한 access도 shellbag trace를 남길 수 있습니다.<sup>[[1]](#references)</sup>
- 모든 shellbag이 성공적인 folder access를 입증하는 것은 아니므로 LNK, Jump List, timestamp 또는 volume mapping과 corroborate해야 합니다.
- 이를 parse하려면 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 또는 **SBECmd**를 사용하십시오.

### USB 정보

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage device의 주요 inventory (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage device를 포함한 더 광범위한 USB device inventory.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: 최신 Windows 10/11 build에서는 install, first install, last arrival 및 last removal과 같은 device별 lifecycle timestamp를 확인할 수 있는 high-value 지점입니다.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volume 및 device identifier를 drive letter / volume GUID에 매핑합니다. 특정 drive letter에 대한 마지막 mapping만 남을 수 있습니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number 및 이전 media metadata로 pivot하는 데 유용합니다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user별 drive-letter 및 share interaction history.<sup>[[2]](#references)</sup>
- MTP/PTP를 통해 연결된 최신 phone 및 tablet은 `USBSTOR` 아래에 나타나지 **않을 수 있습니다**. `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` 및 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`도 확인하십시오.<sup>[[2]](#references)</sup>
- device를 user와 연결하려면 device 또는 volume identifier에서 shellbag, LNK, Jump List, `RecentDocs` 및 `MountPoints2`와 같은 per-user artifact로 pivot하십시오.<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
