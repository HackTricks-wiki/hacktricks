# 흥미로운 Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive는 _무슨 일이 일어났나?_에서 _어떤 user가, 언제, 어디서?_로 가장 빠르게 pivot하는 방법 중 하나다. live analysis에서는 `CurrentControlSet`를 우선 사용하고, offline hive analysis에서는 `ControlSet001`을 hardcoding하지 말고 먼저 어떤 `ControlSet00x`가 active였는지 resolve하라.

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name, and other build metadata.
- `SYSTEM\Select`: `Current`, `Default`, 그리고 `LastKnownGood`를 system이 사용한 실제 `ControlSet00x` 값에 매핑한다.

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: current hostname.

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: configured time zone and DST-related values.

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate`는 NTFS last-access timestamps가 업데이트되는지 여부를 나타낸다.
- 이를 enable하려면: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: last shutdown time.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: older systems may also expose shutdown counters.

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IPs, DHCP leases, gateway and DNS data.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID plus first and last connection times.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` and `...\Unmanaged\{GUID}`: gateway MAC address and DNS suffix 같은 profile correlation data.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host가 공개한 local shared folders.

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: per-host outbound RDP history. Subkeys commonly store `UsernameHint`, and the key `LastWrite` time is a useful pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 특정 user에 연결된 mapped network drives, UNC shares, 및 removable-media mount points.

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` and `...\Tasks\{GUID}`: scheduled task metadata. 여기에는 task가 존재하지만 `Tree\<TaskName>`에서 `SD` 값이 없다면, hidden Tarrask-style task tampering을 의심하고 `C:\Windows\System32\Tasks\<TaskName>`와 연관시켜라.

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer search terms.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manually typed Explorer paths.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 마지막 26개의 `Win + R` commands. `MRUList`는 순서를 보존한다.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: recently opened documents and folders.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent files.

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution history. Value names are ROT13-encoded, and the binary data includes run counters and last run time.
- `UserAssist`는 standalone verdict가 아니라 강한 supporting evidence로 다뤄라: 주로 Explorer를 통해 실행된 apps나 `.lnk` files를 추적하며, command-line이나 service execution은 놓칠 수 있다. Windows 10+에서는 일부 항목이 process가 완전히 실행되었다는 뜻은 아닐 수도 있다.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` and `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution과 last execution time이 포함된 modern Windows 10/11 execution traces. 이는 locally executed binaries에 특히 유용하지만, older entries는 빨리 age out될 수 있고 network shares/removable media에서의 executions는 신뢰도가 더 낮다.
- Prefetch, Amcache, ShimCache, 그리고 SRUM 같은 broader execution artifacts는 main [Windows forensics overview](README.md#programs-executed)를 참고하라.

### Shellbags

- Shellbags are stored in both `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` and `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- `NTUSER.DAT` entries are especially useful for UNC/network browsing, while `UsrClass.dat` is where Windows Vista+ commonly stores local/removable-folder shellbags.
- 폴더가 삭제된 뒤에도 folder existence, traversal, 그리고 folder-view preferences를 보여줄 수 있다. archive files에 대한 Explorer-like access도 shellbag traces를 남길 수 있다.
- 모든 shellbag이 성공적인 folder access를 증명하는 것은 아니므로, LNKs, Jump Lists, timestamps, 또는 volume mappings와 corroborate하라.
- 이를 parse하려면 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** 또는 **SBECmd**를 사용하라.

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage devices의 primary inventory (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage devices를 포함한 더 넓은 USB device inventory.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: recent Windows 10/11 builds에서는 install, first install, last arrival, last removal 같은 per-device lifecycle timestamps를 얻기에 매우 가치가 높은 위치다.
- `HKLM\SYSTEM\MountedDevices`: volume과 device identifiers를 drive letters / volume GUIDs에 매핑한다. 각 drive letter에 대해 마지막 mapping만 남을 수 있다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial numbers와 previous media metadata를 위한 useful pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific drive-letter 및 share interaction history.
- MTP/PTP로 연결된 modern phones and tablets는 `USBSTOR` 아래에 **나타나지 않을 수 있다**. `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM`와 `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`도 확인하라.
- device를 user와 연결하려면, device 또는 volume identifiers에서 shellbags, LNKs, Jump Lists, `RecentDocs`, `MountPoints2` 같은 per-user artifacts로 pivot하라.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
