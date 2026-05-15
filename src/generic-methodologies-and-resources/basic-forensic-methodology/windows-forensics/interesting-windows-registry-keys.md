# Interessante Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hives is een van die vinnigste maniere om te pivoteer van _wat het gebeur?_ na _watter user, wanneer, en van waar af?_. Vir live analysis verkies `CurrentControlSet`; vir offline hive analysis los eers op watter `ControlSet00x` aktief was eerder as om `ControlSet001` hard te kodeer.

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build, install time, registered owner, product name, en ander build metadata.
- `SYSTEM\Select`: map `Current`, `Default`, en `LastKnownGood` na die werklike `ControlSet00x` values wat deur die system gebruik word.

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: current hostname.

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: configured time zone en DST-related values.

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` dui aan of NTFS last-access timestamps opgedateer word.
- Om dit te enable, use: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: last shutdown time.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: older systems may also expose shutdown counters.

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface IPs, DHCP leases, gateway en DNS data.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID plus first en last connection times.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` en `...\Unmanaged\{GUID}`: profile correlation data such as gateway MAC address en DNS suffix.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: local shared folders published by the host.

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: per-host outbound RDP history. Subkeys commonly store `UsernameHint`, en die key `LastWrite` time is a useful pivot.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: mapped network drives, UNC shares, en removable-media mount points tied to a specific user.

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` en `...\Tasks\{GUID}`: scheduled task metadata. If a task exists here but die `SD` value is missing from `Tree\<TaskName>`, suspect hidden Tarrask-style task tampering en correlate it with `C:\Windows\System32\Tasks\<TaskName>`.

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer search terms.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: manually typed Explorer paths.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: die laaste 26 `Win + R` commands. `MRUList` preserve their order.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: recently opened documents and folders.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office recent files.

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution history. Value names are ROT13-encoded, en die binary data includes run counters en last run time.
- Treat `UserAssist` as strong supporting evidence, not a standalone verdict: it mainly tracks apps or `.lnk` files launched through Explorer en can miss command-line or service execution. On Windows 10+, some entries do not necessarily mean the process fully ran.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` en `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: modern Windows 10/11 execution traces with SID attribution en last execution time. These are especially useful for locally executed binaries, but older entries can age out quickly en executions from network shares/removable media are less reliable.
- For broader execution artifacts such as Prefetch, Amcache, ShimCache, en SRUM, see the main [Windows forensics overview](README.md#programs-executed).

### Shellbags

- Shellbags are stored in both `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` en `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- `NTUSER.DAT` entries are especially useful for UNC/network browsing, while `UsrClass.dat` is where Windows Vista+ commonly stores local/removable-folder shellbags.
- They can show folder existence, traversal, en folder-view preferences even after the folder was deleted. Explorer-like access to archive files can also leave shellbag traces.
- Not every shellbag proves successful folder access, so corroborate with LNKs, Jump Lists, timestamps, or volume mappings.
- Use **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** or **SBECmd** to parse them.

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: primary inventory of USB mass-storage devices (vendor, product, revision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: broader USB device inventory, including non-storage devices.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: on recent Windows 10/11 builds this is a high-value spot for per-device lifecycle timestamps such as install, first install, last arrival, en last removal.
- `HKLM\SYSTEM\MountedDevices`: maps volumes en device identifiers to drive letters / volume GUIDs. Only the last mapping for a given drive letter may survive.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: useful pivot for volume serial numbers en previous media metadata.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific drive-letter en share interaction history.
- Modern phones and tablets connected via MTP/PTP may **not** appear under `USBSTOR`. Check `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` en `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` as well.
- To tie a device to a user, pivot from device or volume identifiers into per-user artifacts such as shellbags, LNKs, Jump Lists, `RecentDocs`, en `MountPoints2`.



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
