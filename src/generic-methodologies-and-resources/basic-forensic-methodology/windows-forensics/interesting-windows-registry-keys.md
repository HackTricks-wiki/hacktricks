# 興味深い Windows Registry キー

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry の hive は、_何が起きたのか？_ から _どのユーザーが、いつ、どこから行ったのか？_ へ pivot する最速の方法の一つです。live analysis では `CurrentControlSet` を優先し、offline hive analysis では `ControlSet001` をハードコードせず、まずどの `ControlSet00x` がアクティブだったかを解決してください。

### Windows のバージョンと所有者情報

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows の edition/build、インストール時刻、登録所有者、product name、その他の build metadata。
- `SYSTEM\Select`: `Current`、`Default`、`LastKnownGood` を、システムが使用した実際の `ControlSet00x` の値にマッピングします。

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 現在の hostname。

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 設定された time zone と DST 関連の値。

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` は、NTFS の最終アクセス timestamp が更新されているかどうかを示します。
- 有効にするには、次を使用します: `fsutil behavior set disablelastaccess 0`

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: 最終 shutdown 時刻。
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: 古いシステムでは shutdown counter も確認できる場合があります。

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface の IP、DHCP lease、gateway、DNS data。<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID、および最初と最後の接続時刻。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` および `...\Unmanaged\{GUID}`: gateway MAC address や DNS suffix などの profile correlation data。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host が公開しているローカル shared folder。

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list（`MRU0`..`MRU9`）。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: host ごとの outbound RDP history。subkey には通常 `UsernameHint` が保存され、key の `LastWrite` time は有用な pivot になります。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 特定のユーザーに紐づく mapped network drive、UNC share、removable-media mount point。

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` および `...\Tasks\{GUID}`: scheduled task metadata。ここに task が存在するにもかかわらず、`Tree\<TaskName>` に `SD` value がない場合は、Tarrask-style の hidden task tampering を疑い、`C:\Windows\System32\Tasks\<TaskName>` と相関させてください。

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer の search term。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer に手動入力された path。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 最後の 26 個の `Win + R` command。`MRUList` はその順序を保持します。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 最近開かれた document と folder。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office の recent file。

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI 経由の execution history。value name は ROT13 で encode され、binary data には run counter と最終実行時刻が含まれます。<sup>[[1]](#references)</sup>
- `UserAssist` は standalone verdict ではなく、強力な supporting evidence として扱ってください。主に Explorer 経由で起動された app や `.lnk` file を追跡するため、command-line や service による実行を見逃すことがあります。Windows 10 以降では、一部の entry は必ずしも process が完全に実行されたことを意味しません。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` および `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution と最終実行時刻を含む、modern Windows 10/11 の execution trace。これらはローカルで実行された binary に特に有用ですが、古い entry はすぐに expire する可能性があり、network share/removable media からの実行は信頼性が低くなります。
- Prefetch、Amcache、ShimCache、SRUM などのより広範な execution artifact については、メインの [Windows forensics overview](README.md#programs-executed) を参照してください。

### Shellbags

- Shellbags は `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` と `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` の両方に保存されます。<sup>[[1]](#references)</sup>
- `NTUSER.DAT` entry は UNC/network browsing に特に有用であり、`UsrClass.dat` は Windows Vista 以降で local/removable-folder shellbag を保存する一般的な場所です。
- folder が削除された後でも、folder の存在、traversal、folder-view preference を示すことがあります。archive file への Explorer-like access も shellbag trace を残す場合があります。<sup>[[1]](#references)</sup>
- すべての shellbag が folder への successful access を証明するわけではないため、LNK、Jump List、timestamp、volume mapping と corroborate してください。
- **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** または **SBECmd** を使用して parse できます。

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage device の primary inventory（vendor、product、revision、serial/device instance）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage device を含む、より広範な USB device inventory。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: recent Windows 10/11 build では、install、first install、last arrival、last removal など、device ごとの lifecycle timestamp を確認できる high-value spot です。<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volume と device identifier を drive letter / volume GUID にマッピングします。特定の drive letter については、最後の mapping だけが残る場合があります。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number と過去の media metadata への有用な pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific な drive-letter および share interaction history。<sup>[[2]](#references)</sup>
- MTP/PTP 経由で接続された modern phone や tablet は、`USBSTOR` の下に表示されない場合があります。`HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` と `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` も確認してください。<sup>[[2]](#references)</sup>
- device を user に紐づけるには、device または volume identifier から、shellbag、LNK、Jump List、`RecentDocs`、`MountPoints2` などの per-user artifact へ pivot してください。<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
