# Interesting Windows Registry Keys

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive は、_何が起きたか?_ から _どの user が、いつ、どこから?_ へ最速で絞り込むための手段の1つです。ライブ解析では `CurrentControlSet` を優先し、オフライン hive 解析では `ControlSet001` をハードコードせず、まずどの `ControlSet00x` が有効だったかを解決してください。

### Windows Version and Owner Info

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows edition/build、インストール時刻、registered owner、product name、その他の build metadata。
- `SYSTEM\Select`: `Current`、`Default`、`LastKnownGood` を、システムで使われていた実際の `ControlSet00x` 値に対応付けます。

### Computer Name

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 現在の hostname。

### Time Zone Setting

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 設定された time zone と DST 関連の値。

### Access Time Tracking

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` は、NTFS の last-access タイムスタンプが更新されているかを示します。
- 有効にするには、`fsutil behavior set disablelastaccess 0` を使います。

### Shutdown Details

- `SYSTEM\CurrentControlSet\Control\Windows`: 最後の shutdown time。
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: 古いシステムでは shutdown counter も確認できる場合があります。

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface の IP、DHCP lease、gateway、DNS データ。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile name/SSID と最初・最後の接続時刻。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` と `...\Unmanaged\{GUID}`: gateway MAC address や DNS suffix などの profile correlation data。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host が公開している local shared folders。

### Remote Access and Network Share History

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list (`MRU0`..`MRU9`)。
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: ホストごとの outbound RDP 履歴。Subkey には通常 `UsernameHint` が保存され、key の `LastWrite` time は有用な pivot です。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 特定 user に紐づく mapped network drives、UNC shares、removable-media mount points。

### Programs that Start Automatically and Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` と `...\Tasks\{GUID}`: scheduled task metadata。ここに task が存在するのに `Tree\<TaskName>` から `SD` 値が欠けている場合は、hidden Tarrask-style task tampering を疑い、`C:\Windows\System32\Tasks\<TaskName>` と照合してください。

### Searches, Typed Paths, and MRUs

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer の search term。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: 手動で入力された Explorer path。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 直近26件の `Win + R` command。`MRUList` が順序を保持します。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 最近開いた documents と folders。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office の recent files。

### User Activity Tracking

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI-driven execution history。Value name は ROT13 でエンコードされ、binary data には run counter と last run time が含まれます。
- `UserAssist` は単独の断定材料ではなく、強い補助証拠として扱ってください。主に Explorer 経由で起動された app や `.lnk` file を追跡し、command-line や service execution を見逃すことがあります。Windows 10+ では、一部の entry が process の完全な実行を必ずしも意味しません。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` と `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution と last execution time を含む、Windows 10/11 の modern execution trace。ローカル実行された binary の把握に特に有用ですが、古い entry はすぐに消えることがあり、network share や removable media からの実行は信頼性が低めです。
- Prefetch、Amcache、ShimCache、SRUM などのより広い execution artifact については、メインの [Windows forensics overview](README.md#programs-executed) を参照してください。

### Shellbags

- Shellbags は `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` と `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` の両方に保存されます。
- `NTUSER.DAT` の entry は UNC/network browsing に特に有用で、`UsrClass.dat` は Windows Vista+ が local/removable-folder shellbags を一般的に保存する場所です。
- フォルダが削除された後でも、folder の存在、移動、folder-view preferences を示せます。archive file への Explorer-like access も shellbag trace を残すことがあります。
- すべての shellbag が folder への成功したアクセスを証明するわけではないため、LNK、Jump Lists、timestamps、volume mappings と照合してください。
- 解析には **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** または **SBECmd** を使います。

### USB Information

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage device の primary inventory (vendor、product、revision、serial/device instance)。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage device を含む、より広い USB device inventory。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: 最近の Windows 10/11 build では、install、first install、last arrival、last removal などの per-device lifecycle timestamp を得られる重要な場所です。
- `HKLM\SYSTEM\MountedDevices`: volume と device identifier を drive letter / volume GUID に対応付けます。特定の drive letter については最後の mapping だけが残る場合があります。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number と過去の media metadata への有用な pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: user-specific な drive-letter と share の interaction history。
- MTP/PTP 経由で接続された modern phone や tablet は `USBSTOR` に現れない**場合があります**。`HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` と `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` も確認してください。
- device を user に結び付けるには、device や volume identifier から shellbags、LNKs、Jump Lists、`RecentDocs`、`MountPoints2` などの per-user artifact に pivot します。



## References

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
