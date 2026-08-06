# 興味深い Windows Registry キー

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive は、_何が起きたか？_ から _どのユーザーが、いつ、どこから行ったか？_ へ pivot する最も迅速な方法の一つです。ライブ分析では `CurrentControlSet` を優先し、offline hive 分析では `ControlSet001` を固定的に使用せず、まずどの `ControlSet00x` がアクティブだったかを解決してください。

### Windows バージョンと所有者情報

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows のエディション/build、インストール時刻、登録所有者、製品名、その他の build メタデータ。
- `SYSTEM\Select`: `Current`、`Default`、`LastKnownGood` を、システムで使用された実際の `ControlSet00x` 値に対応付けます。

### コンピューター名

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 現在の hostname。

### タイムゾーン設定

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 設定されたタイムゾーンおよび DST 関連の値。

### アクセス時刻の追跡

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` は、NTFS の最終アクセス timestamp が更新されているかどうかを示します。
- 有効にするには、次を使用します: `fsutil behavior set disablelastaccess 0`

### シャットダウンの詳細

- `SYSTEM\CurrentControlSet\Control\Windows`: 最終シャットダウン時刻。
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: 古いシステムでは、シャットダウン counter も公開されている場合があります。

### Network Configuration

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: interface の IP、DHCP lease、gateway、DNS データ。<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: network profile 名/SSID、および最初と最後の接続時刻。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` および `...\Unmanaged\{GUID}`: gateway MAC address や DNS suffix などの profile 相関データ。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: host が公開しているローカル共有 folder。

### Remote Access と Network Share の履歴

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: outbound RDP MRU list（`MRU0`～`MRU9`）。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: host ごとの outbound RDP 履歴。subkey には通常 `UsernameHint` が保存され、key の `LastWrite` 時刻は有用な pivot になります。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 特定のユーザーに紐付いた mapped network drive、UNC share、removable-media mount point。

### 自動的に起動するプログラムと Scheduled Persistence

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` および `...\Tasks\{GUID}`: scheduled task のメタデータ。ここに task が存在するにもかかわらず、`Tree\<TaskName>` に `SD` value がない場合は、隠し Tarrask-style task tampering を疑い、`C:\Windows\System32\Tasks\<TaskName>` と相関させてください。

### 検索、入力されたパス、MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer の検索語。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer に手動で入力された path。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 直近 26 件の `Win + R` command。`MRUList` はそれらの順序を保持します。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 最近開かれた document と folder。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office の最近使用した file。

### ユーザーアクティビティの追跡

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI による実行履歴。value name は ROT13 で encode され、binary data には run counter と最終実行時刻が含まれます。<sup>[[1]](#references)</sup>
- `UserAssist` は単独の判断材料ではなく、強力な補強証拠として扱ってください。主に Explorer 経由で起動された app または `.lnk` file を追跡するため、command-line や service による実行を見落とす可能性があります。Windows 10 以降では、一部の entry は必ずしも process が完全に実行されたことを意味しません。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` および `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID attribution と最終実行時刻を含む、modern Windows 10/11 の実行 trace。これらはローカルで実行された binary に特に有用ですが、古い entry は短時間で age out する可能性があり、network share/removable media からの実行については信頼性が低くなります。
- Prefetch、Amcache、ShimCache、SRUM など、より広範な実行 artifact については、メインの [Windows forensics overview](README.md#programs-executed) を参照してください。

### Shellbags

- Shellbags は `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` と `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` の両方に保存されます。<sup>[[1]](#references)</sup>
- `NTUSER.DAT` の entry は UNC/network browsing に特に有用で、`UsrClass.dat` は Windows Vista 以降で local/removable-folder shellbags が一般的に保存される場所です。
- folder が削除された後でも、folder の存在、traversal、folder-view preference を示せます。archive file への Explorer-like access も shellbag trace を残すことがあります。<sup>[[1]](#references)</sup>
- すべての shellbag が folder へのアクセス成功を証明するわけではないため、LNK、Jump List、timestamp、volume mapping と照合してください。
- **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** または **SBECmd** を使用して parse してください。

### USB 情報

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB mass-storage device の primary inventory（vendor、product、revision、serial/device instance）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: non-storage device を含む、より広範な USB device inventory。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: recent Windows 10/11 build では、install、first install、last arrival、last removal など、device ごとの lifecycle timestamp を確認できる重要な場所です。<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: volume と device identifier を drive letter / volume GUID に対応付けます。特定の drive letter に対する最後の mapping だけが残る場合があります。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: volume serial number と過去の media metadata への有用な pivot。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: ユーザー固有の drive-letter および share への interaction 履歴。<sup>[[2]](#references)</sup>
- MTP/PTP 経由で接続された modern phone や tablet は、`USBSTOR` に表示されない場合があります。`HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` と `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` も確認してください。<sup>[[2]](#references)</sup>
- device をユーザーに結び付けるには、device または volume identifier から、shellbag、LNK、Jump List、`RecentDocs`、`MountPoints2` などの per-user artifact に pivot してください。<sup>[[2]](#references)</sup>

## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
