# 興味深い Windows Registry キー

{{#include ../../../banners/hacktricks-training.md}}

Windows Registry hive は、「何が起きたのか？」から「どのユーザーが、いつ、どこから実行したのか？」を突き止めるための最短ルートの1つです。ライブ解析では `CurrentControlSet` を優先してください。オフラインの hive を解析する場合は、`ControlSet001` を決め打ちせず、まずどの `ControlSet00x` がアクティブだったかを特定してください。

### Windows のバージョンと所有者情報

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: Windows のエディション／ビルド、インストール時刻、登録所有者、製品名、その他のビルドメタデータ。
- `SYSTEM\Select`: `Current`、`Default`、`LastKnownGood` を、システムが使用した実際の `ControlSet00x` の値に対応付けます。

### コンピューター名

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: 現在のホスト名。

### タイムゾーン設定

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: 設定されたタイムゾーンと DST 関連の値。

### アクセス時刻の追跡

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` は、NTFS の最終アクセス時刻が更新されているかどうかを示します。
- 有効にするには、次を使用します: `fsutil behavior set disablelastaccess 0`

### シャットダウンの詳細

- `SYSTEM\CurrentControlSet\Control\Windows`: 最後のシャットダウン時刻。
- 古いシステムでは、`SYSTEM\CurrentControlSet\Control\Watchdog\Display` にシャットダウンカウンターが記録されている場合もあります。

### ネットワーク設定

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: インターフェースの IP、DHCP リース、ゲートウェイ、DNS データ。<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: ネットワークプロファイル名／SSID、初回および最終接続時刻。
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` および `...\Unmanaged\{GUID}`: ゲートウェイの MAC アドレスや DNS サフィックスなど、プロファイルの相関データ。
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: ホストが公開しているローカル共有フォルダー。

### リモートアクセスとネットワーク共有の履歴

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: 発信 RDP の MRU リスト（`MRU0`～`MRU9`）。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: ホストごとの発信 RDP 履歴。サブキーには通常 `UsernameHint` が保存され、キーの `LastWrite` 時刻も有用な手掛かりです。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: 特定のユーザーに関連付けられた、マップ済みネットワークドライブ、UNC 共有、リムーバブルメディアのマウントポイント。

### 自動起動するプログラムとスケジュールされた永続化

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` および `...\Tasks\{GUID}`: スケジュールされたタスクのメタデータ。ここにタスクが存在するのに `Tree\<TaskName>` に `SD` 値がない場合は、隠された Tarrask スタイルのタスク改ざんを疑い、`C:\Windows\System32\Tasks\<TaskName>` と照合してください。

### 検索、入力されたパス、MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: File Explorer の検索語。<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: Explorer で手動入力されたパス。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: 直近 26 件の `Win + R` コマンド。`MRUList` に順序が保持されています。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: 最近開かれたドキュメントとフォルダー。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: Office の最近使ったファイル。

### ユーザーアクティビティの追跡

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: GUI 操作による実行履歴。値名は ROT13 でエンコードされ、バイナリデータには実行回数と最終実行時刻が含まれます。<sup>[[1]](#references)</sup>
- `UserAssist` は強力な補強証拠として扱い、単独で結論を出さないでください。主に Explorer 経由で起動されたアプリや `.lnk` ファイルを追跡するため、コマンドラインやサービスによる実行を見落とすことがあります。Windows 10 以降では、一部のエントリーはプロセスが最後まで実行されたことを必ずしも意味しません。
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` および `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: SID による帰属情報と最終実行時刻を含む、最新の Windows 10/11 の実行痕跡。ローカルで実行されたバイナリの調査に特に有用ですが、古いエントリーはすぐに消えることがあり、ネットワーク共有／リムーバブルメディアからの実行では信頼性が低くなります。
- Prefetch、Amcache、ShimCache、SRUM など、より広範な実行アーティファクトについては、メインの [Windows forensics overview](./#programs-executed) を参照してください。

### Shellbags

- Shellbags は `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` と `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` の両方に保存されます。<sup>[[1]](#references)</sup>
- `NTUSER.DAT` のエントリーは UNC／ネットワークの閲覧履歴に特に有用です。一方、Windows Vista 以降では、ローカル／リムーバブルフォルダーの shellbags は一般に `UsrClass.dat` に保存されます。
- フォルダーが削除された後でも、フォルダーの存在、移動経路、フォルダービューの設定が分かることがあります。Explorer に似た方法でアーカイブファイルにアクセスした場合も、shellbag の痕跡が残ることがあります。<sup>[[1]](#references)</sup>
- すべての shellbag がフォルダーへのアクセス成功を証明するわけではないため、LNK、Jump Lists、タイムスタンプ、ボリュームのマッピングと照合してください。
- 解析には **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** または **SBECmd** を使用してください。

### USB 情報

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: USB 大容量記憶装置の主要な一覧（ベンダー、製品、リビジョン、シリアル／デバイスインスタンス）。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: ストレージ以外のデバイスも含む、より広範な USB デバイス一覧。
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: 最近の Windows 10/11 ビルドでは、インストール、初回インストール、最終接続、最終取り外しなど、デバイスごとのライフサイクル時刻を確認できる重要な場所です。<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices`: ボリュームとデバイス識別子をドライブ文字／ボリューム GUID に対応付けます。特定のドライブ文字については、最後のマッピングしか残らないことがあります。
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: ボリュームシリアル番号や過去のメディアメタデータを調べる際の有用な手掛かりです。
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: ユーザー固有のドライブ文字および共有へのアクセス履歴。<sup>[[2]](#references)</sup>
- MTP/PTP 経由で接続された最新のスマートフォンやタブレットは、`USBSTOR` に表示されないことがあります。`HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` と `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices` も確認してください。<sup>[[2]](#references)</sup>
- デバイスをユーザーに関連付けるには、デバイスまたはボリュームの識別子から、shellbags、LNK、Jump Lists、`RecentDocs`、`MountPoints2` などのユーザーごとのアーティファクトを調べてください。<sup>[[2]](#references)</sup>



## References

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [Windows 10 および 11 における USB デバイスのフォレンジック - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
