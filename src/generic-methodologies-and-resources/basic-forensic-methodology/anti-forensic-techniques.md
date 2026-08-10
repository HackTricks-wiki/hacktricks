# Anti-Forensic Techniques

## Timestamps

攻撃者は、検知を回避するために**ファイルのタイムスタンプを変更**することに関心を持つ場合があります。\
MFT 内の属性 `$STANDARD_INFORMATION` \_\_ および \_\_ `$FILE_NAME` にタイムスタンプが存在します。

両方の属性には、**Modification**、**access**、**creation**、**MFT registry modification**（MACE または MACB）の 4 つのタイムスタンプがあります。

**Windows explorer** やその他のツールは、**`$STANDARD_INFORMATION`** の情報を表示します。

### TimeStomp - Anti-forensic Tool

このツールは **`$STANDARD_INFORMATION`** 内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`** 内の情報は変更しません。そのため、**不審な** **アクティビティ**を**特定**できます。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal）は、ボリュームの変更を追跡する NTFS（Windows NT file system）の機能です。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ツールを使用すると、これらの変更を調査できます。

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal（Update Sequence Number Journal）は、ボリュームの変更を追跡する NTFS（Windows NT file system）の機能です。...](<../../images/image (801).png>)

前の画像は **tool** が表示した**出力**であり、ファイルに対して**いくつかの変更が実行された**ことを確認できます。

### $LogFile

**ファイルシステムへのすべてのメタデータ変更は、**[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) と呼ばれるプロセスで**記録されます**。記録されたメタデータは、NTFS ファイルシステムのルートディレクトリにある `**$LogFile**` という名前のファイルに保存されます。[LogFileParser](https://github.com/jschicht/LogFileParser) などのツールを使用して、このファイルを解析し、変更を特定できます。

![Usnjrnl - $LogFile: ファイルシステムへのすべてのメタデータ変更は、write-ahead logging と呼ばれるプロセスで記録されます。記録されたメタデータは、ルート...](<../../images/image (137).png>)

ここでも、tool の出力から**いくつかの変更が実行された**ことを確認できます。

同じ tool を使用すると、タイムスタンプが**いつ変更されたか**を特定できます。

![Usnjrnl - $LogFile: 同じ tool を使用すると、タイムスタンプがいつ変更されたかを特定できます](<../../images/image (1089).png>)

- CTIME: ファイルの作成時刻
- ATIME: ファイルの変更時刻
- MTIME: ファイルの MFT registry modification
- RTIME: ファイルのアクセス時刻

### `$STANDARD_INFORMATION` と `$FILE_NAME` の比較

不審な変更済みファイルを特定する別の方法は、両方の属性の時刻を比較して**不一致**を探すことです。

### Nanoseconds

**NTFS** のタイムスタンプの**精度**は **100 ナノ秒**です。そのため、2010-10-10 10:10:**00.000:0000 のようなタイムスタンプを持つファイルは非常に不審です**。

### SetMace - Anti-forensic Tool

このツールは、`$STARNDAR_INFORMATION` と `$FILE_NAME` の両方の属性を変更できます。ただし、Windows Vista 以降では、この情報を変更するには live OS が必要です。

## Data Hiding

NFTS はクラスタと最小情報サイズを使用します。つまり、ファイルが 1 クラスタ半を使用している場合、**残りの半分は**ファイルが削除されるまで**使用されません**。そのため、**この slack space にデータを隠す**ことが可能です。

slacker のように、この「hidden」space にデータを隠せるツールがあります。ただし、`$logfile` と `$usnjrnl` を分析すると、一部のデータが追加されたことを確認できます。

![SetMace - Anti-forensic Tool - Data Hiding: slacker のように、この「hidden」space にデータを隠せるツールがあります。ただし、$logfile と $usnjrnl を分析すると、...](<../../images/image (1060).png>)

その後、FTK Imager などのツールを使用して slack space を取得できます。この種の tool は、コンテンツを obfuscated、あるいは暗号化された状態で保存できる点に注意してください。

## UsbKill

これは、USB ポートに何らかの変更が検出されると、**コンピューターの電源を切る**ツールです。\
これを発見する方法として、実行中のプロセスを調査し、**実行中の各 Python スクリプトを確認**することが挙げられます。

## Live Linux Distributions

これらの distro は **RAM** メモリ内で**実行されます**。検出する唯一の方法は、**NTFS file-system が write permissions 付きで mount されている場合**です。read permissions のみで mount されている場合、侵入を検出することはできません。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

forensics investigation をはるかに困難にするため、複数の Windows logging methods を無効化できます。

### Disable Timestamps - UserAssist

これは、ユーザーが各 executable を実行した日時を保持する registry key です。

UserAssist を無効化するには、次の 2 つの手順が必要です。

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` と `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` の 2 つの registry key をどちらもゼロに設定し、UserAssist を無効化することを通知します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` のような registry subtrees を消去します。

### Disable Timestamps - Prefetch

これは、Windows system のパフォーマンスを向上させる目的で、実行された applications に関する情報を保存します。ただし、これは forensics practices にも役立ちます。

- `regedit` を実行します
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` の file path を選択します
- `EnablePrefetcher` と `EnableSuperfetch` の両方を右クリックします
- それぞれで Modify を選択し、値を 1（または 3）から 0 に変更します
- Restart します

### Disable Timestamps - Last Access Time

Windows NT server 上の NTFS volume から folder を開くたびに、system は**各 listed folder の timestamp field を更新する**ための時刻を取得します。頻繁に使用される NTFS volume では、これがパフォーマンスに影響する可能性があります。

1. Registry Editor（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` に移動します。
3. `NtfsDisableLastAccessUpdate` を探します。存在しない場合は、この DWORD を追加し、値を 1 に設定して process を無効化します。
4. Registry Editor を閉じ、server を reboot します。

### Delete USB History

すべての **USB Device Entries** は Windows Registry の **USBSTOR** registry key に保存されます。この key には、USB Device を PC または Laptop に接続するたびに作成される sub keys が含まれています。この key は H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR` にあります。**これを削除すると**、USB history が削除されます。\
[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) tool を使用して、確実に削除されたことを確認したり、削除したりすることもできます。

USB に関する情報を保存する別の file は、`C:\Windows\INF` 内の `setupapi.dev.log` です。これも削除する必要があります。

### Disable Shadow Copies

`vssadmin list shadowstorage` で Shadow Copies を**一覧表示**します\
`vssadmin delete shadow` を実行して削除します

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) の手順に従い、GUI から削除することもできます。

Shadow Copies を無効化するには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)を使用します。

1. Windows start button をクリックした後、text search box に「services」と入力して Services program を開きます。
2. 一覧から「Volume Shadow Copy」を探して選択し、右クリックして Properties にアクセスします。
3. 「Startup type」drop-down menu から Disabled を選択し、Apply と OK をクリックして変更を確定します。

registry の `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` で、Shadow Copy にコピーする files の設定を変更することもできます。

### Overwrite deleted files

- **Windows tool** `cipher /w:C` を使用できます。これにより、C drive 内の利用可能な unused disk space からデータを削除するよう cipher に指示します。
- [**Eraser**](https://eraser.heidi.ie) などの tools も使用できます。

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> 「Windows Logs」を Expand --> 各 category を Right click して「Clear Log」を選択します
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- services section 内で「Windows Event Log」service を disable します
- `WEvtUtil.exec clear-log` または `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 および Windows Server の最近の versions は、`Microsoft-Windows-PowerShell/Operational`（events 4104/4105/4106）に**豊富な PowerShell forensic artifacts**を保持します。  
攻撃者は、それらを on-the-fly で無効化または wipe できます：
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
Defendersは、これらのregistry keyへの変更と、PowerShellイベントの大量削除を監視する必要があります。

### ETW (Event Tracing for Windows) Patch

Endpoint security製品はETWに大きく依存しています。2024年に広く使われたevasion手法の1つは、メモリ上の`ntdll!EtwEventWrite`/`EtwEventWriteFull`をpatchし、すべてのETW callがイベントを出力せずに`STATUS_SUCCESS`を返すようにすることです。<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs（例: `EtwTiSwallow`）は、同じ primitive を PowerShell または C++ で実装します。
このパッチは**プロセスローカル**であるため、他のプロセス内で動作する EDR はこれを見逃す可能性があります。<sup>[[5]](#references)</sup>
検出: メモリ上の `ntdll` とディスク上のものを比較するか、user-mode より前で hook します。

### Alternate Data Streams (ADS) Revival

2023 年の Malware campaigns（例: **FIN12** loaders）では、従来の scanners の目に触れないよう、
ADS 内に second-stage binaries を staging する事例が確認されています。
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`、`Get-Item -Stream *`、または Sysinternals の `streams64.exe` でストリームを列挙します。
ホストファイルを FAT/exFAT にコピーしたり、SMB 経由でコピーしたりすると、非表示ストリームが削除されるため、調査担当者がペイロードを復元するために利用できます。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver は現在、ランサムウェア侵入における **anti-forensics** に日常的に使用されています。
オープンソースツールの **AuKill** は、署名済みだが脆弱なドライバー（`procexp152.sys`）を読み込み、**暗号化とログ破壊の前に** EDR およびフォレンジックセンサーを一時停止または終了させます。<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
ドライバーはその後削除され、痕跡は最小限に抑えられます。<sup>[[1]](#references)</sup>  
Mitigations: Microsoft の脆弱なドライバーのブロックリスト（HVCI/SAC）を有効にし、ユーザーが書き込み可能なパスからの kernel-service 作成を検知してアラートを発報します。

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### 検知を回避するために侵害したサービスへ self-patching を行う（Linux）
Adversaries は、再侵害を防止し、脆弱性ベースの検知を抑制するため、サービスを exploit した直後に “self-patch” するケースを増やしています。その手法は、脆弱なコンポーネントを最新の正規 upstream バイナリ/JAR に置き換え、persistence と C2 を維持したまま、scanner にはホストが patch 済みであると報告させるというものです。<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Post‑exploitation の段階で、attackers は Maven Central（repo1.maven.org）から正規の JAR を取得し、ActiveMQ の install 内にある脆弱な JAR を削除して、broker を再起動しました。
- これにより初期の RCE は閉じられましたが、その他の foothold（cron、SSH config の変更、個別の C2 implant）は維持されました。

Operational example (illustrative)
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
Forensic/hunting tips
- 予定外のバイナリ/JAR置換がないか、サービスディレクトリを確認する:
- Debian/Ubuntu: `dpkg -V activemq` を実行し、ファイルのハッシュ/パスをリポジトリミラーと比較する。
- RHEL/CentOS: `rpm -Va 'activemq*'`
- ディスク上に存在するがパッケージマネージャーが所有していないJARバージョンや、帯域外で更新されたシンボリックリンクを探す。
- タイムライン: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` を使用して、ctime/mtimeと侵害期間を関連付ける。
- Shell history/process telemetry: 初期エクスプロイトの直後に `repo1.maven.org` またはその他のartifact CDNへ `curl`/`wget` を実行した痕跡を確認する。
- Change management: patched versionが存在することだけでなく、誰が、なぜ「patch」を適用したのかを検証する。

### bearer tokenとanti-analysis stagerを使用したCloud-service C2
観測されたtradecraftでは、複数の長時間接続型C2経路とanti-analysis packagingが組み合わされていた:<sup>[[3]](#references)</sup>
- sandboxingとstatic analysisを妨害する、Password-protected PyInstaller ELF loader（例: encrypted PYZ、一時的な `/_MEI*` 配下への展開）。
- Indicators: `strings` の検索結果に `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` などが含まれる。
- Runtime artifacts: `/tmp/_MEI*` またはカスタムの `--runtime-tmpdir` パスへの展開。
- ハードコードされたOAuth Bearer tokenを使用するDropbox-backed C2
- Network markers: `Authorization: Bearer <token>` を伴う `api.dropboxapi.com` / `content.dropboxapi.com`。
- 通常はファイルをsyncしないサーバーワークロードからDropboxドメインへのoutbound HTTPSを、proxy/NetFlow/Zeek/Suricataでhuntする。
- tunneling（例: Cloudflare Tunnel `cloudflared`）によるparallel/backup C2。一方のchannelがblockされてもcontrolを維持する。
- Host IOCs: `cloudflared` processes/units、`~/.cloudflared/*.json` のconfig、Cloudflare edgeへのoutbound 443。

### accessを維持するためのPersistenceと「hardening rollback」（Linux examples）
Attackersは、self-patchingとdurable access pathsを組み合わせることが多い:<sup>[[3]](#references)</sup>
- Cron/Anacron: 各 `/etc/cron.*/` directory内の `0anacron` stubを編集し、periodic executionを行う。
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root loginを有効化し、low-privileged accountのdefault shellを変更する。
- root login enablementをhuntする:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- system account（例: `games`）上のsuspicious interactive shellをhuntする:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- cloud C2にもcontactする、randomで短い名前のbeacon artifact（8個のalphabetical character）がディスクにdropされる:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenderは、これらのartifactをexternal exposureおよびservice patching eventと関連付け、initial exploitationを隠すために使用されたanti-forensic self-remediationを明らかにすべきである。

## References

- [1] [Sophos X-Ops – AuKill: EDRを無効化するweaponized vulnerable driver（2023年3月）](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – StealthのためのEtwEventWriteのpatching: Detection & Hunting（2024年6月）](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Persistenceのためのpatching: DripDropper Linux malwareがcloud内を移動する方法](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE（NVD）](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Your .NETを隠す - ETW（Adam Chester / XPN）](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
