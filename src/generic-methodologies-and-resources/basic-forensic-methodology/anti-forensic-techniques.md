# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

攻撃者は、検知を回避するために**ファイルのタイムスタンプを変更**したい場合があります。\
タイムスタンプは、MFT 内の属性 `$STANDARD_INFORMATION` __ および __ `$FILE_NAME` にあります。

両方の属性には、**Modification**、**access**、**creation**、**MFT registry modification**（MACE または MACB）の 4 つのタイムスタンプがあります。

**Windows explorer** やその他のツールは、**`$STANDARD_INFORMATION`** の情報を表示します。

### TimeStomp - Anti-forensic Tool

このツールは **`$STANDARD_INFORMATION`** 内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`** 内の情報は**変更しません**。したがって、**不審な**アクティビティを**特定**できます。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal）は、ボリュームの変更を追跡する NTFS（Windows NT file system）の機能です。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ツールを使用すると、これらの変更を調査できます。

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal（Update Sequence Number Journal）は、ボリュームの変更を追跡する NTFS（Windows NT file system）の機能です。...](<../../images/image (801).png>)

上の画像は **tool** が表示した**出力**であり、ファイルに対して**いくつかの変更が実行された**ことを確認できます。

### $LogFile

**ファイルシステムに対するすべてのメタデータ変更は、**[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) と呼ばれるプロセスで記録されます。記録されたメタデータは、NTFS ファイルシステムのルートディレクトリにある `**$LogFile**` という名前のファイルに保存されます。[LogFileParser](https://github.com/jschicht/LogFileParser) などのツールを使用して、このファイルを解析し、変更を特定できます。

![Usnjrnl - $LogFile: ファイルシステムに対するすべてのメタデータ変更は、write-ahead logging と呼ばれるプロセスで記録されます。記録されたメタデータは、ルート...](<../../images/image (137).png>)

ここでも、tool の出力から**いくつかの変更が実行された**ことを確認できます。

同じツールを使用すると、タイムスタンプが**いつ変更されたか**を特定できます。

![Usnjrnl - $LogFile: 同じツールを使用すると、タイムスタンプがいつ変更されたかを特定できます](<../../images/image (1089).png>)

- CTIME: ファイルの作成時刻
- ATIME: ファイルの変更時刻
- MTIME: ファイルの MFT registry modification
- RTIME: ファイルのアクセス時刻

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

不審な変更が行われたファイルを特定するもう 1 つの方法は、両方の属性の時刻を比較して**不一致**を探すことです。

### Nanoseconds

**NTFS** のタイムスタンプの**精度**は **100 nanoseconds** です。そのため、2010-10-10 10:10:**00.000:0000 のようなタイムスタンプを持つファイルは非常に不審です**。

### SetMace - Anti-forensic Tool

このツールは、`$STARNDAR_INFORMATION` と `$FILE_NAME` の両方の属性を変更できます。ただし、Windows Vista 以降では、この情報を変更するには live OS が必要です。

## Data Hiding

NFTS はクラスターと最小情報サイズを使用します。つまり、ファイルが 1.5 クラスターを使用している場合、**残りの半分は**ファイルが削除されるまで**決して使用されません**。したがって、この slack space に**データを隠す**ことができます。

slacker のように、この「hidden」space にデータを隠せるツールがあります。ただし、`$logfile` と `$usnjrnl` を分析すると、データが追加されたことがわかる場合があります。

![SetMace - Anti-forensic Tool - Data Hiding: slacker のように、この「hidden」space にデータを隠せるツールがあります。ただし、$logfile と $usnjrnl を分析すると、データが...](<../../images/image (1060).png>)

その後、FTK Imager などのツールを使用して slack space を取得できます。この種のツールでは、コンテンツを obfuscated、または暗号化された状態で保存できることに注意してください。

## UsbKill

これは、USB ポートに何らかの変更が検知されると、**コンピューターをシャットダウンする**ツールです。\
これを発見する方法の 1 つは、実行中のプロセスを調査し、**実行中の各 python script を確認する**ことです。

## Live Linux Distributions

これらの distro は **RAM** メモリ内で**実行されます**。それらを検知できるのは、NTFS file-system が write permissions 付きで mount されている場合だけです。read permissions のみで mount されている場合、侵入を検知することはできません。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

複数の Windows logging methods を無効化して、forensics investigation を大幅に困難にすることができます。

### Disable Timestamps - UserAssist

これは、ユーザーが各 executable を実行した日時を保持する registry key です。

UserAssist を無効化するには、次の 2 つの手順が必要です。

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` と `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` の 2 つの registry key を、UserAssist を無効化することを示すために、両方とも zero に設定します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` のような registry subtrees を削除します。

### Disable Timestamps - Prefetch

これは、Windows system のパフォーマンスを向上させる目的で、実行された applications に関する情報を保存します。ただし、これは forensics practices にも役立ちます。

- `regedit` を実行します
- file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` を選択します
- `EnablePrefetcher` と `EnableSuperfetch` の両方を右クリックします
- それぞれで Modify を選択し、value を 1（または 3）から 0 に変更します
- Restart します

### Disable Timestamps - Last Access Time

Windows NT server 上の NTFS volume から folder を開くたびに、system は **一覧表示された各 folder の timestamp field を update** する時刻を取得します。頻繁に使用される NTFS volume では、これがパフォーマンスに影響する可能性があります。

1. Registry Editor（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` に移動します。
3. `NtfsDisableLastAccessUpdate` を探します。存在しない場合は、この DWORD を追加し、その value を 1 に設定すると、process が無効になります。
4. Registry Editor を閉じ、server を reboot します。

### Delete USB History

すべての **USB Device Entries** は Windows Registry の **USBSTOR** registry key に保存されています。この key には、USB Device を PC または Laptop に接続するたびに作成される sub keys が含まれます。この key は H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR` にあります。**これを削除すると**、USB history が削除されます。\
[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) ツールを使用して、削除されたことを確認（および削除）することもできます。

USB に関する情報を保存する別の file は、`C:\Windows\INF` 内の `setupapi.dev.log` です。これも削除する必要があります。

### Disable Shadow Copies

`vssadmin list shadowstorage` を実行して shadow copies を**一覧表示**します\
`vssadmin delete shadow` を実行して**削除**します

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) の手順に従い、GUI から削除することもできます。

shadow copies を無効化するには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows) に従います。

1. Windows start button をクリックした後、text search box に "services" と入力して Services program を開きます。
2. list から "Volume Shadow Copy" を探して選択し、右クリックして Properties にアクセスします。
3. "Startup type" drop-down menu から Disabled を選択し、Apply と OK をクリックして変更を確定します。

registry の `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` で、shadow copy にコピーする files の設定を変更することもできます。

### Overwrite deleted files

- **Windows tool** `cipher /w:C` を使用できます。これにより、C drive 内の利用可能な未使用 disk space からデータを削除するよう cipher に指示します。
- [**Eraser**](https://eraser.heidi.ie) などの tools も使用できます。

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> "Windows Logs" を Expand --> 各 category を右クリックして "Clear Log" を選択します
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- services section で "Windows Event Log" service を無効化します
- `WEvtUtil.exec clear-log` または `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11 および Windows Server の最近の versions では、
`Microsoft-Windows-PowerShell/Operational`（events 4104/4105/4106）に**詳細な PowerShell forensic artifacts**が保存されます。
攻撃者は、実行中にこれらを無効化または消去できます。
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
Defendersは、これらのレジストリキーへの変更と、PowerShellイベントの大量削除を監視すべきです。

### ETW (Event Tracing for Windows) Patch

Endpoint security製品はETWに大きく依存しています。2024年に広く使われた回避手法の1つは、メモリ内の
`ntdll!EtwEventWrite`/`EtwEventWriteFull`をpatchし、イベントを生成せずにすべてのETW呼び出しが
`STATUS_SUCCESS`を返すようにする方法です。<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs（例: `EtwTiSwallow`）は、PowerShell または C++ で同じ primitive を実装しています。
この patch は **process-local** であるため、他の process 内で実行されている EDR はこれを見逃す可能性があります。<sup>[[5]](#references)</sup>
Detection: `ntdll` のメモリ上の内容とディスク上の内容を比較するか、user-mode より前で hook します。

### Alternate Data Streams (ADS) の復活

2023 年の Malware campaign（例: **FIN12** loaders）では、traditional scanner の目を逃れるため、
ADS 内に second-stage binary を staging していることが確認されています。
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`、`Get-Item -Stream *`、または Sysinternals の `streams64.exe` で stream を列挙します。
host file を FAT/exFAT にコピーするか、SMB 経由でコピーすると hidden stream が削除されるため、
investigator が payload を復元するために利用できます。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver は現在、ransomware の侵入における **anti-forensics** で
日常的に使用されています。
オープンソース tool の **AuKill** は、署名済みでありながら脆弱な driver (`procexp152.sys`) を
load し、**暗号化と log の破壊の前に** EDR および forensic sensor を
suspend または terminate します:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
ドライバーはその後削除されるため、痕跡は最小限に抑えられます。<sup>[[1]](#references)</sup>
緩和策: Microsoft vulnerable-driver blocklist (HVCI/SAC) を有効にし、
user-writable paths からの kernel-service creation を検知した際に alert を発生させます。

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self‑patching compromised services to reduce detection (Linux)
攻撃者は、再侵害を防止し、脆弱性ベースの検知を抑制するため、サービスを exploit した直後に “self‑patch” するケースを increasingly 増やしています。その手法は、脆弱なコンポーネントを最新の正規 upstream バイナリ/JAR に置き換えることで、persistence と C2 を維持したまま、scanner にホストが patch 済みであると報告させるものです。<sup>[[3]](#references)</sup>

例: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Post‑exploitation の段階で、攻撃者は Maven Central (repo1.maven.org) から正規の JAR を取得し、ActiveMQ の install 内にある脆弱な JAR を削除して broker を再起動しました。
- これにより初期 RCE は封じられましたが、その他の foothold (cron、SSH config の変更、別個の C2 implant) は維持されました。

運用例 (説明用)
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
- 未スケジュールのバイナリ/JAR置換がないか、service directoriesを確認する:
- Debian/Ubuntu: `dpkg -V activemq`を実行し、file hashes/pathsをrepo mirrorsと比較する。
- disk上に存在するがpackage managerが所有していないJAR versionsや、out of bandで更新されたsymbolic linksを探す。
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`を使用し、ctime/mtimeをcompromise windowと照合する。
- Shell history/process telemetry: initial exploitationの直後に`repo1.maven.org`または他のartifact CDNsへ`curl`/`wget`した証拠を確認する。
- Change management: patched versionが存在することだけでなく、誰が、なぜ“patch”を適用したのかを検証する。

### bearer tokensとanti-analysis stagersを使用したCloud-service C2
確認されたtradecraftでは、複数のlong-haul C2 pathsとanti-analysis packagingが組み合わされていた:<sup>[[3]](#references)</sup>
- sandboxingとstatic analysisを妨害する、password-protected PyInstaller ELF loaders（例: encrypted PYZ、`/_MEI*`下へのtemporary extraction）。
- Indicators: `strings`で`PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS`などがヒットする。
- Runtime artifacts: `/tmp/_MEI*`またはcustom `--runtime-tmpdir` pathsへのextraction。
- hardcoded OAuth Bearer tokensを使用する、Dropbox-backed C2
- Network markers: `Authorization: Bearer <token>`を伴う`api.dropboxapi.com` / `content.dropboxapi.com`。
- 通常file syncを行わないserver workloadsからDropbox domainsへのoutbound HTTPSについて、proxy/NetFlow/Zeek/Suricataをhuntingする。
- tunneling（例: Cloudflare Tunnel `cloudflared`）によるparallel/backup C2。一方のchannelがblockedでもcontrolを維持する。
- Host IOCs: `cloudflared` processes/units、`~/.cloudflared/*.json`のconfig、Cloudflare edgesへのoutbound 443。

### accessを維持するためのPersistenceと“hardening rollback”（Linux examples）
Attackersは、self-patchingをdurable access pathsと組み合わせることが多い:<sup>[[3]](#references)</sup>
- Cron/Anacron: periodic executionのため、各`/etc/cron.*/` directory内の`0anacron` stubをeditする。
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: root loginsをenableし、low-privileged accountsのdefault shellsを変更する。
- root login enablementをhuntする:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes"などのvaluesや、過度にpermissiveなsettingsをflagする
```
- system accounts（例: `games`）上のsuspicious interactive shellsをhuntする:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- diskにdropされ、cloud C2にもcontactする、randomで短い名前のbeacon artifacts（8 alphabetical chars）:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defendersは、これらのartifactsをexternal exposureおよびservice patching eventsとcorrelateし、initial exploitationを隠すために使用されたanti-forensic self-remediationを明らかにすべきである。

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)

{{#include ../../banners/hacktricks-training.md}}
