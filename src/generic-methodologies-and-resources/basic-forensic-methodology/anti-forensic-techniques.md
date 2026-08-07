# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

攻撃者は、検知を回避するために**ファイルのタイムスタンプを変更**しようとすることがあります。\
タイムスタンプは、MFT内の属性 `$STANDARD_INFORMATION` \_\_ および \_\_ `$FILE_NAME` に存在します。

両方の属性には、**Modification**、**access**、**creation**、**MFT registry modification**（MACEまたはMACB）の4つのタイムスタンプがあります。

**Windows explorer**やその他のツールは、**`$STANDARD_INFORMATION`** の情報を表示します。

### TimeStomp - Anti-forensic Tool

このツールは、**`$STANDARD_INFORMATION`** 内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`** 内の情報は**変更しません**。そのため、**不審な** **アクティビティ**を**特定**できます。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal）は、ボリュームの変更を追跡するNTFS（Windows NT file system）の機能です。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) toolを使用すると、これらの変更を調査できます。

![TimeStomp - Anti-forensic Tool - Usnjrnl: The USN Journal (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The...](<../../images/image (801).png>)

前の画像は**tool**によって表示された**output**であり、ファイルに対して**いくつかの変更が実行された**ことを確認できます。

### $LogFile

**ファイルシステムに対するすべてのメタデータ変更は、**[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) として知られるプロセスで記録されます。記録されたメタデータは、NTFS file systemのルートディレクトリにある `**$LogFile**` という名前のファイルに保持されます。[LogFileParser](https://github.com/jschicht/LogFileParser) のようなツールを使用して、このファイルを解析し、変更を特定できます。

![Usnjrnl - $LogFile: All metadata changes to a file system are logged in a process known as write-ahead logging. The logged metadata is kept in a file named $LogFile , located in the root...](<../../images/image (137).png>)

ここでも、toolのoutputから**いくつかの変更が実行された**ことを確認できます。

同じtoolを使用すると、**タイムスタンプがいつ変更されたか**を特定できます。

![Usnjrnl - $LogFile: Using the same tool it's possible to identify to which time the timestamps were modified](<../../images/image (1089).png>)

- CTIME: ファイルのcreation time
- ATIME: ファイルのmodification time
- MTIME: ファイルのMFT registry modification
- RTIME: ファイルのaccess time

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

不審な変更が加えられたファイルを特定するもう1つの方法は、両方の属性の時刻を比較して**不一致**を探すことです。

### Nanoseconds

**NTFS**のタイムスタンプの**精度**は**100ナノ秒**です。そのため、2010-10-10 10:10:**00.000:0000 のようなタイムスタンプを持つファイルは非常に不審です**。

### SetMace - Anti-forensic Tool

このtoolは、`$STARNDAR_INFORMATION` と `$FILE_NAME` の両方の属性を変更できます。ただし、Windows Vista以降では、この情報を変更するにはlive OSが必要です。

## Data Hiding

NFTSはclusterと最小情報サイズを使用します。つまり、ファイルが1つ半のclusterを使用する場合、**残りの半分は**ファイルが削除されるまで**使用されません**。そのため、このslack spaceに**データを隠す**ことができます。

slackerのように、この「hidden」spaceへのデータ隠蔽を可能にするtoolsがあります。ただし、`$logfile` と `$usnjrnl` を分析すると、データが追加されたことを確認できます。

![SetMace - Anti-forensic Tool - Data Hiding: There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the $logfile and $usnjrnl can show that...](<../../images/image (1060).png>)

その後、FTK Imagerのようなtoolsを使用してslack spaceを取得できます。この種類のtoolでは、contentをobfuscatedまたはencryptedされた状態で保存することもできます。

## UsbKill

これは、USB portsの変更を検知すると**コンピューターの電源を切る**toolです。\
これを発見する方法は、実行中のprocessesを調査し、**実行中の各python scriptを確認**することです。

## Live Linux Distributions

これらのdistrosは**RAM** memory内で**実行されます**。検知する唯一の方法は、**NTFS file-systemがwrite permissions付きでmountされている場合**です。read permissionsのみでmountされている場合、intrusionを検知することはできません。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

forensics investigationをはるかに困難にするため、いくつかのWindows logging methodsを無効化できます。

### Disable Timestamps - UserAssist

これは、ユーザーが各executableを実行した日時を保持するregistry keyです。

UserAssistを無効化するには、次の2つの手順が必要です。

1. 2つのregistry keys、`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` と `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` を両方ともzeroに設定し、UserAssistを無効化することを示します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` のようなregistry subtreesをクリアします。

### Disable Timestamps - Prefetch

これは、Windows systemのperformanceを向上させる目的で、実行されたapplicationsに関する情報を保存します。ただし、これはforensics practicesにも役立ちます。

- `regedit`を実行します
- file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` を選択します
- `EnablePrefetcher` と `EnableSuperfetch` の両方を右クリックします
- それぞれでModifyを選択し、valueを1（または3）から0に変更します
- Restartします

### Disable Timestamps - Last Access Time

Windows NT server上のNTFS volumeからfolderを開くたびに、systemは**各listed folderのtimestamp fieldをupdate**します。これをlast access timeと呼びます。頻繁に使用されるNTFS volumeでは、performanceに影響する可能性があります。

1. Registry Editor（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` に移動します。
3. `NtfsDisableLastAccessUpdate`を探します。存在しない場合は、このDWORDを追加し、valueを1に設定してprocessを無効化します。
4. Registry Editorを閉じ、serverをrebootします。

### Delete USB History

すべての**USB Device Entries**は、Windows Registryの**USBSTOR** registry keyに保存されています。このkeyには、USB DeviceをPCまたはLaptopに接続するたびに作成されるsub keysが含まれます。このkeyは H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR` にあります。**これを削除すると**、USB historyが削除されます。\
[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) toolを使用して、確実に削除されたことを確認したり、削除したりすることもできます。

USBに関する情報を保存する別のfileは、`C:\Windows\INF` 内の `setupapi.dev.log` です。これも削除する必要があります。

### Disable Shadow Copies

`vssadmin list shadowstorage`でShadow Copiesを**List**します\
`vssadmin delete shadow`を実行して削除します

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) に記載された手順に従い、GUIから削除することもできます。

Shadow Copiesを無効化するには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)に従います。

1. Windows start buttonをクリックした後、text search boxに「services」と入力してServices programを開きます。
2. listから「Volume Shadow Copy」を探して選択し、右クリックしてPropertiesにアクセスします。
3. 「Startup type」drop-down menuからDisabledを選択し、ApplyとOKをクリックして変更を確定します。

registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` で、Shadow Copyにコピーするfilesのconfigurationを変更することもできます。

### Overwrite deleted files

- **Windows tool**を使用できます: `cipher /w:C` これにより、C drive内の利用可能なunused disk spaceからデータを削除するようcipherに指示します。
- [**Eraser**](https://eraser.heidi.ie)のようなtoolsも使用できます。

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> 「Windows Logs」をExpand --> 各categoryを右クリックし、「Clear Log」を選択します
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- services sectionで「Windows Event Log」serviceを無効化します
- `WEvtUtil.exec clear-log` または `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Windows 10/11およびWindows Serverの最近のversionsは、`Microsoft-Windows-PowerShell/Operational`（events 4104/4105/4106）に**詳細なPowerShell forensic artifacts**を保持します。攻撃者は、実行中にこれらを無効化または消去できます：
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
Defendersは、これらのレジストリキーへの変更と、PowerShellイベントの大量削除を監視する必要があります。

### ETW (Event Tracing for Windows) Patch

Endpoint security productsはETWに大きく依存しています。2024年に広く使われている回避手法の1つは、メモリ上の`ntdll!EtwEventWrite`/`EtwEventWriteFull`にpatchを適用し、すべてのETW呼び出しがイベントを発行せずに`STATUS_SUCCESS`を返すようにする方法です：
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs（例: `EtwTiSwallow`）は、PowerShell または C++ で同じプリミティブを実装しています。
パッチは **process-local** であるため、他のプロセス内で実行されている EDR はこれを見逃す可能性があります。
Detection: メモリ上の `ntdll` とディスク上のものを比較するか、user-mode より前に hook します。

### Alternate Data Streams (ADS) の復活

2023 年の Malware campaigns（例: **FIN12** loaders）では、従来型スキャナの目を逃れるため、
ADS 内に second-stage binaries を staging していることが確認されています:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
`dir /R`、`Get-Item -Stream *`、または Sysinternals の `streams64.exe` でストリームを列挙します。
ホストファイルを FAT/exFAT にコピーしたり、SMB 経由でコピーしたりすると、隠しストリームが削除されるため、
investigators が payload を復元するために利用できます。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver は現在、ransomware 侵入における **anti-forensics** に日常的に使用されています。
オープンソースツールの **AuKill** は、署名済みですが脆弱な driver (`procexp152.sys`) を読み込み、
暗号化と log の破壊を実行する**前に** EDR および forensic sensor を一時停止または終了させます：<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
ドライバーはその後削除されるため、痕跡は最小限に抑えられます。<sup>[[1]](#references)</sup>
Mitigations: Microsoft の vulnerable-driver blocklist（HVCI/SAC）を有効化し、
user-writable paths からの kernel-service creation を alert します。

---

## Linux Anti-Forensics: Self-Patching and Cloud C2（2023–2025）

### 検知を低減するために侵害したサービスを Self-patching する（Linux）
Adversaries は、再侵害を防止し、脆弱性ベースの検知を抑制するため、サービスを exploit した直後に increasingly “self-patch” するようになっています。その目的は、脆弱なコンポーネントを最新の正規 upstream binaries/JARs に置き換え、persistence と C2 を維持したまま、scanners にホストが patched 済みであると報告させることです。<sup>[[3]](#references)</sup>

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Post‑exploitation で、attackers は Maven Central（repo1.maven.org）から正規の JARs を取得し、ActiveMQ install 内の脆弱な JARs を削除して、broker を再起動しました。
- これにより initial RCE は閉じられましたが、他の footholds（cron、SSH config changes、separate C2 implants）は維持されました。

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
フォレンジック/ハンティングのヒント
- 予定外のバイナリ/JAR置換がないか、サービスのディレクトリを確認する:
- Debian/Ubuntu: `dpkg -V activemq` を実行し、ファイルのハッシュ/パスをリポジトリミラーと比較する。
- RHEL/CentOS: `rpm -Va 'activemq*'`
- ディスク上に存在するがパッケージマネージャーが所有していないJARバージョンや、範囲外で更新されたシンボリックリンクを探す。
- タイムライン: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` で、ctime/mtimeと侵害期間を関連付ける。
- Shell history/process telemetry: 初回exploitの直後に `repo1.maven.org` やその他のartifact CDNへ `curl`/`wget` を実行した証拠を確認する。
- 変更管理: patched versionが存在することだけでなく、誰が、なぜ“patch”を適用したのかを検証する。

### bearer tokenとanti-analysis stagerを使用したCloud-service C2
確認されたtradecraftでは、複数の長距離C2経路とanti-analysis packagingが組み合わされていた:<sup>[[3]](#references)</sup>
- sandboxingとstatic analysisを妨害する、password-protected PyInstaller ELF loader（例: encrypted PYZ、一時的な `/_MEI*` 配下への展開）。
- Indicators: `strings` で `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` などが検出される。
- Runtime artifacts: `/tmp/_MEI*` またはカスタムの `--runtime-tmpdir` パスへの展開。
- hardcoded OAuth Bearer tokenを使用するDropbox-backed C2
- Network markers: `Authorization: Bearer <token>` を伴う `api.dropboxapi.com` / `content.dropboxapi.com`。
- 通常はファイルをsyncしないserver workloadからDropbox domainへ送信されるHTTPSを、proxy/NetFlow/Zeek/Suricataでhuntする。
- tunneling（例: Cloudflare Tunnel `cloudflared`）によるparallel/backup C2。片方のchannelがblockされてもcontrolを維持する。
- Host IOCs: `cloudflared` process/unit、`~/.cloudflared/*.json` のconfig、Cloudflare edgeへのoutbound 443。

### accessを維持するためのPersistenceと“hardening rollback”（Linuxの例）
Attackersは、self-patchingとdurable access pathを頻繁に組み合わせる:<sup>[[3]](#references)</sup>
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
# "yes" などの値や、過度に permissive な設定をflagする
```
- system account（例: `games`）に対するsuspicious interactive shellをhuntする:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- 8個のalphabetical characterによるrandomで短い名前のbeacon artifactがディスクにdropされ、cloud C2にもcontactする:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenderは、これらのartifactをexternal exposureおよびservice patching eventと関連付け、初回exploitを隠すために使用されたanti-forensic self-remediationを明らかにすべきである。

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
