# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

攻撃者は、検知を避けるために**ファイルのタイムスタンプを変更**しようとすることがあります。\
タイムスタンプは、MFT 内の属性 `$STANDARD_INFORMATION` \_\_ と \_\_ `$FILE_NAME` にあります。

どちらの属性にも、**Modification**、**access**、**creation**、**MFT registry modification** の4つのタイムスタンプがあります（MACE または MACB）。

**Windows エクスプローラー**やその他のツールには、**`$STANDARD_INFORMATION`** の情報が表示されます。

### TimeStomp - Anti-forensic Tool

このツールは、**`$STANDARD_INFORMATION`** 内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`** 内の情報は変更しません。そのため、**不審なアクティビティ**を**特定**できます。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal）は、ボリュームの変更を記録する NTFS（Windows NT file system）の機能です。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ツールを使うと、これらの変更を調査できます。

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal（Update Sequence Number Journal）は、ボリュームの変更を記録する NTFS（Windows NT file system）の機能です。...](<../../images/image (801).png>)

上の画像は**ツールの出力**で、ファイルに対して**いくつかの変更が行われた**ことを確認できます。

### $LogFile

ファイルシステムに対する**すべてのメタデータ変更は、**[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) と呼ばれるプロセスで記録されます。記録されたメタデータは、NTFS ファイルシステムのルートディレクトリにある `**$LogFile**` というファイルに保存されます。[LogFileParser](https://github.com/jschicht/LogFileParser) などのツールを使ってこのファイルを解析し、変更を特定できます。

![Usnjrnl - $LogFile: ファイルシステムに対するすべてのメタデータ変更は、write-ahead logging と呼ばれるプロセスで記録されます。記録されたメタデータは、ルート...にある $LogFile というファイルに保存されます。](<../../images/image (137).png>)

ここでも、ツールの出力から**いくつかの変更が行われた**ことを確認できます。

同じツールを使うと、**タイムスタンプがいつに変更されたか**を特定できます。

![Usnjrnl - $LogFile: 同じツールを使うと、タイムスタンプがいつに変更されたかを特定できます](<../../images/image (1089).png>)

- CTIME: ファイルの作成時刻
- ATIME: ファイルの変更時刻
- MTIME: ファイルの MFT registry modification
- RTIME: ファイルのアクセス時刻

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

不審な変更が加えられたファイルを特定するもう1つの方法は、両方の属性の時刻を比較し、**不一致**を探すことです。

### Nanoseconds

**NTFS** のタイムスタンプの**精度**は**100ナノ秒**です。そのため、2010-10-10 10:10:**00.000:0000 のようなタイムスタンプを持つファイルは非常に不審です**。

### SetMace - Anti-forensic Tool

このツールは、属性 `$STARNDAR_INFORMATION` と `$FILE_NAME` の両方を変更できます。ただし、Windows Vista 以降では、この情報を変更するには OS が起動している必要があります。

## Data Hiding

NFTS はクラスター単位で処理し、情報の最小サイズを使用します。つまり、ファイルがクラスター1つ半を使用している場合、ファイルが削除されるまで、**残りの半分は使用されません**。そのため、このスラックスペースに**データを隠す**ことができます。

slacker など、この「隠された」スペースにデータを隠せるツールがあります。ただし、`$logfile` と `$usnjrnl` を分析すると、データが追加されたことがわかる場合があります。

![SetMace - Anti-forensic Tool - Data Hiding: slacker など、この「隠された」スペースにデータを隠せるツールがあります。ただし、$logfile と $usnjrnl を分析すると...](<../../images/image (1060).png>)

その後、FTK Imager などのツールを使ってスラックスペースからデータを取得できます。この種のツールでは、難読化または暗号化されたコンテンツとして保存できることに注意してください。

## UsbKill

これは、USB ポートに変更が検出されると**コンピューターをシャットダウンする**ツールです。\
実行中のプロセスを調べ、実行中の Python スクリプトを**それぞれ確認する**ことで発見できる場合があります。

## Live Linux Distributions

これらのディストリビューションは**RAM 内で実行されます**。検出できるのは、NTFS ファイルシステムが書き込み権限付きでマウントされている場合のみです。読み取り権限だけでマウントされている場合、侵入を検出することはできません。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Delayed Windows self-deletion

Windows のイメージは、プロセスの実行中にロックされることがあります。プロセスは削除処理を子 `cmd.exe` に渡し、`choice` をタイマーとして使い、シェルが `del` を実行する前に終了できます。遅延を設けることで、元のプロセスがイメージハンドルを解放できます。パスにスペースが含まれる場合は、フルパスを引用符で囲む必要があります。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

この文字列を別の対話型 `cmd` プロンプトから入力せず、`cmd.exe` の引数として直接渡す場合は、`^&` の代わりに `&` を、`^>nul` の代わりに `>nul` を使用してください。これによりディレクトリエントリは削除されますが、**安全な消去ではありません**。実行履歴、タスク、ファイルシステムジャーナル、その他のフォレンジック痕跡は削除されません。コマンドラインに `choice /T`、`Del`、親プロセスのイメージパスを含む、短時間だけ存在する `cmd.exe` の子プロセスを探してください。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows の設定

フォレンジック調査を大幅に困難にするため、Windows のいくつかのログ記録方法を無効にできます。

### タイムスタンプの無効化 - UserAssist

これは、ユーザーが各実行ファイルを実行した日時を記録するレジストリキーです。

UserAssist を無効にするには、次の2つの手順が必要です。

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` と `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` の2つのレジストリキーを両方ともゼロに設定し、UserAssist を無効にするよう指定します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` のようなレジストリサブツリーを消去します。

### タイムスタンプの無効化 - Prefetch

Windows システムのパフォーマンス向上を目的として、実行されたアプリケーションの情報を保存します。ただし、この情報はフォレンジック調査にも役立ちます。

- `regedit` を実行します
- ファイルパス `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` を選択します
- `EnablePrefetcher` と `EnableSuperfetch` の両方を右クリックします
- それぞれの値を1（または3）から0に変更するため、［修正］を選択します
- 再起動します

### タイムスタンプの無効化 - 最終アクセス時刻

Windows NT サーバー上の NTFS ボリュームからフォルダーを開くと、システムは「最終アクセス時刻」と呼ばれる**タイムスタンプフィールドを、一覧にある各フォルダーで更新**します。頻繁に使用される NTFS ボリュームでは、これがパフォーマンスに影響する場合があります。

1. レジストリエディター（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` に移動します。
3. `NtfsDisableLastAccessUpdate` を探します。存在しない場合は、この DWORD を追加して値を1に設定すると、この処理が無効になります。
4. レジストリエディターを閉じ、サーバーを再起動します。

### USB 履歴の削除

すべての**USB デバイスエントリ**は、Windows レジストリの **USBSTOR** キーに保存されます。このキーには、USB デバイスを PC またはノート PC に接続するたびに作成されるサブキーが含まれています。このキーは H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR` にあります。**これを削除すると**、USB 履歴が削除されます。\
ツール [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) を使用して、削除されたことを確認したり（または削除したり）することもできます。

USB に関する情報を保存する別のファイルとして、`C:\Windows\INF` 内の `setupapi.dev.log` があります。これも削除してください。

### シャドウコピーの無効化

`vssadmin list shadowstorage` でシャドウコピーを**一覧表示**します。\
`vssadmin delete shadow` を実行してシャドウコピーを**削除**します。

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) で説明されている手順に従い、GUI から削除することもできます。

シャドウコピーを無効にするには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)に従います。

1. Windows のスタートボタンをクリックし、テキスト検索ボックスに「services」と入力して、［サービス］プログラムを開きます。
2. 一覧から「Volume Shadow Copy」を探して選択し、右クリックして［プロパティ］を開きます。
3. 「スタートアップの種類」ドロップダウンメニューから［無効］を選択し、［適用］と［OK］をクリックして変更を確定します。

レジストリ `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` で、シャドウコピーの対象となるファイルの設定を変更することもできます。

### 削除済みファイルの上書き

- **Windows ツール**を使用できます。`cipher /w:C` を実行すると、C ドライブ内の使用可能な未使用ディスク領域からデータを削除するよう cipher に指示します。
- [**Eraser**](https://eraser.heidi.ie) などのツールも使用できます。

### Windows イベントログの削除

- Windows + R --> eventvwr.msc --> 「Windows ログ」を展開 --> 各カテゴリを右クリックし、「ログの消去」を選択
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows イベントログの無効化

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- サービスの項目で「Windows Event Log」サービスを無効にします
- `WEvtUtil.exec clear-log` または `WEvtUtil.exe cl`

### $UsnJrnl の無効化

- `fsutil usn deletejournal /d c:`

---

## 高度なログ記録と痕跡の改ざん（2023-2025）

### PowerShell ScriptBlock/Module Logging

最近の Windows 10/11 と Windows Server のバージョンでは、`Microsoft-Windows-PowerShell/Operational`（イベント 4104/4105/4106）に**詳細な PowerShell フォレンジックアーティファクト**が保存されます。  
攻撃者は、これらを実行中に無効化したり消去したりできます。

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

Defendersは、これらのレジストリキーの変更と、PowerShellイベントの大量削除を監視する必要があります。

### ETW (Event Tracing for Windows) Patch

Endpoint security製品はETWに大きく依存しています。2024年に広く使われた回避手法は、メモリ内の`ntdll!EtwEventWrite`/`EtwEventWriteFull`をpatchし、イベントを出力せずにすべてのETW呼び出しが`STATUS_SUCCESS`を返すようにするものです。<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoC（例: `EtwTiSwallow`）は、PowerShell または C++ で同じプリミティブを実装しています。  
パッチは**プロセス内に限定される**ため、他のプロセス内で動作する EDR はパッチを見逃す可能性があります。<sup>[[5]](#references)</sup>
検出方法: メモリ内の `ntdll` とディスク上のものを比較するか、ユーザーモードに入る前にフックします。

### Alternate Data Streams (ADS) の復活

2023 年には、マルウェアキャンペーン（例: **FIN12** のローダー）が、従来のスキャナーの目を逃れるため、ADS 内に第 2 段階のバイナリを配置する事例が確認されています:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

`dir /R`、`Get-Item -Stream *`、または Sysinternals の `streams64.exe` でストリームを列挙します。
ホストファイルを FAT/exFAT にコピーしたり、SMB 経由でコピーしたりすると、隠しストリームが削除されるため、調査担当者がペイロードを復元する手段として利用できます。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver は、ランサムウェア侵入における **anti-forensics** の手段として、今では日常的に使われています。  
オープンソースツール **AuKill** は、署名済みながら脆弱性のあるドライバー（`procexp152.sys`）を読み込み、**暗号化とログ破壊の前に** EDR やフォレンジックセンサーを一時停止または終了させます。<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

ドライバーはその後削除され、痕跡は最小限に抑えられます。<sup>[[1]](#references)</sup>  
緩和策: Microsoft vulnerable-driver blocklist (HVCI/SAC) を有効にし、ユーザーが書き込み可能なパスからの kernel-service 作成を検知して警告します。

---

## Linux Anti-Forensics: Self-Patching と Cloud C2 (2023–2025)

### 検知を減らすため、侵害したサービスに自己パッチを適用する (Linux)
攻撃者は、再度の悪用を防ぎ、脆弱性ベースの検知を抑制するため、サービスの悪用直後に「self-patch」を適用するケースが増えています。脆弱なコンポーネントを、最新の正規 upstream バイナリ/JAR に置き換えることで、永続化と C2 を維持しながら、スキャナーにはホストがパッチ適用済みと報告させる手法です。<sup>[[3]](#references)</sup>

例: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)。<sup>[[3]](#references)[[4]](#references)</sup>
- 悪用後、攻撃者は Maven Central (repo1.maven.org) から正規の JAR を取得し、ActiveMQ のインストール先にある脆弱な JAR を削除して、ブローカーを再起動しました。
- これにより初期の RCE を塞ぎつつ、他の足掛かり (cron、SSH 設定の変更、別個の C2 implant) を維持しました。

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
- サービスディレクトリを確認し、予定外のバイナリ/JARの置き換えがないか調べる:
  - Debian/Ubuntu: `dpkg -V activemq` を実行し、ファイルのハッシュ/パスをリポジトリのミラーと比較する。
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - ディスク上に存在するがパッケージマネージャーが所有していないJARのバージョンや、帯域外で更新されたシンボリックリンクを探す。
- タイムライン: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` を実行し、ctime/mtimeを侵害期間と照合する。
- シェル履歴/プロセスのテレメトリ: 初回の悪用直後に `repo1.maven.org` やその他のアーティファクトCDNへ `curl`/`wget` した痕跡。
- 変更管理: パッチ適用済みのバージョンが存在することだけでなく、誰が、なぜ「パッチ」を適用したのか確認する。

### Bearer tokenとanti-analysis stagerを使ったクラウドサービスC2
観測されたtradecraftでは、複数の長期運用C2経路とanti-analysisを意識したパッケージングが組み合わされていた:<sup>[[3]](#references)</sup>
- sandboxingとstatic analysisを妨げる、パスワード保護されたPyInstaller ELF loader（例: 暗号化されたPYZ、`/_MEI*` 以下への一時展開）。
  - Indicators: `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` などの `strings` の検出結果。
  - Runtime artifacts: `/tmp/_MEI*` またはカスタムの `--runtime-tmpdir` パスへの展開。
- ハードコードされたOAuth Bearer tokenを使うDropboxベースのC2
  - Network markers: `Authorization: Bearer <token>` を伴う `api.dropboxapi.com` / `content.dropboxapi.com`。
  - 通常ファイルを同期しないサーバーのワークロードからDropboxドメインへのアウトバウンドHTTPS通信がないか、proxy/NetFlow/Zeek/Suricataを調査する。
- トンネリング（例: Cloudflare Tunnel `cloudflared`）を使った並行/バックアップC2。片方のチャネルが遮断されても制御を維持する。
  - Host IOCs: `cloudflared` のプロセス/units、`~/.cloudflared/*.json` の設定、Cloudflareのエッジへのアウトバウンド443通信。

### アクセスを維持するための永続化と「hardening rollback」（Linuxの例）
攻撃者は、自己パッチ適用と永続的なアクセス経路を組み合わせることが多い:<sup>[[3]](#references)</sup>
- Cron/Anacron: 定期実行のため、各 `/etc/cron.*/` ディレクトリ内の `0anacron` stubを編集する。
  - 調査:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH configuration hardeningのロールバック: root loginを有効にし、低権限アカウントのデフォルトシェルを変更する。
  - root loginの有効化を探す:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - システムアカウント（例: `games`）に不審な対話型シェルが設定されていないか調べる:
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- ランダムな短い名前（アルファベット8文字）の beacon artifact がディスクにドロップされ、cloud C2にも接続する：
  - 調査：
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

防御側は、これらの痕跡を外部への露出やサービスのパッチ適用イベントと照合し、最初の侵害を隠すために使われたanti-forensicな自己修復を明らかにする必要があります。

## 静的組み込みシェルによる実行

インタプリタとコマンドの実装を組み込んだスクリプトラッパーは、`/bin/sh`や個別のユーティリティプロセスを起動せずに、1つの実行ファイル内で対応するシェル操作を実行できます。HimitsuShellは、このような静的muslバイナリをビルドします。[SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md)とは異なり、組み込みコマンドの実行にホストのシェルや個別のユーティリティプロセスを起動する必要はありません。未対応のコマンドはシステムシェルにフォールバックできます。<sup>[[9]](#references)</sup>

これにより、シェルプロセスや子プロセスの`execve`が可視化されにくくなります。<sup>[[9]](#references)</sup> ラッパープロセスとそのシステムコールは、カーネルトレースポイントを通じて引き続き観測可能です。そのため、カーネルトレースに対しても不可視だというプロジェクトの主張を文字どおりに受け取るべきではありません。<sup>[[9]](#references)[[11]](#references)</sup>

ドキュメントに記載されているx86_64ビルドでは、入力ファイルの名前を`launcher.sh`のままにし、コンパイル前にコンテナにコピーしてください。出力ファイルは`safeLauncher`です。<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

公開されている `compile.sh` は、スクリプトを AES-256-CTR で暗号化し、有効期限の値と中間鍵／IVを AES-256-CBC で暗号化します。暗号化したファイルを `xxd -i` で C 配列に変換し、`-static -s` を指定して `lib.bc` とリンクします。最終的な暗号化キーと IV も埋め込まれるため、これは簡単な静的抽出への耐性であり、決して復元できない秘密ではありません。<sup>[[10]](#references)</sup>

デフォルトの LLVM パスは `-sobf` と `-sub` です。ドキュメントに記載された代替手法である制御フローのフラット化（`fla`）や bogus control flow（`bcf`）を有効にするには、ビルド前に `/var/work/compile.sh` を編集してください。<sup>[[9]](#references)[[10]](#references)</sup>

このラッパーに依存する前に、スクリプトとの互換性をテストしてください。このプロジェクトは POSIX shell 構文を対象としており、Bash／Zsh スクリプトは失敗する場合があると警告しています。また、組み込みコマンド以外のコマンドはシステムシェルを呼び出すと説明しています。<sup>[[9]](#references)</sup>

フラット化された制御フローの分析については、[狭い実行スライスを使ったフラット化制御フローのバイパス](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice)を参照してください。

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill：EDR を無効化するための兵器化された脆弱なドライバー（2023年3月）](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – ステルスのための EtwEventWrite のパッチ適用：検出とハンティング（2024年6月）](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – 永続化のためのパッチ適用：DripDropper Linux マルウェアがクラウド内を移動する方法](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE（NVD）](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [.NET の隠蔽 – ETW（Adam Chester / XPN）](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – 正規ソフトウェアに埋め込まれた SectopRAT の亜種を解明](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice コマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del コマンド](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell ビルドスクリプト](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux カーネルのイベントヒストグラムとシステムコールのトレース](https://docs.kernel.org/trace/histogram.html)
