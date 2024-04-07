<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong>！</summary>

HackTricks をサポートする他の方法：

- **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 の **@hacktricks_live** をフォローする
- **ハッキングトリックを共有**するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

# タイムスタンプ

攻撃者は**ファイルのタイムスタンプを変更**して検出を回避する可能性があります。\
MFT内の属性 `$STANDARD_INFORMATION` と `$FILE_NAME` にタイムスタンプを見つけることができます。

両方の属性には4つのタイムスタンプがあります：**変更**、**アクセス**、**作成**、**MFTレジストリの変更**（MACEまたはMACB）。

**Windowsエクスプローラ**や他のツールは **`$STANDARD_INFORMATION`** から情報を表示します。

## TimeStomp - アンチフォレンジックツール

このツールは **`$STANDARD_INFORMATION`** 内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`** 内の情報は**変更しません**。そのため、**疑わしい活動を特定**することが可能です。

## Usnjrnl

**USNジャーナル**（Update Sequence Number Journal）はNTFS（Windows NTファイルシステム）の機能で、ボリュームの変更を追跡します。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ツールを使用してこれらの変更を調査できます。

![](<../../.gitbook/assets/image (449).png>)

前述の画像は、ファイルにいくつかの変更が加えられたことが示されている **ツール**の **出力**です。

## $LogFile

ファイルシステムへのすべてのメタデータ変更は、[先行ログ記録](https://en.wikipedia.org/wiki/Write-ahead_logging)としてプロセスに記録されます。記録されたメタデータは、NTFSファイルシステムのルートディレクトリにある `**$LogFile**` という名前のファイルに保持されます。[LogFileParser](https://github.com/jschicht/LogFileParser)などのツールを使用して、このファイルを解析して変更を特定できます。

![](<../../.gitbook/assets/image (450).png>)

同様に、ツールの出力では **いくつかの変更が行われた**ことがわかります。

同じツールを使用して、**タイムスタンプがいつ変更されたか**を特定できます：

![](<../../.gitbook/assets/image (451).png>)

- CTIME：ファイルの作成時刻
- ATIME：ファイルの変更時刻
- MTIME：ファイルのMFTレジストリの変更
- RTIME：ファイルのアクセス時刻

## `$STANDARD_INFORMATION` と `$FILE_NAME` の比較

疑わしい変更されたファイルを特定する別の方法は、両方の属性の時間を比較し、**不一致**を探すことです。

## ナノ秒

**NTFS**のタイムスタンプは**100ナノ秒の精度**を持ちます。そのため、2010-10-10 10:10:**00.000:0000 のようなタイムスタンプを持つファイルは非常に疑わしいです。

## SetMace - アンチフォレンジックツール

このツールは、属性 `$STARNDAR_INFORMATION` と `$FILE_NAME` の両方を変更できます。ただし、Windows Vista以降では、この情報を変更するにはライブOSが必要です。

# データの隠蔽

NFTSはクラスタと最小情報サイズを使用します。つまり、ファイルが1つ半分のクラスタを使用している場合、ファイルが削除されるまで**残りの半分は決して使用されません**。そのため、このスラックスペースにデータを**隠すことが可能**です。

このような「隠された」スペースにデータを隠すことができる slacker などのツールがあります。ただし、`$logfile` と `$usnjrnl` の分析により、データが追加されたことが示される可能性があります：

![](<../../.gitbook/assets/image (452).png>)

その後、FTK Imagerのようなツールを使用してスラックスペースを取得できます。この種のツールは、コンテンツを難読化したり、暗号化したりすることができますので注意してください。

# UsbKill

これは、USBポートに変更が検出された場合にコンピューターを**シャットダウン**するツールです。\
これを発見する方法は、実行中のプロセスを検査し、**実行中の各Pythonスクリプトを確認**することです。

# ライブLinuxディストリビューション

これらのディストリビューションは**RAM内で実行**されます。NTFSファイルシステムが書き込み権限でマウントされている場合にのみ、侵入を検出することが可能です。読み取り権限でマウントされている場合は、検出することはできません。

# 安全な削除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windowsの設定

フォレンジック調査を困難にするために、Windowsの複数のログ記録方法を無効にすることが可能です。

## タイムスタンプの無効化 - UserAssist

これは、ユーザーが実行した各実行可能ファイルの日付と時間を維持するレジストリキーです。

UserAssistを無効にするには、2つの手順が必要です：

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` と `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` の2つのレジストリキーをゼロに設定して、UserAssistを無効にしたいことを示します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` のようなレジストリサブツリーをクリアします。

## タイムスタンプの無効化 - Prefetch

これは、Windowsシステムのパフォーマンスを向上させることを目的として実行されたアプリケーションに関する情報を保存します。ただし、これはフォレンジックの実践にも役立ちます。

- `regedit` を実行
- ファイルパス `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` を選択
- `EnablePrefetcher` と `EnableSuperfetch` の両方を右クリックし、それぞれの値を1（または3）から0に変更するために「変更」を選択
- 再起動

## タイムスタンプの無効化 - 最終アクセス時刻

Windows NTサーバーのNTFSボリュームからフォルダーが開かれるたびに、システムは**リストされた各フォルダーのタイムスタンプフィールド**である最終アクセス時刻を更新します。使用頻度の高いNTFSボリュームでは、これがパフォーマンスに影響する可能性があります。

1. レジストリエディタ（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem` に移動します。
3. `NtfsDisableLastAccessUpdate` を探します。存在しない場合は、このDWORDを追加し、その値を1に設定してプロセスを無効にします。
4. レジストリエディタを閉じ、サーバーを再起動します。
## USB履歴の削除

すべての**USBデバイスエントリ**は、Windowsレジストリ内の**USBSTOR**レジストリキーの下に保存されています。このキーには、PCやラップトップにUSBデバイスを接続するたびに作成されるサブキーが含まれています。このキーはここにあります`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。これを削除することでUSBの履歴を削除できます。\
また、[**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html)ツールを使用して削除したことを確認することもできます。

USBに関する情報を保存する別のファイルは、`C:\Windows\INF`内の`setupapi.dev.log`ファイルです。これも削除する必要があります。

## シャドウコピーの無効化

`vssadmin list shadowstorage`でシャドウコピーを**リスト**します。\
`vssadmin delete shadow`を実行してそれらを**削除**します。

GUIを使用しても削除できます。手順は[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)に提案されている手順に従います。

シャドウコピーを無効にするには[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)に従います：

1. Windowsのスタートボタンをクリックした後、テキスト検索ボックスに「services」と入力してサービスプログラムを開きます。
2. リストから「Volume Shadow Copy」を見つけ、右クリックしてプロパティにアクセスします。
3. 「起動の種類」ドロップダウンメニューから「無効」を選択し、変更を適用してOKをクリックします。

レジストリ`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`でコピーされるファイルの構成を変更することも可能です。

## 削除されたファイルの上書き

* **Windowsツール**を使用できます：`cipher /w:C` これにより、cipherにCドライブ内の未使用ディスク領域からデータを削除するよう指示します。
* [**Eraser**](https://eraser.heidi.ie)などのツールも使用できます。

## Windowsイベントログの削除

* Windows + R --> eventvwr.msc --> 「Windowsログ」を展開 --> 各カテゴリを右クリックして「ログをクリア」を選択します。
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windowsイベントログの無効化

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* サービスセクション内でサービス「Windowsイベントログ」を無効にします。
* `WEvtUtil.exec clear-log`または`WEvtUtil.exe cl`

## $UsnJrnlの無効化

* `fsutil usn deletejournal /d c:`

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
