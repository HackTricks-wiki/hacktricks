<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを発見
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする。

* **HackTricks**（https://github.com/carlospolop/hacktricks）および**HackTricks Cloud**（https://github.com/carlospolop/hacktricks-cloud）のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>


# タイムスタンプ

攻撃者は**ファイルのタイムスタンプを変更**して検出を回避する可能性があります。\
MFT内の属性`$STANDARD_INFORMATION`および`$FILE_NAME`にタイムスタンプが含まれている可能性があります。

両方の属性には4つのタイムスタンプがあります：**変更**、**アクセス**、**作成**、および**MFTレジストリの変更**（MACEまたはMACB）。

**Windowsエクスプローラ**や他のツールは**`$STANDARD_INFORMATION`**から情報を表示します。

## TimeStomp - アンチフォレンジックツール

このツールは**`$STANDARD_INFORMATION`**内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`**内の情報は**変更しません**。したがって、**疑わしい活動を特定**することが可能です。

## Usnjrnl

**USNジャーナル**（Update Sequence Number Journal）はNTFS（Windows NTファイルシステム）の機能であり、ボリュームの変更を追跡します。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)ツールを使用してこれらの変更を調査できます。

![](<../../.gitbook/assets/image (449).png>)

前述の画像は、ファイルにいくつかの変更が加えられたことが示されているツールの**出力**です。

## $LogFile

ファイルシステムへのすべてのメタデータ変更は、[先行ログ記録](https://en.wikipedia.org/wiki/Write-ahead_logging)としてプロセスに記録されます。記録されたメタデータは、NTFSファイルシステムのルートディレクトリにある`**$LogFile**`という名前のファイルに保持されます。[LogFileParser](https://github.com/jschicht/LogFileParser)などのツールを使用して、このファイルを解析し変更を特定できます。

![](<../../.gitbook/assets/image (450).png>)

ツールの出力でも、**いくつかの変更が行われた**ことがわかります。

同じツールを使用して、**タイムスタンプがいつ変更されたか**を特定することが可能です：

![](<../../.gitbook/assets/image (451).png>)

* CTIME：ファイルの作成時刻
* ATIME：ファイルの変更時刻
* MTIME：ファイルのMFTレジストリの変更
* RTIME：ファイルのアクセス時刻

## `$STANDARD_INFORMATION`と`$FILE_NAME`の比較

疑わしい変更されたファイルを特定する別の方法は、両方の属性の時間を比較し、**不一致**を探すことです。

## ナノ秒

**NTFS**のタイムスタンプは**100ナノ秒の精度**を持ちます。そのため、2010-10-10 10:10:**00.000:0000のようなタイムスタンプを持つファイルは非常に疑わしいです**。

## SetMace - アンチフォレンジックツール

このツールは、属性`$STARNDAR_INFORMATION`と`$FILE_NAME`の両方を変更できます。ただし、Windows Vista以降では、この情報を変更するにはライブOSが必要です。

# データの隠蔽

NFTSはクラスターと最小情報サイズを使用します。つまり、ファイルが1つのクラスターと半分を使用している場合、**残りの半分はファイルが削除されるまで使用されません**。そのため、このスラックスペースにデータを**隠すことが可能**です。

この「隠された」スペースにデータを隠すことができるslackerなどのツールがあります。ただし、`$logfile`および`$usnjrnl`の分析により、データが追加されたことが示される場合があります：

![](<../../.gitbook/assets/image (452).png>)

その後、FTK Imagerなどのツールを使用してスラックスペースを回復することが可能です。この種のツールは、コンテンツを難読化したり、暗号化したりすることができます。

# UsbKill

このツールは、USBポートに変更が検出されるとコンピューターを**シャットダウン**します。\
これを発見する方法は、実行中のプロセスを検査し、**実行中の各Pythonスクリプトを確認**することです。

# ライブLinuxディストリビューション

これらのディストリビューションは**RAM内で実行**されます。NTFSファイルシステムが書き込み権限でマウントされている場合にのみ、それらを検出することが可能です。読み取り権限のみでマウントされている場合は侵入を検出することはできません。

# 安全な削除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windowsの設定

フォレンジック調査を困難にするために、Windowsの複数のログ記録方法を無効にすることが可能です。

## タイムスタンプの無効化 - UserAssist

これは、ユーザーが実行した各実行可能ファイルの日付と時刻を維持するレジストリキーです。

UserAssistを無効にするには、2つの手順が必要です：

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`および`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`という2つのレジストリキーをゼロに設定して、UserAssistを無効にしたいことを示します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`のようなレジストリサブツリーをクリアします。

## タイムスタンプの無効化 - Prefetch

これは、Windowsシステムのパフォーマンスを向上させるために実行されたアプリケーションに関する情報を保存します。ただし、これはフォレンジックの実践にも役立ちます。

* `regedit`を実行します
* ファイルパス`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`を選択します
* `EnablePrefetcher`および`EnableSuperfetch`の両方を右クリックし、それぞれの「修正」を選択して、値を1（または3）から0に変更します
* 再起動します

## タイムスタンプの無効化 - 最終アクセス時刻

Windows NTサーバーのNTFSボリュームからフォルダーが開かれるたびに、システムは**リストされた各フォルダーのタイムスタンプフィールド**である最終アクセス時刻を更新します。使用頻度の高いNTFSボリュームでは、これがパフォーマンスに影響する可能性があります。

1. レジストリエディタ（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`に移動します。
3. `NtfsDisableLastAccessUpdate`を探します。存在しない場合は、このDWORDを追加し、その値を1に設定してプロセスを無効にします。
4. レジストリエディタを閉じ、サーバーを再起動します。

## USB履歴の削除

すべての**USBデバイスエントリ**は、Windowsレジストリの**USBSTOR**レジストリキーの下に保存されます。このキーには、PCまたはラップトップにUSBデバイスを接続するたびに作成されるサブキーが含まれています。このキーはここにあります`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。これを削除すると、USBの履歴が削除されます。\
これらを削除したことを確認するために、ツール[**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html)を使用することもできます（および削除することもできます）。

USBに関する情報を保存する別のファイルは、`C:\Windows\INF`内の`setupapi.dev.log`ファイルです。これも削除する必要があります。

## シャドウコピーの無効化

`vssadmin list shadowstorage`でシャドウコピーを**リスト**します\
`vssadmin delete shadow`を実行してそれらを**削除**します

[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)で提案された手順に従ってGUIからも削除できます。

シャドウコピーを無効にするには、[ここからの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)に従います：

1. Windowsスタートボタンをクリックした後、テキスト検索ボックスに「services」と入力して、サービスプログラムを開きます。
2. リストから「Volume Shadow Copy」を見つけ、右クリックしてプロパティにアクセスします。
3. 「起動の種類」ドロップダウンメニューから「無効」を選択し、変更を適用してOKをクリックします。

また、レジストリ`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`でコピーされるファイルの構成を変更することも可能です。

## 削除されたファイルの上書き

* **Windowsツール**を使用できます：`cipher /w:C` これにより、Cドライブ内の未使用ディスク領域からデータを削除するようにcipherに指示されます。
* [**Eraser**](https://eraser.heidi.ie)などのツールも使用できます

## Windowsイベントログの削除

* Windows + R --> eventvwr.msc --> "Windows Logs"を展開 --> 各カテゴリを右クリックして「ログをクリア」を選択
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windowsイベントログの無効化

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* サービスセクション内でサービス「Windows Event Log」を無効にします
* `WEvtUtil.exec clear-log`または`WEvtUtil.exe cl`

## $UsnJrnlの無効化

* `fsutil usn deletejournal /d c:`

</details>
