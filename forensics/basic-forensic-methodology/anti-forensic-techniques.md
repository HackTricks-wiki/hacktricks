```markdown
# タイムスタンプ

攻撃者は、検出を避けるために**ファイルのタイムスタンプを変更する**ことに興味を持つかもしれません。
タイムスタンプは、MFT内の`$STANDARD_INFORMATION`と`$FILE_NAME`の属性で見つけることができます。

両方の属性には4つのタイムスタンプがあります：**変更**、**アクセス**、**作成**、そして**MFTレジストリの変更**（MACEまたはMACB）。

**Windowsエクスプローラー**や他のツールは、**`$STANDARD_INFORMATION`**からの情報を表示します。

## TimeStomp - アンチフォレンジックツール

このツールは**`$STANDARD_INFORMATION`**内のタイムスタンプ情報を**変更しますが**、**`$FILE_NAME`**内の情報は**変更しません**。したがって、**疑わしい**活動を**特定**することが可能です。

## Usnjrnl

**USNジャーナル**（Update Sequence Number Journal）、またはチェンジジャーナルは、Windows NTファイルシステム（NTFS）の機能で、ボリュームに加えられた変更の記録を**保持します**。
この記録の変更を検索するために、ツール[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)を使用することができます。

![](<../../.gitbook/assets/image (449).png>)

前の画像は、**ツール**によって表示される**出力**で、ファイルに対していくつかの**変更が行われた**ことが観察できます。

## $LogFile

ファイルシステムのメタデータの変更はすべてログされ、システムクラッシュ後に重要なファイルシステム構造の一貫した回復を保証するためです。これは[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)と呼ばれます。
ログされたメタデータは、“**$LogFile**”と呼ばれるファイルに保存され、NTFSファイルシステムのルートディレクトリで見つけることができます。
このファイルを解析し、変更を見つけるために、ツール[LogFileParser](https://github.com/jschicht/LogFileParser)などを使用することができます。

![](<../../.gitbook/assets/image (450).png>)

再び、ツールの出力で**いくつかの変更が行われた**ことが見られます。

同じツールを使用して、タイムスタンプが**いつに変更されたかを特定**することも可能です：

![](<../../.gitbook/assets/image (451).png>)

* CTIME: ファイルの作成時間
* ATIME: ファイルの変更時間
* MTIME: ファイルのMFTレジストリ変更
* RTIME: ファイルのアクセス時間

## `$STANDARD_INFORMATION`と`$FILE_NAME`の比較

疑わしい変更されたファイルを特定する別の方法は、両方の属性の時間を比較して**不一致**を探すことです。

## ナノ秒

**NTFS**のタイムスタンプは**100ナノ秒**の**精度**を持っています。したがって、2010-10-10 10:10:**00.000:0000のようなタイムスタンプを持つファイルを見つけることは非常に疑わしいです。

## SetMace - アンチフォレンジックツール

このツールは、`$STARNDAR_INFORMATION`と`$FILE_NAME`の両方の属性を変更することができます。しかし、Windows Vistaからは、この情報を変更するためにはライブOSが必要です。

# データ隠蔽

NFTSはクラスタを使用し、最小情報サイズを使用します。つまり、ファイルがクラスタと半分を使用している場合、**残りの半分はファイルが削除されるまで決して使用されません**。したがって、このスラックスペースにデータを**隠すことが可能**です。

slackerのようなツールがあり、この「隠された」スペースにデータを隠すことを可能にします。しかし、`$logfile`と`$usnjrnl`の分析は、いくつかのデータが追加されたことを示すかもしれません：

![](<../../.gitbook/assets/image (452).png>)

その後、FTK Imagerのようなツールを使用してスラックスペースを取得することが可能です。この種のツールは、内容を難読化または暗号化して保存することができます。

# UsbKill

これは、USBポートに変更が検出された場合に**コンピュータをオフにする**ツールです。
これを発見する方法は、実行中のプロセスを検査し、**実行中の各pythonスクリプトをレビューする**ことです。

# ライブLinuxディストリビューション

これらのディストリは**RAMメモリ内で実行されます**。NTFSファイルシステムが書き込み権限でマウントされた場合にのみ検出することができます。読み取り権限のみでマウントされた場合は、侵入を検出することはできません。

# 安全な削除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windowsの設定

いくつかのWindowsログ方法を無効にして、フォレンジック調査をはるかに困難にすることが可能です。

## タイムスタンプを無効にする - UserAssist

これは、ユーザーによって実行された各実行可能ファイルの日付と時間を保持するレジストリキーです。

UserAssistを無効にするには2つのステップが必要です：

1. UserAssistを無効にしたいことを示すために、`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`と`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`の両方のレジストリキーをゼロに設定します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`のように見えるレジストリサブツリーをクリアします。

## タイムスタンプを無効にする - Prefetch

これは、Windowsシステムのパフォーマンスを向上させる目的で実行されたアプリケーションに関する情報を保存します。しかし、これはフォレンジック実践にも役立つ可能性があります。

* `regedit`を実行します
* ファイルパス`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`を選択します
* `EnablePrefetcher`と`EnableSuperfetch`の両方を右クリックします
* それぞれの値を1（または3）から0に変更するために、Modifyを選択します
* 再起動します

## タイムスタンプを無効にする - 最終アクセス時間

Windows NTサーバー上のNTFSボリュームからフォルダが開かれるたびに、システムは最終アクセス時間と呼ばれる各リストされたフォルダのタイムスタンプフィールドを**更新する時間を取ります**。頻繁に使用されるNTFSボリュームでは、これはパフォーマンスに影響を与える可能性があります。

1. レジストリエディタ（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`に移動します。
3. `NtfsDisableLastAccessUpdate`を探します。存在しない場合は、このDWORDを追加し、その値を1に設定します。これにより、プロセスが無効になります。
4. レジストリエディタを閉じ、サーバーを再起動します。

## USB履歴を削除する

すべての**USBデバイスエントリ**は、PCまたはラップトップにUSBデバイスを接続するたびに作成されるサブキーを含むWindowsレジストリの**USBSTOR**レジストリキーの下に保存されます。このキーは`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`で見つけることができます。**これを削除する**と、USBの履歴が削除されます。
また、削除されたことを確認するために（そして削除するために）ツール[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)を使用することもできます。

USBに関する情報を保存する別のファイルは、`C:\Windows\INF`内の`setupapi.dev.log`です。これも削除する必要があります。

## シャドウコピーを無効にする

**リスト**シャドウコピーは`vssadmin list shadowstorage`で行います\
**削除**は`vssadmin delete shadow`を実行して行います

GUIを介して削除することもできます。[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)で提案されている手順に従ってください。

シャドウコピーを無効にするには：

1. Windowsのスタートボタンに移動し、「services」と入力してテキスト検索ボックスに入力し、Servicesプログラムを開きます。
2. リストから「Volume Shadow Copy」を見つけ、ハイライトし、右クリック>プロパティを選択します。
3. 「スタートアップタイプ」ドロップダウンメニューから、無効を選択し、適用してOKをクリックします。

![](<../../.gitbook/assets/image (453).png>)

また、レジストリ`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`の設定を変更して、シャドウコピーにコピーされるファイルを変更することも可能です。

## 削除されたファイルを上書きする

* **Windowsツール**を使用できます：`cipher /w:C` これは、Cドライブ内の利用可能な未使用のディスクスペースからデータを削除するようにcipherに指示します。
* [**Eraser**](https://eraser.heidi.ie)のようなツールも使用できます

## Windowsイベントログを削除する

* Windows + R --> eventvwr.msc --> 「Windowsログ」を展開 --> 各カテゴリを右クリックして「ログのクリア」を選択
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windowsイベントログを無効にする

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* サービスセクション内で「Windowsイベントログ」サービスを無効にします
* `WEvtUtil.exec clear-log`または`WEvtUtil.exe cl`

## $UsnJrnlを無効にする

* `fsutil usn deletejournal /d c:`

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。これは私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
```
