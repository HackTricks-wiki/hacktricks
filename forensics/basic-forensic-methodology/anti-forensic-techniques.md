<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


# タイムスタンプ

攻撃者は、検出を回避するためにファイルのタイムスタンプを変更することに興味を持つかもしれません。\
MFT内の属性`$STANDARD_INFORMATION`と`$FILE_NAME`には、タイムスタンプが含まれています。

両方の属性には、**変更**、**アクセス**、**作成**、および**MFTレジストリの変更**（MACEまたはMACB）の4つのタイムスタンプがあります。

**Windowsエクスプローラ**や他のツールは、**`$STANDARD_INFORMATION`**の情報を表示します。

## TimeStomp - アンチフォレンジックツール

このツールは、**`$STANDARD_INFORMATION`**内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`**内の情報は変更しません。したがって、**不審な活動**を**特定**することができます。

## Usnjrnl

**USNジャーナル**（Update Sequence Number Journal）または変更ジャーナルは、Windows NTファイルシステム（NTFS）の機能であり、**ボリュームへの変更の記録を保持**します。\
このレコードの変更を検索するために、[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)というツールを使用することができます。

![](<../../.gitbook/assets/image (449).png>)

前の画像は、ツールによって表示される**出力**で、いくつかの**変更がファイルに行われた**ことがわかります。

## $LogFile

ファイルシステムのすべてのメタデータの変更は、システムクラッシュ後の重要なファイルシステム構造の一貫した回復を保証するためにログに記録されます。これは[write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging)と呼ばれます。\
記録されたメタデータは、「**$LogFile**」という名前のファイルに格納されており、NTFSファイルシステムのルートディレクトリにあります。\
[LogFileParser](https://github.com/jschicht/LogFileParser)などのツールを使用して、このファイルを解析し、変更を見つけることができます。

![](<../../.gitbook/assets/image (450).png>)

ツールの出力でも、**いくつかの変更が行われた**ことがわかります。

同じツールを使用して、**タイムスタンプが変更された時刻**を特定することもできます。

![](<../../.gitbook/assets/image (451).png>)

* CTIME：ファイルの作成時刻
* ATIME：ファイルの変更時刻
* MTIME：ファイルのMFTレジストリの変更時刻
* RTIME：ファイルのアクセス時刻

## `$STANDARD_INFORMATION`と`$FILE_NAME`の比較

変更されたファイルを特定する別の方法は、両方の属性の時間を比較し、**不一致**を探すことです。

## ナノ秒

**NTFS**のタイムスタンプは、**100ナノ秒**の精度を持ちます。そのため、2010-10-10 10:10:**00.000:0000**のようなタイムスタンプを持つファイルは非常に不審です。

## SetMace - アンチフォレンジックツール

このツールは、`$STARNDAR_INFORMATION`と`$FILE_NAME`の両方の属性を変更することができます。ただし、Windows Vista以降では、ライブOSがこの情報を変更するために必要です。

# データの隠蔽

NFTSはクラスタと最小情報サイズを使用します。つまり、ファイルが1つのクラスタと半分を使用している場合、**残りの半分はファイルが削除されるまで使用されません**。そのため、このスラックスペースにデータを**隠すことができます**。

このような「隠された」スペースにデータを隠すことができるslackerなどのツールがあります。ただし、`$logfile`と`$usnjrnl`の分析によって、データが追加されたことがわかる場合があります。

![](<../../.gitbook/assets/image (452).png>)

その後、FTK Imagerなどのツールを使用してスラックスペースを取得することができます。この種のツールは、コンテンツを曖昧化したり、暗号化したりすることができます。

# UsbKill

これは、USBポートに変更が検出された場合にコンピューターを**シャットダウンするツール**です。\
これを発見する方法は、実行中のプロセスを調査し、**実行中の各Pythonスクリプトを確認する**ことです。

# Live Linuxディストリビューション

これらのディストリビューションは、**RAMメモリ内で実行**されます。NTFSファイルシステムが書き込み権限でマウントされている場合にのみ、これらを検出することができます。読み取り権限のみでマウントされている場合、侵入を検出することはできません。
# 安全な削除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windowsの設定

フォレンジック調査を困難にするために、いくつかのWindowsのログ記録方法を無効にすることができます。

## タイムスタンプの無効化 - UserAssist

これは、ユーザーが実行した各実行可能ファイルの日付と時間を保持するレジストリキーです。

UserAssistを無効にするには、2つのステップが必要です。

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`と`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`の2つのレジストリキーを0に設定して、UserAssistを無効にすることを示します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`のようなレジストリのサブツリーをクリアします。

## タイムスタンプの無効化 - Prefetch

これは、Windowsシステムのパフォーマンスを向上させるために実行されたアプリケーションに関する情報を保存します。ただし、これはフォレンジックの実践にも役立ちます。

* `regedit`を実行します。
* ファイルパス`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`を選択します。
* `EnablePrefetcher`と`EnableSuperfetch`の両方を右クリックし、値を1（または3）から0に変更します。
* 再起動します。

## タイムスタンプの無効化 - 最終アクセス時刻

Windows NTサーバーのNTFSボリュームからフォルダが開かれるたびに、システムはリストされた各フォルダのタイムスタンプフィールドである最終アクセス時刻を更新します。使用頻度の高いNTFSボリュームでは、これがパフォーマンスに影響する可能性があります。

1. レジストリエディタ（Regedit.exe）を開きます。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`に移動します。
3. `NtfsDisableLastAccessUpdate`を探します。存在しない場合は、このDWORDを追加し、値を1に設定してプロセスを無効にします。
4. レジストリエディタを閉じ、サーバーを再起動します。

## USBの履歴を削除する

すべての**USBデバイスエントリ**は、PCまたはノートパソコンにUSBデバイスを接続するたびに作成されるサブキーを含む**USBSTOR**レジストリキーの下に保存されます。このキーは`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`にあります。これを削除すると、USBの履歴が削除されます。\
また、USBに関する情報を保存する別のファイルは、`C:\Windows\INF`内の`setupapi.dev.log`です。これも削除する必要があります。

## シャドウコピーの無効化

シャドウコピーを**リスト**するには、`vssadmin list shadowstorage`を実行します。\
シャドウコピーを**削除**するには、`vssadmin delete shadow`を実行します。

また、[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)で提案された手順に従ってGUIからも削除できます。

シャドウコピーを無効にするには：

1. Windowsのスタートボタンに移動し、「services」と入力してテキスト検索ボックスに入力します。Servicesプログラムを開きます。
2. リストから「Volume Shadow Copy」を見つけ、ハイライトして右クリックし、「プロパティ」を選択します。
3. 「起動の種類」のドロップダウンメニューから「無効」を選択し、適用してOKをクリックします。

![](<../../.gitbook/assets/image (453).png>)

シャドウコピーでコピーされるファイルの構成も、レジストリ`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`で変更することができます。

## 削除されたファイルの上書き

* **Windowsツール**を使用することができます：`cipher /w:C`これにより、cipherにCドライブ内の使用可能な未使用ディスク領域からデータを削除するよう指示します。
* [**Eraser**](https://eraser.heidi.ie)のようなツールも使用できます。

## Windowsイベントログの削除

* Windows + R --> eventvwr.msc --> 「Windowsログ」を展開 --> 各カテゴリを右クリックし、「ログをクリア」を選択します。
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windowsイベントログの無効化

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* サービスセクション内で「Windowsイベントログ」サービスを無効にします。
* `WEvtUtil.exec clear-log`または`WEvtUtil.exe cl`

## $UsnJrnlの無効化

* `fsutil usn deletejournal /d c:`


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricksのリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudのリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
