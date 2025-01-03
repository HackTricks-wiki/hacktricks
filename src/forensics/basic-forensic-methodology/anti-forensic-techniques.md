{{#include ../../banners/hacktricks-training.md}}

# タイムスタンプ

攻撃者は**ファイルのタイムスタンプを変更すること**に興味を持つかもしれません。\
タイムスタンプは、MFT内の属性`$STANDARD_INFORMATION` **および** `$FILE_NAME`に見つけることができます。

両方の属性には4つのタイムスタンプがあります: **変更**, **アクセス**, **作成**, および **MFTレジストリ変更** (MACEまたはMACB)。

**Windowsエクスプローラー**や他のツールは、**`$STANDARD_INFORMATION`**からの情報を表示します。

## TimeStomp - アンチフォレンジツール

このツールは**`$STANDARD_INFORMATION`**内のタイムスタンプ情報を**変更**しますが、**`$FILE_NAME`**内の情報は**変更しません**。したがって、**疑わしい** **活動を特定することが可能です**。

## Usnjrnl

**USNジャーナル** (Update Sequence Number Journal)は、NTFS (Windows NTファイルシステム)の機能で、ボリュームの変更を追跡します。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)ツールを使用すると、これらの変更を調査できます。

![](<../../images/image (449).png>)

前の画像は、**ツール**によって表示された**出力**で、ファイルに対して**いくつかの変更が行われた**ことが観察できます。

## $LogFile

**ファイルシステムへのすべてのメタデータ変更は**、[書き込み先行ログ](https://en.wikipedia.org/wiki/Write-ahead_logging)として知られるプロセスでログに記録されます。ログに記録されたメタデータは、NTFSファイルシステムのルートディレクトリにある`**$LogFile**`という名前のファイルに保持されます。[LogFileParser](https://github.com/jschicht/LogFileParser)のようなツールを使用して、このファイルを解析し、変更を特定できます。

![](<../../images/image (450).png>)

再び、ツールの出力では、**いくつかの変更が行われた**ことが確認できます。

同じツールを使用して、**タイムスタンプが変更された時刻を特定することが可能です**：

![](<../../images/image (451).png>)

- CTIME: ファイルの作成時刻
- ATIME: ファイルの変更時刻
- MTIME: ファイルのMFTレジストリ変更
- RTIME: ファイルのアクセス時刻

## `$STANDARD_INFORMATION`と`$FILE_NAME`の比較

疑わしい変更されたファイルを特定する別の方法は、両方の属性の時間を比較して**不一致**を探すことです。

## ナノ秒

**NTFS**のタイムスタンプは**100ナノ秒**の**精度**を持っています。したがって、2010-10-10 10:10:**00.000:0000のようなタイムスタンプを持つファイルを見つけることは非常に疑わしいです。

## SetMace - アンチフォレンジツール

このツールは、両方の属性`$STARNDAR_INFORMATION`と`$FILE_NAME`を変更できます。ただし、Windows Vista以降は、ライブOSでこの情報を変更する必要があります。

# データ隠蔽

NFTSはクラスタと最小情報サイズを使用します。つまり、ファイルがクラスタと半分を占有する場合、**残りの半分はファイルが削除されるまで使用されません**。したがって、このスラックスペースに**データを隠すことが可能です**。

slackerのようなツールを使用すると、この「隠された」スペースにデータを隠すことができます。ただし、`$logfile`や`$usnjrnl`の分析により、いくつかのデータが追加されたことが示される可能性があります：

![](<../../images/image (452).png>)

その後、FTK Imagerのようなツールを使用してスラックスペースを取得することが可能です。この種のツールは、内容を難読化または暗号化して保存することができます。

# UsbKill

これは、**USB**ポートに変更が検出された場合にコンピュータを**シャットダウンする**ツールです。\
これを発見する方法は、実行中のプロセスを検査し、**実行中の各Pythonスクリプトをレビューする**ことです。

# ライブLinuxディストリビューション

これらのディストリビューションは**RAM**メモリ内で**実行されます**。検出する唯一の方法は、**NTFSファイルシステムが書き込み権限でマウントされている場合**です。読み取り権限のみでマウントされている場合、侵入を検出することはできません。

# セキュア削除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows設定

フォレンジック調査をはるかに困難にするために、いくつかのWindowsログ記録方法を無効にすることが可能です。

## タイムスタンプの無効化 - UserAssist

これは、ユーザーが実行した各実行可能ファイルの日時を保持するレジストリキーです。

UserAssistを無効にするには、2つのステップが必要です：

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`と`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`の2つのレジストリキーをゼロに設定して、UserAssistを無効にしたいことを示します。
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`のようなレジストリサブツリーをクリアします。

## タイムスタンプの無効化 - Prefetch

これは、Windowsシステムのパフォーマンスを向上させる目的で実行されたアプリケーションに関する情報を保存します。ただし、これはフォレンジック実践にも役立ちます。

- `regedit`を実行
- ファイルパス`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`を選択
- `EnablePrefetcher`と`EnableSuperfetch`の両方を右クリック
- 各々を変更して、値を1（または3）から0に変更
- 再起動

## タイムスタンプの無効化 - 最後のアクセス時間

NTFSボリュームからフォルダーが開かれるたびに、システムは**各リストされたフォルダーのタイムスタンプフィールドを更新するための時間を取ります**。これは、最後のアクセス時間と呼ばれます。NTFSボリュームが頻繁に使用される場合、これがパフォーマンスに影響を与える可能性があります。

1. レジストリエディタを開く (Regedit.exe)。
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`に移動します。
3. `NtfsDisableLastAccessUpdate`を探します。存在しない場合は、このDWORDを追加し、その値を1に設定してプロセスを無効にします。
4. レジストリエディタを閉じ、サーバーを再起動します。

## USB履歴の削除

すべての**USBデバイスエントリ**は、USBデバイスをPCまたはノートパソコンに接続するたびに作成されるサブキーを含む**USBSTOR**レジストリキーの下にWindowsレジストリに保存されます。このキーはここにあります`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**これを削除することで**、USB履歴を削除します。\
また、[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)ツールを使用して、削除したことを確認することもできます（および削除するために）。

USBに関する情報を保存する別のファイルは、`C:\Windows\INF`内の`setupapi.dev.log`ファイルです。これも削除する必要があります。

## シャドウコピーの無効化

**シャドウコピーをリスト**するには`vssadmin list shadowstorage`\
**削除**するには`vssadmin delete shadow`を実行します。

GUIを介して削除することもできます。手順は[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)を参照してください。

シャドウコピーを無効にするには、[こちらの手順](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)を参照してください：

1. Windowsスタートボタンをクリックした後、テキスト検索ボックスに「services」と入力してサービスプログラムを開きます。
2. リストから「Volume Shadow Copy」を見つけて選択し、右クリックしてプロパティにアクセスします。
3. 「スタートアップの種類」ドロップダウンメニューから「無効」を選択し、変更を適用してOKをクリックして確認します。

シャドウコピーでコピーされるファイルの構成をレジストリ`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`で変更することも可能です。

## 削除されたファイルの上書き

- **Windowsツール**を使用できます：`cipher /w:C` これは、Cドライブ内の未使用のディスクスペースからデータを削除するようにcipherに指示します。
- [**Eraser**](https://eraser.heidi.ie)のようなツールを使用することもできます。

## Windowsイベントログの削除

- Windows + R --> eventvwr.msc --> 「Windowsログ」を展開 --> 各カテゴリを右クリックして「ログのクリア」を選択
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windowsイベントログの無効化

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- サービスセクション内で「Windows Event Log」サービスを無効にします。
- `WEvtUtil.exec clear-log`または`WEvtUtil.exe cl`

## $UsnJrnlの無効化

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
