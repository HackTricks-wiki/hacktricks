# アーカイブ抽出パストラバーサル ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概要

多くのアーカイブ形式（ZIP、RAR、TAR、7-ZIPなど）は、各エントリが独自の**内部パス**を持つことを許可します。抽出ユーティリティがそのパスを盲目的に尊重すると、`..`を含む巧妙に作成されたファイル名や**絶対パス**（例：`C:\Windows\System32\`）がユーザーが選択したディレクトリの外に書き込まれます。この種の脆弱性は*Zip-Slip*または**アーカイブ抽出パストラバーサル**として広く知られています。

結果は、任意のファイルの上書きから、Windowsの*スタートアップ*フォルダなどの**自動実行**場所にペイロードをドロップすることによって**リモートコード実行（RCE）**を直接達成することまで多岐にわたります。

## 根本原因

1. 攻撃者は、1つ以上のファイルヘッダーが以下を含むアーカイブを作成します：
* 相対トラバーサルシーケンス（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* 絶対パス（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
2. 被害者は、埋め込まれたパスを信頼し、それをサニタイズしたり選択したディレクトリの下に強制的に抽出したりしない脆弱なツールでアーカイブを抽出します。
3. ファイルは攻撃者が制御する場所に書き込まれ、システムまたはユーザーがそのパスをトリガーする次回に実行/ロードされます。

## 実際の例 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows用のWinRAR（`rar` / `unrar` CLI、DLL、およびポータブルソースを含む）は、抽出中にファイル名を検証することに失敗しました。悪意のあるRARアーカイブには、次のようなエントリが含まれていました：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
選択した出力ディレクトリの**外**にあり、ユーザーの*Startup*フォルダー内に入ります。ログオン後、Windowsはそこに存在するすべてを自動的に実行し、*永続的*なRCEを提供します。

### PoCアーカイブの作成 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
オプション使用:
* `-ep`  – ファイルパスをそのまま保存（先頭の `./` は削除しない）。

`evil.rar` を被害者に配布し、脆弱な WinRAR ビルドで解凍するよう指示します。

### 実際の悪用の観察

ESET は、カスタマイズされたバックドアを展開し、ランサムウェア操作を促進するために CVE-2025-8088 を悪用した RAR アーカイブを添付した RomCom (Storm-0978/UNC2596) のスピアフィッシングキャンペーンを報告しました。

## 検出のヒント

* **静的検査** – アーカイブエントリをリストし、`../`、`..\\`、*絶対パス* (`C:`) または非正準 UTF-8/UTF-16 エンコーディングを含む名前をフラグします。
* **サンドボックス抽出** – *安全な* エクストラクタ（例: Python の `patool`、7-Zip ≥ 最新、`bsdtar`）を使用して使い捨てディレクトリに解凍し、結果のパスがディレクトリ内に留まることを確認します。
* **エンドポイント監視** – アーカイブが WinRAR/7-Zip/etc. によって開かれた直後に `Startup`/`Run` ロケーションに書き込まれた新しい実行可能ファイルに警告します。

## 緩和策と強化

1. **エクストラクタを更新** – WinRAR 7.13 は適切なパスのサニタイズを実装しています。ユーザーは手動でダウンロードする必要があります。WinRAR には自動更新メカニズムがありません。
2. 可能な場合は **「パスを無視」** オプション（WinRAR: *Extract → "Do not extract paths"*）でアーカイブを抽出します。
3. 信頼できないアーカイブは **サンドボックス** または VM 内で開きます。
4. アプリケーションホワイトリストを実装し、ユーザーの自動実行ディレクトリへの書き込みアクセスを制限します。

## 追加の影響を受けた / 歴史的なケース

* 2018 – 多くの Java/Go/JS ライブラリに影響を与えた Snyk の大規模な *Zip-Slip* アドバイザリー。
* 2023 – `-ao` マージ中の類似のトラバーサルに関する 7-Zip CVE-2023-4011。
* 書き込み前に `PathCanonicalize` / `realpath` を呼び出さないカスタム抽出ロジック。

## 参考文献

- [BleepingComputer – WinRAR ゼロデイがアーカイブ抽出にマルウェアを植え付けるために悪用される](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 チェンジログ](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip 脆弱性の詳細](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
