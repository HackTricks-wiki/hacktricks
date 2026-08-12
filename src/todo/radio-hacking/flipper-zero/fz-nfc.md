# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#id-9wrzi" id="id-9wrzi"></a>

有关 RFID 和 NFC 的信息，请查看以下页面：


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 支持的 NFC 卡片 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> 除了 NFC 卡片之外，Flipper Zero 还支持**其他类型的高频卡片**，例如多种 **Mifare** Classic 和 Ultralight，以及 **NTAG**。

以下功能列表描述的是原始文章所记录的 firmware，不应视为当前完整的支持矩阵。随着时间推移，Flipper firmware 增加了协议并改变了 NFC 行为；请查看已安装 firmware 的当前官方文档。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **银行卡（EMV）** — 只能读取 UID、SAK 和 ATQA，且不会保存。
- **未知卡片** — 读取 UID、SAK 和 ATQA，并模拟 UID。

对于 **NFC 卡片类型 B、F 和 V**，文档所述的 firmware 可以读取 UID，但不会保存。

### NFC 卡片类型 A <a href="#uvusf" id="uvusf"></a>

#### 银行卡（EMV） <a href="#kzmrp" id="kzmrp"></a>

文档所述的 firmware 可以从银行卡读取 UID、SAK、ATQA 以及可用的应用数据，**但不会保存**。

对于这些银行卡，firmware 会显示数据，但不会保存或模拟该卡片。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### 未知卡片 <a href="#id-37eo8" id="id-37eo8"></a>

当 Flipper Zero **无法确定 NFC 卡片的类型**时，只能**读取并保存 UID、SAK 和 ATQA**。

对于未知 NFC 卡片，此模式只能模拟其 UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC 卡片类型 B、F 和 V <a href="#wyg51" id="wyg51"></a>

在原始文章所记录的 firmware 中，NFC 卡片类型 B、F 和 V 只能读取并显示 identifier，无法保存。<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 操作

有关 NFC 的简介，请[**阅读此页面**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### 读取

Flipper Zero 可以读取 NFC 卡片，但并未实现基于 ISO 14443 构建的所有更高层协议。因此，它可能只能获取底层 UID、SAK 和 ATQA，而无法识别应用协议。对于仅通过 UID 进行授权的基本访问控制系统，该工具可以读取、手动输入并模拟该 identifier；经过 cryptographic authentication 的系统需要的不只是复制 UID。<sup>[[1]](#references)</sup>

#### 读取 UID 与读取内部数据的区别 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

在 Flipper 中，读取 13.56 MHz 标签可以分为两部分：<sup>[[1]](#references)</sup>

- **低层读取** — 只读取 UID、SAK 和 ATQA。Flipper 会尝试根据从卡片读取的数据猜测高层协议。由于这只是基于某些因素作出的推断，因此无法保证 100% 准确。
- **高层读取** — 使用特定的高层协议从卡片 memory 中读取数据。例如读取 Mifare Ultralight 中的数据、读取 Mifare Classic 的 sectors，或读取 PayPass/Apple Pay 卡片的 attributes。

### 特定读取

如果 Flipper Zero 无法根据低层数据识别卡片类型，可以在 `Extra Actions` 中选择 `Read Specific Card Type`，然后**手动****指定要读取的卡片类型**。

#### EMV 银行卡（PayPass、payWave、Apple Pay、Google Pay） <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

较早的 Flipper firmware 以及兼容的 EMV 卡片可能会暴露 UID 以外的更多信息，包括 PAN、有效期、持卡人姓名或 transaction log，前提是这些记录由卡片提供。具体可用性取决于卡片、应用和 firmware。印在卡片上的 magnetic-stripe CVV 不会通过这种方式暴露；读取这些记录也不会克隆进行 contactless payment 所需的 cryptographic transaction capability。<sup>[[1]](#references)</sup>

## References

- [1] [使用 Flipper Zero 深入了解 RFID 协议](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero 文档 - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
