# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#id-9wrzi" id="id-9wrzi"></a>

有关 RFID 和 NFC 的信息，请查看以下页面：


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 支持的 NFC 卡片 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> 除 NFC 卡片外，Flipper Zero 还支持**其他类型的高频卡片**，例如多种 **Mifare** Classic、Ultralight 和 **NTAG**。

以下功能列表介绍的是原文所述的固件，不应视为当前完整的支持列表。Flipper 固件已随时间增加协议并改变 NFC 行为；请查看当前安装固件的官方文档。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **银行卡 (EMV)** — 只能读取 UID、SAK 和 ATQA，不会保存。
- **未知卡片** — 读取 UID、SAK 和 ATQA，并模拟 UID。

对于 **NFC B、F 和 V 类卡片**，文中所述固件可以读取 UID，但不会保存。

### NFC A 类卡片 <a href="#uvusf" id="uvusf"></a>

#### 银行卡 (EMV) <a href="#kzmrp" id="kzmrp"></a>

文中所述固件可以读取银行卡的 UID、SAK、ATQA 和可用的应用数据，**但不会保存**。

对于这些银行卡，固件会显示数据，但不会保存或模拟卡片。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### 未知卡片 <a href="#id-37eo8" id="id-37eo8"></a>

当 Flipper Zero **无法确定 NFC 卡片的类型**时，只能**读取并保存**其 **UID、SAK 和 ATQA**。

对于未知 NFC 卡片，此模式只能模拟其 UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC B、F 和 V 类卡片 <a href="#wyg51" id="wyg51"></a>

在原文所述的固件中，NFC B、F 和 V 类卡片只能读取并显示标识符，不会保存。<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 操作

NFC 简介请[**阅读此页面**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1)。

### 读取

Flipper Zero 可以读取 NFC 卡片，但并未实现基于 ISO 14443 的所有高层协议。因此，它可能会读取底层 UID、SAK 和 ATQA，但无法识别应用协议。对于仅通过 UID 授权的简单门禁系统，该工具可以读取、手动输入并模拟该标识符；而经过加密认证的系统则需要的不只是复制 UID。<sup>[[1]](#references)</sup>

#### 读取 UID 与读取卡片内的数据 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

在 Flipper 中，读取 13.56 MHz 标签可分为两种方式：<sup>[[1]](#references)</sup>

- **底层读取** — 只读取 UID、SAK 和 ATQA。Flipper 会尝试根据从卡片读取的数据推测高层协议。由于这只是基于某些因素作出的推断，因此无法保证完全准确。
- **高层读取** — 使用特定的高层协议读取卡片内存中的数据，例如读取 Mifare Ultralight 的数据、读取 Mifare Classic 的扇区，或读取 PayPass/Apple Pay 卡片的属性。

### 指定读取类型

如果 Flipper Zero 无法根据底层数据识别卡片类型，可以在 `Extra Actions` 中选择 `Read Specific Card Type`，然后**手动指定要读取的卡片类型**。

#### EMV 银行卡 (PayPass、payWave、Apple Pay、Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

较旧的 Flipper 固件以及兼容的 EMV 卡片可能会暴露 UID 以外的更多信息，可能包括 PAN、到期日期、持卡人姓名或交易日志（如果卡片提供了这些记录）。具体可读取的信息因卡片、应用和固件而异。通过这种方式无法获取印在卡片上的磁条 CVV；读取这些记录也无法复制进行非接触式支付所需的加密交易能力。<sup>[[1]](#references)</sup>

## References

- [1] [使用 Flipper Zero 深入了解 RFID 协议](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero 文档 - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
