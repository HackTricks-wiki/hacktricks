# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#id-9wrzi" id="id-9wrzi"></a>

有关 RFID 和 NFC 的信息，请查看以下页面：


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 支持的 NFC 卡片 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> 除了 NFC 卡片之外，Flipper Zero 还支持**其他类型的高频卡片**，例如多种 **Mifare** Classic、Ultralight 和 **NTAG**。

支持的卡片列表中将添加新的 NFC 卡片类型。Flipper Zero 支持以下 **A 型 NFC 卡片**（ISO 14443A）：

- **银行卡（EMV）** — 仅读取 UID、SAK 和 ATQA，不保存。
- **未知卡片** — 读取（UID、SAK、ATQA）并模拟 UID。

对于 **B 型、F 型和 V 型 NFC 卡片**，Flipper Zero 能够读取 UID，但不会保存。

### A 型 NFC 卡片 <a href="#uvusf" id="uvusf"></a>

#### 银行卡（EMV） <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero 只能读取银行卡上的 UID、SAK、ATQA 和存储数据，且**不会保存**。

银行卡读取界面对于银行卡，Flipper Zero 只能读取数据，**不会保存或模拟这些数据**。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### 未知卡片 <a href="#id-37eo8" id="id-37eo8"></a>

当 Flipper Zero **无法确定 NFC 卡片的类型**时，只能**读取并保存 UID、SAK 和 ATQA**。

未知卡片读取界面对于未知 NFC 卡片，Flipper Zero 只能模拟 UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### B 型、F 型和 V 型 NFC 卡片 <a href="#wyg51" id="wyg51"></a>

对于 **B 型、F 型和 V 型 NFC 卡片**，Flipper Zero 只能**读取并显示 UID**，不会保存。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 操作

有关 NFC 的简介，请[**阅读此页面**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### 读取

Flipper Zero 可以**读取 NFC 卡片**，但它**不理解**所有基于 ISO 14443 的协议。不过，由于 **UID 是一种低级属性**，你可能会遇到这样的情况：**UID 已经被读取，但高级数据传输协议仍然未知**。对于使用 UID 进行授权的简单读取器，你可以使用 Flipper 读取、模拟并手动输入 UID。<sup>[[1]](#references)</sup>

#### 读取 UID 与读取内部数据的区别 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

在 Flipper 中，读取 13.56 MHz 卡片可以分为两部分：<sup>[[1]](#references)</sup>

- **低级读取** — 仅读取 UID、SAK 和 ATQA。Flipper 会根据从卡片读取的数据尝试猜测高级协议。由于这只是基于某些因素得出的假设，因此无法对此 100% 确定。
- **高级读取** — 使用特定的高级协议从卡片内存读取数据。例如读取 Mifare Ultralight 中的数据、读取 Mifare Classic 中的扇区，或读取 PayPass/Apple Pay 中的卡片属性。

### 指定读取

如果 Flipper Zero 无法根据低级数据确定卡片类型，可以在 `Extra Actions` 中选择 `Read Specific Card Type`，然后**手动****指定想要读取的卡片类型**。

#### EMV 银行卡（PayPass、payWave、Apple Pay、Google Pay） <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

除了简单地读取 UID 外，你还可以从银行卡中提取更多数据。可以**获取完整的卡号**（卡片正面的 16 位数字）、**有效期**，有时甚至可以获取**持卡人姓名**以及**最近交易记录**列表。\
不过，你**无法通过这种方式读取 CVV**（卡片背面的 3 位数字）。此外，**银行卡受到重放攻击防护**，因此使用 Flipper 复制银行卡后尝试模拟它进行支付将无法成功。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
