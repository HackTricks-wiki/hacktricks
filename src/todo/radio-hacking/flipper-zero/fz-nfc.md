# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

有关RFID和NFC的信息，请查看以下页面：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> 除了NFC卡，Flipper Zero还支持**其他类型的高频卡**，例如几种**Mifare** Classic和Ultralight以及**NTAG**。

新的NFC卡类型将被添加到支持的卡列表中。Flipper Zero支持以下**NFC卡类型A**（ISO 14443A）：

- **银行卡（EMV）** — 仅读取UID、SAK和ATQA而不保存。
- **未知卡** — 读取（UID、SAK、ATQA）并模拟UID。

对于**NFC卡类型B、F和V**，Flipper Zero能够读取UID而不保存。

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero只能读取银行卡的UID、SAK、ATQA和存储数据**而不保存**。

银行卡读取屏幕对于银行卡，Flipper Zero只能读取数据**而不保存和模拟**。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

当Flipper Zero**无法确定NFC卡的类型**时，仅能**读取和保存UID、SAK和ATQA**。

未知卡读取屏幕对于未知NFC卡，Flipper Zero只能模拟UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

对于**NFC卡类型B、F和V**，Flipper Zero只能**读取和显示UID**而不保存。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

有关NFC的介绍[**请阅读此页面**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### Read

Flipper Zero可以**读取NFC卡**，但是它**不理解所有基于ISO 14443的协议**。然而，由于**UID是一个低级属性**，您可能会发现自己处于一种情况，即**UID已经被读取，但高级数据传输协议仍然未知**。您可以使用Flipper读取、模拟和手动输入UID，以便为使用UID进行授权的原始读取器。

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

在Flipper中，读取13.56 MHz标签可以分为两个部分：

- **低级读取** — 仅读取UID、SAK和ATQA。Flipper尝试根据从卡片读取的数据猜测高级协议。您不能对此100%确定，因为这只是基于某些因素的假设。
- **高级读取** — 使用特定的高级协议从卡片的内存中读取数据。这将是读取Mifare Ultralight上的数据、从Mifare Classic读取扇区或从PayPass/Apple Pay读取卡片属性。

### Read Specific

如果Flipper Zero无法从低级数据中找到卡片类型，在`Extra Actions`中，您可以选择`Read Specific Card Type`并**手动****指明您想要读取的卡片类型**。

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

除了简单地读取UID，您还可以从银行卡中提取更多数据。可以**获取完整的卡号**（卡片正面的16位数字）、**有效期**，在某些情况下甚至可以获取**持卡人姓名**以及**最近交易**的列表。\
但是，您**无法通过这种方式读取CVV**（卡片背面的3位数字）。此外，**银行卡受到重放攻击的保护**，因此使用Flipper复制后再尝试模拟支付是行不通的。

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
