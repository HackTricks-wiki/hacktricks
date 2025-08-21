# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

有关 iButton 的更多信息，请查看：

{{#ref}}
../ibutton.md
{{#endref}}

## Design

下图的 **蓝色** 部分是您需要 **放置真实 iButton** 的位置，以便 Flipper 可以 **读取它。** **绿色** 部分是您需要 **用 Flipper zero 接触读卡器** 以 **正确模拟 iButton** 的方式。

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

在读取模式下，Flipper 正在等待 iButton 密钥接触，并能够处理三种类型的密钥：**Dallas, Cyfral, 和 Metakom**。Flipper 将 **自动识别密钥类型**。密钥协议的名称将显示在 ID 号码上方的屏幕上。

### Add manually

可以 **手动添加** 类型为：**Dallas, Cyfral, 和 Metakom** 的 iButton。

### **Emulate**

可以 **模拟** 已保存的 iButtons（读取或手动添加）。

> [!TIP]
> 如果您无法使 Flipper Zero 的预期接触点接触读卡器，您可以 **使用外部 GPIO：**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
