# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 介绍

有关 iButton 的更多信息，请查看：

{{#ref}}
../ibutton.md
{{#endref}}

## 设计

下图的 **蓝色** 部分是您需要 **放置真实 iButton** 的位置，以便 Flipper 可以 **读取它。** **绿色** 部分是您需要用 Flipper zero **接触读卡器** 的方式，以 **正确模拟 iButton**。

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 操作

### 读取

在读取模式下，Flipper 正在等待 iButton 密钥接触，并能够处理三种类型的密钥：**Dallas, Cyfral, 和 Metakom**。Flipper 将 **自动识别密钥类型**。密钥协议的名称将显示在 ID 号码上方的屏幕上。

### 手动添加

可以 **手动添加** 类型为：**Dallas, Cyfral, 和 Metakom** 的 iButton。

### **模拟**

可以 **模拟** 已保存的 iButtons（读取或手动添加）。

> [!NOTE]
> 如果您无法使 Flipper Zero 的预期接触点接触读卡器，您可以 **使用外部 GPIO：**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## 参考

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
