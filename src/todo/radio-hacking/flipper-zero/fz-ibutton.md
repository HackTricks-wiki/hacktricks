# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 介绍

有关iButton的更多信息，请查看：

{{#ref}}
../ibutton.md
{{#endref}}

## 设计

下图中的**蓝色**部分是您需要**放置真实iButton**的位置，以便Flipper可以**读取它。** **绿色**部分是您需要用Flipper Zero**接触读卡器**以**正确模拟iButton**的位置。

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 操作

### 读取

在读取模式下，Flipper等待iButton密钥接触，并能够处理三种类型的密钥：**Dallas, Cyfral, 和 Metakom**。Flipper将**自动识别密钥类型**。密钥协议的名称将显示在ID号码上方的屏幕上。

### 手动添加

可以**手动添加**类型为：**Dallas, Cyfral, 和 Metakom**的iButton。

### **模拟**

可以**模拟**已保存的iButton（读取或手动添加）。

> [!NOTE]
> 如果您无法使Flipper Zero的预期接触点接触读卡器，您可以**使用外部GPIO：**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## 参考

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
