# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 简介

有关 iButton 的更多信息，请查看：


{{#ref}}
../ibutton.md
{{#endref}}

## 设计

下图中的**蓝色**部分表示你需要如何**放置真实的 iButton**，以便 Flipper 能够**读取它**。**绿色**部分表示你需要如何用 Flipper Zero **接触读卡器**，以便**正确模拟 iButton**。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 操作

### 读取

在 Read Mode 中，Flipper 会等待 iButton key 接触，并能够识别以下三种类型的 key：**Dallas、Cyfral 和 Metakom**。Flipper 会**自动识别 key 的类型**。key protocol 的名称会显示在屏幕上、ID number 的上方。<sup>[[1]](#references)</sup>

### 手动添加

可以**手动添加**以下类型的 iButton：**Dallas、Cyfral 和 Metakom**

### **Emulate**

可以**模拟**已保存的 iButton（读取的或手动添加的）。

> [!TIP]
> 如果无法让 Flipper Zero 的触点与读卡器正确接触，可以**使用 external GPIO：**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## 参考资料

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
