# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 简介

有关 iButton 技术的背景信息，请参阅：

{{#ref}}
../ibutton.md
{{#endref}}

## 设计

下图中，**蓝色**区域显示了读取时如何将实体 iButton 放在 Flipper Zero 的触点上。**绿色**区域显示了模拟时应与读卡器接触的触点。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 操作

### 读取

在读取模式下，Flipper Zero 会等待钥匙接触其触点，检测协议，并在钥匙 ID 上方显示协议。内置应用支持 Dallas、Cyfral 和 Metakom 门禁钥匙。<sup>[[2]](#references)</sup>

### 手动添加

你可以手动输入 Dallas、Cyfral 和 Metakom 协议的钥匙数据。<sup>[[2]](#references)</sup>

### 模拟

你可以模拟已保存的钥匙，无论它是从实体钥匙读取的，还是手动输入的。<sup>[[2]](#references)</sup>

> [!TIP]
> 如果内置触点无法接触读卡器，可以通过 GPIO 引脚连接数据触点和接地触点。<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [使用 Flipper Zero 驯服 iButton 钥匙](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero 文档 - 读取 iButton 钥匙](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

