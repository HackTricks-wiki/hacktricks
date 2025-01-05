# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 它将监控每个进程所建立的每个连接。根据模式（静默允许连接、静默拒绝连接并警报），它将**在每次建立新连接时向您显示警报**。它还有一个非常好的图形用户界面来查看所有这些信息。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See 防火墙。这是一个基本的防火墙，会对可疑连接发出警报（它有一个图形用户界面，但没有 Little Snitch 的那么花哨）。

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See 应用程序，将在多个位置搜索**恶意软件可能存在的地方**（这是一个一次性工具，而不是监控服务）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): 像 KnockKnock 一样，通过监控生成持久性的进程。

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See 应用程序，用于查找安装键盘“事件捕获”的**键盘记录器**。

{{#include ../../banners/hacktricks-training.md}}
